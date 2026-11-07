"""WebSocket gateway: lets the MDANetPro web app (in a browser) join networks.

Browsers cannot open TCP/UDP sockets, so a browser node connects to a gateway node over a
WebSocket. To the network, the browser is simply a member behind NAT that uses the gateway as
its relay:

  browser -> gateway   {"type":"relay_register","record":R}      register (like a NATed node)
  gateway -> browser   {"type":"relay_deliver","rid":..,"packet":P}  packets for the browser
  browser -> gateway   {"type":"relay_reply","rid":..,"reply":..}
  browser -> gateway   {"type":"gateway_send","rid":..,"to":E,"packet":P,"records":[..]}
  gateway -> browser   {"type":"gateway_result","rid":..,"ok":..,"reply":..,"route":..}
  browser -> gateway   {"type":"gateway_info","rid":..}              the gateway's own networks/record

The browser keeps its own keys and signs its own route record; messages stay onion-encrypted
end to end, so the gateway only forwards ciphertext. Standard library only (RFC 6455).

For a page served over HTTPS (e.g. GitHub Pages) browsers require wss:// except for
ws://localhost. Put the gateway behind a TLS reverse proxy (Caddy/nginx) or a tunnel
(`cloudflared tunnel --url http://localhost:50406`) to use it from other devices.
"""
import base64
import hashlib
import json
import socket
import struct
import threading
import uuid

import mda_p2p

WS_PORT = 50406
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
LEGACY_ALLOWED = {"hello", "ping"}  # packet types the gateway sends to plain IP:port addresses


class WsConnection:
    """Minimal server-side RFC 6455 connection (text frames, ping/pong, close)."""

    def __init__(self, conn):
        self.conn = conn
        self.lock = threading.Lock()
        self.closed = False

    def handshake(self):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.conn.recv(4096)
            if not chunk:
                return False
            data += chunk
            if len(data) > 65536:
                return False
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        if "websocket" not in headers.get("upgrade", "").lower() or "sec-websocket-key" not in headers:
            body = b"MDANetPro web gateway: connect with the MDANetPro web app.\n"
            self.conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\n"
                              b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            return False
        accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] + _GUID).encode()).digest()).decode()
        self.conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                           f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
        return True

    def _read_exact(self, n):
        data = b""
        while len(data) < n:
            chunk = self.conn.recv(n - len(data))
            if not chunk:
                raise ConnectionError("closed")
            data += chunk
        return data

    def receive(self):
        """Next text message, or None when the connection closes."""
        message = b""
        while True:
            b1, b2 = self._read_exact(2)
            fin, opcode = b1 & 0x80, b1 & 0x0F
            length = b2 & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            if length > 16 * 1024 * 1024:
                raise ConnectionError("frame too large")
            mask = self._read_exact(4) if b2 & 0x80 else None
            payload = self._read_exact(length)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 8:
                self.close()
                return None
            if opcode == 9:
                self._send_frame(10, payload)
                continue
            if opcode == 10:
                continue
            message += payload
            if fin:
                return message.decode("utf-8")

    def _send_frame(self, opcode, payload):
        header = bytes([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header += bytes([length])
        elif length < 65536:
            header += bytes([126]) + struct.pack("!H", length)
        else:
            header += bytes([127]) + struct.pack("!Q", length)
        with self.lock:
            self.conn.sendall(header + payload)

    def send_json(self, obj):
        if self.closed:
            raise ConnectionError("closed")
        self._send_frame(1, json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self._send_frame(8, b"")
        except OSError:
            pass
        try:
            self.conn.close()
        except OSError:
            pass


class _BrowserRelaySession:
    """Same interface as mda_p2p._RelaySession, so normal routing reaches the browser."""

    def __init__(self, ws):
        self.ws = ws
        self.pending = {}
        self.closed = False

    def request(self, packet, timeout):
        if self.closed:
            raise OSError("browser disconnected")
        rid = uuid.uuid4().hex
        event = threading.Event()
        self.pending[rid] = [event, None]
        try:
            self.ws.send_json({"type": "relay_deliver", "rid": rid, "packet": packet})
            if not event.wait(timeout):
                raise OSError("no reply from the browser")
            return self.pending[rid][1]
        except ConnectionError as exc:
            raise OSError(str(exc))
        finally:
            self.pending.pop(rid, None)

    def answer(self, rid, reply):
        if rid in self.pending:
            self.pending[rid][1] = reply
            self.pending[rid][0].set()

    def close(self):
        self.closed = True
        self.ws.close()


class WebGateway:
    def __init__(self, node, host="0.0.0.0", port=WS_PORT, policy=None, log=None):
        self.node = node
        self.host, self.port = host, int(port)
        self.policy = policy  # callable(pubkey) -> bool; None = anyone may register
        self.log = log or (lambda text: None)
        self.sock = None
        self.running = False
        self.clients = {}  # browser node address -> session

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(64)
        self.sock = sock
        self.running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self

    def stop(self):
        self.running = False
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
            self.sock = None
        for session in list(self.clients.values()):
            session.close()

    def _accept_loop(self):
        sock = self.sock
        while self.running and sock is not None:
            try:
                conn, addr = sock.accept()
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn, addr), daemon=True).start()

    def _serve(self, conn, addr):
        ws = WsConnection(conn)
        session = None
        endpoint = None
        try:
            conn.settimeout(120)
            if not ws.handshake():
                conn.close()
                return
            while True:
                text = ws.receive()
                if text is None:
                    break
                try:
                    msg = json.loads(text)
                except ValueError:
                    continue
                kind = msg.get("type")
                if kind == "relay_register":
                    session, endpoint = self._register(ws, msg, addr, session, endpoint)
                elif kind == "relay_reply" and session is not None:
                    session.answer(msg.get("rid"), msg.get("reply"))
                elif kind == "relay_ping":
                    ws.send_json({"type": "relay_pong"})
                elif kind == "gateway_send":
                    threading.Thread(target=self._gateway_send, args=(ws, msg), daemon=True).start()
                elif kind == "gateway_info":
                    ws.send_json({"type": "gateway_result", "rid": msg.get("rid"), "ok": True, "reply": self._info()})
        except (OSError, ConnectionError, ValueError):
            pass
        finally:
            if endpoint and self.clients.get(endpoint) is session:
                del self.clients[endpoint]
                transport = self.node.transport
                if transport is not None and transport._relay_sessions.get(endpoint) is session:
                    del transport._relay_sessions[endpoint]
                self.log(f"Web client disconnected: {endpoint}")
            ws.close()

    def _register(self, ws, msg, addr, session, endpoint):
        record = msg.get("record")
        transport = self.node.transport
        if not mda_p2p.verify_record(record):
            ws.send_json({"type": "relay_registered", "ok": False, "error": "invalid record"})
            return session, endpoint
        if callable(self.policy) and not self.policy(record.get("pubkey", "")):
            ws.send_json({"type": "relay_registered", "ok": False, "error": "not allowed on this gateway"})
            return session, endpoint
        transport.learn_record(record)
        new_endpoint = record["node"]
        if session is None:
            session = _BrowserRelaySession(ws)
        old = transport._relay_sessions.get(new_endpoint)
        if old is not None and old is not session:
            old.close()
        transport._relay_sessions[new_endpoint] = session
        self.clients[new_endpoint] = session
        ws.send_json({"type": "relay_registered", "ok": True, "seen_ip": addr[0], "gateway": self.node.nodeid,
                      "gateway_record": transport.local_record})
        if endpoint != new_endpoint:
            self.log(f"Web client connected: {new_endpoint}")
        return session, new_endpoint

    def _info(self):
        networks = []
        if callable(self.node.hello_provider):
            try:
                networks = list(self.node.hello_provider() or [])
            except Exception:
                networks = []
        return {"type": "hello_reply", "nodeid": self.node.nodeid, "networks": networks,
                "record": self.node.transport.local_record if self.node.transport else None}

    def _gateway_send(self, ws, msg):
        rid = msg.get("rid")
        target = str(msg.get("to", ""))
        packet = msg.get("packet") if isinstance(msg.get("packet"), dict) else {}
        transport = self.node.transport
        for record in msg.get("records") or []:
            transport.learn_record(record)
        result = {"type": "gateway_result", "rid": rid, "ok": False}
        try:
            if not mda_p2p.is_virtual(target) and packet.get("type") not in LEGACY_ALLOWED:
                raise OSError("the gateway only sends hello/ping to plain IP addresses")
            timeout = min(max(float(msg.get("timeout", 6)), 1.0), 20.0)
            host, port = mda_p2p.split_endpoint(target)
            reply = self.node.send_message(host, port, packet, timeout=timeout)
            result.update(ok=True, reply=reply, route=self.node.route_description(mda_p2p.format_endpoint(host, port)))
        except (OSError, ValueError) as exc:
            result["error"] = str(exc) or exc.__class__.__name__
        try:
            ws.send_json(result)
        except (OSError, ConnectionError):
            pass
