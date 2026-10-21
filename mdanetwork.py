import json
import socket
import threading
import time


class mdaconnection:
    """Compatibility wrapper for older MDA code."""

    def __init__(self):
        self.contactid = None
        self.nodeid = None
        self.port = None
        self.ip = None
        self.person = None
        self.isreal = False
        self.AESKey = None
        self.RSAKey = None
        self.realrcv = ""
        self.mcounter = 0
        self.ncounter = 0
        self.messages = []
        self.lastmsg = None

    @staticmethod
    def encode_packet(payload):
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return len(body).to_bytes(4, "big") + body

    @staticmethod
    def decode_packet(raw):
        if len(raw) < 4:
            return None
        length = int.from_bytes(raw[:4], "big")
        if len(raw) < 4 + length:
            return None
        return json.loads(raw[4:4 + length].decode("utf-8"))

    @staticmethod
    def send_payload(host, port, payload, timeout=5):
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.sendall(mdaconnection.encode_packet(payload))
            try:
                ack = conn.recv(4096)
                return mdaconnection.decode_packet(ack)
            except socket.timeout:
                return None

    def sendmsg(self, host, port, pingflag, weight, senderid, sender, rcv, ctrlflag, ctrlmsg, msg):
        packet = {
            "protocol": mda.mdaprotocol,
            "pingflag": pingflag,
            "weight": weight,
            "senderid": senderid,
            "sender": sender,
            "rcv": rcv,
            "ctrlflag": ctrlflag,
            "ctrlmsg": ctrlmsg,
            "msg": msg,
        }
        return self.send_payload(host, port, packet)

    def recvmsg(self, packet):
        if not isinstance(packet, dict):
            return None, None, None, None, None, None, None, None, None
        return (
            packet.get("protocol"),
            packet.get("pingflag"),
            packet.get("weight"),
            packet.get("senderid"),
            packet.get("sender"),
            packet.get("rcv"),
            packet.get("ctrlflag"),
            packet.get("ctrlmsg"),
            packet.get("msg"),
        )


class mda:
    """Minimal MDA node implementation designed for lab and public-IP peer communication."""

    mdaprotocol = "MDANetwork v1.1"
    PORT = 50404

    def __init__(self, host=None, port=None, peers=None, node_name=None, on_message=None):
        self.host = host or self.get_local_ip()
        self.port = int(port or self.PORT)
        self.peers = []
        self.node_name = node_name or f"node-{self.port}"
        self.nodeid = f"{self.host}:{self.port}"
        self.server_socket = None
        self.server_thread = None
        self.client_lock = threading.Lock()
        self.received_messages = []
        self.on_message = on_message
        self._peer_map = {}
        self._configure_peers(peers or [])

    @staticmethod
    def get_local_ip():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
            except OSError:
                return "127.0.0.1"

    @staticmethod
    def get_free_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("0.0.0.0", 0))
            return sock.getsockname()[1]

    @staticmethod
    def normalize_peer(value):
        if isinstance(value, (list, tuple)) and len(value) == 2:
            host, port = value
            return str(host), int(port)
        if isinstance(value, str):
            host, port = value.rsplit(":", 1)
            return host, int(port)
        raise ValueError(f"Unsupported peer value: {value!r}")

    def _configure_peers(self, peers):
        for peer in peers:
            self.add_peer(peer)

    def add_peer(self, peer):
        host, port = self.normalize_peer(peer)
        key = f"{host}:{port}"
        if key not in self._peer_map:
            self.peers.append((host, port))
            self._peer_map[key] = {"host": host, "port": port}
        return key

    def remove_peer(self, peer):
        host, port = self.normalize_peer(peer)
        key = f"{host}:{port}"
        if key in self._peer_map:
            del self._peer_map[key]
            self.peers = [(h, p) for h, p in self.peers if not (h == host and p == port)]
            return True
        return False

    def start_server(self):
        if self.server_socket:
            return self

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(32)
        self.server_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.server_thread.start()
        return self

    def _accept_loop(self):
        while True:
            try:
                conn, addr = self.server_socket.accept()
            except OSError:
                break
            thread = threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True)
            thread.start()

    @staticmethod
    def _recv_exact(conn, size):
        data = b""
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _recv_packet(self, conn):
        header = self._recv_exact(conn, 4)
        if not header:
            return None
        length = int.from_bytes(header, "big")
        if length <= 0:
            return None
        body = self._recv_exact(conn, length)
        if body is None:
            return None
        return header + body

    def _handle_connection(self, conn, addr):
        try:
            data = self._recv_packet(conn)
            if not data:
                conn.close()
                return
            packet = mdaconnection.decode_packet(data)
            if packet is None:
                conn.close()
                return
            packet.setdefault("received_from", f"{addr[0]}:{addr[1]}")
            self.received_messages.append(packet)
            if callable(self.on_message):
                self.on_message(packet)
            print(f"[{self.nodeid}] received: {packet}", flush=True)
            if packet.get("type") == "ping":
                reply = {"type": "pong", "nodeid": self.nodeid}
                conn.sendall(mdaconnection.encode_packet(reply))
                return
            conn.sendall(mdaconnection.encode_packet({"status": "ok", "nodeid": self.nodeid}))
        finally:
            conn.close()

    def ping_peer(self, host, port, timeout=5):
        payload = {"type": "ping", "nodeid": self.nodeid, "time": time.time()}
        ack = self.send_message(host, port, payload, timeout=timeout)
        return ack

    def send_message(self, host, port, payload, timeout=5):
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.sendall(mdaconnection.encode_packet(payload))
            raw = self._recv_packet(conn)
            if not raw:
                return None
            return mdaconnection.decode_packet(raw)

    def broadcast(self, payload):
        with self.client_lock:
            for host, port in self.peers:
                try:
                    self.send_message(host, port, payload)
                except (OSError, ValueError):
                    continue

    def close(self):
        if self.server_socket is not None:
            try:
                self.server_socket.close()
            except OSError:
                pass
            self.server_socket = None


def get_ip_addresses():
    return ["127.0.0.1"]
