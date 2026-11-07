import json
import random
import socket
import threading
import time
import uuid

import mda_p2p

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


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
    MESSAGE_REAL = "real"
    MESSAGE_FAKE = "fake"
    MESSAGE_CONTROL = "control"
    ONION_BODY_SIZE = 768

    def __init__(
        self,
        host=None,
        port=None,
        peers=None,
        node_name=None,
        on_message=None,
        private_key_pem=None,
        public_key_pem=None,
        onion_body_size=None,
        bind_host=None,
        stun_servers=None,
        p2p=True,
    ):
        self.host = host or self.get_local_ip()
        # Listen on every adapter by default; self.host is only the address we advertise.
        self.bind_host = "0.0.0.0" if bind_host is None else bind_host
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
        self._circuits = {}
        self._sender_counter = 0
        self._seen_message_nonces = {}
        # Optional callable returning a list of network summaries for "hello" lookups.
        self.hello_provider = None
        if onion_body_size is None:
            onion_body_size = self.ONION_BODY_SIZE
        self.onion_body_size = max(128, int(onion_body_size))
        self._private_key, self._public_key = self._load_or_create_keys(private_key_pem, public_key_pem)
        self.transport = None
        if p2p:
            # Stable address derived from our key; the IP is only one of several routes.
            self.nodeid = mda_p2p.node_address(self.get_public_key_pem(), self.port)
            self.transport = mda_p2p.P2PTransport(self, stun_servers=stun_servers)
        self._configure_peers(peers or [])

    @staticmethod
    def get_local_ip():
        try:
            from mda_netutils import best_local_ip
            return best_local_ip()
        except Exception:
            pass
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
            except OSError:
                return "127.0.0.1"

    def set_advertised_host(self, host):
        """Change the address other nodes should use for us. Returns the old endpoint."""
        old_endpoint = self.nodeid
        self.host = str(host)
        if self.transport is None:
            self.nodeid = f"{self.host}:{self.port}"
        else:
            self.transport.refresh_local_record()
        return old_endpoint

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
            return mda_p2p.split_endpoint(value)
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

        dual_stack = self.bind_host in ("0.0.0.0", "::") and socket.has_ipv6
        if dual_stack:
            try:
                self.server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except (OSError, AttributeError):
                dual_stack = False
        if not dual_stack:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # Windows: SO_REUSEADDR would let a second copy of the app silently share the port.
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind(("::" if dual_stack else self.bind_host, self.port))
        except OSError:
            self.server_socket.close()
            self.server_socket = None
            if dual_stack:  # IPv6 switched off on this computer: plain IPv4
                self.bind_host = "0.0.0.0" if self.bind_host == "::" else self.bind_host
                return self._start_ipv4_only()
            raise
        return self._after_bind()

    def _start_ipv4_only(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.bind_host, self.port))
        except OSError:
            self.server_socket.close()
            self.server_socket = None
            raise
        return self._after_bind()

    def _after_bind(self):
        self.server_socket.listen(32)
        self.server_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.server_thread.start()
        if self.transport is not None:
            self.transport.start()
        return self

    def _accept_loop(self):
        server_socket = self.server_socket  # close() sets the attribute to None
        while server_socket is not None:
            try:
                conn, addr = server_socket.accept()
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
        addr = (self._plain_ip(addr[0]), addr[1])
        try:
            data = self._recv_packet(conn)
            if not data:
                return
            packet = mdaconnection.decode_packet(data)
            if not isinstance(packet, dict):
                return
            if packet.get("type") == "relay_register" and self.transport is not None:
                conn.settimeout(None)
                self.transport.handle_relay_register(conn, packet, addr)  # long-lived connection
                return
            reply = self._process_packet(packet, addr)
            if reply is not None:
                conn.sendall(mdaconnection.encode_packet(reply))
        except (OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _plain_ip(ip):
        ip = str(ip)
        return ip[7:] if ip.startswith("::ffff:") else ip

    def _process_packet(self, packet, addr):
        """Handle one incoming packet (from TCP, a relay, or UDP) and return the reply."""
        target = packet.pop("_to", "")
        if target and target != self.nodeid:
            return {"status": "wrong_node", "nodeid": self.nodeid}
        packet.setdefault("received_from", f"{addr[0]}:{addr[1]}")
        ptype = packet.get("type")
        if ptype == "ping":
            return {"type": "pong", "nodeid": self.nodeid, "seen_ip": addr[0]}
        if ptype == "reach_probe":
            return self._answer_reach_probe(packet, addr)
        if ptype == "hello":
            if self.transport is not None and isinstance(packet.get("record"), dict):
                self.transport.learn_record(packet["record"])
            networks = []
            if callable(self.hello_provider):
                try:
                    networks = list(self.hello_provider() or [])
                except Exception:
                    networks = []
            reply = {"type": "hello_reply", "nodeid": self.nodeid, "seen_ip": addr[0], "networks": networks}
            if self.transport is not None:
                reply["record"] = self.transport.local_record
            return reply
        if self.transport is not None:
            if ptype == "relay_forward":
                return self.transport.handle_relay_forward(packet)
            if ptype == "punch_request":
                return self.transport.handle_punch_request(packet)
            if ptype == "routes_record":
                return {"status": "ok" if self.transport.learn_record(packet.get("record")) else "ignored"}
        if packet.get("routing") == "onion" and ptype in (self.MESSAGE_REAL, self.MESSAGE_FAKE):
            return self._handle_onion_packet(packet)
        print(f"[{self.nodeid}] received: {ptype} {packet.get('action', '')}", flush=True)
        self.received_messages.append(packet)
        if callable(self.on_message):
            self.on_message(packet)
        return {"status": "ok", "nodeid": self.nodeid}

    @staticmethod
    def _load_or_create_keys(private_key_pem, public_key_pem):
        if private_key_pem and public_key_pem:
            return RSA.import_key(private_key_pem), RSA.import_key(public_key_pem)
        private_key = RSA.generate(2048)
        return private_key, private_key.publickey()

    def get_public_key_pem(self):
        return self._public_key.export_key(format="PEM").decode("ascii")

    @staticmethod
    def _encode_json(payload):
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    @staticmethod
    def _decode_json(raw):
        return json.loads(raw.decode("utf-8"))

    @staticmethod
    def _aes_encrypt(raw, key):
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(raw)
        return nonce, ciphertext, tag

    @staticmethod
    def _aes_decrypt(nonce, ciphertext, tag, key):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    @staticmethod
    def _b64_encode(raw):
        return __import__("base64").b64encode(raw).decode("ascii")

    @staticmethod
    def _b64_decode(value):
        return __import__("base64").b64decode(value.encode("ascii"))

    def _pack_final_body(self, text):
        body = str(text).encode("utf-8")
        if len(body) > self.onion_body_size:
            body = body[: self.onion_body_size]
        random_pad = get_random_bytes(self.onion_body_size - len(body))
        return {
            "body_b64": self._b64_encode(body + random_pad),
            "body_len": len(body),
        }

    def _unpack_final_body(self, packed):
        raw = self._b64_decode(str(packed.get("body_b64", "")))
        body_len = int(packed.get("body_len", 0))
        if body_len < 0:
            body_len = 0
        if body_len > len(raw):
            body_len = len(raw)
        return raw[:body_len].decode("utf-8", errors="ignore")

    def _encrypt_layer(self, layer_payload, public_key_pem):
        hop_key = get_random_bytes(32)
        raw = self._encode_json(layer_payload)
        nonce, ciphertext, tag = self._aes_encrypt(raw, hop_key)
        pub = RSA.import_key(public_key_pem)
        rsa_cipher = PKCS1_OAEP.new(pub)
        encrypted_key = rsa_cipher.encrypt(hop_key)
        return {
            "scheme": "rsa-aes-gcm",
            "ek": self._b64_encode(encrypted_key),
            "nonce": self._b64_encode(nonce),
            "tag": self._b64_encode(tag),
            "ct": self._b64_encode(ciphertext),
        }

    def _decrypt_layer(self, onion_layer):
        encrypted_key = self._b64_decode(onion_layer["ek"])
        nonce = self._b64_decode(onion_layer["nonce"])
        tag = self._b64_decode(onion_layer["tag"])
        ciphertext = self._b64_decode(onion_layer["ct"])
        rsa_cipher = PKCS1_OAEP.new(self._private_key)
        hop_key = rsa_cipher.decrypt(encrypted_key)
        raw = self._aes_decrypt(nonce, ciphertext, tag, hop_key)
        return self._decode_json(raw)

    def _cleanup_seen_message_nonces(self, ttl=600):
        cutoff = time.time() - ttl
        stale = [nonce for nonce, seen_time in self._seen_message_nonces.items() if seen_time < cutoff]
        for nonce in stale:
            del self._seen_message_nonces[nonce]

    def _handle_onion_packet(self, packet):
        route_id = packet.get("route_id", "")
        msg_nonce = str(packet.get("msg_nonce", "")).strip()
        if msg_nonce:
            self._cleanup_seen_message_nonces()
            if msg_nonce in self._seen_message_nonces:
                return {"status": "replay_dropped", "nodeid": self.nodeid, "route_id": route_id}
            self._seen_message_nonces[msg_nonce] = time.time()
        onion_layer = packet.get("onion")
        if not isinstance(onion_layer, dict):
            return {"status": "invalid_onion", "nodeid": self.nodeid, "route_id": route_id}
        try:
            layer_payload = self._decrypt_layer(onion_layer)
        except Exception as exc:
            return {"status": "decrypt_error", "nodeid": self.nodeid, "route_id": route_id, "error": str(exc)}

        next_hop = layer_payload.get("next_hop")
        if next_hop:
            inner = layer_payload.get("inner")
            if not isinstance(inner, dict):
                return {"status": "invalid_inner", "nodeid": self.nodeid, "route_id": route_id}
            forward_packet = {
                "type": packet.get("type"),
                "routing": "onion",
                "network": packet.get("network", ""),
                "route_id": route_id,
                "circuit_id": str(packet.get("circuit_id", "")),
                "msg_nonce": msg_nonce,
                "sender_counter": int(packet.get("sender_counter", 0)),
                "sender": packet.get("sender", ""),
                "receiver": packet.get("receiver", ""),
                "onion": inner,
                "time": time.time(),
            }
            try:
                host, port = self.normalize_peer(next_hop)
                self.send_message(host, port, forward_packet, timeout=5)
                return {"status": "forwarded", "nodeid": self.nodeid, "route_id": route_id}
            except (OSError, ValueError) as exc:
                return {"status": "forward_error", "nodeid": self.nodeid, "route_id": route_id, "error": str(exc)}

        final_payload = layer_payload.get("payload", {})
        if not isinstance(final_payload, dict):
            return {"status": "invalid_final_payload", "nodeid": self.nodeid, "route_id": route_id}

        msg_type = packet.get("type")
        if msg_type == self.MESSAGE_FAKE:
            return {"status": "fake_discarded", "nodeid": self.nodeid, "route_id": route_id}

        delivered = {
            "type": self.MESSAGE_REAL,
            "routing": "onion",
            "network": packet.get("network", ""),
            "sender": packet.get("sender", ""),
            "receiver": packet.get("receiver", ""),
            "route_id": route_id,
            "circuit_id": str(packet.get("circuit_id", "")),
            "msg_nonce": msg_nonce,
            "sender_counter": int(packet.get("sender_counter", 0)),
            "text": self._unpack_final_body(final_payload.get("packed_body", {})),
            "time": time.time(),
        }
        self.received_messages.append(delivered)
        if callable(self.on_message):
            self.on_message(delivered)
        return {"status": "delivered", "nodeid": self.nodeid, "route_id": route_id}

    def ping_peer(self, host, port, timeout=5):
        payload = {"type": "ping", "nodeid": self.nodeid, "time": time.time()}
        ack = self.send_message(host, port, payload, timeout=timeout)
        return ack

    def _answer_reach_probe(self, packet, addr):
        """Connect back to the asking node (at the IP we saw it from) to test the reverse path."""
        result = {"type": "reach_result", "nodeid": self.nodeid, "seen_ip": addr[0], "callback_ok": False, "callback_error": ""}
        callback_node = str(packet.get("callback_node", ""))
        if callback_node and self.transport is not None and mda_p2p.is_virtual(callback_node):
            # Reverse test through normal routing (direct, hole punch or relay).
            if isinstance(packet.get("record"), dict):
                self.transport.learn_record(packet["record"])
            try:
                reply = self.send_message(*self.normalize_peer(callback_node), {"type": "ping", "nodeid": self.nodeid}, timeout=8)
                result["callback_ok"] = isinstance(reply, dict) and reply.get("type") == "pong"
                result["callback_route"] = self.route_description(callback_node)
            except (OSError, ValueError) as exc:
                result["callback_error"] = str(exc) or exc.__class__.__name__
            return result
        try:
            callback_port = int(packet.get("callback_port", 0))
        except (TypeError, ValueError):
            callback_port = 0
        if not 0 < callback_port < 65536:
            result["callback_error"] = "missing callback port"
            return result
        try:
            reply = self.ping_peer(addr[0], callback_port, timeout=4)
            result["callback_ok"] = isinstance(reply, dict) and reply.get("type") == "pong"
            if not result["callback_ok"]:
                result["callback_error"] = "no reply"
        except (OSError, ValueError) as exc:
            result["callback_error"] = str(exc) or exc.__class__.__name__
        return result

    def probe_reachability(self, endpoint, timeout=8):
        """Test both directions with one peer.

        Returns {"connect_ok", "callback_ok", "seen_ip", "error"}:
        connect_ok  - we could open a connection to the peer
        callback_ok - the peer could open a connection back to us
        seen_ip     - the address the peer saw us coming from
        """
        result = {"connect_ok": False, "callback_ok": False, "seen_ip": "", "error": ""}
        try:
            host, port = self.normalize_peer(endpoint)
            probe = {"type": "reach_probe", "callback_port": self.port, "nodeid": self.nodeid}
            if self.transport is not None:
                probe["callback_node"] = self.nodeid
                probe["record"] = self.transport.local_record
            reply = self.send_message(host, port, probe, timeout=timeout)
        except (OSError, ValueError) as exc:
            result["error"] = str(exc) or exc.__class__.__name__
            return result
        result["connect_ok"] = True
        result["route"] = self.route_description(mda_p2p.format_endpoint(host, port))
        if isinstance(reply, dict):
            result["seen_ip"] = str(reply.get("seen_ip", ""))
            if reply.get("type") == "reach_result":
                result["callback_ok"] = bool(reply.get("callback_ok"))
                result["error"] = str(reply.get("callback_error", ""))
                result["callback_route"] = str(reply.get("callback_route", ""))
            else:
                result["error"] = "peer runs an older version (cannot test the reverse direction)"
        return result

    def hello(self, endpoint, timeout=5):
        """Ask a node which networks it offers. Returns the hello_reply dict or None."""
        host, port = self.normalize_peer(endpoint)
        request = {"type": "hello", "nodeid": self.nodeid}
        if self.transport is not None:
            request["record"] = self.transport.local_record
        reply = self.send_message(host, port, request, timeout=timeout)
        if not (isinstance(reply, dict) and reply.get("type") == "hello_reply"):
            return None
        if self.transport is not None and isinstance(reply.get("record"), dict):
            self.transport.learn_record(reply["record"])
        return reply

    def send_message(self, host, port, payload, timeout=5):
        """Send to a node and return its reply, using whichever route works (see mda_p2p)."""
        if self.transport is not None:
            return self.transport.send(mda_p2p.format_endpoint(host, port), payload, timeout)
        return self._send_tcp(host, port, payload, timeout)

    def _send_tcp(self, host, port, payload, timeout=5):
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.sendall(mdaconnection.encode_packet(payload))
            raw = self._recv_packet(conn)
            if not raw:
                return None
            return mdaconnection.decode_packet(raw)

    def route_description(self, endpoint):
        if self.transport is None:
            return "direct"
        return self.transport.last_route.get(endpoint, "")

    def _local_endpoint(self):
        return self.nodeid

    def _normalize_endpoint_list(self, values):
        endpoints = []
        for value in values:
            try:
                host, port = self.normalize_peer(value)
                endpoints.append(f"{host}:{port}")
            except ValueError:
                continue
        return sorted(set(endpoints))

    def _build_onion_packet(
        self,
        message_type,
        network_name,
        sender_endpoint,
        receiver_endpoint,
        text,
        route,
        public_key_map,
        circuit_id,
        sender_counter,
    ):
        if not route:
            raise ValueError("Route cannot be empty")
        route_id = str(uuid.uuid4())
        final_layer = {
            "next_hop": "",
            "payload": {
                "route_id": route_id,
                "message_type": message_type,
                "packed_body": self._pack_final_body(text),
            },
        }
        receiver_key = public_key_map.get(route[-1], "")
        if not receiver_key:
            raise ValueError(f"Missing public key for receiver {route[-1]}")
        onion = self._encrypt_layer(final_layer, receiver_key)

        for index in range(len(route) - 2, -1, -1):
            hop = route[index]
            next_hop = route[index + 1]
            hop_key = public_key_map.get(hop, "")
            if not hop_key:
                raise ValueError(f"Missing public key for hop {hop}")
            layer = {"next_hop": next_hop, "inner": onion}
            onion = self._encrypt_layer(layer, hop_key)

        packet = {
            "type": message_type,
            "routing": "onion",
            "network": network_name,
            "route_id": route_id,
            "circuit_id": circuit_id,
            "msg_nonce": uuid.uuid4().hex,
            "sender_counter": sender_counter,
            "sender": sender_endpoint,
            "receiver": receiver_endpoint,
            "onion": onion,
            "time": time.time(),
        }
        return route[0], packet, route_id

    def _circuit_cache_key(self, network_name, receiver_endpoint, message_type):
        return f"{network_name}|{receiver_endpoint}|{message_type}"

    def _get_or_create_circuit(self, network_name, receiver_endpoint, message_type, relay_count, candidate_relays):
        key = self._circuit_cache_key(network_name, receiver_endpoint, message_type)
        now = time.time()
        circuit = self._circuits.get(key)
        if circuit:
            if (
                now < circuit.get("expires_at", 0.0)
                and circuit.get("use_count", 0) < circuit.get("max_uses", 8)
                and all(relay in candidate_relays for relay in circuit.get("relays", []))
            ):
                circuit["use_count"] += 1
                circuit["last_used_at"] = now
                return circuit
        shuffled = list(candidate_relays)
        random.shuffle(shuffled)
        relays = shuffled[: min(max(relay_count, 0), len(shuffled))]
        circuit = {
            "id": f"circuit-{uuid.uuid4().hex}",
            "network": network_name,
            "receiver": receiver_endpoint,
            "relays": relays,
            "created_at": now,
            "last_used_at": now,
            "expires_at": now + 120.0,
            "use_count": 1,
            "max_uses": 8,
        }
        self._circuits[key] = circuit
        return circuit

    def send_onion_message(
        self,
        receiver_endpoint,
        text,
        network_name,
        message_type="real",
        relay_count=2,
        relay_pool=None,
        public_key_map=None,
        timeout=5,
    ):
        sender_endpoint = self._local_endpoint()
        receiver_host, receiver_port = self.normalize_peer(receiver_endpoint)
        receiver_endpoint = f"{receiver_host}:{receiver_port}"
        if public_key_map is None:
            raise ValueError("public_key_map is required for encrypted onion routing")
        if receiver_endpoint not in public_key_map:
            raise ValueError(f"Missing receiver public key for {receiver_endpoint}")

        candidate_values = relay_pool if relay_pool is not None else [f"{host}:{port}" for host, port in self.peers]
        candidates = self._normalize_endpoint_list(candidate_values)
        candidates = [value for value in candidates if value not in (sender_endpoint, receiver_endpoint)]

        if relay_count < 0:
            relay_count = 0
        circuit = self._get_or_create_circuit(
            network_name=network_name,
            receiver_endpoint=receiver_endpoint,
            message_type=message_type,
            relay_count=relay_count,
            candidate_relays=candidates,
        )
        route = list(circuit.get("relays", [])) + [receiver_endpoint]
        self._sender_counter += 1
        first_hop, packet, route_id = self._build_onion_packet(
            message_type=message_type,
            network_name=network_name,
            sender_endpoint=sender_endpoint,
            receiver_endpoint=receiver_endpoint,
            text=text,
            route=route,
            public_key_map=public_key_map,
            circuit_id=circuit.get("id", ""),
            sender_counter=self._sender_counter,
        )
        first_host, first_port = self.normalize_peer(first_hop)
        response = self.send_message(first_host, first_port, packet, timeout=timeout)
        return {
            "first_hop": first_hop,
            "route": route,
            "response": response,
            "message_type": message_type,
            "route_id": route_id,
            "circuit_id": circuit.get("id", ""),
            "sender_counter": self._sender_counter,
        }

    def send_control_message(self, endpoint, payload, timeout=5):
        host, port = self.normalize_peer(endpoint)
        direct_payload = dict(payload)
        direct_payload["type"] = self.MESSAGE_CONTROL
        direct_payload["routing"] = "direct"
        return self.send_message(host, port, direct_payload, timeout=timeout)

    def send_fake_message(self, network_name, relay_pool=None, relay_count=2, public_key_map=None, timeout=5):
        candidate_values = relay_pool if relay_pool is not None else [f"{host}:{port}" for host, port in self.peers]
        candidates = self._normalize_endpoint_list(candidate_values)
        local_endpoint = self._local_endpoint()
        candidates = [value for value in candidates if value != local_endpoint]
        if not candidates:
            return {"status": "no_receiver"}
        receiver_endpoint = random.choice(candidates)
        fake_text = f"fake-{uuid.uuid4().hex[:12]}"
        return self.send_onion_message(
            receiver_endpoint=receiver_endpoint,
            text=fake_text,
            network_name=network_name,
            message_type=self.MESSAGE_FAKE,
            relay_count=relay_count,
            relay_pool=candidates,
            public_key_map=public_key_map,
            timeout=timeout,
        )

    def broadcast(self, payload):
        with self.client_lock:
            for host, port in self.peers:
                try:
                    self.send_message(host, port, payload)
                except (OSError, ValueError):
                    continue

    def close(self):
        if self.transport is not None:
            self.transport.close()
        if self.server_socket is not None:
            try:
                # Wake the thread blocked in accept(); close() alone does not on Linux.
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.server_socket.close()
            except OSError:
                pass
            self.server_socket = None


def get_ip_addresses():
    return ["127.0.0.1"]
