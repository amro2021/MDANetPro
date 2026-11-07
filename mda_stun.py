"""Minimal STUN (RFC 5389) client and server.

The client asks a STUN server "what address do you see me as?" from the node's own
UDP socket. That public address is what other peers must send to for UDP hole
punching. Asking two different servers also reveals the NAT type: if they see two
different ports, the NAT is *symmetric* (hole punching will not work, use a relay).
"""
import os
import socket
import struct
import threading

MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020

# Free public STUN servers (two different operators so NAT type detection works).
DEFAULT_SERVERS = (
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun1.l.google.com", 19302),
)


def is_stun_packet(data):
    return len(data) >= 20 and data[0] & 0xC0 == 0 and struct.unpack("!I", data[4:8])[0] == MAGIC_COOKIE


def build_request(transaction_id=None):
    transaction_id = transaction_id or os.urandom(12)
    return struct.pack("!HHI12s", BINDING_REQUEST, 0, MAGIC_COOKIE, transaction_id), transaction_id


def parse_response(data):
    """Return (transaction_id, (ip, port)) for a binding success response, else None."""
    if not is_stun_packet(data):
        return None
    msg_type, length, _cookie, transaction_id = struct.unpack("!HHI12s", data[:20])
    if msg_type != BINDING_SUCCESS:
        return None
    offset, end = 20, min(len(data), 20 + length)
    mapped = None
    while offset + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
        value = data[offset + 4:offset + 4 + attr_len]
        if attr_type in (ATTR_XOR_MAPPED_ADDRESS, ATTR_MAPPED_ADDRESS) and len(value) >= 8:
            family = value[1]
            port = struct.unpack("!H", value[2:4])[0]
            if family == 0x01:
                raw = value[4:8]
                if attr_type == ATTR_XOR_MAPPED_ADDRESS:
                    port ^= MAGIC_COOKIE >> 16
                    raw = bytes(b ^ c for b, c in zip(raw, struct.pack("!I", MAGIC_COOKIE)))
                address = (socket.inet_ntoa(raw), port)
                if attr_type == ATTR_XOR_MAPPED_ADDRESS or mapped is None:
                    mapped = address
        offset += 4 + attr_len + ((4 - attr_len % 4) % 4)
    return (transaction_id, mapped) if mapped else None


def build_response(transaction_id, address):
    ip, port = address
    xport = port ^ (MAGIC_COOKIE >> 16)
    xip = bytes(b ^ c for b, c in zip(socket.inet_aton(ip), struct.pack("!I", MAGIC_COOKIE)))
    attr = struct.pack("!HHBBH4s", ATTR_XOR_MAPPED_ADDRESS, 8, 0, 0x01, xport, xip)
    return struct.pack("!HHI12s", BINDING_SUCCESS, len(attr), MAGIC_COOKIE, transaction_id) + attr


class StunServer:
    """Tiny STUN server (used by tests; can also run on any public machine)."""

    def __init__(self, host="0.0.0.0", port=3478):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.5)
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self._running:
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if is_stun_packet(data) and struct.unpack("!H", data[:2])[0] == BINDING_REQUEST:
                self.sock.sendto(build_response(data[8:20], addr), addr)

    def close(self):
        self._running = False
        self.sock.close()


def classify(results, local_port):
    """Turn [(server, (ip, port)), ...] into a NAT summary dict."""
    mapped = [address for _server, address in results if address]
    if not mapped:
        return {"public": None, "nat": "unknown"}
    ips = {ip for ip, _port in mapped}
    ports = {port for _ip, port in mapped}
    public = mapped[0]
    if len(mapped) >= 2 and (len(ips) > 1 or len(ports) > 1):
        nat = "symmetric"
    elif public[1] == local_port:
        nat = "cone-preserving"  # also true for no NAT at all
    else:
        nat = "cone"
    return {"public": public, "nat": nat}
