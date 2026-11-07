"""LAN discovery for MDANetPro ("Networks nearby").

Seed/trusted nodes broadcast a small UDP announcement for each discoverable network.
Other nodes on the same LAN collect them so the user can join with one click instead
of copying a .mdar file. Joining still needs approval from the seed/trusted node.
"""
import json
import socket
import threading
import time

from mda_netutils import broadcast_targets

DISCOVERY_PORT = 50405
MAGIC = "MDANetPro/announce/1"
STALE_AFTER = 12.0  # seconds without an announcement before a network disappears


class LanDiscovery:
    def __init__(self, port=DISCOVERY_PORT, own_endpoint_getter=None):
        self.port = int(port)
        self._own_endpoint_getter = own_endpoint_getter or (lambda: "")
        self._sock = None
        self._thread = None
        self._running = False
        self._lock = threading.Lock()
        self._seen = {}  # (network, endpoint) -> announcement dict
        self.listen_error = ""

    # ---- listening -------------------------------------------------------------
    def start(self):
        if self._running:
            return self
        self._running = True
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind(("", self.port))
            sock.settimeout(1.0)
            self._sock = sock
        except OSError as exc:
            self.listen_error = str(exc)
            self._sock = None
            return self
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _listen_loop(self):
        while self._running and self._sock is not None:
            try:
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.handle_datagram(data, addr)

    def handle_datagram(self, data, addr):
        try:
            message = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return
        if not isinstance(message, dict) or message.get("magic") != MAGIC:
            return
        network = str(message.get("network", "")).strip()
        endpoint = str(message.get("endpoint", "")).strip()
        if not network or not endpoint or endpoint == self._own_endpoint_getter():
            return
        message["seen_from"] = addr[0]
        message["last_seen"] = time.time()
        with self._lock:
            self._seen[(network, endpoint)] = message

    def nearby(self):
        """Fresh announcements, newest first."""
        cutoff = time.time() - STALE_AFTER
        with self._lock:
            for key in [k for k, v in self._seen.items() if v.get("last_seen", 0) < cutoff]:
                del self._seen[key]
            items = list(self._seen.values())
        items.sort(key=lambda item: (item.get("network", "").lower(), item.get("endpoint", "")))
        return items

    # ---- announcing ------------------------------------------------------------
    @staticmethod
    def build_announcement(network, info):
        payload = dict(info)
        payload["magic"] = MAGIC
        payload["network"] = network
        return payload

    def announce(self, announcements):
        """Broadcast each announcement dict on every local interface."""
        if not announcements:
            return 0
        sent = 0
        for broadcast_ip, source_ip in broadcast_targets():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    if source_ip:
                        sock.bind((source_ip, 0))  # pick the outgoing adapter on Windows
                    for item in announcements:
                        body = json.dumps(item, separators=(",", ":")).encode("utf-8")
                        if len(body) > 1400:
                            continue
                        sock.sendto(body, (broadcast_ip, self.port))
                        sent += 1
            except OSError:
                continue
        return sent
