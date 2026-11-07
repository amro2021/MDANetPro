"""Peer-to-peer transport for MDANetPro: reach nodes on other networks.

Every node has a stable address derived from its public key:

    <fingerprint>.mda:<port>        e.g. 3f9a0c2e5b7d11aa8c42.mda:50404

and publishes a signed *route record* listing the ways to reach it right now:

    lan    - its LAN address (works when both nodes share a network)
    ipv6   - a global IPv6 address (no NAT involved)
    public - a public IPv4 port opened by UPnP / NAT-PMP or a manual port-forward
    udp    - its public UDP address seen by STUN (for hole punching)
    relay  - a reachable member that forwards traffic to it

The fingerprint is a hash of the public key, so a record can be checked by anyone:
only the key owner can sign a record for that address. Nothing central is needed;
the route records travel with join requests, member lists, .mdar files and updates.

When sending, routes are tried in this order: LAN -> IPv6 -> public -> existing UDP
session -> UDP hole punch -> relay. The route that works is cached.
"""
import base64
import hashlib
import ipaddress
import json
import os
import random
import socket
import threading
import time
import uuid

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

import mda_stun

VIRTUAL_SUFFIX = ".mda"
UDP_MAGIC = b"MDAU"
UDP_REQ, UDP_RESP, UDP_PUNCH, UDP_PUNCH_ACK, UDP_KEEPALIVE = 1, 2, 3, 4, 5
UDP_CHUNK = 1100
RECORD_MAX_AGE = 30 * 24 * 3600  # routes are only hints; the signature is what matters


# ------------------------------------------------------------------ addresses
def fingerprint(pubkey_pem):
    normalized = "".join(str(pubkey_pem or "").split())
    return hashlib.sha256(normalized.encode("ascii", errors="ignore")).hexdigest()[:20]


def node_address(pubkey_pem, port):
    return f"{fingerprint(pubkey_pem)}{VIRTUAL_SUFFIX}:{int(port)}"


def split_endpoint(endpoint):
    """'host:port', '[v6]:port' or 'v6:port' -> (host_without_brackets, port)."""
    text = str(endpoint).strip()
    if text.startswith("["):
        host, _, port = text[1:].partition("]:")
        return host, int(port)
    host, port = text.rsplit(":", 1)
    return host, int(port)


def format_endpoint(host, port):
    return f"[{host}]:{int(port)}" if ":" in str(host) else f"{host}:{int(port)}"


def is_virtual(endpoint):
    try:
        host, _port = split_endpoint(endpoint)
    except (ValueError, AttributeError):
        return False
    return host.endswith(VIRTUAL_SUFFIX)


_V6_CACHE = {"time": 0.0, "value": []}


def global_ipv6_addresses():
    now = time.time()
    if now - _V6_CACHE["time"] < 15:
        return list(_V6_CACHE["value"])
    _V6_CACHE["value"] = _global_ipv6_uncached()
    _V6_CACHE["time"] = now
    return list(_V6_CACHE["value"])


def _global_ipv6_uncached():
    found = []
    try:  # which IPv6 source address would reach the internet (no packet is sent)
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.connect(("2001:4860:4860::8888", 80))
            found.append(sock.getsockname()[0].split("%")[0])
    except OSError:
        pass
    box = []

    def lookup():
        try:
            box.extend(info[4][0].split("%")[0] for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6))
        except OSError:
            pass

    thread = threading.Thread(target=lookup, daemon=True)
    thread.start()
    thread.join(1.0)
    found.extend(box)
    try:
        import psutil  # type: ignore

        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family == socket.AF_INET6:
                    found.append(addr.address.split("%")[0])
    except Exception:
        pass
    result = []
    for value in found:
        try:
            addr = ipaddress.IPv6Address(value)
        except ValueError:
            continue
        if addr in ipaddress.IPv6Network("2000::/3") and not addr.is_multicast and value not in result:
            result.append(value)
    return result[:2]


def _servers_from_env():
    """MDANET_STUN_SERVERS="host:port,host:port" overrides the public STUN servers."""
    result = []
    for item in os.environ.get("MDANET_STUN_SERVERS", "").split(","):
        item = item.strip()
        if item:
            try:
                result.append(split_endpoint(item))
            except ValueError:
                continue
    return result


# ------------------------------------------------------------------ route records
def _canonical(data):
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign_record(record, private_key):
    body = {key: value for key, value in record.items() if key != "sig"}
    signature = pss.new(private_key).sign(SHA256.new(_canonical(body)))
    signed = dict(body)
    signed["sig"] = base64.b64encode(signature).decode("ascii")
    return signed


def verify_record(record, max_age=RECORD_MAX_AGE):
    """True if the record is signed by the key its address was derived from."""
    if not isinstance(record, dict):
        return False
    try:
        pubkey = str(record["pubkey"])
        host, _port = split_endpoint(record["node"])
        if host != fingerprint(pubkey) + VIRTUAL_SUFFIX:
            return False
        if max_age and abs(time.time() - float(record.get("time", 0))) > max_age:
            return False
        body = {key: value for key, value in record.items() if key != "sig"}
        pss.new(RSA.import_key(pubkey)).verify(SHA256.new(_canonical(body)), base64.b64decode(record["sig"]))
        return True
    except (KeyError, ValueError, TypeError):
        return False


def _interfaces_with_networks():
    try:
        from mda_netutils import _interfaces
    except ImportError:
        return []
    result = []
    for _name, ip, mask in _interfaces():
        try:
            net = ipaddress.IPv4Network(f"{ip}/{mask or 24}", strict=False)
        except ValueError:
            continue
        result.append((ip, str(net)))
    return result


# ------------------------------------------------------------------ transport
class P2PTransport:
    def __init__(self, node, stun_servers=None):
        self.node = node
        self.stun_servers = list(stun_servers or _servers_from_env() or mda_stun.DEFAULT_SERVERS)
        self.records = {}  # node address -> verified route record
        self.local_record = None
        self.route_cache = {}  # endpoint -> (kind, address, expires)
        self.failed_routes = {}  # (endpoint, kind, address) -> retry_after
        self.last_route = {}  # endpoint -> human readable description of the route used
        self.stun_result = {"public": None, "nat": "unknown"}
        self.port_mapping = None  # dict from mda_nat.open_port
        self.manual_public = ""  # "host:port" set by the user (router port-forward)
        self.relays = []  # node addresses we keep a relay connection to
        self.relay_status = {}  # relay -> "connected" / error text
        self.relay_policy = None  # callable(pubkey_pem) -> bool, for our relay server
        self.on_record_changed = None  # callable(record)
        self._relay_sessions = {}  # (server side) node address -> _RelaySession
        self._relay_clients = {}  # (client side) relay -> thread state
        self._lock = threading.RLock()
        self._udp = None
        self._udp_sessions = {}  # endpoint -> {"addr": (ip, port), "last": t}
        self._udp_waiters = {}  # msg_id -> [event, reply]
        self._udp_partial = {}
        self._udp_reply_cache = {}
        self._punch_tokens = {}  # token -> [event, endpoint, addr]
        self._stun_waiters = {}
        self._running = False
        self.debug = None  # optional callable(str) for route diagnostics

    # ---------------------------------------------------------- lifecycle
    def start(self):
        self._running = True
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind(("0.0.0.0", self.node.port))
            sock.settimeout(0.5)
            self._udp = sock
            threading.Thread(target=self._udp_loop, daemon=True).start()
        except OSError:
            self._udp = None
        threading.Thread(target=self._keepalive_loop, daemon=True).start()
        self.refresh_local_record()

    def close(self):
        self._running = False
        for state in list(self._relay_clients.values()):
            state["stop"] = True
            conn = state.get("conn")
            if conn is not None:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    conn.close()
                except OSError:
                    pass
        for session in list(self._relay_sessions.values()):
            session.close()
        if self._udp is not None:
            try:
                self._udp.close()
            except OSError:
                pass
            self._udp = None

    # ---------------------------------------------------------- NAT discovery
    def discover_nat(self, use_upnp=True, upnp_kwargs=None):
        """Run STUN (and UPnP/NAT-PMP if enabled), then refresh the route record. Blocking."""
        self.stun_result = self.stun_probe()
        if use_upnp:
            try:
                import mda_nat

                mapping = mda_nat.open_port(self.node.host, self.node.port, **(upnp_kwargs or {}))
            except Exception:
                mapping = None
            if mapping and mapping.get("external_ip"):
                public = (self.stun_result.get("public") or (None,))[0]
                ext = mapping["external_ip"]
                # Double NAT: the router's "external" address is itself private.
                mapping["usable"] = mda_nat.is_public_ipv4(ext) and (public is None or public == ext)
            self.port_mapping = mapping
        self.refresh_local_record()
        return {"stun": self.stun_result, "mapping": self.port_mapping}

    def stun_probe(self, timeout=1.5):
        if self._udp is None:
            return {"public": None, "nat": "unknown"}
        results = []
        for server in self.stun_servers[:3]:
            try:
                address = socket.getaddrinfo(server[0], server[1], socket.AF_INET, socket.SOCK_DGRAM)[0][4]
            except (OSError, IndexError):
                continue
            request, txid = mda_stun.build_request()
            event = threading.Event()
            self._stun_waiters[txid] = [event, None]
            mapped = None
            for _attempt in range(2):
                try:
                    self._udp.sendto(request, address)
                except OSError:
                    break
                if event.wait(timeout):
                    mapped = self._stun_waiters[txid][1]
                    break
            self._stun_waiters.pop(txid, None)
            results.append((server, mapped))
            if len([r for r in results if r[1]]) >= 2:
                break
        return mda_stun.classify(results, self.node.port)

    # ---------------------------------------------------------- local record
    def build_routes(self):
        port = self.node.port
        routes = []
        for ip, net in _interfaces_with_networks()[:3]:
            routes.append({"t": "tcp", "a": format_endpoint(ip, port), "s": "lan", "net": net})
        if not routes and self.node.host:
            routes.append({"t": "tcp", "a": format_endpoint(self.node.host, port), "s": "lan", "net": ""})
        for ip in global_ipv6_addresses():
            routes.append({"t": "tcp", "a": format_endpoint(ip, port), "s": "ipv6"})
        mapping = self.port_mapping or {}
        if mapping.get("usable"):
            routes.append({"t": "tcp", "a": format_endpoint(mapping["external_ip"], mapping["tcp_port"]), "s": "public", "m": mapping.get("method", "")})
            if mapping.get("udp_port"):
                routes.append({"t": "udp", "a": format_endpoint(mapping["external_ip"], mapping["udp_port"]), "s": "public"})
        if self.manual_public:
            try:
                host, mport = split_endpoint(self.manual_public if ":" in self.manual_public else f"{self.manual_public}:{port}")
                routes.append({"t": "tcp", "a": format_endpoint(host, mport), "s": "public", "m": "manual"})
            except ValueError:
                pass
        public = self.stun_result.get("public")
        if public:
            routes.append({"t": "udp", "a": format_endpoint(public[0], public[1]), "s": "stun"})
        for relay in self.relays:
            if self.relay_status.get(relay) == "connected":
                routes.append({"t": "relay", "a": relay, "via": self._direct_addresses(relay)[:3]})
        return routes

    def refresh_local_record(self):
        # Serialized: two threads rebuilding at once could publish the older state last.
        with self._lock:
            return self._refresh_local_record_locked()

    def _refresh_local_record_locked(self):
        public = self.stun_result.get("public")
        mapping = self.port_mapping or {}
        record = {
            "node": self.node.nodeid,
            "pubkey": self.node.get_public_key_pem(),
            "routes": self.build_routes(),
            "pub_ip": public[0] if public else (mapping.get("external_ip", "") if mapping.get("usable") else ""),
            "nat": self.stun_result.get("nat", "unknown"),
            "time": time.time(),
        }
        record["reachable"] = any(r["t"] == "tcp" and r["s"] in ("public", "ipv6") for r in record["routes"])
        old = self.local_record
        self.local_record = sign_record(record, self.node._private_key)
        self.records[self.node.nodeid] = self.local_record
        if old is None or self._record_meaning(old) != self._record_meaning(self.local_record):
            if callable(self.on_record_changed):
                try:
                    self.on_record_changed(self.local_record)
                except Exception:
                    pass
        return self.local_record

    @staticmethod
    def _record_meaning(record):
        return json.dumps([record.get("routes"), record.get("nat"), record.get("pub_ip")], sort_keys=True)

    def is_reachable(self):
        return bool(self.local_record and self.local_record.get("reachable"))

    def connectivity_summary(self):
        record = self.local_record or {}
        routes = record.get("routes", [])
        public = [r for r in routes if r["t"] == "tcp" and r["s"] == "public"]
        ipv6 = [r for r in routes if r["t"] == "tcp" and r["s"] == "ipv6"]
        relays = [r["a"] for r in routes if r["t"] == "relay"]
        if public:
            how = public[0].get("m") or "port-forward"
            return f"reachable from the internet at {public[0]['a']} ({how})"
        if ipv6:
            return f"reachable over IPv6 at {ipv6[0]['a']}"
        nat = record.get("nat", "unknown")
        if relays:
            return f"behind NAT ({nat}); others reach you via {len(relays)} relay(s)"
        return f"behind NAT ({nat}); reachable on your local network only"

    # ---------------------------------------------------------- records from others
    def learn_record(self, record):
        """Store a peer's route record if it is valid and newer. Returns True if stored."""
        if not verify_record(record):
            return False
        node = record["node"]
        if node == self.node.nodeid:
            return False
        with self._lock:
            current = self.records.get(node)
            if current and float(current.get("time", 0)) >= float(record.get("time", 0)):
                return False
            self.records[node] = record
            self.route_cache.pop(node, None)
            for key in [k for k in self.failed_routes if k[0] == node]:
                del self.failed_routes[key]  # new routes: earlier failures no longer apply
        return True

    def _direct_addresses(self, endpoint):
        record = self.records.get(endpoint) or {}
        return [r["a"] for r in record.get("routes", []) if r.get("t") == "tcp"]

    # ---------------------------------------------------------- route selection
    def _my_networks(self):
        return [ipaddress.IPv4Network(net) for _ip, net in _interfaces_with_networks()]

    def candidate_routes(self, endpoint):
        """Ordered list of (kind, address) to try for a virtual endpoint."""
        record = self.records.get(endpoint)
        if not record:
            return [("self-relay", self.node.nodeid)] if endpoint in self._relay_sessions else []
        routes = record.get("routes", [])
        if not routes:
            return [("self-relay", self.node.nodeid)] if endpoint in self._relay_sessions else []
        mine = self.local_record or {}
        my_nets = self._my_networks()
        my_ips = {ip for ip, _net in _interfaces_with_networks()} | {self.node.host}
        both_known = bool(mine.get("pub_ip")) and bool(record.get("pub_ip"))
        same_public = both_known and mine.get("pub_ip") == record.get("pub_ip")
        ordered = []

        def own_address(address):
            try:
                host, port = split_endpoint(address)
            except ValueError:
                return True
            return host in my_ips and port == self.node.port

        def add(kind, address):
            if (kind, address) not in ordered:
                ordered.append((kind, address))

        for route in routes:  # 1. same LAN (same public IP; or same subnet when that is unknown)
            if route["t"] == "tcp" and route["s"] == "lan" and not own_address(route["a"]):
                try:
                    in_my_net = route.get("net") and any(ipaddress.IPv4Network(route["net"]) == net for net in my_nets)
                except ValueError:
                    in_my_net = False
                if same_public or (in_my_net and not both_known):
                    add("tcp", route["a"])
        if global_ipv6_addresses():  # 2. IPv6
            for route in routes:
                if route["t"] == "tcp" and route["s"] == "ipv6":
                    add("tcp", route["a"])
        for route in routes:  # 3. public port
            if route["t"] == "tcp" and route["s"] == "public":
                add("tcp", route["a"])
        if endpoint in self._udp_sessions:  # 4. existing UDP session
            add("udp", "session")
        udp_routes = [r for r in routes if r["t"] == "udp"]
        if udp_routes and self._udp is not None and record.get("nat") != "symmetric" and mine.get("nat") != "symmetric":
            add("punch", "")  # 5. hole punching
        for route in routes:  # 6. relays
            if route["t"] == "relay" and route["a"] != self.node.nodeid:
                add("relay", route["a"])
        if endpoint in self._relay_sessions or self.node.nodeid in [r["a"] for r in routes if r["t"] == "relay"]:
            add("self-relay", self.node.nodeid)  # it keeps a connection open to us
        if not both_known:  # 7. LAN addresses we could not confirm, last
            for route in routes:
                if route["t"] == "tcp" and route["s"] == "lan" and not own_address(route["a"]):
                    add("tcp", route["a"])
        return ordered

    def send(self, endpoint, payload, timeout=5):
        """Deliver payload to endpoint and return its reply. Raises OSError if every route fails."""
        if endpoint == self.node.nodeid:
            return self.node._process_packet(dict(payload), ("127.0.0.1", 0))
        if not is_virtual(endpoint):
            host, port = split_endpoint(endpoint)
            return self.node._send_tcp(host, port, payload, timeout)
        candidates = self.candidate_routes(endpoint)
        if not candidates:
            if endpoint not in self.records:
                raise OSError(f"no route to {endpoint} (unknown node: its route record has not been received)")
            raise OSError(f"no usable route to {endpoint}: it is behind NAT and has no relay yet")
        cached = self.route_cache.get(endpoint)
        if cached and cached[2] > time.time() and (cached[0], cached[1]) in candidates:
            candidates.remove((cached[0], cached[1]))
            candidates.insert(0, (cached[0], cached[1]))
        errors = []
        now = time.time()
        skip_failed = any(self.failed_routes.get((endpoint, k, a), 0) <= now for k, a in candidates)
        for kind, address in candidates:
            key = (endpoint, kind, address)
            recently_failed = self.failed_routes.get(key, 0) > now
            if skip_failed and recently_failed and not (cached and (kind, address) == (cached[0], cached[1])):
                continue  # (if every route failed recently, try them all again anyway)
            started = time.time()
            try:
                reply = self._send_on(endpoint, kind, address, payload, timeout)
            except (OSError, ValueError) as exc:
                self.failed_routes[key] = time.time() + 60
                errors.append(f"{kind} {address}: {exc}".strip())
                self._debug(f"route {kind} {address} to {endpoint} failed after {time.time() - started:.1f}s: {exc}")
                continue
            self._debug(f"route {kind} {address} to {endpoint} ok in {time.time() - started:.1f}s")
            self.failed_routes.pop(key, None)
            self.route_cache[endpoint] = (kind, address, time.time() + 300)
            self.last_route[endpoint] = self.describe_route(endpoint, kind, address)
            return reply
        raise OSError(f"all routes to {endpoint} failed: " + ("; ".join(errors) or "none usable"))

    def _debug(self, text):
        if callable(self.debug):
            try:
                self.debug(text)
            except Exception:
                pass

    def describe_route(self, endpoint, kind, address):
        if kind == "tcp":
            record = self.records.get(endpoint) or {}
            scope = next((r["s"] for r in record.get("routes", []) if r.get("a") == address), "")
            return {"lan": "direct (same network)", "ipv6": "direct (IPv6)", "public": "direct (internet)"}.get(scope, "direct") + f" {address}"
        if kind in ("udp", "punch"):
            session = self._udp_sessions.get(endpoint, {})
            addr = session.get("addr")
            return "direct (UDP hole punch)" + (f" {format_endpoint(*addr)}" if addr else "")
        if kind == "relay":
            return f"via relay {address}"
        if kind == "self-relay":
            return "via its connection to you"
        return kind

    def _send_on(self, endpoint, kind, address, payload, timeout):
        payload = dict(payload)
        payload["_to"] = endpoint  # the receiver rejects packets meant for another node
        reply = self._send_on_raw(endpoint, kind, address, payload, timeout)
        if isinstance(reply, dict) and reply.get("status") == "wrong_node":
            raise OSError(f"reached a different node ({reply.get('nodeid', '?')})")
        return reply

    def _send_on_raw(self, endpoint, kind, address, payload, timeout):
        if kind == "tcp":
            host, port = split_endpoint(address)
            short = min(timeout, 2.5) if self._route_scope(endpoint, address) == "lan" else timeout
            return self.node._send_tcp(host, port, payload, short)
        if kind == "udp":
            return self._udp_request(endpoint, payload, timeout)
        if kind == "punch":
            self.punch(endpoint, timeout=min(timeout, 4))
            return self._udp_request(endpoint, payload, timeout)
        if kind == "relay":
            return self._send_via_relay(address, endpoint, payload, timeout)
        if kind == "self-relay":
            session = self._relay_sessions.get(endpoint)
            if session is None:
                raise OSError("not connected to us as a relay")
            return session.request(payload, timeout)
        raise ValueError(f"unknown route kind {kind}")

    def _route_scope(self, endpoint, address):
        record = self.records.get(endpoint) or {}
        return next((r["s"] for r in record.get("routes", []) if r.get("a") == address), "")

    def _send_direct_only(self, endpoint, payload, timeout):
        """Reach a node without relays or UDP (used to talk to relays themselves)."""
        if not is_virtual(endpoint):
            host, port = split_endpoint(endpoint)
            return self.node._send_tcp(host, port, payload, timeout)
        errors = []
        for kind, address in self.candidate_routes(endpoint):
            if kind != "tcp":
                continue
            try:
                host, port = split_endpoint(address)
                return self.node._send_tcp(host, port, payload, min(timeout, 3))
            except OSError as exc:
                errors.append(str(exc))
        raise OSError("no direct route: " + "; ".join(errors))

    def _send_via_relay(self, relay, endpoint, payload, timeout):
        forward = {"type": "relay_forward", "to": endpoint, "packet": payload}
        try:
            reply = self._send_direct_only(relay, forward, timeout + 1)
        except OSError:
            # We may not know the relay itself (e.g. a web gateway): use the addresses the
            # target listed for it in its own signed record.
            reply = None
            for route in (self.records.get(endpoint) or {}).get("routes", []):
                if route.get("t") == "relay" and route.get("a") == relay:
                    for address in route.get("via") or []:
                        try:
                            host, port = split_endpoint(address)
                            reply = self.node._send_tcp(host, port, forward, timeout + 1)
                            break
                        except (OSError, ValueError):
                            continue
            if reply is None:
                raise
        if not isinstance(reply, dict) or reply.get("type") != "relay_result":
            raise OSError("relay gave no answer")
        if not reply.get("ok"):
            raise OSError(f"relay: {reply.get('error', 'failed')}")
        return reply.get("reply")

    # ---------------------------------------------------------- relay server side
    def handle_relay_register(self, conn, packet, addr):
        """Runs on the relay: keep the connection and forward packets down it."""
        record = packet.get("record")
        if not verify_record(record):
            conn.sendall(_frame({"type": "relay_registered", "ok": False, "error": "invalid record"}))
            return
        if callable(self.relay_policy) and not self.relay_policy(record.get("pubkey", "")):
            conn.sendall(_frame({"type": "relay_registered", "ok": False, "error": "not a member"}))
            return
        self.learn_record(record)
        endpoint = record["node"]
        session = _RelaySession(conn, endpoint)
        old = self._relay_sessions.get(endpoint)
        self._relay_sessions[endpoint] = session
        if old is not None:
            old.close()
        session.write({"type": "relay_registered", "ok": True, "seen_ip": addr[0]})
        try:
            session.read_loop()
        finally:
            if self._relay_sessions.get(endpoint) is session:
                del self._relay_sessions[endpoint]

    def handle_relay_forward(self, packet):
        target = str(packet.get("to", ""))
        inner = packet.get("packet")
        if not isinstance(inner, dict):
            return {"type": "relay_result", "ok": False, "error": "bad packet"}
        if target == self.node.nodeid:
            return {"type": "relay_result", "ok": True, "reply": self.node._process_packet(inner, ("relay", 0))}
        session = self._relay_sessions.get(target)
        if session is None:
            return {"type": "relay_result", "ok": False, "error": "target not connected to this relay"}
        try:
            return {"type": "relay_result", "ok": True, "reply": session.request(inner, 8)}
        except OSError as exc:
            return {"type": "relay_result", "ok": False, "error": str(exc)}

    def relay_clients(self):
        return sorted(self._relay_sessions)

    # ---------------------------------------------------------- relay client side
    def set_relays(self, relays):
        relays = [r for r in relays if r and r != self.node.nodeid][:2]
        for relay in list(self._relay_clients):
            if relay not in relays:
                state = self._relay_clients.pop(relay)
                state["stop"] = True
                if state.get("conn") is not None:
                    try:
                        state["conn"].shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                self.relay_status.pop(relay, None)
        self.relays = relays
        for relay in relays:
            if relay not in self._relay_clients:
                state = {"stop": False, "conn": None}
                self._relay_clients[relay] = state
                threading.Thread(target=self._relay_client_loop, args=(relay, state), daemon=True).start()
        self.refresh_local_record()

    def _relay_client_loop(self, relay, state):
        backoff = 2
        while self._running and not state["stop"]:
            conn = None
            try:
                conn = self._open_direct(relay, timeout=5)
                state["conn"] = conn
                conn.settimeout(None)
                write_lock = threading.Lock()
                record = self.local_record or self.refresh_local_record()
                conn.sendall(_frame({"type": "relay_register", "record": record}))
                answer = _read_frame(conn)
                if not answer or not answer.get("ok"):
                    raise OSError((answer or {}).get("error", "registration refused"))
                self.relay_status[relay] = "connected"
                self.refresh_local_record()
                backoff = 2
                stop_ping = threading.Event()

                def pinger():
                    while not stop_ping.wait(20):
                        try:
                            with write_lock:
                                conn.sendall(_frame({"type": "relay_ping"}))
                        except OSError:
                            return

                threading.Thread(target=pinger, daemon=True).start()
                try:
                    while not state["stop"]:
                        frame = _read_frame(conn)
                        if frame is None:
                            break
                        if frame.get("type") == "relay_deliver":
                            threading.Thread(target=self._answer_relayed, args=(conn, write_lock, frame), daemon=True).start()
                finally:
                    stop_ping.set()
            except (OSError, ValueError) as exc:
                self.relay_status[relay] = f"error: {exc}"
            finally:
                state["conn"] = None
                if conn is not None:
                    try:
                        conn.close()
                    except OSError:
                        pass
            if self.relay_status.get(relay) == "connected":
                self.relay_status[relay] = "disconnected"
            if self._running and not state["stop"]:
                self.refresh_local_record()
                time.sleep(backoff + random.random())
                backoff = min(backoff * 2, 30)

    def _open_direct(self, endpoint, timeout):
        addresses = [endpoint] if not is_virtual(endpoint) else [a for k, a in self.candidate_routes(endpoint) if k == "tcp"]
        last = None
        for address in addresses:
            host, port = split_endpoint(address)
            try:
                return socket.create_connection((host, port), timeout=timeout)
            except OSError as exc:
                last = exc
        raise OSError(f"cannot reach relay {endpoint}: {last}")

    def _answer_relayed(self, conn, write_lock, frame):
        packet = frame.get("packet") if isinstance(frame.get("packet"), dict) else {}
        try:
            reply = self.node._process_packet(packet, ("relay", 0))
        except Exception as exc:  # never kill the relay connection
            reply = {"status": "error", "error": str(exc)}
        try:
            with write_lock:
                conn.sendall(_frame({"type": "relay_reply", "rid": frame.get("rid"), "reply": reply}))
        except OSError:
            pass

    # ---------------------------------------------------------- UDP
    def _udp_send_frames(self, addr, kind, msg_id, data):
        chunks = [data[i:i + UDP_CHUNK] for i in range(0, len(data), UDP_CHUNK)] or [b""]
        for index, chunk in enumerate(chunks):
            header = UDP_MAGIC + bytes([kind]) + msg_id + index.to_bytes(2, "big") + len(chunks).to_bytes(2, "big")
            self._udp.sendto(header + chunk, addr)

    def _udp_loop(self):
        while self._running and self._udp is not None:
            try:
                data, addr = self._udp.recvfrom(65535)
            except socket.timeout:
                self._cleanup_udp()
                continue
            except OSError:
                if not self._running:
                    break
                continue
            if mda_stun.is_stun_packet(data):
                parsed = mda_stun.parse_response(data)
                if parsed and parsed[0] in self._stun_waiters:
                    self._stun_waiters[parsed[0]][1] = parsed[1]
                    self._stun_waiters[parsed[0]][0].set()
                continue
            if len(data) < 25 or not data.startswith(UDP_MAGIC):
                continue
            kind = data[4]
            msg_id = data[5:21]
            index = int.from_bytes(data[21:23], "big")
            count = int.from_bytes(data[23:25], "big")
            chunk = data[25:]
            if kind in (UDP_PUNCH, UDP_PUNCH_ACK, UDP_KEEPALIVE):
                self._handle_punch_frame(kind, chunk, addr)
                continue
            if count == 0 or count > 2000 or index >= count:
                continue
            key = (addr, msg_id, kind)
            entry = self._udp_partial.setdefault(key, {"parts": {}, "count": count, "time": time.time()})
            entry["parts"][index] = chunk
            if len(entry["parts"]) < entry["count"]:
                continue
            del self._udp_partial[key]
            body = b"".join(entry["parts"][i] for i in range(entry["count"]))
            if kind == UDP_REQ:
                threading.Thread(target=self._udp_serve, args=(addr, msg_id, body), daemon=True).start()
            elif kind == UDP_RESP and msg_id in self._udp_waiters:
                try:
                    self._udp_waiters[msg_id][1] = json.loads(body.decode("utf-8"))
                except ValueError:
                    self._udp_waiters[msg_id][1] = None
                self._udp_waiters[msg_id][0].set()

    def _cleanup_udp(self):
        cutoff = time.time() - 30
        for key in [k for k, v in self._udp_partial.items() if v["time"] < cutoff]:
            self._udp_partial.pop(key, None)
        for key in [k for k, v in self._udp_reply_cache.items() if v[0] < cutoff]:
            self._udp_reply_cache.pop(key, None)

    def _udp_serve(self, addr, msg_id, body):
        cached = self._udp_reply_cache.get(msg_id)
        if cached is None:
            try:
                request = json.loads(body.decode("utf-8"))
                sender = str(request.get("from", ""))
                if sender:
                    self._udp_sessions[sender] = {"addr": addr, "last": time.time()}
                reply = self.node._process_packet(request.get("packet") or {}, addr)
            except Exception as exc:
                reply = {"status": "error", "error": str(exc)}
            cached = (time.time(), json.dumps(reply, separators=(",", ":")).encode("utf-8"))
            self._udp_reply_cache[msg_id] = cached
        try:
            self._udp_send_frames(addr, UDP_RESP, msg_id, cached[1])
        except OSError:
            pass

    def _udp_request(self, endpoint, payload, timeout):
        session = self._udp_sessions.get(endpoint)
        if session is None or self._udp is None:
            raise OSError("no UDP session")
        msg_id = uuid.uuid4().bytes
        body = json.dumps({"from": self.node.nodeid, "packet": payload}, separators=(",", ":")).encode("utf-8")
        event = threading.Event()
        self._udp_waiters[msg_id] = [event, None]
        try:
            deadline = time.time() + timeout
            while time.time() < deadline:
                self._udp_send_frames(session["addr"], UDP_REQ, msg_id, body)
                if event.wait(min(1.0, max(0.05, deadline - time.time()))):
                    session["last"] = time.time()
                    return self._udp_waiters[msg_id][1]
            raise OSError("UDP request timed out")
        finally:
            self._udp_waiters.pop(msg_id, None)

    def _handle_punch_frame(self, kind, chunk, addr):
        try:
            info = json.loads(chunk.decode("utf-8")) if chunk else {}
        except ValueError:
            return
        sender = str(info.get("from", ""))
        token = str(info.get("token", ""))
        if not sender or sender == self.node.nodeid:
            return  # our own probe looped back (e.g. same LAN address on another network)
        self._udp_sessions[sender] = {"addr": addr, "last": time.time()}
        if kind == UDP_PUNCH:
            ack = json.dumps({"from": self.node.nodeid, "token": token}).encode("utf-8")
            try:
                self._udp_send_frames(addr, UDP_PUNCH_ACK, uuid.uuid4().bytes, ack)
            except OSError:
                pass
        waiter = self._punch_tokens.get(token)
        if waiter is not None and kind in (UDP_PUNCH, UDP_PUNCH_ACK):
            waiter[2] = addr
            waiter[0].set()

    def _udp_addresses(self, record, exclude_own=True):
        result = []
        own = {ip for ip, _net in _interfaces_with_networks()} | {self.node.host} if exclude_own else set()
        for route in (record or {}).get("routes", []):
            if route.get("t") == "udp":
                result.append(split_endpoint(route["a"]))
            elif route.get("t") == "tcp" and route.get("s") == "lan":
                host, port = split_endpoint(route["a"])
                if ":" not in host and not (host in own and port == self.node.port):
                    result.append((host, port))  # UDP uses the same port number
        return result

    def _spray(self, addresses, token, duration):
        payload = json.dumps({"from": self.node.nodeid, "token": token}).encode("utf-8")
        end = time.time() + duration
        while time.time() < end and self._running:
            for address in addresses:
                try:
                    self._udp_send_frames(address, UDP_PUNCH, uuid.uuid4().bytes, payload)
                except OSError:
                    continue
            event = self._punch_tokens.get(token, [None])[0]
            if event is not None and event.is_set():
                break
            time.sleep(0.15)

    def punch(self, endpoint, timeout=4):
        """UDP hole punching: both sides send at once, coordinated through a relay."""
        if endpoint in self._udp_sessions:
            return True
        record = self.records.get(endpoint)
        targets = self._udp_addresses(record)
        if not targets or self._udp is None:
            raise OSError("no UDP address for peer")
        token = uuid.uuid4().hex
        event = threading.Event()
        self._punch_tokens[token] = [event, endpoint, None]
        try:
            request = {"type": "punch_request", "from": self.node.nodeid, "token": token,
                       "record": self.local_record, "udp": [format_endpoint(*a) for a in self._udp_addresses(self.local_record, exclude_own=False)]}
            introduced = False
            for kind, address in self.candidate_routes(endpoint):
                if kind not in ("relay", "self-relay"):
                    continue
                try:
                    self._send_on(endpoint, kind, address, request, 4)
                    introduced = True
                    break
                except OSError:
                    continue
            if not introduced:
                raise OSError("no relay to coordinate hole punching")
            threading.Thread(target=self._spray, args=(targets, token, timeout), daemon=True).start()
            if not event.wait(timeout):
                raise OSError("hole punching failed (NAT did not open)")
            addr = self._punch_tokens[token][2]
            self._udp_sessions[endpoint] = {"addr": addr, "last": time.time()}
            return True
        finally:
            self._punch_tokens.pop(token, None)

    def handle_punch_request(self, packet):
        """We were asked (via relay) to punch towards a peer: spray at its addresses."""
        record = packet.get("record")
        if record:
            self.learn_record(record)
        targets = []
        for value in packet.get("udp", []):
            try:
                targets.append(split_endpoint(value))
            except ValueError:
                continue
        token = str(packet.get("token", ""))
        if targets and token and self._udp is not None:
            threading.Thread(target=self._spray, args=(targets, token, 4), daemon=True).start()
        return {"status": "punching"}

    def _keepalive_loop(self):
        while self._running:
            time.sleep(15)
            now = time.time()
            for endpoint, session in list(self._udp_sessions.items()):
                if now - session["last"] > 180:
                    self._udp_sessions.pop(endpoint, None)
                    continue
                try:
                    self._udp_send_frames(session["addr"], UDP_KEEPALIVE, uuid.uuid4().bytes,
                                          json.dumps({"from": self.node.nodeid}).encode("utf-8"))
                except OSError:
                    pass


class _RelaySession:
    """Relay side of one registered node's persistent connection."""

    def __init__(self, conn, endpoint):
        self.conn = conn
        self.endpoint = endpoint
        self.lock = threading.Lock()
        self.pending = {}
        self.closed = False

    def write(self, frame):
        with self.lock:
            self.conn.sendall(_frame(frame))

    def request(self, packet, timeout):
        if self.closed:
            raise OSError("relay connection closed")
        rid = uuid.uuid4().hex
        event = threading.Event()
        self.pending[rid] = [event, None]
        try:
            self.write({"type": "relay_deliver", "rid": rid, "packet": packet})
            if not event.wait(timeout):
                raise OSError("no reply through relay")
            return self.pending[rid][1]
        finally:
            self.pending.pop(rid, None)

    def read_loop(self):
        self.conn.settimeout(90)  # pings arrive every 20 s
        try:
            while not self.closed:
                frame = _read_frame(self.conn)
                if frame is None:
                    break
                kind = frame.get("type")
                if kind == "relay_reply" and frame.get("rid") in self.pending:
                    self.pending[frame["rid"]][1] = frame.get("reply")
                    self.pending[frame["rid"]][0].set()
                elif kind == "relay_ping":
                    self.write({"type": "relay_pong"})
        except (OSError, ValueError):
            pass
        finally:
            self.close()

    def close(self):
        self.closed = True
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.conn.close()
        except OSError:
            pass


def _frame(payload):
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return len(body).to_bytes(4, "big") + body


def _read_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _read_frame(conn):
    header = _read_exact(conn, 4)
    if not header:
        return None
    length = int.from_bytes(header, "big")
    if length <= 0 or length > 16 * 1024 * 1024:
        return None
    body = _read_exact(conn, length)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))
