"""Unit tests for the P2P layer (no network needed). Run: python -m pytest tests/test_p2p_units.py
or simply: python tests/test_p2p_units.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.PublicKey import RSA  # noqa: E402

import mda_p2p  # noqa: E402
import mda_stun  # noqa: E402


class FakeNode:
    def __init__(self, host="192.168.1.10", port=50404):
        self._private_key = RSA.generate(2048)
        self.host, self.port = host, port
        self.nodeid = mda_p2p.node_address(self.get_public_key_pem(), port)

    def get_public_key_pem(self):
        return self._private_key.publickey().export_key().decode()


def make_record(node, routes, pub_ip="", nat="cone", reachable=False):
    record = {"node": node.nodeid, "pubkey": node.get_public_key_pem(), "routes": routes,
              "pub_ip": pub_ip, "nat": nat, "time": time.time(), "reachable": reachable}
    return mda_p2p.sign_record(record, node._private_key)


def test_endpoints():
    assert mda_p2p.split_endpoint("[2a01:4f8::1]:50404") == ("2a01:4f8::1", 50404)
    assert mda_p2p.split_endpoint("10.0.0.1:50404") == ("10.0.0.1", 50404)
    assert mda_p2p.split_endpoint("abc.mda:50404") == ("abc.mda", 50404)
    assert mda_p2p.format_endpoint("2a01:4f8::1", 50404) == "[2a01:4f8::1]:50404"
    assert mda_p2p.is_virtual("0123456789abcdef0123.mda:50404")
    assert not mda_p2p.is_virtual("192.168.1.5:50404")


def test_record_signature_binds_address_to_key():
    a, b = FakeNode(), FakeNode()
    record = make_record(a, [{"t": "tcp", "a": "1.2.3.4:50404", "s": "public"}])
    assert mda_p2p.verify_record(record)
    tampered = dict(record, routes=[{"t": "tcp", "a": "6.6.6.6:50404", "s": "public"}])
    assert not mda_p2p.verify_record(tampered), "changed routes must break the signature"
    stolen = dict(record, node=b.nodeid)
    assert not mda_p2p.verify_record(stolen), "a record cannot claim another key's address"
    resigned = mda_p2p.sign_record({k: v for k, v in stolen.items() if k != "sig"}, a._private_key)
    assert not mda_p2p.verify_record(resigned), "fingerprint must match the signing key"
    old = mda_p2p.sign_record(dict({k: v for k, v in record.items() if k != "sig"}, time=time.time() - 40 * 86400), a._private_key)
    assert not mda_p2p.verify_record(old), "very old records are rejected"


def _transport(node, pub_ip="31.0.0.20", nat="cone", ipv6=False):
    t = mda_p2p.P2PTransport(node, stun_servers=[])
    t.local_record = make_record(node, [{"t": "tcp", "a": f"{node.host}:{node.port}", "s": "lan", "net": "192.168.1.0/24"}], pub_ip, nat)
    t._udp = object() if nat != "none" else None
    mda_p2p._V6_CACHE.update(time=time.time(), value=["2a01:4f8::b"] if ipv6 else [])
    return t


def test_route_order_other_network():
    me, peer, relay = FakeNode(), FakeNode(host="192.168.1.10"), FakeNode(host="31.0.0.10")
    t = _transport(me)
    t.learn_record(make_record(peer, [
        {"t": "tcp", "a": "192.168.1.10:50404", "s": "lan", "net": "192.168.1.0/24"},  # same IP as me, other home
        {"t": "tcp", "a": "[2a01:4f8::a]:50404", "s": "ipv6"},
        {"t": "udp", "a": "31.0.0.40:50404", "s": "stun"},
        {"t": "relay", "a": relay.nodeid, "via": []},
    ], pub_ip="31.0.0.40"))
    kinds = t.candidate_routes(peer.nodeid)
    assert ("tcp", "192.168.1.10:50404") not in kinds, "never try a LAN address of another network that equals ours"
    assert kinds[0] == ("punch", ""), kinds  # no IPv6 here -> hole punching first
    assert kinds[-1] == ("relay", relay.nodeid)
    t6 = _transport(me, ipv6=True)
    t6.learn_record(t.records[peer.nodeid])
    assert t6.candidate_routes(peer.nodeid)[0] == ("tcp", "[2a01:4f8::a]:50404"), "IPv6 first when we have it"


def test_route_order_same_network_and_symmetric():
    me, peer = FakeNode(), FakeNode(host="192.168.1.20")
    t = _transport(me, pub_ip="31.0.0.20", nat="symmetric")
    t.learn_record(make_record(peer, [
        {"t": "tcp", "a": "192.168.1.20:50404", "s": "lan", "net": "192.168.1.0/24"},
        {"t": "udp", "a": "31.0.0.20:50404", "s": "stun"},
    ], pub_ip="31.0.0.20"))
    kinds = t.candidate_routes(peer.nodeid)
    assert kinds[0] == ("tcp", "192.168.1.20:50404"), "same public IP -> same home -> LAN first"
    assert ("punch", "") not in kinds, "symmetric NAT: hole punching is skipped"


def test_stun_roundtrip_and_classify():
    request, txid = mda_stun.build_request()
    assert mda_stun.is_stun_packet(request)
    response = mda_stun.build_response(txid, ("31.0.0.20", 61000))
    assert mda_stun.parse_response(response) == (txid, ("31.0.0.20", 61000))
    assert mda_stun.classify([("s1", ("1.1.1.1", 5000)), ("s2", ("1.1.1.1", 5001))], 50404)["nat"] == "symmetric"
    assert mda_stun.classify([("s1", ("1.1.1.1", 50404)), ("s2", ("1.1.1.1", 50404))], 50404)["nat"] == "cone-preserving"


if __name__ == "__main__":
    failed = 0
    for name, func in sorted(globals().items()):
        if name.startswith("test_") and callable(func):
            try:
                func()
                print("PASS", name)
            except AssertionError as exc:
                failed += 1
                print("FAIL", name, exc)
    print("RESULT:", "ALL PASSED" if not failed else f"{failed} FAILED")
    sys.exit(1 if failed else 0)
