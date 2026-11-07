"""Writes Python-produced fixtures for the Kotlin unit tests (canonical JSON, signatures, onion layer)."""
import json, os, sys, time
repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, repo)
from Crypto.PublicKey import RSA
import mda_p2p
from mdanetwork import mda

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
cases = [
    {"b": 1, "a": [1.5, 2, "x"], "nested": {"z": None, "y": True}},
    {"text": "Hé llo é中\U0001F600 \"quoted\" \\ back\n\t\x01", "t": time.time()},
    {"time": 1794043339.5123456, "small": 0.1, "big": 12345678901234567890, "neg": -3.25, "e": 1e-05},
]
with open(os.path.join(out, "json_cases.txt"), "w") as f:
    for c in cases:
        # line 1: pretty (non-canonical) input, line 2: Python's canonical output
        f.write(json.dumps(c, indent=None, sort_keys=False, ensure_ascii=False).replace("\n", "\\n") + "\n")
        f.write(json.dumps(c, sort_keys=True, separators=(",", ":")) + "\n")
node = mda(port=50499, stun_servers=[])
record = {"node": node.nodeid, "pubkey": node.get_public_key_pem(), "routes": [{"t": "tcp", "a": "10.0.0.5:50499", "s": "lan", "net": "10.0.0.0/24"}],
          "pub_ip": "", "nat": "unknown", "time": time.time(), "reachable": False}
signed = mda_p2p.sign_record(record, node._private_key)
with open(os.path.join(out, "record.json"), "w") as f:
    json.dump(signed, f, sort_keys=True, separators=(",", ":"))
# An onion layer the Kotlin side must decrypt: encrypted to a key we give it.
key = RSA.generate(2048)
with open(os.path.join(out, "onion_private.pem"), "wb") as f:
    f.write(key.export_key(format="PEM", pkcs=8))
layer = node._encrypt_layer({"next_hop": "", "payload": {"route_id": "r1", "message_type": "real", "packed_body": node._pack_final_body("hello from python")}},
                            key.publickey().export_key().decode())
with open(os.path.join(out, "onion_layer.json"), "w") as f:
    json.dump(layer, f)
print("fixtures written to", out)
