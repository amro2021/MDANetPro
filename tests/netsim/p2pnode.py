"""One node of the transport test. Usage: p2pnode.py NAME REPO SHAREDIR SECONDS"""
import json
import os
import sys
import time

name, repo, share, duration = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
sys.path.insert(0, repo)
import mda_p2p  # noqa: E402
from mdanetwork import mda  # noqa: E402

STUN = [("31.0.0.100", 3478), ("31.0.0.101", 3478)]
names = ["A", "B", "C", "E"]
got = []
node = mda(port=50404, node_name=name, stun_servers=STUN, on_message=lambda p: got.append(p))
node.start_server()
info = node.transport.discover_nat(use_upnp=True)
mapping = info["mapping"] or {}
print(f"[{name}] {node.nodeid} stun={info['stun']} upnp={mapping.get('method')} usable={mapping.get('usable')}", flush=True)
print(f"[{name}] {node.transport.connectivity_summary()}", flush=True)


def publish():
    with open(os.path.join(share, f"{name}.json.tmp"), "w") as handle:
        json.dump(node.transport.local_record, handle)
    os.replace(os.path.join(share, f"{name}.json.tmp"), os.path.join(share, f"{name}.json"))


def load_all():
    found = {}
    for other in names:
        path = os.path.join(share, f"{other}.json")
        if other != name and os.path.exists(path):
            with open(path) as handle:
                record = json.load(handle)
            node.transport.learn_record(record)
            found[other] = record
    return found


publish()
node.transport.on_record_changed = lambda record: publish()  # the GUI re-sends changed records the same way
node.transport.debug = lambda text: print(f"[{name}] {time.strftime('%H:%M:%S')} {text}", flush=True)
deadline = time.time() + 30
while time.time() < deadline and len(load_all()) < len(names) - 1:
    time.sleep(0.3)
others = load_all()

# Behind NAT: keep a relay connection to a reachable node (as the GUI does with members).
if not node.transport.is_reachable():
    relays = [rec["node"] for rec in others.values() if rec.get("reachable")]
    node.transport.set_relays(relays)
    for _ in range(50):
        if any(v == "connected" for v in node.transport.relay_status.values()):
            break
        time.sleep(0.2)
    print(f"[{name}] relays: {node.transport.relay_status}", flush=True)
    publish()

def barrier(tag, timeout=60):
    open(os.path.join(share, f"{name}.{tag}"), "w").close()
    end = time.time() + timeout
    while time.time() < end and not all(os.path.exists(os.path.join(share, f"{n}.{tag}")) for n in names):
        time.sleep(0.2)


barrier("ready")
others = load_all()  # final records, including relay routes
print(f"[{name}] relay sessions on me: {node.transport.relay_clients()}", flush=True)

results = {}
for other, record in sorted(others.items()):
    start = time.time()
    try:
        reply = node.send_message(*mda_p2p.split_endpoint(record["node"]), {"type": "ping", "nodeid": node.nodeid}, timeout=6)
        ok = isinstance(reply, dict) and reply.get("type") == "pong" and reply.get("nodeid") == record["node"]
        results[other] = {"ok": ok, "route": node.route_description(record["node"]), "ms": int((time.time() - start) * 1000)}
    except OSError as exc:
        results[other] = {"ok": False, "route": str(exc), "ms": int((time.time() - start) * 1000)}
    try:
        reply = node.send_control_message(record["node"], {"action": "test", "network": "", "text": f"hello {other} from {name}"}, timeout=6)
        results[other]["second_ok"] = isinstance(reply, dict) and reply.get("status") == "ok"
        results[other]["second_route"] = node.route_description(record["node"])
    except OSError as exc:
        results[other]["second_ok"] = False
        results[other]["second_err"] = str(exc)

barrier("done", timeout=120)
time.sleep(1)
with open(os.path.join(share, f"{name}.result.json"), "w") as handle:
    json.dump({"results": results, "nat": node.transport.stun_result, "summary": node.transport.connectivity_summary(),
               "relay_status": node.transport.relay_status,
               "received": [p.get("text") for p in got if p.get("text")]}, handle)
barrier("written", timeout=30)
node.close()
