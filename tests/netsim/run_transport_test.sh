#!/bin/bash
# Runs 4 nodes in the simulated internet and prints who reached whom, and how.
REPO=${1:-$(cd "$(dirname "$0")/../.." && pwd)}
DIR=$(cd "$(dirname "$0")" && pwd)
SHARE=$(mktemp -d)
bash "$DIR/netsim.sh" up >/dev/null
ip netns exec inet python3 -c "
import sys; sys.path.insert(0, '$REPO'); import mda_stun, time
a = mda_stun.StunServer('31.0.0.100', 3478); b = mda_stun.StunServer('31.0.0.101', 3478)
time.sleep(120)" &
ip netns exec rA python3 "$DIR/fake_igd.py" 192.168.1.1 31.0.0.10 > "$SHARE/igd.log" 2>&1 &
sleep 1
for n in A B C E; do
  ip netns exec h$n python3 -I "$DIR/p2pnode.py" $n "$REPO" "$SHARE" 25 > "$SHARE/$n.log" 2>&1 &
done
wait_for() { for i in $(seq 1 120); do [ -f "$SHARE/$1.result.json" ] && return 0; sleep 0.5; done; return 1; }
for n in A B C E; do wait_for $n || echo "no result from $n"; done
sleep 1
python3 - "$SHARE" <<'EOF'
import json, os, sys
share = sys.argv[1]
print(open(os.path.join(share, "igd.log")).read().strip())
fails = 0
for n in "ABCE":
    path = os.path.join(share, f"{n}.result.json")
    if not os.path.exists(path):
        print(f"{n}: NO RESULT"); print(open(os.path.join(share, f"{n}.log")).read()[-2000:]); fails += 1; continue
    data = json.load(open(path))
    print(f"\n{n}: NAT={data['nat']['nat']} public={data['nat']['public']} | {data['summary']}")
    for other, r in sorted(data["results"].items()):
        ok = r["ok"] and r.get("second_ok")
        fails += not ok
        print(f"   {'PASS' if ok else 'FAIL'} {n} -> {other}: {r['route']} ({r['ms']} ms){'' if r.get('second_ok') else '  second: ' + r.get('second_err', 'failed')}")
    print(f"   received {len(data['received'])} messages: {sorted(data['received'])}")
print("\nRESULT:", "ALL PASSED" if not fails else f"{fails} FAILED")
EOF
for n in A B C E; do grep -h "Traceback\|Error" "$SHARE/$n.log" | head -3; done
kill %1 %2 2>/dev/null
bash "$DIR/netsim.sh" down
