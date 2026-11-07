#!/bin/bash
# Three real app windows in three simulated homes; prints every check.
REPO=${1:-$(cd "$(dirname "$0")/../.." && pwd)}
PY=${PY:-/usr/bin/python3.12}
DIR=$(cd "$(dirname "$0")" && pwd)
SHARE=$(mktemp -d)
bash "$DIR/netsim.sh" up >/dev/null
Xvfb :77 -screen 0 1280x900x24 >/dev/null 2>&1 &
XPID=$!
export DISPLAY=:77
ip netns exec inet python3 -c "
import sys; sys.path.insert(0, '$REPO'); import mda_stun, time
a = mda_stun.StunServer('31.0.0.100', 3478); b = mda_stun.StunServer('31.0.0.101', 3478)
time.sleep(400)" &
SPID=$!
ip netns exec rA python3 "$DIR/fake_igd.py" 192.168.1.1 31.0.0.10 > "$SHARE/igd.log" 2>&1 &
IPID=$!
sleep 1
for r in A B C; do
  ip netns exec h$r env DISPLAY=:77 $PY -I "$DIR/gui_node.py" $r "$REPO" "$SHARE" > "$SHARE/$r.out" 2>&1 &
done
for r in A B C; do
  for i in $(seq 1 400); do [ -f "$SHARE/$r.gui.json" ] && break; sleep 1; done
done
$PY - "$SHARE" <<'EOF'
import json, os, sys
share = sys.argv[1]
fails = 0
for r in "ABC":
    path = os.path.join(share, f"{r}.gui.json")
    if not os.path.exists(path):
        print(f"{r}: no result"); print(open(os.path.join(share, f"{r}.out")).read()[-3000:]); fails += 1; continue
    data = json.load(open(path))
    print(f"\n== {r}  internet: {data.get('internet')}")
    for label, ok in data["checks"].items():
        fails += not ok
        print(f"   {'PASS' if ok else 'FAIL'} {label}")
    if data.get("connection_test"):
        print("   --- Test Connection window ---")
        for line in data["connection_test"].strip().splitlines():
            print("   | " + line)
    for e in data["errors"]:
        fails += 1; print("   ERROR:", e[-1500:])
    if any(not ok for ok in data["checks"].values()):
        print("   --- last log lines ---")
        for line in data["log"][-25:]:
            if "Fake message" not in line and "RX [fake]" not in line:
                print("   > " + line)
print("\nRESULT:", "ALL PASSED" if not fails else f"{fails} FAILED")
EOF
kill $SPID $IPID $XPID 2>/dev/null
bash "$DIR/netsim.sh" down
