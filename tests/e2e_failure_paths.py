"""End-to-end test of failure paths: unreachable seed, one-way blocking, restart on a
new address, forged address updates, .mdar join with duplicate names.
Run: python tests/e2e_failure_paths.py   (close MDANetPro first)
"""
import os, sys, time, tempfile, traceback, json, base64
sys.stdout.reconfigure(errors="replace")  # Windows consoles may not print emoji
repo = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, repo); os.chdir(tempfile.mkdtemp())
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import mdaclient, mda_firewall
popups = []
messagebox.showinfo = lambda t, m, **k: popups.append(("info", t, m))
messagebox.showwarning = lambda t, m, **k: popups.append(("warn", t, m))
messagebox.showerror = lambda t, m, **k: popups.append(("error", t, m))
messagebox.askyesno = lambda t, m, **k: (popups.append(("ask", t, m)) or True)
errors = []
tk.Tk.report_callback_exception = lambda self, e, v, tb: errors.append("".join(traceback.format_exception(e, v, tb)))
apps = []
def make(name, port):
    os.environ["MDANET_DATA_DIR"] = d = tempfile.mkdtemp(prefix=f"mda-{name}-")
    root = tk.Tk(); app = mdaclient.MDAClientGUI(root)
    app.port_var.set(str(port)); app.node_name_var.set(name); app.setup_done = True
    apps.append(app); app._dir = d
    return app
def pump(sec, until=None):
    end = time.time() + sec
    while time.time() < end:
        for a in apps:
            try: a.root.update()
            except tk.TclError: pass
        if until and until(): return True
        time.sleep(0.02)
    return bool(until and until())
def walk(w):
    yield w
    for c in w.winfo_children(): yield from walk(c)
failed = False
def check(label, cond):
    global failed
    print(("PASS " if cond else "FAIL ") + label); failed = failed or not cond
def run_test(app, extra=None):
    app.test_connection(extra_targets=extra)
    win = [w for w in app.root.winfo_children() if isinstance(w, tk.Toplevel) and w.title() == "Connection Test"][-1]
    txt = [w for w in walk(win) if isinstance(w, tk.Text)][0]
    pump(20, until=lambda: "Testing" not in txt.get("1.0", "end"))
    out = txt.get("1.0", "end"); win.destroy(); return out

A = make("Amr", 50404); B = make("Nano", 50414)
pump(1.2)
for a in (A, B):
    if a._wizard: a._wizard.destroy()
A._create_network("Lab", "private", "seed", 1, "", [], True)
B._join_from_summary(A._hello_networks()[0])
check("B joined Lab", pump(10, until=lambda: B.networks["Lab"].get("membership_status") == "active"))

# 1. Peer unreachable
A.stop_node()
out = run_test(B)
print(out); check("test: seed off -> can't reach it", "can't reach it" in out)
A.start_node(); pump(0.5)

# 2. One-way: B closes its listening socket; B can still reach A but A can't call back
B.node.close()
res = B.node.probe_reachability(A.node.nodeid)
check("probe: connect ok, callback fails", res["connect_ok"] and not res["callback_ok"])
out = run_test(B)
check("test: one-way -> 'can't reach you back'", "can't reach you back" in out)
B.stop_node(); pump(0.3)

# 3. B restarts on a different address (manual 127.0.0.1) -> A follows, no duplicate
old_b = f"{B.host_var.get()}:50414"
B.host_mode = "manual"; B.host_var.set("127.0.0.1")
B.start_node()
check("B restarted at 127.0.0.1", B.node.nodeid == "127.0.0.1:50414")
ok = pump(8, until=lambda: any(c["endpoint"] == "127.0.0.1:50414" for c in A.contacts))
check("A updated Nano's address after B restarted", ok)
nano = [e for e in A.networks["Lab"]["nodes"].values() if isinstance(e, dict) and e.get("nickname") == "Nano"]
check("A has exactly one Nano entry", len(nano) == 1 and nano[0]["endpoint"] == "127.0.0.1:50414")
check("Nano contact name preserved", any(c["nickname"] == "Nano" and c["endpoint"] == "127.0.0.1:50414" for c in A.contacts))
out = run_test(B)
check("test after restart: connected both ways", "connected both ways" in out)

# 4. Forged address update (stranger key, and tampered signature) is ignored
from Crypto.PublicKey import RSA
stranger = RSA.generate(2048)
pk = stranger.publickey().export_key().decode()
fake = {"type": "control", "action": "address_update", "network": "", "old_endpoint": "127.0.0.1:50414",
        "new_endpoint": "6.6.6.6:50414", "pubkey": pk, "time": time.time(), "signature": "AAAA", "sender": "6.6.6.6:50414"}
A.node.send_control_message(A.node.nodeid, fake); pump(1)
real_pub = B.identity["public_key_pem"]
fake2 = dict(fake, pubkey=real_pub)  # claims to be B, cannot sign
A.node.send_control_message(A.node.nodeid, fake2); pump(1)
check("forged address updates ignored", not any("6.6.6.6" in c["endpoint"] for c in A.contacts))
check("forgery logged as invalid", "invalid signature" in A.log.get("1.0", "end"))

# 5. Old .mdar flow still works, with a duplicate name ("Nano" again)
path = os.path.join(tempfile.mkdtemp(), "lab.mdar")
filedialog.asksaveasfilename = lambda **k: path
A.export_mdar()
D = make("Nano", 50434); pump(1.0)
if D._wizard: D._wizard.destroy()
filedialog.askopenfilename = lambda **k: path
D._show_form_dialog = lambda title, fields, **k: {f["name"]: f["initial"] for f in fields}
D.join_network_dialog()
check("D (also 'Nano') joined with .mdar", pump(10, until=lambda: D.networks["Lab"].get("membership_status") == "active"))
names = sorted(e.get("nickname") + "@" + e.get("endpoint").rsplit(":",1)[1] for e in A.networks["Lab"]["nodes"].values())
print("   A's node list:", names)
check("A keeps both Nanos as separate nodes", len([n for n in names if n.startswith("Nano@")]) == 2)

# 6. Data dir + firewall helper (non-Windows)
check("state saved in data dir", os.path.exists(os.path.join(A._dir, "mdaclient_state.json")))
check("firewall helper reports not needed on Linux", mda_firewall.check_firewall()["ok"] and not mda_firewall.is_supported())
s = mda_firewall.build_allow_script(50404, 50405, r"C:\Program Files\MDANetPro\MDANetClient.exe")
check("allow script has TCP/UDP/ICMP + block-rule cleanup", all(x in s for x in ("-LocalPort 50404", "-LocalPort 50405", "ICMPv4", "Action -eq 'Block'", "MDANetClient.exe")))
s2 = mda_firewall.build_allow_script(50404, 50405, r"C:\Users\O'Brien\app.exe")
check("PowerShell quoting of paths with apostrophes", "'C:\\Users\\O''Brien\\app.exe'" in s2)

check("no Tk callback errors", not errors)
for e in errors: print(e)
for a in apps:
    try: a._on_close()
    except Exception: pass
print("RESULT:", "FAILED" if failed else "ALL PASSED")
