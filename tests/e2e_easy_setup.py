"""End-to-end test: wizard, Networks Nearby, join/approve, chat, connection test,
address change, join by address. Opens real windows; uses ports 50404/50414/50424.
Run: python tests/e2e_easy_setup.py   (close MDANetPro first)
"""
import os, sys, time, tempfile, traceback
sys.stdout.reconfigure(errors="replace")  # Windows consoles may not print emoji
repo = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo)
os.chdir(tempfile.mkdtemp())  # no legacy data in cwd
import tkinter as tk
from tkinter import messagebox, ttk
import mdaclient

popups = []
messagebox.showinfo = lambda title, msg, **k: popups.append(("info", title, msg))
messagebox.showwarning = lambda title, msg, **k: popups.append(("warn", title, msg))
messagebox.showerror = lambda title, msg, **k: popups.append(("error", title, msg))
messagebox.askyesno = lambda title, msg, **k: (popups.append(("ask", title, msg)) or True)
errors = []
def report_callback_exception(self, exc, val, tb):
    errors.append("".join(traceback.format_exception(exc, val, tb)))
tk.Tk.report_callback_exception = report_callback_exception

apps = []
def make(name, port):
    os.environ["MDANET_DATA_DIR"] = tempfile.mkdtemp(prefix=f"mda-{name}-")
    root = tk.Tk(); root.title(name)
    app = mdaclient.MDAClientGUI(root)
    app.port_var.set(str(port))
    apps.append(app)
    return app

def pump(seconds, until=None):
    end = time.time() + seconds
    while time.time() < end:
        for a in apps:
            a.root.update()
        if until and until():
            return True
        time.sleep(0.02)
    return bool(until and until())

def walk(w):
    yield w
    for c in w.winfo_children():
        yield from walk(c)

def click(top, text):
    for w in walk(top):
        if isinstance(w, (ttk.Button, tk.Button)) and w.cget("text") == text and w.winfo_ismapped():
            w.invoke(); return True
    raise AssertionError(f"button {text!r} not visible")

def type_into_visible_entry(top, text, index=0):
    entries = [w for w in walk(top) if isinstance(w, ttk.Entry) and w.winfo_ismapped()]
    entries[index].delete(0, "end"); entries[index].insert(0, text)

def check(label, cond):
    print(("PASS " if cond else "FAIL ") + label)
    if not cond:
        global failed; failed = True
failed = False

A = make("Amr", 50404)
B = make("Nano", 50414)
pump(1.5)
check("both nodes auto-started", bool(A.node and B.node))
print("A at", A.node.nodeid, "| B at", B.node.nodeid)
check("wizard opened on first run", A._wizard is not None and B._wizard is not None)

# --- Wizard on A: name -> (no firewall page on Linux) -> create network
type_into_visible_entry(A._wizard, "Amr")
click(A._wizard, "Next →"); pump(0.2)
type_into_visible_entry(A._wizard, "Said Shabaka")
click(A._wizard, "Create my network"); pump(0.3)
check("A created network as seed", A.networks.get("Said Shabaka", {}).get("my_role") == "seed")
check("A wizard closed + setup_done", A._wizard is None and A.setup_done)

# --- Wizard on B: name -> Join a network nearby
type_into_visible_entry(B._wizard, "Nano")
click(B._wizard, "Next →"); pump(0.2)
click(B._wizard, "Join a network nearby…"); pump(0.3)
check("B nearby window open", B._nearby_window is not None)

seen = pump(10, until=lambda: any(i.get("network") == "Said Shabaka" for i in B._nearby_items.values()))
check("B sees 'Said Shabaka' in Networks Nearby", seen)
row = [iid for iid, i in B._nearby_items.items() if i.get("network") == "Said Shabaka"]
B._nearby_tree.selection_set(row[0])
click(B._nearby_window, "Join")
joined = pump(10, until=lambda: B.networks.get("Said Shabaka", {}).get("membership_status") == "active")
check("B joined after A approved", joined)
check("A asked to approve Nano", any(p[0] == "ask" and "Nano" in p[2] for p in popups))
check("B got 'You joined' popup", any(p[1] == "Joined" for p in popups))
check("B nearby row now says member", "member" in B._membership_label("Said Shabaka"))
a_ep_in_b = {c["nickname"]: c["endpoint"] for c in B.contacts}
check("B has A as contact", a_ep_in_b.get("Amr") == A.node.nodeid)
check("A has Nano as contact", any(c["nickname"] == "Nano" and c["endpoint"] == B.node.nodeid for c in A.contacts))

# --- Chat both ways
A.send_to_peer(B.node.nodeid, "hi from Amr")
got = pump(12, until=lambda: B.node.nodeid and any("hi from Amr" in w.log.get("1.0", "end") for w in B.chat_windows.values()))
check("Nano received chat from Amr", got)

# --- Connection test from B
before = set(A.root.winfo_children()) | set(B.root.winfo_children())
B.test_connection()
win = [w for w in B.root.winfo_children() if isinstance(w, tk.Toplevel) and w.title() == "Connection Test"][-1]
txt = [w for w in walk(win) if isinstance(w, tk.Text)][0]
done = pump(15, until=lambda: "Testing" not in txt.get("1.0", "end"))
out = txt.get("1.0", "end")
print("---- connection test output ----\n" + out.strip() + "\n--------------------------------")
check("connection test: connected both ways", "connected both ways" in out)
win.destroy()

# --- IP change on A: its key-based address stays the same, so nothing needs renaming
old_a = A.node.nodeid
A._change_address("127.0.0.1", reason="test")
check("A keeps the same network address after an IP change", A.node.nodeid == old_a and A.node.host == "127.0.0.1")
pump(2)
amr = [e for e in B.networks["Said Shabaka"]["nodes"].values() if isinstance(e, dict) and e.get("nickname") == "Amr"]
check("B still has exactly one Amr entry at the same address", len(amr) == 1 and amr[0]["endpoint"] == old_a)
A.send_to_peer(B.node.nodeid, "second message after move")
got2 = pump(12, until=lambda: any("second message after move" in w.log.get("1.0", "end") for w in B.chat_windows.values()))
check("chat still works after A moved", got2)

# --- watcher: 127.0.0.1 is not a real adapter, A should move back automatically
back = pump(9, until=lambda: A.node.host != "127.0.0.1")
check("address watcher moved A back to a real adapter", back)
check("B's contact for Amr unchanged", any(c["nickname"] == "Amr" and c["endpoint"] == old_a for c in B.contacts))

# --- Third node joins by address (hello lookup)
C = make("Zed", 50424)
pump(1.0)
C.setup_done = True
if C._wizard: C._wizard.destroy()
C.node_name_var.set("Zed")
reply = C.node.hello(f"{A.node.host}:50404")
check("hello reply carries A's signed route record", reply and reply.get("record", {}).get("node") == A.node.nodeid)
check("hello lists A's network", reply and [n["network"] for n in reply["networks"]] == ["Said Shabaka"])
C._finish_join_by_address(f"{A.node.host}:50404", reply, "")
joinedC = pump(10, until=lambda: C.networks.get("Said Shabaka", {}).get("membership_status") == "active")
check("C joined by address", joinedC)
synced = pump(10, until=lambda: any(c["nickname"] == "Zed" for c in B.contacts))
check("B learned about Zed via node_list_update", synced)

check("no Tk callback errors", not errors)
for e in errors: print(e)
for a in apps:
    a._on_close()
print("RESULT:", "FAILED" if failed else "ALL PASSED")
