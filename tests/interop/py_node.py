"""Python side of the Kotlin<->Python interop test (CI). Runs the real MDANetClient app.

  py_node.py seed   SHARE   : creates "Interop", approves the Kotlin member, chats with it
  py_node.py member SHARE   : joins the Kotlin seed by address, chats with it
"""
import json, os, sys, tempfile, time, traceback
role, share = sys.argv[1], sys.argv[2]
repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, repo)
os.chdir(tempfile.mkdtemp())
os.environ["MDANET_DATA_DIR"] = tempfile.mkdtemp(prefix=f"py-{role}-")
import tkinter as tk
from tkinter import messagebox
import mdaclient

popups, errors, checks = [], [], {}
messagebox.showinfo = lambda t, m, **k: popups.append(("info", t, m))
messagebox.showwarning = lambda t, m, **k: popups.append(("warn", t, m))
messagebox.showerror = lambda t, m, **k: popups.append(("error", t, m))
messagebox.askyesno = lambda t, m, **k: (popups.append(("ask", t, m)) or True)
tk.Tk.report_callback_exception = lambda self, e, v, tb: errors.append("".join(traceback.format_exception(e, v, tb)))
root = tk.Tk()
app = mdaclient.MDAClientGUI(root)
app.setup_done = True
app.node_name_var.set("Amr" if role == "seed" else "Pyno")


def pump(sec, until=None):
    end = time.time() + sec
    while time.time() < end:
        root.update()
        if until and until():
            return True
        time.sleep(0.02)
    return bool(until and until())


def check(label, ok):
    checks[label] = bool(ok)
    print(("PASS " if ok else "FAIL ") + label, flush=True)


def chat_text():
    return "\n".join(w.log.get("1.0", "end") for w in app.chat_windows.values())


def endpoint_of(nick):
    return next((c["endpoint"] for c in app.contacts if c.get("nickname") == nick), "")


try:
    pump(2)
    if app._wizard:
        app._wizard.destroy()
    pump(15, until=lambda: app._last_nat_check > 0)
    if role == "seed":
        app._create_network("Interop", "private", "seed", 1, "", [], True)
        open(os.path.join(share, "py_seed.ready"), "w").close()
        check("Kotlin member joined (approved here)", pump(150, until=lambda: endpoint_of("Kotty")))
        pump(4)
        app.send_to_peer(endpoint_of("Kotty"), "welcome Kotty")
        check("got reply from the Kotlin member", pump(90, until=lambda: "thanks from Kotty" in chat_text()))
        pump(15)
    else:
        ready = os.path.join(share, "kt_seed.ready")
        check("Kotlin seed ready", pump(90, until=lambda: os.path.exists(ready)))
        reply = app.node.hello("127.0.0.1:50414", timeout=8)
        check("hello to the Kotlin seed works", bool(reply))
        app._finish_join_by_address("127.0.0.1:50414", reply, "")
        check("joined the Kotlin seed's network", pump(120, until=lambda: app.networks.get("KNet", {}).get("membership_status") == "active"))
        check("got chat from the Kotlin seed", pump(90, until=lambda: "welcome Pyno" in chat_text()))
        app.send_to_peer(endpoint_of("KSeed"), "thanks from Pyno")
        pump(20)
except Exception:
    errors.append(traceback.format_exc())
for e in errors:
    print("ERROR", e)
for line in app.log.get("1.0", "end").splitlines()[-30:]:
    if "Cover traffic" not in line and "RX [fake]" not in line:
        print("LOG", line)
failed = sum(1 for v in checks.values() if not v) + len(errors)
print("RESULT:", "ALL PASSED" if not failed else f"{failed} FAILED", flush=True)
try:
    app._on_close()
except Exception:
    pass
sys.exit(1 if failed else 0)
