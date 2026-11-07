"""Real MDANetClient instance inside a netsim namespace. Usage: gui_node.py ROLE REPO SHARE"""
import json
import os
import sys
import tempfile
import time
import traceback

role, repo, share = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, repo)
os.chdir(tempfile.mkdtemp())
os.environ["MDANET_DATA_DIR"] = tempfile.mkdtemp(prefix=f"mda-{role}-")
os.environ["MDANET_STUN_SERVERS"] = "31.0.0.100:3478,31.0.0.101:3478"
import tkinter as tk  # noqa: E402
from tkinter import filedialog, messagebox  # noqa: E402

import mdaclient  # noqa: E402

popups, errors = [], []
messagebox.showinfo = lambda t, m, **k: popups.append(("info", t, m))
messagebox.showwarning = lambda t, m, **k: popups.append(("warn", t, m))
messagebox.showerror = lambda t, m, **k: popups.append(("error", t, m))
messagebox.askyesno = lambda t, m, **k: (popups.append(("ask", t, m)) or True)
tk.Tk.report_callback_exception = lambda self, e, v, tb: errors.append("".join(traceback.format_exception(e, v, tb)))

NAMES = {"A": "Amr", "B": "Nano", "C": "Zed"}
root = tk.Tk()
app = mdaclient.MDAClientGUI(root)
app.node_name_var.set(NAMES[role])
app.setup_done = True
result = {"role": role, "checks": {}, "log": []}


def pump(seconds, until=None):
    end = time.time() + seconds
    while time.time() < end:
        root.update()
        if until and until():
            return True
        time.sleep(0.02)
    return bool(until and until())


def check(label, cond):
    result["checks"][label] = bool(cond)


def flag(name):
    open(os.path.join(share, name), "w").close()


def wait_flag(name, seconds):
    return pump(seconds, until=lambda: os.path.exists(os.path.join(share, name)))


def chat_text():
    return "\n".join(w.log.get("1.0", "end") for w in app.chat_windows.values())


def endpoint_of(nickname):
    return next((c["endpoint"] for c in app.contacts if c.get("nickname") == nickname), "")


def connection_test():
    app.test_connection()
    win = [w for w in root.winfo_children() if isinstance(w, tk.Toplevel) and w.title() == "Connection Test"][-1]
    text = [w for w in _walk(win) if isinstance(w, tk.Text)][0]
    pump(60, until=lambda: "Testing" not in text.get("1.0", "end"))
    out = text.get("1.0", "end")
    win.destroy()
    return out


def _walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


try:
    pump(2)
    if app._wizard:
        app._wizard.destroy()
    pump(15, until=lambda: app._last_nat_check > 0)
    result["internet"] = app.node.transport.connectivity_summary()

    if role == "A":
        app._create_network("Said Shabaka", "private", "seed", 1, "", [], True)
        path = os.path.join(share, "said.mdar")
        filedialog.asksaveasfilename = lambda **k: path
        app.export_mdar()
        check("seed is reachable from the internet (UPnP)", app.node.transport.is_reachable())
        flag("A.ready")
        joined = pump(120, until=lambda: endpoint_of("Nano") and endpoint_of("Zed"))
        check("both members joined", joined)
        wait_flag("B.joined", 60)
        wait_flag("C.joined", 60)
        pump(3)
        for nick in ("Nano", "Zed"):
            app.send_to_peer(endpoint_of(nick), f"welcome {nick}")
        got = pump(60, until=lambda: "thanks from Nano" in chat_text() and "thanks from Zed" in chat_text())
        check("seed got replies from Nano and Zed", got)
        flag("A.chatdone")
        wait_flag("B.done", 150)
        wait_flag("C.done", 150)
    else:
        if not wait_flag("A.ready", 90):
            raise RuntimeError("seed never became ready")
        check("member is behind NAT (not reachable directly)", not app.node.transport.is_reachable())
        if role == "B":
            reply = app.node.hello("31.0.0.10:50404", timeout=8)  # what "Join by Address" does
            check("hello to the seed's public IP works", bool(reply))
            app._finish_join_by_address("31.0.0.10:50404", reply, "")
        else:
            filedialog.askopenfilename = lambda **k: os.path.join(share, "said.mdar")
            app._show_form_dialog = lambda title, fields, **k: {f["name"]: f["initial"] for f in fields}
            app.join_network_dialog()
        joined = pump(90, until=lambda: app.networks.get("Said Shabaka", {}).get("membership_status") == "active")
        check("joined across NAT", joined)
        check("got the 'You joined' popup", any(p[1] == "Joined" for p in popups))
        check("uses a relay while behind NAT", bool(app.node.transport.relays))
        flag(f"{role}.joined")
        got = pump(90, until=lambda: f"welcome {NAMES[role]}" in chat_text())
        check("received chat from the seed", got)
        app.send_to_peer(endpoint_of("Amr"), f"thanks from {NAMES[role]}")
        if role == "B":
            wait_flag("C.joined", 60)
            ok = pump(60, until=lambda: endpoint_of("Zed"))
            check("Nano knows Zed (member list)", ok)
            pump(5)
            app.send_to_peer(endpoint_of("Zed"), "hi Zed, Nano here")
        else:
            got = pump(90, until=lambda: "hi Zed, Nano here" in chat_text())
            check("member-to-member chat across two NATs", got)
        wait_flag("A.chatdone", 90)
        out = connection_test()
        result["connection_test"] = out
        check("connection test: seed reachable both ways", "connected both ways" in out)
        flag(f"{role}.done")
        wait_flag("B.done" if role == "C" else "C.done", 60)
except Exception:
    errors.append(traceback.format_exc())
finally:
    result["errors"] = errors
    result["popups"] = [p for p in popups if p[0] != "info" or p[1] == "Joined"]
    result["log"] = app.log.get("1.0", "end").splitlines()[-60:]
    with open(os.path.join(share, f"{role}.gui.json"), "w") as handle:
        json.dump(result, handle, indent=1)
    try:
        app._on_close()
    except Exception:
        pass
