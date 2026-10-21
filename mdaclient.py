#!/usr/bin/env python3
import argparse
import queue
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from mdanetwork import mda
from net_profile import export_mdar_file, import_mdar_file


def parse_peer(value):
    if value is None:
        return None
    host, port = value.rsplit(":", 1)
    return host.strip(), int(port)


class MDAClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MDA Network Client")
        self.node = None
        self.message_queue = queue.Queue()
        self.network_name_var = tk.StringVar(value="lab-network")
        self.host_var = tk.StringVar(value=mda.get_local_ip())
        self.port_var = tk.StringVar(value="50404")
        self.peer_entry_var = tk.StringVar(value="")
        self.message_var = tk.StringVar(value="")
        self.node_status_var = tk.StringVar(value="Stopped")
        self._build_ui()
        self.root.after(250, self._drain_messages)

    def _build_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        ttk.Label(frame, text="Network").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.network_name_var, width=25).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Label(frame, text="Host").grid(row=0, column=2, sticky="w")
        ttk.Entry(frame, textvariable=self.host_var, width=20).grid(row=0, column=3, sticky="ew", padx=4)
        ttk.Label(frame, text="Port").grid(row=0, column=4, sticky="w")
        ttk.Entry(frame, textvariable=self.port_var, width=10).grid(row=0, column=5, sticky="ew", padx=4)
        ttk.Button(frame, text="Detect IP", command=self._detect_ip).grid(row=0, column=6, padx=4)

        ttk.Button(frame, text="Start Node", command=self.start_node).grid(row=1, column=0, pady=6, sticky="ew")
        ttk.Button(frame, text="Stop Node", command=self.stop_node).grid(row=1, column=1, pady=6, sticky="ew")
        ttk.Button(frame, text="Import .mdar", command=self.import_mdar).grid(row=1, column=2, pady=6, sticky="ew")
        ttk.Button(frame, text="Export .mdar", command=self.export_mdar).grid(row=1, column=3, pady=6, sticky="ew")
        ttk.Label(frame, textvariable=self.node_status_var).grid(row=1, column=4, columnspan=3, sticky="w")

        ttk.Label(frame, text="Peer host:port").grid(row=2, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.peer_entry_var, width=25).grid(row=2, column=1, columnspan=2, sticky="ew", padx=4)
        ttk.Button(frame, text="Add Peer", command=self.add_peer).grid(row=2, column=3, sticky="ew", padx=4)
        ttk.Button(frame, text="Remove Selected Peer", command=self.remove_selected_peer).grid(row=2, column=4, columnspan=2, sticky="ew")
        ttk.Button(frame, text="Ping Peers", command=self.ping_peers).grid(row=2, column=6, sticky="ew", padx=4)

        self.peer_list = tk.Listbox(frame, height=6, exportselection=False)
        self.peer_list.grid(row=3, column=0, columnspan=7, sticky="nsew", pady=(4, 8))

        ttk.Label(frame, text="Message").grid(row=4, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.message_var).grid(row=4, column=1, columnspan=5, sticky="ew", padx=4)
        ttk.Button(frame, text="Send", command=self.send_message).grid(row=4, column=6, sticky="ew")

        self.log = scrolledtext.ScrolledText(frame, height=16, state="disabled")
        self.log.grid(row=5, column=0, columnspan=7, sticky="nsew")

        for i in range(7):
            frame.columnconfigure(i, weight=1)
        frame.rowconfigure(3, weight=1)
        frame.rowconfigure(5, weight=2)

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _log(self, text):
        self.log.configure(state="normal")
        self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)
        self.log.configure(state="disabled")

    def _detect_ip(self):
        self.host_var.set(mda.get_local_ip())
        self._log("Detected local IP.")

    def _update_status(self):
        if self.node:
            self.node_status_var.set(f"Running as {self.node.nodeid}")
        else:
            self.node_status_var.set("Stopped")

    def _drain_messages(self):
        while True:
            try:
                packet = self.message_queue.get_nowait()
            except queue.Empty:
                break
            sender = packet.get("sender", packet.get("received_from", "unknown"))
            msg_type = packet.get("type", "data")
            text = packet.get("text", "")
            self._log(f"RX [{msg_type}] from {sender}: {text}")
        self.root.after(250, self._drain_messages)

    def _on_packet(self, packet):
        self.message_queue.put(packet)

    def _list_peers(self):
        values = []
        for i in range(self.peer_list.size()):
            values.append(self.peer_list.get(i))
        return values

    def add_peer(self):
        peer = self.peer_entry_var.get().strip()
        if not peer:
            return
        try:
            host, port = parse_peer(peer)
            peer_norm = f"{host}:{port}"
        except Exception:
            messagebox.showerror("Invalid Peer", "Use peer format: host:port")
            return
        if peer_norm not in self._list_peers():
            self.peer_list.insert(tk.END, peer_norm)
        if self.node:
            self.node.add_peer(peer_norm)
        self.peer_entry_var.set("")
        self._log(f"Peer added: {peer_norm}")

    def remove_selected_peer(self):
        selected = self.peer_list.curselection()
        if not selected:
            return
        index = selected[0]
        peer = self.peer_list.get(index)
        self.peer_list.delete(index)
        if self.node:
            self.node.remove_peer(peer)
        self._log(f"Peer removed: {peer}")

    def _peers_from_ui(self):
        peers = []
        for raw in self._list_peers():
            host, port = parse_peer(raw)
            peers.append((host, port))
        return peers

    def start_node(self):
        if self.node:
            self._log("Node is already running.")
            return
        host = self.host_var.get().strip()
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be a number.")
            return
        peers = self._peers_from_ui()
        try:
            self.node = mda(host=host, port=port, peers=peers, node_name=self.network_name_var.get().strip(), on_message=self._on_packet)
            self.node.start_server()
        except OSError as exc:
            self.node = None
            messagebox.showerror("Start Failed", str(exc))
            return
        self._update_status()
        self._log(f"Node started on {self.node.nodeid}")

    def stop_node(self):
        if self.node:
            self.node.close()
            self.node = None
            self._log("Node stopped.")
        self._update_status()

    def send_message(self):
        if not self.node:
            messagebox.showwarning("Node Not Running", "Start the node first.")
            return
        text = self.message_var.get().strip()
        if not text:
            return
        payload = {"type": "chat", "sender": self.node.nodeid, "text": text, "time": time.time()}
        self.node.broadcast(payload)
        self._log(f"TX to {len(self.node.peers)} peer(s): {text}")
        self.message_var.set("")

    def ping_peers(self):
        if not self.node:
            messagebox.showwarning("Node Not Running", "Start the node first.")
            return
        if not self.node.peers:
            self._log("No peers configured.")
            return
        for host, port in self.node.peers:
            try:
                response = self.node.ping_peer(host, port, timeout=2)
                if response and response.get("type") == "pong":
                    self._log(f"Ping OK: {host}:{port} -> {response.get('nodeid')}")
                else:
                    self._log(f"Ping no response: {host}:{port}")
            except OSError as exc:
                self._log(f"Ping failed {host}:{port}: {exc}")

    def import_mdar(self):
        path = filedialog.askopenfilename(
            title="Import MDA profile",
            filetypes=[("MDA Profile", "*.mdar"), ("All files", "*.*")],
        )
        if not path:
            return
        payload = import_mdar_file(path)
        if not payload:
            messagebox.showerror("Import Failed", "Invalid or unreadable .mdar file.")
            return
        self.network_name_var.set(payload.get("name", self.network_name_var.get()))
        nodes = payload.get("nodes", {}) or {}
        self.peer_list.delete(0, tk.END)
        for value in nodes.values():
            try:
                host, port = parse_peer(value)
                self.peer_list.insert(tk.END, f"{host}:{port}")
            except Exception:
                continue
        self._log(f"Imported .mdar profile from {path}")

    def export_mdar(self):
        path = filedialog.asksaveasfilename(
            title="Export MDA profile",
            defaultextension=".mdar",
            filetypes=[("MDA Profile", "*.mdar"), ("All files", "*.*")],
        )
        if not path:
            return
        peers = self._list_peers()
        selected_nodes = {}
        if self.node:
            selected_nodes["self"] = self.node.nodeid
        else:
            host = self.host_var.get().strip()
            try:
                port = int(self.port_var.get().strip())
                selected_nodes["self"] = f"{host}:{port}"
            except ValueError:
                pass
        for index, peer in enumerate(peers, start=1):
            selected_nodes[f"peer-{index}"] = peer
        export_mdar_file(
            self.network_name_var.get().strip() or "lab-network",
            file_path=path,
            net_type="private",
            net_description="MDA lab profile",
            net_rules=["allow-lab-communication"],
            selected_nodes=selected_nodes,
        )
        self._log(f"Exported .mdar profile to {path}")

    def _on_close(self):
        self.stop_node()
        self.root.destroy()


def run_cli_mode(args):
    peers = [parse_peer(peer) for peer in args.peer if peer]
    node = mda(host=args.host, port=args.port, peers=peers, node_name=f"client-{args.port}")
    node.start_server()

    if args.message:
        payload = {"type": "chat", "sender": node.nodeid, "text": args.message, "time": time.time()}
        node.broadcast(payload)
        print(f"Sent message to {len(node.peers)} peers", flush=True)
        node.close()
        return

    print(f"MDA client running on {node.nodeid}", flush=True)
    print("Type a message and press Enter. Use 'quit' to exit.", flush=True)
    try:
        while True:
            text = input("message> ")
            if text.strip().lower() == "quit":
                break
            payload = {"type": "chat", "sender": node.nodeid, "text": text, "time": time.time()}
            node.broadcast(payload)
    except KeyboardInterrupt:
        pass
    finally:
        node.close()


def main():
    parser = argparse.ArgumentParser(description="MDA chat client")
    parser.add_argument("--host", default=mda.get_local_ip(), help="Local bind host for this node")
    parser.add_argument("--port", type=int, default=50404, help="Local port to bind the node")
    parser.add_argument("--peer", action="append", default=[], help="Peer endpoint host:port")
    parser.add_argument("--message", default="", help="Message to send to peers")
    parser.add_argument("--cli", action="store_true", help="Run in terminal mode instead of GUI")
    args = parser.parse_args()

    if args.cli or args.message:
        run_cli_mode(args)
        return

    root = tk.Tk()
    app = MDAClientGUI(root)
    app.host_var.set(args.host)
    app.port_var.set(str(args.port))
    for peer in args.peer:
        app.peer_entry_var.set(peer)
        app.add_peer()
    root.mainloop()


if __name__ == "__main__":
    main()
