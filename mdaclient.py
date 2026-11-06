#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import queue
import random
import subprocess
import sys
import time
import tkinter as tk
import uuid
import urllib.request
from tkinter import filedialog, messagebox, scrolledtext, ttk

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

from client_storage import ClientStorage
from mdanetwork import mda
from net_profile import export_mdar_file, import_mdar_file


def parse_peer(value):
    if value is None:
        return None
    host, port = value.rsplit(":", 1)
    return host.strip(), int(port)


class ChatWindow:
    def __init__(self, root, peer, title_label, send_callback, close_callback):
        self.peer = peer
        self.send_callback = send_callback
        self.close_callback = close_callback
        self.window = tk.Toplevel(root)
        self.window.title(f"Chat - {title_label}")
        self.window.geometry("520x360")
        self.window.minsize(420, 280)

        frame = ttk.Frame(self.window, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)

        self.log = scrolledtext.ScrolledText(frame, height=14, state="disabled", wrap="word")
        self.log.grid(row=0, column=0, columnspan=2, sticky="nsew")

        self.message_var = tk.StringVar(value="")
        ttk.Entry(frame, textvariable=self.message_var).grid(row=1, column=0, sticky="ew", pady=(8, 0))
        ttk.Button(frame, text="Send", command=self._send).grid(row=1, column=1, sticky="ew", padx=(6, 0), pady=(8, 0))

        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=0)
        frame.rowconfigure(0, weight=1)

        self.window.bind("<Return>", self._send_event)
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)

    def _append(self, text):
        self.log.configure(state="normal")
        self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)
        self.log.configure(state="disabled")

    def append_outgoing(self, text):
        self._append(f"You: {text}")

    def append_incoming(self, sender, text):
        self._append(f"{sender}: {text}")

    def _send_event(self, _event):
        self._send()

    def _send(self):
        text = self.message_var.get().strip()
        if not text:
            return
        sent = self.send_callback(self.peer, text)
        if sent:
            self.append_outgoing(text)
            self.message_var.set("")

    def focus(self):
        self.window.deiconify()
        self.window.lift()
        self.window.focus_force()

    def _on_close(self):
        self.close_callback(self.peer)
        self.window.destroy()


class MDAClientGUI:
    STATE_FILE = "mdaclient_state.json"

    def __init__(self, root):
        self.root = root
        self.root.title("MDA Network Client")
        self.node = None
        self.message_queue = queue.Queue()
        self.storage = ClientStorage(os.getcwd())
        self.identity = self.storage.get_or_create_identity()
        self.active_network_var = tk.StringVar(value="lab-network")
        self.node_name_var = tk.StringVar(value="node")
        self.node_description_var = tk.StringVar(value="")
        self.host_var = tk.StringVar(value=mda.get_local_ip())
        self.port_var = tk.StringVar(value="50404")
        self.peer_entry_var = tk.StringVar(value="")
        self.broadcast_var = tk.StringVar(value="")
        self.node_status_var = tk.StringVar(value="Stopped")
        self.experiment_opt_in_var = tk.BooleanVar(value=False)
        self.experiment_collector_url_var = tk.StringVar(value="http://127.0.0.1:9090")
        self.experiment_publish_var = tk.BooleanVar(value=False)
        self.experiment_auto_upload_var = tk.BooleanVar(value=False)
        self.chat_windows = {}
        self.contacts = []
        self.networks = {}
        self._contact_index_map = []
        self.cover_traffic_enabled = True
        self.traffic_interval_ms = 4000
        self.relay_hops = 2
        self.onion_body_size = mda.ONION_BODY_SIZE
        self.outgoing_real_queue = []
        self.pending_updates = {}
        self._load_state()
        self._ensure_default_network()
        self._build_ui()
        self.active_network_var.trace_add("write", self._on_active_network_changed)
        self._refresh_active_network_selector()
        self.root.after(250, self._drain_messages)
        self.root.after(400, self._auto_start_node)
        self.root.after(self.traffic_interval_ms, self._traffic_tick)

    def _build_ui(self):
        self._create_menu()

        frame = ttk.Frame(self.root, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        ttk.Label(frame, text="Active Network").grid(row=0, column=0, sticky="w")
        self.active_network_selector = ttk.Combobox(
            frame,
            textvariable=self.active_network_var,
            values=self._network_names(),
            state="readonly",
            width=20,
        )
        self.active_network_selector.grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Label(frame, text="Host").grid(row=0, column=2, sticky="w")
        ttk.Entry(frame, textvariable=self.host_var, width=18).grid(row=0, column=3, sticky="ew", padx=4)
        ttk.Label(frame, text="Port").grid(row=0, column=4, sticky="w")
        ttk.Entry(frame, textvariable=self.port_var, width=10).grid(row=0, column=5, sticky="ew", padx=4)
        ttk.Button(frame, text="Detect IP", command=self._detect_ip).grid(row=0, column=6, padx=4)

        ttk.Button(frame, text="Start Node", command=self.start_node).grid(row=1, column=0, pady=6, sticky="ew")
        ttk.Button(frame, text="Stop Node", command=self.stop_node).grid(row=1, column=1, pady=6, sticky="ew")
        ttk.Button(frame, text="Import .mdar", command=self.import_mdar).grid(row=1, column=2, pady=6, sticky="ew")
        ttk.Button(frame, text="Export .mdar", command=self.export_mdar).grid(row=1, column=3, pady=6, sticky="ew")
        ttk.Label(frame, textvariable=self.node_status_var).grid(row=1, column=4, columnspan=3, sticky="w")

        ttk.Label(frame, text="Contact endpoint host:port").grid(row=2, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.peer_entry_var, width=25).grid(row=2, column=1, columnspan=2, sticky="ew", padx=4)
        ttk.Button(frame, text="Add Contact", command=self.add_contact_dialog).grid(row=2, column=3, sticky="ew", padx=4)
        ttk.Button(frame, text="Open Chat", command=self.open_selected_chat).grid(row=2, column=4, sticky="ew", padx=4)
        ttk.Button(frame, text="Remove Selected", command=self.remove_selected_peer).grid(row=2, column=5, sticky="ew")
        ttk.Button(frame, text="Ping Contacts", command=self.ping_peers).grid(row=2, column=6, sticky="ew", padx=4)

        ttk.Label(frame, text="Contacts").grid(row=3, column=0, sticky="w")
        self.peer_list = tk.Listbox(frame, height=8, exportselection=False)
        self.peer_list.grid(row=3, column=0, columnspan=7, sticky="nsew", pady=(4, 8))
        self.peer_list.bind("<Double-Button-1>", self._open_selected_chat_event)
        self.peer_list.bind("<Return>", self._open_selected_chat_event)

        ttk.Label(frame, text="Broadcast Message").grid(row=4, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.broadcast_var).grid(row=4, column=1, columnspan=5, sticky="ew", padx=4)
        ttk.Button(frame, text="Send to All", command=self.send_message).grid(row=4, column=6, sticky="ew")

        self.log = scrolledtext.ScrolledText(frame, height=16, state="disabled")
        self.log.grid(row=5, column=0, columnspan=7, sticky="nsew")

        for i in range(7):
            frame.columnconfigure(i, weight=1)
        frame.rowconfigure(3, weight=1)
        frame.rowconfigure(5, weight=2)

        self._refresh_contact_list()
        self._update_status()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _create_menu(self):
        menubar = tk.Menu(self.root)

        contacts_menu = tk.Menu(menubar, tearoff=False)
        contacts_menu.add_command(label="Add Contact", command=self.add_contact_dialog)
        contacts_menu.add_command(label="Edit Selected Contact", command=self.edit_selected_contact)
        contacts_menu.add_command(label="Delete Selected Contact", command=self.remove_selected_peer)
        contacts_menu.add_separator()
        contacts_menu.add_command(label="List Contacts", command=self.show_contacts)
        menubar.add_cascade(label="Contacts", menu=contacts_menu)

        network_menu = tk.Menu(menubar, tearoff=False)
        network_menu.add_command(label="Create New Network", command=self.create_network_dialog)
        network_menu.add_command(label="Edit Network Rules", command=self.edit_network_rules_dialog)
        network_menu.add_command(label="Join a Network", command=self.join_network_dialog)
        network_menu.add_command(label="Delete a Network", command=self.delete_network_dialog)
        network_menu.add_separator()
        network_menu.add_command(label="Import .mdar", command=self.import_mdar)
        network_menu.add_command(label="Export .mdar", command=self.export_mdar)
        network_menu.add_separator()
        network_menu.add_command(label="My Networks", command=self.show_networks)
        menubar.add_cascade(label="Network", menu=network_menu)

        node_menu = tk.Menu(menubar, tearoff=False)
        node_menu.add_command(label="Start Node", command=self.start_node)
        node_menu.add_command(label="Stop Node", command=self.stop_node)
        node_menu.add_command(label="Send Fake Message (Active Network)", command=self.send_fake_message_once)
        node_menu.add_command(label="Toggle Cover Traffic", command=self.toggle_cover_traffic)
        node_menu.add_separator()
        node_menu.add_command(label="Traffic Settings", command=self.traffic_settings_dialog)
        node_menu.add_command(label="Node Settings", command=self.node_settings_dialog)
        menubar.add_cascade(label="Node", menu=node_menu)

        experiment_menu = tk.Menu(menubar, tearoff=False)
        experiment_menu.add_command(label="Participation Settings", command=self.experiment_settings_dialog)
        experiment_menu.add_command(label="Open Collector Dashboard", command=self.open_collector_dashboard)
        experiment_menu.add_command(label="Test Collector Connection", command=self.test_collector_connection)
        menubar.add_cascade(label="Experiment", menu=experiment_menu)

        about_menu = tk.Menu(menubar, tearoff=False)
        about_menu.add_command(label="Help", command=self.show_help)
        about_menu.add_command(label="About", command=self.show_about)
        about_menu.add_command(label="Message History", command=self.show_message_history)
        menubar.add_cascade(label="About", menu=about_menu)

        self.root.config(menu=menubar)

    def _log(self, text):
        self.log.configure(state="normal")
        self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)
        self.log.configure(state="disabled")

    def _show_form_dialog(self, title, fields, submit_label="Save"):
        result = {"values": None}
        window = tk.Toplevel(self.root)
        window.title(title)
        window.transient(self.root)
        window.grab_set()
        window.resizable(True, False)

        frame = ttk.Frame(window, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")
        window.columnconfigure(0, weight=1)
        window.rowconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        variables = {}
        for row_index, field in enumerate(fields):
            name = field["name"]
            label = field.get("label", name)
            initial = field.get("initial", "")
            kind = field.get("kind", "entry")
            options = field.get("options", [])

            ttk.Label(frame, text=label).grid(row=row_index, column=0, sticky="w", padx=(0, 8), pady=4)
            var = tk.StringVar(value=str(initial))
            variables[name] = var
            if kind == "combobox":
                widget = ttk.Combobox(frame, textvariable=var, values=options, state="readonly")
            else:
                widget = ttk.Entry(frame, textvariable=var)
            widget.grid(row=row_index, column=1, sticky="ew", pady=4)
            if row_index == 0:
                widget.focus_set()

        buttons = ttk.Frame(frame)
        buttons.grid(row=len(fields), column=0, columnspan=2, sticky="e", pady=(10, 0))

        def on_save():
            values = {}
            for key, var in variables.items():
                values[key] = var.get().strip()
            result["values"] = values
            window.destroy()

        def on_cancel():
            window.destroy()

        ttk.Button(buttons, text="Cancel", command=on_cancel).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(buttons, text=submit_label, command=on_save).grid(row=0, column=1)

        window.protocol("WM_DELETE_WINDOW", on_cancel)
        self.root.wait_window(window)
        return result["values"]

    def _state_path(self):
        return os.path.join(os.getcwd(), self.STATE_FILE)

    def _load_state(self):
        path = self._state_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError, TypeError) as exc:
            print(f"Failed to load state from {path}: {exc}", flush=True)
            return

        node_data = payload.get("node", {})
        self.node_name_var.set(str(node_data.get("name", self.node_name_var.get())))
        self.node_description_var.set(str(node_data.get("description", self.node_description_var.get())))
        self.host_var.set(str(node_data.get("host", self.host_var.get())))
        self.port_var.set(str(node_data.get("port", self.port_var.get())))
        self.active_network_var.set(str(payload.get("active_network", self.active_network_var.get())))

        contacts = payload.get("contacts", [])
        if isinstance(contacts, list):
            self.contacts = []
            for item in contacts:
                if not isinstance(item, dict):
                    continue
                endpoint = item.get("endpoint")
                nickname = item.get("nickname")
                if endpoint and nickname:
                    self.contacts.append(
                        {
                            "nickname": str(nickname),
                            "endpoint": str(endpoint),
                            "circuit": str(item.get("circuit", "")),
                            "network": str(item.get("network", "")).strip(),
                        }
                    )

        networks = payload.get("networks", {})
        if isinstance(networks, dict):
            self.networks = {}
            for name, info in networks.items():
                if not isinstance(info, dict):
                    continue
                network_info = {
                    "type": str(info.get("type", "private")),
                    "description": str(info.get("description", "")),
                    "rules": list(info.get("rules", [])) if isinstance(info.get("rules", []), list) else [str(info.get("rules", ""))],
                    "nodes": dict(info.get("nodes", {})) if isinstance(info.get("nodes", {}), dict) else {},
                    "my_role": str(info.get("my_role", "member")),
                    "min_approvals": 2,
                }
                try:
                    network_info["min_approvals"] = max(1, int(info.get("min_approvals", 2)))
                except (TypeError, ValueError):
                    network_info["min_approvals"] = 2
                membership_status = info.get("membership_status")
                if membership_status:
                    network_info["membership_status"] = str(membership_status)
                self.networks[str(name)] = network_info

        traffic_settings = payload.get("traffic_settings", {})
        if isinstance(traffic_settings, dict):
            interval = traffic_settings.get("interval_ms", self.traffic_interval_ms)
            relay_hops = traffic_settings.get("relay_hops", self.relay_hops)
            onion_body_size = traffic_settings.get("onion_body_size", self.onion_body_size)
            cover_enabled = traffic_settings.get("cover_enabled", self.cover_traffic_enabled)
            try:
                self.traffic_interval_ms = max(1000, int(interval))
            except (TypeError, ValueError):
                pass
            try:
                self.relay_hops = max(0, int(relay_hops))
            except (TypeError, ValueError):
                pass
            try:
                self.onion_body_size = max(128, int(onion_body_size))
            except (TypeError, ValueError):
                pass
            if isinstance(cover_enabled, str):
                self.cover_traffic_enabled = cover_enabled.strip().lower() in ("1", "true", "enabled", "yes", "on")
            else:
                self.cover_traffic_enabled = bool(cover_enabled)

        experiment_settings = payload.get("experiment_settings", {})
        if isinstance(experiment_settings, dict):
            opt_in = experiment_settings.get("opt_in", self.experiment_opt_in_var.get())
            collector_url = experiment_settings.get("collector_url", self.experiment_collector_url_var.get())
            publish = experiment_settings.get("publish", self.experiment_publish_var.get())
            auto_upload = experiment_settings.get("auto_upload", self.experiment_auto_upload_var.get())
            self.experiment_opt_in_var.set(bool(opt_in))
            self.experiment_collector_url_var.set(str(collector_url))
            self.experiment_publish_var.set(bool(publish))
            self.experiment_auto_upload_var.set(bool(auto_upload))

    def _save_state(self):
        payload = {
            "node": {
                "name": self.node_name_var.get().strip(),
                "description": self.node_description_var.get().strip(),
                "host": self.host_var.get().strip(),
                "port": self.port_var.get().strip(),
            },
            "active_network": self.active_network_var.get().strip(),
            "contacts": self.contacts,
            "networks": self.networks,
            "traffic_settings": {
                "interval_ms": self.traffic_interval_ms,
                "relay_hops": self.relay_hops,
                "onion_body_size": self.onion_body_size,
                "cover_enabled": self.cover_traffic_enabled,
            },
            "experiment_settings": {
                "opt_in": bool(self.experiment_opt_in_var.get()),
                "collector_url": self.experiment_collector_url_var.get().strip(),
                "publish": bool(self.experiment_publish_var.get()),
                "auto_upload": bool(self.experiment_auto_upload_var.get()),
            },
        }
        path = self._state_path()
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
        except OSError as exc:
            self._log(f"State save failed: {exc}")
            return
        for network_name, snapshot in self.networks.items():
            self.storage.save_network_snapshot(network_name, snapshot)

    def experiment_settings_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Experiment Participation Settings")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        ttk.Label(dialog, text="Data collection participation").grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(12, 8))
        ttk.Checkbutton(dialog, text="I agree to share experiment data from this machine", variable=self.experiment_opt_in_var).grid(row=1, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 8))
        ttk.Checkbutton(dialog, text="Publish my run to the collector for analysis", variable=self.experiment_publish_var).grid(row=2, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 8))
        ttk.Checkbutton(dialog, text="Auto-upload local batches when available", variable=self.experiment_auto_upload_var).grid(row=3, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 8))

        ttk.Label(dialog, text="Collector URL").grid(row=4, column=0, sticky="w", padx=12, pady=(0, 6))
        ttk.Entry(dialog, textvariable=self.experiment_collector_url_var, width=38).grid(row=4, column=1, sticky="ew", padx=(0, 12), pady=(0, 6))

        ttk.Label(dialog, text="Status").grid(row=5, column=0, sticky="w", padx=12, pady=(0, 6))
        status_label = ttk.Label(dialog, text="Opt-in is off")
        status_label.grid(row=5, column=1, sticky="w", padx=(0, 12), pady=(0, 6))

        def update_status_label():
            if self.experiment_opt_in_var.get():
                status_label.config(text="Participation enabled")
            else:
                status_label.config(text="Participation disabled")
        self.experiment_opt_in_var.trace_add("write", lambda *_: update_status_label())
        update_status_label()

        ttk.Button(dialog, text="Test Connection", command=self.test_collector_connection).grid(row=6, column=0, padx=12, pady=(8, 12), sticky="w")
        ttk.Button(dialog, text="Close", command=dialog.destroy).grid(row=6, column=1, sticky="e", padx=(0, 12), pady=(8, 12))
        self._save_state()

    def test_collector_connection(self):
        collector_url = self.experiment_collector_url_var.get().strip()
        if not collector_url:
            messagebox.showwarning("Experiment", "Collector URL is empty.")
            return
        url = f"{collector_url.rstrip('/')}/health"
        try:
            with urllib.request.urlopen(url, timeout=8) as response:
                payload = json.loads(response.read().decode("utf-8"))
            messagebox.showinfo("Collector Health", json.dumps(payload, indent=2, sort_keys=True))
        except Exception as exc:
            messagebox.showerror("Collector Health", f"Unable to contact collector:\n{exc}")

    def open_collector_dashboard(self):
        script_path = os.path.join(os.getcwd(), "collector_dashboard.py")
        if not os.path.exists(script_path):
            messagebox.showwarning("Collector Dashboard", "collector_dashboard.py was not found in the project folder.")
            return
        try:
            subprocess.Popen([sys.executable, script_path, "--collector-url", self.experiment_collector_url_var.get().strip() or "http://127.0.0.1:9090"])
        except Exception as exc:
            messagebox.showerror("Collector Dashboard", f"Failed to launch dashboard:\n{exc}")

    def _ensure_default_network(self):
        active = self._active_network_name()
        if active not in self.networks:
            self.networks[active] = {
                "type": "private",
                "description": "",
                "rules": [],
                "nodes": {},
                "membership_status": "active",
                "my_role": "member",
                "min_approvals": 2,
            }

    def _active_network_name(self):
        return self.active_network_var.get().strip() or "lab-network"

    def _network_names(self):
        names = sorted(self.networks.keys())
        active = self._active_network_name()
        if active and active not in names:
            names.append(active)
        return names

    def _refresh_active_network_selector(self):
        if hasattr(self, "active_network_selector"):
            self.active_network_selector["values"] = self._network_names()

    def _on_active_network_changed(self, *_args):
        active = self._active_network_name()
        if active not in self.networks:
            self.networks[active] = {
                "type": "private",
                "description": "",
                "rules": [],
                "nodes": {},
                "membership_status": "active",
                "my_role": "member",
                "min_approvals": 2,
            }
        self._refresh_active_network_selector()
        self._sync_node_peers_for_active_network()
        self._update_status()
        self._save_state()

    def _contact_network(self, contact):
        network_name = str(contact.get("network", "")).strip()
        return network_name

    def _contact_display(self, contact):
        nickname = contact.get("nickname", "")
        network_name = self._contact_network(contact) or "unassigned"
        circuit = contact.get("circuit", "")
        endpoint = contact.get("endpoint", "")
        if circuit:
            return f"{nickname} | network: {network_name} | circuit: {circuit}"
        if endpoint:
            return f"{nickname} | network: {network_name}"
        return f"{nickname} | network: {network_name}"

    def _refresh_contact_list(self):
        self.peer_list.delete(0, tk.END)
        self._contact_index_map = []
        for index, contact in enumerate(self.contacts):
            self.peer_list.insert(tk.END, self._contact_display(contact))
            self._contact_index_map.append(index)

    def _selected_contact_index(self):
        selected = self.peer_list.curselection()
        if not selected:
            return None
        list_index = selected[0]
        if list_index >= len(self._contact_index_map):
            return None
        return self._contact_index_map[list_index]

    def _selected_contact(self):
        index = self._selected_contact_index()
        if index is None:
            return None
        return self.contacts[index]

    def _find_contact_by_endpoint(self, endpoint):
        for contact in self.contacts:
            if contact.get("endpoint") == endpoint:
                return contact
        return None

    def _upsert_contact(self, endpoint, nickname=None, circuit=None, network=None):
        existing = self._find_contact_by_endpoint(endpoint)
        if existing:
            if nickname:
                existing["nickname"] = nickname
            if circuit is not None:
                existing["circuit"] = circuit
            if network is not None:
                existing["network"] = network
            return existing
        contact = {
            "nickname": nickname or endpoint,
            "endpoint": endpoint,
            "circuit": circuit or "",
            "network": network or "",
        }
        self.contacts.append(contact)
        return contact

    def _open_selected_chat_event(self, _event):
        self.open_selected_chat()

    def _detect_ip(self):
        self.host_var.set(mda.get_local_ip())
        self._log("Detected local IP.")
        self._save_state()

    def _update_status(self):
        active_network = self._active_network_name()
        if self.node:
            self.node_status_var.set(
                f"Running as {self.node.nodeid} | Name: {self.node_name_var.get().strip() or 'node'} | Active network: {active_network}"
            )
        else:
            self.node_status_var.set(f"Stopped | Active network: {active_network}")

    def _auto_start_node(self):
        if self.node:
            return
        self.start_node()

    def _sync_node_peers_for_active_network(self):
        if not self.node:
            return
        target_peers = set(self._peers_from_contacts())
        current_peers = set((host, port) for host, port in self.node.peers)

        for host, port in list(current_peers - target_peers):
            self.node.remove_peer(f"{host}:{port}")

        for host, port in list(target_peers - current_peers):
            self.node.add_peer(f"{host}:{port}")

    def _put_node_entry(self, nodes, name, entry):
        """Insert/update a node in a network node map without clobbering a different node.

        Node maps are keyed by nickname, and nicknames are not unique (every client
        defaults to "node"). Match by endpoint first; if the name is already used by a
        different endpoint, store under a suffixed key instead of overwriting it.
        """
        endpoint = entry.get("endpoint", "")
        for node_key, node_entry in nodes.items():
            if endpoint and self._extract_node_endpoint(node_entry) == endpoint:
                if isinstance(node_entry, dict):
                    node_entry.update(entry)
                else:
                    nodes[node_key] = dict(entry)
                return node_key
        base = str(name).strip() or endpoint or "node"
        key, suffix = base, 2
        while key in nodes:
            key = f"{base}-{suffix}"
            suffix += 1
        nodes[key] = dict(entry)
        return key

    def _upsert_local_node_in_networks(self):
        local_endpoint = self._local_endpoint()
        local_name = self.node_name_var.get().strip() or "self"
        local_pubkey = self.node.get_public_key_pem() if self.node else self.identity.get("public_key_pem", "")
        for network_name, network_info in self.networks.items():
            nodes = network_info.get("nodes", {})
            if not isinstance(nodes, dict):
                nodes = {}
            updated = False
            for node_key, node_entry in list(nodes.items()):
                endpoint = self._extract_node_endpoint(node_entry)
                if endpoint != local_endpoint:
                    continue
                if not isinstance(node_entry, dict):
                    node_entry = {"endpoint": endpoint}
                node_entry["endpoint"] = local_endpoint
                node_entry["nickname"] = local_name
                node_entry["pubkey"] = local_pubkey
                node_entry.setdefault("role", network_info.get("my_role", "member"))
                nodes[node_key] = node_entry
                updated = True
            if not updated:
                self._put_node_entry(nodes, local_name, {
                    "endpoint": local_endpoint,
                    "nickname": local_name,
                    "role": network_info.get("my_role", "member"),
                    "pubkey": local_pubkey,
                })
            network_info["nodes"] = nodes

    def _drain_messages(self):
        while True:
            try:
                packet = self.message_queue.get_nowait()
            except queue.Empty:
                break
            sender = packet.get("sender", packet.get("received_from", "unknown"))
            packet_network = str(packet.get("network", "")).strip()
            msg_type = packet.get("type", "data")
            text = packet.get("text", "")
            self._log(f"RX [{msg_type}] from {sender}: {text}")
            if msg_type == "control":
                self._handle_control_packet(packet)
                continue
            if msg_type in ("chat", "real"):
                peer = self._resolve_peer(packet)
                contact = self._ensure_peer_in_contacts(peer, packet_network or self._active_network_name())
                if packet_network and packet_network != self._active_network_name():
                    self._log(
                        f"Chat received for network '{packet_network}' while active network is "
                        f"'{self._active_network_name()}'. Switch network to reply."
                    )
                    continue
                window = self.open_chat_for_peer(contact)
                if window:
                    window.append_incoming(sender, text)
                self._log_message_db(
                    direction="in",
                    network_name=packet_network or self._active_network_name(),
                    sender=sender,
                    receiver=self._local_endpoint(),
                    message_type="real",
                    route_id=str(packet.get("route_id", "")),
                    text=text,
                    route=[],
                )
            if msg_type == "fake":
                self._log(f"Fake message received and ignored for route {packet.get('route_id', '')}.")
                self._log_message_db(
                    direction="in",
                    network_name=packet_network or self._active_network_name(),
                    sender=sender,
                    receiver=self._local_endpoint(),
                    message_type="fake",
                    route_id=str(packet.get("route_id", "")),
                    text="fake",
                    route=[],
                )
        self.root.after(250, self._drain_messages)

    def _on_packet(self, packet):
        self.message_queue.put(packet)

    def _local_endpoint(self):
        if self.node and self.node.nodeid:
            return self.node.nodeid
        return f"{self.host_var.get().strip()}:{self.port_var.get().strip()}"

    def _handle_control_packet(self, packet):
        action = str(packet.get("action", "")).strip().lower()
        network_name = str(packet.get("network", "")).strip()
        self._log_message_db(
            direction="in",
            network_name=network_name,
            sender=str(packet.get("sender", "")),
            receiver=self._local_endpoint(),
            message_type="control",
            route_id=str(packet.get("route_id", "")),
            text=action or "control",
            route=[],
        )
        if action == "join_request":
            self._handle_join_request(packet, network_name)
            return
        if action in ("join_approved", "node_list_update"):
            self._handle_signed_update_packet(packet, network_name, action, mark_active=(action == "join_approved"))
            return
        if action == "join_rejected":
            reason = str(packet.get("reason", "Rejected by trusted/seed node."))
            self._log(f"Join request rejected for network '{network_name}': {reason}")
            messagebox.showwarning("Join Request Rejected", reason)
            return
        self._log(f"Unknown control action ignored: {action}")

    def _handle_signed_update_packet(self, packet, network_name, action, mark_active=False):
        update_id = str(packet.get("update_id", "")).strip()
        update_hash = str(packet.get("update_hash", "")).strip()
        update_body = packet.get("update_body", {})
        vote = {
            "signer": packet.get("signer", ""),
            "signer_pubkey": packet.get("signer_pubkey", ""),
            "signature": packet.get("signature", ""),
        }
        if not update_id or not update_hash or not isinstance(update_body, dict):
            self._log(f"Ignored malformed update packet for network '{network_name}'.")
            return
        computed_hash = self._network_update_hash(update_body)
        if computed_hash != update_hash:
            self._log(f"Ignored update with hash mismatch for network '{network_name}'.")
            return
        if not self._verify_update_vote(action, network_name, update_id, update_hash, vote):
            self._log(f"Ignored update with invalid signature for network '{network_name}'.")
            return
        signer = str(vote.get("signer", "")).strip()
        signer_pubkey = str(vote.get("signer_pubkey", "")).strip()
        known_pubkey = self._network_public_key_map(network_name).get(signer, "")
        if known_pubkey and known_pubkey != signer_pubkey:
            self._log(f"Ignored update with signer key mismatch for network '{network_name}'.")
            return
        signer_role = ""
        role_rank = {"member": 0, "trusted": 1, "seed": 2}
        for node_key, node_entry in (update_body.get("nodes", {}) or {}).items():
            endpoint = self._extract_node_endpoint(node_entry)
            if endpoint != signer:
                continue
            candidate_role = self._extract_node_role(node_key, node_entry)
            if role_rank.get(candidate_role, -1) > role_rank.get(signer_role, -1):
                signer_role = candidate_role
        if signer_role not in ("trusted", "seed"):
            self._log(f"Ignored update from non-trusted signer '{signer}' for network '{network_name}'.")
            return
        pending = self._register_update_vote(network_name, action, update_id, update_hash, update_body, vote)
        if pending is None:
            self._log(f"Ignored conflicting update packet for network '{network_name}'.")
            return

        my_role = str(self.networks.get(network_name, {}).get("my_role", "member")).strip().lower()
        my_signer = self._local_endpoint()
        if action == "node_list_update" and my_role in ("trusted", "seed") and my_signer not in pending["votes"]:
            my_vote = self._sign_update_vote(action, network_name, update_id, update_hash)
            pending["votes"][my_vote["signer"]] = my_vote
            self._broadcast_update_vote(network_name, action, update_id, update_hash, update_body, my_vote)

        if action == "join_approved":
            required = 1
        else:
            required = self._required_approvals(network_name, update_body)
        if pending["applied"]:
            return
        if len(pending["votes"]) < required:
            self._log(
                f"Pending update '{update_id}' for network '{network_name}' "
                f"({len(pending['votes'])}/{required} approvals)."
            )
            return

        approved_packet = dict(packet)
        approved_packet.update(update_body)
        pending["applied"] = True
        self._apply_network_update(approved_packet, network_name, mark_active=mark_active)

    def _resolve_peer(self, packet):
        sender = packet.get("sender")
        if sender:
            return sender
        received_from = packet.get("received_from", "")
        if ":" in received_from:
            host = received_from.split(":", 1)[0]
            return f"{host}:{self.port_var.get().strip() or '50404'}"
        return received_from or "unknown:0"

    def _ensure_peer_in_contacts(self, peer, network_name=None):
        if not peer or peer == "unknown:0":
            return {
                "nickname": "Unknown",
                "endpoint": peer,
                "circuit": "",
                "network": (network_name or self._active_network_name()),
            }
        nickname = f"Peer-{peer.rsplit(':', 1)[-1]}" if ":" in peer else "Peer"
        contact = self._upsert_contact(endpoint=peer, nickname=nickname, network=(network_name or self._active_network_name()))
        self._refresh_contact_list()
        self._save_state()
        if self.node and self._contact_network(contact) == self._active_network_name():
            try:
                self.node.add_peer(peer)
            except ValueError:
                self._log(f"Could not add auto-discovered contact: {peer}")
        return contact

    def add_peer(self, endpoint, nickname=None, circuit="", network_name=None):
        if not endpoint:
            return
        try:
            host, port = parse_peer(endpoint)
            endpoint = f"{host}:{port}"
        except ValueError:
            messagebox.showerror("Invalid Endpoint", "Use endpoint format: host:port")
            return
        network_name = (network_name or self._active_network_name()).strip()
        if not network_name:
            messagebox.showerror("Add Contact", "Contact must belong to a network.")
            return
        if network_name not in self.networks:
            messagebox.showerror("Add Contact", f"Unknown network: {network_name}")
            return
        default_nickname = endpoint
        contact = self._upsert_contact(
            endpoint=endpoint,
            nickname=(nickname or "").strip() or default_nickname,
            circuit=(circuit or "").strip(),
            network=network_name,
        )
        self._refresh_contact_list()
        if self.node and network_name == self._active_network_name():
            self.node.add_peer(contact["endpoint"])
        self.peer_entry_var.set("")
        self._log(f"Contact saved: {contact['nickname']} [{network_name}]")
        self._sync_node_peers_for_active_network()
        self._save_state()

    def add_contact_dialog(self):
        network_options = self._network_names()
        if not network_options:
            messagebox.showinfo("Add Contact", "Create or join a network first, then add contacts.")
            return
        values = self._show_form_dialog(
            "Add Contact",
            [
                {"name": "endpoint", "label": "Endpoint host:port", "initial": self.peer_entry_var.get().strip()},
                {"name": "nickname", "label": "Nickname", "initial": ""},
                {"name": "circuit", "label": "Preferred circuit label", "initial": ""},
                {"name": "network", "label": "MDA network", "initial": self._active_network_name(), "kind": "combobox", "options": network_options},
            ],
            submit_label="Save Contact",
        )
        if values is None:
            return
        endpoint = values.get("endpoint", "")
        if not endpoint:
            messagebox.showerror("Add Contact", "Endpoint is required.")
            return
        self.add_peer(
            endpoint=endpoint,
            nickname=values.get("nickname", ""),
            circuit=values.get("circuit", ""),
            network_name=values.get("network", ""),
        )

    def edit_selected_contact(self):
        contact = self._selected_contact()
        if not contact:
            messagebox.showinfo("Edit Contact", "Select a contact first.")
            return
        values = self._show_form_dialog(
            "Edit Contact",
            [
                {"name": "endpoint", "label": "Endpoint host:port", "initial": contact.get("endpoint", "")},
                {"name": "nickname", "label": "Nickname", "initial": contact.get("nickname", "")},
                {"name": "circuit", "label": "Preferred circuit label", "initial": contact.get("circuit", "")},
                {"name": "network", "label": "MDA network", "initial": self._contact_network(contact) or self._active_network_name(), "kind": "combobox", "options": self._network_names()},
            ],
            submit_label="Update Contact",
        )
        if values is None:
            return
        endpoint = values.get("endpoint", "")
        nickname = values.get("nickname", "")
        circuit = values.get("circuit", "")
        network_name = values.get("network", "").strip()
        if not network_name:
            messagebox.showerror("Edit Contact", "MDA network is required.")
            return
        if network_name not in self.networks:
            messagebox.showerror("Edit Contact", f"Unknown network: {network_name}")
            return
        try:
            host, port = parse_peer(endpoint.strip())
            endpoint = f"{host}:{port}"
        except ValueError:
            messagebox.showerror("Invalid Endpoint", "Use endpoint format: host:port")
            return

        old_endpoint = contact["endpoint"]
        contact["nickname"] = nickname.strip() or endpoint
        contact["endpoint"] = endpoint
        contact["circuit"] = circuit.strip()
        contact["network"] = network_name

        if old_endpoint in self.chat_windows and old_endpoint != endpoint:
            self.chat_windows[old_endpoint].window.destroy()
            del self.chat_windows[old_endpoint]

        if self.node:
            self.node.remove_peer(old_endpoint)
            if network_name == self._active_network_name():
                self.node.add_peer(endpoint)

        self._refresh_contact_list()
        self._log(f"Contact updated: {contact['nickname']} [{network_name}]")
        self._sync_node_peers_for_active_network()
        self._save_state()

    def show_contacts(self):
        if not self.contacts:
            messagebox.showinfo("Contacts", "No contacts saved.")
            return
        lines = []
        for contact in self.contacts:
            lines.append(self._contact_display(contact))
        messagebox.showinfo("Contacts", "\n".join(lines))

    def _can_contact_in_active_network(self, contact):
        active_network = self._active_network_name()
        network_info = self.networks.get(active_network, {})
        if network_info.get("membership_status", "active") != "active":
            return False
        contact_network = self._contact_network(contact)
        if not contact_network:
            return False
        return contact_network == active_network

    def open_selected_chat(self):
        contact = self._selected_contact()
        if not contact:
            messagebox.showinfo("Open Chat", "Select a contact first.")
            return
        if not self._can_contact_in_active_network(contact):
            active_network = self._active_network_name()
            status = self.networks.get(active_network, {}).get("membership_status", "active")
            if status != "active":
                messagebox.showwarning(
                    "Network Not Approved",
                    f"Active network '{active_network}' status is '{status}'. Wait for approval before contacting members.",
                )
                return
            messagebox.showwarning(
                "Network Membership Required",
                f"You can only contact members of the active network '{self._active_network_name()}'.",
            )
            return
        self.open_chat_for_peer(contact)

    def open_chat_for_peer(self, contact):
        if not self._can_contact_in_active_network(contact):
            self._log(
                f"Chat blocked for {contact.get('nickname', 'unknown')}: "
                f"contact is not in active network '{self._active_network_name()}'."
            )
            return None
        endpoint = contact.get("endpoint", "")
        title_label = f"{contact.get('nickname', endpoint)} | {self._contact_network(contact)}"
        if endpoint in self.chat_windows:
            self.chat_windows[endpoint].focus()
            return self.chat_windows[endpoint]
        window = ChatWindow(
            self.root,
            peer=endpoint,
            title_label=title_label,
            send_callback=self.send_to_peer,
            close_callback=self._on_chat_window_closed,
        )
        self.chat_windows[endpoint] = window
        self._log(f"Opened chat with {title_label}")
        return window

    def _on_chat_window_closed(self, endpoint):
        if endpoint in self.chat_windows:
            del self.chat_windows[endpoint]

    def _queue_real_message(self, receiver_endpoint, text):
        self.outgoing_real_queue.append(
            {
                "receiver": receiver_endpoint,
                "text": text,
                "network": self._active_network_name(),
                "queued_at": time.time(),
            }
        )

    def _send_onion_payload(self, receiver_endpoint, text, message_type, network_name):
        if not self.node:
            return False, "node-not-running"
        relay_pool = self._network_endpoints(network_name)
        public_key_map = self._network_public_key_map(network_name)
        route_result = self.node.send_onion_message(
            receiver_endpoint=receiver_endpoint,
            text=text,
            network_name=network_name,
            message_type=message_type,
            relay_count=self.relay_hops,
            relay_pool=relay_pool,
            public_key_map=public_key_map,
            timeout=5,
        )
        self._log_message_db(
            direction="out",
            network_name=network_name,
            sender=self.node.nodeid,
            receiver=receiver_endpoint,
            message_type=message_type,
            route_id=route_result.get("route_id", ""),
            text=text,
            route=route_result.get("route", []),
        )
        return True, route_result

    def _send_fake_slot(self, network_name):
        active_contacts = [c for c in self.contacts if self._contact_network(c) == network_name]
        if not active_contacts:
            return
        receiver_endpoint = random.choice(active_contacts).get("endpoint", "")
        if not receiver_endpoint:
            return
        fake_text = f"cover-{int(time.time())}"
        try:
            ok, result = self._send_onion_payload(receiver_endpoint, fake_text, "fake", network_name)
            if ok:
                self._log(f"Cover traffic sent on '{network_name}' route: {result.get('route', [])}")
        except (OSError, ValueError) as exc:
            self._log(f"Cover traffic failed: {exc}")

    def _traffic_tick(self):
        try:
            if self.node:
                active_network = self._active_network_name()
                status = self.networks.get(active_network, {}).get("membership_status", "active")
                if status == "active":
                    queue_index = None
                    for idx, queued in enumerate(self.outgoing_real_queue):
                        if queued.get("network") == active_network:
                            queue_index = idx
                            break
                    if queue_index is not None:
                        item = self.outgoing_real_queue.pop(queue_index)
                        try:
                            ok, _result = self._send_onion_payload(
                                item.get("receiver", ""),
                                item.get("text", ""),
                                "real",
                                active_network,
                            )
                            if ok:
                                self._log(f"Traffic slot used by real message to {item.get('receiver', '')}")
                        except (OSError, ValueError) as exc:
                            self._log(f"Queued real message failed: {exc}")
                    elif self.cover_traffic_enabled:
                        self._send_fake_slot(active_network)
        finally:
            self.root.after(self.traffic_interval_ms, self._traffic_tick)

    def toggle_cover_traffic(self):
        self.cover_traffic_enabled = not self.cover_traffic_enabled
        state = "enabled" if self.cover_traffic_enabled else "disabled"
        self._log(f"Cover traffic {state}.")
        self._save_state()
        messagebox.showinfo("Cover Traffic", f"Cover traffic is now {state}.")

    def traffic_settings_dialog(self):
        values = self._show_form_dialog(
            "Traffic Settings",
            [
                {"name": "interval_ms", "label": "Traffic slot interval (ms)", "initial": str(self.traffic_interval_ms)},
                {"name": "relay_hops", "label": "Relay hops", "initial": str(self.relay_hops)},
                {"name": "onion_body_size", "label": "Onion payload size (bytes)", "initial": str(self.onion_body_size)},
                {
                    "name": "cover_enabled",
                    "label": "Cover traffic",
                    "initial": "enabled" if self.cover_traffic_enabled else "disabled",
                    "kind": "combobox",
                    "options": ["enabled", "disabled"],
                },
            ],
            submit_label="Save Traffic Settings",
        )
        if values is None:
            return
        try:
            interval_ms = max(1000, int(values.get("interval_ms", self.traffic_interval_ms)))
            relay_hops = max(0, int(values.get("relay_hops", self.relay_hops)))
            onion_body_size = max(128, int(values.get("onion_body_size", self.onion_body_size)))
        except ValueError:
            messagebox.showerror("Traffic Settings", "Interval, relay hops, and payload size must be numeric.")
            return
        cover_enabled = values.get("cover_enabled", "enabled").strip().lower() == "enabled"

        self.traffic_interval_ms = interval_ms
        self.relay_hops = relay_hops
        self.onion_body_size = onion_body_size
        self.cover_traffic_enabled = cover_enabled
        if self.node:
            self.node.onion_body_size = self.onion_body_size
        self._save_state()
        self._log(
            f"Traffic settings updated: interval={self.traffic_interval_ms}ms, "
            f"hops={self.relay_hops}, onion_body_size={self.onion_body_size}, "
            f"cover={'on' if self.cover_traffic_enabled else 'off'}"
        )

    def send_to_peer(self, peer, text):
        if not self.node:
            messagebox.showwarning("Node Not Running", "Start the node first.")
            return False
        active_network = self._active_network_name()
        status = self.networks.get(active_network, {}).get("membership_status", "active")
        if status != "active":
            messagebox.showwarning(
                "Network Not Approved",
                f"Active network '{active_network}' status is '{status}'. Wait for approval before messaging.",
            )
            return False
        contact = self._find_contact_by_endpoint(peer)
        if not contact:
            messagebox.showerror("Contact Not Found", "This endpoint is not saved as a contact.")
            return False
        if not self._can_contact_in_active_network(contact):
            messagebox.showwarning(
                "Network Membership Required",
                f"Cannot contact '{contact.get('nickname', peer)}' because they are not in active network '{self._active_network_name()}'.",
            )
            return False
        try:
            host, port = parse_peer(peer)
        except ValueError:
            messagebox.showerror("Invalid Endpoint", f"Unsupported endpoint: {peer}")
            return False
        endpoint = f"{host}:{port}"
        self._queue_real_message(endpoint, text)
        self._log(f"Queued real message to {endpoint}")
        return True

    def remove_selected_peer(self):
        index = self._selected_contact_index()
        if index is None:
            return
        contact = self.contacts[index]
        if not messagebox.askyesno("Delete Contact", f"Delete {contact['nickname']} ({contact['endpoint']})?"):
            return
        endpoint = contact["endpoint"]
        if endpoint in self.chat_windows:
            self.chat_windows[endpoint].window.destroy()
        if self.node:
            self.node.remove_peer(endpoint)
        self.contacts.pop(index)
        self._refresh_contact_list()
        self._log(f"Contact removed: {endpoint}")
        self._sync_node_peers_for_active_network()
        self._save_state()

    def _peers_from_contacts(self):
        peers = []
        active_network = self._active_network_name()
        network_info = self.networks.get(active_network, {})
        if network_info.get("membership_status", "active") != "active":
            return peers
        for contact in self.contacts:
            if self._contact_network(contact) != active_network:
                continue
            endpoint = contact.get("endpoint", "")
            try:
                host, port = parse_peer(endpoint)
            except ValueError:
                continue
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

        peers = self._peers_from_contacts()
        try:
            self.node = mda(
                host=host,
                port=port,
                peers=peers,
                node_name=self.node_name_var.get().strip() or f"node-{port}",
                on_message=self._on_packet,
                private_key_pem=self.identity.get("private_key_pem", ""),
                public_key_pem=self.identity.get("public_key_pem", ""),
                onion_body_size=self.onion_body_size,
            )
            self.node.start_server()
        except OSError as exc:
            self.node = None
            messagebox.showerror("Start Failed", str(exc))
            return
        self._upsert_local_node_in_networks()
        self._sync_node_peers_for_active_network()
        self._update_status()
        self._log(f"Node started on {self.node.nodeid}")
        self._save_state()

    def stop_node(self):
        if self.node:
            self.node.close()
            self.node = None
            self._log("Node stopped.")
        self._update_status()

    def node_settings_dialog(self):
        values = self._show_form_dialog(
            "Node Settings",
            [
                {"name": "name", "label": "Node name", "initial": self.node_name_var.get()},
                {"name": "description", "label": "Node description", "initial": self.node_description_var.get()},
                {"name": "host", "label": "Host", "initial": self.host_var.get()},
                {"name": "port", "label": "Port", "initial": self.port_var.get()},
            ],
            submit_label="Save Settings",
        )
        if values is None:
            return
        name = values.get("name", "")
        description = values.get("description", "")
        host = values.get("host", "")
        port_text = values.get("port", "")
        try:
            int(port_text.strip())
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be a number.")
            return
        self.node_name_var.set(name.strip() or "node")
        self.node_description_var.set(description.strip())
        self.host_var.set(host.strip())
        self.port_var.set(port_text.strip())
        self._upsert_local_node_in_networks()
        self._update_status()
        self._save_state()
        self._log("Node settings updated.")

    def send_message(self):
        if not self.node:
            messagebox.showwarning("Node Not Running", "Start the node first.")
            return
        text = self.broadcast_var.get().strip()
        if not text:
            return
        active_network = self._active_network_name()
        status = self.networks.get(active_network, {}).get("membership_status", "active")
        if status != "active":
            messagebox.showwarning(
                "Network Not Approved",
                f"Active network '{active_network}' status is '{status}'. Wait for approval before messaging.",
            )
            return
        queued_count = 0
        for contact in self.contacts:
            if self._contact_network(contact) != active_network:
                continue
            endpoint = contact.get("endpoint", "")
            try:
                parse_peer(endpoint)
            except ValueError:
                continue
            self._queue_real_message(endpoint, text)
            queued_count += 1
        self._log(f"Queued broadcast real message to {queued_count} contact(s) in network '{active_network}'.")
        self.broadcast_var.set("")

    def ping_peers(self):
        if not self.node:
            messagebox.showwarning("Node Not Running", "Start the node first.")
            return
        active_network = self._active_network_name()
        status = self.networks.get(active_network, {}).get("membership_status", "active")
        if status != "active":
            self._log(f"Ping skipped: network '{active_network}' status is '{status}'.")
            return
        active_contacts = [c for c in self.contacts if self._contact_network(c) == active_network]
        if not active_contacts:
            self._log(f"No contacts configured in active network '{active_network}'.")
            return
        for contact in active_contacts:
            endpoint = contact.get("endpoint", "")
            try:
                host, port = parse_peer(endpoint)
            except ValueError:
                self._log(f"Ping skipped invalid endpoint: {endpoint}")
                continue
            try:
                response = self.node.ping_peer(host, port, timeout=2)
                if response and response.get("type") == "pong":
                    self._log(f"Ping OK: {endpoint} -> {response.get('nodeid')}")
                else:
                    self._log(f"Ping no response: {endpoint}")
            except OSError as exc:
                self._log(f"Ping failed {endpoint}: {exc}")

    def send_fake_message_once(self):
        if not self.node:
            messagebox.showwarning("Node Not Running", "Start the node first.")
            return
        active_network = self._active_network_name()
        status = self.networks.get(active_network, {}).get("membership_status", "active")
        if status != "active":
            messagebox.showwarning(
                "Network Not Approved",
                f"Active network '{active_network}' status is '{status}'. Wait for approval before fake routing.",
            )
            return
        active_contacts = [c for c in self.contacts if self._contact_network(c) == active_network]
        if not active_contacts:
            messagebox.showinfo("Fake Message", "No receiver candidates available in active network.")
            return
        receiver_endpoint = random.choice(active_contacts).get("endpoint", "")
        fake_text = f"cover-{int(time.time())}"
        try:
            ok, result = self._send_onion_payload(receiver_endpoint, fake_text, "fake", active_network)
        except (OSError, ValueError) as exc:
            self._log(f"Fake message failed: {exc}")
            messagebox.showerror("Fake Message Failed", str(exc))
            return
        if ok:
            self._log(f"Fake onion message sent on network '{active_network}' via route: {result.get('route', [])}")

    @staticmethod
    def _normalize_network_nodes(nodes):
        normalized = {}
        if not isinstance(nodes, dict):
            return normalized
        for key, value in nodes.items():
            if isinstance(value, str):
                normalized[str(key)] = value
                continue
            if isinstance(value, dict):
                endpoint = value.get("endpoint")
                host = value.get("host")
                port = value.get("port")
                if endpoint:
                    normalized[str(key)] = str(endpoint)
                elif host and port:
                    normalized[str(key)] = f"{host}:{port}"
        return normalized

    @staticmethod
    def _extract_node_endpoint(node_entry):
        if isinstance(node_entry, str):
            try:
                host, port = parse_peer(node_entry)
                return f"{host}:{port}"
            except ValueError:
                return ""
        if isinstance(node_entry, dict):
            endpoint = node_entry.get("endpoint")
            host = node_entry.get("host")
            port = node_entry.get("port")
            if endpoint:
                try:
                    host_norm, port_norm = parse_peer(str(endpoint))
                    return f"{host_norm}:{port_norm}"
                except ValueError:
                    return ""
            if host and port:
                return f"{host}:{port}"
        return ""

    @staticmethod
    def _extract_node_role(node_key, node_entry):
        if isinstance(node_entry, dict):
            return str(node_entry.get("role", "")).strip().lower()
        if str(node_key).strip().lower().startswith("seed"):
            return "seed"
        return ""

    @staticmethod
    def _extract_node_nickname(node_key, node_entry):
        if isinstance(node_entry, dict):
            nickname = str(node_entry.get("nickname", "")).strip()
            if nickname:
                return nickname
        name = str(node_key).strip()
        if not name or name.lower() in ("self",):
            return ""
        return name

    def _network_endpoints(self, network_name):
        info = self.networks.get(network_name, {})
        nodes = info.get("nodes", {})
        endpoints = []
        if isinstance(nodes, dict):
            for node_key, node_entry in nodes.items():
                endpoint = self._extract_node_endpoint(node_entry)
                if not endpoint:
                    endpoint = self._extract_node_endpoint(node_key)
                if endpoint:
                    endpoints.append(endpoint)
        return sorted(set(endpoints))

    def _network_public_key_map(self, network_name):
        key_map = {}
        network_info = self.networks.get(network_name, {})
        nodes = network_info.get("nodes", {})
        if isinstance(nodes, dict):
            for _node_key, node_entry in nodes.items():
                endpoint = self._extract_node_endpoint(node_entry)
                if not endpoint:
                    continue
                if isinstance(node_entry, dict):
                    pubkey = str(node_entry.get("pubkey", "")).strip()
                    if pubkey:
                        key_map[endpoint] = pubkey
        local_endpoint = self._local_endpoint()
        key_map[local_endpoint] = self.identity.get("public_key_pem", "")
        if self.node:
            key_map[self.node.nodeid] = self.node.get_public_key_pem()
        return key_map

    def _log_message_db(self, direction, network_name, sender, receiver, message_type, route_id, text, route):
        payload = {"text": text, "route": route or []}
        self.storage.log_message(
            direction=direction,
            network_name=network_name or "",
            sender=sender or "",
            receiver=receiver or "",
            message_type=message_type or "",
            route_id=route_id or "",
            payload=payload,
        )

    @staticmethod
    def _canonical_json_bytes(payload):
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _network_update_body(self, network_info):
        try:
            min_approvals = max(1, int(network_info.get("min_approvals", 2)))
        except (TypeError, ValueError):
            min_approvals = 2
        return {
            "network_type": network_info.get("type", "private"),
            "network_description": network_info.get("description", ""),
            "network_rules": network_info.get("rules", []),
            "nodes": network_info.get("nodes", {}),
            "min_approvals": min_approvals,
        }

    def _network_update_hash(self, update_body):
        return hashlib.sha256(self._canonical_json_bytes(update_body)).hexdigest()

    def _sign_update_vote(self, action, network_name, update_id, update_hash):
        signer = self._local_endpoint()
        signer_pubkey = self.node.get_public_key_pem() if self.node else self.identity.get("public_key_pem", "")
        private_key_pem = self.identity.get("private_key_pem", "")
        private_key = RSA.import_key(private_key_pem)
        signable = {
            "action": action,
            "network": network_name,
            "update_id": update_id,
            "update_hash": update_hash,
            "signer": signer,
        }
        digest = SHA256.new(self._canonical_json_bytes(signable))
        signature = pss.new(private_key).sign(digest)
        return {
            "signer": signer,
            "signer_pubkey": signer_pubkey,
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    def _verify_update_vote(self, action, network_name, update_id, update_hash, vote):
        signer = str(vote.get("signer", "")).strip()
        signer_pubkey = str(vote.get("signer_pubkey", "")).strip()
        signature_b64 = str(vote.get("signature", "")).strip()
        if not signer or not signer_pubkey or not signature_b64:
            return False
        try:
            signature = base64.b64decode(signature_b64.encode("ascii"))
            public_key = RSA.import_key(signer_pubkey)
        except Exception:
            return False
        signable = {
            "action": action,
            "network": network_name,
            "update_id": update_id,
            "update_hash": update_hash,
            "signer": signer,
        }
        digest = SHA256.new(self._canonical_json_bytes(signable))
        try:
            pss.new(public_key).verify(digest, signature)
            return True
        except (ValueError, TypeError):
            return False

    def _trusted_signer_count_in_nodes(self, nodes):
        count = 0
        if not isinstance(nodes, dict):
            return count
        for node_key, node_entry in nodes.items():
            role = self._extract_node_role(node_key, node_entry)
            if role in ("trusted", "seed"):
                count += 1
        return count

    def _required_approvals(self, network_name, update_body):
        info = self.networks.get(network_name, {})
        base_required = int(info.get("min_approvals", update_body.get("min_approvals", 2)))
        if base_required < 1:
            base_required = 1
        trusted_count = self._trusted_signer_count_in_nodes(update_body.get("nodes", {}))
        if trusted_count <= 1:
            return 1
        return min(base_required, trusted_count)

    def _register_update_vote(self, network_name, action, update_id, update_hash, update_body, vote):
        network_bucket = self.pending_updates.setdefault(network_name, {})
        pending_key = f"{action}|{update_id}"
        pending = network_bucket.get(pending_key)
        if not pending:
            pending = {
                "action": action,
                "hash": update_hash,
                "body": update_body,
                "votes": {},
                "applied": False,
                "created_at": time.time(),
            }
            network_bucket[pending_key] = pending
        if pending.get("hash") != update_hash:
            return None
        signer = vote.get("signer", "")
        pending["votes"][signer] = vote
        return pending

    def _infer_my_role_from_nodes(self, nodes):
        local_endpoint = self._local_endpoint()
        if not isinstance(nodes, dict):
            return ""
        for node_key, node_entry in nodes.items():
            endpoint = self._extract_node_endpoint(node_entry)
            if endpoint != local_endpoint:
                continue
            role = self._extract_node_role(node_key, node_entry)
            if role in ("member", "trusted", "seed"):
                return role
        return ""

    def _collect_join_targets(self, nodes):
        targets = []
        local_endpoint = self._local_endpoint()
        if not isinstance(nodes, dict):
            return targets
        for key, value in nodes.items():
            endpoint = self._extract_node_endpoint(value)
            role = self._extract_node_role(key, value)
            if not endpoint:
                continue
            if endpoint == local_endpoint:
                continue
            if role in ("seed", "trusted"):
                targets.append(endpoint)
        return sorted(set(targets))

    def _request_network_join(self, network_name, join_targets):
        if not self.node:
            messagebox.showerror("Join Network", "Node is not running. Start node first, then retry join request.")
            return
        if not join_targets:
            messagebox.showwarning("Join Network", "No seed/trusted nodes found in .mdar to send join request.")
            return

        payload = {
            "type": "control",
            "action": "join_request",
            "network": network_name,
            "sender": self.node.nodeid,
            "node_name": self.node_name_var.get().strip() or "node",
            "description": self.node_description_var.get().strip(),
            "requested_role": self.networks.get(network_name, {}).get("my_role", "member"),
            "public_key": self.node.get_public_key_pem() if self.node else self.identity.get("public_key_pem", ""),
            "time": time.time(),
        }

        sent_count = 0
        local_endpoint = self._local_endpoint()
        for endpoint in join_targets:
            if endpoint == local_endpoint:
                self._log(
                    f"Skipping join target {endpoint} because it matches local endpoint. "
                    "Use a .mdar exported from the seed/trusted computer."
                )
                continue
            try:
                self.node.send_control_message(endpoint, payload, timeout=5)
                sent_count += 1
                self._log(f"Join request sent to {endpoint} for network '{network_name}'")
                self._log_message_db(
                    direction="out",
                    network_name=network_name,
                    sender=self._local_endpoint(),
                    receiver=endpoint,
                    message_type="control",
                    route_id="",
                    text="join_request",
                    route=[],
                )
            except (OSError, ValueError) as exc:
                self._log(f"Join request failed to {endpoint}: {exc}")

        if sent_count == 0:
            messagebox.showwarning(
                "Join Network",
                "Join request could not be sent to any external seed/trusted node.\n"
                "This usually means the .mdar points to this same computer instead of the seed computer.",
            )
            return
        messagebox.showinfo(
            "Join Network",
            f"Join request sent to {sent_count} node(s).\n"
            "Wait for seed/trusted approval and updated .mdar.",
        )

    def _send_control_message(self, endpoint, payload, timeout=5):
        if not self.node:
            return False
        try:
            self.node.send_control_message(endpoint, payload, timeout=timeout)
            return True
        except (OSError, ValueError) as exc:
            self._log(f"Control message failed to {endpoint}: {exc}")
            return False

    def _broadcast_update_vote(self, network_name, action, update_id, update_hash, update_body, vote):
        payload = {
            "type": "control",
            "action": action,
            "network": network_name,
            "update_id": update_id,
            "update_hash": update_hash,
            "update_body": update_body,
            "signer": vote.get("signer", ""),
            "signer_pubkey": vote.get("signer_pubkey", ""),
            "signature": vote.get("signature", ""),
            "sender": self._local_endpoint(),
            "time": time.time(),
        }
        for endpoint in self._network_endpoints(network_name):
            if endpoint == self._local_endpoint():
                continue
            self._send_control_message(endpoint, payload)

    def _apply_network_update(self, packet, network_name, mark_active=False):
        if not network_name:
            self._log("Network update ignored: missing network name.")
            return
        info = self.networks.get(
            network_name,
            {"type": "private", "description": "", "rules": [], "nodes": {}, "my_role": "member", "min_approvals": 2},
        )
        packet_type = str(packet.get("network_type", info.get("type", "private"))).strip().lower()
        if packet_type in ("private", "public"):
            info["type"] = packet_type
        info["description"] = str(packet.get("network_description", info.get("description", "")))
        packet_rules = packet.get("network_rules", info.get("rules", []))
        if isinstance(packet_rules, str):
            packet_rules = [packet_rules]
        info["rules"] = [str(item).strip() for item in packet_rules if str(item).strip()]
        try:
            info["min_approvals"] = max(1, int(packet.get("min_approvals", info.get("min_approvals", 2))))
        except (TypeError, ValueError):
            info["min_approvals"] = max(1, int(info.get("min_approvals", 2)))

        merged_nodes = {}
        existing_nodes = info.get("nodes", {})
        if isinstance(existing_nodes, dict):
            merged_nodes.update(existing_nodes)
        incoming_nodes = packet.get("nodes", {})
        if isinstance(incoming_nodes, dict):
            merged_nodes.update(incoming_nodes)
        info["nodes"] = merged_nodes
        inferred_role = self._infer_my_role_from_nodes(merged_nodes)
        if inferred_role:
            info["my_role"] = inferred_role

        if mark_active:
            info["membership_status"] = "active"
        elif "membership_status" not in info:
            info["membership_status"] = "active"
        if "my_role" not in info:
            info["my_role"] = "member"

        self.networks[network_name] = info
        if mark_active:
            self.active_network_var.set(network_name)

        local_endpoint = self._local_endpoint()
        added = 0
        for node_key, node_entry in merged_nodes.items():
            endpoint = self._extract_node_endpoint(node_entry)
            if not endpoint:
                continue
            if endpoint == local_endpoint:
                continue
            nickname = self._extract_node_nickname(node_key, node_entry)
            if not nickname:
                nickname = f"Peer-{endpoint.rsplit(':', 1)[-1]}" if ":" in endpoint else endpoint
            self._upsert_contact(endpoint=endpoint, nickname=nickname, network=network_name)
            if self.node and network_name == self._active_network_name():
                try:
                    self.node.add_peer(endpoint)
                except ValueError:
                    self._log(f"Invalid endpoint in network update: {endpoint}")
            added += 1

        self._refresh_active_network_selector()
        self._sync_node_peers_for_active_network()
        self._refresh_contact_list()
        self._save_state()
        self._log(f"Network '{network_name}' synchronized ({added} contacts refreshed).")

    def _handle_join_request(self, packet, network_name):
        if not network_name:
            self._log("Join request ignored: missing network.")
            return
        if network_name not in self.networks:
            self._log(f"Join request ignored: unknown network '{network_name}'.")
            return
        network_info = self.networks[network_name]
        my_role = str(network_info.get("my_role", "member")).strip().lower()
        sender_endpoint = str(packet.get("sender", "")).strip()
        requester_name = str(packet.get("node_name", "New node")).strip() or "New node"
        if my_role not in ("seed", "trusted"):
            self._log(f"Join request from {sender_endpoint} ignored; local role '{my_role}' is not approver.")
            return
        if not sender_endpoint:
            self._log("Join request ignored: sender endpoint missing.")
            return

        approved = messagebox.askyesno(
            "Join Request",
            f"Approve join request?\n\nNetwork: {network_name}\nNode: {requester_name}\nEndpoint: {sender_endpoint}",
        )

        if not approved:
            reject_payload = {
                "type": "control",
                "action": "join_rejected",
                "network": network_name,
                "reason": "Join request rejected by trusted/seed node.",
                "sender": self._local_endpoint(),
                "time": time.time(),
            }
            self._send_control_message(sender_endpoint, reject_payload)
            self._log(f"Join request rejected for {sender_endpoint} on network '{network_name}'.")
            return

        nodes = network_info.get("nodes", {})
        if not isinstance(nodes, dict):
            nodes = {}
        requested_role = str(packet.get("requested_role", "member")).strip().lower()
        if requested_role not in ("member", "trusted", "seed"):
            requested_role = "member"
        if requested_role in ("trusted", "seed") and my_role != "seed":
            requested_role = "member"
        requester_pubkey = str(packet.get("public_key", "")).strip()
        self._put_node_entry(nodes, requester_name, {
            "endpoint": sender_endpoint,
            "role": requested_role,
            "nickname": requester_name,
            "pubkey": requester_pubkey,
        })
        network_info["nodes"] = nodes
        self.networks[network_name] = network_info
        self._upsert_contact(endpoint=sender_endpoint, nickname=requester_name, network=network_name)
        self._refresh_contact_list()
        self._sync_node_peers_for_active_network()
        self._save_state()

        update_body = self._network_update_body(network_info)
        update_id = f"update-{uuid.uuid4().hex}"
        update_hash = self._network_update_hash(update_body)
        vote_for_join = self._sign_update_vote("join_approved", network_name, update_id, update_hash)
        vote_for_update = self._sign_update_vote("node_list_update", network_name, update_id, update_hash)
        self._register_update_vote(network_name, "node_list_update", update_id, update_hash, update_body, vote_for_update)

        join_payload = {
            "type": "control",
            "action": "join_approved",
            "network": network_name,
            "update_id": update_id,
            "update_hash": update_hash,
            "update_body": update_body,
            "signer": vote_for_join.get("signer", ""),
            "signer_pubkey": vote_for_join.get("signer_pubkey", ""),
            "signature": vote_for_join.get("signature", ""),
            "sender": self._local_endpoint(),
            "time": time.time(),
        }
        self._send_control_message(sender_endpoint, join_payload)

        self._broadcast_update_vote(
            network_name=network_name,
            action="node_list_update",
            update_id=update_id,
            update_hash=update_hash,
            update_body=update_body,
            vote=vote_for_update,
        )
        self._log(f"Join request approved for {requester_name} ({sender_endpoint}) on network '{network_name}'.")

    def create_network_dialog(self):
        values = self._show_form_dialog(
            "Create Network",
            [
                {"name": "name", "label": "Network name", "initial": ""},
                {"name": "type", "label": "Type", "initial": "private", "kind": "combobox", "options": ["private", "public"]},
                {"name": "my_role", "label": "My role", "initial": "seed", "kind": "combobox", "options": ["member", "trusted", "seed"]},
                {"name": "min_approvals", "label": "Min approvals for updates", "initial": "2"},
                {"name": "description", "label": "Description", "initial": ""},
                {"name": "rules", "label": "Rules (comma-separated)", "initial": "allow-lab-communication"},
            ],
            submit_label="Create Network",
        )
        if values is None:
            return
        name = values.get("name", "").strip()
        if not name:
            messagebox.showerror("Create Network", "Network name is required.")
            return
        net_type = values.get("type", "").strip().lower()
        if net_type not in ("public", "private"):
            messagebox.showerror("Create Network", "Type must be public or private.")
            return
        my_role = values.get("my_role", "member").strip().lower()
        if my_role not in ("member", "trusted", "seed"):
            messagebox.showerror("Create Network", "My role must be member, trusted, or seed.")
            return
        try:
            min_approvals = max(1, int(values.get("min_approvals", "2")))
        except ValueError:
            messagebox.showerror("Create Network", "Min approvals must be numeric.")
            return
        description = values.get("description", "")
        rules_raw = values.get("rules", "")
        rules = [item.strip() for item in rules_raw.split(",") if item.strip()]
        self.networks[name] = {
            "type": net_type,
            "description": description.strip(),
            "rules": rules,
            "nodes": {},
            "membership_status": "active",
            "my_role": my_role,
            "min_approvals": min_approvals,
        }
        local_endpoint = self._local_endpoint()
        self.networks[name]["nodes"][self.node_name_var.get().strip() or "self"] = {
            "endpoint": local_endpoint,
            "role": my_role,
            "nickname": self.node_name_var.get().strip() or "self",
            "pubkey": self.identity.get("public_key_pem", ""),
        }
        self.active_network_var.set(name)
        self._log(f"Network created: {name}")
        self._save_state()

    def edit_network_rules_dialog(self):
        if not self.networks:
            messagebox.showinfo("Edit Network Settings", "No networks saved.")
            return
        network_names = sorted(self.networks.keys())
        default_name = self.active_network_var.get().strip()
        if default_name not in self.networks:
            default_name = network_names[0]
        defaults = self.networks.get(default_name, {"type": "private", "description": "", "rules": []})
        values = self._show_form_dialog(
            "Edit Network Settings",
            [
                {"name": "name", "label": "Select network", "initial": default_name, "kind": "combobox", "options": network_names},
                {"name": "type", "label": "Type", "initial": defaults.get("type", "private"), "kind": "combobox", "options": ["private", "public"]},
                {"name": "my_role", "label": "My role", "initial": defaults.get("my_role", "member"), "kind": "combobox", "options": ["member", "trusted", "seed"]},
                {"name": "min_approvals", "label": "Min approvals for updates", "initial": str(defaults.get("min_approvals", 2))},
                {"name": "description", "label": "Description", "initial": defaults.get("description", "")},
                {"name": "rules", "label": "Rules (comma-separated)", "initial": ", ".join(defaults.get("rules", []))},
            ],
            submit_label="Update Network",
        )
        if values is None:
            return
        name = values.get("name", "").strip()
        if name not in self.networks:
            messagebox.showerror("Edit Network Rules", f"Network not found: {name}")
            return
        net_type = values.get("type", "").strip().lower()
        if net_type not in ("public", "private"):
            messagebox.showerror("Edit Network Settings", "Type must be public or private.")
            return
        my_role = values.get("my_role", "member").strip().lower()
        if my_role not in ("member", "trusted", "seed"):
            messagebox.showerror("Edit Network Settings", "My role must be member, trusted, or seed.")
            return
        try:
            min_approvals = max(1, int(values.get("min_approvals", "2")))
        except ValueError:
            messagebox.showerror("Edit Network Settings", "Min approvals must be numeric.")
            return
        self.networks[name]["type"] = net_type
        self.networks[name]["my_role"] = my_role
        self.networks[name]["min_approvals"] = min_approvals
        self.networks[name]["description"] = values.get("description", "").strip()
        rules_raw = values.get("rules", "")
        self.networks[name]["rules"] = [item.strip() for item in rules_raw.split(",") if item.strip()]
        self.active_network_var.set(name)
        self._log(f"Network settings updated: {name}")
        self._save_state()

    def join_network_dialog(self):
        mdar_path = filedialog.askopenfilename(
            title="Select .mdar to Join Network",
            filetypes=[("MDA Profile", "*.mdar"), ("All files", "*.*")],
        )
        if not mdar_path:
            return

        payload = import_mdar_file(mdar_path)
        if not payload:
            messagebox.showerror("Join Network", "Invalid or unreadable .mdar file.")
            return

        payload_name = str(payload.get("name", "")).strip()
        payload_type = str(payload.get("type", "private")).strip().lower()
        payload_desc = str(payload.get("description", ""))
        payload_rules = payload.get("rules", [])
        if isinstance(payload_rules, str):
            payload_rules = [payload_rules]
        payload_nodes_raw = payload.get("nodes", {})
        if not isinstance(payload_nodes_raw, dict):
            payload_nodes_raw = {}
        # Work on a copy so adding our own entry can never alter the .mdar's node list.
        payload_nodes_raw = {key: (dict(value) if isinstance(value, dict) else value) for key, value in payload_nodes_raw.items()}
        join_targets = self._collect_join_targets(payload_nodes_raw)
        inferred_role = self._infer_my_role_from_nodes(payload_nodes_raw)
        rules_text = ", ".join([str(item).strip() for item in payload_rules if str(item).strip()])
        values = self._show_form_dialog(
            "Join Network Request",
            [
                {"name": "mdar_file", "label": ".mdar file", "initial": mdar_path},
                {"name": "name", "label": "Network name", "initial": payload_name},
                {"name": "type", "label": "Type", "initial": payload_type if payload_type in ("private", "public") else "private", "kind": "combobox", "options": ["private", "public"]},
                {"name": "my_role", "label": "My role", "initial": inferred_role or "member", "kind": "combobox", "options": ["member", "trusted", "seed"]},
                {"name": "min_approvals", "label": "Min approvals for updates", "initial": "2"},
                {"name": "description", "label": "Description", "initial": payload_desc},
                {"name": "rules", "label": "Rules (comma-separated)", "initial": rules_text},
            ],
            submit_label="Send Join Request",
        )
        if values is None:
            return
        name = values.get("name", "").strip()
        if not name:
            messagebox.showerror("Join Network", "Network name is required.")
            return
        net_type = values.get("type", "private").strip().lower()
        if net_type not in ("private", "public"):
            messagebox.showerror("Join Network", "Type must be public or private.")
            return
        my_role = values.get("my_role", "member").strip().lower()
        if my_role not in ("member", "trusted", "seed"):
            messagebox.showerror("Join Network", "My role must be member, trusted, or seed.")
            return
        try:
            min_approvals = max(1, int(values.get("min_approvals", "2")))
        except ValueError:
            messagebox.showerror("Join Network", "Min approvals must be numeric.")
            return
        rules_raw = values.get("rules", "")
        network_entry = self.networks.get(name, {"nodes": {}})
        network_entry["type"] = net_type
        network_entry["description"] = values.get("description", "").strip()
        network_entry["rules"] = [item.strip() for item in rules_raw.split(",") if item.strip()]
        network_entry["nodes"] = payload_nodes_raw
        network_entry["membership_status"] = "pending_approval"
        network_entry["my_role"] = my_role
        network_entry["min_approvals"] = min_approvals
        local_name = self.node_name_var.get().strip() or "self"
        local_endpoint = self._local_endpoint()
        nodes_map = network_entry.get("nodes", {})
        if isinstance(nodes_map, dict):
            self._put_node_entry(nodes_map, local_name, {
                "endpoint": local_endpoint,
                "role": my_role,
                "nickname": local_name,
                "pubkey": self.identity.get("public_key_pem", ""),
            })
            network_entry["nodes"] = nodes_map
        self.networks[name] = network_entry

        self.active_network_var.set(name)
        self._log(f"Loaded join profile for network: {name}")
        if join_targets:
            self._log(f"Join targets for '{name}': {', '.join(join_targets)}")
        else:
            self._log(
                f"No external seed/trusted targets found in .mdar for '{name}'. "
                "Re-export from the seed computer."
            )
        self._request_network_join(name, join_targets)
        self._save_state()

    def delete_network_dialog(self):
        if not self.networks:
            messagebox.showinfo("Delete Network", "No networks saved.")
            return
        default_name = self.active_network_var.get().strip()
        values = self._show_form_dialog(
            "Delete Network",
            [
                {"name": "name", "label": "Network name", "initial": default_name, "kind": "combobox", "options": sorted(self.networks.keys())},
            ],
            submit_label="Delete",
        )
        if values is None:
            return
        name = values.get("name", "").strip()
        if name not in self.networks:
            messagebox.showerror("Delete Network", f"Network not found: {name}")
            return
        if not messagebox.askyesno("Delete Network", f"Delete network '{name}'?"):
            return
        del self.networks[name]
        if self.active_network_var.get().strip() == name:
            self.active_network_var.set("lab-network")
        self._refresh_active_network_selector()
        self._sync_node_peers_for_active_network()
        self._log(f"Network deleted: {name}")
        self._save_state()

    def show_networks(self):
        if not self.networks:
            messagebox.showinfo("My Networks", "No networks saved.")
            return
        lines = []
        for name, info in sorted(self.networks.items()):
            rules = ", ".join(info.get("rules", [])) or "no rules"
            status = info.get("membership_status", "active")
            role = info.get("my_role", "member")
            min_approvals = info.get("min_approvals", 2)
            lines.append(
                f"{name} | type={info.get('type', 'private')} | role={role} | status={status} | "
                f"min_approvals={min_approvals} | rules={rules}"
            )
        messagebox.showinfo("My Networks", "\n".join(lines))

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

        name = str(payload.get("name", self.active_network_var.get())).strip() or "lab-network"
        net_type = str(payload.get("type", "private"))
        rules = payload.get("rules", [])
        if isinstance(rules, str):
            rules = [rules]
        description = str(payload.get("description", ""))
        nodes = payload.get("nodes", {}) or {}
        if not isinstance(nodes, dict):
            nodes = {}

        self.networks[name] = {
            "type": net_type,
            "description": description,
            "rules": list(rules),
            "nodes": dict(nodes),
            "membership_status": "active",
            "my_role": self._infer_my_role_from_nodes(nodes) or "member",
            "min_approvals": 2,
        }
        self.active_network_var.set(name)

        imported_count = 0
        for key, value in nodes.items():
            endpoint = self._extract_node_endpoint(value)
            if not endpoint and isinstance(value, str):
                endpoint = value
            if not endpoint:
                continue
            try:
                host, port = parse_peer(endpoint)
            except ValueError:
                continue
            endpoint = f"{host}:{port}"
            contact_name = self._extract_node_nickname(key, value)
            if not contact_name or contact_name.lower().startswith("peer-") or contact_name.lower() == "self":
                contact_name = f"Peer-{port}"
            self._upsert_contact(endpoint=endpoint, nickname=contact_name, network=name)
            imported_count += 1
            if self.node:
                self.node.add_peer(endpoint)

        self._refresh_contact_list()
        self._save_state()
        self._log(f"Imported .mdar profile from {path} ({imported_count} contact endpoints)")

    def export_mdar(self):
        path = filedialog.asksaveasfilename(
            title="Export MDA profile",
            defaultextension=".mdar",
            filetypes=[("MDA Profile", "*.mdar"), ("All files", "*.*")],
        )
        if not path:
            return

        network_name = self.active_network_var.get().strip() or "lab-network"
        network_info = self.networks.get(network_name, {"type": "private", "description": "", "rules": []})
        selected_nodes = {}
        selected_by_endpoint = {}
        role_rank = {"member": 0, "trusted": 1, "seed": 2}

        def upsert_selected(endpoint, role, nickname, pubkey):
            if not endpoint:
                return
            role = role if role in ("member", "trusted", "seed") else "member"
            nickname = (nickname or endpoint).strip() or endpoint
            pubkey = (pubkey or "").strip()
            existing = selected_by_endpoint.get(endpoint)
            if not existing:
                selected_by_endpoint[endpoint] = {
                    "endpoint": endpoint,
                    "role": role,
                    "nickname": nickname,
                    "pubkey": pubkey,
                }
                return
            if role_rank.get(role, 0) > role_rank.get(existing.get("role", "member"), 0):
                existing["role"] = role
            if pubkey:
                existing["pubkey"] = pubkey
            if not existing.get("nickname"):
                existing["nickname"] = nickname

        network_nodes = network_info.get("nodes", {}) if isinstance(network_info.get("nodes", {}), dict) else {}
        network_meta_by_endpoint = {}
        for node_key, node_entry in network_nodes.items():
            endpoint = self._extract_node_endpoint(node_entry)
            if not endpoint:
                continue
            role = self._extract_node_role(node_key, node_entry) or "member"
            pubkey = ""
            nickname = self._extract_node_nickname(node_key, node_entry)
            if isinstance(node_entry, dict):
                pubkey = str(node_entry.get("pubkey", "")).strip()
            existing = network_meta_by_endpoint.get(endpoint)
            if existing:
                current_rank = {"member": 0, "trusted": 1, "seed": 2}.get(existing.get("role", "member"), 0)
                candidate_rank = {"member": 0, "trusted": 1, "seed": 2}.get(role, 0)
                if candidate_rank < current_rank:
                    continue
            network_meta_by_endpoint[endpoint] = {
                "role": role,
                "pubkey": pubkey,
                "nickname": nickname,
            }
            upsert_selected(endpoint=endpoint, role=role, nickname=nickname, pubkey=pubkey)
        network_contacts = [contact for contact in self.contacts if self._contact_network(contact) == network_name]
        local_endpoint = self.node.nodeid if self.node and self.node.nodeid else self._local_endpoint()
        for contact in network_contacts:
            nickname = contact.get("nickname", "").strip() or contact.get("endpoint", "")
            endpoint = contact.get("endpoint", "")
            if not endpoint:
                continue
            if endpoint == local_endpoint:
                continue
            pubkey = ""
            role = "member"
            endpoint_meta = network_meta_by_endpoint.get(endpoint)
            if endpoint_meta:
                pubkey = endpoint_meta.get("pubkey", "")
                role = endpoint_meta.get("role", "member")
            upsert_selected(endpoint=endpoint, role=role, nickname=nickname, pubkey=pubkey)

        if self.node:
            upsert_selected(
                endpoint=self.node.nodeid,
                role=network_info.get("my_role", "member"),
                nickname=self.node_name_var.get().strip() or "self",
                pubkey=self.node.get_public_key_pem(),
            )

        for endpoint, node_data in sorted(selected_by_endpoint.items()):
            base_key = (node_data.get("nickname", "") or endpoint).strip() or endpoint
            key = base_key
            suffix = 2
            while key in selected_nodes and selected_nodes[key].get("endpoint") != endpoint:
                key = f"{base_key}-{suffix}"
                suffix += 1
            selected_nodes[key] = node_data

        export_mdar_file(
            network_name,
            file_path=path,
            net_type=network_info.get("type", "private"),
            net_description=network_info.get("description", ""),
            net_rules=network_info.get("rules", []),
            selected_nodes=selected_nodes,
        )
        self._log(f"Exported .mdar profile to {path}")

    def show_message_history(self):
        window = tk.Toplevel(self.root)
        window.title("Encrypted Message History")
        window.geometry("900x480")
        window.minsize(760, 360)

        frame = ttk.Frame(window, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")
        window.columnconfigure(0, weight=1)
        window.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        header = ttk.Frame(frame)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(header, text="Recent encrypted message records (local DB)").grid(row=0, column=0, sticky="w")

        viewer = scrolledtext.ScrolledText(frame, state="disabled", wrap="none")
        viewer.grid(row=1, column=0, sticky="nsew")

        def render():
            rows = self.storage.recent_messages(limit=300)
            lines = []
            for row in rows:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(row.get("created_at", 0.0))))
                payload = row.get("payload", {})
                text = str(payload.get("text", ""))
                route = payload.get("route", [])
                lines.append(
                    f"[{row.get('id')}] {ts} | {row.get('direction')} | {row.get('message_type')} | "
                    f"net={row.get('network_name')} | {row.get('sender')} -> {row.get('receiver')} | "
                    f"route_id={row.get('route_id')} | route={route} | text={text}"
                )
            viewer.configure(state="normal")
            viewer.delete("1.0", tk.END)
            viewer.insert(tk.END, "\n".join(lines) if lines else "No messages yet.")
            viewer.configure(state="disabled")

        ttk.Button(header, text="Refresh", command=render).grid(row=0, column=1, padx=(10, 0))
        render()

    def show_help(self):
        messagebox.showinfo(
            "Help",
            "Use the menu bar for all actions:\n\n"
            "Contacts: add/edit/delete/list contacts.\n"
            "Network: create/edit/join/delete/import/export/list networks.\n"
            "Node: start/stop node and edit node settings.\n"
            "About: this help and about information.\n\n"
            "Tip: double-click a contact to open its chat window.",
        )

    def show_about(self):
        messagebox.showinfo(
            "About MDANetPro",
            "MDANetPro\nPeer-to-peer messaging client.\n\n"
            "This UI supports menu-driven Contacts, Network, Node, and About actions.",
        )

    def _on_close(self):
        for window in list(self.chat_windows.values()):
            window.window.destroy()
        self.chat_windows.clear()
        self.stop_node()
        self._save_state()
        self.root.destroy()


def run_cli_mode(args):
    peers = [parse_peer(peer) for peer in args.peer if peer]
    node = mda(host=args.host, port=args.port, peers=peers, node_name=f"client-{args.port}")
    node.start_server()

    if args.message:
        sent = 0
        for host, port in node.peers:
            try:
                payload = {
                    "type": "real",
                    "routing": "direct",
                    "network": "cli-network",
                    "sender": node.nodeid,
                    "text": args.message,
                    "time": time.time(),
                }
                node.send_message(host, port, payload, timeout=5)
                sent += 1
            except (OSError, ValueError) as exc:
                print(f"send failed to {host}:{port}: {exc}", flush=True)
        print(f"Sent real direct message to {sent} peer(s)", flush=True)
        node.close()
        return

    print(f"MDA client running on {node.nodeid}", flush=True)
    print("Type a message and press Enter. Use 'quit' to exit.", flush=True)
    try:
        while True:
            text = input("message> ")
            if text.strip().lower() == "quit":
                break
            for host, port in node.peers:
                try:
                    payload = {
                        "type": "real",
                        "routing": "direct",
                        "network": "cli-network",
                        "sender": node.nodeid,
                        "text": text,
                        "time": time.time(),
                    }
                    node.send_message(host, port, payload, timeout=5)
                except (OSError, ValueError) as exc:
                    print(f"send failed to {host}:{port}: {exc}", flush=True)
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
    active_network = app._active_network_name()
    for peer in args.peer:
        app._upsert_contact(endpoint=peer, nickname=f"Peer-{peer.rsplit(':', 1)[-1] if ':' in peer else peer}", network=active_network)
    app._refresh_contact_list()
    app._save_state()
    root.mainloop()


if __name__ == "__main__":
    main()
