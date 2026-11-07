#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import queue
import random
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import uuid
import urllib.request
from tkinter import filedialog, messagebox, scrolledtext, ttk

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

import mda_firewall
from client_storage import ClientStorage
from mda_discovery import DISCOVERY_PORT, LanDiscovery
import mda_netutils
import mda_p2p
import mda_webgateway
from mda_netutils import best_local_ip, candidate_ips, local_ip_for
from mdanetwork import mda
from net_profile import export_mdar_file, import_mdar_file

LEGACY_DATA_FILES = ("mdaclient_state.json", "mda_client_local.db")


def app_data_dir():
    """Folder for state, keys and the local database.

    MDANET_DATA_DIR overrides. Existing data in the current folder keeps being used.
    A packaged .exe otherwise stores data in %LOCALAPPDATA%\\MDANetPro, so it works
    when installed under Program Files. Source runs keep using the current folder.
    """
    override = os.environ.get("MDANET_DATA_DIR", "").strip()
    if override:
        os.makedirs(override, exist_ok=True)
        return override
    cwd = os.getcwd()
    if any(os.path.exists(os.path.join(cwd, name)) for name in LEGACY_DATA_FILES):
        return cwd
    if getattr(sys, "frozen", False):
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        path = os.path.join(base, "MDANetPro")
        os.makedirs(path, exist_ok=True)
        return path
    return cwd


def default_node_name():
    """A per-computer default so two new users don't both end up named "node"."""
    for value in (os.environ.get("USERNAME"), os.environ.get("USER"), socket.gethostname()):
        value = str(value or "").strip()
        if value:
            return value[:32]
    return "node"


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
        self.data_dir = app_data_dir()
        self.first_run = not os.path.exists(os.path.join(self.data_dir, self.STATE_FILE))
        self.storage = ClientStorage(self.data_dir)
        self.identity = self.storage.get_or_create_identity()
        self.active_network_var = tk.StringVar(value="lab-network")
        self.node_name_var = tk.StringVar(value=default_node_name())
        self.node_description_var = tk.StringVar(value="")
        self.host_mode = "auto"  # "auto": pick and follow the right IP; "manual": use host_var as typed
        self.use_upnp = True  # ask the home router to open the port automatically
        self.public_address = ""  # optional "ip-or-name[:port]" of a manual router port-forward
        self.web_gateway_mode = "this computer"  # "off" | "this computer" | "all devices": web app access
        self.web_gateway = None
        self._recent_join_requesters = {}  # pubkey -> time (allowed to use us as relay while pending)
        self._routes_broadcast_pending = False
        self._nat_check_running = False
        self._last_nat_check = 0.0
        self.host_var = tk.StringVar(value=best_local_ip())
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
        self.ui_calls = queue.Queue()  # callables from worker threads, run on the Tk thread
        self.discovery = None
        self.firewall_state = None
        self.setup_done = False
        self._nearby_window = None
        self._hello_cache = []
        self._load_state()
        self._ensure_default_network()
        self._build_ui()
        self.active_network_var.trace_add("write", self._on_active_network_changed)
        self._refresh_active_network_selector()
        self.root.after(250, self._drain_messages)
        self.root.after(400, self._auto_start_node)
        self.root.after(self.traffic_interval_ms, self._traffic_tick)
        self.root.after(5000, self._address_watch_tick)
        self.root.after(4000, self._p2p_tick)
        self.root.after(1000, self._announce_tick)
        if self.first_run or not self.setup_done:
            self.root.after(700, self.setup_wizard)

    def _build_ui(self):
        self._create_menu()

        # Banner shown only when something needs the user's attention (e.g. firewall).
        self.banner = tk.Frame(self.root, background="#fff4ce", padx=10, pady=6)
        self.banner_text_var = tk.StringVar(value="")
        tk.Label(self.banner, textvariable=self.banner_text_var, background="#fff4ce", anchor="w", justify="left").pack(side="left", fill="x", expand=True)
        self.banner_button = ttk.Button(self.banner, text="Allow network access", command=self.allow_network_access)
        self.banner_button.pack(side="right")

        frame = ttk.Frame(self.root, padding=10)
        frame.grid(row=1, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        ttk.Label(frame, text="Active Network").grid(row=0, column=0, sticky="w")
        self.active_network_selector = ttk.Combobox(
            frame,
            textvariable=self.active_network_var,
            values=self._network_names(),
            state="readonly",
            width=20,
        )
        self.active_network_selector.grid(row=0, column=1, sticky="ew", padx=4)
        quick = ttk.Frame(frame)
        quick.grid(row=0, column=2, columnspan=5, sticky="w", padx=4)
        ttk.Button(quick, text="Networks Nearby", command=self.show_nearby_networks).pack(side="left", padx=(0, 4))
        ttk.Button(quick, text="Test Connection", command=self.test_connection).pack(side="left", padx=4)
        ttk.Button(quick, text="Setup Wizard", command=self.setup_wizard).pack(side="left", padx=4)

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
        network_menu.add_command(label="Networks Nearby…", command=self.show_nearby_networks)
        network_menu.add_command(label="Join by Address…", command=self.join_by_address_dialog)
        network_menu.add_command(label="Join with .mdar File…", command=self.join_network_dialog)
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
        node_menu.add_separator()
        node_menu.add_command(label="Test Connection", command=self.test_connection)
        node_menu.add_command(label="Allow Network Access (Firewall)", command=self.allow_network_access)
        node_menu.add_command(label="Setup Wizard", command=self.setup_wizard)
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
        return os.path.join(self.data_dir, self.STATE_FILE)

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
        host_mode = str(node_data.get("host_mode", "")).strip().lower()
        if host_mode == "manual":
            self.host_mode = "manual"
            self.host_var.set(str(node_data.get("host", self.host_var.get())))
        # In auto mode the saved host is ignored: the address is re-detected every start.
        self.port_var.set(str(node_data.get("port", self.port_var.get())))
        self.use_upnp = bool(node_data.get("use_upnp", True))
        self.public_address = str(node_data.get("public_address", "")).strip()
        mode = str(node_data.get("web_gateway", "this computer")).strip().lower()
        self.web_gateway_mode = mode if mode in ("off", "this computer", "all devices") else "this computer"
        self.setup_done = bool(payload.get("setup_done", True))
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
                network_info["discoverable"] = bool(info.get("discoverable", True))
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
                "host_mode": self.host_mode,
                "use_upnp": bool(self.use_upnp),
                "public_address": self.public_address,
                "web_gateway": self.web_gateway_mode,
                "port": self.port_var.get().strip(),
            },
            "setup_done": bool(self.setup_done),
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
        self.host_mode = "auto"
        self.host_var.set(best_local_ip())
        self._log("Detected local IP.")
        self._save_state()

    def _update_status(self):
        active_network = self._active_network_name()
        if self.node:
            reach = self.node.transport.connectivity_summary() if self.node.transport else ""
            if self._nat_check_running and not self._last_nat_check:
                reach = "checking internet connectivity…"
            self.node_status_var.set(
                f"Running ({self.node.host}) | Name: {self.node_name_var.get().strip() or 'node'} | "
                f"Network: {active_network} | Internet: {reach}"
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

    @staticmethod
    def _same_pubkey(left, right):
        left = str(left or "").strip()
        right = str(right or "").strip()
        return bool(left) and left == right

    def _put_node_entry(self, nodes, name, entry, previous_endpoints=None):
        """Insert/update a node in a network node map without clobbering a different node.

        A node is the same node if it has the same public key (its address may have
        changed) or, for entries without keys, the same endpoint. Nicknames are not
        unique, so a name already used by a different node gets a suffix (name-2...).
        Old endpoints of a node whose address changed are appended to previous_endpoints.
        """
        if not isinstance(entry, dict):
            entry = {"endpoint": self._extract_node_endpoint(entry)}
        endpoint = self._extract_node_endpoint(entry)
        pubkey = str(entry.get("pubkey", "")).strip()
        match_key = None
        if pubkey:
            for node_key, node_entry in nodes.items():
                if isinstance(node_entry, dict) and self._same_pubkey(node_entry.get("pubkey"), pubkey):
                    match_key = node_key
                    break
        if match_key is None and endpoint:
            for node_key, node_entry in nodes.items():
                if self._extract_node_endpoint(node_entry) == endpoint:
                    match_key = node_key
                    break
        if match_key is not None:
            node_entry = nodes[match_key]
            old_endpoint = self._extract_node_endpoint(node_entry)
            if old_endpoint and endpoint and old_endpoint != endpoint and previous_endpoints is not None:
                previous_endpoints.append(old_endpoint)
            if isinstance(node_entry, dict):
                node_entry.update(entry)
            else:
                nodes[match_key] = dict(entry)
            return match_key
        base = str(name).strip() or endpoint or "node"
        key, suffix = base, 2
        while key in nodes:
            key = f"{base}-{suffix}"
            suffix += 1
        nodes[key] = dict(entry)
        return key

    def _upsert_local_node_in_networks(self):
        """Make sure every network lists this node at its current address.

        Returns the set of old endpoints this node was listed under (address changed).
        """
        local_endpoint = self._local_endpoint()
        local_name = self.node_name_var.get().strip() or "self"
        local_pubkey = self.node.get_public_key_pem() if self.node else self.identity.get("public_key_pem", "")
        old_endpoints = set()
        for network_name, network_info in self.networks.items():
            nodes = network_info.get("nodes", {})
            if not isinstance(nodes, dict):
                nodes = {}
            previous = []
            existing_role = ""
            for node_key, node_entry in nodes.items():
                if isinstance(node_entry, dict) and self._same_pubkey(node_entry.get("pubkey"), local_pubkey):
                    existing_role = str(node_entry.get("role", "")).strip().lower()
                    break
            self._put_node_entry(nodes, local_name, {
                "endpoint": local_endpoint,
                "nickname": local_name,
                "role": existing_role or network_info.get("my_role", "member"),
                "pubkey": local_pubkey,
            }, previous_endpoints=previous)
            old_endpoints.update(endpoint for endpoint in previous if endpoint != local_endpoint)
            network_info["nodes"] = nodes
        return old_endpoints

    def _drain_messages(self):
        while True:
            try:
                call = self.ui_calls.get_nowait()
            except queue.Empty:
                break
            try:
                call()
            except Exception as exc:  # keep the UI loop alive
                self._log(f"UI update failed: {exc}")
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
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            port = mda.PORT
        return mda_p2p.node_address(self.identity.get("public_key_pem", ""), port)

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
        if action == "address_update":
            self._handle_address_update(packet)
            return
        if action == "routes_update":
            self._handle_routes_update(packet)
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
        existing = self._find_contact_by_endpoint(peer)
        if existing:
            # Known contact: keep its real name (don't rename it to "Peer-<port>").
            nickname = None
        else:
            nickname = self._nickname_for_endpoint(peer) or (f"Peer-{peer.rsplit(':', 1)[-1]}" if ":" in peer else "Peer")
        contact = self._upsert_contact(endpoint=peer, nickname=nickname, network=(network_name or self._active_network_name()))
        self._refresh_contact_list()
        self._save_state()
        if self.node and self._contact_network(contact) == self._active_network_name():
            try:
                self.node.add_peer(peer)
            except ValueError:
                self._log(f"Could not add auto-discovered contact: {peer}")
        return contact

    def _nickname_for_endpoint(self, endpoint):
        for network_info in self.networks.values():
            nodes = network_info.get("nodes", {})
            if not isinstance(nodes, dict):
                continue
            for node_key, node_entry in nodes.items():
                if self._extract_node_endpoint(node_entry) == endpoint:
                    nickname = self._extract_node_nickname(node_key, node_entry)
                    if nickname:
                        return nickname
        return ""

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
        host = self._resolve_host()
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
                bind_host="0.0.0.0",
            )
            self.node.hello_provider = self._hello_networks
            self.node.transport.relay_policy = self._relay_allowed
            self.node.transport.manual_public = self.public_address
            self.node.transport.on_record_changed = lambda record: self.ui_calls.put(lambda: self._on_local_record_changed(record))
            self.node.start_server()
        except OSError as exc:
            self.node = None
            if getattr(exc, "errno", None) in (98, 10048, 10013, 48):
                messagebox.showerror(
                    "Start Failed",
                    f"Port {port} is already in use.\n\nMDANetPro may already be open on this computer. "
                    "Close the other copy, or change the port in Node > Node Settings.",
                )
            else:
                messagebox.showerror("Start Failed", str(exc))
            return
        old_endpoints = self._upsert_local_node_in_networks()
        self._load_records_into_transport()
        self._refresh_hello_cache()
        self._sync_node_peers_for_active_network()
        self._start_discovery()
        self._start_nat_check()
        self._start_web_gateway()
        self._update_status()
        self._log(f"Node started on {self.node.nodeid}")
        self._save_state()
        if old_endpoints:
            self._log(f"Your address changed ({', '.join(sorted(old_endpoints))} -> {self.node.nodeid}); telling your networks.")
            self._announce_address_change(old_endpoints)
        self._check_firewall_async()

    def _start_web_gateway(self):
        """WebSocket access for the MDANetPro web app (browser)."""
        if self.web_gateway is not None or not self.node or self.web_gateway_mode == "off":
            return
        host = "127.0.0.1" if self.web_gateway_mode == "this computer" else "0.0.0.0"
        try:
            self.web_gateway = mda_webgateway.WebGateway(
                self.node, host=host, port=mda_webgateway.WS_PORT,
                log=lambda text: self.ui_calls.put(lambda: self._log(text)),
            ).start()
            self._log(f"Web app access: ws://{'localhost' if host == '127.0.0.1' else self.node.host}:{mda_webgateway.WS_PORT}")
        except OSError as exc:
            self.web_gateway = None
            self._log(f"Web app access unavailable (port {mda_webgateway.WS_PORT}: {exc}).")

    def _stop_web_gateway(self):
        if self.web_gateway is not None:
            self.web_gateway.stop()
            self.web_gateway = None

    def stop_node(self):
        self._stop_web_gateway()
        if self.discovery is not None:
            self.discovery.stop()
            self.discovery = None
        if self.node:
            self.node.close()
            self.node = None
            self._log("Node stopped.")
        self._update_status()

    def _resolve_host(self):
        """Address to advertise: typed value in manual mode, otherwise auto-detected."""
        if self.host_mode == "manual" and self.host_var.get().strip():
            return self.host_var.get().strip()
        host = best_local_ip()
        self.host_var.set(host)
        return host

    def node_settings_dialog(self):
        values = self._show_form_dialog(
            "Node Settings",
            [
                {"name": "name", "label": "Node name", "initial": self.node_name_var.get()},
                {"name": "description", "label": "Node description", "initial": self.node_description_var.get()},
                {"name": "host", "label": "Address (\"auto\" = detect automatically)", "initial": "auto" if self.host_mode == "auto" else self.host_var.get()},
                {"name": "use_upnp", "label": "Open router port automatically (UPnP)", "initial": "yes" if self.use_upnp else "no", "kind": "combobox", "options": ["yes", "no"]},
                {"name": "public_address", "label": "Public address of a router port-forward (optional)", "initial": self.public_address},
                {"name": "web_gateway", "label": "Web app access (WebSocket port 50406)", "initial": self.web_gateway_mode, "kind": "combobox", "options": ["this computer", "all devices", "off"]},
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
        use_upnp = str(values.get("use_upnp", "yes")).strip().lower() != "no"
        public_address = str(values.get("public_address", "")).strip()
        nat_changed = use_upnp != self.use_upnp or public_address != self.public_address
        web_mode = str(values.get("web_gateway", self.web_gateway_mode)).strip().lower()
        if web_mode in ("off", "this computer", "all devices") and web_mode != self.web_gateway_mode:
            self.web_gateway_mode = web_mode
            self._stop_web_gateway()
            self._start_web_gateway()
        self.use_upnp, self.public_address = use_upnp, public_address
        if self.node and self.node.transport:
            self.node.transport.manual_public = public_address
            if nat_changed:
                self._start_nat_check()
        try:
            int(port_text.strip())
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be a number.")
            return
        self.node_name_var.set(name.strip() or default_node_name())
        self.node_description_var.set(description.strip())
        host = host.strip()
        if not host or host.lower() == "auto":
            self.host_mode = "auto"
            new_host = best_local_ip()
        else:
            self.host_mode = "manual"
            new_host = host
        self.host_var.set(new_host)
        port_changed = self.node is not None and str(self.node.port) != port_text.strip()
        self.port_var.set(port_text.strip())
        if self.node and not port_changed and new_host != self.node.host:
            self._change_address(new_host, reason="settings")
        else:
            self._upsert_local_node_in_networks()
        self._update_status()
        self._save_state()
        self._log("Node settings updated." + (" Restart the node (Stop/Start) to use the new port." if port_changed else ""))

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
            "network_rules": list(network_info.get("rules", [])),
            # A copy: the live node list keeps changing (route records) after this is hashed.
            "nodes": json.loads(json.dumps(network_info.get("nodes", {}))),
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
            "record": self.node.transport.local_record if self.node.transport else None,
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

        if sent_count:
            self._choose_relays()  # behind NAT: keep a line open so the approval can reach us
        if sent_count == 0:
            if messagebox.askyesno(
                "Join Network",
                "Could not reach the network owner's computer.\n\n"
                "Make sure it is switched on, has MDANetPro open, and is on the same network as you.\n\n"
                "Run a connection test now?",
            ):
                self.test_connection()
            return
        messagebox.showinfo(
            "Join Network",
            f"Join request sent to {sent_count} node(s).\n"
            "You will be notified here when the network owner approves it.",
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

    def _send_control_reliable(self, endpoint, payload, within=180, label=""):
        """Deliver an important control message in the background, retrying until it gets through.

        A member behind NAT may not be reachable for a few seconds (e.g. right after its join
        request, before its relay connection is up). Duplicates are harmless: updates are
        identified by update_id and applied once.
        """
        if not self.node:
            return
        node = self.node
        label = label or str(payload.get("action", "message"))
        # Freeze the message now: signed update bodies must not change while we retry.
        payload = json.loads(json.dumps(payload))

        def worker():
            deadline = time.time() + within
            attempt = 0
            last_error = ""
            while time.time() < deadline and self.node is node:
                attempt += 1
                try:
                    node.send_control_message(endpoint, payload, timeout=6)
                    if attempt > 1:
                        self.ui_calls.put(lambda: self._log(f"{label} delivered to {self._nickname_for_endpoint(endpoint) or endpoint} (attempt {attempt})."))
                    return
                except (OSError, ValueError) as exc:
                    last_error = str(exc)
                    time.sleep(min(3 * attempt, 15))
            self.ui_calls.put(lambda: self._log(f"Could not deliver {label} to {endpoint}: {last_error}"))

        threading.Thread(target=worker, daemon=True).start()

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
            self._send_control_reliable(endpoint, payload, label=action)

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

        was_pending = info.get("membership_status") == "pending_approval"
        merged_nodes = {}
        existing_nodes = info.get("nodes", {})
        if isinstance(existing_nodes, dict):
            merged_nodes.update({key: (dict(value) if isinstance(value, dict) else value) for key, value in existing_nodes.items()})
        incoming_nodes = packet.get("nodes", {})
        if isinstance(incoming_nodes, dict):
            self._learn_records_from_nodes(incoming_nodes)
            for node_key, node_entry in incoming_nodes.items():
                previous = []
                self._put_node_entry(merged_nodes, node_key, node_entry, previous_endpoints=previous)
                new_endpoint = self._extract_node_endpoint(node_entry)
                for old_endpoint in previous:
                    if old_endpoint != self._local_endpoint():
                        self._rename_endpoint(old_endpoint, new_endpoint)
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
        self._refresh_hello_cache()
        self._log(f"Network '{network_name}' synchronized ({added} contacts refreshed).")
        if mark_active and was_pending:
            self._choose_relays()
            self.root.after(500, self._broadcast_routes)  # let the other members learn how to reach us
            if self._nearby_window is not None:
                self._render_nearby()
            messagebox.showinfo("Joined", f"You joined '{network_name}'.\n\nThe members now appear in your contacts.")

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
        if requester_pubkey:
            self._recent_join_requesters[requester_pubkey] = time.time()
        requester_record = packet.get("record") if isinstance(packet.get("record"), dict) else None
        if requester_record and self.node and self.node.transport:
            if not (mda_p2p.verify_record(requester_record) and self._same_pubkey(requester_record.get("pubkey"), requester_pubkey)):
                requester_record = None
            else:
                self.node.transport.learn_record(requester_record)
        previous = []
        entry = {
            "endpoint": sender_endpoint,
            "role": requested_role,
            "nickname": requester_name,
            "pubkey": requester_pubkey,
        }
        if requester_record:
            entry["record"] = requester_record
        self._put_node_entry(nodes, requester_name, entry, previous_endpoints=previous)
        for old_endpoint in previous:
            self._rename_endpoint(old_endpoint, sender_endpoint)
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
        self._send_control_reliable(sender_endpoint, join_payload, label="join approval")

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
                {"name": "discoverable", "label": "Show in 'Networks Nearby'", "initial": "yes", "kind": "combobox", "options": ["yes", "no"]},
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
        rules_raw = values.get("rules", "")
        rules = [item.strip() for item in rules_raw.split(",") if item.strip()]
        discoverable = str(values.get("discoverable", "yes")).strip().lower() not in ("no", "false", "0")
        self._create_network(name, net_type, my_role, min_approvals, values.get("description", ""), rules, discoverable)

    def _create_network(self, name, net_type="private", my_role="seed", min_approvals=2, description="", rules=None, discoverable=True):
        self.networks[name] = {
            "type": net_type,
            "description": str(description or "").strip(),
            "rules": list(rules or []),
            "nodes": {},
            "membership_status": "active",
            "my_role": my_role,
            "min_approvals": min_approvals,
            "discoverable": bool(discoverable),
        }
        local_name = self.node_name_var.get().strip() or "self"
        self.networks[name]["nodes"][local_name] = {
            "endpoint": self._local_endpoint(),
            "role": my_role,
            "nickname": local_name,
            "pubkey": self.identity.get("public_key_pem", ""),
        }
        self._refresh_active_network_selector()
        self.active_network_var.set(name)
        self._refresh_hello_cache()
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
        self._join_network(
            name=name,
            net_type=net_type,
            description=values.get("description", "").strip(),
            rules=[item.strip() for item in rules_raw.split(",") if item.strip()],
            nodes=payload_nodes_raw,
            my_role=my_role,
            min_approvals=min_approvals,
        )

    def _join_network(self, name, net_type, description, rules, nodes, my_role="member", min_approvals=2):
        """Store a pending membership for `name` and ask its seed/trusted nodes to let us in."""
        nodes = {key: (dict(value) if isinstance(value, dict) else value) for key, value in (nodes or {}).items()}
        self._learn_records_from_nodes(nodes)
        join_targets = self._collect_join_targets(nodes)
        network_entry = self.networks.get(name, {"nodes": {}})
        network_entry["type"] = net_type
        network_entry["description"] = description
        network_entry["rules"] = list(rules or [])
        network_entry["nodes"] = nodes
        network_entry["membership_status"] = "pending_approval"
        network_entry["my_role"] = my_role
        network_entry["min_approvals"] = min_approvals
        network_entry.setdefault("discoverable", True)
        self.networks[name] = network_entry
        # Use the adapter that actually reaches the seed (e.g. cable, not Wi-Fi) before
        # adding ourselves, so the seed gets an address it can reply to.
        self._adjust_address_for_targets(join_targets)
        local_name = self.node_name_var.get().strip() or "self"
        self._put_node_entry(nodes, local_name, {
            "endpoint": self._local_endpoint(),
            "role": my_role,
            "nickname": local_name,
            "pubkey": self.identity.get("public_key_pem", ""),
        })

        self._refresh_active_network_selector()
        self.active_network_var.set(name)
        self._log(f"Loaded join profile for network: {name}")
        if join_targets:
            self._log(f"Join targets for '{name}': {', '.join(join_targets)}")
        else:
            self._log(
                f"No external seed/trusted targets found for '{name}'. "
                "Re-export the .mdar from the seed computer."
            )
        self._save_state()
        self._request_network_join(name, join_targets)

    def _adjust_address_for_targets(self, endpoints):
        if not self.node or self.host_mode != "auto":
            return
        local_ips = candidate_ips()
        for endpoint in endpoints or []:
            if mda_p2p.is_virtual(endpoint):
                continue  # key-based address: routing picks the adapter itself
            try:
                host, _port = parse_peer(endpoint)
            except (ValueError, AttributeError):
                continue
            route_ip = local_ip_for(host)
            if route_ip and route_ip in local_ips:
                if route_ip != self.node.host:
                    self._change_address(route_ip, reason=f"route to {host}")
                return

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
                record = self._record_for_endpoint(endpoint)
                if record:
                    selected_by_endpoint[endpoint]["record"] = record
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

    # ------------------------------------------------------------------
    # Automatic address: follow IP changes and tell the other nodes
    # ------------------------------------------------------------------
    def _rename_endpoint(self, old_endpoint, new_endpoint):
        """Point contacts, chats, queued messages and peers at a node's new address."""
        if not old_endpoint or not new_endpoint or old_endpoint == new_endpoint:
            return
        for contact in self.contacts:
            if contact.get("endpoint") == old_endpoint:
                contact["endpoint"] = new_endpoint
        if old_endpoint in self.chat_windows:
            window = self.chat_windows.pop(old_endpoint)
            window.peer = new_endpoint
            self.chat_windows[new_endpoint] = window
        for item in self.outgoing_real_queue:
            if item.get("receiver") == old_endpoint:
                item["receiver"] = new_endpoint
        if self.node:
            try:
                self.node.remove_peer(old_endpoint)
            except ValueError:
                pass
        self._sync_node_peers_for_active_network()
        self._refresh_contact_list()

    def _change_address(self, new_host, reason=""):
        if not self.node or not new_host or new_host == self.node.host:
            return
        old_endpoint = self.node.set_advertised_host(new_host)
        self.host_var.set(new_host)
        changed = self._upsert_local_node_in_networks()
        changed.add(old_endpoint)
        changed.discard(self.node.nodeid)
        self._refresh_hello_cache()
        self._update_status()
        self._save_state()
        suffix = f" ({reason})" if reason else ""
        self._log(f"Address changed to {self.node.nodeid}{suffix}; telling your networks.")
        self._announce_address_change(changed)

    def _address_signable(self, old_endpoint, new_endpoint, timestamp, pubkey):
        return {
            "action": "address_update",
            "old": old_endpoint,
            "new": new_endpoint,
            "time": timestamp,
            "pubkey_sha256": hashlib.sha256(pubkey.encode("utf-8")).hexdigest(),
        }

    def _announce_address_change(self, old_endpoints):
        if not self.node or not old_endpoints:
            return
        new_endpoint = self.node.nodeid
        pubkey = self.identity.get("public_key_pem", "")
        try:
            private_key = RSA.import_key(self.identity.get("private_key_pem", ""))
        except (ValueError, TypeError):
            self._log("Address update not sent: identity key unavailable.")
            return
        timestamp = time.time()
        payloads = []
        for old_endpoint in sorted(old_endpoints):
            if old_endpoint == new_endpoint:
                continue
            digest = SHA256.new(self._canonical_json_bytes(self._address_signable(old_endpoint, new_endpoint, timestamp, pubkey)))
            payloads.append({
                "type": "control",
                "action": "address_update",
                "network": "",
                "old_endpoint": old_endpoint,
                "new_endpoint": new_endpoint,
                "pubkey": pubkey,
                "time": timestamp,
                "signature": base64.b64encode(pss.new(private_key).sign(digest)).decode("ascii"),
                "sender": new_endpoint,
                "record": self.node.transport.local_record if self.node.transport else None,
            })
        if not payloads:
            return
        skip = set(old_endpoints) | {new_endpoint}
        targets = set()
        for network_name in self.networks:
            targets.update(self._network_endpoints(network_name))
        targets.update(contact.get("endpoint", "") for contact in self.contacts)
        targets = sorted(endpoint for endpoint in targets if endpoint and endpoint not in skip)
        node = self.node

        def worker():
            told = 0
            for endpoint in targets:
                try:
                    for payload in payloads:
                        node.send_control_message(endpoint, payload, timeout=3)
                    told += 1
                except (OSError, ValueError):
                    continue
            self.ui_calls.put(lambda: self._log(f"Address update delivered to {told}/{len(targets)} node(s)."))

        threading.Thread(target=worker, daemon=True).start()

    def _handle_address_update(self, packet):
        old_endpoint = str(packet.get("old_endpoint", "")).strip()
        new_endpoint = str(packet.get("new_endpoint", "")).strip()
        pubkey = str(packet.get("pubkey", "")).strip()
        try:
            timestamp = float(packet.get("time", 0))
            parse_peer(new_endpoint)
            signature = base64.b64decode(str(packet.get("signature", "")).encode("ascii"))
            digest = SHA256.new(self._canonical_json_bytes(self._address_signable(old_endpoint, new_endpoint, timestamp, pubkey)))
            pss.new(RSA.import_key(pubkey)).verify(digest, signature)
        except (ValueError, TypeError, AttributeError):
            self._log(f"Ignored address update with an invalid signature (claimed {old_endpoint} -> {new_endpoint}).")
            return
        if abs(time.time() - timestamp) > 24 * 3600:
            self._log(f"Ignored stale address update for {old_endpoint}.")
            return
        if isinstance(packet.get("record"), dict) and self.node and self.node.transport:
            self.node.transport.learn_record(packet["record"])
        previous = set()
        nickname = ""
        for network_info in self.networks.values():
            nodes = network_info.get("nodes", {})
            if not isinstance(nodes, dict):
                continue
            for node_key, node_entry in nodes.items():
                if not isinstance(node_entry, dict) or not self._same_pubkey(node_entry.get("pubkey"), pubkey):
                    continue
                if float(node_entry.get("addr_time", 0) or 0) >= timestamp:
                    continue
                current = self._extract_node_endpoint(node_entry)
                if current and current != new_endpoint:
                    previous.add(current)
                node_entry["endpoint"] = new_endpoint
                node_entry["addr_time"] = timestamp
                nickname = nickname or self._extract_node_nickname(node_key, node_entry)
        if not previous:
            if not any(
                isinstance(entry, dict) and self._same_pubkey(entry.get("pubkey"), pubkey)
                for info in self.networks.values() for entry in (info.get("nodes", {}) or {}).values()
            ):
                self._log(f"Ignored address update from an unknown node ({new_endpoint}).")
            return
        previous.add(old_endpoint)
        for endpoint in previous:
            self._rename_endpoint(endpoint, new_endpoint)
        self._save_state()
        self._log(f"{nickname or 'A node'} moved to {new_endpoint} (was {', '.join(sorted(previous))}).")

    def _address_watch_tick(self):
        """Every few seconds: if our address disappeared (Wi-Fi off, cable plugged), follow it."""
        try:
            if self.node and self.host_mode == "auto":
                local_ips = candidate_ips()
                if self.node.host not in local_ips:
                    new_host = best_local_ip()
                    if new_host and new_host != "127.0.0.1" and new_host != self.node.host:
                        self._change_address(new_host, reason="network changed")
        finally:
            self.root.after(5000, self._address_watch_tick)

    # ------------------------------------------------------------------
    # Networks nearby (LAN discovery) and join by address
    # ------------------------------------------------------------------
    def _network_summary(self, network_name, info):
        local_pubkey = self.identity.get("public_key_pem", "")
        return {
            "network": network_name,
            "type": str(info.get("type", "private")),
            "description": str(info.get("description", ""))[:160],
            "rules": [str(rule)[:40] for rule in (info.get("rules") or [])][:5],
            "min_approvals": int(info.get("min_approvals", 2) or 2),
            "endpoint": self._local_endpoint(),
            "role": str(info.get("my_role", "member")),
            "nickname": self.node_name_var.get().strip() or "node",
            "pubkey": local_pubkey,
            "port": self.node.port if self.node else self._node_port(),
            "record": self.node.transport.local_record if (self.node and self.node.transport) else None,
        }

    def _refresh_hello_cache(self):
        """Snapshot of the networks this node can admit people to (read by network threads)."""
        summaries = []
        for network_name, info in self.networks.items():
            if str(info.get("my_role", "member")).lower() not in ("seed", "trusted"):
                continue
            if info.get("membership_status", "active") != "active" or not info.get("discoverable", True):
                continue
            summaries.append(self._network_summary(network_name, info))
        self._hello_cache = summaries

    def _hello_networks(self):
        return list(getattr(self, "_hello_cache", []))

    def _start_discovery(self):
        if self.discovery is not None:
            return
        self.discovery = LanDiscovery(DISCOVERY_PORT, own_endpoint_getter=self._local_endpoint).start()
        if self.discovery.listen_error:
            self._log(f"Networks Nearby is unavailable (port {DISCOVERY_PORT}: {self.discovery.listen_error}). Use Join by Address.")

    def _announce_tick(self):
        try:
            if self.node and self.discovery is not None:
                announcements = [
                    LanDiscovery.build_announcement(item["network"], {k: v for k, v in item.items() if k not in ("pubkey", "record")})
                    for item in self._hello_networks()
                ]
                if announcements:
                    self.discovery.announce(announcements)
        except Exception as exc:
            self._log(f"Announcement failed: {exc}")
        finally:
            self.root.after(3000, self._announce_tick)

    def _membership_label(self, network_name):
        info = self.networks.get(network_name)
        if not info:
            return ""
        status = info.get("membership_status", "active")
        return "you are a member" if status == "active" else "waiting for approval"

    def show_nearby_networks(self):
        if not self.node:
            self.start_node()
            if not self.node:
                return
        if self._nearby_window is not None:
            try:
                self._nearby_window.lift()
                return
            except tk.TclError:
                self._nearby_window = None
        window = tk.Toplevel(self.root)
        window.title("Networks Nearby")
        window.geometry("620x340")
        self._nearby_window = window
        body = ttk.Frame(window, padding=10)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Networks on this Wi-Fi / cable network. Select one and click Join.").pack(anchor="w")
        columns = ("network", "owner", "type", "status")
        tree = ttk.Treeview(body, columns=columns, show="headings", height=9, selectmode="browse")
        for column, title, width in (("network", "Network", 170), ("owner", "Owner", 190), ("type", "Type", 70), ("status", "", 150)):
            tree.heading(column, text=title)
            tree.column(column, width=width, anchor="w")
        tree.pack(fill="both", expand=True, pady=6)
        self._nearby_tree = tree
        self._nearby_hint_var = tk.StringVar(master=window, value="")
        ttk.Label(body, textvariable=self._nearby_hint_var, foreground="#555", wraplength=580, justify="left").pack(anchor="w")
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(6, 0))
        ttk.Button(buttons, text="Join", command=self._join_selected_nearby).pack(side="left")
        ttk.Button(buttons, text="Join by Address…", command=self.join_by_address_dialog).pack(side="left", padx=6)
        ttk.Button(buttons, text="Use .mdar File…", command=self.join_network_dialog).pack(side="left")
        ttk.Button(buttons, text="Close", command=window.destroy).pack(side="right")
        tree.bind("<Double-Button-1>", lambda _e: self._join_selected_nearby())
        window.bind("<Destroy>", lambda e: setattr(self, "_nearby_window", None) if e.widget is window else None)
        self._nearby_items = {}
        self._render_nearby()

    def _render_nearby(self):
        window = self._nearby_window
        if window is None:
            return
        try:
            if not window.winfo_exists():
                self._nearby_window = None
                return
        except tk.TclError:
            self._nearby_window = None
            return
        items = self.discovery.nearby() if self.discovery is not None else []
        tree = self._nearby_tree
        selected = tree.selection()
        tree.delete(*tree.get_children())
        self._nearby_items = {}
        for index, item in enumerate(items):
            iid = f"n{index}"
            host = str(item.get("endpoint", "")).rsplit(":", 1)[0]
            owner = f"{item.get('nickname', '?')} ({host})"
            tree.insert("", "end", iid=iid, values=(item.get("network", ""), owner, item.get("type", ""), self._membership_label(item.get("network", ""))))
            self._nearby_items[iid] = item
        for iid in selected:
            if iid in self._nearby_items:
                tree.selection_set(iid)
        if items:
            self._nearby_hint_var.set("Joining sends a request; the network owner must approve it.")
        else:
            self._nearby_hint_var.set(
                "Looking for networks… Nothing yet? The owner's computer must have MDANetPro open, and some Wi-Fi "
                "networks block this kind of discovery. Ask the owner for their address and use 'Join by Address'."
            )
        window.after(1500, self._render_nearby)

    def _join_selected_nearby(self):
        selection = self._nearby_tree.selection() if self._nearby_window is not None else ()
        if not selection:
            messagebox.showinfo("Networks Nearby", "Select a network first.", parent=self._nearby_window)
            return
        item = self._nearby_items.get(selection[0])
        if not item:
            return
        if item.get("seen_from"):
            # The announcement is small; ask the owner directly for its routes and key.
            self._lookup_and_join(f"{item['seen_from']}:{int(item.get('port') or mda.PORT)}", preferred=item.get("network"))
        else:
            self._join_from_summary(item, parent=self._nearby_window)

    def _join_from_summary(self, summary, parent=None):
        name = str(summary.get("network", "")).strip()
        endpoint = str(summary.get("endpoint", "")).strip()
        if not name or not endpoint:
            return
        existing = self.networks.get(name)
        if existing and existing.get("membership_status", "active") == "active":
            messagebox.showinfo("Join Network", f"You are already a member of '{name}'.", parent=parent or self.root)
            return
        owner = summary.get("nickname", "the owner")
        if not messagebox.askyesno("Join Network", f"Ask {owner} to let you join '{name}'?", parent=parent or self.root):
            return
        nodes = {
            str(owner): {
                "endpoint": endpoint,
                "role": str(summary.get("role", "seed")),
                "nickname": str(owner),
                "pubkey": str(summary.get("pubkey", "")),
            }
        }
        record = summary.get("record")
        if isinstance(record, dict) and mda_p2p.verify_record(record):
            nodes[str(owner)]["record"] = record
            if self.node and self.node.transport:
                self.node.transport.learn_record(record)
        net_type = str(summary.get("type", "private")).lower()
        try:
            min_approvals = max(1, int(summary.get("min_approvals", 2)))
        except (TypeError, ValueError):
            min_approvals = 2
        self._join_network(
            name=name,
            net_type=net_type if net_type in ("private", "public") else "private",
            description=str(summary.get("description", "")),
            rules=[str(rule) for rule in (summary.get("rules") or []) if str(rule).strip()],
            nodes=nodes,
            my_role="member",
            min_approvals=min_approvals,
        )

    def join_by_address_dialog(self):
        if not self.node:
            self.start_node()
            if not self.node:
                return
        values = self._show_form_dialog(
            "Join by Address",
            [{"name": "address", "label": "Network owner's address (e.g. 192.168.1.20)", "initial": ""}],
            submit_label="Find Networks",
        )
        if not values:
            return
        address = values.get("address", "").strip()
        if not address:
            return
        if address.count(":") > 1 and not address.startswith("["):
            endpoint = f"[{address}]:{mda.PORT}"  # bare IPv6 address
        else:
            endpoint = address if ":" in address else f"{address}:{mda.PORT}"
        try:
            mda_p2p.split_endpoint(endpoint)
        except ValueError:
            messagebox.showerror("Join by Address", f"'{address}' is not a valid address.")
            return
        self._lookup_and_join(endpoint)

    def _lookup_and_join(self, endpoint, preferred=None):
        node = self.node
        self._log(f"Looking up networks at {endpoint}…")

        def worker():
            try:
                reply = node.hello(endpoint, timeout=6)
                error = "" if reply else "That computer runs an older MDANetPro version."
            except (OSError, ValueError) as exc:
                reply, error = None, str(exc) or exc.__class__.__name__
            self.ui_calls.put(lambda: self._finish_join_by_address(endpoint, reply, error, preferred))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_join_by_address(self, endpoint, reply, error, preferred=None):
        if reply is None:
            if messagebox.askyesno(
                "Join by Address",
                f"Could not reach {endpoint}.\n\n{error}\n\n"
                "Check that the owner's computer is on, has MDANetPro open, and that you are on the same network.\n\n"
                "Run a connection test?",
            ):
                self.test_connection(extra_targets=[endpoint])
            return
        networks = [dict(item) for item in reply.get("networks", []) if isinstance(item, dict) and item.get("network")]
        record = reply.get("record") if isinstance(reply.get("record"), dict) else None
        for item in networks:
            if record and mda_p2p.verify_record(record) and record.get("node") == item.get("endpoint"):
                item["record"] = record
        if preferred:
            networks = [item for item in networks if item["network"] == preferred] or networks
        if not networks:
            messagebox.showinfo("Join by Address", "That computer is reachable, but it has no networks open for joining.")
            return
        if len(networks) == 1:
            self._join_from_summary(networks[0])
            return
        names = [item["network"] for item in networks]
        values = self._show_form_dialog(
            "Choose Network",
            [{"name": "network", "label": "Network", "initial": names[0], "kind": "combobox", "options": names}],
            submit_label="Join",
        )
        if values:
            chosen = next((item for item in networks if item["network"] == values.get("network")), None)
            if chosen:
                self._join_from_summary(chosen)

    # ------------------------------------------------------------------
    # Internet (P2P): route records, relays, NAT check
    # ------------------------------------------------------------------
    def _record_for_endpoint(self, endpoint):
        transport = self.node.transport if self.node else None
        if transport and endpoint in transport.records:
            return transport.records[endpoint]
        for info in self.networks.values():
            for entry in (info.get("nodes") or {}).values():
                if isinstance(entry, dict) and entry.get("endpoint") == endpoint and isinstance(entry.get("record"), dict):
                    return entry["record"]
        if endpoint == self._local_endpoint() and transport:
            return transport.local_record
        return None

    def _learn_records_from_nodes(self, nodes):
        if not (self.node and self.node.transport) or not isinstance(nodes, dict):
            return
        for entry in nodes.values():
            if isinstance(entry, dict) and isinstance(entry.get("record"), dict):
                record = entry["record"]
                if self._same_pubkey(record.get("pubkey"), entry.get("pubkey")) or not entry.get("pubkey"):
                    self.node.transport.learn_record(record)

    def _load_records_into_transport(self):
        for info in self.networks.values():
            self._learn_records_from_nodes(info.get("nodes") or {})

    def _relay_allowed(self, pubkey):
        """Who may use this computer as a relay: members of our networks and pending joiners."""
        pubkey = str(pubkey or "").strip()
        if not pubkey:
            return False
        if time.time() - self._recent_join_requesters.get(pubkey, 0) < 3600:
            return True
        for info in list(self.networks.values()):
            for entry in list((info.get("nodes") or {}).values()):
                if isinstance(entry, dict) and self._same_pubkey(entry.get("pubkey"), pubkey):
                    return True
        return False

    def _start_nat_check(self):
        if not (self.node and self.node.transport) or self._nat_check_running:
            return
        self._nat_check_running = True
        node, use_upnp = self.node, self.use_upnp

        def worker():
            try:
                result = node.transport.discover_nat(use_upnp=use_upnp)
            except Exception as exc:
                result = {"error": str(exc)}

            def done():
                self._nat_check_running = False
                self._last_nat_check = time.time()
                mapping = (result or {}).get("mapping") or {}
                stun = (result or {}).get("stun") or {}
                if mapping.get("usable"):
                    self._log(f"Router opened port {mapping.get('tcp_port')} automatically ({mapping.get('method')}).")
                elif mapping:
                    self._log("Router accepted the port request, but it is behind another NAT (not reachable from the internet).")
                if stun.get("public"):
                    self._log(f"Internet address {stun['public'][0]} (NAT type: {stun.get('nat')}).")
                else:
                    self._log("Could not reach STUN servers: internet connections may only work through relays.")
                self._choose_relays()
                self._update_status()

            self.ui_calls.put(done)

        threading.Thread(target=worker, daemon=True).start()

    def _p2p_tick(self):
        try:
            if self.node and self.node.transport:
                if time.time() - self._last_nat_check > 600 and self._last_nat_check:
                    mda_netutils.invalidate_cache()
                    self._start_nat_check()  # renew the router port mapping and STUN address
                self._choose_relays()
                cutoff = time.time() - 3600
                for key in [k for k, v in self._recent_join_requesters.items() if v < cutoff]:
                    del self._recent_join_requesters[key]
                self._update_status()
        finally:
            self.root.after(15000, self._p2p_tick)

    def _choose_relays(self):
        """Behind NAT: keep a connection open to up to two reachable members (seed/trusted first)."""
        if not (self.node and self.node.transport):
            return
        transport = self.node.transport
        if transport.is_reachable():
            if transport.relays:
                transport.set_relays([])
            return
        local = self._local_endpoint()
        rank = {"seed": 0, "trusted": 1}
        candidates = []
        for network_name, info in self.networks.items():
            pending = info.get("membership_status") == "pending_approval"
            for node_key, entry in (info.get("nodes") or {}).items():
                endpoint = self._extract_node_endpoint(entry)
                if not endpoint or endpoint == local:
                    continue
                record = transport.records.get(endpoint)
                if not (record and record.get("reachable")):
                    continue
                role = self._extract_node_role(node_key, entry)
                score = (0 if pending else 1, rank.get(role, 2))
                candidates.append((score, endpoint))
        candidates.sort()
        chosen = []
        for _score, endpoint in candidates:
            if endpoint not in chosen:
                chosen.append(endpoint)
        chosen = chosen[:2]
        if chosen != transport.relays:
            transport.set_relays(chosen)
            if chosen:
                names = ", ".join(self._nickname_for_endpoint(e) or e for e in chosen)
                self._log(f"Behind NAT: others will reach you through {names}.")

    def _on_local_record_changed(self, record):
        """Our routes changed: store them in our own node entries and tell the others."""
        local_pubkey = self.identity.get("public_key_pem", "")
        for info in self.networks.values():
            for entry in (info.get("nodes") or {}).values():
                if isinstance(entry, dict) and self._same_pubkey(entry.get("pubkey"), local_pubkey):
                    entry["record"] = record
        self._refresh_hello_cache()
        self._update_status()
        if not self._routes_broadcast_pending:
            self._routes_broadcast_pending = True
            self.root.after(1500, self._broadcast_routes)

    def _broadcast_routes(self):
        self._routes_broadcast_pending = False
        if not (self.node and self.node.transport and self.node.transport.local_record):
            return
        self._save_state()
        payload = {"type": "control", "action": "routes_update", "network": "", "sender": self.node.nodeid,
                   "record": self.node.transport.local_record}
        local = self._local_endpoint()
        targets = set()
        for network_name in self.networks:
            targets.update(self._network_endpoints(network_name))
        targets = sorted(t for t in targets if t and t != local)
        node = self.node

        def worker():
            for endpoint in targets:
                try:
                    node.send_control_message(endpoint, payload, timeout=4)
                except (OSError, ValueError):
                    continue

        threading.Thread(target=worker, daemon=True).start()

    def _handle_routes_update(self, packet):
        record = packet.get("record")
        if not (self.node and self.node.transport and isinstance(record, dict)):
            return
        if not mda_p2p.verify_record(record):
            self._log("Ignored a routes update with an invalid signature.")
            return
        is_new = self.node.transport.learn_record(record)
        if is_new and self._relay_allowed(record.get("pubkey")):
            # Pass newer routes on once (dedup by record time): members behind NAT learn each other.
            sender = str(packet.get("sender", ""))
            targets = set()
            for network_name in self.networks:
                targets.update(self._network_endpoints(network_name))
            targets = sorted(t for t in targets if t and t not in (sender, record["node"], self._local_endpoint()))
            node = self.node
            forward = {"type": "control", "action": "routes_update", "network": "", "sender": node.nodeid, "record": record}

            def worker():
                for endpoint in targets:
                    try:
                        node.send_control_message(endpoint, forward, timeout=4)
                    except (OSError, ValueError):
                        continue

            threading.Thread(target=worker, daemon=True).start()
        changed = False
        for info in self.networks.values():
            for entry in (info.get("nodes") or {}).values():
                if isinstance(entry, dict) and self._same_pubkey(entry.get("pubkey"), record.get("pubkey")):
                    old = self._extract_node_endpoint(entry)
                    if old != record["node"]:
                        self._rename_endpoint(old, record["node"])
                        entry["endpoint"] = record["node"]
                    entry["record"] = record
                    changed = True
        if changed:
            self._save_state()

    # ------------------------------------------------------------------
    # Firewall
    # ------------------------------------------------------------------
    def _node_port(self):
        try:
            return int(self.node.port if self.node else self.port_var.get().strip())
        except (TypeError, ValueError):
            return mda.PORT

    def _check_firewall_async(self, then=None):
        if not mda_firewall.is_supported():
            self._apply_firewall_state({"supported": False, "ok": True}, then)
            return
        port = self._node_port()

        def worker():
            state = mda_firewall.check_firewall(port, DISCOVERY_PORT)
            self.ui_calls.put(lambda: self._apply_firewall_state(state, then))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_firewall_state(self, state, then=None):
        self.firewall_state = state
        if state.get("supported") and not state.get("ok"):
            if state.get("error"):
                self.banner_text_var.set("Could not check Windows Firewall. If others can't connect to you, click 'Allow network access'.")
            else:
                self.banner_text_var.set("Other computers can't connect to you yet: Windows Firewall is blocking MDANetPro.")
            self.banner.grid(row=0, column=0, sticky="ew")
        else:
            self.banner.grid_remove()
        if callable(then):
            then(state)

    def allow_network_access(self, then=None):
        if not mda_firewall.is_supported():
            messagebox.showinfo("Network Access", "Nothing to do: this computer does not use Windows Firewall.")
            return
        port = self._node_port()
        self.banner_text_var.set("Waiting for Windows permission… (click Yes on the Windows prompt)")
        self.banner.grid(row=0, column=0, sticky="ew")

        def worker():
            started, message = mda_firewall.allow_network_access(port, DISCOVERY_PORT)
            state = mda_firewall.check_firewall(port, DISCOVERY_PORT)

            def done():
                self._apply_firewall_state(state)
                if state.get("ok"):
                    self._log("Network access allowed in Windows Firewall.")
                    messagebox.showinfo("Network Access", "Done. Other computers can now connect to you.")
                elif not started:
                    messagebox.showwarning("Network Access", message)
                else:
                    messagebox.showwarning(
                        "Network Access",
                        "The rules were added, but something is still blocking.\n\n"
                        "If you use another security program (Kaspersky, Avast, ESET…), allow MDANetPro there too.",
                    )
                if callable(then):
                    then(state)

            self.ui_calls.put(done)

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    # Test connection
    # ------------------------------------------------------------------
    def _test_targets(self, network_name):
        info = self.networks.get(network_name, {})
        nodes = info.get("nodes", {}) if isinstance(info.get("nodes", {}), dict) else {}
        local = self._local_endpoint()
        rank = {"seed": 0, "trusted": 1}
        targets = []
        for node_key, node_entry in nodes.items():
            endpoint = self._extract_node_endpoint(node_entry)
            if not endpoint or endpoint == local:
                continue
            if isinstance(node_entry, dict) and self._same_pubkey(node_entry.get("pubkey"), self.identity.get("public_key_pem", "")):
                continue
            role = self._extract_node_role(node_key, node_entry)
            name = self._extract_node_nickname(node_key, node_entry) or endpoint
            targets.append((rank.get(role, 2), name, endpoint, role))
        targets.sort()
        return [(name, endpoint, role) for _rank, name, endpoint, role in targets[:6]]

    def test_connection(self, extra_targets=None):
        if not self.node:
            self.start_node()
            if not self.node:
                return
        network_name = self._active_network_name()
        targets = self._test_targets(network_name)
        for endpoint in extra_targets or []:
            if endpoint not in [item[1] for item in targets]:
                targets.insert(0, (endpoint, endpoint, ""))

        window = tk.Toplevel(self.root)
        window.title("Connection Test")
        window.geometry("600x380")
        body = ttk.Frame(window, padding=10)
        body.pack(fill="both", expand=True)
        text = scrolledtext.ScrolledText(body, height=14, wrap="word", state="normal")
        text.pack(fill="both", expand=True)
        text.insert(tk.END, "Testing… this can take a few seconds.\n")
        text.configure(state="disabled")
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(8, 0))
        fix_firewall = ttk.Button(buttons, text="Allow network access", command=lambda: self.allow_network_access(then=lambda _s: rerun()))
        fix_address = ttk.Button(buttons, text="Use suggested address")
        ttk.Button(buttons, text="Close", command=window.destroy).pack(side="right")
        ttk.Button(buttons, text="Test again", command=lambda: rerun()).pack(side="right", padx=6)
        node = self.node
        port = self._node_port()

        def rerun():
            try:
                window.destroy()
            except tk.TclError:
                pass
            self.test_connection(extra_targets=extra_targets)

        def worker():
            firewall = mda_firewall.check_firewall(port, DISCOVERY_PORT) if mda_firewall.is_supported() else {"supported": False, "ok": True}
            results = [(name, endpoint, role, node.probe_reachability(endpoint, timeout=8)) for name, endpoint, role in targets]
            self.ui_calls.put(lambda: show(firewall, results))

        def show(firewall, results):
            self._apply_firewall_state(firewall)
            try:
                if not window.winfo_exists():
                    return
            except tk.TclError:
                return
            lines = [f"Network: {network_name}   This computer: {node.host}",
                     f"Internet: {node.transport.connectivity_summary() if node.transport else 'n/a'}", ""]
            need_firewall = firewall.get("supported") and not firewall.get("ok")
            suggested = ""
            if firewall.get("supported"):
                lines.append("✅ Windows Firewall allows MDANetPro." if firewall.get("ok") else "❌ Windows Firewall is blocking MDANetPro on this computer.")
                lines.append("")
            if not results:
                lines.append(f"There are no other computers in '{network_name}' yet.")
                lines.append("When someone joins, run this test again." if not need_firewall else "Click 'Allow network access' so others can join you.")
            local_ips = candidate_ips()
            for name, endpoint, role, result in results:
                label = f"{name} ({endpoint})" + (f" [{role}]" if role else "")
                if not result["connect_ok"]:
                    lines.append(f"❌ {label}: can't reach it.")
                    lines.append("    It may be switched off, not running MDANetPro, on a different network, or its firewall is blocking.")
                    lines.append("    Ask its owner to open MDANetPro and click 'Allow network access'.")
                elif result["callback_ok"]:
                    lines.append(f"✅ {label}: connected both ways.")
                    if result.get("route"):
                        lines.append(f"    you → them: {result['route']}")
                    if result.get("callback_route"):
                        lines.append(f"    them → you: {result['callback_route']}")
                else:
                    need_firewall = need_firewall or mda_firewall.is_supported()
                    lines.append(f"⚠️ {label}: you can reach it, but it can't reach you back.")
                    if mda_p2p.is_virtual(endpoint) and node.transport and not node.transport.is_reachable() and not node.transport.relays:
                        lines.append("    You are behind a router (NAT) and have no relay yet. A member who is reachable from")
                        lines.append("    the internet (e.g. the network owner with UPnP or a port-forward) is needed.")
                    else:
                        lines.append("    This computer is blocking incoming connections. Click 'Allow network access'.")
                    if result.get("error"):
                        lines.append(f"    ({result['error']})")
                seen_ip = result.get("seen_ip", "")
                same_network_route = str(result.get("route", "")).startswith("direct (same network)") or not mda_p2p.is_virtual(endpoint)
                if result["connect_ok"] and same_network_route and seen_ip and seen_ip != node.host:
                    if seen_ip in local_ips:
                        suggested = seen_ip
                        lines.append(f"    It sees you as {seen_ip}, but you announce {node.host}. Click 'Use suggested address'.")
                    else:
                        lines.append(f"    It sees you as {seen_ip} (a router is translating addresses); replies may not reach you.")
                lines.append("")
            text.configure(state="normal")
            text.delete("1.0", tk.END)
            text.insert(tk.END, "\n".join(lines))
            text.configure(state="disabled")
            if need_firewall:
                fix_firewall.pack(side="left")
            if suggested:
                fix_address.configure(command=lambda: (self._set_auto_address(suggested), rerun()))
                fix_address.pack(side="left", padx=6)

        threading.Thread(target=worker, daemon=True).start()

    def _set_auto_address(self, host):
        self._change_address(host, reason="connection test")

    # ------------------------------------------------------------------
    # First-run wizard
    # ------------------------------------------------------------------
    def setup_wizard(self):
        if getattr(self, "_wizard", None) is not None:
            try:
                self._wizard.lift()
                return
            except tk.TclError:
                pass
        wizard = tk.Toplevel(self.root)
        self._wizard = wizard
        wizard.title("Welcome to MDANetPro")
        wizard.geometry("520x340")
        wizard.resizable(False, False)
        wizard.transient(self.root)
        wizard.bind("<Destroy>", lambda e: setattr(self, "_wizard", None) if e.widget is wizard else None)
        container = ttk.Frame(wizard, padding=18)
        container.pack(fill="both", expand=True)
        pages = []

        def finish():
            self.setup_done = True
            self._save_state()
            try:
                wizard.destroy()
            except tk.TclError:
                pass

        def show(index):
            for page in pages:
                page.pack_forget()
            pages[index].pack(fill="both", expand=True)

        # Page 1: name
        page1 = ttk.Frame(container)
        ttk.Label(page1, text="Step 1 of 3 — Your name", font=("TkDefaultFont", 12, "bold")).pack(anchor="w")
        ttk.Label(page1, text="This is the name other people will see when you join or create a network.", wraplength=460).pack(anchor="w", pady=(8, 12))
        name_var = tk.StringVar(master=wizard, value=self.node_name_var.get())
        name_entry = ttk.Entry(page1, textvariable=name_var, width=32)
        name_entry.pack(anchor="w")

        def page1_next():
            name = name_var.get().strip()
            if not name:
                messagebox.showerror("Your name", "Please enter a name.", parent=wizard)
                return
            self.node_name_var.set(name[:32])
            self._upsert_local_node_in_networks()
            self._refresh_hello_cache()
            self._update_status()
            self._save_state()
            if mda_firewall.is_supported():
                show(1)
                refresh_firewall()
            else:
                show(2)

        ttk.Button(page1, text="Next →", command=page1_next).pack(side="bottom", anchor="e")
        pages.append(page1)

        # Page 2: firewall
        page2 = ttk.Frame(container)
        ttk.Label(page2, text="Step 2 of 3 — Allow connections", font=("TkDefaultFont", 12, "bold")).pack(anchor="w")
        ttk.Label(
            page2,
            text="Windows must allow other computers to connect to MDANetPro. Click the button and answer "
                 "'Yes' on the Windows prompt. You only need to do this once.",
            wraplength=460, justify="left",
        ).pack(anchor="w", pady=(8, 12))
        fw_status = tk.StringVar(master=wizard, value="Checking…")
        ttk.Label(page2, textvariable=fw_status).pack(anchor="w")
        allow_button = ttk.Button(page2, text="Allow network access")
        allow_button.pack(anchor="w", pady=8)

        def on_fw_state(state):
            try:
                if not wizard.winfo_exists():
                    return
            except tk.TclError:
                return
            if state.get("ok"):
                fw_status.set("✅ Connections are allowed.")
                allow_button.state(["disabled"])
            else:
                fw_status.set("❌ Not allowed yet.")
                allow_button.state(["!disabled"])

        def refresh_firewall():
            fw_status.set("Checking…")
            self._check_firewall_async(then=on_fw_state)

        allow_button.configure(command=lambda: self.allow_network_access(then=on_fw_state))
        nav2 = ttk.Frame(page2)
        nav2.pack(side="bottom", fill="x")
        ttk.Button(nav2, text="← Back", command=lambda: show(0)).pack(side="left")
        ttk.Button(nav2, text="Next →", command=lambda: show(2)).pack(side="right")
        pages.append(page2)

        # Page 3: create or join
        page3 = ttk.Frame(container)
        ttk.Label(page3, text="Step 3 of 3 — Create or join a network", font=("TkDefaultFont", 12, "bold")).pack(anchor="w")
        ttk.Label(page3, text="Start your own network, or join one that someone near you has created.", wraplength=460).pack(anchor="w", pady=(8, 12))
        create_var = tk.StringVar(master=wizard, value="")
        create_row = ttk.Frame(page3)
        create_row.pack(fill="x", pady=4)
        ttk.Entry(create_row, textvariable=create_var, width=26).pack(side="left")

        def do_create():
            name = create_var.get().strip()
            if not name:
                messagebox.showerror("Create Network", "Type a name for your network first.", parent=wizard)
                return
            if name in self.networks:
                messagebox.showerror("Create Network", f"You already have a network called '{name}'.", parent=wizard)
                return
            if not self.node:
                self.start_node()
            self._create_network(name, "private", "seed", 1, "", [], True)
            finish()
            messagebox.showinfo(
                "Network Created",
                f"'{name}' is ready.\n\nPeople near you can now find it under 'Networks Nearby' and ask to join. "
                "You will be asked to approve each person.",
            )

        ttk.Button(create_row, text="Create my network", command=do_create).pack(side="left", padx=8)
        ttk.Button(page3, text="Join a network nearby…", command=lambda: (finish(), self.show_nearby_networks())).pack(anchor="w", pady=(14, 4))
        ttk.Button(page3, text="I have an invite file (.mdar)…", command=lambda: (finish(), self.join_network_dialog())).pack(anchor="w", pady=4)
        nav3 = ttk.Frame(page3)
        nav3.pack(side="bottom", fill="x")
        ttk.Button(nav3, text="← Back", command=lambda: show(1 if mda_firewall.is_supported() else 0)).pack(side="left")
        ttk.Button(nav3, text="Skip for now", command=finish).pack(side="right")
        pages.append(page3)

        show(0)
        name_entry.focus_set()

    def show_help(self):
        messagebox.showinfo(
            "Help",
            "Getting started:\n"
            "1. Setup Wizard: choose your name and allow network access.\n"
            "2. Create a network, or open 'Networks Nearby' and click Join.\n"
            "3. The network owner approves you; members then appear in Contacts.\n\n"
            "Something not working? Click 'Test Connection'. It checks both directions\n"
            "and tells you what to fix.\n\n"
            "Not on the same Wi-Fi? Use Network > Join by Address, or a .mdar invite file.\n\n"
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
    parser.add_argument("--host", default=None, help="Address to announce (default: detect automatically)")
    parser.add_argument("--port", type=int, default=50404, help="Local port to bind the node")
    parser.add_argument("--peer", action="append", default=[], help="Peer endpoint host:port")
    parser.add_argument("--message", default="", help="Message to send to peers")
    parser.add_argument("--cli", action="store_true", help="Run in terminal mode instead of GUI")
    args = parser.parse_args()

    if args.cli or args.message:
        args.host = args.host or mda.get_local_ip()
        run_cli_mode(args)
        return

    root = tk.Tk()
    app = MDAClientGUI(root)
    if args.host:
        app.host_mode = "manual"
        app.host_var.set(args.host)
    if args.port != 50404 or not app.port_var.get().strip():
        app.port_var.set(str(args.port))
    active_network = app._active_network_name()
    for peer in args.peer:
        app._upsert_contact(endpoint=peer, nickname=f"Peer-{peer.rsplit(':', 1)[-1] if ':' in peer else peer}", network=active_network)
    app._refresh_contact_list()
    app._save_state()
    root.mainloop()


if __name__ == "__main__":
    main()
