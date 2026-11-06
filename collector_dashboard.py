#!/usr/bin/env python3
"""Simple UI to monitor the MDANetPro observer collector while it is running."""

import argparse
import json
import tkinter as tk
import urllib.request
from tkinter import ttk, scrolledtext, messagebox


class CollectorDashboard:
    def __init__(self, root, collector_url):
        self.root = root
        self.collector_url = collector_url.rstrip("/")
        self.root.title("MDA Collector Dashboard")
        self.root.geometry("860x540")
        self.root.minsize(700, 420)

        self.status_var = tk.StringVar(value="Checking collector...")
        self.health_text = scrolledtext.ScrolledText(root, height=8, state="disabled", wrap="word")
        self.run_list = tk.Listbox(root, height=12, exportselection=False)
        self.detail_box = scrolledtext.ScrolledText(root, height=16, state="disabled", wrap="word")

        top = ttk.Frame(root, padding=10)
        top.grid(row=0, column=0, sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        ttk.Label(top, text="Collector URL").grid(row=0, column=0, sticky="w")
        self.url_var = tk.StringVar(value=self.collector_url)
        ttk.Entry(top, textvariable=self.url_var, width=45).grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Button(top, text="Refresh", command=self.refresh).grid(row=0, column=2, sticky="ew")
        ttk.Button(top, text="Open Health", command=self.show_health).grid(row=0, column=3, sticky="ew", padx=(6, 0))
        ttk.Label(top, textvariable=self.status_var).grid(row=1, column=0, columnspan=4, sticky="w", pady=(6, 0))
        top.columnconfigure(1, weight=1)

        body = ttk.Frame(root, padding=(10, 0, 10, 10))
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        left = ttk.Frame(body)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ttk.Label(left, text="Runs").grid(row=0, column=0, sticky="w")
        self.run_list.grid(row=1, column=0, sticky="nsew")
        self.run_list.bind("<<ListboxSelect>>", self.on_run_selected)
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)

        right = ttk.Frame(body)
        right.grid(row=0, column=1, sticky="nsew")
        ttk.Label(right, text="Collector details").grid(row=0, column=0, sticky="w")
        self.detail_box.grid(row=1, column=0, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        self.refresh()

    def _http_get(self, path):
        url = f"{self.collector_url}{path}"
        with urllib.request.urlopen(url, timeout=8) as response:
            return json.loads(response.read().decode("utf-8"))

    def refresh(self):
        try:
            health = self._http_get("/health")
            runs = self._http_get("/runs")
            self.status_var.set(f"Collector ready on {self.collector_url} | status: {health.get('status', 'unknown')}")
            self.run_list.delete(0, tk.END)
            items = runs.get("runs", [])
            if not items:
                self.run_list.insert(tk.END, "No runs yet")
            else:
                for run in items:
                    label = f"{run.get('run_id', 'unknown')} | {run.get('status', 'unknown')}"
                    self.run_list.insert(tk.END, label)
            self.detail_box.configure(state="normal")
            self.detail_box.delete("1.0", tk.END)
            self.detail_box.insert(tk.END, "Collector health:\n")
            self.detail_box.insert(tk.END, json.dumps(health, indent=2, sort_keys=True))
            self.detail_box.insert(tk.END, "\n\nRuns:\n")
            self.detail_box.insert(tk.END, json.dumps(runs, indent=2, sort_keys=True))
            self.detail_box.configure(state="disabled")
        except Exception as exc:
            self.status_var.set(f"Collector unavailable: {exc}")
            self.detail_box.configure(state="normal")
            self.detail_box.delete("1.0", tk.END)
            self.detail_box.insert(tk.END, f"Error: {exc}\n")
            self.detail_box.configure(state="disabled")
            self.run_list.delete(0, tk.END)
            self.run_list.insert(tk.END, "Collector offline")

    def on_run_selected(self, _event=None):
        selection = self.run_list.curselection()
        if not selection:
            return
        label = self.run_list.get(selection[0])
        if "No runs yet" in label or "Collector offline" in label:
            return
        run_id = label.split(" | ", 1)[0]
        self.detail_box.configure(state="normal")
        self.detail_box.delete("1.0", tk.END)
        self.detail_box.insert(tk.END, f"Selected run: {run_id}\n\n")
        try:
            data = self._http_get("/runs")
            for run in data.get("runs", []):
                if run.get("run_id") == run_id:
                    self.detail_box.insert(tk.END, json.dumps(run, indent=2, sort_keys=True))
                    break
        except Exception as exc:
            self.detail_box.insert(tk.END, f"Could not load run details: {exc}")
        self.detail_box.configure(state="disabled")

    def show_health(self):
        try:
            data = self._http_get("/health")
            messagebox.showinfo("Collector Health", json.dumps(data, indent=2, sort_keys=True))
        except Exception as exc:
            messagebox.showerror("Collector Health", str(exc))


def main():
    parser = argparse.ArgumentParser(description="Monitor the MDANetPro observer collector")
    parser.add_argument("--collector-url", default="http://127.0.0.1:9090", help="Base URL of the collector")
    args = parser.parse_args()

    root = tk.Tk()
    app = CollectorDashboard(root, args.collector_url)
    root.mainloop()


if __name__ == "__main__":
    main()
