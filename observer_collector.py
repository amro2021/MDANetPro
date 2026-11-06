#!/usr/bin/env python3
"""Separate observer/collector for MDANetPro experiments.

This service is intentionally kept outside the client GUI. It receives JSON event
batches from lab nodes, stores them in a local SQLite database, prepares
reproducible run artifacts, and writes a GitHub-ready export directory.
"""

import argparse
import csv
import hashlib
import json
import os
import sqlite3
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

from experiment_manifest import validate_manifest


class ObserverCollector:
    def __init__(self, data_dir="experiment_data", host="0.0.0.0", port=9090):
        self.data_dir = data_dir
        self.host = host
        self.port = int(port)
        self.db_path = os.path.join(self.data_dir, "collector.sqlite3")
        self.github_dir = os.path.join(self.data_dir, "github_export")
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.github_dir, exist_ok=True)
        self._connect_db()

    def _connect_db(self):
        self.db = sqlite3.connect(self.db_path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL;")
        self.db.execute("PRAGMA synchronous=NORMAL;")
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS experiments (
                experiment_id TEXT PRIMARY KEY,
                name TEXT,
                status TEXT,
                created_at REAL,
                metadata TEXT
            )
            """
        )
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                experiment_id TEXT,
                status TEXT,
                created_at REAL,
                manifest TEXT,
                collector_host TEXT,
                collector_port INTEGER,
                notes TEXT
            )
            """
        )
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                experiment_id TEXT,
                run_id TEXT,
                first_seen REAL,
                last_seen REAL,
                public_key TEXT,
                metadata TEXT
            )
            """
        )
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS batches (
                batch_id TEXT PRIMARY KEY,
                run_id TEXT,
                node_id TEXT,
                experiment_id TEXT,
                received_at REAL,
                signature_valid INTEGER,
                event_count INTEGER,
                metadata TEXT
            )
            """
        )
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                batch_id TEXT,
                run_id TEXT,
                experiment_id TEXT,
                node_id TEXT,
                event_type TEXT,
                ts REAL,
                payload TEXT,
                signature TEXT,
                event_hash TEXT,
                UNIQUE(event_id)
            )
            """
        )
        self.db.commit()

    def register_experiment(self, experiment_id, name, metadata=None):
        metadata = metadata or {}
        self.db.execute(
            "INSERT OR REPLACE INTO experiments (experiment_id, name, status, created_at, metadata) VALUES (?, ?, ?, ?, ?)",
            (experiment_id, name, "active", time.time(), json.dumps(metadata, sort_keys=True)),
        )
        self.db.commit()

    def create_run(self, experiment_id, manifest):
        manifest = validate_manifest(manifest)
        run_id = manifest.get("run_id") or str(uuid.uuid4())
        self.db.execute(
            "INSERT OR REPLACE INTO runs (run_id, experiment_id, status, created_at, manifest, collector_host, collector_port, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                experiment_id,
                "created",
                time.time(),
                json.dumps(manifest, sort_keys=True),
                self.host,
                self.port,
                manifest.get("metadata", {}).get("experiment_notes", ""),
            ),
        )
        self.db.commit()
        return run_id

    def update_run_status(self, run_id, status):
        self.db.execute(
            "UPDATE runs SET status = ? WHERE run_id = ?",
            (status, run_id),
        )
        self.db.commit()

    def store_node(self, node_id, experiment_id, run_id, public_key=None, metadata=None):
        metadata = metadata or {}
        self.db.execute(
            "INSERT OR REPLACE INTO nodes (node_id, experiment_id, run_id, first_seen, last_seen, public_key, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                node_id,
                experiment_id,
                run_id,
                time.time(),
                time.time(),
                public_key,
                json.dumps(metadata, sort_keys=True),
            ),
        )
        self.db.commit()

    def verify_signature(self, payload, signature, public_key_pem=None):
        if not signature:
            return False
        if not public_key_pem:
            return False
        try:
            pub = RSA.import_key(public_key_pem)
            h = SHA256.new(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
            pss.new(pub).verify(h, base64_decode(signature))
            return True
        except Exception:
            return False

    def ingest_batch(self, payload):
        run_id = payload.get("run_id") or "unknown_run"
        experiment_id = payload.get("experiment_id") or "unknown_experiment"
        node_id = payload.get("node_id") or "unknown_node"
        events = payload.get("events") or []
        public_key = payload.get("public_key")
        signature = payload.get("signature")
        signature_valid = self.verify_signature({"node_id": node_id, "run_id": run_id, "events": events}, signature, public_key)

        self.store_node(node_id, experiment_id, run_id, public_key=public_key, metadata={"last_batch": time.time()})
        batch_id = payload.get("batch_id") or str(uuid.uuid4())
        self.db.execute(
            "INSERT OR REPLACE INTO batches (batch_id, run_id, node_id, experiment_id, received_at, signature_valid, event_count, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                batch_id,
                run_id,
                node_id,
                experiment_id,
                time.time(),
                int(bool(signature_valid)),
                len(events),
                json.dumps({"signature": bool(signature), "public_key_present": bool(public_key)}, sort_keys=True),
            ),
        )

        for event in events:
            event_id = event.get("event_id") or sha256_json(event)
            event_hash = sha256_json(event)
            self.db.execute(
                "INSERT OR REPLACE INTO events (event_id, batch_id, run_id, experiment_id, node_id, event_type, ts, payload, signature, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    batch_id,
                    run_id,
                    experiment_id,
                    node_id,
                    event.get("event_type", "unknown"),
                    float(event.get("timestamp", time.time())),
                    json.dumps(event, sort_keys=True),
                    event.get("signature", ""),
                    event_hash,
                ),
            )
        self.db.commit()
        return {"status": "accepted", "batch_id": batch_id, "event_count": len(events), "signature_valid": bool(signature_valid)}

    def summary_rows(self, run_id):
        return self.db.execute(
            """
            SELECT event_type, COUNT(*), MIN(ts), MAX(ts)
            FROM events
            WHERE run_id = ?
            GROUP BY event_type
            ORDER BY event_type
            """,
            (run_id,),
        ).fetchall()

    def prepare_github_export(self, run_id):
        run = self.db.execute("SELECT experiment_id, manifest FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not run:
            raise ValueError(f"Unknown run_id: {run_id}")
        experiment_id, manifest_json = run
        export_dir = os.path.join(self.github_dir, run_id)
        os.makedirs(export_dir, exist_ok=True)

        manifest = json.loads(manifest_json)
        manifest["export_dir"] = export_dir
        manifest["prepared_at"] = time.time()
        manifest["collector"] = {"host": self.host, "port": self.port}
        with open(os.path.join(export_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)

        summary = self.summary_rows(run_id)
        csv_path = os.path.join(export_dir, "event_summary.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["event_type", "count", "min_ts", "max_ts"])
            for row in summary:
                writer.writerow(row)

        readme = os.path.join(export_dir, "README.md")
        with open(readme, "w", encoding="utf-8") as fh:
            fh.write(
                "# MDANetPro experiment export\n\n"
                f"Experiment ID: {experiment_id}\n\n"
                f"Run ID: {run_id}\n\n"
                "This dataset is prepared for publication. Raw event data is stored in the collector database. "
                "The exported files here are sanitized for GitHub archival and repeated analysis.\n"
            )

        return export_dir

    def health(self):
        return {
            "status": "ok",
            "host": self.host,
            "port": self.port,
            "database": self.db_path,
            "github_export": self.github_dir,
            "uptime": time.time(),
        }


def sha256_json(data):
    return hashlib.sha256(json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()


def base64_decode(value):
    import base64

    return base64.b64decode(value.encode("ascii"))


class CollectorHTTPHandler(BaseHTTPRequestHandler):
    server_version = "MDAObserverCollector/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            payload = self.server.collector.health()
            self.send_json(payload)
            return
        if parsed.path == "/runs":
            runs = self.server.collector.db.execute(
                "SELECT run_id, experiment_id, status, created_at FROM runs ORDER BY created_at DESC"
            ).fetchall()
            self.send_json({"runs": [dict(zip(["run_id", "experiment_id", "status", "created_at"], row)) for row in runs]})
            return
        self.send_json({"status": "not_found"}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/v1/batch":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                self.send_json({"status": "invalid_json", "error": str(exc)}, status=400)
                return
            result = self.server.collector.ingest_batch(payload)
            self.send_json(result)
            return
        if parsed.path == "/api/v1/run":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                self.send_json({"status": "invalid_json", "error": str(exc)}, status=400)
                return
            experiment_id = payload.get("experiment_id", "default_experiment")
            manifest = payload.get("manifest", {})
            self.server.collector.register_experiment(experiment_id, payload.get("name", experiment_id), payload.get("metadata", {}))
            run_id = self.server.collector.create_run(experiment_id, manifest)
            self.send_json({"status": "run_created", "run_id": run_id})
            return
        if parsed.path == "/api/v1/export":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                self.send_json({"status": "invalid_json", "error": str(exc)}, status=400)
                return
            run_id = payload.get("run_id")
            if not run_id:
                self.send_json({"status": "missing_run_id"}, status=400)
                return
            export_dir = self.server.collector.prepare_github_export(run_id)
            self.send_json({"status": "export_ready", "export_dir": export_dir})
            return
        self.send_json({"status": "not_found"}, status=404)

    def send_json(self, payload, status=200):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class CollectorHTTPServer(ThreadingHTTPServer):
    def __init__(self, collector, server_address):
        self.collector = collector
        super().__init__(server_address, CollectorHTTPHandler)


def main():
    parser = argparse.ArgumentParser(description="MDANetPro observer collector")
    parser.add_argument("--host", default="0.0.0.0", help="Collector bind host")
    parser.add_argument("--port", type=int, default=9090, help="Collector port")
    parser.add_argument("--data-dir", default="experiment_data", help="Directory for collector SQLite and export artifacts")
    args = parser.parse_args()

    collector = ObserverCollector(data_dir=args.data_dir, host=args.host, port=args.port)
    server = CollectorHTTPServer(collector, (args.host, args.port))
    print(f"Observer collector listening on http://{args.host}:{args.port}", flush=True)
    print(f"Data directory: {os.path.abspath(args.data_dir)}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping observer collector", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
