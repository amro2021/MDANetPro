#!/usr/bin/env python3
"""Tiny uploader for experimental data from lab machines to the observer collector.

This script is intentionally separate from the client GUI. It allows a lab node
or analysis tool to push JSON event batches to the collector without integrating
anything into the application menu.
"""

import argparse
import json
import os
import time
import uuid
from urllib import request, error

from experiment_manifest import ExperimentManifest


def post_json(url, payload):
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    req = request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {body}") from exc


def build_run_manifest(run_id=None, experiment_id="demo_experiment", experiment_name="demo_run", network_name="lab_net", notes="", **kwargs):
    run_id = run_id or str(uuid.uuid4())
    manifest = ExperimentManifest.build(
        experiment_id=experiment_id,
        experiment_name=experiment_name,
        run_id=run_id,
        study_type=kwargs.get("study_type", "performance"),
        network_id=network_name,
        node_count=kwargs.get("node_count", 0),
        notes=notes,
        collector_url=kwargs.get("collector_url", "http://127.0.0.1:9090"),
        duration_sec=kwargs.get("duration_sec", 300),
        slot_interval_sec=kwargs.get("slot_interval_sec", 2),
        message_size_bytes=kwargs.get("message_size_bytes", 768),
        real_to_fake_ratio=kwargs.get("real_to_fake_ratio", 1.0),
        cover_traffic_enabled=kwargs.get("cover_traffic_enabled", True),
        relay_count=kwargs.get("relay_count", 2),
    )
    manifest["metadata"].update({
        "network_name": network_name,
        "lab_name": kwargs.get("lab_name", ""),
        "notes": notes,
    })
    manifest["environment"].update({
        "platform": kwargs.get("platform", "windows"),
        "python_version": kwargs.get("python_version", ""),
        "lab_name": kwargs.get("lab_name", ""),
        "machines": kwargs.get("machines", []),
    })
    manifest["network"].update({
        "seed_nodes": kwargs.get("seed_nodes", []),
        "trusted_nodes": kwargs.get("trusted_nodes", []),
        "network_rules": kwargs.get("network_rules", {}),
        "join_policy": kwargs.get("join_policy", "manual_approval"),
    })
    manifest["workload"].update({
        "message_count_target": kwargs.get("message_count_target", 0),
        "senders": kwargs.get("senders", []),
        "receivers": kwargs.get("receivers", []),
        "message_pattern": kwargs.get("message_pattern", "steady_state"),
        "failure_model": kwargs.get("failure_model", {
            "packet_loss_pct": 0,
            "jitter_ms": 0,
            "node_churn": False,
            "churn_schedule": [],
        }),
        "security_tests": kwargs.get("security_tests", []),
    })
    manifest["logging"].update({
        "batch_interval_sec": kwargs.get("batch_interval_sec", 30),
        "log_levels": kwargs.get("log_levels", ["event", "packet", "control"]),
        "anonymization_level": kwargs.get("anonymization_level", "pseudonymized"),
        "share_mode": kwargs.get("share_mode", "opt_in"),
        "retention_days": kwargs.get("retention_days", 30),
    })
    return manifest


def register_run(collector_url, experiment_id, name, manifest, metadata=None):
    payload = {"experiment_id": experiment_id, "name": name, "metadata": metadata or {}, "manifest": manifest}
    return post_json(f"{collector_url}/api/v1/run", payload)


def send_batch(collector_url, experiment_id, run_id, node_id, events, public_key=None, signature=None):
    batch = {
        "experiment_id": experiment_id,
        "run_id": run_id,
        "node_id": node_id,
        "batch_id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "events": events,
        "public_key": public_key,
        "signature": signature,
    }
    return post_json(f"{collector_url}/api/v1/batch", batch)


def main():
    parser = argparse.ArgumentParser(description="Send experiment data to MDANetPro observer collector")
    parser.add_argument("--collector-url", default="http://127.0.0.1:9090", help="Base URL of the collector")
    parser.add_argument("--experiment-id", default="demo_experiment", help="Experiment ID")
    parser.add_argument("--run-id", default=None, help="Run ID; generated automatically if omitted")
    parser.add_argument("--node-id", default="lab-node-01", help="This machine/node identifier")
    parser.add_argument("--name", default="demo_run", help="Friendly run name")
    parser.add_argument("--notes", default="demo traffic upload", help="Notes for the run")
    args = parser.parse_args()

    manifest = build_run_manifest(
        run_id=args.run_id,
        experiment_id=args.experiment_id,
        experiment_name=args.name,
        network_name="lab_net",
        notes=args.notes,
        collector_url=args.collector_url,
        duration_sec=600,
        slot_interval_sec=2,
        message_size_bytes=768,
        real_to_fake_ratio=1.0,
        cover_traffic_enabled=True,
        relay_count=2,
        node_count=3,
        seed_nodes=["node-01:50404"],
        trusted_nodes=["node-01:50404"],
        log_levels=["event", "packet", "control", "security"],
        share_mode="opt_in",
    )
    register_result = register_run(args.collector_url, args.experiment_id, args.name, manifest, metadata={"source": "observer_client_uploader"})
    print(json.dumps(register_result, indent=2, sort_keys=True))

    sample_events = [
        {
            "event_id": str(uuid.uuid4()),
            "event_type": "node_state",
            "timestamp": time.time(),
            "payload": {"status": "started", "uptime_sec": 1.0},
        },
        {
            "event_id": str(uuid.uuid4()),
            "event_type": "packet_sent",
            "timestamp": time.time(),
            "payload": {"type": "real", "bytes": 768, "destination": "peer-02"},
        },
    ]
    response = send_batch(args.collector_url, args.experiment_id, manifest["run_id"], args.node_id, sample_events)
    print(json.dumps(response, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
