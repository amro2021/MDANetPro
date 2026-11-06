#!/usr/bin/env python3
"""Schema and validation helpers for MDANetPro experiment manifests.

This module defines a richer manifest format for lab experiments. The manifest is
shared with the collector at run creation time and is stored in the database as
JSON. It supports reproducible, publication-oriented experiments while keeping
all node-specific configuration explicit and reviewable.
"""

import hashlib
import json
import time
from copy import deepcopy


REQUIRED_TOP_LEVEL_FIELDS = {
    "experiment_id",
    "experiment_name",
    "run_id",
    "schema_version",
    "study_type",
    "created_at",
    "start_time",
    "end_time",
    "environment",
    "network",
    "traffic",
    "workload",
    "logging",
}


def _json_dumps(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _sha256(value):
    return hashlib.sha256(_json_dumps(value).encode("utf-8")).hexdigest()


class ExperimentManifest:
    """Simple schema wrapper with validation and hash generation."""

    def __init__(self, **kwargs):
        self.data = {
            "schema_version": "mda_manifest_v1",
            "study_type": "performance",
            "created_at": time.time(),
            "start_time": None,
            "end_time": None,
            "environment": {
                "platform": "windows",
                "python_version": "",
                "cpu_cores": 0,
                "memory_gb": 0,
                "lab_name": "",
                "machines": [],
            },
            "network": {
                "network_id": "",
                "topology": "mesh",
                "member_count": 0,
                "relay_count": 2,
                "seed_nodes": [],
                "trusted_nodes": [],
                "network_rules": {},
                "join_policy": "manual_approval",
            },
            "traffic": {
                "slot_interval_sec": 2,
                "message_size_bytes": 768,
                "real_to_fake_ratio": 1.0,
                "payload_padding": True,
                "onion_hops": 2,
                "circuit_ttl_sec": 120,
                "circuit_max_uses": 8,
                "control_message_interval_sec": 30,
                "cover_traffic_enabled": True,
            },
            "workload": {
                "duration_sec": 300,
                "message_count_target": 0,
                "senders": [],
                "receivers": [],
                "message_pattern": "steady_state",
                "failure_model": {
                    "packet_loss_pct": 0,
                    "jitter_ms": 0,
                    "node_churn": False,
                    "churn_schedule": [],
                },
                "security_tests": [],
            },
            "logging": {
                "collector_url": "",
                "batch_interval_sec": 30,
                "log_levels": ["event", "packet", "control"],
                "anonymization_level": "pseudonymized",
                "share_mode": "opt_in",
                "retention_days": 30,
            },
            "metadata": {
                "experiment_notes": "",
                "contact_email": "",
                "github_repository": "",
                "software_commit": "",
                "analysis_scripts": [],
            },
            "controls": {
                "random_seed": 0,
                "config_hash": "",
                "run_hash": "",
            },
            **kwargs,
        }
        self.validate()

    @staticmethod
    def build(
        *,
        experiment_id,
        experiment_name,
        run_id,
        study_type="performance",
        network_id="",
        node_count=0,
        notes="",
        collector_url="",
        duration_sec=300,
        slot_interval_sec=2,
        message_size_bytes=768,
        real_to_fake_ratio=1.0,
        cover_traffic_enabled=True,
        relay_count=2,
        **extra,
    ):
        manifest = {
            "experiment_id": experiment_id,
            "experiment_name": experiment_name,
            "run_id": run_id,
            "schema_version": "mda_manifest_v1",
            "study_type": study_type,
            "created_at": time.time(),
            "start_time": time.time(),
            "end_time": None,
            "environment": {
                "platform": "windows",
                "python_version": "",
                "cpu_cores": 0,
                "memory_gb": 0,
                "lab_name": "",
                "machines": [],
            },
            "network": {
                "network_id": network_id,
                "topology": "mesh",
                "member_count": int(node_count),
                "relay_count": int(relay_count),
                "seed_nodes": [],
                "trusted_nodes": [],
                "network_rules": {},
                "join_policy": "manual_approval",
            },
            "traffic": {
                "slot_interval_sec": int(slot_interval_sec),
                "message_size_bytes": int(message_size_bytes),
                "real_to_fake_ratio": float(real_to_fake_ratio),
                "payload_padding": True,
                "onion_hops": int(relay_count),
                "circuit_ttl_sec": 120,
                "circuit_max_uses": 8,
                "control_message_interval_sec": 30,
                "cover_traffic_enabled": bool(cover_traffic_enabled),
            },
            "workload": {
                "duration_sec": int(duration_sec),
                "message_count_target": 0,
                "senders": [],
                "receivers": [],
                "message_pattern": "steady_state",
                "failure_model": {
                    "packet_loss_pct": 0,
                    "jitter_ms": 0,
                    "node_churn": False,
                    "churn_schedule": [],
                },
                "security_tests": [],
            },
            "logging": {
                "collector_url": collector_url,
                "batch_interval_sec": 30,
                "log_levels": ["event", "packet", "control"],
                "anonymization_level": "pseudonymized",
                "share_mode": "opt_in",
                "retention_days": 30,
            },
            "metadata": {
                "experiment_notes": notes,
                "contact_email": "",
                "github_repository": "",
                "software_commit": "",
                "analysis_scripts": [],
            },
            "controls": {
                "random_seed": 0,
                "config_hash": "",
                "run_hash": "",
            },
        }
        manifest.update(extra)
        return ExperimentManifest(**manifest).data

    def validate(self):
        missing = sorted(REQUIRED_TOP_LEVEL_FIELDS - set(self.data.keys()))
        if missing:
            raise ValueError(f"Manifest missing required top-level keys: {missing}")

        if not self.data.get("experiment_id"):
            raise ValueError("experiment_id is required")
        if not self.data.get("run_id"):
            raise ValueError("run_id is required")
        if not self.data.get("experiment_name"):
            raise ValueError("experiment_name is required")
        if not self.data.get("schema_version"):
            raise ValueError("schema_version is required")
        if self.data.get("traffic", {}).get("slot_interval_sec", 0) <= 0:
            raise ValueError("traffic.slot_interval_sec must be > 0")
        if self.data.get("traffic", {}).get("message_size_bytes", 0) <= 0:
            raise ValueError("traffic.message_size_bytes must be > 0")
        if self.data.get("workload", {}).get("duration_sec", 0) <= 0:
            raise ValueError("workload.duration_sec must be > 0")

        self.data["controls"]["config_hash"] = self.config_hash()
        self.data["controls"]["run_hash"] = self.run_hash()
        return self.data

    def config_hash(self):
        payload = {k: v for k, v in self.data.items() if k != "controls"}
        return _sha256(payload)

    def run_hash(self):
        return _sha256({
            "experiment_id": self.data.get("experiment_id"),
            "run_id": self.data.get("run_id"),
            "config_hash": self.data.get("controls", {}).get("config_hash", ""),
            "created_at": self.data.get("created_at"),
        })

    def to_dict(self):
        return deepcopy(self.data)


def validate_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ValueError("Manifest must be a dictionary")
    return ExperimentManifest(**manifest).to_dict()


def demo_manifest():
    return ExperimentManifest.build(
        experiment_id="lab-net-01",
        experiment_name="steady-state performance test",
        run_id="run-001",
        network_id="mda-demo",
        node_count=6,
        notes="Measure end-to-end latency and cover-traffic behavior with 6-node mesh.",
        collector_url="http://127.0.0.1:9090",
        duration_sec=600,
        slot_interval_sec=2,
        message_size_bytes=768,
        real_to_fake_ratio=1.0,
        cover_traffic_enabled=True,
        relay_count=2,
    )


if __name__ == "__main__":
    print(json.dumps(demo_manifest(), indent=2, sort_keys=True))
