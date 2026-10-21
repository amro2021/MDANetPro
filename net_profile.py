# -*- coding: utf-8 -*-
# MDA Network Project
# Ring decentralized P2P network for secure instance-messaging
# By Amr Abdelnaser C&E Engineer, Qatar
# Begin in 14/9/2015 04:23 PM

# This file handles .mdar network profile import/export.
import ast
import base64
import json

import db_dht as db


class mdar:
    """
    Manage a MDA network profile file (.mdar) for exporting and importing
    node information and network metadata.
    """

    def __init__(self):
        self.mda_pre = "**MDA Project Network profile**"
        self.network_name = None
        self.network_type = "private"  # Public or Private
        self.network_rules = []
        self.network_description = ""

    def make_mdar(self, net_name, net_type="private", net_description="", net_rules=None, file_path=None, selected_nodes=None):
        """Create and save a .mdar file for a network."""
        self.network_name = net_name
        self.network_type = net_type if net_type in ("public", "private") else "public"
        self.network_description = net_description or ""
        self.network_rules = net_rules or []

        if selected_nodes is None:
            try:
                selected_nodes = db.select_nodes(net_name)
            except Exception:
                selected_nodes = {}

        if isinstance(selected_nodes, str):
            try:
                selected_nodes = ast.literal_eval(selected_nodes)
            except (ValueError, SyntaxError):
                selected_nodes = {}

        if not file_path:
            file_path = "{}.mdar".format(self.network_name)

        data = self.mdar_format(selected_nodes)
        with open(file_path, "wb") as fo:
            fo.write(data)
        return file_path

    def mdar_format(self, selected_nodes):
        """Serialize network metadata and the node list into a .mdar payload."""
        payload = {
            "magic": self.mda_pre,
            "name": self.network_name,
            "type": self.network_type,
            "description": self.network_description,
            "rules": list(self.network_rules),
            "nodes": selected_nodes,
        }
        text = json.dumps(payload, indent=2, sort_keys=True)
        return base64.b64encode(text.encode("utf-8"))

    def export_network(self, net_name, file_path=None, net_type="private", net_description="", net_rules=None, selected_nodes=None):
        """Convenience method to export node information to a .mdar file."""
        self.network_name = net_name
        self.network_type = net_type if net_type in ("public", "private") else "private"
        self.network_description = net_description or ""
        self.network_rules = net_rules or []
        return self.make_mdar(net_name, self.network_type, self.network_description, self.network_rules, file_path=file_path, selected_nodes=selected_nodes)

    def add_network(self, file_name):
        """Import a .mdar file into the local database."""
        payload = self.read_mdar(file_name)
        if not payload:
            return False

        net_name = payload.get("name")
        net_type = payload.get("type", "private")
        net_des = payload.get("description", "")
        net_rules = payload.get("rules", [])
        selected_nodes = payload.get("nodes", {})

        try:
            db.add_network(net_name, net_type, net_des, str(net_rules), str(selected_nodes))
            return True
        except Exception:
            return False

    def read_mdar(self, file_name):
        """Read and decode a .mdar file. Accepts the modern JSON-based format and the legacy format."""
        if not file_name:
            return {}

        with open(file_name, "rb") as fo:
            raw = fo.read().strip()

        if not raw:
            return {}

        try:
            decoded = base64.b64decode(raw)
            payload = json.loads(decoded.decode("utf-8"))
            if isinstance(payload, dict) and payload.get("magic"):
                return payload
        except (TypeError, ValueError, json.JSONDecodeError):
            pass

        try:
            decoded_data = base64.b64decode(raw)
            data = decoded_data.decode("utf-8", errors="ignore")
            parts = data.split("\n", 4)
            if len(parts) >= 4:
                header, bit2, bit3, bit4 = parts[:4]
                if self.mda_pre in header:
                    net_name, net_type = bit2.split(":", 1)
                    net_des, net_rules = bit3.split(":", 1)
                    return {
                        "magic": header,
                        "name": net_name,
                        "type": net_type,
                        "description": net_des,
                        "rules": net_rules,
                        "nodes": ast.literal_eval(bit4) if bit4 else {},
                    }
        except Exception:
            pass

        return {}


def export_mdar_file(net_name, file_path=None, net_type="private", net_description="", net_rules=None, selected_nodes=None):
    profile = mdar()
    return profile.export_network(net_name, file_path=file_path, net_type=net_type, net_description=net_description, net_rules=net_rules, selected_nodes=selected_nodes)


def import_mdar_file(file_path):
    profile = mdar()
    return profile.read_mdar(file_path)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MDA .mdar import/export tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    export_parser = subparsers.add_parser("export", help="Export a network profile to .mdar")
    export_parser.add_argument("--network", required=True, help="Network name")
    export_parser.add_argument("--file", default=None, help="Output .mdar file path")
    export_parser.add_argument("--type", choices=["private", "public"], default="private")
    export_parser.add_argument("--description", default="", help="Network description")

    import_parser = subparsers.add_parser("import", help="Import from a .mdar file")
    import_parser.add_argument("--file", required=True, help="Input .mdar file")

    args = parser.parse_args()

    if args.command == "export":
        out = export_mdar_file(args.network, file_path=args.file, net_type=args.type, net_description=args.description)
        print(out)
    elif args.command == "import":
        payload = import_mdar_file(args.file)
        print(json.dumps(payload, indent=2, sort_keys=True))

