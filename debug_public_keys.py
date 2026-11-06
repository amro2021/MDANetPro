#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Debug script to diagnose missing public key issues in MDANetPro networks.
Run this to check which nodes are missing public keys.
"""

import json
import os
import sys
from pathlib import Path

# Handle Windows console encoding
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


def check_network_keys(state_file="mdaclient_state.json"):
    """Check all networks and identify nodes without public keys."""
    
    if not os.path.exists(state_file):
        print(f"❌ State file not found: {state_file}")
        print("   Make sure you've run MDAClient at least once.")
        return False
    
    try:
        with open(state_file, 'r') as f:
            state = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in {state_file}: {e}")
        return False
    
    networks = state.get("networks", {})
    if not networks:
        print("ℹ️  No networks configured yet.")
        return True
    
    print(f"\n{'='*70}")
    print(f"NETWORK PUBLIC KEY AUDIT")
    print(f"{'='*70}\n")
    
    all_good = True
    
    for network_name, network_info in networks.items():
        print(f"\n📡 Network: {network_name}")
        print(f"   Type: {network_info.get('type', 'unknown')}")
        print(f"   Status: {network_info.get('membership_status', 'unknown')}")
        
        nodes = network_info.get("nodes", {})
        if not isinstance(nodes, dict):
            print(f"   ❌ Nodes is not a dict: {type(nodes)}")
            all_good = False
            continue
        
        if not nodes:
            print(f"   ⚠️  No nodes in this network")
            continue
        
        print(f"   Nodes ({len(nodes)}):")
        
        for node_name, node_entry in nodes.items():
            # Extract endpoint
            if isinstance(node_entry, dict):
                endpoint = node_entry.get("endpoint", "")
                if not endpoint:
                    host = node_entry.get("host", "")
                    port = node_entry.get("port", "")
                    endpoint = f"{host}:{port}" if host and port else ""
            elif isinstance(node_entry, str):
                endpoint = node_entry
            else:
                endpoint = str(node_entry)
            
            # Check for public key
            if isinstance(node_entry, dict):
                pubkey = node_entry.get("pubkey", "").strip()
                role = node_entry.get("role", "unknown")
                nickname = node_entry.get("nickname", node_name)
            else:
                pubkey = ""
                role = "unknown"
                nickname = node_name
            
            # Report status
            if pubkey:
                key_preview = pubkey[:40] + "..." if len(pubkey) > 40 else pubkey
                print(f"      ✅ {nickname} ({node_name})")
                print(f"         Endpoint: {endpoint}")
                print(f"         Role: {role}")
                print(f"         Key: {key_preview}")
            else:
                print(f"      ❌ {nickname} ({node_name})")
                print(f"         Endpoint: {endpoint}")
                print(f"         Role: {role}")
                print(f"         ⚠️  MISSING PUBLIC KEY!")
                all_good = False
    
    print(f"\n{'='*70}")
    if all_good:
        print("✅ All nodes have public keys!")
    else:
        print("❌ Some nodes are missing public keys!")
        print("\n📋 TO FIX:")
        print("   1. On the missing node's computer, generate RSA keys:")
        print("      python generate_rsakey.py")
        print("   2. Export that node's .mdar file")
        print("   3. Exchange .mdar files between all computers")
        print("   4. Re-import the network using the .mdar file")
        print("   5. Run this script again to verify")
    print(f"{'='*70}\n")
    
    return all_good


def show_local_public_key():
    """Show this computer's public key (if it has generated one)."""
    
    print(f"\n{'='*70}")
    print("YOUR LOCAL PUBLIC KEY")
    print(f"{'='*70}\n")
    
    # Check for RSA keys
    key_paths = [
        Path("id_rsa.pub"),
        Path.home() / ".ssh" / "id_rsa.pub",
    ]
    
    found = False
    for key_path in key_paths:
        if key_path.exists():
            print(f"Found: {key_path}")
            try:
                with open(key_path, 'r') as f:
                    pubkey = f.read()
                print(f"\nPublic Key:")
                print(pubkey)
                print(f"\n✅ Copy this key and share it with other computers")
                found = True
                break
            except Exception as e:
                print(f"❌ Error reading key: {e}")
    
    if not found:
        print("❌ No RSA public key found!")
        print("\n📋 TO GENERATE:")
        print("   python generate_rsakey.py")
    
    print(f"\n{'='*70}\n")


if __name__ == "__main__":
    import sys
    
    print("\n🔍 MDANetPro Public Key Debugger\n")
    
    # Check state file
    state_file = "mdaclient_state.json"
    if not check_network_keys(state_file):
        if "No networks" not in str(sys.exc_info()):
            sys.exit(1)
    
    # Show local key
    show_local_public_key()
    
    print("✨ Debug complete!")
