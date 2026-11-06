# Fix: "Missing receiver public key" Error in MDANetPro

## Problem
When sending messages between two computers, you get:
```
Queued real message failed: Missing receiver public key for 192.168.43.118:50404
```

## Root Cause
The network configuration doesn't include the RSA public key for the receiver node. When `mdaclient.py` tries to encrypt a message using onion routing, it needs the receiver's public key, but the `public_key_map` is empty for that node.

## Where This Happens
In `mdaclient.py` at line ~1438-1455, the `_network_public_key_map()` method builds a map of public keys:

```python
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
                pubkey = str(node_entry.get("pubkey", "")).strip()  # LOOKS FOR "pubkey" FIELD
                if pubkey:
                    key_map[endpoint] = pubkey
    # ... rest of method
    return key_map
```

**The code expects each node to have a `"pubkey"` field with the RSA public key in PEM format.**

## Solution: Ensure All Nodes Have Public Keys

### Step 1: Generate RSA Keys on Both Computers (if not done yet)

Run the key generation script on **each computer**:

```bash
python generate_rsakey.py
```

This creates RSA key pairs used for encryption.

### Step 2: Exchange .mdar Profile Files

1. **On Computer 1** (the creator/seed node):
   - Open MDAClient.exe
   - Create a new network in the GUI
   - Export it as a `.mdar` file (right-click network → Export)
   - Share this `.mdar` file with Computer 2

2. **On Computer 2**:
   - Import the `.mdar` file (File → Join Network)
   - Your public key is automatically added when you import

### Step 3: Manually Fix Existing Network Configuration

If you already have a network configured but nodes are missing public keys:

**Option A: Re-import the network profile**
1. Get the `.mdar` file from the other computer
2. Delete your current network in MDAClient
3. Join the network by importing the `.mdar` file again

**Option B: Manually add public keys**

Edit the network configuration in `mdaclient_state.json`:

Find your network's nodes section. It should look like this:

```json
{
  "networks": {
    "MyNetwork": {
      "nodes": {
        "node1": {
          "endpoint": "192.168.43.118:50404",
          "role": "member",
          "nickname": "Computer2",
          "pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----"
        }
      }
    }
  }
}
```

**Make sure each node in `"nodes"` has a `"pubkey"` field with the full RSA public key in PEM format.**

To get a node's public key:
1. Find the node's `id_rsa.pub` file
2. Copy its contents
3. Paste it as the `"pubkey"` value (keep the line breaks)

### Step 4: Verify the Fix

After ensuring all nodes have public keys:

1. Restart MDAClient.exe
2. Try sending a message again
3. You should no longer get the "Missing receiver public key" error

## Prevention: When Adding New Nodes

When manually adding nodes to a network, **always include their public key**:

```python
nodes_map[node_name] = {
    "endpoint": "192.168.x.x:50404",
    "role": "member",
    "nickname": "NodeName",
    "pubkey": "<their_public_key_in_PEM_format>"  # REQUIRED
}
```

## Debugging Tips

1. **Check what public keys are loaded:**
   - Add a debug print in `_network_public_key_map()` to see what keys were found
   
2. **Verify node endpoint format:**
   - Endpoints must be in format: `"192.168.43.118:50404"` (IP:PORT)
   
3. **Check JSON validity:**
   - Use an online JSON validator on `mdaclient_state.json`
   - Watch for missing commas or quotes

4. **Verify public key format:**
   - Keys must start with `-----BEGIN PUBLIC KEY-----`
   - Keys must end with `-----END PUBLIC KEY-----`
   - Newlines must be preserved

## Files Involved
- `mdaclient.py` - Main client code
- `mdanetwork.py` - Network and message handling (line 525 has the error)
- `mdaclient_state.json` - Network configuration storage
- `generate_rsakey.py` - RSA key generation

## Related Error Messages
Similar errors with different formats:
- "Missing public key for receiver {route[-1]}"
- "Missing public key for hop {hop}"

All indicate missing public keys in the configuration.
