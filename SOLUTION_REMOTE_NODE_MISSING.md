# Solution: Add the Remote Node to Your Network

The error "Missing receiver public key for 192.168.43.118:50404" occurs because that remote computer is not properly registered in your network.

## The Issue

Your network configuration only has:
```json
"networks": {
  "gb": {
    "nodes": {
      "my": { 
        "endpoint": "10.51.11.234:50404",
        "pubkey": "...",
        "role": "member"
      }
    }
  }
}
```

But you're trying to send a message to: `192.168.43.118:50404` ❌ (not in the network)

## The Fix (Choose One)

### Option 1: Exchange .mdar Files (RECOMMENDED)

This is the proper way to add all nodes with their public keys:

**On Computer 2 (192.168.43.118):**
1. Open MDAClient.exe on the second computer
2. Export the network as .mdar:
   - Right-click the network → Export
   - Or: File → Export Network Profile
   - Save as something like `gb.mdar`

**On Computer 1 (10.51.11.234):**
1. Open MDAClient.exe
2. Delete the current network (File → Delete Network)
3. Join the network using .mdar (File → Join Network)
4. Select the `gb.mdar` file from Computer 2
5. Complete the join dialog

This automatically adds Computer 2's node with its public key.

---

### Option 2: Manually Add the Remote Node

If Option 1 doesn't work, manually edit `mdaclient_state.json`:

**Step 1:** Get the remote node's public key
- On Computer 2, find `id_rsa.pub` file (usually in the same folder as MDANetPro)
- Or run: `python generate_rsakey.py` if the file doesn't exist
- Copy the entire contents

**Step 2:** Edit mdaclient_state.json on Computer 1
- CLOSE MDAClient.exe first!
- Open `mdaclient_state.json`
- Find the network "gb"
- Add the remote node in the "nodes" section:

```json
"gb": {
  "nodes": {
    "my": {
      "endpoint": "10.51.11.234:50404",
      "nickname": "my",
      "pubkey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
      "role": "member"
    },
    "remote_node": {
      "endpoint": "192.168.43.118:50404",
      "nickname": "Computer2",
      "pubkey": "-----BEGIN PUBLIC KEY-----\n[PASTE COMPUTER 2's PUBLIC KEY HERE]\n-----END PUBLIC KEY-----",
      "role": "member"
    }
  }
}
```

**Important:**
- Replace `[PASTE COMPUTER 2's PUBLIC KEY HERE]` with the actual public key from Computer 2
- Keep the newlines (`\n`) in the public key
- Make sure JSON syntax is valid (commas, quotes, etc.)

**Step 3:** Save and restart
- Save the file
- Reopen MDAClient.exe
- Try sending a message again

---

### Option 3: Check Both Computers Are in the Same Network

Make sure both computers:
1. Created/joined the same network (e.g., "gb")
2. Run MDAClient with matching network configuration
3. Have generated RSA keys

---

## Verify the Fix Works

1. Run the debug script:
   ```
   python debug_public_keys.py
   ```
   Should show both nodes with ✅ markers

2. Try sending a message in MDAClient
   Should NOT show the "Missing receiver public key" error

---

## Still Having Issues?

Run this debug command:
```python
import json

with open('mdaclient_state.json', 'r') as f:
    state = json.load(f)

# Check "gb" network nodes
nodes = state['networks']['gb']['nodes']
for name, node in nodes.items():
    endpoint = node.get('endpoint')
    pubkey = node.get('pubkey')
    print(f"{name}: {endpoint} -> {'HAS KEY' if pubkey else 'MISSING KEY'}")
```

Output should show both computers with HAS KEY.
