# MDANetPro

MDANetPro is a lightweight peer-to-peer networking/chat prototype built in Python.

## Install

### Prerequisites
- Python 3.8+ (recommended: Python 3.10 or newer)
- `tkinter` support (required for GUI mode of `mdaclient.py`)
- `pycryptodome` (required for RSA/AES onion encryption and local encrypted storage)

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/amro2021/MDANetPro.git
   cd MDANetPro
   ```
2. (Optional) Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   ```
   - Windows PowerShell:
     ```powershell
     .\.venv\Scripts\Activate.ps1
     ```
3. Install dependencies:
   ```bash
   pip install pycryptodome peewee psutil   # psutil is optional
   ```

## Quick start (no technical setup)

1. Open **MDANetClient**. A 3-step **Setup Wizard** appears on first run:
   1. Type your name (what others will see).
   2. Click **Allow network access** and answer *Yes* on the Windows prompt (once per computer).
      The installer does this for you, so installed copies skip this step.
   3. **Create my network**, or **Join a network nearby**.
2. To join, open **Networks Nearby**, select the network, and click **Join**. The owner gets an approval popup;
   once approved, you get a "You joined" message and the members appear in your contacts.
3. If something doesn't work, click **Test Connection**. It checks both directions with every member and says,
   in plain words, what to fix (firewall, wrong address, other computer off). It also offers a one-click fix.

What happens automatically:
- **Address:** the node listens on all network adapters and picks the right IP itself (Node > Node Settings,
  Address = `auto`). If you move from Wi-Fi to a cable, it notices and tells your networks the new address
  (signed with your key), so nobody has to re-export a `.mdar`.
- **Identity:** nodes are recognised by their public key, so a node that changes IP is updated, not duplicated,
  and two people can use the same name.
- **Discovery:** seed/trusted nodes announce their networks on the local network (UDP 50405). You can turn this
  off per network ("Show in 'Networks Nearby'" when creating a network).

Not on the same Wi-Fi, or discovery blocked? Use **Network > Join by Address** (type the owner's IP) or a `.mdar` invite file.

### Ports
| Port | Protocol | Use |
|---|---|---|
| 50404 | TCP | node connections (messages, joins, connection test) |
| 50404 | UDP | hole punching between members on different networks |
| 50405 | UDP | Networks Nearby announcements |

### Building the Windows installer
1. `pip install pyinstaller pycryptodome peewee psutil` (`psutil` is optional; it improves adapter detection)
2. `pyinstaller MDANetClient.spec` builds `dist\MDANetClient.exe`
3. Compile `installer\MDANetPro.iss` with [Inno Setup](https://jrsoftware.org/isinfo.php) to get `installer\Output\MDANetPro-Setup.exe`.
   The installer adds the firewall rules. App data is stored in `%LOCALAPPDATA%\MDANetPro`. A copy that already has
   data next to it keeps using that folder.

### Tests
`python tests/e2e_easy_setup.py` and `python tests/e2e_failure_paths.py` run real nodes on this computer
(close MDANetPro first; they use ports 50404–50434).

## Connecting across different networks (internet, peer-to-peer)

Members don't have to be on the same Wi-Fi. There is no central server: nodes talk directly, and
other members help only when a direct path is impossible.

**Addresses.** Each node's address is derived from its key, e.g. `3f9a0c2e5b7d11aa8c42.mda:50404`, so it
stays the same when the IP changes and can't be impersonated. Each node publishes a *signed route record*
with every way to reach it right now. Records travel with join requests, member lists, `.mdar` files and
updates.

**How a connection is made**, tried in this order:
1. **Same network**: the LAN address, when both are behind the same router.
2. **IPv6**: direct, when both sides have a global IPv6 address.
3. **Public port**: opened automatically on the home router with **UPnP / NAT-PMP**, or a manual
   port-forward (Node > Node Settings > *Public address*).
4. **UDP hole punching**: both sides learn their public address from STUN servers and "punch" through
   their NATs at the same time (introduced by a member they're both connected to).
5. **Relay through a member**: a node behind NAT keeps a connection open to one or two reachable members
   (seed/trusted first). Only members and pending joiners may use a relay. Messages stay end-to-end
   encrypted (onion layers), so the relay can't read them.

**What's needed:** at least one member who is reachable from the internet, usually the network owner,
with a router that allows UPnP or has a port-forward for TCP+UDP 50404. Others can then join from anywhere
with **Join by Address** (type the owner's public IP) or a `.mdar` file. The status bar and **Test Connection**
show how each member is reached ("direct (internet)", "direct (UDP hole punch)", "via relay …").

Mobile data and many university networks use symmetric/carrier NAT: hole punching won't work there, and
those members are reached through a relay automatically.

STUN servers default to public ones (Google, Cloudflare). Set `MDANET_STUN_SERVERS=host:port,host:port`
to use your own (`python -c "import mda_stun,time; mda_stun.StunServer(); time.sleep(1e9)"` runs one).

Tests: `tests/test_p2p_units.py`, and the simulated-internet tests in `tests/netsim/` (Linux, root).

## Android app

`android/` contains a native Kotlin app with the same features as the PC app, and it talks to the PC app
directly: same protocol, same encryption, same `.mdar` invites.

- **Chats**: contacts grouped by network, unread badges, notifications for new messages.
- **Networks**: create a network (you become the seed), join **nearby** (same Wi-Fi), **by address**
  (the owner's public or local IP), or with an **invite file** (`.mdar`); share/save invites; members; delete.
- **Approvals**: when someone asks to join your network, a banner and a notification let you approve or reject.
- **Status**: internet connectivity (direct, UPnP, IPv6, behind NAT via relay), **Test connection**, settings
  (name, UPnP, port-forward address, cover traffic), log.
- Runs as a foreground service, so you keep receiving messages in the background. It follows Wi-Fi ↔ mobile data
  switches automatically. On mobile data the phone is reached through a relay (a reachable member).

**Get the APK:** every push builds it in GitHub Actions (*Actions → Android APK → Artifacts → MDANetPro-android*).
Install it on the phone and allow "install unknown apps" for your browser or file manager.

**Build it yourself:** Android Studio → *Open* the `android/` folder → Run. Or `gradle -p android :app:assembleDebug`.

Structure:
- `android/core`: pure Kotlin protocol implementation (JSON compatible with Python's canonical form, crypto,
  P2P transport, onion messaging, discovery, and the `Engine` with all network logic). It runs on the JVM, so it's unit-tested.
- `android/app`: Compose UI, foreground service, notifications.
- `android/cli`: headless node used by CI.

CI (`.github/workflows/android.yml`) checks compatibility with the Python app on every push:
1. Kotlin unit tests against fixtures generated by Python (canonical JSON, a Python-signed record, a Python onion layer).
2. A Kotlin node joins the Python app; then the Python app joins a Kotlin seed (signed approvals, encrypted chat both ways).
3. The Android app runs in an emulator (behind the emulator's NAT), joins a Python PC network **through a relay**,
   chats, and runs Test connection. Screenshots are uploaded as artifacts.

## How to Use

### 1) Start a node server
Run a server node that can accept peer connections:

```bash
python mdaserver.py --host 0.0.0.0 --port 50404
```

Add one or more known peers when starting:

```bash
python mdaserver.py --port 50404 --peer 192.168.1.20:50404 --peer 192.168.1.30:50404
```

### 2) Run the client (GUI mode)
Launch the GUI client:

```bash
python mdaclient.py
```

The client starts your node internally (no separate server terminal window required).

In the GUI you can access everything from menu lists:
- **Contacts**: add/edit/delete/list contacts (nickname + MDA network + endpoint + circuit label)
- **Network**: create, edit rules, join, delete, import/export `.mdar`, and list your networks
- **Node**: start/stop node, configure node name/description/host/port
- **About**: help and about dialogs
- Settings dialogs are single-window forms (not step-by-step wizards)
- Joining a network uses a `.mdar` file and sends a join request to available seed/trusted nodes
- Trusted/seed nodes can approve join requests and push synchronized node-list updates to network members

Also available in the main view:
- Open a dedicated chat window per contact (double-click contact or use **Open Chat**)
- Ping contacts
- Send broadcast messages to contacts in the active network
- Send direct messages from each chat window
- Contacts must be in the active network to be contacted
- Active-network switching updates runtime peers without restarting the node
- Chat messages carry the network identity; messages from other networks are logged until you switch to that network
- Message model:
  - **Real**: sent over onion routing when users chat
  - **Fake**: onion-routed cover traffic (manual trigger from Node menu)
  - **Control**: direct node-to-node for join/sync services
- Onion layers use per-hop hybrid cryptography (RSA + AES-GCM) with node public keys from network membership data
- Each client stores local message/network history in an encrypted SQLite database (`mda_client_local.db`)
- Traffic scheduler runs fixed slots: if queued real messages exist, a slot carries real traffic; otherwise it carries fake traffic
- Real and fake traffic use the same onion routing path, same encrypted packet structure, and fixed-size padded payload body
- Use **About -> Message History** to inspect local encrypted message records
- Use **Node -> Traffic Settings** to tune slot interval, relay hops, payload size, and cover-traffic enable/disable
- Onion transport includes circuit lifecycle (reused circuit IDs with expiry/max-use limits) and replay protection via per-message nonces/counters
- Node-list updates use signed control votes (trusted/seed roles) with configurable minimum approvals before applying synchronized updates
- Local encrypted DB stores message metadata inside encrypted payloads; indexed columns keep only hashed identifiers

### 3) Run the client in terminal mode

```bash
python mdaclient.py --cli --host 0.0.0.0 --port 50405 --peer 127.0.0.1:50404
```

Send a one-time message:

```bash
python mdaclient.py --message "Hello network" --peer 127.0.0.1:50404
```

## Experiment observer / collector (optional, separate from client UI)

This project also includes a dedicated collector service for lab experiments and publishable results. It is intentionally not integrated into the GUI; all sharing is voluntary and controlled by a separate process.

### Start the collector

```bash
python observer_collector.py --host 0.0.0.0 --port 9090 --data-dir experiment_data
```

The service exposes:
- `GET /health` — collector health
- `GET /runs` — list registered experiment runs
- `POST /api/v1/run` — register an experiment and create a run manifest
- `POST /api/v1/batch` — accept a JSON batch of events from a node
- `POST /api/v1/export` — prepare a GitHub-ready export for a run

### Upload experiment data from a lab node

```bash
python observer_client_uploader.py --collector-url http://127.0.0.1:9090 --experiment-id lab-net-01 --node-id node-01 --name demo-run --notes "first lab run"
```

The uploader sends a small sample batch to the collector and creates a run manifest. In real lab use, your custom traffic or security tools can send their structured event records to the same endpoint.

### Rich experiment manifest schema

The project includes a richer experiment manifest defined in `experiment_manifest.py`. This is used when registering a run with the collector and is designed for reproducible, publication-oriented experiments. A typical run manifest contains:

- `experiment_id`, `run_id`, `experiment_name`
- `study_type` (`performance`, `security`, `usability`, etc.)
- `environment` details (platform, Python version, machines, lab name)
- `network` configuration (network id, topology, seed/trusted nodes, join rules)
- `traffic` configuration (slot interval, relay count, fake rate, packet size, cover traffic)
- `workload` configuration (duration, sender/receiver pairing, failure model, security tests)
- `logging` configuration (collector URL, batching interval, anonymization level, shared/opt-in policy)
- `controls` (config hash, run hash, random seed)

Example registration call:

```python
from experiment_manifest import ExperimentManifest
manifest = ExperimentManifest.build(
    experiment_id="lab-net-01",
    experiment_name="steady-state performance test",
    run_id="run-001",
    network_id="mda-demo",
    node_count=6,
    notes="Measure latency and cover-traffic behavior.",
    collector_url="http://127.0.0.1:9090",
    duration_sec=600,
    slot_interval_sec=2,
    message_size_bytes=768,
    real_to_fake_ratio=1.0,
    relay_count=2,
)
```

This is also used by the uploader script to generate a stronger manifest before `POST /api/v1/run`.

### GitHub preparation

To prepare a run for GitHub publication after the collector has received data:

```bash
python -c "import json,urllib.request; print(json.loads(urllib.request.urlopen('http://127.0.0.1:9090/api/v1/export', data=json.dumps({'run_id':'<RUN_ID>'}).encode(), timeout=10).read().decode()))"
```

This writes a folder under `experiment_data/github_export/<RUN_ID>/` containing:
- `manifest.json`
- `event_summary.csv`
- `README.md`

The resulting files are ready for a repository export / GitHub Pages commit after any required sanitization.

## Notes
- Default network port is `50404`.
- If running multiple local nodes, assign a different port to each node.
- Make sure firewalls allow inbound/outbound traffic on the selected ports.
- The collector runs separately from the client portal and can be used for controlled, consent-based experiment logging.
