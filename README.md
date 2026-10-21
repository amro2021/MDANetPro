# MDANetPro

MDANetPro is a lightweight peer-to-peer networking/chat prototype built in Python.

## Install

### Prerequisites
- Python 3.8+ (recommended: Python 3.10 or newer)
- `tkinter` support (required for GUI mode of `mdaclient.py`)

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
3. No external packages are required for the core scripts in this repository.

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

In the GUI you can:
- Start/stop your node
- Add/remove peers
- Ping peers
- Send chat messages
- Import/export `.mdar` network profiles

### 3) Run the client in terminal mode

```bash
python mdaclient.py --cli --host 0.0.0.0 --port 50405 --peer 127.0.0.1:50404
```

Send a one-time message:

```bash
python mdaclient.py --message "Hello network" --peer 127.0.0.1:50404
```

## Notes
- Default network port is `50404`.
- If running multiple local nodes, assign a different port to each node.
- Make sure firewalls allow inbound/outbound traffic on the selected ports.
