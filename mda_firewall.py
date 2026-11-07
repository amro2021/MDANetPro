"""Windows Firewall helper for MDANetPro.

check_firewall() reads the current rules (no admin needed).
allow_network_access() shows the normal Windows admin prompt once and adds the rules:
  - inbound TCP on the node port (default 50404)
  - inbound UDP on the node port (hole punching) and the discovery port (default 50405)
  - inbound ping (ICMPv4 echo), so connection tests give clear answers
It also removes inbound *Block* rules that Windows creates for this program when the
user clicks Cancel on the first-run firewall popup (a Block rule beats any Allow rule).
On non-Windows systems everything reports "not needed".
"""
import base64
import json
import os
import subprocess
import sys

RULE_PREFIX = "MDANetPro"


def is_supported():
    return os.name == "nt"


def program_path():
    """Path Windows Firewall sees for this app (the .exe when frozen, python.exe otherwise)."""
    return os.path.abspath(sys.executable)


def _ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def _encode(script):
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _no_window_flags():
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def build_check_script(tcp_port, udp_port, program):
    return f"""
$ErrorActionPreference = 'SilentlyContinue'
$own = @(Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' | Where-Object {{ $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }})
$tcp = $false; $udp = $false
foreach ($r in $own) {{
  $pf = $r | Get-NetFirewallPortFilter
  if ($pf.Protocol -eq 'TCP' -and ($pf.LocalPort -contains '{int(tcp_port)}')) {{ $tcp = $true }}
  if ($pf.Protocol -eq 'UDP' -and ($pf.LocalPort -contains '{int(udp_port)}') -and ($pf.LocalPort -contains '{int(tcp_port)}')) {{ $udp = $true }}
}}
$blocked = @(Get-NetFirewallApplicationFilter -Program {_ps_quote(program)} | Get-NetFirewallRule | Where-Object {{ $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' }}).Count
$profiles = @(Get-NetFirewallProfile | Where-Object {{ $_.Enabled -eq 'True' }}).Count
@{{ tcp = $tcp; udp = $udp; blocked = $blocked; firewall_on = ($profiles -gt 0) }} | ConvertTo-Json -Compress
"""


def build_allow_script(tcp_port, udp_port, program):
    return f"""
$ErrorActionPreference = 'SilentlyContinue'
Get-NetFirewallApplicationFilter -Program {_ps_quote(program)} | Get-NetFirewallRule | Where-Object {{ $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' }} | Remove-NetFirewallRule
Remove-NetFirewallRule -DisplayName '{RULE_PREFIX}*'
New-NetFirewallRule -DisplayName '{RULE_PREFIX} node (TCP {int(tcp_port)})' -Direction Inbound -Protocol TCP -LocalPort {int(tcp_port)} -Action Allow -Profile Any | Out-Null
New-NetFirewallRule -DisplayName '{RULE_PREFIX} p2p + discovery (UDP {int(tcp_port)},{int(udp_port)})' -Direction Inbound -Protocol UDP -LocalPort {int(tcp_port)},{int(udp_port)} -Action Allow -Profile Any | Out-Null
New-NetFirewallRule -DisplayName '{RULE_PREFIX} ping' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any | Out-Null
"""


def check_firewall(tcp_port=50404, udp_port=50405, program=None):
    """Return {"supported", "ok", "tcp", "udp", "blocked", "error"}."""
    if not is_supported():
        return {"supported": False, "ok": True, "tcp": True, "udp": True, "blocked": 0, "error": ""}
    script = build_check_script(tcp_port, udp_port, program or program_path())
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", _encode(script)],
            capture_output=True, text=True, timeout=40, creationflags=_no_window_flags(),
        )
        data = json.loads((proc.stdout or "").strip().splitlines()[-1])
    except Exception as exc:
        return {"supported": True, "ok": False, "tcp": False, "udp": False, "blocked": 0, "error": str(exc)}
    tcp, udp = bool(data.get("tcp")), bool(data.get("udp"))
    blocked = int(data.get("blocked") or 0)
    firewall_on = bool(data.get("firewall_on", True))
    ok = (not firewall_on) or (tcp and udp and blocked == 0)
    return {"supported": True, "ok": ok, "tcp": tcp, "udp": udp, "blocked": blocked, "error": ""}


def allow_network_access(tcp_port=50404, udp_port=50405, program=None, timeout_ms=120000):
    """Run the allow script elevated (Windows admin prompt). Returns (started, message)."""
    if not is_supported():
        return True, "Not needed on this system."
    import ctypes
    from ctypes import wintypes

    script = build_allow_script(tcp_port, udp_port, program or program_path())
    params = f"-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {_encode(script)}"

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE),
        ]

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = "powershell.exe"
    info.lpParameters = params
    info.nShow = 0
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        return False, "Permission was not granted (the Windows admin prompt was cancelled)."
    if info.hProcess:
        ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, int(timeout_ms))
        ctypes.windll.kernel32.CloseHandle(info.hProcess)
    return True, "Network access rules added."
