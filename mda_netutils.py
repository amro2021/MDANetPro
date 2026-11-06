"""Local network address helpers for MDANetPro.

Picks the IPv4 address other computers should use to reach this node, without the
user typing it. Works without extra packages; uses psutil when it is installed for
better interface names and real netmasks.
"""
import ipaddress
import socket

try:  # optional
    import psutil  # type: ignore
except Exception:  # pragma: no cover - psutil missing is a normal case
    psutil = None

# Adapters that are almost never the network the user means (WSL, Hyper-V, VMs, VPN taps).
_VIRTUAL_HINTS = ("vethernet", "virtualbox", "vmware", "hyper-v", "wsl", "docker", "loopback", "vbox", "tap", "tun", "zerotier", "tailscale")


def _is_usable(ip):
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast)


def local_ip_for(target_host, port=80):
    """Return the local IPv4 the OS would use to reach target_host (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((target_host, port))
            ip = sock.getsockname()[0]
    except OSError:
        return ""
    return ip if _is_usable(ip) else ""


def _interfaces():
    """List of (name, ip, netmask) for IPv4 interfaces that are up."""
    result = []
    if psutil is not None:
        try:
            stats = psutil.net_if_stats()
            for name, addrs in psutil.net_if_addrs().items():
                if name in stats and not stats[name].isup:
                    continue
                for addr in addrs:
                    if addr.family == socket.AF_INET and _is_usable(addr.address):
                        result.append((name, addr.address, addr.netmask or ""))
        except Exception:
            result = []
    if result:
        return result
    seen = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if _is_usable(ip) and ip not in seen:
                seen.add(ip)
                result.append(("", ip, ""))
    except OSError:
        pass
    return result


def candidate_ips():
    """All usable local IPv4 addresses, best first."""
    default_route = local_ip_for("8.8.8.8")
    scored = []
    for name, ip, _mask in _interfaces():
        lname = name.lower()
        score = 0
        if ip == default_route:
            score += 100
        if any(hint in lname for hint in _VIRTUAL_HINTS):
            score -= 50
        addr = ipaddress.IPv4Address(ip)
        if ip.startswith("192.168."):
            score += 20
        elif ip.startswith("10."):
            score += 15
        elif addr in ipaddress.IPv4Network("172.16.0.0/12"):
            score += 5  # often WSL / Hyper-V / Docker
        scored.append((score, ip))
    if default_route and default_route not in [ip for _s, ip in scored]:
        scored.append((100, default_route))
    scored.sort(key=lambda item: -item[0])
    ordered = []
    for _score, ip in scored:
        if ip not in ordered:
            ordered.append(ip)
    return ordered


def best_local_ip():
    """Best guess at the address peers should use. Falls back to 127.0.0.1."""
    ips = candidate_ips()
    return ips[0] if ips else "127.0.0.1"


def broadcast_targets():
    """(broadcast_address, source_ip) pairs for LAN discovery on every usable interface."""
    targets = []
    for _name, ip, mask in _interfaces():
        net = None
        if mask:
            try:
                net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            except ValueError:
                net = None
        if net is None:
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)  # common LAN guess
        if net.prefixlen < 31:
            targets.append((str(net.broadcast_address), ip))
        targets.append(("255.255.255.255", ip))
    if not targets:
        targets.append(("255.255.255.255", ""))
    unique = []
    for item in targets:
        if item not in unique:
            unique.append(item)
    return unique
