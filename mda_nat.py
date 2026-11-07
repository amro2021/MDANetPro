"""Automatic port opening on home routers: UPnP IGD and NAT-PMP.

Many home routers let an app ask "please forward port 50404 to me". If that works,
the node becomes directly reachable from the internet with no manual setup.
University and mobile networks normally refuse; the node then uses hole punching
or a peer relay instead. Pure standard library, no extra packages.
"""
import ipaddress
import os
import re
import socket
import struct
import subprocess
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

SSDP_ADDR = ("239.255.255.250", 1900)
WAN_SERVICES = (
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)
SEARCH_TARGETS = ("urn:schemas-upnp-org:device:InternetGatewayDevice:1", "upnp:rootdevice")


# ---------------------------------------------------------------- default gateway
def default_gateway():
    """IPv4 address of the default gateway, or ""."""
    try:  # Linux
        with open("/proc/net/route") as handle:
            for line in handle.readlines()[1:]:
                fields = line.split()
                if len(fields) > 2 and fields[1] == "00000000" and int(fields[3], 16) & 2:
                    return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    except OSError:
        pass
    commands = (["route", "print", "-4", "0.0.0.0"], ["netstat", "-rn"]) if os.name == "nt" else (["netstat", "-rn"],)
    for command in commands:
        try:
            output = subprocess.run(command, capture_output=True, text=True, timeout=5,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
        except Exception:
            continue
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] in ("0.0.0.0", "default") and parts[1] in ("0.0.0.0", "default") or (
                len(parts) >= 2 and parts[0] == "default"
            ):
                for token in parts[1:]:
                    try:
                        if ipaddress.IPv4Address(token) and token != "0.0.0.0":
                            return token
                    except ValueError:
                        continue
    return ""


# ---------------------------------------------------------------- NAT-PMP (RFC 6886)
def natpmp_map(gateway, internal_port, external_port, protocol="tcp", lifetime=3600, timeout=1.5):
    """Return (external_ip, external_port) or None."""
    if not gateway:
        return None
    opcode = 2 if protocol == "tcp" else 1
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(struct.pack("!BBHHHI", 0, opcode, 0, internal_port, external_port, lifetime), (gateway, 5351))
            data, _ = sock.recvfrom(64)
            if len(data) < 16:
                return None
            _ver, op, result, _epoch, _internal, mapped_port, _life = struct.unpack("!BBHIHHI", data[:16])
            if op != 128 + opcode or result != 0:
                return None
            sock.sendto(struct.pack("!BB", 0, 0), (gateway, 5351))
            data, _ = sock.recvfrom(64)
            if len(data) < 12 or struct.unpack("!H", data[2:4])[0] != 0:
                return None
            return socket.inet_ntoa(data[8:12]), mapped_port
    except OSError:
        return None


# ---------------------------------------------------------------- UPnP IGD
class UpnpGateway:
    def __init__(self, control_url, service_type, local_ip):
        self.control_url = control_url
        self.service_type = service_type
        self.local_ip = local_ip

    def _soap(self, action, arguments, timeout=4):
        args = "".join(f"<{key}>{value}</{key}>" for key, value in arguments)
        body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{self.service_type}">{args}</u:{action}>'
            "</s:Body></s:Envelope>"
        ).encode("utf-8")
        request = urllib.request.Request(self.control_url, data=body, method="POST", headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{self.service_type}#{action}"',
        })
        with _no_proxy_opener().open(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")

    def external_ip(self):
        text = self._soap("GetExternalIPAddress", [])
        match = re.search(r"<NewExternalIPAddress>\s*([^<\s]+)\s*</NewExternalIPAddress>", text)
        return match.group(1) if match else ""

    def add_mapping(self, external_port, internal_port, protocol="TCP", lifetime=3600, description="MDANetPro"):
        self._soap("AddPortMapping", [
            ("NewRemoteHost", ""), ("NewExternalPort", int(external_port)), ("NewProtocol", protocol.upper()),
            ("NewInternalPort", int(internal_port)), ("NewInternalClient", self.local_ip), ("NewEnabled", 1),
            ("NewPortMappingDescription", description), ("NewLeaseDuration", int(lifetime)),
        ])
        return True

    def delete_mapping(self, external_port, protocol="TCP"):
        try:
            self._soap("DeletePortMapping", [("NewRemoteHost", ""), ("NewExternalPort", int(external_port)), ("NewProtocol", protocol.upper())])
        except Exception:
            pass


def _no_proxy_opener():
    # The router is on the LAN: never send these requests through a system proxy.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def discover_upnp(local_ip="", timeout=2.0, ssdp_addr=SSDP_ADDR):
    """Find the router's UPnP WAN service. Returns UpnpGateway or None."""
    locations = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            if local_ip:
                try:
                    sock.bind((local_ip, 0))
                except OSError:
                    pass
            for target in SEARCH_TARGETS:
                message = (
                    "M-SEARCH * HTTP/1.1\r\n"
                    f"HOST: {ssdp_addr[0]}:{ssdp_addr[1]}\r\n"
                    'MAN: "ssdp:discover"\r\nMX: 1\r\n'
                    f"ST: {target}\r\n\r\n"
                ).encode("ascii")
                sock.sendto(message, ssdp_addr)
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data, _addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                match = re.search(rb"(?im)^location:\s*(\S+)", data)
                if match:
                    location = match.group(1).decode("ascii", errors="ignore")
                    if location not in locations:
                        locations.append(location)
    except OSError:
        return None
    for location in locations:
        gateway = _gateway_from_description(location, local_ip)
        if gateway:
            return gateway
    return None


def _gateway_from_description(location, local_ip):
    try:
        with _no_proxy_opener().open(location, timeout=3) as response:
            text = response.read()
        root = ET.fromstring(text)
    except Exception:
        return None
    for service in root.iter():
        if not service.tag.endswith("service"):
            continue
        fields = {child.tag.split("}")[-1]: (child.text or "").strip() for child in service}
        if fields.get("serviceType") in WAN_SERVICES and fields.get("controlURL"):
            control = urllib.parse.urljoin(location, fields["controlURL"])
            if not local_ip:
                host = urllib.parse.urlparse(location).hostname or ""
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.connect((host, 1900))
                        local_ip = sock.getsockname()[0]
                except OSError:
                    local_ip = ""
            return UpnpGateway(control, fields["serviceType"], local_ip)
    return None


# ---------------------------------------------------------------- high level
def open_port(local_ip, port, lifetime=3600, ssdp_addr=SSDP_ADDR, gateway_ip=None):
    """Try NAT-PMP, then UPnP. Returns a dict describing the mapping, or None.

    {"method", "external_ip", "tcp_port", "udp_port", "gateway"}
    """
    gateway_ip = default_gateway() if gateway_ip is None else gateway_ip
    tcp = natpmp_map(gateway_ip, port, port, "tcp", lifetime)
    if tcp:
        udp = natpmp_map(gateway_ip, port, port, "udp", lifetime)
        return {"method": "nat-pmp", "external_ip": tcp[0], "tcp_port": tcp[1], "udp_port": udp[1] if udp else 0, "gateway": gateway_ip}
    gateway = discover_upnp(local_ip, ssdp_addr=ssdp_addr)
    if gateway is None:
        return None
    try:
        gateway.add_mapping(port, port, "TCP", lifetime)
    except Exception:
        return None
    udp_port = 0
    try:
        gateway.add_mapping(port, port, "UDP", lifetime)
        udp_port = port
    except Exception:
        pass
    try:
        external_ip = gateway.external_ip()
    except Exception:
        external_ip = ""
    return {"method": "upnp", "external_ip": external_ip, "tcp_port": port, "udp_port": udp_port, "gateway": gateway}


def close_port(mapping, port):
    if not mapping:
        return
    gateway = mapping.get("gateway")
    if isinstance(gateway, UpnpGateway):
        gateway.delete_mapping(port, "TCP")
        if mapping.get("udp_port"):
            gateway.delete_mapping(port, "UDP")
    elif isinstance(gateway, str) and gateway:
        natpmp_map(gateway, port, 0, "tcp", 0)
        natpmp_map(gateway, port, 0, "udp", 0)


def is_public_ipv4(ip):
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if addr in ipaddress.IPv4Network("100.64.0.0/10"):  # carrier-grade NAT
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified)
