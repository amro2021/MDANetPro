"""Fake UPnP Internet Gateway Device for the netsim router namespace.

Answers SSDP M-SEARCH on the LAN, serves a device description, and implements
AddPortMapping / DeletePortMapping / GetExternalIPAddress by adding real iptables
DNAT rules, so mapped ports really become reachable from the simulated internet.
"""
import re
import socket
import struct
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAN_IP, WAN_IP, HTTP_PORT = sys.argv[1], sys.argv[2], 5000
SERVICE = "urn:schemas-upnp-org:service:WANIPConnection:1"
DESC = f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
<serviceList><service><serviceType>{SERVICE}</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
<controlURL>/ctl/IPConn</controlURL><SCPDURL>/scpd.xml</SCPDURL></service></serviceList>
</device></deviceList></device></deviceList></device></root>"""
mappings = []


def field(body, name):
    match = re.search(rf"<{name}>([^<]*)</{name}>", body)
    return match.group(1) if match else ""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = DESC.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        action = self.headers.get("SOAPAction", "").strip('"').split("#")[-1]
        result = ""
        if action == "AddPortMapping":
            proto = field(body, "NewProtocol").lower()
            ext, inport, client = field(body, "NewExternalPort"), field(body, "NewInternalPort"), field(body, "NewInternalClient")
            subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", "wan", "-p", proto, "--dport", ext,
                            "-j", "DNAT", "--to-destination", f"{client}:{inport}"], check=True)
            mappings.append((proto, ext, client, inport))
            print(f"IGD: mapped {proto} {WAN_IP}:{ext} -> {client}:{inport}", flush=True)
        elif action == "GetExternalIPAddress":
            result = f"<NewExternalIPAddress>{WAN_IP}</NewExternalIPAddress>"
        elif action == "DeletePortMapping":
            pass
        out = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
               f'<u:{action}Response xmlns:u="{SERVICE}">{result}</u:{action}Response></s:Body></s:Envelope>').encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def ssdp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 1900))
    mreq = struct.pack("4s4s", socket.inet_aton("239.255.255.250"), socket.inet_aton(LAN_IP))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    while True:
        data, addr = sock.recvfrom(4096)
        if b"M-SEARCH" in data:
            reply = (f"HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                     f"LOCATION: http://{LAN_IP}:{HTTP_PORT}/desc.xml\r\nUSN: uuid:fake-igd\r\n\r\n").encode()
            sock.sendto(reply, addr)


threading.Thread(target=ssdp, daemon=True).start()
print("IGD ready", flush=True)
ThreadingHTTPServer((LAN_IP, HTTP_PORT), Handler).serve_forever()
