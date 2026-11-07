"""Headless MDANetPro gateway node, for a server.

Runs a reachable node that (1) relays for members behind NAT and (2) lets the web app connect
over WebSocket. Put a TLS reverse proxy in front of the WebSocket port for wss://, e.g. Caddy:

    gateway.example.org {
        reverse_proxy localhost:50406
    }

Usage:
    python mda_gateway.py [--port 50404] [--ws-host 127.0.0.1] [--ws-port 50406] [--public HOST[:PORT]]

Open TCP+UDP 50404 on the server's firewall. The web app then connects to wss://gateway.example.org
"""
import argparse
import signal
import sys
import time

import mda_webgateway
from mdanetwork import mda


def main():
    parser = argparse.ArgumentParser(description="MDANetPro gateway node")
    parser.add_argument("--port", type=int, default=50404, help="node port (TCP+UDP)")
    parser.add_argument("--ws-host", default="127.0.0.1", help="WebSocket bind address (127.0.0.1 behind a TLS proxy)")
    parser.add_argument("--ws-port", type=int, default=mda_webgateway.WS_PORT)
    parser.add_argument("--public", default="", help="public address if the server has a port-forward/NAT")
    parser.add_argument("--no-upnp", action="store_true")
    args = parser.parse_args()

    node = mda(port=args.port, node_name="gateway")
    node.transport.manual_public = args.public
    node.start_server()
    node.transport.discover_nat(use_upnp=not args.no_upnp)
    gateway = mda_webgateway.WebGateway(node, host=args.ws_host, port=args.ws_port, log=lambda t: print(t, flush=True)).start()
    print(f"Gateway node {node.nodeid}", flush=True)
    print(f"Internet: {node.transport.connectivity_summary()}", flush=True)
    print(f"WebSocket: ws://{args.ws_host}:{args.ws_port}", flush=True)

    def shutdown(*_args):
        gateway.stop()
        node.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    last_check = time.time()
    while True:
        time.sleep(5)
        if time.time() - last_check > 600:  # renew router mapping / public address
            node.transport.discover_nat(use_upnp=not args.no_upnp)
            last_check = time.time()


if __name__ == "__main__":
    main()
