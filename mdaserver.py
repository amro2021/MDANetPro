#!/usr/bin/env python3
import argparse
import time

from mdanetwork import mda


def parse_peer(value):
    if value is None:
        return None
    host, port = value.rsplit(":", 1)
    return host, int(port)


def main():
    parser = argparse.ArgumentParser(description="MDA node server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host for the node server")
    parser.add_argument("--port", type=int, default=50404, help="Bind port for the node server")
    parser.add_argument("--peer", action="append", default=[], help="Peer endpoint host:port")
    args = parser.parse_args()

    peers = [parse_peer(peer) for peer in args.peer if peer]
    node = mda(host=args.host, port=args.port, peers=peers, node_name=f"server-{args.port}")
    node.start_server()

    print(f"MDA node started on {node.nodeid}", flush=True)
    print(f"Peers: {node.peers}", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down server")
        node.close()


if __name__ == "__main__":
    main()
