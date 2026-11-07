# Simulated internet tests (Linux, root)

These build a small "internet" out of Linux network namespaces with real NAT routers
(iptables), two STUN servers and a fake UPnP router, then run MDANetPro nodes in it:

| Home | Router | LAN | Notes |
|---|---|---|---|
| A | 31.0.0.10 | 192.168.1.10 | router supports UPnP (adds real port forwards) |
| B | 31.0.0.20 | 192.168.1.10 | normal home NAT, same LAN IP as A and E |
| E | 31.0.0.40 | 192.168.1.10 | normal home NAT |
| C | 31.0.0.30 | 10.0.0.10 | symmetric NAT (like mobile data) |

- `sudo bash run_transport_test.sh`: 4 nodes message each other; prints the route used
  (direct internet, UDP hole punch, relay).
- `sudo bash run_gui_test.sh`: 3 real app windows (needs Xvfb, python3-tk): the seed creates a
  network, one member joins by typing the seed's public IP, another with a .mdar file;
  they chat across NATs and run Test Connection.

Requires: `iproute2`, `iptables`, `Xvfb` (GUI test), `pycryptodome`, `peewee`.
