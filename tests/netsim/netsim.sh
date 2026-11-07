#!/bin/bash
# Simulated internet with NAT routers, built from Linux network namespaces.
#   inet : "internet" bridge 31.0.0.0/24, STUN servers at 31.0.0.100 / .101
#   A    : home with UPnP router   (rA wan 31.0.0.10, LAN 192.168.1.0/24, host hA 192.168.1.10)
#   B    : home, normal NAT         (rB wan 31.0.0.20, LAN 192.168.1.0/24, host hB 192.168.1.10)
#   E    : home, normal NAT         (rE wan 31.0.0.40, LAN 192.168.1.0/24, host hE 192.168.1.10)
#   C    : mobile, symmetric NAT    (rC wan 31.0.0.30, LAN 10.0.0.0/24,    host hC 10.0.0.10)
set -e
down() {
  for ns in inet rA hA rB hB rC hC rE hE; do ip netns del $ns 2>/dev/null || true; done
}
if [ "$1" = "down" ]; then down; exit 0; fi
down
ip netns add inet
ip netns exec inet ip link set lo up
ip netns exec inet ip link add br0 type bridge
ip netns exec inet ip link set br0 up
ip netns exec inet ip addr add 31.0.0.100/24 dev br0
ip netns exec inet ip addr add 31.0.0.101/24 dev br0

home() {  # name wanip lanprefix hostip natmode
  local n=$1 wan=$2 lan=$3 hostip=$4 mode=$5
  ip netns add r$n; ip netns add h$n
  ip netns exec r$n ip link set lo up; ip netns exec h$n ip link set lo up
  ip link add w$n type veth peer name wi$n
  ip link set w$n netns r$n; ip link set wi$n netns inet
  ip netns exec inet ip link set wi$n master br0; ip netns exec inet ip link set wi$n up
  ip netns exec r$n ip link set w$n name wan; ip netns exec r$n ip link set wan up
  ip netns exec r$n ip addr add $wan/24 dev wan
  ip link add l$n type veth peer name hl$n
  ip link set l$n netns r$n; ip link set hl$n netns h$n
  ip netns exec r$n ip link set l$n name lan; ip netns exec r$n ip link set lan up
  ip netns exec r$n ip addr add $lan.1/24 dev lan
  ip netns exec h$n ip link set hl$n name eth0; ip netns exec h$n ip link set eth0 up
  ip netns exec h$n ip addr add $hostip/24 dev eth0
  ip netns exec h$n ip route add default via $lan.1
  ip netns exec h$n ip link set eth0 multicast on
  ip netns exec h$n ip route add 239.0.0.0/8 dev eth0 2>/dev/null || true
  ip netns exec r$n sysctl -qw net.ipv4.ip_forward=1
  if [ "$mode" = "symmetric" ]; then
    ip netns exec r$n iptables -t nat -A POSTROUTING -o wan -j MASQUERADE --random-fully
  else
    ip netns exec r$n iptables -t nat -A POSTROUTING -o wan -j MASQUERADE
  fi
  # A home router does not let the internet in unless a mapping exists.
  ip netns exec r$n iptables -A FORWARD -i lan -o wan -j ACCEPT
  ip netns exec r$n iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip netns exec r$n iptables -A FORWARD -m conntrack --ctstate DNAT -j ACCEPT
  ip netns exec r$n iptables -P FORWARD DROP
}
home A 31.0.0.10 192.168.1 192.168.1.10 cone
home B 31.0.0.20 192.168.1 192.168.1.10 cone
home E 31.0.0.40 192.168.1 192.168.1.10 cone
home C 31.0.0.30 10.0.0 10.0.0.10 symmetric
echo "netsim up"
