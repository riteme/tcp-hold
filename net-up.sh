#!/bin/bash

WLAN=wlp59s0

set -e

ip link add name br0 type bridge
ip link set br0 up
ip addr add 192.168.100.100/24 dev br0

ip link add outer0 type veth peer name inner0
ip link set outer0 up
ip link set outer0 master br0

ip netns add ns0
ip link set inner0 netns ns0
ip netns exec ns0 ip link set lo up
ip netns exec ns0 ip link set inner0 up
ip netns exec ns0 ip addr add 192.168.100.101/24 dev inner0
ip netns exec ns0 ip route add default via 192.168.100.100

sysctl net.ipv4.ip_forward=1
iptables -A FORWARD -i br0 -o $WLAN -j ACCEPT
iptables -t nat -A POSTROUTING -o $WLAN -j MASQUERADE
iptables -A FORWARD -i $WLAN -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT
