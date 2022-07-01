#!/bin/bash

WLAN=wlp59s0

iptables -D FORWARD -i br0 -o $WLAN -j ACCEPT
iptables -t nat -D POSTROUTING -o $WLAN -j MASQUERADE
iptables -D FORWARD -i $WLAN -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT

ip link del outer0
ip link del br0
ip netns del ns0
