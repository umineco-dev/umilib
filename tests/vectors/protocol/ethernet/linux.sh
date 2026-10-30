#!/bin/sh
# Captures packets that the Linux kernel generates between two network
# namespaces joined by a veth pair: ARP, NDP, fragmented ICMP echoes,
# IPv4 options, VLAN and QinQ tags, UDP and TCP.
set -eu
apt-get update -qq >/dev/null && apt-get install -y -qq tcpdump iproute2 iputils-ping netcat-openbsd ethtool >/dev/null
ip netns add a; ip netns add b
ip link add va type veth peer name vb
ip link set va netns a; ip link set vb netns b
for n in a b; do ip -n $n link set lo up; done
ip -n a link set va address 02:00:00:00:00:0a; ip -n b link set vb address 02:00:00:00:00:0b
ip -n a addr add 192.0.2.1/24 dev va; ip -n b addr add 192.0.2.2/24 dev vb
ip -n a addr add 2001:db8::1/64 dev va nodad; ip -n b addr add 2001:db8::2/64 dev vb nodad
ip -n a link set va up; ip -n b link set vb up
ip -n a link set va mtu 1500; ip -n b link set vb mtu 1500
# 802.1Q (VLAN 100) and 802.1ad (service VLAN 200 over customer VLAN 300).
ip -n a link add link va name va.100 type vlan id 100; ip -n b link add link vb name vb.100 type vlan id 100
ip -n a addr add 198.51.100.1/24 dev va.100; ip -n b addr add 198.51.100.2/24 dev vb.100
ip -n a link add link va name va.200 type vlan proto 802.1ad id 200; ip -n b link add link vb name vb.200 type vlan proto 802.1ad id 200
ip -n a link add link va.200 name va.300 type vlan id 300; ip -n b link add link vb.200 name vb.300 type vlan id 300
ip -n a addr add 203.0.113.1/24 dev va.300; ip -n b addr add 203.0.113.2/24 dev vb.300
for i in va.100 va.200 va.300; do ip -n a link set $i up; done
for i in vb.100 vb.200 vb.300; do ip -n b link set $i up; done
ip netns exec a ethtool -K va tx off rx off
ip netns exec b ethtool -K vb tx off rx off
sleep 2
ip netns exec b tcpdump -i vb -U -s 0 -w /out/capture.pcap 2>/dev/null &
dump=$!
sleep 2
ip netns exec a ping -c 1 -s 3000 192.0.2.2 >/dev/null
ip netns exec a ping -c 1 -R 192.0.2.2 >/dev/null
ip netns exec a ping -6 -c 1 -s 3000 2001:db8::2 >/dev/null
ip netns exec a ping -c 1 198.51.100.2 >/dev/null
ip netns exec a ping -c 1 203.0.113.2 >/dev/null
ip netns exec b sh -c 'nc -u -l -W 1 7001 >/dev/null' & sleep 1
echo udp | ip netns exec a nc -u -w 1 192.0.2.2 7001 || true
ip netns exec b sh -c 'nc -6 -u -l -W 1 7001 >/dev/null' & sleep 1
echo udp6 | ip netns exec a nc -6 -u -w 1 2001:db8::2 7001 || true
ip netns exec b sh -c 'nc -l 7000 >/dev/null' & sleep 1
echo tcp | ip netns exec a nc -N -w 2 192.0.2.2 7000 || true
ip netns exec b sh -c 'nc -6 -l 7000 >/dev/null' & sleep 1
echo tcp6 | ip netns exec a nc -6 -N -w 2 2001:db8::2 7000 || true
sleep 2
kill $dump; sleep 1
tcpdump -r /out/capture.pcap -n -e -v -tttt 2>/dev/null > /out/capture.txt || true
