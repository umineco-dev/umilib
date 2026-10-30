#!/bin/sh
# Captures the ICMP and ICMPv6 messages that the Linux kernel sends between
# namespaces: a host (a), a router (r) with radvd, a second router on the
# host's link (c), and a host behind the router (b) on a link of a smaller MTU.
set -eu
apt-get update -qq >/dev/null && apt-get install -y -qq tcpdump iproute2 iputils-ping netcat-openbsd ethtool radvd python3 procps >/dev/null
for n in a r b c; do ip netns add $n; ip -n $n link set lo up; done
ip link add vetha type veth peer name vethra; ip link set vetha netns a; ip link set vethra netns r
ip link add vethb type veth peer name vethrb; ip link set vethb netns b; ip link set vethrb netns r
ip link add vethc type veth peer name vethrc; ip link set vethc netns c; ip link set vethrc netns r
ip -n a link set vetha address 02:00:00:00:01:0a; ip -n r link set vethra address 02:00:00:00:01:01
ip -n b link set vethb address 02:00:00:00:02:0b; ip -n r link set vethrb address 02:00:00:00:02:01
ip -n c link set vethc address 02:00:00:00:01:0c; ip -n r link set vethrc address 02:00:00:00:03:01
# The host's link is a bridge in r joining vethra and vethrc, so that a and c share it.
ip -n r link add lan type bridge; ip -n r link set vethra master lan; ip -n r link set vethrc master lan
ip -n r link set lan address 02:00:00:00:01:01
for i in vethra vethrc lan vethrb; do ip -n r link set $i up; done
ip -n a link set vetha up; ip -n b link set vethb up; ip -n c link set vethc up
for n in a b c r; do ip netns exec $n sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0; done
ip netns exec a sysctl -qw net.ipv6.conf.vetha.accept_dad=1
ip -n r link set vethrb mtu 1280; ip -n b link set vethb mtu 1280
ip -n r addr add 192.0.2.254/24 dev lan; ip -n r addr add 2001:db8:1::ff/64 dev lan nodad
ip -n r addr add 198.51.100.254/24 dev vethrb; ip -n r addr add 2001:db8:2::ff/64 dev vethrb nodad
# IPv4 to the far link takes a route MTU of 576 (IPv6 needs at least 1,280 on the link).
ip -n r route replace 198.51.100.0/24 dev vethrb mtu lock 576
ip -n a addr add 192.0.2.1/24 dev vetha
ip -n c addr add 192.0.2.3/24 dev vethc; ip -n c addr add 2001:db8:1::3/64 dev vethc nodad
ip -n b addr add 198.51.100.2/24 dev vethb; ip -n b addr add 2001:db8:2::2/64 dev vethb nodad
ip netns exec r sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
ip netns exec c sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
ip netns exec r sysctl -qw net.ipv4.conf.all.send_redirects=1 net.ipv4.conf.lan.send_redirects=1
ip netns exec r sysctl -qw net.ipv4.icmp_ratelimit=0 net.ipv6.icmp.ratelimit=0
ip netns exec b sysctl -qw net.ipv4.icmp_ratelimit=0 net.ipv6.icmp.ratelimit=0 net.ipv4.ipfrag_time=3 net.ipv6.ip6frag_time=3
for n in r b; do ip netns exec $n sysctl -qw net.ipv4.icmp_errors_extension_mask=1 2>/dev/null || true; done
ip -n b route add default via 198.51.100.254; ip -n b -6 route add default via 2001:db8:2::ff
ip -n c route add default via 192.0.2.254; ip -n c -6 route add default via 2001:db8:1::ff
ip -n r route add 203.0.113.0/24 via 192.0.2.3; ip -n r -6 route add 2001:db8:3::/64 via 2001:db8:1::3
ip -n c addr add 203.0.113.3/32 dev lo; ip -n c addr add 2001:db8:3::3/128 dev lo
ip netns exec a ethtool -K vetha tx off rx off >/dev/null; ip netns exec b ethtool -K vethb tx off rx off >/dev/null
ip netns exec c ethtool -K vethc tx off rx off >/dev/null
for i in vethra vethrb vethrc; do ip netns exec r ethtool -K $i tx off rx off >/dev/null; done
cat > /tmp/radvd.conf <<'CONF'
interface lan {
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 4;
    AdvLinkMTU 1500;
    AdvReachableTime 30000;
    AdvRetransTimer 1000;
    prefix 2001:db8:1::/64 { AdvOnLink on; AdvAutonomous on; };
    route 2001:db8:2::/64 { };
    RDNSS 2001:db8:1::53 { };
};
CONF
sleep 1
ip netns exec r tcpdump -i lan -U -s 0 -w /out/lan.pcap 2>/dev/null &
first=$!
ip netns exec r tcpdump -i vethrb -U -s 0 -w /out/far.pcap 2>/dev/null &
second=$!
sleep 2
ip netns exec r radvd -C /tmp/radvd.conf -n -m stderr_clean 2>/dev/null &
radvd=$!
# The host autoconfigures from the advertisement, with duplicate address detection.
ip netns exec a sysctl -qw net.ipv6.conf.vetha.accept_ra=2 net.ipv6.conf.vetha.autoconf=1
ip netns exec a sh -c 'echo 1 > /proc/sys/net/ipv6/conf/vetha/disable_ipv6; echo 0 > /proc/sys/net/ipv6/conf/vetha/disable_ipv6'
sleep 6
ip -n a route add default via 192.0.2.254 2>/dev/null || true
A6=$(ip -n a -6 addr show dev vetha scope global | awk '/inet6/ {print $2}' | cut -d/ -f1 | head -1)
echo "a: $A6" >&2
# Echoes across the router; TTL and hop limit 1 (Time Exceeded).
ip netns exec a ping -c 1 198.51.100.2 >/dev/null
ip netns exec a ping -6 -c 1 2001:db8:2::2 >/dev/null
ip netns exec a ping -c 1 -t 1 198.51.100.2 >/dev/null || true
ip netns exec a ping -6 -c 1 -t 1 2001:db8:2::2 >/dev/null || true
# Too big for the far link: Fragmentation Needed and Packet Too Big.
ip netns exec a ping -c 1 -M do -s 1000 198.51.100.2 >/dev/null || true
ip netns exec a ping -6 -c 1 -s 1400 2001:db8:2::2 >/dev/null || true
# Closed ports: Port Unreachable.
echo x | ip netns exec a nc -u -w 1 198.51.100.2 9 || true
echo x | ip netns exec a nc -6 -u -w 1 2001:db8:2::2 9 || true
# Another router on the link: Redirect.
ip netns exec a ping -c 2 203.0.113.3 >/dev/null || true
ip netns exec a ping -6 -c 2 2001:db8:3::3 >/dev/null || true
# Crafted packets: an unknown protocol, an unknown next header, an unknown
# option that asks for an error, and a first fragment alone (Reassembly Time Exceeded).
ip netns exec a python3 - "$A6" <<'PY'
import socket, struct, sys, time
def checksum(data):
    if len(data) % 2: data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16: total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF
def ipv4(protocol, payload, fragment=0, identification=0x4242):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), identification, fragment, 64, protocol, 0,
                         socket.inet_aton("192.0.2.1"), socket.inet_aton("198.51.100.2"))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
raw.sendto(ipv4(253, b"unknown protocol"), ("198.51.100.2", 0))
echo = struct.pack("!BBHHH", 8, 0, 0, 0x77, 1) + bytes(range(64))
echo = echo[:2] + struct.pack("!H", checksum(echo)) + echo[4:]
raw.sendto(ipv4(1, echo[:40], fragment=0x2000), ("198.51.100.2", 0))
source = sys.argv[1]
six = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 253)
six.sendto(b"unknown next header", ("2001:db8:2::2", 0))
options = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 59)
# A Destination Options header with option type 0x8b (action 10: discard and send an error).
options.setsockopt(socket.IPPROTO_IPV6, 59, bytes([59, 0, 0x8B, 2, 0, 0, 1, 0]))
options.sendto(b"", ("2001:db8:2::2", 0))
try:
    whole = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
    payload = struct.pack("!BBBBI", 58, 0, 0, 1, 0x4243) + struct.pack("!BBHHH", 128, 0, 0, 0x78, 1) + bytes(32)
    header = struct.pack("!IHBB16s16s", 6 << 28, len(payload), 44, 64,
                         socket.inet_pton(socket.AF_INET6, source), socket.inet_pton(socket.AF_INET6, "2001:db8:2::2"))
    whole.sendto(header + payload, ("2001:db8:2::2", 0))
except OSError as error:
    print("no IPv6 first fragment:", error, file=sys.stderr)
time.sleep(5)
PY
sleep 4
kill $radvd $first $second; sleep 1
tcpdump -r /out/lan.pcap -n -e -v -tttt 2>/dev/null > /out/lan.txt || true
tcpdump -r /out/far.pcap -n -e -v -tttt 2>/dev/null > /out/far.txt || true
