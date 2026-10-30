#!/bin/sh
# Captures the UDP datagrams that the Linux kernel sends between two
# namespaces (a and b): echoes over IPv4 and IPv6, an empty and an odd-length
# payload, a datagram without a checksum (IPv4, and IPv6 as RFC 6935
# allows), datagrams too long for the link (fragmented), and one to a closed
# port (answered with Port Unreachable).
set -eu
apt-get update -qq >/dev/null && apt-get install -y -qq tcpdump iproute2 ethtool python3 procps >/dev/null
for n in a b; do ip netns add $n; ip -n $n link set lo up; done
ip link add vetha type veth peer name vethb; ip link set vetha netns a; ip link set vethb netns b
ip -n a link set vetha address 02:00:00:00:00:0a; ip -n b link set vethb address 02:00:00:00:00:0b
for n in a b; do ip netns exec $n sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0; done
ip -n a link set vetha up; ip -n b link set vethb up
ip -n a addr add 192.0.2.1/24 dev vetha; ip -n a addr add 2001:db8::1/64 dev vetha nodad
ip -n b addr add 192.0.2.2/24 dev vethb; ip -n b addr add 2001:db8::2/64 dev vethb nodad
ip netns exec a ethtool -K vetha tx off rx off >/dev/null; ip netns exec b ethtool -K vethb tx off rx off >/dev/null
ip netns exec b sysctl -qw net.ipv4.icmp_ratelimit=0 net.ipv6.icmp.ratelimit=0
# Resolve the neighbors first, so that the capture holds only the datagrams.
ip netns exec a python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"", ("192.0.2.2", 9))'
ip netns exec a python3 -c 'import socket; socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).sendto(b"", ("2001:db8::2", 9))'
sleep 2
ip netns exec a tcpdump -i vetha -U -s 0 -w /out/udp.pcap 'udp or icmp or (ip6 and not icmp6) or icmp6[0] == 1' 2>/dev/null &
capture=$!
sleep 2
# Echo servers in b: port 7001 for IPv4, 7002 for IPv6, and 7003 for IPv6
# accepting datagrams without a checksum (UDP_NO_CHECK6_RX).
ip netns exec b python3 - <<'PY' &
import socket, threading
def serve(family, port, options):
    server = socket.socket(family, socket.SOCK_DGRAM)
    for level, name, value in options:
        server.setsockopt(level, name, value)
    server.bind(("", port))
    while True:
        data, peer = server.recvfrom(65535)
        server.sendto(data, peer)
threads = [threading.Thread(target=serve, args=arguments, daemon=True) for arguments in (
    (socket.AF_INET, 7001, []),
    (socket.AF_INET6, 7002, []),
    (socket.AF_INET6, 7003, [(socket.IPPROTO_UDP, 102, 1)]),
)]
for thread in threads:
    thread.start()
threading.Event().wait(30)
PY
server=$!
sleep 2
ip netns exec a python3 - <<'PY'
import socket, time
def send(family, address, data, options=(), port=None):
    client = socket.socket(family, socket.SOCK_DGRAM)
    for level, name, value in options:
        client.setsockopt(level, name, value)
    if port is not None:
        client.bind(("", port))
    client.sendto(data, address)
    client.settimeout(1)
    try:
        client.recvfrom(65535)
    except OSError:
        pass
    client.close()
    time.sleep(0.3)
send(socket.AF_INET, ("192.0.2.2", 7001), b"hello, udp", port=40001)
send(socket.AF_INET6, ("2001:db8::2", 7002), b"hello, udp6", port=40002)
send(socket.AF_INET, ("192.0.2.2", 7001), b"", port=40003)
send(socket.AF_INET6, ("2001:db8::2", 7002), b"", port=40004)
send(socket.AF_INET, ("192.0.2.2", 7001), b"odd", port=40005)
send(socket.AF_INET6, ("2001:db8::2", 7002), b"odd", port=40006)
# SO_NO_CHECK (11): an IPv4 datagram with no checksum (RFC 768).
send(socket.AF_INET, ("192.0.2.2", 7001), b"no checksum", [(socket.SOL_SOCKET, 11, 1)], port=40007)
# UDP_NO_CHECK6_TX (101): an IPv6 datagram with a zero checksum (RFC 6935),
# to the server that accepts it.
send(socket.AF_INET6, ("2001:db8::2", 7003), b"zero checksum", [(socket.IPPROTO_UDP, 101, 1)], port=40008)
# Longer than the link's MTU: fragmented by the sender.
send(socket.AF_INET, ("192.0.2.2", 7001), bytes(range(256)) * 12, port=40009)
send(socket.AF_INET6, ("2001:db8::2", 7002), bytes(range(256)) * 12, port=40010)
# A closed port: Port Unreachable.
send(socket.AF_INET, ("192.0.2.2", 9), b"closed", port=40011)
send(socket.AF_INET6, ("2001:db8::2", 9), b"closed", port=40012)
PY
sleep 2
kill $capture $server 2>/dev/null || true; sleep 1
tcpdump -r /out/udp.pcap -n -e -v -tttt 2>/dev/null > /out/udp.txt || true
