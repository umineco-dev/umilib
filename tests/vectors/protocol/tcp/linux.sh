#!/bin/sh
# Captures the TCP segments that the Linux kernel sends between two
# namespaces (a, the client, and b, the server): connections over IPv4 and
# IPv6 with the options of RFC 7323 and RFC 2018, data both ways and a
# graceful close; a connection refused with a reset; a bulk transfer over a
# link that loses packets (SACK and retransmissions); a zero window and its
# probes; urgent data; keep-alives; a connection without the options; and
# the negotiation of ECN (RFC 3168).
set -eu
apt-get update -qq >/dev/null && apt-get install -y -qq tcpdump iproute2 ethtool python3 procps iptables >/dev/null
for n in a b; do ip netns add $n; ip -n $n link set lo up; done
ip link add vetha type veth peer name vethb; ip link set vetha netns a; ip link set vethb netns b
ip -n a link set vetha address 02:00:00:00:00:0a; ip -n b link set vethb address 02:00:00:00:00:0b
for n in a b; do ip netns exec $n sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0; done
ip -n a link set vetha up; ip -n b link set vethb up
ip -n a addr add 192.0.2.1/24 dev vetha; ip -n a addr add 2001:db8::1/64 dev vetha nodad
ip -n b addr add 192.0.2.2/24 dev vethb; ip -n b addr add 2001:db8::2/64 dev vethb nodad
# No offloading: every segment on the wire is one the kernel built, with its checksum.
for n in a b; do ip netns exec $n ethtool -K veth$n tx off rx off tso off gso off gro off >/dev/null 2>&1 || true; done
ip netns exec b sysctl -qw net.ipv4.tcp_ecn=2
ip netns exec a sysctl -qw net.ipv4.tcp_ecn=0
ip netns exec a python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"", ("192.0.2.2", 9))'
ip netns exec a python3 -c 'import socket; socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).sendto(b"", ("2001:db8::2", 9))'
sleep 2
ip netns exec a tcpdump -i vetha -U -s 0 -w /out/tcp.pcap tcp 2>/dev/null &
capture=$!
sleep 2
# Servers in b: an echo server on 7000 (IPv4 and IPv6), a slow reader on 7001,
# a reader of urgent data on 7002 and a sink on 7003.
ip netns exec b python3 - <<'PY' &
import socket, threading, time
def serve(family, port, handle, buffer=None):
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    if buffer:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer)
    server.bind(("", port))
    server.listen(4)
    while True:
        connection, _ = server.accept()
        threading.Thread(target=handle, args=(connection,), daemon=True).start()
def echo(connection):
    while data := connection.recv(65536):
        connection.sendall(data)
    connection.close()
def slow(connection):
    time.sleep(4)
    while connection.recv(65536):
        pass
    connection.close()
def urgent(connection):
    time.sleep(0.5)
    try:
        connection.recv(1, socket.MSG_OOB)
    except OSError:
        pass
    while connection.recv(65536):
        pass
    connection.close()
def sink(connection):
    while connection.recv(65536):
        pass
    connection.close()
for arguments in ((socket.AF_INET, 7000, echo), (socket.AF_INET6, 7000, echo), (socket.AF_INET, 7001, slow, 2048),
                  (socket.AF_INET, 7002, urgent), (socket.AF_INET, 7003, sink)):
    threading.Thread(target=serve, args=arguments, daemon=True).start()
time.sleep(60)
PY
server=$!
sleep 2
ip netns exec a python3 - <<'PY'
import socket, time
def connect(family, address, port, bind):
    client = socket.socket(family, socket.SOCK_STREAM)
    client.bind((bind, port))
    client.connect(address)
    return client
# Data both ways and a graceful close, over IPv4 and IPv6.
for family, address, bind, port in ((socket.AF_INET, ("192.0.2.2", 7000), "", 40001), (socket.AF_INET6, ("2001:db8::2", 7000), "", 40002)):
    client = connect(family, address, port, bind)
    client.sendall(b"hello, tcp")
    client.recv(100)
    time.sleep(0.3)
    client.shutdown(socket.SHUT_WR)
    client.recv(100)
    client.close()
    time.sleep(0.5)
# A closed port: a reset.
try:
    connect(socket.AF_INET, ("192.0.2.2", 9), 40003, "")
except OSError:
    pass
time.sleep(0.5)
# A zero window: the server reads nothing for four seconds.
client = connect(socket.AF_INET, ("192.0.2.2", 7001), 40004, "")
client.sendall(bytes(range(256)) * 128)
client.close()
time.sleep(1)
# Urgent data (RFC 9293 §3.8.5).
client = connect(socket.AF_INET, ("192.0.2.2", 7002), 40005, "")
client.sendall(b"normal")
client.send(b"!", socket.MSG_OOB)
time.sleep(1)
client.close()
time.sleep(0.5)
# Keep-alives after one second of idleness.
client = connect(socket.AF_INET, ("192.0.2.2", 7003), 40006, "")
client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
time.sleep(3.5)
client.close()
time.sleep(0.5)
PY
# A bulk transfer whose every twelfth data segment the server drops (after the
# capture point): SACK, fast retransmit and recovery.
ip netns exec a tc qdisc add dev vetha root netem delay 5ms 2>/dev/null || echo "no netem" >&2
ip netns exec b iptables -A INPUT -p tcp --dport 7003 -m length --length 1000:1600 -m statistic --mode nth --every 12 --packet 5 -j DROP
ip netns exec a python3 - <<'PY'
import socket, time
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(("", 40007))
client.connect(("192.0.2.2", 7003))
client.sendall(bytes(range(256)) * 256)
time.sleep(2)
client.close()
time.sleep(1)
PY
ip netns exec a tc qdisc del dev vetha root 2>/dev/null || true
ip netns exec b iptables -F INPUT
# Without timestamps, SACK and window scaling, and with ECN requested.
ip netns exec a sysctl -qw net.ipv4.tcp_timestamps=0 net.ipv4.tcp_sack=0 net.ipv4.tcp_window_scaling=0
ip netns exec a python3 - <<'PY'
import socket, time
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(("", 40008))
client.connect(("192.0.2.2", 7000))
client.sendall(b"plain")
client.recv(100)
client.close()
time.sleep(0.5)
PY
ip netns exec a sysctl -qw net.ipv4.tcp_timestamps=1 net.ipv4.tcp_sack=1 net.ipv4.tcp_window_scaling=1 net.ipv4.tcp_ecn=1
ip netns exec a python3 - <<'PY'
import socket, time
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(("", 40009))
client.connect(("192.0.2.2", 7000))
client.sendall(b"ecn")
client.recv(100)
client.close()
time.sleep(0.5)
PY
sleep 1
kill $capture $server 2>/dev/null || true; sleep 1
tcpdump -r /out/tcp.pcap -n -e -v -tttt 2>/dev/null > /out/tcp.txt || true
