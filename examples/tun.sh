#!/bin/sh
# Runs examples/tun.rs against the Linux kernel: pings over IPv4 and IPv6,
# UDP echoes, TCP echoes of 1 MiB (one connection, then eight at once, then
# over a link that loses and reorders packets), a refused connection, and a
# connection the example opens to an echo server of the kernel.
#
#   docker run --rm --cap-add NET_ADMIN --device /dev/net/tun -v "$PWD":/work -w /work \
#       -e CARGO_TARGET_DIR=/work/target/docker-linux rust:1-bookworm sh examples/tun.sh
#
# Each check prints "ok" or "FAILED"; the script exits with 1 if any failed.
set -eu
apt-get update -qq >/dev/null && apt-get install -y -qq iproute2 iputils-ping python3 >/dev/null
cargo build -q --release --example tun --features platform-linux,protocol-icmp,protocol-udp,protocol-tcp
tun="$CARGO_TARGET_DIR/release/examples/tun"
failed=0
check() {
    if "$@"; then echo "ok: $*"; else echo "FAILED: $*"; failed=1; fi
}

"$tun" umi0 10.7.0.2 fd00:7::2 &
host=$!
sleep 1
ip link set umi0 up mtu 1500
ip address add 10.7.0.1/24 dev umi0
ip address add fd00:7::1/64 dev umi0 nodad
sleep 1

check ping -q -c 3 -i 0.2 -W 2 10.7.0.2
check ping -q -c 3 -i 0.2 -W 2 fd00:7::2
check ping -q -c 2 -s 1472 -M do -W 2 10.7.0.2
check ping -q -c 2 -s 1452 -M do -W 2 fd00:7::2

cat > /tmp/clients.py <<'PY'
import socket, sys, threading, time

def udp(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        for size in (0, 1, 100, 1000, 1472 if family == socket.AF_INET else 1452):
            data = bytes(index % 256 for index in range(size))
            client.sendto(data, (address, 7))
            reply, _ = client.recvfrom(65536)
            assert reply == data, (address, size)

def tcp(address, port=7, size=1 << 20):
    data = bytes(index * 7 % 251 for index in range(size))
    with socket.create_connection((address, port), timeout=30) as client:
        received = bytearray()
        def read():
            while chunk := client.recv(65536):
                received.extend(chunk)
        reader = threading.Thread(target=read)
        reader.start()
        client.sendall(data)
        client.shutdown(socket.SHUT_WR)
        reader.join(60)
    assert bytes(received) == data, (address, len(received))

def tcp_many(address, count=8):
    errors = []
    def one():
        try:
            tcp(address, size=1 << 18)
        except Exception as error:
            errors.append(error)
    threads = [threading.Thread(target=one) for _ in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors, errors

def refused(address):
    try:
        socket.create_connection((address, 9), timeout=5).close()
    except ConnectionRefusedError:
        return
    raise AssertionError("connected to a closed port")

def serve(address, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, int(port)))
    server.listen()
    connection, _ = server.accept()
    while data := connection.recv(65536):
        connection.sendall(data)
    connection.close()

started = time.monotonic()
globals()[sys.argv[1]](*sys.argv[2:])
print(f"  {sys.argv[1]} {' '.join(sys.argv[2:])}: {time.monotonic() - started:.2f} s")
PY

check python3 /tmp/clients.py udp 10.7.0.2
check python3 /tmp/clients.py udp fd00:7::2
check python3 /tmp/clients.py tcp 10.7.0.2
check python3 /tmp/clients.py tcp fd00:7::2
check python3 /tmp/clients.py tcp_many 10.7.0.2
check python3 /tmp/clients.py refused 10.7.0.2

# Loss, delay and reordering on the kernel's side of the link: the
# example's retransmissions and SACK recovery against Linux's.
tc qdisc add dev umi0 root netem delay 10ms 5ms loss 3% reorder 5% 2>/dev/null || echo "no netem"
check python3 /tmp/clients.py tcp 10.7.0.2
check python3 /tmp/clients.py tcp fd00:7::2
tc qdisc del dev umi0 root 2>/dev/null || true

# The example opens the connection: an echo server of the kernel on port
# 7000, listening before the example's first SYN.
python3 /tmp/clients.py serve 0.0.0.0 7000 &
server=$!
sleep 0.5
"$tun" umi1 10.8.0.2 fd00:8::2 --connect 10.8.0.1:7000 --bytes 1048576 > /tmp/client.log 2>&1 &
client=$!
sleep 0.5
ip link set umi1 up
ip address add 10.8.0.1/24 dev umi1
check wait $client
cat /tmp/client.log
kill $server 2>/dev/null || true

kill $host 2>/dev/null || true
exit $failed
