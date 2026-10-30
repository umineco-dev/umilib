#!/bin/sh
# Runs umilib's DHCP (examples/dhcp.rs) against ISC dhclient, BusyBox
# udhcpc and dnsmasq, and against itself, between two network namespaces
# joined by a veth pair: "a" with the server (10.9.0.1/24, fd00:9::1/64) and
# "b" with the client (no address but its link-local one).
#
#   docker run --rm --privileged -v "$PWD":/work -w /work \
#       -e CARGO_TARGET_DIR=/work/target/docker-linux rust:1-bookworm sh examples/dhcp.sh
#
# Each case prints "ok NAME" or "FAILED NAME"; the script exits with the number that failed.
set -u
apt-get update -qq >/dev/null && apt-get install -y -qq iproute2 isc-dhcp-client dnsmasq busybox >/dev/null 2>&1
cargo build -q --release --example dhcp --features platform-native,protocol-dhcp || exit 1
TOOL=$CARGO_TARGET_DIR/release/examples/dhcp
WORK=$(mktemp -d)
FAILED=0

ip netns add a
ip netns add b
ip link add va type veth peer name vb
ip link set va netns a
ip link set vb netns b
for namespace in a b; do
    ip -n $namespace link set lo up
    ip netns exec $namespace sysctl -q -w net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0
done
ip netns exec a sysctl -q -w net.ipv6.conf.va.accept_dad=0
ip netns exec b sysctl -q -w net.ipv6.conf.vb.accept_dad=0
ip -n a addr add 10.9.0.1/24 dev va
ip -n a addr add fd00:9::1/64 dev va nodad
ip -n a link set va up
ip -n b link set vb up
# Both ends send to 255.255.255.255 by these routes (RFC 2131 §4.1).
ip -n a route add 255.255.255.255/32 dev va
ip -n b route add 255.255.255.255/32 dev vb
sleep 2

check() { # name, file, pattern...
    name=$1 file=$2
    shift 2
    for pattern in "$@"; do
        if ! grep -q -- "$pattern" "$file"; then
            echo "FAILED $name: no \"$pattern\" in $(basename "$file")"
            sed 's/^/    /' "$file" | head -30
            FAILED=$((FAILED + 1))
            return
        fi
    done
    echo "ok $name"
}

serve() { # name, command... (in namespace a, in the background)
    name=$1
    shift
    ip netns exec a "$@" >"$WORK/$name.server" 2>&1 &
    SERVER=$!
    sleep 1
}

stop() {
    kill $SERVER 2>/dev/null
    wait $SERVER 2>/dev/null
}

unconfigure() { # removes what --configure added; with it went the route of 255.255.255.255
    ip -n b address flush dev vb scope global
    ip -n b route replace 255.255.255.255/32 dev vb
}

client() { # name, command... (in namespace b, for at most 30 seconds)
    name=$1
    shift
    timeout 30 ip netns exec b "$@" >"$WORK/$name.out" 2>&1
}

UMILIB4="$TOOL server4 va 10.9.0.1 10.9.0.100 10.9.0.110 --router 10.9.0.1 --dns 10.9.0.53 --lease 600"
UMILIB6="$TOOL server6 va fd00:9::100 fd00:9::1ff --prefix fd00:9:100::/40/56 --dns fd00:9::53"
DNSMASQ="dnsmasq -d -u root --port=0 --interface=va --bind-interfaces --dhcp-authoritative --log-dhcp"

# DHCPv4 (RFC 2131): the server of umilib, and its client.
serve self4 $UMILIB4
client self4 $TOOL client4 vb --configure --release
sleep 1
stop
unconfigure
check self4 "$WORK/self4.out" "bound: 10.9.0.10" "option: router 10.9.0.1" "option: dns 10.9.0.53" \
    "option: mask 255.255.255.0" "option: lease 600" "released"
check self4-server "$WORK/self4.server" "lease: 10.9.0.10" "release: 10.9.0.10"

serve dhclient4 $UMILIB4
client dhclient4 dhclient -4 -1 -v -sf /bin/true -lf "$WORK/dhclient4.leases" -pf "$WORK/dhclient4.pid" vb
kill "$(cat "$WORK/dhclient4.pid" 2>/dev/null)" 2>/dev/null
stop
check dhclient4 "$WORK/dhclient4.out" "DHCPOFFER of 10.9.0.10" "DHCPACK of 10.9.0.10" "bound to 10.9.0.10"
check dhclient4-lease "$WORK/dhclient4.leases" "option routers 10.9.0.1" "option domain-name-servers 10.9.0.53"

serve udhcpc $UMILIB4
client udhcpc busybox udhcpc -i vb -n -q -f -s /bin/true
stop
check udhcpc "$WORK/udhcpc.out" "lease of 10.9.0.10" "obtained"

serve dnsmasq4 $DNSMASQ --dhcp-range=10.9.0.50,10.9.0.60,1h --dhcp-option=3,10.9.0.1 --dhcp-option=6,10.9.0.53
client dnsmasq4 $TOOL client4 vb --configure --release
sleep 1
stop
unconfigure
check dnsmasq4 "$WORK/dnsmasq4.out" "bound: 10.9.0.5" "option: router 10.9.0.1" "option: dns 10.9.0.53" \
    "option: lease 3600" "released"
check dnsmasq4-server "$WORK/dnsmasq4.server" "DHCPACK(va) 10.9.0.5" "DHCPRELEASE(va) 10.9.0.5"

# DHCPv6 (RFC 9915): addresses (IA_NA), prefixes (IA_PD), Rapid Commit, Information-request.
serve self6 $UMILIB6
client self6 $TOOL client6 vb --prefix 56 --release
client self6-information $TOOL client6 vb --no-addresses
client self6-rapid $TOOL client6 vb --rapid-commit
stop
check self6 "$WORK/self6.out" "bound: fd00:9::1" "bound: fd00:9:1" "/56" "option: dns fd00:9::53" "released"
check self6-information "$WORK/self6-information.out" "informed" "option: dns fd00:9::53"
check self6-rapid "$WORK/self6-rapid.out" "bound: fd00:9::1"
check self6-server "$WORK/self6.server" "lease: fd00:9::1" "lease: fd00:9:1"

serve dhclient6 $UMILIB6
client dhclient6 dhclient -6 -1 -v -sf /bin/true -lf "$WORK/dhclient6.leases" -pf "$WORK/dhclient6.pid" vb
kill "$(cat "$WORK/dhclient6.pid" 2>/dev/null)" 2>/dev/null
client dhclient6-prefix dhclient -6 -P -1 -v -sf /bin/true -lf "$WORK/dhclient6p.leases" -pf "$WORK/dhclient6p.pid" vb
kill "$(cat "$WORK/dhclient6p.pid" 2>/dev/null)" 2>/dev/null
stop
check dhclient6 "$WORK/dhclient6.leases" "iaaddr fd00:9::1" "option dhcp6.name-servers fd00:9::53"
check dhclient6-prefix "$WORK/dhclient6p.leases" "iaprefix fd00:9:1" "/56"

serve dnsmasq6 $DNSMASQ --dhcp-range=fd00:9::100,fd00:9::1ff,64,1h --dhcp-option=option6:dns-server,[fd00:9::53]
client dnsmasq6 $TOOL client6 vb --release
client dnsmasq6-information $TOOL client6 vb --no-addresses
sleep 1
stop
check dnsmasq6 "$WORK/dnsmasq6.out" "bound: fd00:9::1" "option: dns fd00:9::53" "released"
check dnsmasq6-information "$WORK/dnsmasq6-information.out" "informed" "option: dns fd00:9::53"
check dnsmasq6-server "$WORK/dnsmasq6.server" "DHCPREPLY(va) fd00:9::1" "DHCPRELEASE(va)"

[ $FAILED -eq 0 ] && echo "all passed" || echo "$FAILED FAILED"
exit $FAILED
