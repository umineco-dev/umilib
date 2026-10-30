#!/bin/sh
# Runs umilib's DNS (examples/dns.rs) against dig, against BIND 9.20 (dig,
# delv), Knot 3.4 (kdig) and Unbound 1.26 of Debian in Docker, and against
# itself; prints "ok NAME" or "FAILED NAME" for each case. The server serves
# a zone signed with an NSEC chain over UDP, TCP, TLS, HTTPS and QUIC; the
# resolver validates it, and through Unbound. Without Docker, the cases of
# Docker are skipped:
#   sh examples/dns.sh
#   DOCKER=/Applications/Docker.app/Contents/Resources/bin/docker sh examples/dns.sh
set -u
OPENSSL=${OPENSSL:-openssl}
DOCKER=${DOCKER:-docker}
cargo build -q --release --example dns --features platform-native,protocol-dns || exit 1
TOOL=$PWD/target/release/examples/dns
CERTIFICATES=$PWD/tests/vectors/protocol/tls/certificates
WORK=$(mktemp -d)
CONTAINER=umilib-dns-$$
trap '"$DOCKER" rm -f $CONTAINER >/dev/null 2>&1; kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
for name in root server-p256; do
    "$OPENSSL" x509 -inform DER -in "$CERTIFICATES/$name.der" -out "$WORK/$name.pem"
done
cp "$CERTIFICATES/server-p256.key" "$WORK/server-p256.key"
PORT=25353
SECURE=25354
NAME=server.example
FAILED=0

cat >"$WORK/zone" <<'EOF'
$TTL 300
@ IN SOA ns admin 1 3600 600 86400 300
@ IN NS ns
ns IN A 127.0.0.1
www IN A 192.0.2.80
www IN AAAA 2001:db8::80
*.wild IN TXT "wildcard"
alias IN CNAME www
EOF
"$TOOL" keygen 13 example.test. "$WORK/ksk" --flags 257 >"$WORK/ksk.records" || exit 1
"$TOOL" keygen 15 example.test. "$WORK/zsk" --flags 256 >"$WORK/zsk.records" || exit 1
grep " DS " "$WORK/ksk.records" >"$WORK/ds"
# A DS of the key whose digest is wrong (all zeros): its zone must be bogus.
awk '{ $NF = sprintf("%064d", 0); print }' "$WORK/ds" >"$WORK/wrong-ds"
KSK=$(grep " DNSKEY " "$WORK/ksk.records" | awk '{print $8}')

"$TOOL" server $PORT "$WORK/zone" example.test. --sign "$WORK/ksk:257" --sign "$WORK/zsk:256" --transfers \
    --cert "$WORK/server-p256.pem" --key "$WORK/server-p256.key" >"$WORK/server.log" 2>&1 &
for _ in 1 2 3 4 5 6 7 8 9 10; do
    grep -q "listening: udp" "$WORK/server.log" 2>/dev/null && break
    sleep 0.2
done

check() { # name, file, pattern... (the file's spaces and tabs as one space)
    name=$1 file=$2
    shift 2
    tr -s ' \t' '  ' <"$file" >"$file.spaced"
    for pattern in "$@"; do
        if ! grep -q -- "$pattern" "$file.spaced"; then
            echo "FAILED $name: no \"$pattern\" in $(basename "$file")"
            sed 's/^/    /' "$file" | head -30
            FAILED=$((FAILED + 1))
            return
        fi
    done
    echo "ok $name"
}

case_run() { # name, patterns, command...
    name=$1 patterns=$2
    shift 2
    "$@" >"$WORK/$name.out" 2>&1
    # shellcheck disable=SC2086
    eval "set -- $patterns"
    check "$name" "$WORK/$name.out" "$@"
}

DIG="dig @127.0.0.1 -p $PORT +norec"
# dig, of any version: RFC 1034 §4.3.2 and its signatures (RFC 4035 §3.1).
case_run dig-answer "'status: NOERROR' 'flags: qr aa' 'IN A 192.0.2.80' 'RRSIG A 15 3 300'" $DIG www.example.test A +dnssec
case_run dig-nxdomain "'status: NXDOMAIN' 'IN SOA' 'IN NSEC'" $DIG none.example.test A +dnssec
case_run dig-nodata "'status: NOERROR' 'ANSWER: 0' 'IN SOA'" $DIG www.example.test MX
case_run dig-wildcard "'a.wild.example.test. 300 IN TXT \"wildcard\"'" $DIG a.wild.example.test TXT
case_run dig-cname "'IN CNAME www.example.test.' 'IN A 192.0.2.80'" $DIG alias.example.test A
case_run dig-tcp "'status: NOERROR' 'IN AAAA 2001:db8::80'" $DIG www.example.test AAAA +tcp
case_run dig-axfr "'XFR size' 'IN DNSKEY 257 3 13'" $DIG example.test AXFR
case_run dig-refused "'status: REFUSED'" $DIG www.example.org A
case_run dig-badvers "'status: BADVERS'" $DIG www.example.test A +edns=1 +noednsnegotiation

# Itself: every transport, validated from the zone's DS (RFC 4035 §5).
for transport in udp tcp tls https quic; do
    case $transport in udp | tcp) port=$PORT ;; *) port=$SECURE ;; esac
    case_run "self-$transport" "'rcode: 0' 'IN A 192.0.2.80' 'status: secure'" \
        "$TOOL" resolve 127.0.0.1 $port www.example.test A --transport $transport --name $NAME \
        --ca "$WORK/root.pem" --dnssec --anchor "$WORK/ds"
done
case_run self-https-post "'rcode: 0' 'status: secure'" "$TOOL" resolve 127.0.0.1 $SECURE alias.example.test A \
    --transport https --post --name $NAME --ca "$WORK/root.pem" --dnssec --anchor "$WORK/ds"
case_run self-nxdomain "'rcode: 3' 'status: secure'" "$TOOL" resolve 127.0.0.1 $PORT none.example.test A \
    --dnssec --anchor "$WORK/ds"
case_run self-wildcard "'wildcard' 'status: secure'" "$TOOL" resolve 127.0.0.1 $PORT b.wild.example.test TXT \
    --dnssec --anchor "$WORK/ds"
case_run self-bogus "'error: bogus'" "$TOOL" resolve 127.0.0.1 $PORT www.example.test A --dnssec --anchor "$WORK/wrong-ds"

if ! "$DOCKER" info >/dev/null 2>&1; then
    echo "skipped: the cases of Docker"
    [ $FAILED -eq 0 ] && echo "all passed" || echo "$FAILED FAILED"
    exit $FAILED
fi

# Docker: BIND, Knot and Unbound of Debian; the server is the host's, at host.docker.internal.
"$DOCKER" build -q -t umilib-dns-interop - >/dev/null <<'EOF' || exit 1
FROM debian:trixie
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bind9-dnsutils knot-dnsutils unbound dns-root-data ca-certificates
EOF
cat >"$WORK/unbound.conf" <<EOF
server:
    interface: 0.0.0.0@53
    interface: 0.0.0.0@853
    interface: 0.0.0.0@443
    tls-port: 853
    https-port: 443
    tls-service-key: /work/server-p256.key
    tls-service-pem: /work/server-p256.pem
    access-control: 0.0.0.0/0 allow
    access-control: ::/0 allow
    username: ""
    chroot: ""
    do-ip6: yes
    do-not-query-localhost: no
    module-config: "validator iterator"
    trust-anchor-file: /usr/share/dns/root.key
    trust-anchor: "$(cat "$WORK/ds")"
    local-zone: "test." nodefault
    domain-insecure: "nothing.invalid."
stub-zone:
    name: "example.test."
    stub-addr: HOST@$PORT
EOF
"$DOCKER" run -d --name $CONTAINER -v "$WORK:/work" -p 127.0.0.1:25053:53/udp -p 127.0.0.1:25053:53/tcp \
    -p 127.0.0.1:25853:853 -p 127.0.0.1:25443:443 umilib-dns-interop sh -c \
    'sed -i "s/HOST/$(getent ahostsv4 host.docker.internal | head -1 | cut -d" " -f1)/" /work/unbound.conf && unbound -d -c /work/unbound.conf' >/dev/null
sleep 2
in_docker() { "$DOCKER" exec $CONTAINER "$@"; }
SERVER=host.docker.internal
printf 'trust-anchors { example.test. static-key 257 3 13 "%s"; };\n' "$KSK" >"$WORK/anchors.conf"

# BIND 9.20: cookies (RFC 7873), padding over TLS (RFC 8467), DNS over TLS, HTTPS and XoT, validation.
case_run bind-cookie "'COOKIE: [0-9a-f]* (good)'" in_docker dig @$SERVER -p $PORT www.example.test A +norec +cookie
case_run bind-tls "'status: NOERROR' 'IN A 192.0.2.80'" in_docker dig @$SERVER -p $SECURE +tls www.example.test A +norec
case_run bind-padding "'PADDING' 'MSG SIZE rcvd: 468'" in_docker dig @$SERVER -p $SECURE +tls +padding=128 www.example.test A +norec
case_run bind-https-get "'status: NOERROR' 'IN A 192.0.2.80'" in_docker dig @$SERVER -p $SECURE +https-get www.example.test A +norec
case_run bind-https-post "'status: NOERROR' 'IN A 192.0.2.80'" in_docker dig @$SERVER -p $SECURE +https www.example.test A +norec
case_run bind-xot "'XFR size'" in_docker dig @$SERVER -p $SECURE +tls example.test AXFR
case_run bind-delv "'; fully validated' 'www.example.test. 300 IN A 192.0.2.80'" \
    in_docker delv -a /work/anchors.conf +root=example.test @$SERVER -p $PORT www.example.test A
case_run bind-delv-nxdomain "'negative response, fully validated' 'ncache nxdomain'" \
    in_docker delv -a /work/anchors.conf +root=example.test @$SERVER -p $PORT none.example.test A
case_run bind-delv-wildcard "'; fully validated' 'wildcard'" \
    in_docker delv -a /work/anchors.conf +root=example.test @$SERVER -p $PORT c.wild.example.test TXT

# Knot 3.4: DNS over TLS and HTTPS, and the server's NSID-less EDNS.
case_run knot-tls "'status: NOERROR' '192.0.2.80'" in_docker kdig @$SERVER -p $SECURE +tls www.example.test A +norec
case_run knot-https "'status: NOERROR' '192.0.2.80'" in_docker kdig @$SERVER -p $SECURE +https www.example.test A +norec
case_run knot-https-get "'status: NOERROR' '192.0.2.80'" in_docker kdig @$SERVER -p $SECURE +https-get www.example.test A +norec
case_run knot-tcp "'status: NOERROR' '192.0.2.80'" in_docker kdig @$SERVER -p $PORT +tcp www.example.test A +norec

# Unbound validating the server's zone: the AD bit (RFC 4035 §3.2.3).
case_run unbound-validates "'flags: qr rd ra ad' 'IN A 192.0.2.80'" in_docker dig @127.0.0.1 www.example.test A +dnssec
# The resolver through Unbound, over UDP, TLS and HTTPS, validating itself.
for transport in udp tls https; do
    case $transport in udp) port=25053 ;; tls) port=25853 ;; https) port=25443 ;; esac
    case_run "self-unbound-$transport" "'rcode: 0' 'status: secure'" \
        "$TOOL" resolve 127.0.0.1 $port www.example.test A --transport $transport --name $NAME \
        --ca "$WORK/root.pem" --dnssec --anchor "$WORK/ds"
done
# The Internet through Unbound: a zone signed from the root, and one that is broken on purpose
# (Unbound's cache filled first, so that the resolver's timeouts are not of Unbound's first resolution).
in_docker dig @127.0.0.1 ietf.org A +dnssec >/dev/null 2>&1
in_docker dig @127.0.0.1 dnssec-failed.org A +cd >/dev/null 2>&1
case_run self-internet "'rcode: 0' 'status: secure'" "$TOOL" resolve 127.0.0.1 25053 ietf.org A --dnssec
case_run self-internet-bogus "'error: bogus'" "$TOOL" resolve 127.0.0.1 25053 dnssec-failed.org A --dnssec

[ $FAILED -eq 0 ] && echo "all passed" || echo "$FAILED FAILED"
exit $FAILED
