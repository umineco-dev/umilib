#!/bin/sh
# Runs umilib's QUIC (examples/quic.rs) against itself, OpenSSL's QUIC
# client (s_client -quic) and curl's (ngtcp2, --http3-only), and prints
# "ok NAME" or "FAILED NAME" for each case. Needs OpenSSL 3.5 or later and a
# curl built with HTTP/3:
#   OPENSSL=/opt/homebrew/opt/openssl@4/bin/openssl CURL=/opt/homebrew/opt/curl/bin/curl sh examples/quic.sh
# The server does not speak HTTP/3 yet: against curl it reads and never
# answers (--sink), so curl times out after its handshake and streams, and
# closes with NO_ERROR.
set -u
OPENSSL=${OPENSSL:-openssl}
CURL=${CURL:-curl}
cargo build -q --release --example quic --features platform-native,protocol-quic || exit 1
TOOL=$PWD/target/release/examples/quic
CERTIFICATES=$PWD/tests/vectors/protocol/tls/certificates
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
for name in root server-p256; do
    "$OPENSSL" x509 -inform DER -in "$CERTIFICATES/$name.der" -out "$WORK/$name.pem"
done
PORT=24600
FAILED=0
NAME=server.example

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

# A server with the options $2.., run until its connection closes; the log is $1.
serve() {
    log=$1
    shift
    PORT=$((PORT + 1))
    "$TOOL" server "$PORT" --cert "$WORK/server-p256.pem" --key "$CERTIFICATES/server-p256.key" "$@" >"$log" 2>&1 &
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        grep -q listening "$log" 2>/dev/null && return
        sleep 0.2
    done
}

# Waits for the server's connection to close, at most 5 s.
finish() {
    for _ in $(seq 1 25); do
        grep -q "^closed" "$1" && return
        sleep 0.2
    done
}

client() { # name, server options, client options
    name=$1 server_options=$2 client_options=$3
    serve "$WORK/$name.server" $server_options
    timeout 10 "$TOOL" client 127.0.0.1 "$PORT" --name $NAME --ca "$WORK/root.pem" $client_options >"$WORK/$name.client" 2>&1
    finish "$WORK/$name.server"
}

client self "" "--send hello --datagram dg"
check self "$WORK/self.client" "connected: yes" "alpn: echo" "echo: hello" "datagram: dg" "closed: local application 0x0"
check self-server "$WORK/self.server" "stream 0: 5 bytes" "datagram: dg" "closed: 0 peer application 0x0"
client version-2 "--version 2" "--version 2"
check version-2 "$WORK/version-2.client" "version: 0x6b3343cf" "echo: hello"
client retry "--retry" ""
check retry "$WORK/retry.server" "retry: true" "closed: 0 peer application 0x0"
check retry-client "$WORK/retry.client" "echo: hello"

openssl_client() { # name, server options
    name=$1
    serve "$WORK/$name.server" --alpn echo $2
    (printf 'from openssl\n'; sleep 2) | timeout 8 "$OPENSSL" s_client -quic -alpn echo -connect 127.0.0.1:$PORT \
        -servername $NAME -CAfile "$WORK/root.pem" >"$WORK/$name.client" 2>&1
    finish "$WORK/$name.server"
}

openssl_client openssl ""
check openssl "$WORK/openssl.client" "Protocol: QUICv1" "ALPN protocol: echo" "Verify return code: 0" "^from openssl"
check openssl-server "$WORK/openssl.server" "stream 0: 13 bytes" "closed: 0 peer application 0x0"
openssl_client openssl-retry "--retry"
check openssl-retry "$WORK/openssl-retry.server" "retry: true" "closed: 0 peer application 0x0"
check openssl-retry-client "$WORK/openssl-retry.client" "^from openssl"

curl_client() { # name, server options
    name=$1
    serve "$WORK/$name.server" --alpn h3 --sink $2
    timeout 10 "$CURL" -sv --max-time 2 --http3-only --cacert "$WORK/root.pem" \
        --resolve $NAME:$PORT:127.0.0.1 "https://$NAME:$PORT/" -o /dev/null >"$WORK/$name.client" 2>&1
    finish "$WORK/$name.server"
}

curl_client curl ""
check curl "$WORK/curl.client" "SSL certificate verified" "using HTTP/3" "Request completely sent off"
check curl-server "$WORK/curl.server" "alpn: h3" "stream 0: " "stream 2: " "closed: 0 peer transport 0x0"
curl_client curl-retry "--retry"
check curl-retry "$WORK/curl-retry.server" "retry: true" "closed: 0 peer transport 0x0"
# A server of version 2 only: Version Negotiation, and curl (version 1 only) gives up (RFC 9000 §6.2).
curl_client curl-negotiation "--version 2"
check curl-negotiation "$WORK/curl-negotiation.client" "QUIC connect to 127.0.0.1 port $PORT failed"

if [ "$FAILED" -eq 0 ]; then echo "all ok"; else echo "$FAILED FAILED"; exit 1; fi
