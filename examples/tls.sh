#!/bin/sh
# Runs umilib's TLS (examples/tls.rs) against OpenSSL (s_client, s_server,
# ech) and curl, both ways, and prints "ok NAME" or "FAILED NAME" for each
# case. Needs OpenSSL 4.1 or later (ECH) and a curl built with it:
#   OPENSSL=/opt/homebrew/opt/openssl@4/bin/openssl CURL=/opt/homebrew/opt/curl/bin/curl sh examples/tls.sh
set -u
OPENSSL=${OPENSSL:-openssl}
CURL=${CURL:-curl}
FEATURES=platform-native,protocol-tls,crypto-hpke,crypto-hybrid,crypto-dh,crypto-mode-ccm,codec-base-base64,auth-cert-ocsp
cargo build -q --release --example tls --features "$FEATURES" || exit 1
TOOL=$PWD/target/release/examples/tls
CERTIFICATES=$PWD/tests/vectors/protocol/tls/certificates
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
for name in root server-p256 server-rsa server-ed25519 client; do
    "$OPENSSL" x509 -inform DER -in "$CERTIFICATES/$name.der" -out "$WORK/$name.pem"
done
PORT=24400
FAILED=0
CONNECT="-connect 127.0.0.1:"
NAME=server.example

check() { # name, file, pattern...
    name=$1 file=$2
    shift 2
    for pattern in "$@"; do
        if ! grep -q -- "$pattern" "$file"; then
            echo "FAILED $name: no \"$pattern\""
            sed 's/^/    /' "$file" | head -40
            FAILED=$((FAILED + 1))
            return
        fi
    done
    echo "ok $name"
}

# Waits until the server writing to $1 listens: umilib's server prints
# "listening", OpenSSL's "ACCEPT". (Probing the port would be a connection.)
wait_listening() {
    for _ in $(seq 100); do
        grep -q -e "^listening" -e "^ACCEPT" "$1" 2>/dev/null && return
        sleep 0.1
    done
}

# umilib's server, then a client command with the port; the server's
# report goes to $WORK/server, the client's to $WORK/client.
serve() { # server options..., then -- client command
    PORT=$((PORT + 1))
    options=""
    while [ "$1" != "--" ]; do options="$options $1"; shift; done
    shift
    # shellcheck disable=SC2086
    "$TOOL" server "$PORT" --cert "$WORK/server-p256.pem" --key "$CERTIFICATES/server-p256.key" $options > "$WORK/server" 2>&1 &
    server=$!
    wait_listening "$WORK/server"
    command=$(echo "$*" | sed "s/PORT/$PORT/g")
    eval "$command" > "$WORK/client" 2>&1 < /dev/null
    sleep 0.3
    kill "$server" 2>/dev/null
    wait "$server" 2>/dev/null
}

S_CLIENT="printf 'GET / HTTP/1.0\r\n\r\n' | timeout 10 $OPENSSL s_client ${CONNECT}PORT -servername $NAME -CAfile $WORK/root.pem -verify_return_error -ign_eof"

echo "== OpenSSL s_client to umilib"
serve --http -- "$S_CLIENT"
check "s_client tls1.3 default" "$WORK/client" "Protocol: TLSv1.3" "X25519MLKEM768" "Verify return code: 0" "hello from umilib"
for group in X25519:x25519 X448:x448 P-256:p256 P-384:p384 P-521:p521 ffdhe2048:ffdhe2048 SecP256r1MLKEM768:p256mlkem768 SecP384r1MLKEM1024:p384mlkem1024; do
    serve --http --groups "${group#*:}" -- "$S_CLIENT -groups ${group%%:*}"
    check "s_client tls1.3 group ${group%%:*}" "$WORK/client" "Protocol: TLSv1.3" "hello from umilib"
done
for suite in TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_CCM_SHA256; do
    serve --http -- "$S_CLIENT -ciphersuites $suite"
    check "s_client tls1.3 $suite" "$WORK/client" "Cipher is $suite" "hello from umilib"
done
for cipher in ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305; do
    serve --http -- "$S_CLIENT -tls1_2 -cipher $cipher"
    check "s_client tls1.2 $cipher" "$WORK/client" "Protocol: TLSv1.2" "Cipher is $cipher" "Extended master secret: yes" "hello from umilib"
done
PORT=$((PORT + 1))
"$TOOL" server "$PORT" --cert "$WORK/server-rsa.pem" --key "$CERTIFICATES/server-rsa.key" --http > "$WORK/server" 2>&1 &
wait_listening "$WORK/server"
eval "$(echo "$S_CLIENT -tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384" | sed "s/PORT/$PORT/")" > "$WORK/client" 2>&1
check "s_client tls1.2 ECDHE-RSA-AES256-GCM-SHA384" "$WORK/client" "Protocol: TLSv1.2" "hello from umilib"
serve --http --alpn h2,http/1.1 -- "$S_CLIENT -alpn http/1.1"
check "s_client alpn" "$WORK/client" "ALPN protocol: http/1.1"
serve --http --client-ca "$WORK/root.pem" --require-certificate -- "$S_CLIENT -cert $WORK/client.pem -key $CERTIFICATES/client.key"
check "s_client client certificate" "$WORK/client" "hello from umilib"
check "s_client client certificate (server)" "$WORK/server" "peer_certificates: [1-9]"
serve --http --client-ca "$WORK/root.pem" --require-certificate -- "$S_CLIENT"
check "s_client without the required certificate" "$WORK/server" "error: Protocol"
# s_client answers the request while it reads: its input stays open for a while.
PHA="(printf 'GET / HTTP/1.0\\r\\n\\r\\n'; sleep 2) | timeout 10 $OPENSSL s_client ${CONNECT}PORT -servername $NAME -CAfile $WORK/root.pem -ign_eof"
serve --http --client-ca "$WORK/root.pem" --request-certificate -- "$PHA -enable_pha -cert $WORK/client.pem -key $CERTIFICATES/client.key"
check "s_client post-handshake authentication" "$WORK/server" "authenticated: [1-9]"
# Resumption and early data: two connections to one server.
PORT=$((PORT + 1))
"$TOOL" server "$PORT" --cert "$WORK/server-p256.pem" --key "$CERTIFICATES/server-p256.key" --http --tickets --early-data 16384 --connections 2 > "$WORK/server" 2>&1 &
wait_listening "$WORK/server"
eval "$(echo "$S_CLIENT -sess_out $WORK/session" | sed "s/PORT/$PORT/")" > "$WORK/client" 2>&1
printf 'GET /early HTTP/1.0\r\n\r\n' > "$WORK/early"
timeout 10 "$OPENSSL" s_client -connect "127.0.0.1:$PORT" -servername "$NAME" -CAfile "$WORK/root.pem" -sess_in "$WORK/session" -early_data "$WORK/early" -ign_eof < /dev/null > "$WORK/client" 2>&1
sleep 0.3
check "s_client resumption" "$WORK/client" "Reused, TLSv1.3"
check "s_client early data" "$WORK/client" "Early data was accepted"
check "s_client early data (server)" "$WORK/server" "early_data_received: GET /early"
# ECH: umilib's key, OpenSSL's client.
PORT=$((PORT + 1))
"$TOOL" server "$PORT" --cert "$WORK/server-p256.pem" --key "$CERTIFICATES/server-p256.key" --http --ech public.wild.example > "$WORK/server" 2>&1 &
wait_listening "$WORK/server"
LIST=$(sed -n 's/^ech_config_list: //p' "$WORK/server")
# The ClientHelloInner must offer only TLS 1.3 (RFC 9849 §6.1); OpenSSL's offers what its outer one
# does unless TLS 1.2 is off, which umilib refuses with illegal_parameter as §7.1 requires.
eval "$(echo "$S_CLIENT -tls1_3 -ech_config_list $LIST" | sed "s/PORT/$PORT/")" > "$WORK/client" 2>&1
sleep 0.3
check "s_client ech" "$WORK/client" "ECH: success" "hello from umilib"
check "s_client ech (server)" "$WORK/server" "ech: Accepted" "server_name: server.example"
PORT=$((PORT + 1))
"$TOOL" server "$PORT" --cert "$WORK/server-p256.pem" --key "$CERTIFICATES/server-p256.key" --http --ech public.wild.example > "$WORK/server" 2>&1 &
wait_listening "$WORK/server"
LIST=$(sed -n 's/^ech_config_list: //p' "$WORK/server")
eval "$(echo "$S_CLIENT -ech_config_list $LIST" | sed "s/PORT/$PORT/")" > "$WORK/client" 2>&1
sleep 0.3
check "s_client ech offering tls1.2 inside" "$WORK/client" "alert illegal parameter"

echo "== curl to umilib"
serve --http --alpn http/1.1 -- "$CURL -sS --cacert $WORK/root.pem --resolve $NAME:PORT:127.0.0.1 https://$NAME:PORT/"
check "curl" "$WORK/client" "hello from umilib over Some(TLSVersion(772))"
serve --http --alpn http/1.1 -- "$CURL -sS --tls-max 1.2 --cacert $WORK/root.pem --resolve $NAME:PORT:127.0.0.1 https://$NAME:PORT/"
check "curl tls1.2" "$WORK/client" "hello from umilib over Some(TLSVersion(771))"

echo "== umilib to OpenSSL s_server"
CLIENT="$TOOL client 127.0.0.1 PORT --name $NAME --ca $WORK/root.pem"
# OpenSSL's server, then umilib's client.
openssl_serve() { # s_server options..., then -- client options
    PORT=$((PORT + 1))
    options=""
    while [ "$1" != "--" ]; do options="$options $1"; shift; done
    shift
    # shellcheck disable=SC2086
    "$OPENSSL" s_server -accept "$PORT" -cert "$WORK/server-p256.pem" -key "$CERTIFICATES/server-p256.key" -www $options > "$WORK/server" 2>&1 &
    server=$!
    wait_listening "$WORK/server"
    command=$(echo "$CLIENT $*" | sed "s/PORT/$PORT/g")
    eval "$command" > "$WORK/client" 2>&1
    kill "$server" 2>/dev/null
    wait "$server" 2>/dev/null
}
openssl_serve -- ""
check "s_server tls1.3 default" "$WORK/client" "version: Some(772)" "group: 11ec" "response: HTTP/1.0 200 ok"
for group in x25519:X25519 x448:X448 p256:P-256 p384:P-384 p521:P-521 ffdhe2048:ffdhe2048 p256mlkem768:SecP256r1MLKEM768 p384mlkem1024:SecP384r1MLKEM1024; do
    openssl_serve -groups "${group#*:}" -- "--groups ${group%%:*}"
    check "s_server tls1.3 group ${group%%:*}" "$WORK/client" "version: Some(772)" "response: HTTP/1.0 200 ok"
done
openssl_serve -tls1_2 -- ""
check "s_server tls1.2" "$WORK/client" "version: Some(771)" "cipher_suite: c02b" "response: HTTP/1.0 200 ok"
openssl_serve -- "--version 1.2 --groups p384,p256"
check "s_server tls1.2 p384" "$WORK/client" "version: Some(771)" "group: 0018"
openssl_serve -alpn h2 -- "--alpn http/1.1,h2"
check "s_server alpn" "$WORK/client" "protocol: h2"
openssl_serve -Verify 1 -CAfile "$WORK/root.pem" -- "--cert $WORK/client.pem --key $CERTIFICATES/client.key"
check "s_server client certificate" "$WORK/client" "response: HTTP/1.0 200 ok"
openssl_serve -status_file "$CERTIFICATES/ocsp-good.der" -- "--ocsp"
check "s_server ocsp stapling" "$WORK/client" "certificate_status: [1-9]"
openssl_serve -status_file "$CERTIFICATES/ocsp-revoked.der" -- "--ocsp"
check "s_server ocsp revoked" "$WORK/client" "error: Protocol(TLSAlertDescription(44))"
openssl_serve -early_data -- "--connections 2 --early hello"
check "s_server resumption" "$WORK/client" "resumed: true" "early_data: Accepted"
openssl_serve -- "--key-update"
check "s_server key update" "$WORK/client" "response: HTTP/1.0 200 ok"
"$OPENSSL" ech -public_name public.wild.example -out "$WORK/ech.pem" > /dev/null 2>&1
LIST=$(sed -n '/BEGIN ECHCONFIG/,/END ECHCONFIG/p' "$WORK/ech.pem" | grep -v ECHCONFIG | tr -d '\n')
openssl_serve -ech_key "$WORK/ech.pem" -- "--ech $LIST"
check "s_server ech" "$WORK/client" "ech: Accepted" "response: HTTP/1.0 200 ok"
"$OPENSSL" ech -public_name public.wild.example -out "$WORK/other.pem" > /dev/null 2>&1
OTHER=$(sed -n '/BEGIN ECHCONFIG/,/END ECHCONFIG/p' "$WORK/other.pem" | grep -v ECHCONFIG | tr -d '\n')
openssl_serve -ech_key "$WORK/ech.pem" -- "--ech $OTHER"
check "s_server ech rejected" "$WORK/client" "ech: Rejected { retry_configs: Some" "error: Protocol(TLSAlertDescription(121))"

echo "failed: $FAILED"
exit "$FAILED"
