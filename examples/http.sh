#!/bin/sh
# Runs umilib's HTTP (examples/http.rs) against curl (HTTP/1.1, HTTP/2 with
# prior knowledge and over TLS, HTTP/3), Python's http.client, a WebSocket
# client written with Python's standard library, Python's http.server, and
# itself; prints "ok NAME" or "FAILED NAME" for each case. Needs a curl built
# with HTTP/2 and HTTP/3:
#   OPENSSL=/opt/homebrew/opt/openssl@4/bin/openssl CURL=/opt/homebrew/opt/curl/bin/curl sh examples/http.sh
set -u
OPENSSL=${OPENSSL:-openssl}
CURL=${CURL:-curl}
PYTHON=${PYTHON:-python3}
cargo build -q --release --example http --features platform-native,protocol-http,protocol-tls,protocol-quic,codec-gzip || exit 1
TOOL=$PWD/target/release/examples/http
CERTIFICATES=$PWD/tests/vectors/protocol/tls/certificates
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
for name in root server-p256; do
    "$OPENSSL" x509 -inform DER -in "$CERTIFICATES/$name.der" -out "$WORK/$name.pem"
done
PLAIN=24700
SECURE=24701
NAME=server.example
FAILED=0

"$TOOL" server $PLAIN >"$WORK/plain.log" 2>&1 &
"$TOOL" server $SECURE --cert "$WORK/server-p256.pem" --key "$CERTIFICATES/server-p256.key" --quic >"$WORK/secure.log" 2>&1 &
for _ in 1 2 3 4 5 6 7 8 9 10; do
    grep -q listening "$WORK/plain.log" 2>/dev/null && grep -q listening "$WORK/secure.log" 2>/dev/null && break
    sleep 0.2
done

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

case_run() { # name, patterns, command...
    name=$1 patterns=$2
    shift 2
    "$@" >"$WORK/$name.out" 2>&1
    # shellcheck disable=SC2086
    eval "set -- $patterns"
    check "$name" "$WORK/$name.out" "$@"
}

PLAIN_URL=http://127.0.0.1:$PLAIN
SECURE_URL=https://$NAME:$SECURE
TRUST="--cacert $WORK/root.pem --resolve $NAME:$SECURE:127.0.0.1"

# curl, cleartext: HTTP/1.1 and HTTP/2 with prior knowledge (RFC 9113 §3.3).
case_run curl-http1.1 "'over HTTP/1.1' 'HTTP/1.1 200'" "$CURL" -si --http1.1 "$PLAIN_URL/"
case_run curl-http2-prior-knowledge "'over HTTP/2' 'HTTP/2 200'" "$CURL" -si --http2-prior-knowledge "$PLAIN_URL/"
case_run curl-http1.1-echo "'^umilib-echo-body'" "$CURL" -s --http1.1 -d umilib-echo-body "$PLAIN_URL/echo"
case_run curl-http1.1-chunked "'^chunked-upload$'" sh -c "printf 'chunked-upload\n' | '$CURL' -s --http1.1 -H 'Transfer-Encoding: chunked' --data-binary @- '$PLAIN_URL/echo'"
case_run curl-http1.1-bytes "'^3000000$'" sh -c "'$CURL' -s --http1.1 '$PLAIN_URL/bytes?3000000' | wc -c | tr -d ' '"
case_run curl-http2-bytes "'^3000000$'" sh -c "'$CURL' -s --http2-prior-knowledge '$PLAIN_URL/bytes?3000000' | wc -c | tr -d ' '"
case_run curl-gzip "'content-encoding: gzip' 'a text that compresses'" "$CURL" -si --compressed --http1.1 "$PLAIN_URL/gzip"
case_run curl-not-found "'HTTP/1.1 404'" "$CURL" -si --http1.1 "$PLAIN_URL/missing"
case_run curl-keep-alive "'Reusing existing' 'over HTTP/1.1'" "$CURL" -sv --http1.1 "$PLAIN_URL/" "$PLAIN_URL/"
case_run curl-http2-parallel "'^4$'" sh -c "'$CURL' -s --http2-prior-knowledge -Z '$PLAIN_URL/' '$PLAIN_URL/' '$PLAIN_URL/' '$PLAIN_URL/' | grep -c 'over HTTP/2'"

# curl over TLS: ALPN h2 and http/1.1, and HTTP/3 over QUIC.
# shellcheck disable=SC2086
case_run curl-https-http1.1 "'over HTTP/1.1' 'HTTP/1.1 200'" "$CURL" -si $TRUST --http1.1 "$SECURE_URL/"
# shellcheck disable=SC2086
case_run curl-https-http2 "'over HTTP/2' 'HTTP/2 200'" "$CURL" -si $TRUST --http2 "$SECURE_URL/"
# shellcheck disable=SC2086
case_run curl-http3 "'over HTTP/3' 'HTTP/3 200'" "$CURL" -si $TRUST --http3-only "$SECURE_URL/"
# shellcheck disable=SC2086
case_run curl-http3-echo "'^h3-echo-body'" "$CURL" -s $TRUST --http3-only -d h3-echo-body "$SECURE_URL/echo"
case_run curl-http3-bytes "'^3000000$'" sh -c "'$CURL' -s $TRUST --http3-only '$SECURE_URL/bytes?3000000' | wc -c | tr -d ' '"
case_run curl-https-http2-bytes "'^3000000$'" sh -c "'$CURL' -s $TRUST --http2 '$SECURE_URL/bytes?3000000' | wc -c | tr -d ' '"

# Python's http.client: requests on one persistent connection.
cat >"$WORK/client.py" <<'PYTHON'
import http.client, sys
connection = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]))
for _ in range(3):
    connection.request("GET", "/")
    print(connection.getresponse().read().decode().strip())
connection.request("POST", "/echo", body=b"from python", headers={"Content-Type": "text/plain"})
response = connection.getresponse()
print(response.status, response.read().decode())
connection.request("GET", "/missing")
response = connection.getresponse()
print(response.status, response.read().decode().strip())
PYTHON
case_run python-http-client "'over HTTP/1.1' '200 from python' '404 not found'" "$PYTHON" -I "$WORK/client.py" $PLAIN

# A WebSocket client of Python's standard library (RFC 6455 §4.1, §5.3).
cat >"$WORK/websocket.py" <<'PYTHON'
import base64, hashlib, os, socket, struct, sys
key = base64.b64encode(os.urandom(16)).decode()
connection = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
connection.sendall(("GET /chat HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
head = b""
while b"\r\n\r\n" not in head:
    head += connection.recv(1)
print(head.split(b"\r\n")[0].decode())
accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
print("accept ok" if f"sec-websocket-accept: {accept}".lower() in head.decode().lower() else "accept wrong")
def send(opcode, payload):
    mask = os.urandom(4)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    connection.sendall(bytes([0x80 | opcode, 0x80 | len(payload)]) + mask + masked)
def receive():
    first, second = connection.recv(1)[0], connection.recv(1)[0]
    length = second & 0x7F
    payload = b""
    while len(payload) < length:
        payload += connection.recv(length - len(payload))
    return first & 0x0F, payload
send(0x1, "héllo from python".encode())
opcode, payload = receive()
print("echo:", payload.decode())
send(0x8, struct.pack("!H", 1000) + b"bye")
opcode, payload = receive()
print("close:", opcode, struct.unpack("!H", payload[:2])[0])
PYTHON
case_run python-websocket "'HTTP/1.1 101' 'accept ok' 'echo: héllo from python' 'close: 8 1000'" "$PYTHON" -I "$WORK/websocket.py" $PLAIN

# umilib's client: against umilib's server over each version, WebSocket included.
case_run umilib-http1.1 "'status: 200' 'over HTTP/1.1'" "$TOOL" client "$PLAIN_URL/"
case_run umilib-http1.1-echo "'status: 200' '^posted'" "$TOOL" client "$PLAIN_URL/echo" --method POST --data posted
case_run umilib-https-http2 "'status: 200' 'over HTTP/2'" "$TOOL" client "https://127.0.0.1:$SECURE/" --version 2 --name $NAME --ca "$WORK/root.pem"
case_run umilib-http3 "'status: 200' 'over HTTP/3'" "$TOOL" client "https://127.0.0.1:$SECURE/" --version 3 --insecure
case_run umilib-websocket-http1.1 "'status: 101' 'echo: over one' 'websocket closed: 1000'" "$TOOL" client "ws://127.0.0.1:$PLAIN/chat" --websocket "over one"
case_run umilib-websocket-http2 "'status: 200' 'echo: over two' 'websocket closed: 1000'" "$TOOL" client "wss://127.0.0.1:$SECURE/chat" --version 2 --name $NAME --ca "$WORK/root.pem" --websocket "over two"
case_run umilib-websocket-http3 "'status: 200' 'echo: over three' 'websocket closed: 1000'" "$TOOL" client "wss://127.0.0.1:$SECURE/chat" --version 3 --insecure --websocket "over three"

# umilib's client against Python's http.server.
mkdir "$WORK/site" && printf 'served by python\n' >"$WORK/site/index.txt"
"$PYTHON" -I -m http.server 24702 --bind 127.0.0.1 --directory "$WORK/site" >"$WORK/python-server.log" 2>&1 &
sleep 1
case_run umilib-to-python-http-server "'status: 200' 'served by python'" "$TOOL" client "http://127.0.0.1:24702/index.txt"

echo "server logs: $(grep -c '^request:' "$WORK/plain.log") + $(grep -c '^request:' "$WORK/secure.log") requests"
if [ "$FAILED" -ne 0 ]; then
    echo "$FAILED FAILED"
    exit 1
fi
echo "all ok"
