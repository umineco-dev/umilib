#!/bin/sh
# Runs umilib's CoAP (examples/coap.rs) against libcoap 4.3 of Debian in
# Docker (coap-client and coap-server, without DTLS) and against itself;
# prints "ok NAME" or "FAILED NAME" for each case:
#   DOCKER=/Applications/Docker.app/Contents/Resources/bin/docker sh examples/coap.sh
set -u
DOCKER=${DOCKER:-docker}
cargo build -q --release --example coap --features platform-native,protocol-coap || exit 1
TOOL=$PWD/target/release/examples/coap
WORK=$(mktemp -d)
CONTAINER=umilib-coap-$$
trap '"$DOCKER" rm -f $CONTAINER >/dev/null 2>&1; kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
PORT=25683
LIBCOAP=25684
FAILED=0

"$TOOL" server $PORT >"$WORK/server.log" 2>&1 &
sleep 0.5

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

# Itself: piggybacked and Non-confirmable responses, blocks of the server's
# size and of a smaller one (RFC 7959 §2.4), observation, the Link Format.
case_run self-get "'code: 2.05' 'hello world'" "$TOOL" client 127.0.0.1 $PORT get /hello
case_run self-non "'code: 2.05' 'hello world'" "$TOOL" client 127.0.0.1 $PORT get /hello --non
case_run self-post "'code: 2.04' 'ping'" "$TOOL" client 127.0.0.1 $PORT post /echo --payload ping
case_run self-block "'code: 2.05' 'abcdefghijklmnopqrstuvwxyz'" "$TOOL" client 127.0.0.1 $PORT get /large
case_run self-block-smaller "'code: 2.05' 'stuvwxyzabcdefghijklmnopqrstuvwx$'" "$TOOL" client 127.0.0.1 $PORT get /large --block 64
case_run self-observe "'code: 2.05' 'notification: ' 'cancelled'" "$TOOL" client 127.0.0.1 $PORT get /counter --observe 2
case_run self-core "'</hello>;rt=example.hello;ct=0' '</counter>;obs'" "$TOOL" client 127.0.0.1 $PORT get /.well-known/core
case_run self-not-found "'code: 4.04'" "$TOOL" client 127.0.0.1 $PORT get /none
case_run self-method "'code: 4.05'" "$TOOL" client 127.0.0.1 $PORT put /hello

if ! "$DOCKER" info >/dev/null 2>&1; then
    echo "skipped: the cases of Docker"
    [ $FAILED -eq 0 ] && echo "all passed" || echo "$FAILED FAILED"
    exit $FAILED
fi

"$DOCKER" build -q -t umilib-coap-interop - >/dev/null <<'EOF' || exit 1
FROM debian:trixie
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libcoap3-bin
EOF
"$DOCKER" run -d --name $CONTAINER -p 127.0.0.1:$LIBCOAP:5683/udp umilib-coap-interop coap-server-notls -v 4 >/dev/null
sleep 1
in_docker() { "$DOCKER" exec $CONTAINER "$@"; }
HOST=$(in_docker getent ahostsv4 host.docker.internal | head -1 | cut -d' ' -f1)
SERVER=coap://$HOST:$PORT

# libcoap's client against the server.
case_run libcoap-get "'hello world'" in_docker coap-client-notls -m get $SERVER/hello
case_run libcoap-non "'hello world'" in_docker coap-client-notls -m get -N $SERVER/hello
case_run libcoap-post "'^ping$'" in_docker coap-client-notls -m post -e ping $SERVER/echo
case_run libcoap-block "'stuvwxyzabcdefghijklmnopqrstuvwx$'" in_docker coap-client-notls -m get $SERVER/large
case_run libcoap-block-smaller "'stuvwxyzabcdefghijklmnopqrstuvwx$'" in_docker coap-client-notls -m get -b 32 $SERVER/large
case_run libcoap-observe "'^[0-9][0-9]*$'" in_docker coap-client-notls -m get -s 3 $SERVER/counter
case_run libcoap-core "'</hello>;rt=example.hello;ct=0'" in_docker coap-client-notls -m get $SERVER/.well-known/core
case_run libcoap-not-found "'4.04'" in_docker coap-client-notls -m get $SERVER/none
case_run libcoap-token "'hello world'" in_docker coap-client-notls -m get -T umilib42 $SERVER/hello
check libcoap-server-log "$WORK/server.log" "request: 0.01 /hello" "request: 0.02 /echo" "request: 0.01 /large"

# The client against libcoap's server: its index, its observable time, and a PUT.
case_run self-libcoap-get "'code: 2.05' 'libcoap'" "$TOOL" client 127.0.0.1 $LIBCOAP get /
case_run self-libcoap-core "'code: 2.05' '</time>'" "$TOOL" client 127.0.0.1 $LIBCOAP get /.well-known/core
case_run self-libcoap-observe "'notification: ' 'cancelled'" "$TOOL" client 127.0.0.1 $LIBCOAP get /time --observe 2
case_run self-libcoap-put "'code: 2.0'" "$TOOL" client 127.0.0.1 $LIBCOAP put /example_data --payload umilib
case_run self-libcoap-get-put "'code: 2.05' 'umilib'" "$TOOL" client 127.0.0.1 $LIBCOAP get /example_data
case_run self-libcoap-non "'code: 2.05'" "$TOOL" client 127.0.0.1 $LIBCOAP get / --non

[ $FAILED -eq 0 ] && echo "all passed" || echo "$FAILED FAILED"
exit $FAILED
