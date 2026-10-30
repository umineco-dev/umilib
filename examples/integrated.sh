#!/bin/sh
# Runs the integrated example (examples/integrated.rs): an authorization server, an API and
# SMTP, IMAP and POP3 servers in two worker processes, against curl, Python's standard library
# (examples/integrated.py: the code flow with PKCE, smtplib, imaplib and poplib with
# OAUTHBEARER) and this crate's own OAuth client; then, with Docker, the client against
# Keycloak. Prints "ok NAME" or "FAILED NAME" for each case:
#   DOCKER=/Applications/Docker.app/Contents/Resources/bin/docker sh examples/integrated.sh
set -u
DOCKER=${DOCKER:-docker}
# Docker Desktop finds its credential helper next to its binary.
case $DOCKER in */*) PATH=$(dirname "$DOCKER"):$PATH ;; esac
FEATURES=auth-oauth,auth-sasl-oauthbearer,codec-mail,platform-runtime,protocol-http-v1,protocol-imap-v4,protocol-pop-v3,protocol-smtp,service
cargo build -q --release --example integrated --features $FEATURES || exit 1
BIN=$PWD/target/release/examples/integrated
HELPER="python3 $PWD/examples/integrated.py"
WORK=$(mktemp -d)
CONTAINER=umilib-keycloak-$$
AUTH=29080 API=29081 SMTP=22525 IMAP=21143 POP=21110 KEYCLOAK=28180
ISSUER=http://127.0.0.1:$AUTH
METADATA=$ISSUER/.well-known/oauth-authorization-server
trap '"$DOCKER" stop $CONTAINER >/dev/null 2>&1; kill $SERVER 2>/dev/null; sleep 1; rm -rf "$WORK"' EXIT
FAILED=0

"$BIN" serve --auth $AUTH --api $API --smtp $SMTP --imap $IMAP --pop $POP --workers 2 --state "$WORK/state" >"$WORK/server.log" 2>&1 &
SERVER=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    curl -s -o /dev/null http://127.0.0.1:$API/.well-known/oauth-protected-resource && break
    sleep 0.3
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

json() { # file, member
    python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

# The documents of RFC 8414 and RFC 9728, and the challenges of RFC 6750 §3.
case_run metadata-server "'\"issuer\":\"$ISSUER\"' '\"code_challenge_methods_supported\":\[\"S256\"\]' 'authorization_response_iss_parameter_supported\":true'" curl -s $METADATA
case_run metadata-resource "'\"resource\":\"http://127.0.0.1:$API\"' '\"authorization_servers\":\[\"$ISSUER\"\]'" curl -s http://127.0.0.1:$API/.well-known/oauth-protected-resource
case_run api-unauthenticated "'401 Unauthorized' 'www-authenticate: Bearer realm=\"umilib\", resource_metadata=' 'www-authenticate: DPoP realm=\"umilib\", algs='" curl -s -i http://127.0.0.1:$API/api/whoami

# Client credentials with curl (RFC 6749 §4.4), and the API in two processes.
curl -s -u service:service-secret -d grant_type=client_credentials $ISSUER/token >"$WORK/service.json"
check client-credentials-curl "$WORK/service.json" '"token_type":"Bearer"' '"scope":"api"'
SERVICE=$(json "$WORK/service.json" access_token)
# Connections in parallel, in rounds, until two worker processes answered (the kernel spreads
# the connections of a shared listener, without promising an order). Only the curls are waited
# for: a bare `wait` would also wait for the server.
: >"$WORK/api.out"
for round in 1 2 3 4 5; do
    PIDS=
    for index in 1 2 3 4 5 6 7 8; do
        curl -s -H "Authorization: Bearer $SERVICE" http://127.0.0.1:$API/api/whoami >"$WORK/api-$round-$index.out" &
        PIDS="$PIDS $!"
    done
    for pid in $PIDS; do wait "$pid"; done
    for index in 1 2 3 4 5 6 7 8; do cat "$WORK/api-$round-$index.out"; echo; done >>"$WORK/api.out"
    [ "$(grep -o '"process":[0-9]*' "$WORK/api.out" | sort -u | wc -l)" -ge 2 ] && break
done
check api-bearer "$WORK/api.out" '"subject":"service"'
if [ "$(grep -o '"process":[0-9]*' "$WORK/api.out" | sort -u | wc -l)" -ge 2 ]; then echo "ok api-two-workers"; else echo "FAILED api-two-workers"; FAILED=$((FAILED + 1)); fi
case_run api-repeated-authorization "'HTTP/1.1 400'" curl -s -i -H "Authorization: Bearer $SERVICE" -H "Authorization: Bearer $SERVICE" http://127.0.0.1:$API/api/whoami
case_run api-mail-needs-mail-scope "'HTTP/1.1 403' 'insufficient_scope'" curl -s -i -H "Authorization: Bearer $SERVICE" http://127.0.0.1:$API/api/mail
case_run client-credentials-wrong-secret "'HTTP/1.1 401' 'www-authenticate: Basic' 'invalid_client'" curl -s -i -u service:wrong -d grant_type=client_credentials $ISSUER/token
case_run token-get-refused "'invalid_request'" curl -s $ISSUER/token

# The code flow with PKCE of Python's standard library, and mail with its tokens.
$HELPER code $ISSUER alice wonderland "api mail" >"$WORK/alice.json" 2>&1
check code-python-alice "$WORK/alice.json" '"token_type":"Bearer"' '"refresh_token"'
$HELPER code $ISSUER bob builder "api mail" >"$WORK/bob.json" 2>&1
check code-python-bob "$WORK/bob.json" '"token_type":"Bearer"'
ALICE=$(json "$WORK/alice.json" access_token) BOB=$(json "$WORK/bob.json" access_token)
case_run code-wrong-password "'AssertionError'" $HELPER code $ISSUER alice wrong "api"
case_run smtp-python "'sent: Hello Bob'" $HELPER smtp $SMTP "$ALICE" alice bob "Hello Bob"
case_run smtp-bad-token "'535'" $HELPER smtp $SMTP "x$ALICE" alice bob "Never"
case_run smtp-spoofed-sender "'550'" $HELPER smtp $SMTP "$ALICE" bob bob "Spoofed"
case_run smtp-unknown-recipient "'550'" $HELPER smtp $SMTP "$ALICE" alice nobody "Lost"
case_run imap-python "'select: OK 1' 'fetch: Subject: Hello Bob'" $HELPER imap $IMAP "$BOB"
case_run imap-bad-token "'AUTHENTICATIONFAILED'" $HELPER imap $IMAP "x$BOB"
case_run pop3-python "'auth: +OK' 'stat: 1 ' 'retr: Subject: Hello Bob'" $HELPER pop3 $POP "$BOB"
case_run api-mail "'\"user\":\"bob\"' '\"messages\":\[\"Hello Bob\"\]'" curl -s -H "Authorization: Bearer $BOB" http://127.0.0.1:$API/api/mail
case_run mail-scope-required "'535'" $HELPER smtp $SMTP "$SERVICE" service bob "No mail scope"
check server-mail "$WORK/server.log" 'smtp: alice sent "Hello Bob" to 1' 'imap: bob authenticated' 'pop3: bob authenticated'

# Refresh tokens rotate; a replaced one used again revokes the grant (RFC 9700 §4.14.2).
REFRESH=$(json "$WORK/alice.json" refresh_token)
curl -s -d grant_type=refresh_token -d client_id=cli --data-urlencode "refresh_token=$REFRESH" $ISSUER/token >"$WORK/refreshed.json"
check refresh "$WORK/refreshed.json" '"refresh_token"'
case_run refresh-reuse "'invalid_grant'" curl -s -d grant_type=refresh_token -d client_id=cli --data-urlencode "refresh_token=$REFRESH" $ISSUER/token
case_run refresh-revoked-grant "'invalid_grant'" curl -s -d grant_type=refresh_token -d client_id=cli --data-urlencode "refresh_token=$(json "$WORK/refreshed.json" refresh_token)" $ISSUER/token

# This crate's client: the device grant, DPoP, introspection and revocation.
"$BIN" device $METADATA cli --scope api >"$WORK/device.out" 2>&1 &
DEVICE=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do grep -q user_code "$WORK/device.out" && break; sleep 0.3; done
$HELPER verify $ISSUER "$(grep user_code: "$WORK/device.out" | cut -d' ' -f2)" alice wonderland >"$WORK/verify.out" 2>&1
wait $DEVICE
check device "$WORK/device.out" 'user_code: [BCDFGHJKLMNPQRSTVWXZ]\{4\}-[BCDFGHJKLMNPQRSTVWXZ]\{4\}' 'token_type: Bearer'
case_run dpop "'token_type: DPoP' 'api: 200' '\"bound\":true'" "$BIN" client-credentials $METADATA service service-secret --dpop --api http://127.0.0.1:$API/api/whoami
BOUND=$(grep access_token: "$WORK/dpop.out" | cut -d' ' -f2)
case_run dpop-as-bearer "'401' 'www-authenticate: DPoP' 'invalid_token'" curl -s -i -H "Authorization: Bearer $BOUND" http://127.0.0.1:$API/api/whoami
# Alice's grant was revoked by the reuse above; Bob's is live.
case_run introspect "'active: true, sub: bob'" "$BIN" introspect $METADATA api api-secret "$BOB"
case_run introspect-revoked-grant "'active: false'" "$BIN" introspect $METADATA api api-secret "$ALICE"
case_run revoke "'HTTP/1.1 200'" curl -s -i -d client_id=cli --data-urlencode "token=$BOB" $ISSUER/revoke
case_run introspect-revoked "'active: false'" "$BIN" introspect $METADATA api api-secret "$BOB"
case_run console "'Sign in'" curl -s $ISSUER/
case_run console-start "'302' 'location: $ISSUER/authorize?'" curl -s -i $ISSUER/console/start

# Keycloak as the authorization server of this crate's client.
if "$DOCKER" image inspect quay.io/keycloak/keycloak:26.4 >/dev/null 2>&1; then
    "$DOCKER" run --rm -d --name $CONTAINER -p 127.0.0.1:$KEYCLOAK:8080 \
        -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -e KC_HOSTNAME=http://127.0.0.1:$KEYCLOAK \
        -v "$PWD/examples/integrated-realm.json:/opt/keycloak/data/import/realm.json:ro" \
        quay.io/keycloak/keycloak:26.4 start-dev --import-realm --features=dpop >/dev/null
    KMETADATA=http://127.0.0.1:$KEYCLOAK/realms/demo/.well-known/oauth-authorization-server
    for _ in $(seq 1 120); do curl -s -o /dev/null -f $KMETADATA && break; sleep 1; done
    case_run keycloak-client-credentials "'issuer: http://127.0.0.1:$KEYCLOAK/realms/demo' 'token_type: Bearer'" "$BIN" client-credentials $KMETADATA umilib-service umilib-secret
    case_run keycloak-introspect "'active: true'" "$BIN" introspect $KMETADATA umilib-resource resource-secret "$(grep access_token: "$WORK/keycloak-client-credentials.out" | cut -d' ' -f2)"
    case_run keycloak-dpop "'token_type: DPoP'" "$BIN" client-credentials $KMETADATA umilib-service umilib-secret --dpop
    case_run keycloak-wrong-secret "'invalid_client\|unauthorized_client'" "$BIN" client-credentials $KMETADATA umilib-service wrong
else
    echo "skipped keycloak: no image quay.io/keycloak/keycloak:26.4"
fi

[ $FAILED -eq 0 ] && echo "all passed" || { echo "$FAILED failed"; exit 1; }
