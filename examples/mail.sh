#!/bin/sh
# Runs umilib's SMTP, POP3 and IMAP (examples/smtp.rs, pop3.rs, imap.rs)
# against themselves, against curl and Python's smtplib, poplib and imaplib,
# and in Docker against Postfix and Dovecot of Debian: the client delivers a
# message to Postfix, reads it back through Dovecot by POP3 and IMAP, and
# Postfix relays a message to the server. Prints "ok NAME" or "FAILED NAME"
# for each case:
#   DOCKER=/Applications/Docker.app/Contents/Resources/bin/docker sh examples/mail.sh
set -u
DOCKER=${DOCKER:-docker}
FEATURES=protocol-smtp,protocol-pop-v3,protocol-imap-v4,hash-md-v5,secret
cargo build -q --release --example smtp --example pop3 --example imap --features $FEATURES || exit 1
BIN=$PWD/target/release/examples
WORK=$(mktemp -d)
CONTAINER=umilib-mail-$$
trap '"$DOCKER" rm -f $CONTAINER >/dev/null 2>&1; kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
SMTP=25525 POP3=25110 IMAP=25143
FAILED=0

"$BIN/smtp" server $SMTP --auth >"$WORK/smtp-server.log" 2>&1 &
"$BIN/pop3" server $POP3 >"$WORK/pop3-server.log" 2>&1 &
"$BIN/imap" server $IMAP >"$WORK/imap-server.log" 2>&1 &
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

status() { # command...: runs it, then prints its exit status
    "$@"
    echo "exit: $?"
}

case_run() { # name, patterns, command...
    name=$1 patterns=$2
    shift 2
    "$@" >"$WORK/$name.out" 2>&1
    # shellcheck disable=SC2086
    eval "set -- $patterns"
    check "$name" "$WORK/$name.out" "$@"
}

message() { # subject
    printf 'From: umilib <a@client.test>\r\nTo: Tim <tim@mail.test>\r\nSubject: %s\r\n\r\nHello from umilib.\r\n.A line that begins with a period.\r\n' "$1"
}

smtp_client() { # subject, arguments...
    subject=$1
    shift
    message "$subject" | "$BIN/smtp" client "$@"
}

# Itself.
case_run self-smtp "'reply: DATA end -> 250' 'sent'" smtp_client self 127.0.0.1 $SMTP --from a@client.test --to b@umilib.test
case_run self-smtp-auth "'reply: AUTH -> 235' 'sent'" smtp_client self-auth 127.0.0.1 $SMTP --from a@client.test --to b@umilib.test --auth tim:secret
case_run self-smtp-chunking "'reply: BDAT -> 250' 'sent'" smtp_client self-bdat 127.0.0.1 $SMTP --from a@client.test --to b@umilib.test --chunking
check self-smtp-server "$WORK/smtp-server.log" "subject: self" "subject: self-auth" "subject: self-bdat" "auth: tim"
case_run self-pop3 "'stat: 2 ' 'list: 1 ' 'Subject: first' '^.A line that begins'" "$BIN/pop3" client 127.0.0.1 $POP3 tim secret --retr 1
case_run self-pop3-apop "'stat: 2 ' 'quit'" "$BIN/pop3" client 127.0.0.1 $POP3 tim tanstaaf --apop
case_run self-pop3-auth "'stat: 2 ' 'quit'" "$BIN/pop3" client 127.0.0.1 $POP3 tim secret --auth
case_run self-imap "'completed: LOGIN OK' '\\* 2 EXISTS' 'Saying Hello' 'completed: LOGOUT OK'" "$BIN/imap" client 127.0.0.1 $IMAP tim secret
case_run self-imap-auth "'completed: AUTHENTICATE OK' 'completed: FETCH OK'" "$BIN/imap" client 127.0.0.1 $IMAP tim secret --auth --fetch 2

# curl and Python's standard library against the servers.
message curl >"$WORK/curl.eml"
case_run curl-smtp "'exit: 0'" status curl -sS smtp://127.0.0.1:$SMTP --mail-from a@curl.test --mail-rcpt b@umilib.test -T "$WORK/curl.eml"
case_run curl-smtp-auth "'exit: 0'" status curl -sS smtp://127.0.0.1:$SMTP --mail-from a@curl.test --mail-rcpt b@umilib.test -T "$WORK/curl.eml" -u tim:secret --login-options AUTH=PLAIN
check curl-smtp-server "$WORK/smtp-server.log" "mail: <a@curl.test>" "subject: curl"
case_run curl-pop3-list "'^1 [0-9]' '^2 [0-9]'" curl -sS pop3://127.0.0.1:$POP3/ -u tim:secret
case_run curl-pop3-retr "'Subject: first' '^.A line that begins'" curl -sS pop3://127.0.0.1:$POP3/1 -u tim:secret
case_run curl-imap-list "'LIST.*INBOX'" curl -sS imap://127.0.0.1:$IMAP/ -u tim:secret
case_run curl-imap-fetch "'Subject: Saying Hello'" curl -sS "imap://127.0.0.1:$IMAP/INBOX;UID=1" -u tim:secret
case_run curl-imap-search "'SEARCH 1 2'" curl -sS "imap://127.0.0.1:$IMAP/INBOX?ALL" -u tim:secret
case_run python-smtplib "'sent'" python3 -I -c "
import smtplib
with smtplib.SMTP('127.0.0.1', $SMTP, local_hostname='python.test', timeout=10) as client:
    client.login('tim', 'secret')
    client.sendmail('a@python.test', ['b@umilib.test'], b'Subject: python\r\n\r\n.dot\r\nbody\r\n')
print('sent')"
check python-smtplib-server "$WORK/smtp-server.log" "mail: <a@python.test>" "subject: python"
case_run python-poplib "'messages 2' 'Subject: second'" python3 -I -c "
import poplib
client = poplib.POP3('127.0.0.1', $POP3, timeout=10)
client.apop('tim', 'tanstaaf')
print('messages', client.stat()[0])
print(b'\n'.join(client.retr(2)[1]).decode())
client.quit()"
case_run python-imaplib "'exists 2' 'Subject: Re: Saying Hello' 'BYE'" python3 -I -c "
import imaplib
client = imaplib.IMAP4('127.0.0.1', $IMAP, timeout=10)
client.login('tim', 'secret')
print('exists', client.select('INBOX')[1][0].decode())
print(client.fetch('2', '(BODY.PEEK[HEADER])')[1][0][1].decode())
print(client.logout()[0])"

if ! "$DOCKER" info >/dev/null 2>&1; then
    echo "skipped: the cases of Docker"
    [ $FAILED -eq 0 ] && echo "all passed" || echo "$FAILED FAILED"
    exit $FAILED
fi

"$DOCKER" build -q -t umilib-mail-interop - >/dev/null <<'EOF' || exit 1
FROM debian:trixie
RUN echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections \
    && echo "postfix postfix/mailname string mail.test" | debconf-set-selections \
    && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       postfix dovecot-imapd dovecot-pop3d vsftpd procps mailutils ca-certificates
EOF
# A user tim of the password secret, Postfix delivering mail.test to /var/mail/tim and
# relaying the rest to umilib's server, Dovecot serving that mailbox, both without TLS.
"$DOCKER" run -d --name $CONTAINER -p 127.0.0.1:2525:25 -p 127.0.0.1:2110:110 -p 127.0.0.1:2143:143 \
    umilib-mail-interop sh -c "
useradd -m tim && echo tim:secret | chpasswd && touch /var/mail/tim && chown tim:mail /var/mail/tim && chmod 660 /var/mail/tim
postconf -e myhostname=mail.test mydestination='mail.test, localhost' inet_interfaces=all inet_protocols=ipv4 \
    mynetworks=0.0.0.0/0 relayhost=[host.docker.internal]:$SMTP default_transport=smtp relay_transport=smtp \
    smtp_tls_security_level=none smtpd_tls_security_level=none
printf 'auth_allow_cleartext = yes\nssl = no\nauth_mechanisms = plain login\n' >/etc/dovecot/conf.d/99-umilib.conf
postfix start && dovecot && sleep infinity" >/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10; do
    "$DOCKER" exec $CONTAINER sh -c 'pgrep -x master && pgrep -x dovecot' >/dev/null 2>&1 && break
    sleep 1
done
sleep 1
in_docker() { "$DOCKER" exec $CONTAINER "$@"; }

# The client delivers to Postfix, then reads the message back through Dovecot.
case_run postfix-smtp "'reply: DATA end -> 250' 'sent'" smtp_client "to postfix" 127.0.0.1 2525 --from a@client.test --to tim@mail.test
for _ in 1 2 3 4 5 6 7 8 9 10; do
    in_docker grep -q "to postfix" /var/mail/tim && break
    sleep 1
done
case_run postfix-delivered "'Subject: to postfix'" in_docker cat /var/mail/tim
case_run dovecot-pop3 "'stat: 1 ' 'Subject: to postfix' '^.A line that begins'" "$BIN/pop3" client 127.0.0.1 2110 tim secret --retr 1
case_run dovecot-pop3-auth "'capability: SASL PLAIN' 'stat: 1 '" "$BIN/pop3" client 127.0.0.1 2110 tim secret --auth
case_run dovecot-imap "'completed: LOGIN OK' '\\* 1 EXISTS' 'to postfix' 'completed: LOGOUT OK'" "$BIN/imap" client 127.0.0.1 2143 tim secret
case_run dovecot-imap-auth "'completed: AUTHENTICATE OK' 'completed: FETCH OK'" "$BIN/imap" client 127.0.0.1 2143 tim secret --auth
case_run dovecot-imap-wrong "'NO'" "$BIN/imap" client 127.0.0.1 2143 tim wrong

# Postfix relays to the server.
in_docker sh -c "printf 'Subject: from postfix\n\nrelayed\n' | sendmail -f root@mail.test bob@remote.test"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    grep -q "subject: from postfix" "$WORK/smtp-server.log" && break
    sleep 1
done
check postfix-relay "$WORK/smtp-server.log" "rcpt: <bob@remote.test>" "subject: from postfix"

[ $FAILED -eq 0 ] && echo "all passed" || echo "$FAILED FAILED"
exit $FAILED
