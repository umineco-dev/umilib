#!/bin/sh
# Runs umilib's FTP (examples/ftp.rs) against itself, against curl and
# Python's ftplib, and in Docker against vsftpd of Debian; prints "ok NAME"
# or "FAILED NAME" for each case:
#   DOCKER=/Applications/Docker.app/Contents/Resources/bin/docker sh examples/ftp.sh
set -u
DOCKER=${DOCKER:-docker}
cargo build -q --release --example ftp --features protocol-ftp || exit 1
TOOL=$PWD/target/release/examples/ftp
WORK=$(mktemp -d)
CONTAINER=umilib-ftp-$$
trap '"$DOCKER" stop $CONTAINER >/dev/null 2>&1; kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
PORT=25021
FAILED=0

"$TOOL" server $PORT --passive 30000-30099 >"$WORK/server.log" 2>&1 &
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

put() { # file, arguments...
    file=$1
    shift
    "$TOOL" client "$@" <"$file"
}

head -c 100000 /dev/urandom >"$WORK/random.bin"
printf 'uploaded by umilib\r\n' >"$WORK/upload.txt"

# Itself: EPSV and PASV, MLSD, SIZE and MDTM, RETR and STOR.
case_run self-list "'reply: PWD -> 257' 'entry: type=file;size=13;' 'reply: MLSD -> 226' 'reply: QUIT -> 221'" "$TOOL" client 127.0.0.1 $PORT anonymous guest --list
case_run self-size "'size: 65536' 'mdtm: 20231114221320'" "$TOOL" client 127.0.0.1 $PORT anonymous guest --size data.bin
case_run self-get "'Hello, FTP!' 'reply: RETR -> 226'" "$TOOL" client 127.0.0.1 $PORT anonymous guest --get hello.txt
case_run self-put-pasv "'reply: PASV -> 227' 'reply: STOR -> 226'" put "$WORK/upload.txt" 127.0.0.1 $PORT anonymous guest --put upload.txt --pasv
case_run self-get-stored "'uploaded by umilib'" "$TOOL" client 127.0.0.1 $PORT anonymous guest --get upload.txt
check self-server-log "$WORK/server.log" "command: EPSV" "command: PASV" "stored: upload.txt 20 octets"

# curl and Python's ftplib against the server.
case_run curl-list "'hello.txt' 'data.bin'" curl -sS ftp://127.0.0.1:$PORT/
case_run curl-get "'Hello, FTP!'" curl -sS ftp://127.0.0.1:$PORT/hello.txt
case_run curl-get-pasv "'Hello, FTP!'" curl -sS --disable-epsv ftp://127.0.0.1:$PORT/hello.txt
case_run curl-put "'exit: 0'" status curl -sS -T "$WORK/random.bin" ftp://127.0.0.1:$PORT/random.bin
curl -sS ftp://127.0.0.1:$PORT/random.bin -o "$WORK/random.back" 2>"$WORK/curl-get-back.out"
if cmp -s "$WORK/random.bin" "$WORK/random.back"; then echo "ok curl-put-get-back"; else echo "FAILED curl-put-get-back"; FAILED=$((FAILED + 1)); fi
case_run curl-rest "'^FTP!'" curl -sS -r 7- ftp://127.0.0.1:$PORT/hello.txt
case_run python-ftplib "'pwd /' 'size 65536' 'files .*hello.txt' 'facts file 13' 'stored 8' '221'" python3 -I -c "
import ftplib, io
client = ftplib.FTP()
client.connect('127.0.0.1', $PORT, timeout=10)
client.login('anonymous', 'guest@example.com')
print('pwd', client.pwd())
print('size', client.size('data.bin'))
print('files', client.nlst())
facts = dict(client.mlsd())
print('facts', facts['hello.txt']['type'], facts['hello.txt']['size'])
client.storbinary('STOR python.txt', io.BytesIO(b'from ftp'))
out = io.BytesIO()
client.retrbinary('RETR python.txt', out.write)
print('stored', len(out.getvalue()))
print(client.quit())"
# RFC 2577 §3: PORT to another host than the client is refused.
case_run bounce-refused "'504'" python3 -I -c "
import ftplib
client = ftplib.FTP()
client.connect('127.0.0.1', $PORT, timeout=10)
client.login('anonymous', 'guest')
try:
    client.sendcmd('PORT 10,0,0,9,7,138')
except ftplib.error_perm as error:
    print(error)"

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
# vsftpd of a user tim of the password secret, its passive ports published, writing allowed.
"$DOCKER" run --rm -d --name $CONTAINER -p 127.0.0.1:2121:21 -p 127.0.0.1:31000-31009:31000-31009 umilib-mail-interop sh -c "
useradd -m tim && echo tim:secret | chpasswd && printf 'Hello from vsftpd\r\n' >/home/tim/hello.txt && chown tim /home/tim/hello.txt
printf 'listen=YES\nlisten_ipv6=NO\nanonymous_enable=NO\nlocal_enable=YES\nwrite_enable=YES\nseccomp_sandbox=NO\npasv_enable=YES\npasv_min_port=31000\npasv_max_port=31009\npasv_address=127.0.0.1\nsecure_chroot_dir=/var/run/vsftpd/empty\npam_service_name=vsftpd\n' >/etc/vsftpd.conf
mkdir -p /var/run/vsftpd/empty && vsftpd /etc/vsftpd.conf" >/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10; do
    "$DOCKER" exec $CONTAINER pgrep -x vsftpd >/dev/null 2>&1 && break
    sleep 1
done
sleep 1

case_run vsftpd-list "'reply: PWD -> 257' 'hello.txt' 'reply: LIST -> 226'" "$TOOL" client 127.0.0.1 2121 tim secret --list
case_run vsftpd-get "'Hello from vsftpd' 'reply: RETR -> 226'" "$TOOL" client 127.0.0.1 2121 tim secret --get hello.txt
case_run vsftpd-get-pasv "'reply: PASV -> 227' 'Hello from vsftpd'" "$TOOL" client 127.0.0.1 2121 tim secret --get hello.txt --pasv
case_run vsftpd-put "'reply: STOR -> 226'" put "$WORK/random.bin" 127.0.0.1 2121 tim secret --put random.bin
case_run vsftpd-size "'size: 100000'" "$TOOL" client 127.0.0.1 2121 tim secret --size random.bin
"$DOCKER" exec $CONTAINER cat /home/tim/random.bin >"$WORK/vsftpd.back"
if cmp -s "$WORK/random.bin" "$WORK/vsftpd.back"; then echo "ok vsftpd-stored"; else echo "FAILED vsftpd-stored"; FAILED=$((FAILED + 1)); fi
case_run vsftpd-wrong "'error: PASS'" "$TOOL" client 127.0.0.1 2121 tim wrong --list

[ $FAILED -eq 0 ] && echo "all passed" || echo "$FAILED FAILED"
exit $FAILED
