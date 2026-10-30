#!/bin/sh
# Makes the OCSP responses of the TLS tests (RFC 6960) for server-p256,
# with the certificates of make.sh:
#   docker run --rm -v "$PWD":/out -w /out debian:trixie sh ocsp.sh
# ocsp-good.der (good, signed by the root), ocsp-revoked.der (revoked,
# signed by the root) and ocsp-other.der (good, signed by another CA,
# which is not authorized to answer for the root's certificates). Each is
# current for 20 years from when it is made.
set -eu
apt-get update -qq >/dev/null && apt-get install -y -qq openssl >/dev/null
openssl version > ocsp-version.txt
work=$(mktemp -d)
for name in root other server-p256; do
    openssl x509 -inform DER -in "$name.der" -out "$work/$name.pem"
done
serial=$(openssl x509 -in "$work/server-p256.pem" -noout -serial | cut -d= -f2)
subject=$(openssl x509 -in "$work/server-p256.pem" -noout -subject -nameopt compat | sed 's/^subject=//')
openssl ocsp -issuer "$work/root.pem" -cert "$work/server-p256.pem" -no_nonce -reqout "$work/request.der"
respond() { # output, status line, signer
    printf '%s\n' "$2" > "$work/index.txt"
    openssl ocsp -index "$work/index.txt" -CA "$work/root.pem" -rsigner "$work/$3.pem" -rkey "$3.key" -rmd sha256 \
        -ndays 7300 -reqin "$work/request.der" -respout "$1"
    openssl ocsp -respin "$1" -resp_text -noverify > "${1%.der}.txt"
}
respond ocsp-good.der "$(printf 'V\t460101000000Z\t\t%s\tunknown\t%s' "$serial" "$subject")" root
respond ocsp-revoked.der "$(printf 'R\t460101000000Z\t260601000000Z,keyCompromise\t%s\tunknown\t%s' "$serial" "$subject")" root
respond ocsp-other.der "$(printf 'V\t460101000000Z\t\t%s\tunknown\t%s' "$serial" "$subject")" other
rm -r "$work"
