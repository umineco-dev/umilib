#!/bin/sh
# Makes the certificates of the TLS tests with OpenSSL:
#   docker run --rm -v "$PWD":/out -w /out debian:trixie sh make.sh
# a root CA (P-256), servers of server.example (and *.wild.example,
# 127.0.0.1, ::1) with each kind of key, a client, a server of another CA,
# and an expired server. Keys are PKCS #8 PEM, certificates DER.
set -eu
apt-get update -qq >/dev/null && apt-get install -y -qq openssl >/dev/null
openssl version > openssl-version.txt
dates="-not_before 20260101000000Z -not_after 20460101000000Z"
ca() {
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key"
    openssl req -config openssl.cnf -new -x509 -key "$1.key" -subj "/CN=$2" -sha256 $dates -set_serial 1 -extensions ca -outform DER -out "$1.der"
}
issue() { # name, issuer, extensions, subject, then the options of genpkey
    name=$1; issuer=$2; extensions=$3; subject=$4; shift 4
    openssl genpkey "$@" -out "$name.key"
    openssl req -config openssl.cnf -new -key "$name.key" -subj "/CN=$subject" -out "$name.csr.pem"
    openssl x509 -req -in "$name.csr.pem" -CA "$issuer.der" -CAform DER -CAkey "$issuer.key" -sha256 $dates -set_serial "0x$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')" -extfile openssl.cnf -extensions "$extensions" -outform DER -out "$name.der"
    rm "$name.csr.pem"
}
ca root "TLS Test Root"
ca other "Other Test Root"
issue server-p256 root server server.example -algorithm EC -pkeyopt ec_paramgen_curve:P-256
issue server-p384 root server server.example -algorithm EC -pkeyopt ec_paramgen_curve:P-384
issue server-p521 root server server.example -algorithm EC -pkeyopt ec_paramgen_curve:P-521
issue server-rsa root server server.example -algorithm RSA -pkeyopt rsa_keygen_bits:2048
issue server-pss root server server.example -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048
issue server-ed25519 root server server.example -algorithm ED25519
issue server-ed448 root server server.example -algorithm ED448
issue client root client client -algorithm EC -pkeyopt ec_paramgen_curve:P-256
issue stranger other server server.example -algorithm EC -pkeyopt ec_paramgen_curve:P-256
dates="-not_before 20200101000000Z -not_after 20210101000000Z"
issue expired root server server.example -algorithm EC -pkeyopt ec_paramgen_curve:P-256
for name in root other server-p256 server-p384 server-p521 server-rsa server-pss server-ed25519 server-ed448 client stranger expired; do
    openssl x509 -inform DER -in "$name.der" -noout -text > "$name.txt"
done
