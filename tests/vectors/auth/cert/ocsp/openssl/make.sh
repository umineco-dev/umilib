#!/bin/sh
# Makes the OpenSSL fixtures of the OCSP tests: run in this directory, in Debian trixie (OpenSSL 3.5):
#   docker run --rm -v "$PWD":/work -w /work debian:trixie sh -c "apt-get -qq update && apt-get -qq install -y openssl >/dev/null && sh make.sh"
# Certificates are DER (NAME.der) with their keys (NAME.key, PKCS #8 PEM); requests are request-NAME.der and
# responses response-NAME.der (DER).
set -eu
openssl version > openssl-version.txt
rm -f index.txt index.txt.*
touch index.txt
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key"; }
dates="-not_before 20260101000000Z -not_after 20360101000000Z"
# issue NAME ISSUER SERIAL EXTENSIONS SUBJECT: a certificate of NAME.key issued by ISSUER, also as NAME.pem.
issue() {
  openssl req -config openssl.cnf -new -key "$1.key" -subj "$5" -out "$1.csr.pem"
  openssl x509 -req -in "$1.csr.pem" -CA "$2.pem" -CAkey "$2.key" -sha256 $dates -set_serial "$3" -extfile openssl.cnf -extensions "$4" -out "$1.pem"
  openssl x509 -in "$1.pem" -outform DER -out "$1.der"
  rm "$1.csr.pem"
}

# A root, a responder it authorized, leaves of each status, and a responder of another root.
for name in root other-root; do key $name; done
openssl req -config openssl.cnf -new -x509 -key root.key -sha256 $dates -set_serial 1 -extensions root -out root.pem
openssl req -config openssl.cnf -new -x509 -key other-root.key -subj "/C=JP/O=umilib/CN=umilib Other Root CA" -sha256 $dates -set_serial 1 -extensions root -out other-root.pem
for name in root other-root; do openssl x509 -in $name.pem -outform DER -out $name.der; done
for name in responder other-responder good revoked unknown; do key $name; done
issue responder root 0x20 responder "/C=JP/O=umilib/CN=umilib OCSP Responder"
issue other-responder other-root 0x20 responder "/C=JP/O=umilib/CN=umilib OCSP Responder"
issue good root 0x10 leaf "/CN=good.example.com"
issue revoked root 0x11 leaf "/CN=revoked.example.com"
issue unknown root 0x12 leaf "/CN=unknown.example.com"
openssl ca -config openssl.cnf -cert root.pem -keyfile root.key -valid good.pem
openssl ca -config openssl.cnf -cert root.pem -keyfile root.key -revoke revoked.pem -crl_compromise 20260201000000Z

# Requests: one certificate with a nonce (SHA-1 CertID, the default), three without (SHA-256 CertID), and a signed one.
openssl ocsp -issuer root.pem -cert good.pem -reqout request-nonce.der
openssl ocsp -issuer root.pem -sha256 -cert good.pem -cert revoked.pem -cert unknown.pem -no_nonce -reqout request-multiple.der
openssl ocsp -issuer root.pem -cert good.pem -signer good.pem -signkey good.key -no_nonce -reqout request-signed.der

# Responses: by the root itself (repeating the nonce), by its responder (by name and by key), without nextUpdate,
# by a certificate the root did not authorize, and by the responder of another root.
respond() {
  out=$1; request=$2; signer=$3; shift 3
  openssl ocsp -index index.txt -CA root.pem -rsigner "$signer.pem" -rkey "$signer.key" -reqin "request-$request.der" -respout "response-$out.der" "$@"
}
respond direct nonce root -ndays 3650
respond delegated multiple responder -ndays 3650
respond key-id multiple responder -ndays 3650 -resp_key_id
respond no-next-update multiple root
respond unauthorized multiple good -ndays 3650
respond other multiple other-responder -ndays 3650
rm -f index.txt* *.pem

# Text dumps, for reading the fixtures.
for file in *.der; do
  case "$file" in
    request-*) openssl ocsp -reqin "$file" -req_text > "${file%.der}.txt" ;;
    response-*) openssl ocsp -respin "$file" -resp_text -noverify > "${file%.der}.txt" ;;
    *) openssl x509 -inform DER -in "$file" -noout -text > "${file%.der}.txt" ;;
  esac
done
