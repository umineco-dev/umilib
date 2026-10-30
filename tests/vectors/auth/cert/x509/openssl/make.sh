#!/bin/sh
# Makes the OpenSSL fixtures of the X.509 tests: run in this directory, in Debian trixie (OpenSSL 3.5):
#   docker run --rm -v "$PWD":/work -w /work debian:trixie sh -c "apt-get -qq update && apt-get -qq install -y openssl >/dev/null && sh make.sh"
# Certificates are DER (NAME.der) with their keys (NAME.key, PKCS #8 PEM); CRLs are NAME.crl and requests NAME.csr (DER).
set -eu
openssl version > openssl-version.txt
rm -f index.txt index.txt.* crlnumber crlnumber.*
touch index.txt
echo 1000 > crlnumber
key() { openssl genpkey "$@"; }
dates="-not_before 20260101000000Z -not_after 20360101000000Z"

# A P-256 root, an RSA intermediate with every certificate extension, and leaves.
key -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root.key
openssl req -config openssl.cnf -new -x509 -key root.key -sha256 $dates -set_serial 1 -extensions root -outform DER -out root.der
key -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out intermediate.key
openssl req -config openssl.cnf -new -key intermediate.key -subj "/C=JP/O=umilib/OU=Testing+CN=umilib Intermediate CA" -multivalue-rdn -out intermediate.csr.pem
openssl x509 -req -in intermediate.csr.pem -CA root.der -CAform DER -CAkey root.key -sha256 $dates -set_serial 0x0123456789abcdef0123456789abcdef01234567 -extfile openssl.cnf -extensions intermediate -outform DER -out intermediate.der
leaf() {
  name=$1; shift
  openssl req -config openssl.cnf -new -key "$name.key" -subj "/C=JP/ST=東京都/L=Chiyoda/O=umilib/CN=www.example.com/emailAddress=user@example.com" -out "$name.csr.pem"
  openssl x509 -req -in "$name.csr.pem" -CA intermediate.der -CAform DER -CAkey intermediate.key "$@" -extfile openssl.cnf -outform DER -out "$name.der"
  rm "$name.csr.pem"
}
key -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key
leaf leaf -sha256 $dates -set_serial 2 -extensions leaf
key -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out leaf-pss.key
leaf leaf-pss -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -not_before 20260101000000Z -not_after 20510101000000Z -set_serial 3 -extensions leaf
key -algorithm ML-KEM-768 -out leaf-mlkem768.key
openssl req -config openssl.cnf -new -key leaf.key -subj "/CN=kem.example.com" -out kem.csr.pem
openssl x509 -req -in kem.csr.pem -force_pubkey leaf-mlkem768.key -CA intermediate.der -CAform DER -CAkey intermediate.key -sha256 $dates -set_serial 4 -extfile openssl.cnf -extensions kem -outform DER -out leaf-mlkem768.der
rm kem.csr.pem
key -algorithm X25519 -out leaf-x25519.key
openssl req -config openssl.cnf -new -key leaf.key -subj "/CN=x25519.example.com" -out x25519.csr.pem
openssl x509 -req -in x25519.csr.pem -force_pubkey leaf-x25519.key -CA intermediate.der -CAform DER -CAkey intermediate.key -sha256 $dates -set_serial 5 -extfile openssl.cnf -extensions agreement -outform DER -out leaf-x25519.der
rm x25519.csr.pem

# Self-signed certificates of each signature algorithm.
self() {
  name=$1; shift
  openssl req -config openssl.cnf -new -x509 -key "$name.key" -subj "/CN=$name" "$@" $dates -set_serial 7 -extensions self -outform DER -out "$name.der"
}
key -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out p384.key; self p384 -sha384
key -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out p521.key; self p521 -sha512
key -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key; self rsa -sha512
key -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha384 -pkeyopt rsa_pss_keygen_mgf1_md:sha384 -pkeyopt rsa_pss_keygen_saltlen:48 -out rsa-pss.key; self rsa-pss -sha384 -sigopt rsa_pss_saltlen:48
key -algorithm ED25519 -out ed25519.key; self ed25519
key -algorithm ED448 -out ed448.key; self ed448
key -algorithm ML-DSA-44 -out mldsa44.key; self mldsa44
key -algorithm ML-DSA-65 -out mldsa65.key; self mldsa65
key -algorithm ML-DSA-87 -out mldsa87.key; self mldsa87
key -algorithm SLH-DSA-SHA2-128s -out slhdsa-sha2-128s.key; self slhdsa-sha2-128s
key -algorithm SLH-DSA-SHAKE-128f -out slhdsa-shake-128f.key; self slhdsa-shake-128f

# CRLs: an empty one of the root, and one of the intermediate with revoked entries and their reasons.
openssl ca -config openssl.cnf -gencrl -cert root.der -keyfile root.key -out root.crl.pem
openssl crl -in root.crl.pem -outform DER -out root.crl
openssl x509 -inform DER -in leaf.der -out leaf.pem
openssl x509 -inform DER -in leaf-pss.der -out leaf-pss.pem
openssl x509 -inform DER -in intermediate.der -out intermediate.pem
openssl ca -config openssl.cnf -cert intermediate.pem -keyfile intermediate.key -revoke leaf.pem -crl_compromise 20260201000000Z
openssl ca -config openssl.cnf -cert intermediate.pem -keyfile intermediate.key -revoke leaf-pss.pem -crl_hold holdInstructionCallIssuer
openssl ca -config openssl.cnf -gencrl -cert intermediate.pem -keyfile intermediate.key -crlexts crl_extensions -out intermediate.crl.pem
openssl crl -in intermediate.crl.pem -outform DER -out intermediate.crl
rm -f root.crl.pem intermediate.crl.pem leaf.pem leaf-pss.pem intermediate.pem index.txt* crlnumber* intermediate.csr.pem

# Certification requests with attributes and extensions, and one without attributes.
for name in leaf rsa ed25519 mldsa65; do openssl req -config openssl.cnf -section csr -new -key "$name.key" -outform DER -out "$name.csr"; done
openssl req -config openssl.cnf -new -key ed448.key -subj "/CN=bare" -outform DER -out bare.csr

# Text dumps, for reading the fixtures.
for file in *.der; do openssl x509 -inform DER -in "$file" -noout -text > "${file%.der}.txt"; done
for file in *.crl; do openssl crl -inform DER -in "$file" -noout -text > "${file%.crl}.crl.txt"; done
for file in *.csr; do openssl req -inform DER -in "$file" -noout -text > "${file%.csr}.csr.txt"; done
