#!/bin/sh
# Makes the OpenSSL fixtures of the key tests: run in this directory, in Debian trixie (OpenSSL 3.5):
#   docker run --rm -v "$PWD":/work -w /work debian:trixie sh -c "apt-get -qq update && apt-get -qq install -y openssl >/dev/null && sh make.sh"
# For each key: NAME.key (PKCS #8 PEM as OpenSSL writes it), NAME.pub (its SubjectPublicKeyInfo PEM) and, for signing
# keys, NAME.ALGORITHM.sig (the signature of message.txt, raw bytes as in a certificate's signatureValue).
set -eu
printf 'umilib interoperability' > message.txt
openssl version > openssl-version.txt
key() { name=$1; shift; openssl genpkey "$@" -out "$name.key"; openssl pkey -in "$name.key" -pubout -out "$name.pub"; }
key rsa -algorithm RSA -pkeyopt rsa_keygen_bits:2048
key rsa-pss -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32
key p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
key p384 -algorithm EC -pkeyopt ec_paramgen_curve:P-384
key p521 -algorithm EC -pkeyopt ec_paramgen_curve:P-521
key ed25519 -algorithm ED25519
key ed448 -algorithm ED448
key x25519 -algorithm X25519
key x448 -algorithm X448
key mldsa65 -algorithm ML-DSA-65
key mlkem768 -algorithm ML-KEM-768
key slhdsa-sha2-128f -algorithm SLH-DSA-SHA2-128f
# Legacy encodings: PKCS #1 and RFC 5915.
openssl rsa -in rsa.key -traditional -out rsa.pkcs1.key
openssl ec -in p256.key -out p256.sec1.key
# Signatures.
openssl dgst -sha256 -sign rsa.key -out rsa.rsa-sha256.sig message.txt
openssl dgst -sha256 -sign rsa.key -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 -out rsa.pss-sha256.sig message.txt
openssl dgst -sha256 -sign rsa-pss.key -sigopt rsa_pss_saltlen:32 -out rsa-pss.pss-sha256.sig message.txt
openssl dgst -sha256 -sign p256.key -out p256.ecdsa-sha256.sig message.txt
openssl dgst -sha384 -sign p384.key -out p384.ecdsa-sha384.sig message.txt
openssl dgst -sha512 -sign p521.key -out p521.ecdsa-sha512.sig message.txt
openssl pkeyutl -sign -rawin -inkey ed25519.key -in message.txt -out ed25519.ed25519.sig
openssl pkeyutl -sign -rawin -inkey ed448.key -in message.txt -out ed448.ed448.sig
openssl pkeyutl -sign -rawin -inkey mldsa65.key -in message.txt -out mldsa65.mldsa65.sig
openssl pkeyutl -sign -rawin -inkey slhdsa-sha2-128f.key -in message.txt -out slhdsa-sha2-128f.slhdsa.sig
# Encrypted PKCS #8 with the password "umilib".
openssl pkcs8 -topk8 -in p256.key -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 2048 -passout pass:umilib -out p256.aes256-sha256.key
openssl pkcs8 -topk8 -in ed25519.key -v2 aes-128-cbc -v2prf hmacWithSHA1 -iter 1000 -passout pass:umilib -out ed25519.aes128-sha1.key
