# Features

Every module of umilib is enabled by a Cargo feature. No feature is enabled by
default, so a crate pays only for what it uses.

## Names

The feature name is the module path joined by `-`:

| Feature | Module | Directory |
| --- | --- | --- |
| `bytes` | `umilib::bytes` | `src/bytes` |
| `platform-bench` | `umilib::platform::bench` | `src/platform/bench` |

- Enabling a feature also compiles its parent modules (`platform-bench` compiles
  `umilib::platform`, with only `bench` inside it).
- Enabling a parent enables all of its children (`platform` enables
  `platform-bench` and `platform-fuzz`).
- Versions are segments starting with `v`, and a decimal point is written `_`:
  `protocol-ip-v4` is IPv4 and `protocol-tls-v1_3` is TLS 1.3.
- Common spellings are aliases of the canonical name, for example
  `protocol-ipv4` for `protocol-ip-v4`. An alias enables exactly its canonical
  feature.
- `ffi` adds the C ABI of every other enabled module (see [ffi.md](ffi.md)).

There is no feature that enables everything; use `cargo build --all-features`
for that.

## `no_std`

Every module outside `umilib::platform` uses only `core` and `alloc`. A
`no_std` crate can use them as long as it provides a global allocator and a
panic handler. `platform` and its children use `std`.

## Currently available

| Feature | Contents |
| --- | --- |
| `bytes` | `Reader`, `Writer`, `Buffer`, `SliceWriter`, `Integer`, `BytesError`, `BitReader`, `BitWriter`, `BitQueue` |
| `calendar` | `Date`: the proleptic Gregorian calendar ([calendar.md](calendar.md)) |
| `codec-asn1-der`, `codec-asn1-ber` | ASN.1 DER and BER ([codec-asn1.md](codec-asn1.md)) |
| `codec-base-base16`, `-base32`, `-base58`, `-base64`, `-base85` | Binary-to-text encodings ([codec-base.md](codec-base.md)) |
| `codec-brotli` | Brotli (RFC 7932) with its static dictionary ([codec-brotli.md](codec-brotli.md)) |
| `codec-filter-delta`, `codec-filter-bcj` | Delta and BCJ filters ([codec-filter.md](codec-filter.md)) |
| `codec-deflate`, `codec-zlib`, `codec-gzip` | Deflate (RFC 1951), zlib (RFC 1950) and gzip (RFC 1952) ([codec-deflate.md](codec-deflate.md)) |
| `codec-huffman-canonical`, `codec-huffman-adaptive` | Canonical and adaptive Huffman coding ([codec-huffman.md](codec-huffman.md), [codec-compression.md](codec-compression.md)) |
| `codec-json` | JSON ([codec-json.md](codec-json.md)) |
| `codec-lz4` | LZ4 blocks and frames ([codec-lz4.md](codec-lz4.md)) |
| `codec-lzma` | LZMA (.lzma files) and raw LZMA2 ([codec-lzma.md](codec-lzma.md)) |
| `codec-xz` | .xz files ([codec-xz.md](codec-xz.md)) |
| `codec-zstandard` | Zstandard (RFC 8878) ([codec-zstandard.md](codec-zstandard.md)) |
| `codec-lz77`, `codec-lz78`, `codec-lzss` | LZ77 (with the window and match finder of the LZ77 formats), LZ78, LZSS ([codec-lz.md](codec-lz.md)) |
| `codec-pem` | PEM ([codec-pem.md](codec-pem.md)) |
| `codec-rle` | PackBits ([codec-rle.md](codec-rle.md)) |
| `codec-stringprep` | Stringprep (RFC 3454), Unicode 3.2 normalization, SASLprep (RFC 4013), LDAPPrep (RFC 4518) ([codec-stringprep.md](codec-stringprep.md)) |
| `crypto-aes`, `crypto-aria`, `crypto-camellia`, `crypto-seed`, `crypto-sm4` | Block ciphers with 128-bit blocks ([crypto.md](crypto.md)) |
| `crypto-gost-kuznyechik`, `crypto-gost-magma` | The GOST R 34.12-2015 block ciphers |
| `crypto-des`, `crypto-idea`, `crypto-rc2`, `crypto-rc4` | Legacy ciphers: DES and Triple DES, IDEA, RC2, RC4 |
| `crypto-mode-ecb`, `-cbc`, `-cfb`, `-ofb`, `-ctr`, `-xts`, `-gcm`, `-ccm`, `-siv`, `-gcmsiv`, `-kw` | The modes of the block ciphers, key wrapping (SP 800-38F) and PKCS #7 |
| `crypto-chacha20`, `crypto-poly1305`, `crypto-chacha20poly1305` | ChaCha20, XChaCha20, Poly1305 and their AEADs |
| `crypto-aegis`, `crypto-ascon` | AEGIS-128X and AEGIS-256X, Ascon-AEAD128 |
| `crypto-cmac`, `crypto-hmac` | CMAC and HMAC |
| `crypto-hkdf`, `crypto-pbkdf2`, `crypto-scrypt`, `crypto-argon2`, `crypto-kbkdf`, `crypto-kdftree`, `crypto-concatkdf` | Key derivation functions |
| `crypto-random` | The `Random` interface and the SP 800-90A DRBGs |
| `crypto-curve-p256`, `-p384`, `-p521`, `-secp256k1`, `-brainpool-p256r1`, `-brainpool-p384r1`, `-brainpool-p512r1`, `-curve25519`, `-curve448`, `-gost`, `-sm2` | The curves of the specifications ([crypto-public-key.md](crypto-public-key.md#curves)) |
| `crypto-ecdh`, `crypto-dh` | ECDH (SP 800-56A, RFC 7748) and finite-field Diffie-Hellman (RFC 7919, RFC 3526) |
| `crypto-ecdsa`, `crypto-eddsa`, `crypto-dsa`, `crypto-gostr3410` | ECDSA (FIPS 186-5, RFC 6979), EdDSA (RFC 8032), DSA (FIPS 186-4), GOST R 34.10-2012 |
| `crypto-rsa` | RSA: PKCS #1 v1.5 signatures, PSS and OAEP (RFC 8017) |
| `crypto-hpke` | HPKE (RFC 9180) |
| `crypto-sm2` | SM2 signatures, key exchange and encryption (GB/T 32918) |
| `crypto-sm9` | SM9 key exchange, key encapsulation and encryption (GM/T 0044.3, 0044.4) |
| `crypto-eccsi`, `crypto-dragonfly`, `crypto-srp` | ECCSI (RFC 6507), Dragonfly (RFC 7664), SRP-6a (RFC 5054) |
| `crypto-ibs-hess`, `-chacheon`, `-sm9` | Identity-based signatures: Hess, Cha–Cheon, SM9 (GM/T 0044.2) |
| `crypto-mlkem`, `crypto-mldsa`, `crypto-slhdsa` | ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) ([crypto-post-quantum.md](crypto-post-quantum.md)) |
| `crypto-hybrid` | The hybrid groups of RFC 10024: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 |
| `hash-sha-v1`, `-v2`, `-v3` | SHA-1, SHA-2, SHA-3 and SP 800-185 ([hash.md](hash.md)); aliases `hash-sha1`, `hash-sha2`, `hash-sha3` |
| `hash-blake-v2`, `-v3` | BLAKE2 and BLAKE3; aliases `hash-blake2`, `hash-blake3` |
| `hash-md-v4`, `-v5` | MD4 and MD5; aliases `hash-md4`, `hash-md5` |
| `hash-ripemd`, `hash-sm3`, `hash-streebog` | RIPEMD, SM3, Streebog |
| `hash-ascon` | Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128 and the permutation Ascon-p |
| `hash-siphash` | SipHash and HalfSipHash |
| `hash-xxhash-xxh32`, `-xxh64`, `-xxh3` | xxHash; aliases `hash-xxh32`, `hash-xxh64`, `hash-xxh3` |
| `hash-crc` | CRC of any width and the RevEng catalogue |
| `hash-adler32` | Adler-32 (RFC 1950) |
| `math-bigint` | Big integers `Uint`, `BoxedUint` ([math-bigint.md](math-bigint.md)) |
| `math-modular` | Modular arithmetic `Modulus`, `BoxedModulus` ([math-modular.md](math-modular.md)) |
| `math-ec` | Elliptic curves: Weierstrass, Montgomery and Edwards ([math-ec.md](math-ec.md)) |
| `math-pairing` | Pairings on BLS12-381, BN254, BN462 and the curve of SM9 ([math-pairing.md](math-pairing.md)) |
| `math-lattice` | Polynomial rings of module lattices and the NTT ([math-lattice.md](math-lattice.md)) |
| `secret` | `Choice`, `ConstantTimeEq`, `ConditionallySelectable`, `ConstantTimeTable`, `Zeroize`, `Secret` |
| `ffi` | The C ABI and its manifest |
| `runtime` | The asynchronous runtime without `std`: executors, channels, timers, I/O traits ([runtime.md](runtime.md)) |
| `service` | Services, rules, byte patterns and routers ([service.md](service.md)) |
| `auth-totp` | One-time passwords: HOTP (RFC 4226) and TOTP (RFC 6238) ([auth-totp.md](auth-totp.md)) |
| `auth-sasl-plain`, `-external`, `-anonymous`, `-scram`, `-oauthbearer` | SASL mechanisms: PLAIN (RFC 4616), EXTERNAL (RFC 4422), ANONYMOUS (RFC 4505), SCRAM-SHA-1/256 and -PLUS (RFC 5802, RFC 7677), OAUTHBEARER (RFC 7628) ([auth-sasl.md](auth-sasl.md)) |
| `auth-cert-key` | Keys and algorithm identifiers of X.509: SubjectPublicKeyInfo, PKCS #8, encrypted PKCS #8 ([auth-cert-key.md](auth-cert-key.md)) |
| `auth-cert-x509` | X.509 certificates, CRLs, names and extensions (RFC 5280) ([auth-cert-x509.md](auth-cert-x509.md)) |
| `auth-cert-csr` | Certification requests (PKCS #10, RFC 2986) ([auth-cert-csr.md](auth-cert-csr.md)) |
| `auth-cert-path` | Certification path building and validation (RFC 5280 §6, RFC 9618, RFC 9525) ([auth-cert-path.md](auth-cert-path.md)) |
| `auth-cert-ocsp` | OCSP requests and responses (RFC 6960, RFC 8954) ([auth-cert-ocsp.md](auth-cert-ocsp.md)) |
| `protocol-ethernet` | MAC addresses, EtherTypes, headers with VLAN tags, frame check sequences ([protocol-ethernet.md](protocol-ethernet.md)) |
| `protocol-arp` | ARP packets and the address cache (RFC 826, RFC 1122 §2.3.2, RFC 5227) ([protocol-arp.md](protocol-arp.md)) |
| `protocol-ip-v4`, `protocol-ip-v6` | IPv4 (RFC 791) and IPv6 (RFC 8200): headers, options and extension headers, fragmentation and reassembly; either enables `protocol::ip`, with addresses (RFC 4291, RFC 5952), the Internet checksum (RFC 1071, RFC 1624) and pseudo-headers ([protocol-ip.md](protocol-ip.md)); aliases `protocol-ipv4`, `protocol-ipv6` |
| `protocol-icmp-v4`, `protocol-icmp-v6` | ICMP (RFC 792, RFC 1122 §3.2.2) and ICMPv6 (RFC 4443) with Neighbor Discovery and the Neighbor Cache (RFC 4861, RFC 4191, RFC 8106); either enables `protocol::icmp`, with the multi-part extensions (RFC 4884) and the rate limit of errors ([protocol-icmp.md](protocol-icmp.md)); `protocol-icmp` enables both; aliases `protocol-icmpv4`, `protocol-icmpv6` |
| `protocol-udp` | UDP datagrams over IPv4 and IPv6 (RFC 768), the zero checksum of IPv6 tunnels (RFC 6935, RFC 6936), jumbograms (RFC 2675) and the rule that routes datagrams by endpoint ([protocol-udp.md](protocol-udp.md)) |
| `protocol-tcp` | TCP segments and options (RFC 9293, RFC 7323, RFC 2018), connections and listeners without I/O, the retransmission timer (RFC 6298), initial sequence numbers (RFC 6528), loss recovery (RFC 6675, RFC 6582), congestion control (NewReno, CUBIC), the defences of RFC 5961, ECN, and the rule that routes connections ([protocol-tcp.md](protocol-tcp.md)) |
| `protocol-jwt` | JWK, JWS, JWE and JWT (RFC 7515 to RFC 7519, RFC 8725) ([protocol-jwt.md](protocol-jwt.md)) |
| `platform-unix`, `platform-linux`, `platform-android`, `platform-darwin`, `platform-windows`, `platform-native` | The operating system layers: random bytes, sockets, pollers, completion ports ([platform.md](platform.md)) |
| `platform-runtime` | The thread pool, reactor, asynchronous sockets and supervisor of worker processes ([platform-runtime.md](platform-runtime.md)) |
| `platform-bench` | The benchmark harness |
| `platform-fuzz` | The fuzzing harness |
