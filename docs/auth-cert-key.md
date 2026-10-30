# Keys of the X.509 public-key infrastructure: `umilib::auth::cert::key`

`auth-cert-key` (no `std`) reads, writes, generates and uses the keys of
certificates, certification requests, CRLs and OCSP: public keys
(`SubjectPublicKeyInfo`), private keys (PKCS #8), encrypted private keys,
and the identifiers of their algorithms.

```rust
use umilib::auth::cert::key::{HashAlgorithm, KeyAlgorithm, NamedCurve, PrivateKey, PublicKey, SignatureAlgorithm};

let key = PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut random)?;
let algorithm = SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256);
let signature = key.sign(&algorithm, b"to be signed", &mut random)?;
let public_key = key.public_key()?;
public_key.verify(&algorithm, b"to be signed", &signature)?;

let pem = key.to_pem()?;                                   // "-----BEGIN PRIVATE KEY-----", zeroized when dropped
let again = PrivateKey::from_pem(pem.expose())?;
let spki = public_key.to_der()?;                           // a SubjectPublicKeyInfo
```

## Algorithms

| Keys (`KeyAlgorithm`) | Signatures (`SignatureAlgorithm`) | Specifications |
| --- | --- | --- |
| `RSA` | `RSAPKCS1v15(hash)` (SHA-1, SHA-2, SHA-3), `RSAPSS(parameters)` | RFC 3279, RFC 4055, RFC 8017 |
| `RSAPSS(None or Some(parameters))` | `RSAPSS(parameters)` (with the key's parameters, if it has some) | RFC 4055 |
| `EC(curve)`: P-256, P-384, P-521; secp256k1 and brainpool when their features are enabled | `ECDSA(hash)` (SHA-1, SHA-2, SHA-3) | RFC 5480, RFC 5639, RFC 5758 |
| `Ed25519`, `Ed448` | `Ed25519`, `Ed448` | RFC 8410 |
| `X25519`, `X448` | (key agreement) | RFC 8410 |
| `MLDSA(set)`: 44, 65, 87 | `MLDSA(set)` | RFC 9881 |
| `SLHDSA(set)`, `HashSLHDSA(set)`: the 12 sets | `SLHDSA(set)`, `HashSLHDSA(set)` | RFC 9909 |
| `MLKEM(set)`: 512, 768, 1024 | (key encapsulation) | RFC 9935 |

The identifiers are checked as their specifications require:
- parameters must be absent, except for RSA ones;
- the key identifier rsaEncryption needs `NULL` parameters (RFC 3279 §2.3.1);
- the signature identifiers of RSASSA-PKCS1-v1_5 accept `NULL` and absent
  parameters alike, and write `NULL` (RFC 4055 §5);
- RSASSA-PSS signatures carry their parameters, which `PSSParameters`
  reads with the defaults of RFC 4055;
- an EC key must name its curve.

An identifier this module does not know is `KeyError::UnknownAlgorithm`.
One it knows whose crypto feature is disabled is `KeyError::Unsupported`.

`KeyAlgorithm::signs(signature)` tells which signatures a key makes:
- an RSA key makes both RSA paddings;
- an RSASSA-PSS key makes only RSASSA-PSS. If the key has parameters,
  signatures use the same hash functions and a salt at least as long
  (RFC 4055 §3.3).
- ML-DSA and SLH-DSA keys make only the signatures of their own set. An
  SLH-DSA key's identifier commits it to pure or to pre-hashed signing
  (RFC 9909).

Verifying or signing with any other pairing fails with `KeyError::Mismatch`.

Signatures are in the form of a certificate's `signatureValue`: DER
`Ecdsa-Sig-Value` for ECDSA, raw for the others. ML-DSA and SLH-DSA use the
empty context. HashML-DSA is not offered: RFC 9881 §8.3 forbids it in
certificates.

## Public keys

`PublicKey::from_der(spki)` (or `from_pem`, label `PUBLIC KEY`) reads a
`SubjectPublicKeyInfo` and validates the key:
- the DER of an RSA key;
- a point on its curve, compressed or not;
- an EdDSA point;
- the length of an X25519 or X448 key (every string of that length is a key);
- an ML-KEM key's modulus check (FIPS 203 §7.2).

The decoded key is kept, so `verify` does not decode it again.

RSA keys are bounded by `KeyLimits`, by default a modulus of 16384 bits and
an exponent of 64 bits, OpenSSL's limits. A key from an untrusted
certificate therefore cannot make one verification take minutes. A larger
key fails with `KeyError::Limit`; `PublicKey::new_with_limits` and
`from_info_with_limits` take other limits.
`SubjectPublicKeyInfo` is the borrowed view of the encoding.

## Private keys

`PrivateKey` holds the key of the crypto module for its algorithm
(`RSAPrivateKey`, `ECDSASigningKey<P256>`, `MLDSASigningKey<MLDSA65>`, ...),
which zeroizes itself when dropped. `key::<T>()` gives the typed key, and
`from_key(algorithm, key)` wraps one.

- **Making keys:** `generate(algorithm, random)` makes any key but RSA;
  `generate_rsa(algorithm, bits, random)` makes RSA keys, with the public
  exponent 65537.
- **Using them:** `public_key()` derives the public key, and
  `sign(algorithm, message, random)` signs. Signatures are hedged where the
  algorithm allows it, and RSASSA-PSS draws its salt from `random`.
- **Reading PKCS #8:**
  - `from_pkcs8_der` reads a `OneAsymmetricKey` (RFC 5958, v1 or v2) in DER;
  - `from_pkcs8_ber` also accepts BER, which RFC 5958 requires receivers to;
  - `from_pem` reads `PRIVATE KEY` (in BER), `RSA PRIVATE KEY` (PKCS #1)
    and `EC PRIVATE KEY` (RFC 5915).
- **Writing PKCS #8:** `to_pkcs8_der` and `to_pem` write v1. Both return a
  `Secret`, zeroized when dropped. The DER writer leaves no copy of a key in
  freed memory.
- **Debug output:** the `Debug` of `PrivateKey`, `PrivateKeyInfo`,
  `ECPrivateKey` and `SeedChoice` prints no secret.

The private key of each algorithm is encoded as its specification says:

| Algorithm | Encoding |
| --- | --- |
| RSA | PKCS #1 `RSAPrivateKey` |
| EC | `ECPrivateKey` with its curve and public key (RFC 5915 requires the curve) |
| X25519, X448, Ed25519, Ed448 | an OCTET STRING in the OCTET STRING (RFC 8410 §7) |
| SLH-DSA | the raw key |
| ML-DSA, ML-KEM | the CHOICE of RFC 9881 / RFC 9935: the seed, the expanded key, or both |

ML-DSA and ML-KEM keys are written as their seed when it is known (as
those RFCs recommend), and as their expanded key otherwise.

Reading checks every part of a key against the others, and refuses an
inconsistent key with `KeyError::Inconsistent` (or `InvalidKey`):
- a public key given with the private key (PKCS #8 v2, the `publicKey` of
  an `ECPrivateKey`) must be its own (an EC point may be given compressed);
- a seed and an expanded key given together must match (RFC 9881 §8.2,
  RFC 9935 §8);
- an expanded ML-DSA key must have the `t0` and `tr` of its `s1` and `s2`;
- an expanded ML-KEM key must pass the hash check of FIPS 203 §7.3 and a
  pairwise check (a secret encapsulated to its public key must decapsulate
  to the same secret);
- an SLH-DSA key must have the root of its seeds.

## Encrypted private keys

`to_encrypted_pkcs8_der(password, config, random)` and `to_encrypted_pem`
write an `EncryptedPrivateKeyInfo` (RFC 5958 §3) with PBES2 (RFC 8018):
PBKDF2 with HMAC and AES-CBC. `PBES2Config` holds the parameters:
- the PRF, `HashAlgorithm::SHA256` by default (SHA-1 and SHA-2 are allowed);
- `iterations`, 600 000;
- `salt_length`, 16;
- the cipher, `PBES2Cipher::AES256CBC` (or AES-128, AES-192);
- `maximum_iterations`, 10 000 000.

Writing refuses a salt shorter than 8 bytes and fewer than 1000 iterations
(RFC 8018 §4). It also refuses a salt longer than 64 bytes.

`from_encrypted_pkcs8_der(der, password, config)`, `from_encrypted_pkcs8_ber`
(which accepts BER, as RFC 5958 §3 requires) and `from_encrypted_pem`
refuse more iterations than `config.maximum_iterations`
(`KeyError::Parameters`), so a hostile file cannot make PBKDF2 run for
hours. A wrong password is `KeyError::Decryption`.

## Interoperability

The tests read the examples of RFC 8410, RFC 9881, RFC 9909 and RFC 9935,
including the inconsistent keys of RFC 9881 and RFC 9935, which are refused.
They also read keys, signatures and encrypted keys made by OpenSSL 3.5, and
check the public keys derived, the signatures and the deterministic
signatures (Ed25519, Ed448, RSA PKCS #1 v1.5) against OpenSSL's. OpenSSL
reads the keys umilib writes and verifies its signatures.

## C and Python

The C ABI (`include/umilib/auth/cert/key.h`) and the Python package
`umilib.auth.cert.key` provide:
- the algorithms, as handles: one constructor per kind, and `from_der` and
  `to_der` of the `AlgorithmIdentifier`;
- hash functions, curves, parameter sets and ciphers as numbers (Python
  `IntEnum`s);
- `PublicKey` and `PrivateKey` with the methods above. Calls that draw
  random bytes take a generator of `crypto::random`.
