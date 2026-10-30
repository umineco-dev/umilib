# JOSE and JWT: `umilib::protocol::jwt`

`protocol-jwt` (no `std`) reads, writes, signs, verifies, encrypts and
decrypts the objects of JSON Object Signing and Encryption, and validates
JSON Web Tokens:

| Object | Types | Specifications |
| --- | --- | --- |
| JWK, JWK Set | `JWK`, `JWKKey`, `JWKCurve`, `JWKSet` | RFC 7517, RFC 7518 §6, RFC 8037, RFC 8812, RFC 9964; thumbprints RFC 7638, RFC 9278 |
| JOSE Header | `JOSEHeader` | RFC 7515 §4, RFC 7516 §4 |
| JWS | `JWS`, `JWSSignature`, `JWSConfig`, `JWSAlgorithm` | RFC 7515, RFC 7518 §3, RFC 7797, RFC 8812, RFC 9864, RFC 9964 |
| JWE | `JWE`, `JWERecipient`, `JWEConfig`, `JWEAlgorithm`, `JWEEncryption`, `JWEEncryptedKey` | RFC 7516, RFC 7518 §4 and §5, RFC 8037 §3.2 |
| JWT | `JWT`, `JWTClaims`, `JWTValidation` | RFC 7519, RFC 8725 |

It does no I/O and reads no clock: the caller passes the time of a
validation and a generator of [`crypto::random`](crypto.md) for the
operations that need randomness. Errors are `JWTError`.

```rust
use umilib::protocol::jwt::{JOSEHeader, JWK, JWSAlgorithm, JWSConfig, JWT, JWTClaims, JWTValidation};

let key = JWK::from_json(br#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#)?;

// Signing.
let mut claims = JWTClaims::new();
claims.set_string("iss", "https://issuer.example");
claims.set_string("aud", "https://api.example");
claims.set_numeric_date("exp", now + 300);
let header = JOSEHeader::decode(br#"{"alg":"HS256","typ":"at+jwt"}"#)?;
let token = JWT::sign(&claims, &header, &key, &mut random)?;

// Verifying: the algorithms allowed, the issuer, the audience and the type expected.
let validation = JWTValidation {
    issuer: Some("https://issuer.example".into()),
    audience: Some("https://api.example".into()),
    token_type: Some("at+jwt".into()),
    ..JWTValidation::new(now)
};
let jwt = JWT::verify(&token, &key, &JWSConfig::new(&[JWSAlgorithm::HS256]), &validation)?;
assert_eq!(jwt.claims.issuer()?, Some("https://issuer.example"));
```

## JWK

- `JWK::from_json` reads a JWK and checks it as RFC 7517 and RFC 7518 §6
  require: the members of its key type (`EC`, `RSA`, `oct`, `OKP`, `AKP`),
  coordinates of the size of the curve and on it, RSA integers without
  leading zeros, all or none of the RSA private parameters (`oth` is
  refused), and an `alg` for `AKP` keys (RFC 9964 §4). `JWK::check` adds the
  rules that relate members: no repeated `key_ops`, `use` and `key_ops`
  consistent (RFC 7517 §4.3), private parameters of the public key, and an
  `x5c` whose first certificate holds the key. Unknown members are kept
  (`other`).
- `to_json`, `to_public` (without private parameters), `public_key` and
  `private_key` (the keys of [`auth::cert::key`](auth-cert-key.md)),
  `from_public_key` and `from_private_key` convert keys.
- `thumbprint(hash)` is the thumbprint of RFC 7638 (for `OKP` the members of
  RFC 8037 §2, for `AKP` those of RFC 9964 §6); `thumbprint_uri` is the URI
  of RFC 9278.
- `JWKSet::from_json` ignores the keys it cannot use (RFC 7517 §5): of
  unknown types or curves, missing required members, or with values out of
  the supported ranges. Only a set that is not an object with an array of
  objects in `keys` is an error. `find(kid)` gives the keys of a `kid`.
- `allows(operation, algorithm)` tells whether `alg`, `use` and `key_ops`
  allow an operation; signing, verifying, encrypting and decrypting check it
  and fail with `KeyMismatch` otherwise.

## JWS

```rust
use umilib::protocol::jwt::{JOSEHeader, JWS, JWSAlgorithm, JWSConfig};

let mut jws = JWS::new(payload.to_vec());
jws.sign(&JOSEHeader::decode(br#"{"alg":"ES256"}"#)?, None, &private, &mut random)?;
let compact = jws.to_compact()?;
let read = JWS::from_compact(&compact)?;
read.verify(&public, &JWSConfig::new(&[JWSAlgorithm::ES256]))?;
```

- The algorithms are those of RFC 7518 §3 (HS*, RS*, PS*, ES*), `ES256K`
  (RFC 8812), `Ed25519`, `Ed448` and the deprecated `EdDSA` (RFC 9864), and
  `ML-DSA-44/65/87` (RFC 9964). HMAC keys must be at least as long as the
  hash output and RSA keys at least 2048 bits (RFC 7518 §3.2, §3.3). ECDSA
  signatures are R || S of the size of the curve (RFC 7518 §3.4).
- `verify(key, config)` accepts the first signature whose algorithm
  `config` allows and fits the key and that verifies. It never accepts
  `none`; an Unsecured JWS is accepted only by the explicit
  `verify_unsecured` (RFC 8725 §3.1). Signatures with algorithms this module
  does not know are skipped. A JWS with more signatures than
  `JWSConfig::maximum_signatures` (16 by default) fails with `Limit` before
  any is verified.
- Serializations: compact (`from_compact`, `to_compact`), general and
  flattened JSON (`from_json`, `to_json`, `to_flattened_json`), each with the
  payload detached (RFC 7515 appendix F). The unencoded payload of RFC 7797
  (`"b64":false`, which must be in the protected header and listed in
  `crit`) is supported; in the compact serialization it must not contain
  `.`.
- `crit` (RFC 7515 §4.1.11) is in the protected header only, not empty, and
  lists, once each, parameters JOSE does not define that occur in the JOSE
  Header (any of its headers). `JWSConfig::critical` lists the extension
  parameters the application understands; `b64` is always understood. A
  producer understands what its own `crit` lists, so `sign` accepts it.

## JWE

```rust
use umilib::protocol::jwt::{JOSEHeader, JWE, JWEAlgorithm, JWEConfig, JWEEncryption};

let protected = JOSEHeader::decode(br#"{"alg":"ECDH-ES+A128KW","enc":"A128GCM"}"#)?;
let jwe = JWE::encrypt(plaintext, &protected, None, &[(&recipient_public, None)], None, &mut random)?;
let compact = jwe.to_compact()?;
let config = JWEConfig::new(&[JWEAlgorithm::ECDHESA128KW], &[JWEEncryption::A128GCM]);
let (plaintext, recipient) = JWE::from_compact(&compact)?.decrypt(&recipient_private, &config, &mut random)?;
```

| `alg` | Key | Header parameters |
| --- | --- | --- |
| `RSA-OAEP`, `RSA-OAEP-256`, `RSA-OAEP-384`, `RSA-OAEP-512` | RSA, 2048 bits or more (MGF1 over the same hash) | |
| `A128KW`, `A192KW`, `A256KW` | `oct` of 16, 24 or 32 bytes (RFC 3394) | |
| `dir` | `oct` of the size of the content key | |
| `ECDH-ES`, `ECDH-ES+A128KW`, `+A192KW`, `+A256KW` | `EC` on P-256, P-384, P-521, or `OKP` on X25519, X448 | `epk`; `apu`, `apv` read from the header |
| `A128GCMKW`, `A192GCMKW`, `A256GCMKW` | `oct` of 16, 24 or 32 bytes | `iv`, `tag` |
| `PBES2-HS256+A128KW`, `-HS384+A192KW`, `-HS512+A256KW` | `oct` holding the password | `p2s`, `p2c` (`p2c` read from the header if present) |

| `enc` | Content encryption |
| --- | --- |
| `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` | AES-CBC with HMAC (RFC 7518 §5.2) |
| `A128GCM`, `A192GCM`, `A256GCM` | AES-GCM, 96-bit IV, 128-bit tag |

- `JWE::encrypt(plaintext, protected, unprotected, recipients, aad,
  random)` encrypts for each recipient, a key and its per-recipient header.
  Each JOSE Header (the union of the three headers, which must not share a
  parameter) has the `alg` of its recipient and the `enc` all share. The
  direct algorithms (`dir`, `ECDH-ES`) take one recipient. The parameters
  the key management adds (`epk`, `iv`, `tag`, `p2s`, `p2c`) go into the
  protected header when there is one recipient without a per-recipient
  header (as the compact serialization needs), and into the per-recipient
  header otherwise. A generated PBES2 salt has 16 bytes, and the count
  without `p2c` is `JWEAlgorithm::PBES2_COUNT` (600 000).
- `zip` of `DEF` in the protected header compresses the plaintext with
  Deflate (RFC 7516 §4.1.3); it is refused in an unprotected header.
- `decrypt(key, config, random)` tries the recipients whose algorithms
  `config` allows and fit the key, and returns the plaintext and the
  recipient. Every failure to recover the key or to decrypt is
  `JWTError::Decryption`, and a key that fails to decrypt continues as a
  random key (RFC 7516 §11.5), so that nothing tells which step failed.
- `JWEConfig` bounds the work an attacker can cause: `maximum_recipients`
  (16 by default; a JWE with more fails with `Limit` before any key
  management), `maximum_pbes2_count` (1 000 000 by default, per recipient;
  at least 1000 iterations and 8 bytes of salt are required, RFC 7518
  §4.8.1, RFC 8725 §3.2), and compressed plaintexts are
  refused unless `compression` is set, then limited to
  `maximum_decompressed` bytes (1 MiB by default).
- Serializations: compact (`from_compact`, `to_compact`: one recipient,
  only a protected header, no JWE AAD), general and flattened JSON
  (`from_json`, `to_json`, `to_flattened_json`).
- `RSA1_5` (RSAES-PKCS1-v1_5) is not implemented: its padding oracles make
  it unsafe for decryption (RFC 8725 §3.2), and a JWE using it is refused
  like an algorithm the configuration does not allow. The JOSE algorithms of
  HPKE are drafts and are not implemented yet.
- The pieces are public: `JWEEncryption::encrypt` and `decrypt` (content
  encryption), and `JWEAlgorithm::encrypt_key`, `decrypt_key`, `derive` and
  `agreement_info` (the Concat KDF of RFC 7518 §4.6.2), `pbes2_key`, `wrap`
  and `unwrap`.

## JWT

Each form of JWT has its pair of functions, so that the application chooses
the form it accepts (RFC 8725 §3.12):

| Form | Producing | Consuming |
| --- | --- | --- |
| JWS | `JWT::sign` | `JWT::verify` |
| Unsecured JWS (RFC 7519 §6) | `JWT::sign` with `{"alg":"none"}` | `JWT::verify_unsecured` |
| JWE | `JWT::encrypt` | `JWT::decrypt` |
| Nested: a JWS inside a JWE (RFC 7519 §5.2) | `JWT::sign_and_encrypt` (sets `"cty":"JWT"`) | `JWT::decrypt_and_verify` |

A token of another form is refused (`Format` for the wrong serialization,
`Type` for a nested JWT where claims are expected). A JWT payload is always
base64url-encoded (`"b64":false` is refused).

`JWTValidation` checks, with `JWTValidation::validate(header, claims)`:

- `typ`, when `token_type` is set (explicit typing, RFC 8725 §3.11),
  compared as a media type: without regard to case and with or without
  `application/` (RFC 7515 §4.1.9);
- the types of the registered claims (`InvalidClaim`): `iss`, `sub` and
  `jti` strings, `aud` a string or strings, `exp`, `nbf` and `iat`
  NumericDates (numbers of seconds, possibly with a fraction);
- `exp` and `nbf` against `now`, give or take `leeway` seconds (`Expired`,
  `NotYetValid`);
- `iss` and `sub`, when `issuer` and `subject` are set;
- `aud`: when `audience` is set, `aud` must hold it; when it is not set, a
  token with `aud` is refused, as RFC 7519 §4.1.3 requires (`Audience`);
- the claims of `required` (`MissingClaim`).

The header a `JWT` holds is the one of its claims: that of the JWS (the
inner one for a nested JWT), or the JOSE Header of the JWE.

## C and Python

The C ABI (`ffi`) exports every type as a handle (`umilib_protocol_jwt_JWK`,
`umilib_protocol_jwt_JWS`, ...); algorithms cross as their index in
`JWSAlgorithm::ALL`, `JWEAlgorithm::ALL` and `JWEEncryption::ALL`. Header
parameters and claims are the JSON values of
[`codec::json`](codec-json.md). The Python package mirrors it in
`umilib.protocol.jwt`:

```python
from umilib.protocol.jwt import JOSEHeader, JWK, JWSAlgorithm, JWSConfig, JWT, JWTClaims, JWTValidation

claims = JWTClaims()
claims.set_string("iss", "https://issuer.example")
token = JWT.sign(claims, JOSEHeader.decode('{"alg":"HS256"}'), key, random)
jwt = JWT.verify(token, key, JWSConfig([JWSAlgorithm.HS256]), JWTValidation(now, issuer="https://issuer.example"))
```
