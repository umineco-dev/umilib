# JOSE and JWT

How `umilib::protocol::jwt` (and the key wrapping and Concat KDF it uses)
is built. The user-facing description is `docs/protocol-jwt.md`.

## Shape

- **Files by role:** `algorithm.rs` (the enums and their names),
  `signature.rs` (JWS algorithms on keys), `content.rs` (content
  encryption), `key_management.rs` (JWE key management), and one file per
  object (`header.rs`, `jwk.rs`, `jws.rs`, `jwe.rs`, `jwt.rs`). The
  algorithms are methods of their enums, so that a new algorithm is a new
  variant and the arms of its methods.
- **Headers stay JSON:** `JOSEHeader` and `JWTClaims` keep their JSON
  object, in order, and read the registered parameters on demand. Unknown
  parameters survive a round trip, and a JWS keeps the base64url text of its
  protected header (`JWSSignature::protected`, `JWE::protected`), which is
  what the signature and the AAD cover: re-encoding a header could change it.
- **Keys:** `JWK` converts to the keys of `auth::cert::key` for signatures,
  so that JWS reuses the dispatch over curves, RSA, EdDSA and ML-DSA. JWE key
  agreement works on the raw coordinates (`agreement_public`) with
  `ECDH<C>` and `XDH<C>` directly.
- **One function per form of JWT** (`verify`, `decrypt`,
  `decrypt_and_verify`, `verify_unsecured`) instead of one that follows
  `cty` to any depth: RFC 8725 §3.12 asks for rules that keep the kinds of
  JWT apart, and an unbounded nesting is work an attacker chooses.

## Key management

- **Where the parameters go.** `epk`, `iv`, `tag`, `p2s` and `p2c` are made
  by the key management of each recipient, before the protected header is
  encoded. With one recipient without a per-recipient header they go into
  the protected header (the compact serialization has no other); otherwise
  into the per-recipient header. `p2c` given in the header is kept (the
  count is the caller's policy); a salt and an IV are always generated.
- **Indistinguishable failures** (RFC 7516 §11.5): a key that does not
  unwrap (RSA-OAEP, KW, GCMKW, PBES2) continues as a random CEK of the right
  size, and the content decryption then fails with the same `Decryption`
  error as a modified ciphertext. The tests decrypt with a generator seeded
  apart from that of the encryption (`decrypting()`): with the same seed, the
  "random" CEK equals the real one, and a wrong key appears to decrypt.
- **Unknown algorithms are skipped** when a JWS has several signatures or a
  JWE several recipients (RFC 7520 §5.13 has an RSA1_5 recipient beside
  others); a JWS or JWE with no usable entry fails with
  `AlgorithmNotAllowed`.
- **`crit`** names parameters of the JOSE Header, the union of the headers
  (RFC 7515 §4.1.11), so a listed parameter may be in an unprotected header;
  `crit` itself must be protected. The producer's own list counts as
  understood when it signs or encrypts.
- **JWK Sets** ignore every key that does not read, not only unknown types
  (RFC 7517 §5: missing members, values out of range).
- **The `alg` of a `dir` key** may be the content encryption algorithm: the
  key is the CEK (RFC 7520 §5.6 uses `"alg":"A128GCM"`).
- **Bounds:** a bound per recipient is not a bound per object: the JSON
  serializations may carry any number of recipients or signatures, each of
  which may cost a key derivation (PBES2, ECDH-ES) or a verification, and a
  recipient that fails does not stop the loop (RFC 7516 §11.5). Hence
  `JWEConfig::maximum_recipients` and `JWSConfig::maximum_signatures`,
  checked before any work. PBES2 needs 1000 to `maximum_pbes2_count`
  iterations and a salt of 8 bytes or more; Deflate output is limited and the stream must end with
  the plaintext (trailing bytes are refused).
- **Not implemented:** RSA1_5 (a padding oracle for decryption, RFC 8725
  §3.2), and the JOSE HPKE drafts, which wait for their RFC.

## Key wrapping and the Concat KDF

- `crypto::mode::kw::Wrapping<C>` is W and W⁻¹ of SP 800-38F in the indexed
  form of RFC 3394, over any block size: KW and KWP over 128-bit ciphers,
  TKW over 64-bit ones (a semiblock of 4 bytes). Lengths are checked once, in
  `Wrapping::check_length`, against the limits of SP 800-38F §5.3.1.
  `KW::new` and `KWP::new` refuse other block sizes: the integrity values
  are semiblocks of those sizes, and the step counter of a smaller block
  would not fit.
- `crypto::concatkdf::ConcatKDF<F>` takes any `AuxiliaryFunction`: a hash
  function, or every `PRF` (HMAC). It needs `crypto-hmac` because the hash
  module root is compiled with it (see feature-system.md).

## Vectors and their errors

- **Cookbook:** the `rfc7797/` examples do not follow RFC 7797 and are not
  stored; RFC 7797 is tested from its text. The input of `jwe/5_13` misspells
  its `enc`, so the tests read `enc` from the headers. `curve25519/ecdh-es`
  gives an ephemeral key in `encrypting_key` that is not the one of its
  header, and says it is not reproducible. The "json" outputs of §5.5 and
  §5.6 have no `recipients`: they are flattened serializations, which the
  tests compare with `to_flattened_json`.
- **Wycheproof JWS:** nine tests are divergences, each listed with its
  reason in `tests/protocol/jwt/jws.rs`: keys whose `alg` names another
  algorithm than the one they are used with, a malformed `key_ops`, and
  files whose base64url was corrupted (367, 370, 372, 373).
- **Wycheproof JWE:** test 22 is a valid flattened JSON serialization that
  Wycheproof expects an API of the compact serialization to refuse; the
  RSA1_5 tests are refused (`AlgorithmNotAllowed`) whatever they expect.
  `json_web_key_test.json` checks the keyset policies of a library, not the
  specifications, and is not used.
- **RFC texts:** the examples wrap their lines differently from one appendix
  to the next ("RSA key represented in JSON Web Key [JWK] format below"
  breaks before or after "below"); the helpers of `tests/protocol/jwt/mod.rs`
  (`folded`, `object`, `decimals`, `hexadecimal`) take a marker and join the
  lines after it, skipping page breaks.
