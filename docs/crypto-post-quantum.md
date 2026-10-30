# Post-quantum cryptography in `umilib::crypto`

The standards of NIST for post-quantum cryptography and the hybrids of TLS
1.3. Each module has its feature; the arithmetic of the lattice schemes is
that of [math-lattice.md](math-lattice.md).

| Module | Feature | Standard | Interface |
| --- | --- | --- | --- |
| `mlkem` | `crypto-mlkem` | FIPS 203 (ML-KEM-512, -768, -1024) | `KeyEncapsulation` |
| `mldsa` | `crypto-mldsa` | FIPS 204 (ML-DSA-44, -65, -87) | `SignatureScheme` |
| `slhdsa` | `crypto-slhdsa` | FIPS 205 (the twelve SLH-DSA parameter sets) | `SignatureScheme` |
| `hybrid` | `crypto-hybrid` | RFC 10024 (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024) | `KeyEncapsulation` |

## Key encapsulation

`KeyEncapsulation` is the interface of KEMs, as `KeyAgreement` and
`SignatureScheme` are of the other schemes ([crypto-public-key.md](crypto-public-key.md)):
`generate`, `encapsulation_key`, `encapsulate` (a ciphertext and the shared
secret it carries), `decapsulate`, and the encodings of keys at the sizes of
`DECAPSULATION_KEY_SIZE`, `ENCAPSULATION_KEY_SIZE`, `CIPHERTEXT_SIZE` and
`SHARED_SECRET_SIZE`.

```rust
use umilib::crypto::KeyEncapsulation;
use umilib::crypto::mlkem::{MLKEM, MLKEM768};

let key = MLKEM::<MLKEM768>::generate(&mut random)?;            // the recipient
let public = MLKEM::<MLKEM768>::encapsulation_key(&key);
let (mut ciphertext, mut sent) = ([0u8; 1088], [0u8; 32]);
MLKEM::<MLKEM768>::encapsulate(&public, &mut random, &mut ciphertext, &mut sent)?;   // the sender
let mut received = [0u8; 32];
MLKEM::<MLKEM768>::decapsulate(&key, &ciphertext, &mut received)?;
assert_eq!(sent, received);
```

### ML-KEM (`crypto-mlkem`)

- `MLKEM<P>` for the parameter sets `MLKEM512`, `MLKEM768` and `MLKEM1024`
  (`MLKEMParameters`). Keys are the encodings of FIPS 203: an encapsulation
  key is read only if it passes the type and modulus checks of section 7.2,
  a decapsulation key only if it passes the type and hash checks of section
  7.3 (`InvalidKey` otherwise); a ciphertext of another length fails with
  `InputLength`.
- Decapsulation rejects implicitly: a ciphertext that was not made for the
  key gives J(z || c), selected in constant time; it never fails for a
  ciphertext of the right length.
- A decapsulation key can be kept as the seed d || z of 64 bytes it is
  generated from: `decapsulation_key_from_seed` and `write_seed` (which
  fails with `InvalidKey` for a key read from its expanded encoding).
- The functions of K-PKE (`kpke_key_gen`, `kpke_encrypt`, `kpke_decrypt`)
  and the internal functions (`key_gen_internal`, `encapsulate_internal`,
  `decapsulate_internal`) take their randomness as arguments, for testing.

### Hybrids (`crypto-hybrid`)

`HybridKEM<P>` makes a KEM of a post-quantum KEM and a traditional key
agreement whose shares and secrets are concatenated (`HybridKEMParameters`):
the groups of RFC 10024, `X25519MLKEM768`, `SecP256r1MLKEM768` and
`SecP384r1MLKEM1024`, with their codepoints (`CODEPOINT`). The
encapsulation key is the client's key_exchange, the ciphertext the
server's, and the shared secret the concatenation of the two secrets, in
the order of the group (ML-KEM first for X25519MLKEM768, the curve first
for the others). The parts are checked as their schemes require, and a key
agreement that refuses its result (X25519 giving zero) fails with
`InvalidKey`.

## Signatures

ML-DSA and SLH-DSA implement `SignatureScheme`, which signs
deterministically with the empty context. Their own functions take a
context of at most 255 bytes (`InvalidParameter` otherwise):

| Function | ML-DSA (FIPS 204) | SLH-DSA (FIPS 205) |
| --- | --- | --- |
| `sign_with_context` | ML-DSA.Sign, hedged: rnd from a `Random` | slh_sign, hedged: addrnd from a `Random` |
| `sign_deterministic_with_context` | rnd = 0^32 | opt_rand = PK.seed |
| `verify_with_context` | ML-DSA.Verify | slh_verify |
| `sign_pre_hash`, `sign_pre_hash_deterministic`, `verify_pre_hash` | HashML-DSA | HashSLH-DSA |
| `sign_internal`, `verify_internal` | on M' (section 6) | on M' (section 9) |

The pre-hash functions take a hash function of the trait `PreHash` (feature
`hash-sha-v2` with `hash-sha-v3`): SHA-224, SHA-256, SHA-384, SHA-512,
SHA-512/224, SHA-512/256, SHA3-224 to SHA3-512, SHAKE128 (256 bits) and
SHAKE256 (512 bits), each with the DER encoding of its object identifier.

```rust
use umilib::crypto::mldsa::{MLDSA, MLDSA65};
use umilib::crypto::SignatureScheme;

let key = MLDSA::<MLDSA65>::generate(&mut random)?;
let mut signature = [0u8; 3309];
MLDSA::<MLDSA65>::sign_with_context(&key, b"message", b"context", &mut random, &mut signature)?;
MLDSA::<MLDSA65>::verify_with_context(&MLDSA::<MLDSA65>::verifying_key(&key), b"message", b"context", &signature)?;
```

### ML-DSA (`crypto-mldsa`)

- `MLDSA<P>` for `MLDSA44`, `MLDSA65` and `MLDSA87` (`MLDSAParameters`).
  A private key is read only if its s1 and s2 are in [-η, η] and its t0
  and tr are those its other parts define (`InvalidKey` otherwise); it can
  also be kept as the seed ξ of 32 bytes (`signing_key_from_seed`,
  `write_seed`).
- `sign_mu` and `verify_mu` work on the message representative μ (the
  "external μ" interface); `message_representative` computes it.

### SLH-DSA (`crypto-slhdsa`)

- `SLHDSA<P>` for the twelve parameter sets `SLHDSA_SHA2_128s` to
  `SLHDSA_SHAKE_256f` (`SLHDSAParameters`), named as the standard names
  them. The hash functions of a family are `SLHDSAHash`: `SLHDSASHAKE`,
  `SLHDSASHA2Category1` (n = 16) and `SLHDSASHA2Category3And5`.
- A private key is read only if PK.root is the root its seeds generate
  (the check of section 3.1); `key_gen_internal` makes the key of SK.seed,
  SK.prf and PK.seed.
- The `s` parameter sets have small signatures and slow signing (hundreds
  of milliseconds); the `f` sets sign in tens of milliseconds.

## Timing

The secret parts of ML-KEM and ML-DSA are handled in constant time,
including the comparison and selection of implicit rejection, except what
the standards let reveal: the number of iterations of the signing loop of
ML-DSA and of its sampling of secrets by rejection (FIPS 204 appendix C).
Expansions of public seeds (Â) take time that depends on the seed. SLH-DSA
hashes secrets and public values alike, in time that depends on the public
indices alone.

## C and Python

The C ABI chooses a parameter set by the C type name of its type, such as
`umilib_crypto_mlkem_MLKEM768`, `umilib_crypto_mldsa_MLDSA65`,
`umilib_crypto_slhdsa_SLHDSA_SHAKE_128f` or
`umilib_crypto_hybrid_X25519MLKEM768`, and works on the encodings of keys:

- The KEMs (`mlkem_mlkem`, `hybrid_hybrid_kem`) export `_sizes` (four
  sizes), `_generate`, `_encapsulation_key`, `_check_decapsulation_key`,
  `_check_encapsulation_key`, `_encapsulate` and `_decapsulate`; ML-KEM adds
  `_decapsulation_key_from_seed` and `_encapsulate_internal`.
- ML-DSA and SLH-DSA export the functions of `SignatureScheme` and
  `_sign_with_context`, `_sign_deterministic_with_context`,
  `_verify_with_context`, `_sign_pre_hash`, `_sign_pre_hash_deterministic`
  and `_verify_pre_hash` (the hash function named by the C type name of its
  type); ML-DSA adds `_signing_key_from_seed`, SLH-DSA `_key_gen_internal`.

In Python, `MLKEM[MLKEM768]` and `HybridKEM[X25519MLKEM768]` are
`KeyEncapsulation` classes whose keys are `DecapsulationKey` and
`EncapsulationKey` objects; `MLDSA[MLDSA65]` and `SLHDSA[SLHDSA_SHAKE_128f]`
are `ContextSignatureScheme` classes with the same functions as C, the
pre-hash ones taking the hash class first (`sign_pre_hash(SHA512, key,
message, context, random)`).
