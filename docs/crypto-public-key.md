# Public-key cryptography in `umilib::crypto`

Key agreement, signatures and public-key encryption. Each module has its
feature (see [features.md](features.md)); the arithmetic is that of
[math-ec.md](math-ec.md), [math-modular.md](math-modular.md) and
[math-pairing.md](math-pairing.md).

## Interfaces

| Trait | Purpose |
| --- | --- |
| `KeyAgreement` | `generate`, `public_key`, `agree`, and the encodings of private and public keys at the sizes of `PRIVATE_KEY_SIZE`, `PUBLIC_KEY_SIZE` and `SHARED_SECRET_SIZE`. ECDH, XDH and DH implement it. |
| `SignatureScheme` | `generate`, `verifying_key`, `sign`, `verify`, and the encodings of keys and signatures at fixed sizes. ECDSA, EdDSA, SM2DSA and GOSTR3410 implement it, and ML-DSA and SLH-DSA ([crypto-post-quantum.md](crypto-post-quantum.md)). |
| `KeyEncapsulation` | `generate`, `encapsulation_key`, `encapsulate`, `decapsulate`, and the encodings of keys and ciphertexts at fixed sizes. ML-KEM and the hybrids of RFC 10024 implement it ([crypto-post-quantum.md](crypto-post-quantum.md)). |

A scheme is a type of no value (`ECDH<P256>`, `Ed25519`,
`ECDSA<P256, SHA256>`) whose associated functions work on its key types.
Private keys are zeroized when dropped and print only their public parts;
a key encoding of another length fails with `InvalidKey`, a signature of
another length with `InvalidSignature`, an output buffer of another length
with `InputLength`. `CryptoError` adds `InvalidKey`, `InvalidSignature`,
`RandomFailed` and `DecryptionFailed` to the errors of
[crypto.md](crypto.md). Generation takes any `crypto::random::Random`.

```rust
use umilib::crypto::curve::p256::P256;
use umilib::crypto::ecdsa::ECDSA;
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::SignatureScheme;
use umilib::hash::sha::v2::SHA256;

let mut random = HMACDRBG::<SHA256>::new(&entropy, &nonce, b"keys")?;
let key = ECDSA::<P256, SHA256>::generate(&mut random)?;
let mut signature = [0u8; 64];
ECDSA::<P256, SHA256>::sign(&key, b"message", &mut signature)?;   // deterministic (RFC 6979)
ECDSA::<P256, SHA256>::verify(&ECDSA::<P256, SHA256>::verifying_key(&key), b"message", &signature)?;
```

## Curves

`crypto::curve` defines the curves of the specifications as parameters of
`math::ec` (feature `crypto-curve-<name>`):

| Module | Types | Specification |
| --- | --- | --- |
| `p256`, `p384`, `p521` | `P256`, `P384`, `P521` (with `P256Field`, `P256Scalar`, ...) | FIPS 186-5, SP 800-186 |
| `secp256k1` | `Secp256k1` | SEC 2 |
| `brainpool::p256r1`, `p384r1`, `p512r1` | `BrainpoolP256r1`, ... | RFC 5639 |
| `curve25519` | `Curve25519` (Montgomery), `Edwards25519` | RFC 7748, RFC 8032 |
| `curve448` | `Curve448`, `Edwards448` | RFC 7748, RFC 8032 |
| `sm2` | `SM2` | GB/T 32918.5 |
| `gost` | `GOST256A` to `GOST256D`, `GOST512A` to `GOST512C` | RFC 7836, RFC 4357 (id-tc26-gost-3410-2012-*-paramSet*) |

Each field type has `element(hex)`, a `const fn` for constants. `GOST256A`
and `GOST512C` are twisted Edwards curves of cofactor 4 in Weierstrass form.

## Key agreement

- **`ecdh::ECDH<C>`** (`crypto-ecdh`): SEC 1 section 3.3.1 on a Weierstrass
  curve. Private keys are big-endian scalars in 1..n; public keys are SEC 1
  points (uncompressed written, compressed also read), validated as SEC 1
  section 3.2.2.1 requires; the shared secret is the x-coordinate.
- **`ecdh::XDH<C>`**, `X25519`, `X448`: RFC 7748. Any bytes are a private
  key (decoded by `XDH::decode_scalar` at each use); every encoding of a
  public key is read; a shared secret of zero (a public key of small order)
  fails with `InvalidKey`, as TLS 1.3 and HPKE require.
- **`dh::DH<G>`** (`crypto-dh`): SP 800-56A section 5.7.1.1 in the groups
  `FFDHE2048` to `FFDHE8192` (RFC 7919) and `MODP1536` to `MODP8192` (RFC
  3526). Generated private keys have twice the security strength in bits;
  public keys are fully validated (2 ≤ y ≤ p - 2, y^q = 1); the shared
  secret keeps the bytes of p.
- **`dragonfly::DragonflyPeer<C, H>`** (`crypto-dragonfly`): RFC 7664 on a
  Weierstrass curve with a profile fixed by this library (H, KDF and
  encodings, see the module documentation): `new`, `commit`, `process` (the
  peer's commit; returns the confirm) and `finish` (the peer's confirm;
  returns mk).
- **`srp`** (`crypto-srp`): SRP-6a as RFC 5054 defines it, in the groups
  `SRP1024` to `SRP8192`: `SRP::verifier` for the server's database,
  `SRPClient` and `SRPServer` for the premaster secret.

## Signatures

- **`ecdsa::ECDSA<C, H>`** (`crypto-ecdsa`): FIPS 186-5 section 6 with the
  nonce of RFC 6979 (`sign_digest`), or with random bytes added
  (`sign_digest_hedged`, RFC 6979 section 3.6). `ECDSASignature` reads and
  writes r || s and, with `codec-asn1-der`, the DER `Ecdsa-Sig-Value`.
- **`eddsa::EdDSA<C>`**, `Ed25519`, `Ed448` (`crypto-eddsa`): RFC 8032; the
  pure variants through `SignatureScheme`, `sign_with_context` for
  Ed25519ctx and Ed448 with a context, `sign_prehashed` for Ed25519ph and
  Ed448ph. Verification is cofactored and refuses non-canonical R and S ≥ L.
- **`dsa::DSA<H>`** (`crypto-dsa`): FIPS 186-4 with the nonce of RFC 6979,
  for keys of `DSAParameters` of the sizes (1024, 160), (2048, 224),
  (2048, 256) and (3072, 256).
- **`sm2::SM2DSA<C, H>`** (`crypto-sm2`): GB/T 32918.2, with the identity
  of the signer (`SM2DSA::DEFAULT_IDENTITY` through `SignatureScheme`).
- **`gostr3410::GOSTR3410<C, H>`** (`crypto-gostr3410`): GOST R 34.10-2012
  (RFC 7091) with the encodings of RFC 9215 (s || r big-endian; x || y
  little-endian).
- **`eccsi`** (`crypto-eccsi`): RFC 6507: `ECCSIKMS` issues `ECCSIUserKey`s,
  `ECCSI` signs and verifies against an identity and KPAK.
- **`ibs::hess::Hess<C, H>`**, **`ibs::chacheon::ChaCheon<C, H>`**,
  **`ibs::sm9::SM9<C, H>`** (`crypto-ibs-hess`, `crypto-ibs-chacheon`,
  `crypto-ibs-sm9`): identity-based signatures on the pairing curves,
  through `ibs::IdentityBasedSignature`. SM9 is GM/T 0044.2-2016 as
  `SM9<SM9BN256, SM3>` (the curve and hash function GM/T 0044.5 specifies;
  hid 0x01, or another with `extract_with_identifier` and
  `verify_with_identifier`): a signature is h (32 bytes) || S
  uncompressed, and the master public key 04 || x || y with each coordinate
  of GF(p^2) as its u-coefficient, then its constant. Each scheme encodes
  its master public key (`master_public_key_to_bytes`); the user key is the
  identity, its point of G_1 and the master public key.

ECDSA, DSA, SM2 and GOST R 34.10 derive their nonces deterministically
(HMAC_DRBG over the scheme's hash, seeded with the key and the digest, as
RFC 6979 section 3.2 does), so their signatures never depend on the quality
of a source of random bytes; their `_hedged` functions add random bytes.

## RSA (`crypto-rsa`)

`RSAPublicKey` (n, e) and `RSAPrivateKey` (d, with the primes when known);
`RSAPrivateKey::generate(bits, e, random)` follows FIPS 186-5 appendix A.1
(at least 2048 bits). With `codec-asn1-der`, keys read and write PKCS #1
DER. The schemes:

| Type | Scheme |
| --- | --- |
| `RSAPKCS1v15<H>` | RSASSA-PKCS1-v1_5 (RFC 8017 section 8.2), for the hashes of `PKCS1Digest` (SHA-1, SHA-2, SHA-3) |
| `RSAPSS<H, G = H>` | RSASSA-PSS (section 8.1) with MGF1 over `G` and a salt length given to `sign` and `verify` |
| `RSAOAEP<H, G = H>` | RSAES-OAEP (section 7.1); `decrypt` fails with `DecryptionFailed` alike for every malformed ciphertext |

The private operation blinds its input with bytes of the given `Random`,
uses the Chinese remainder theorem when the primes are known, and checks its
result against the public operation. RSAES-PKCS1-v1_5 encryption is not
provided: its decryption cannot be protected against padding oracles.

## Public-key encryption

- **`hpke`** (`crypto-hpke`): RFC 9180, `HPKE<K, F, A>` with
  `DHKEM<ECDH<P256>, SHA256>`, `DHKEM<X25519, SHA256>`, ... the KDFs
  SHA-256/384/512 and the AEADs AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
  and `HPKEExportOnly`, in the four modes; sender contexts only seal and
  receiver contexts only open.
- **`sm2::SM2PKE<C, H>`**: GB/T 32918.4 in either order of the ciphertext
  (`SM2CiphertextOrder::C1C3C2`, of the 2016 standard, or `C1C2C3`).
- **`sm2::SM2KEP<C, H>`**: the key exchange of GB/T 32918.3 with its
  confirmations.

## SM9 (`crypto-sm9`)

`crypto::sm9` holds the identity-based key exchange (GM/T 0044.3-2016), key
encapsulation and public key encryption (GM/T 0044.4-2016) of SM9; its
signatures are `ibs::sm9::SM9` above. Every type is generic over a pairing
curve `C` and a hash function `H`; the standard instance is `SM9BN256` with
`SM3` (GM/T 0044.5), and the examples of GM/T 0044.5 annexes B to D are the
tests.

- **`SM9EncryptMasterKey<C>`**: the KGC's ke and Ppub-e = [ke]P1 in G_1
  (`new`, `generate`). `extract::<H>(identity, hid)` gives the
  **`SM9EncryptUserKey<C>`** of an identity: de = [ke / (H1(ID || hid, N) +
  ke)]P2 in G_2, with the identifier hid of the key generating function,
  which senders and peers must use as well (the annexes use 0x03).
- **`SM9KEP<C, H>`**: one side of the key exchange, of an `SM9Role`
  (`Initiator` is A, `Responder` is B), the user's key, the other user's
  identity and the random r (`new`, or `generate`). Each side sends
  `ephemeral_public_key` (R); `agree` writes SK of the other side's R into a
  buffer of the length of the key to derive and returns the optional
  `SM9KeyConfirmation` (S_B and S_A), which `confirm` checks in constant
  time.
- **`SM9KEM<C, H>`**: `encapsulate` writes K for an identity, hid and
  Ppub-e into a buffer of klen / 8 bytes and returns C; `decapsulate` writes
  K of C for the user's key. An empty buffer is refused (`InputLength`).
- **`SM9PKE<C, H, E = SM9StreamCipher>`**: `encrypt` returns C1 || C3 || C2
  (C1 = x || y, C3 = MAC(K2, C2) of the bytes of H); `decrypt` checks C3
  before it decrypts C2 and fails with `DecryptionFailed` alike for every
  invalid ciphertext. `E` is the cipher of step A6: **`SM9StreamCipher`**
  (C2 = M xor K1) or **`SM9BlockCipher<B>`** (with `crypto-mode-cbc`): the
  block cipher `B` in CBC mode with a zero initial vector, K1 a key of B of
  its largest size, k bytes, and the message padded with k - (mlen mod k)
  bytes of that value, as annex D does with SM4.
- The `_with_ephemeral` functions take r instead of a generator, for test
  vectors: r must be secret, random and used once. They fail with
  `InvalidParameter` when K (or K1) is zero, where the generator versions
  draw another r, as the standard requires. An empty message has an empty
  K1, which is not zero.
- `SM9Hash` (H1 and H2), `SM9KDF` and `SM9Encoding` (the conversions of GM/T
  0044.1 clause 7) are the functions all parts share, the signatures
  included. Points of G_1 are written x || y in the hash inputs and the
  ciphertexts, points of G_2 04 || x || y with the u-coefficients first, and
  elements of G_T as GM/T 0044.5 section 3.2 orders them.

## Timing

Operations on private keys are constant time: scalar multiplications, the
exponentiations of DH, DSA and SRP, and the private operation of RSA.
Verification and the public operations take time that depends on their
public inputs. Key generation of RSA takes time that depends on the
candidates it rejects. The pairings of [math-pairing.md](math-pairing.md)
take time that does not depend on their points, which lets SM9 pair its
private keys de; the hashes H1 and the points Q = [H1(ID || hid)]P1 +
Ppub-e of identities are computed in time that depends on the identity.

## C and Python

The C ABI chooses the parameters of a scheme at run time, as for the
symmetric primitives ([crypto.md](crypto.md)):

- A curve is chosen by the C type name of its type, such as
  `umilib_crypto_curve_p256_P256`, `umilib_crypto_curve_curve25519_Edwards25519`
  or `umilib_math_pairing_BLS12381`; a group of DH or SRP likewise
  (`umilib_crypto_dh_FFDHE2048`, `umilib_crypto_srp_SRP1024`); a hash
  function by the C type name of the hash type.
- The schemes of `KeyAgreement` (`ecdh_ecdh`, `ecdh_xdh`, `dh_dh`) export
  `_sizes`, `_generate`, `_public_key`, `_check_private_key`,
  `_check_public_key` and `_agree`; those of `SignatureScheme`
  (`ecdsa_ecdsa`, `eddsa_eddsa`, `gostr3410_gostr3410`, `sm2_sm2dsa`) export
  `_sizes`, `_generate`, `_verifying_key`, `_check_signing_key`,
  `_check_verifying_key`, `_sign` and `_verify`. Keys are the byte encodings
  of the traits; the `_check_*` functions validate them as the
  `*_from_bytes` functions of the traits do.
- A function that draws random values takes a generator handle and the C
  type name of its type (`umilib_crypto_random_HMACDRBG`,
  `umilib_crypto_random_HashDRBG` or `umilib_crypto_random_CTRDRBG`).
- HPKE takes a suite as the identifiers of RFC 9180 section 7 (`kem`, `kdf`,
  `aead`). A pre-shared key is absent when it and its identifier are both
  empty, the sender's key when it is empty.
- RSA keys, DSA parameters and keys, the contexts of HPKE, the peers of
  Dragonfly, the parties of SRP, the side of the key exchange of SM2 and the
  keys of the identity-based signatures are opaque handles.
- The master and user keys of SM9 and the sides of its key exchange are
  handles that keep their curve; the functions that take one name the hash
  function (and the cipher of `sm9pke`) as the Rust functions take them as
  type parameters. The cipher of `sm9pke` is named
  `umilib_crypto_sm9_SM9StreamCipher` or by the C type name of a block cipher
  for `SM9BlockCipher` (such as `umilib_crypto_sm4_SM4`). `umilib_crypto_sm9_sizes`
  gives the bytes of a scalar, of a point of G_1 (Ppub-e, R, C), of a point
  of G_2 (de) and of an output of the hash function (C3, S_A, S_B).
- ECDSA, DSA and SM2 signatures convert between r || s and DER
  (`_signature_from_der`, `_signature_to_der`, with `codec-asn1-der`), both
  into a new buffer.
- No output may share a byte with an input or another output, names
  included (`InvalidArgument`).

In Python the subscript chooses the parameters, as they are in Rust. Keys of
`KeyAgreement` and `SignatureScheme` are `PrivateKey`, `PublicKey`,
`SigningKey` and `VerifyingKey` objects that hold their encodings, the secret
ones in a `umilib.secret.Secret`. Secrets that functions give (shared
secrets, decrypted messages, exported values, private exponents) are written
into a `bytearray` or returned as one, never through an immutable `bytes`
copy, and the caller erases them. A pre-shared key of HPKE is a pair of
non-empty values or `None`; an empty pair is refused (`InvalidParameter`),
as in Rust.

The keys of SM9 are handles of a curve, `SM9EncryptMasterKey[SM9BN256]` and
`SM9EncryptUserKey[SM9BN256]`, and `extract` takes the hash function as its
first argument, as Rust takes it as `extract::<SM3>`; the schemes are
`SM9KEP[C, H]`, `SM9KEM[C, H]`, `SM9PKE[C, H]` and `SM9PKE[C, H,
SM9BlockCipher[SM4]]`. The given r of the `_with_ephemeral` functions and of
`SM9KEP` is a `bytes` or a `bytearray`, which is zeroized afterwards.

```python
from umilib.crypto.curve.p256 import P256
from umilib.crypto.ecdh import ECDH, X25519
from umilib.crypto.ecdsa import ECDSA, ECDSASignature
from umilib.crypto.hpke import DHKEM, HPKE
from umilib.crypto.chacha20poly1305 import ChaCha20Poly1305
from umilib.crypto.random import HMACDRBG
from umilib.hash.sha.v2 import SHA256

random = HMACDRBG[SHA256](secrets.token_bytes(32), secrets.token_bytes(16))
key = ECDSA[P256, SHA256].generate(random)
signature = ECDSA[P256, SHA256].sign(key, b"message")
der = ECDSASignature[P256].from_bytes(signature).to_der()

private = X25519.generate(random)
shared = bytearray(X25519.SHARED_SECRET_SIZE)
X25519.agree(private, X25519.public_key_from_bytes(peer), shared)

suite = HPKE[DHKEM[X25519, SHA256], SHA256, ChaCha20Poly1305]
encapsulated, context = suite.setup_sender(recipient, b"info", None, None, random)
ciphertext = context.seal(b"", b"message")
```
