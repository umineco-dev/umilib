# `umilib::crypto`

Cryptography: block and stream ciphers, their modes, authenticated
encryption, message authentication, key derivation and random bit
generation. Feature: `crypto`, or one feature per module (see
[features.md](features.md)). Public-key cryptography is described in
[crypto-public-key.md](crypto-public-key.md).

## Interfaces

| Trait or type | Purpose |
| --- | --- |
| `BlockCipher` | `BLOCK_SIZE`, `Block`, `encrypt_block`/`decrypt_block` and `encrypt_blocks`/`decrypt_blocks` in place. |
| `KeyInit` | `new_from_slice(key)` with `MINIMUM_KEY_SIZE`..=`MAXIMUM_KEY_SIZE` bytes. |
| `StreamCipher` | `apply_keystream(data)`: xors the next bytes of key stream; fails with `LimitExceeded`, changing nothing, past the end of the key stream. |
| `AEAD` | `NONCE_SIZE`, `TAG_SIZE`, `encrypt_in_place` (returns the tag), `decrypt_in_place`, and `encrypt`/`decrypt` with the ciphertext followed by the tag (RFC 5116). |
| `MAC` | `OUTPUT_SIZE`, `update`, `finalize(self)`, `reset`, `verify(self, tag)` in constant time. |
| `PRF` | A `MAC` that is a pseudorandom function under one key for any number of messages (HMAC, CMAC), as the KDFs require. |
| `CryptoError` | `KeyLength`, `NonceLength`, `TagLength`, `InputLength`, `InvalidParameter`, `AuthenticationFailed`, `LimitExceeded`, `Allocation`, and for public keys `InvalidKey`, `InvalidSignature`, `RandomFailed`, `DecryptionFailed`. |

Every key, round key and state is zeroized when dropped and prints as
`Name(..)`. No memory access or branch depends on secret data: AES is
bitsliced, the ciphers defined by lookup tables read every entry of their
tables through `secret::ConstantTimeTable` (see
[secret.md](secret.md)), and tags are compared with `ConstantTimeEq`.

A failed `AEAD::decrypt_in_place` never leaves plaintext: GCM and
ChaCha20-Poly1305 check the tag before decrypting and leave the buffer
unchanged; CCM, SIV, GCM-SIV and Ascon-AEAD128 decrypt first and encrypt
again, so the buffer holds the ciphertext as it was; AEGIS zeroes the buffer,
as its specification requires.

## Block ciphers

| Module (feature) | Types | Specification |
| --- | --- | --- |
| `aes` | `AES128`, `AES192`, `AES256`, `AESBitslice` | FIPS 197 (bitsliced) |
| `aria` | `ARIA128`, `ARIA192`, `ARIA256` | RFC 5794 |
| `camellia` | `Camellia128`, `Camellia192`, `Camellia256` | RFC 3713 |
| `seed` | `SEED` | RFC 4269 |
| `sm4` | `SM4` | GB/T 32907-2016 |
| `gost::kuznyechik`, `gost::magma` | `Kuznyechik`, `Magma` | GOST R 34.12-2015, RFC 7801, RFC 8891 |
| `des` | `DES`, `TDES` | SP 800-67r2 (legacy only) |
| `idea` | `IDEA` | Lai and Massey (legacy only) |
| `rc2` | `RC2` | RFC 2268 (broken: legacy only) |

- `TDES::new(k1, k2, k3)` takes the three keys; `new_from_slice` takes 24
  bytes, or 16 for two-key TDES (Key3 = Key1). Bundles with Key1 = Key2 or
  Key2 = Key3 (ignoring the parity bits) are refused with
  `InvalidParameter`, because they are single DES. `DES::is_weak` recognizes
  the weak, semi-weak and possibly weak keys of section 3.3.2.
- `RC2::new(key, effective_bits)` takes keys of 1 to 128 bytes and an
  effective key length of 1 to 1024 bits; `KeyInit` uses 8 × the key length.
- `AESBitslice::round(blocks, keys)` is one round of AES, which AEGIS uses.
- The table ciphers (ARIA, Camellia, SEED, SM4, Kuznyechik, Magma, DES)
  are slower than lookup-table implementations (about 3 to 11 MiB/s), the
  price of reading every table entry for each lookup.

## Modes (`crypto-mode-*`)

Each mode is generic over its block cipher, as `CBC<AES128>`, and takes the
cipher object: `CBC::new(AES128::new(&key), &iv)`.

| Module | Types | Specification |
| --- | --- | --- |
| `mode::ecb` | `ECB<C>` | SP 800-38A (equal blocks show: legacy only) |
| `mode::cbc` | `CBC<C>` | SP 800-38A |
| `mode::cfb` | `CFB<C>`, `CFB8<C>`, `CFB1<C>` | SP 800-38A |
| `mode::ofb` | `OFB<C>` | SP 800-38A |
| `mode::ctr` | `CTR<C>` | SP 800-38A |
| `mode::xts` | `XTS<C>` | SP 800-38E, IEEE 1619 |
| `mode::gcm` | `GCM<C, TAG>` | SP 800-38D |
| `mode::ccm` | `CCM<C, TAG>` | SP 800-38C, RFC 3610 |
| `mode::siv` | `SIV<C>`, `S2V<C>` | RFC 5297 |
| `mode::gcmsiv` | `GCMSIV<C>`, `POLYVAL` | RFC 8452 |
| `mode::kw` | `KW<C>`, `KWP<C>`, `Wrapping<C>` | SP 800-38F, RFC 3394, RFC 5649 |
| `mode` | `PKCS7` | RFC 5652 section 6.3 |

- ECB and CBC take whole blocks (`InputLength` otherwise); pad with
  `PKCS7::pad`, and remove the padding with `PKCS7::unpad`, which checks it
  in constant time (`InvalidParameter` if it is wrong). A padding check
  still tells whether the padding was right: authenticate CBC ciphertexts.
- CBC, CFB and OFB continue across calls. `CFB1` encrypts the first `bits`
  bits of its buffer (`encrypt_bits`).
- `CTR::new` counts with the whole block; `with_counter_bits(cipher, initial,
  bits)` with its last bits only. CTR fails with `LimitExceeded` before the
  counter would return to its first value (`remaining_bytes`).
- `XTS::new(data, tweak)` takes the two ciphers; `KeyInit` takes the double
  key, whose halves must differ (`XTS::check_keys`). A data unit has 16 bytes
  to 2^20 blocks (SP 800-38E); `XTS::tweak_of(n)` is the tweak of data unit `n`.
- `GCM<C, TAG>` has tags of 4, 8 or 12 to 16 bytes (16 by default) and any
  nonce of at least 1 byte; 12 bytes are recommended. `CCM<C, TAG>` has tags
  of 4 to 16 bytes (even) and nonces of 7 to 13 bytes.
- `SIV<C>` is deterministic authenticated encryption with up to 126
  components of associated data (`encrypt_vector_in_place`), and an AEAD
  whose nonce is the last component; `encrypt` returns V followed by the
  ciphertext (section 6). `KeyInit` takes K1 followed by K2.
- `GCMSIV<C>` has a key-generating key of 16 or 32 bytes, 12-byte nonces and
  16-byte tags; it resists the reuse of nonces.
- `KW<C>` wraps keys of whole semiblocks (half a block), at least two, adding
  one semiblock: KW over a cipher of 128-bit blocks, TKW over one of 64-bit
  blocks (Triple DES); `KW::new` fails with `InvalidParameter` for other
  block sizes. `KWP<C>` (128-bit blocks only, `InvalidParameter`
  otherwise) wraps keys of 1 to 2^32 − 1 bytes, padded with zeros. Size the
  output with `wrapped_length`; `unwrap` checks the integrity value in
  constant time and fails with `AuthenticationFailed`, its output zeroed.
  `Wrapping<C>` is the wrapping function W and its inverse, which both use.

## Stream ciphers

- `chacha20::ChaCha20::new(key, nonce, counter)` (RFC 8439: a 12-byte nonce
  and a 32-bit counter) and `with_64_bit_counter(key, nonce, counter)` (the
  original design and libsodium: an 8-byte nonce and a 64-bit counter).
  `XChaCha20` takes 24-byte nonces through `hchacha20`. Both stop with
  `LimitExceeded` before the counter wraps.
- `rc4::RC4` is broken (RFC 7465): for legacy data only.

## Authenticated encryption

| Module | Types | Specification |
| --- | --- | --- |
| `chacha20poly1305` | `ChaCha20Poly1305`, `XChaCha20Poly1305` | RFC 8439, draft-irtf-cfrg-xchacha |
| `aegis` | `AEGIS128X<D, TAG>`, `AEGIS256X<D, TAG>`, aliases `AEGIS128L<TAG>`, `AEGIS256<TAG>` | draft-irtf-cfrg-aegis-aead |
| `ascon` | `AsconAEAD128<TAG>` | NIST SP 800-232 |

- AEGIS has degrees `D` of 1, 2 or 4 and tags of 16 or 32 bytes; nonces have
  the length of the key. Its state's `stream(key, nonce, out)` is the key
  stream of section 7.
- Ascon-AEAD128 has tags of 4 to 16 bytes (16 recommended) and 16-byte
  nonces; `with_nonce_mask(key, mask)` is the nonce masking of section
  4.2.2, which `KeyInit` takes as a 32-byte key.

## Message authentication

- `hmac::HMAC<H>`: see below.
- `cmac::CMAC<C>` (SP 800-38B, RFC 4493) over a block cipher of either block
  size. `verify_truncated` accepts the leftmost bytes, at least 8;
  `verify_truncated_with_minimum(tag, minimum)` accepts shorter tags, which
  appendix A.2 allows only where the protocol limits failed verifications.
- `poly1305::Poly1305` (RFC 8439): a one-time MAC; a key must authenticate
  one message only.
- `aegis::AEGISMAC128X<D, TAG>`, `AEGISMAC256X<D, TAG>`: the MACs of AEGIS,
  keyed with a key and a nonce.

### `crypto::hmac` (`crypto-hmac`)

`HMAC<H>` is HMAC (RFC 2104, FIPS 198-1) over any `CryptographicDigest`
hash function `H`.

```rust
use umilib::crypto::hmac::HMAC;
use umilib::hash::sha::v2::SHA256;

let tag = HMAC::<SHA256>::mac(b"key", b"message");
let mut hmac = HMAC::<SHA256>::new(b"key");
hmac.update(b"message");
assert!(hmac.verify(&tag));
```

- A key longer than the block size of `H` is hashed first; the padded key is
  absorbed once into an inner and an outer state, and each message continues
  copies of them (`reset` returns to the key).
- `verify(tag)` compares the whole tag in constant time.
  `verify_truncated(tag)` accepts the leftmost bytes of the tag, of at least
  `MINIMUM_TRUNCATED_LENGTH`: half of the output and at least 80 bits (RFC
  2104 section 5). Longer or shorter tags never verify.
- The states are zeroized when dropped, and `zeroize()` erases the key (the
  state is unusable afterwards). The tag compared by `verify` is erased too.
- `H` must be a `CryptographicDigest` (SHA, SHA-3, BLAKE2, BLAKE3, MD, RIPEMD,
  SM3, Streebog, Ascon-Hash256), not a checksum or a keyed hash such as
  SipHash.
- `verify_truncated` follows RFC 2104; protocols with shorter tags (SP
  800-107 allows 32 bits) compare a prefix of `finalize()` with
  `ConstantTimeEq` themselves.

## Key derivation

| Module | Types | Specification |
| --- | --- | --- |
| `hkdf` | `HKDF<H>` | RFC 5869 |
| `pbkdf2` | `PBKDF2<H>` | RFC 8018 section 5.2 |
| `scrypt` | `Scrypt` | RFC 7914 |
| `argon2` | `Argon2`, `Argon2Type` | RFC 9106 (version 0x13) |
| `kbkdf` | `KBKDF<P>`, `KBKDFCounter` | SP 800-108r1 |
| `kdftree` | `KDFTree<P>` | RFC 7836 section 4.4 |
| `concatkdf` | `ConcatKDF<F>`, `HashFunction<H>`, `AuxiliaryFunction` | SP 800-56C Rev. 2 section 4 (the Concat KDF of RFC 7518 section 4.6.2) |

```rust
use umilib::crypto::hkdf::HKDF;
use umilib::crypto::hmac::HMAC;
use umilib::crypto::kbkdf::KBKDF;
use umilib::hash::sha::v2::SHA256;

let mut okm = [0u8; 42];
HKDF::<SHA256>::derive(salt, ikm, info, &mut okm)?;
let kbkdf = KBKDF::new(HMAC::<SHA256>::new(&key), 32)?;
kbkdf.counter(&[], &fixed_input, &mut okm)?;
```

- HKDF: `extract`, `new(prk)` (at least HashLen bytes), `from_secret`,
  `expand` (at most 255 × HashLen bytes) and `derive`.
- PBKDF2 needs at least one iteration.
- scrypt and Argon2 check their parameters when they are created
  (`InvalidParameter`) and allocate their memory for each derivation, with
  `try_reserve` (`Allocation` if it fails), zeroizing it afterwards.
  `Scrypt::memory` and `Argon2::memory_bytes` tell how much: bound them
  before deriving with parameters an attacker chose. scrypt reads its memory
  at indices derived from the password, as its design does.
- `KBKDF<P>` and `KDFTree<P>` take a keyed PRF: a `MAC` that also implements
  `PRF` (HMAC and CMAC; not the one-time Poly1305). The
  caller builds the fixed input data (typically Label || 0x00 || Context ||
  [L]), as protocols define it; the output length is the buffer's.
- `ConcatKDF<F>` is the one-step KDF: K(i) = H([i]_32 || Z || FixedInfo)
  with the auxiliary function H a hash function
  (`ConcatKDF::<HashFunction<SHA256>>::hash()`, option 1) or a PRF keyed with
  the salt (`ConcatKDF::new(HMAC::<SHA256>::new(salt))`, option 2). The caller
  builds FixedInfo, as JOSE does for ECDH-ES
  ([protocol-jwt.md](protocol-jwt.md)); the output length is the buffer's.

## Random bit generation (`crypto-random`, uses `crypto-hmac`)

The deterministic random bit generators of NIST SP 800-90A Revision 1:
`HMACDRBG<H>` (HMAC_DRBG), `HashDRBG<H>` (Hash_DRBG) and `CTRDRBG<C>`
(CTR_DRBG over a 128-bit block cipher with one key size, such as AES). They
expand the entropy their user supplies; umilib's `platform` module will
supply it from the operating system.

```rust
use umilib::crypto::random::{DRBG, HMACDRBG, Random};
use umilib::hash::sha::v2::SHA256;

let mut drbg = HMACDRBG::<SHA256>::new(&entropy, &nonce, b"application")?;
let mut key = [0u8; 32];
drbg.generate(&mut key, &[])?;     // one request, with optional additional input
drbg.reseed(&fresh_entropy, &[])?;
drbg.fill(&mut key)?;               // Random: any length
```

- `DRBG`: `generate` makes one request of at most the maximum size;
  `generate_all` splits a long one, which is how the generators implement
  `Random` (`fill`, `next_u32`, `next_u64`).
- Any `CryptographicDigest` may be the hash function and any 128-bit block
  cipher with one key size the cipher, but SP 800-90A approves only SHA-1
  and SHA-2 (HMAC_DRBG, Hash_DRBG) and AES (CTR_DRBG); with other primitives
  the generators are not SP 800-90A generators, and their security strength
  is at most that of the primitive (MD4 and MD5 have none).
- The security strength follows SP 800-90A table 2: 128 bits for SHA-1, 192
  for SHA-224 and SHA-512/224, 256 for the other hash functions; the key
  length of the cipher for CTR_DRBG (table 3). The entropy input must have at
  least that many bits (`EntropyLength` otherwise), and with the nonce at
  least 3/2 of them (`NonceLength` otherwise): section 8.6.7 asks for a nonce
  of half the security strength, which may be a counter or a time, or for the
  entropy input to carry it. Every input is at most 2^35 bits (`InputLength`).
- `CTRDRBG::new` uses the derivation function;
  `instantiate_without_derivation(config, entropy, personalization)` takes
  an entropy input of exactly seedlen bytes (section 10.2.1.3.1). CTR_DRBG
  over TDEA is not provided: SP 800-131A no longer approves it.
- `DRBG` has the four functions of section 9: `instantiate` (also `new` and
  `with_config`), `reseed`, `generate` and `uninstantiate`, which erases the
  state; afterwards every function fails with `Uninstantiated`. `zeroize`
  and dropping uninstantiate too.
- `DRBGConfig` holds the reseed interval (at most 2^48 requests) and the
  maximum request (at most 2^16 bytes); `clamped()` brings any value within
  those limits, which constructors apply. After `reseed_interval` requests,
  `generate` fails with `ReseedRequired` until `reseed`.
- Prediction resistance is a `reseed` with fresh entropy right before each
  request.
- Generators cannot be cloned (two copies would generate the same bytes) and
  are zeroized when dropped.

## C and Python

The C ABI exports each concrete type as an opaque handle, and each generic
type once, choosing its parameters at run time:

- A hash function `H` is chosen by the C type name of the hash type, such as
  `umilib_hash_sha_v2_SHA256` (`HMAC`, `HKDF`, `PBKDF2`, the DRBGs).
- A block cipher `C` is chosen by the C type name of the cipher type, such as
  `umilib_crypto_aes_AES128`, and its key (the modes, `CMAC`, `CTRDRBG`).
  The modes of SP 800-38A and CMAC take ciphers of either block size; XTS,
  GCM, CCM, SIV, GCM-SIV and CTR_DRBG take 128-bit ones.
- Sizes are arguments: the tag size of GCM, CCM and Ascon-AEAD128, the
  degree and tag size of AEGIS.
- The PRF of `KBKDF` and `KDFTree` is chosen by two names: the C type name
  of the PRF (`umilib_crypto_hmac_HMAC` or `umilib_crypto_cmac_CMAC`) and
  that of its hash function or cipher.

An unknown or disabled name fails with `InvalidArgument`. Where Rust takes
two ciphers (`XTS::new`, `SIV::new`), C takes the cipher name and two keys.
`DRBGConfig` is a C structure; `Argon2Type` and `KBKDFCounter` cross as
integers (0, 1, 2 and 0 to 3).

In Python the subscript chooses the parameters, as they are in Rust:

```python
from umilib.crypto.aes import AES128
from umilib.crypto.hmac import HMAC
from umilib.crypto.kbkdf import KBKDF
from umilib.crypto.mode.gcm import GCM
from umilib.crypto.random import CTRDRBG, HMACDRBG
from umilib.hash.sha.v2 import SHA256

HMAC[SHA256].mac(b"key", b"message")
sealed = GCM[AES128, 16](key).encrypt(nonce, b"header", b"message")
KBKDF[HMAC[SHA256]](key, 32).counter(b"", fixed_input, 32)
drbg = HMACDRBG[SHA256](secrets.token_bytes(32), secrets.token_bytes(16))
drbg.bytes(16)
CTRDRBG[AES128](secrets.token_bytes(16), secrets.token_bytes(8)).bytes(16)
```

Operations in place take a `bytearray`, as in `CBC[AES128](key, iv).encrypt(buffer)`.
