# `umilib::hash`

Hash functions: the cryptographic ones (SHA-1, SHA-2, SHA-3 and SP 800-185,
BLAKE2, BLAKE3, MD4, MD5, RIPEMD, SM3, Streebog, Ascon), keyed hashes for hash
tables (SipHash), fast checksums (xxHash, Adler-32) and cyclic redundancy
checks (CRC).
Feature: `hash`, or one feature per family (`hash-sha-v2`, `hash-blake-v3`,
`hash-crc`, ...; see [features.md](features.md)).

```rust
use umilib::hash::Digest;
use umilib::hash::sha::v2::SHA256;

let digest = SHA256::digest(b"abc");          // [u8; 32]
let mut state = SHA256::new();
state.update(b"a");
state.update(b"bc");
assert_eq!(state.finalize(), digest);
```

## Interfaces

- `Digest`: fixed output (`OUTPUT_SIZE`, `BLOCK_SIZE`); `update`,
  `finalize(self)`, `finalize_reset(&mut self)`, `reset`, and `digest(data)`
  for unkeyed types (`Default`). Outputs are byte arrays.
- `ExtendableOutput`: output of any length; `finalize_xof(self)` returns an
  `XOFReader`, whose `read(out)` continues the output stream. `digest_xof`
  fills a buffer in one call.
- `CryptographicDigest`: the `Digest` types designed as cryptographic hash
  functions (SHA, SHA-3, Keccak, BLAKE2, BLAKE3, MD, RIPEMD, SM3, Streebog,
  Ascon-Hash256),
  which HMAC and the DRBGs require; their states can be zeroized.
- `BlockBuffer<N>` collects input into blocks of `N` bytes for the
  compression functions of the Merkle–Damgård hashes, and pads them.
- `HashError`: `OutputLength`, `KeyLength`, `InvalidParameter`.

Every cryptographic hash state is zeroized when dropped and prints as
`Name(..)`. A state after `zeroize()` is not a fresh one: keyed and
customized states are unusable except to be dropped. The functions take time that depends only on the input lengths
(no table lookups indexed by data; see [secret.md](secret.md)).

## Families

| Module | Types | Specification |
| --- | --- | --- |
| `sha::v1` | `SHA1` | FIPS 180-4 (collisions are practical: compatibility only) |
| `sha::v2` | `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA512_224`, `SHA512_256` | FIPS 180-4 |
| `sha::v3` | `SHA3_224` … `SHA3_512`, `Keccak224` … `Keccak512`, `SHAKE128`, `SHAKE256`, `CSHAKE128`, `CSHAKE256`, `TupleHash128`, `TupleHash256`, `ParallelHash128`, `ParallelHash256`, `KeccakF1600`, `Sponge<RATE>` | FIPS 202, SP 800-185 |
| `md::v4`, `md::v5` | `MD4`, `MD5` | RFC 1320, RFC 1321 (broken: compatibility only) |
| `ripemd` | `RIPEMD128`, `RIPEMD160`, `RIPEMD256`, `RIPEMD320` | Dobbertin, Bosselaers, Preneel |
| `sm3` | `SM3` | GB/T 32905-2016 |
| `streebog` | `Streebog256`, `Streebog512` | GOST R 34.11-2012, RFC 6986 |
| `blake::v2` | `BLAKE2b`, `BLAKE2s`, `BLAKE2bp`, `BLAKE2sp`, `BLAKE2Xb`, `BLAKE2Xs`, `BLAKE2b160` … `BLAKE2s256`, `BLAKE2bParameters`, `BLAKE2sParameters` | RFC 7693, the BLAKE2 and BLAKE2X specifications |
| `blake::v3` | `BLAKE3`, `BLAKE3Reader`, `BLAKE3Chunk`, `BLAKE3Output` | the BLAKE3 specification |
| `ascon` | `AsconHash256`, `AsconXOF128`, `AsconCXOF128`, `AsconReader`, `AsconSponge`, `AsconPermutation` | NIST SP 800-232 |
| `siphash` | `SipHash<C, D>`, `SipHash128<C, D>`, `HalfSipHash<C, D>`, `HalfSipHash64<C, D>` and aliases such as `SipHash24` | the SipHash paper and reference code |
| `xxhash::xxh32`, `xxh64`, `xxh3` | `XXH32`, `XXH64`, `XXH3_64`, `XXH3_128` | the xxHash specification 0.2.0 |
| `crc` | `CRCTable<W>`, `CRC<W>`, `CRCParameters<W>`, `CRCCatalogue` | the Rocksoft model and the RevEng catalogue |
| `adler32` | `Adler32` (`checksum`, `value`, `with_value` to continue a checksum) | RFC 1950 sections 8 and 9; the digest is the value in big-endian order |

## Behavior

- **Byte order of Streebog.** GOST R 34.11-2012 and RFC 6986 write messages
  and hash codes as numbers, last byte first. umilib takes and returns byte
  strings in the order they are transmitted, so the examples of RFC 6986
  read reversed are the inputs and outputs.
- **SHA-2.** `SHA256::with_state` and `SHA512::with_state` take another
  initial hash value, such as `SHA512::truncated_initial_state(t)` for
  SHA-512/t, which `reset` keeps; `finalize_truncated(out)` writes the
  leftmost `out.len()` bytes.
- **SHA-3 and Keccak.** `Keccak256` uses the padding of the Keccak submission
  (domain bits `0x01`), as Ethereum does; `SHA3_256` uses FIPS 202 (`0x06`).
- **cSHAKE** with an empty function name and customization is SHAKE, as SP
  800-185 defines it.
- **TupleHash** absorbs its strings with `push`; its output length is part of
  the input, so `finalize(out)` and the XOF variant `finalize_xof()` differ.
- **ParallelHash** fails with `InvalidParameter` for blocks of 0 bytes.
- **BLAKE2.** `BLAKE2b::new(n)` and `with_key(key, n)` take an output of 1 to
  64 bytes (32 for BLAKE2s) and a key of up to 64 bytes (32);
  `with_parameters` takes every field of the parameter block, whose
  `key_length` must be the key's length. `finalize_into(out)` writes exactly
  the output length and returns the state to its start. The inner length
  cannot exceed the maximum output; a depth of 0 is allowed because the
  output nodes of BLAKE2X use it. BLAKE2X takes the output length when it is
  created, or `UNKNOWN_LENGTH` to choose it when finalizing, and the root's
  parameters (salt, personalization) through `with_parameters`. Besides
  `finalize_into`, `finalize_xof` returns a reader that computes the output
  nodes as they are read; with `UNKNOWN_LENGTH` its nodes are all whole, so
  it equals `finalize_into` for lengths that are multiples of the node size.
- **BLAKE3.** `new` is the hash mode, `with_key(&[u8; 32])` the keyed hash
  mode and `with_context(context)` the key derivation mode; `Digest` gives the
  default 32 bytes and `finalize_xof` any length up to 2^64 bytes, readable
  from any position (`set_position`). `root()` gives the output without
  consuming the state.
- **Ascon.** The functions of SP 800-232 are byte-oriented and little-endian,
  as the standard specifies. `AsconCXOF128::new(customization)` takes a
  customization string of at most 256 bytes (`InvalidParameter`), which
  `reset` keeps. `AsconPermutation` is Ascon-p with 1 to 16 rounds, which
  `AsconAEAD128` shares.
- **SipHash** is keyed: construct it with `new(&key)`, or hash once with
  `hash(&key, data)`. It implements
  `core::hash::Hasher` (64-bit outputs only). The integer methods of
  `Hasher` write bytes in native order, so their results differ between byte
  orders; hash byte slices for portable results.
- **xxHash** is not cryptographic: it detects accidental changes only. The
  output bytes of `Digest` are the canonical, big-endian form of `value()`,
  and `hash(seed, data)` gives the value at once. Every type has `new()` (the
  seed 0) and `with_seed(seed)`; XXH3 also takes a secret of at least 136
  bytes (`with_secret`, or `XXH3Secret`, whose constructors check it); the
  seed 0 is the default secret. A seed that protects a hash table from chosen
  collisions is a key, so seeds and secrets are hidden from `Debug` and
  zeroized on drop.
- **CRC.** `CRCTable::<W>::new(parameters)` is a `const fn` (the presets are
  built at compile time) and fails unless the width is 1 to the bits of `W`,
  every value fits the width and `check` is the CRC of `123456789`, which
  catches mistyped parameters; the residue is not checked. `CRCCatalogue` holds every algorithm of the RevEng
  catalogue as a constant (`CRCCatalogue::CRC32_ISO_HDLC`), and the lists
  `TABLES_U8` … `TABLES_U128` for lookups by name. `CRC::remainder` is the
  register before the final xor: after an error-free codeword of whole bytes
  it equals the `residue` of the parameters (34 algorithms of the catalogue
  have widths that no byte string fills, so the byte interface never reaches
  their residue).

## Performance

The implementations are portable and constant-time; none uses
processor-specific instructions yet. Streebog is the slowest (about 3 MiB/s)
because its S-box is evaluated by scanning all 256 entries for every byte
instead of an indexed table lookup, which would leak the data through the
cache. `cargo bench --features "platform-bench hash"` measures all of them.

## C and Python

Every hash type is an opaque C handle with `_new`, `_free`, `_clone`,
`_update`, `_finalize` (which releases the handle on success, as the Rust
method consumes the state), `_finalize_reset`, `_reset`, `_digest` and the
sizes; outputs are written into caller memory of exactly the output size.
Generic types are exported for the parameters C can name: `Sponge<168>` as
`Sponge168`, `SipHash<2, 4>` as `SipHash24`, and one `CRCTable` and `CRC`
for every register type with 128-bit values (`umilib_ffi_U128`); a `CRC`
computation keeps its own copy of its table. Functions that read input and
write output reject ranges that overlap (`InvalidArgument`).
`BLAKE2bParameters` is a C structure. In Python (`umilib.hash`), every type
is a class with the same methods; `finalize` returns `bytes` and releases the
object, so `clone()` first to keep it:

```python
from umilib.hash.sha.v2 import SHA256
from umilib.hash.crc import CRC, CRCCatalogue

SHA256.digest(b"abc")
CRC.checksum(CRCCatalogue.CRC32_ISO_HDLC, b"123456789")  # 0xCBF43926
```
