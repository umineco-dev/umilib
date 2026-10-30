# `umilib::codec::base`

Binary-to-text encodings. Features: `codec-base` (all), or one of
`codec-base-base16`, `codec-base-base32`, `codec-base-base58`,
`codec-base-base64`, `codec-base-base85` (aliases `codec-base16`, ...).

Every encoding implements `Encoding`:

| Method | Meaning |
| --- | --- |
| `encode(input) -> String` | Encodes; panics only if memory cannot be allocated (`try_encode` returns an error instead) |
| `decode(input) -> Result<Vec<u8>, BaseError>` | Decodes strictly |
| `encode_to_slice` / `decode_to_slice` | Write into a slice you provide; no allocation |
| `maximum_encoded_length(n)` / `maximum_decoded_length(n)` | Buffer sizes (exact for Base16/32/64) |

| Type | Presets | Specification |
| --- | --- | --- |
| `Base16` | `UPPER` (RFC), `LOWER`; decoding accepts both cases | RFC 4648 §8 |
| `Base32` | `STANDARD`, `STANDARD_NO_PADDING`, `HEX`, `HEX_NO_PADDING`; `*_ALPHABET_ANY_CASE` alphabets also accept lowercase | RFC 4648 §6, §7 |
| `Base64` | `STANDARD`, `STANDARD_NO_PADDING`, `URL_SAFE`, `URL_SAFE_NO_PADDING` (JWT) | RFC 4648 §4, §5 |
| `Base58` | `BITCOIN`, `FLICKR`, `RIPPLE`; input limited to `maximum_length` (default 4096) because the conversion is quadratic | Bitcoin |
| `Base85` | `ASCII85`, `ASCII85_ADOBE` (`<~`…`~>`), `Z85` (ZeroMQ RFC 32), `RFC1924` (Git, Python `b85encode`) | Adobe PLRM, ZeroMQ RFC 32, RFC 1924 |

## Strict decoding

Decoding rejects, with the position of the problem:

- characters outside the alphabet, including white space and line breaks
  (strip them first if your format allows them; Ascii85 skips white space as
  Adobe specifies);
- missing, misplaced or forbidden padding, and lengths no encoding produces;
- **non-canonical text**: text whose unused bits are set (`Zh==` instead of
  `Zg==`, RFC 4648 §3.5) or, in Base85, a partial group other than the one the
  encoder writes. Every accepted text is therefore the unique encoding of its
  bytes, which prevents malleability.

The padding and the length are checked before the characters.

## Constant time

Base16, Base32 and Base64 (and every `Alphabet`) convert characters with
arithmetic masks over the runs of the alphabet instead of table lookups, so
encoding and decoding secrets (keys in PEM files, tokens) does not leak them
through cache timing. Only whether the text is valid is observable. Base58 is
not constant-time.

## Custom alphabets

`Alphabet::new(&[AlphabetRange::new(first, count, value), ...])` describes an
alphabet as runs of consecutive characters; `AlphabetRange::decode_only` adds
characters accepted only when decoding. Pass it to `Base64::new(alphabet,
padding)` and the like. Custom alphabets need `'static` data and are only
available from Rust; C and Python use the presets. `BitEncoding::is_valid`
checks a custom bit encoding: 1 to 7 bits per character, an alphabet of
exactly `2^bits` characters, and a padding character outside the alphabet
(otherwise padding could not be told from data); the C constructors reject
encodings that are not valid.
