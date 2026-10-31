# `umilib::codec::deflate`, `zlib` and `gzip`

Deflate (RFC 1951) and its two containers, zlib (RFC 1950) and gzip
(RFC 1952). Features: `codec-deflate` (uses `bytes`,
`codec-huffman-canonical` and `codec-lz77`), `codec-zlib` (adds
`hash-adler32`) and `codec-gzip` (adds `hash-crc`). The streaming
interface is that of [codec-compression.md](codec-compression.md).

```rust
use umilib::codec::{Compressor, Decompressor};
use umilib::codec::deflate::{DeflateConfig, DeflateDecompressorConfig};
use umilib::codec::zlib::{ZlibCompressor, ZlibDecompressor};

let stream = ZlibCompressor::new(DeflateConfig { level: 9, window_bits: 15 })?.compress_to_vec(data)?;
let data = ZlibDecompressor::new(DeflateDecompressorConfig::default())?.decompress_to_vec(&stream, 1 << 24)?;
```

## Deflate (`deflate`)

- `DeflateCompressor` writes raw Deflate streams. `DeflateConfig::level`
  (0 to 9, 6 by default) selects the search of zlib's level of the same
  number (`DeflateLevel`): greedy matching for 1 to 3, lazy matching for 4
  to 9; level 0 writes stored blocks. `window_bits` (8 to 15, 15 by
  default) bounds the distances. Each block holds at most 16383 symbols and
  is written as stored, fixed or dynamic, whichever takes the fewest bits;
  dynamic codes always have at least two codes, as zlib's do.
- A sync flush ends the block and writes an empty stored block
  (`00 00 FF FF`), as zlib's `Z_SYNC_FLUSH` does; finishing writes the last
  block (an empty stream is an empty fixed block, `03 00`).
- `DeflateDecompressor` reads raw Deflate streams with the checks of zlib:
  a block type of 3, stored lengths that do not match, more than 286
  literal/length or 30 distance codes, over-subscribed or incomplete codes
  (except a literal/length or distance code of a single symbol of 1 bit or,
  for distances, none), a repeat with no previous length, too many code
  lengths, no code for the end of a block, the symbols 286, 287, 30 and 31,
  and distances before the start of the data fail with `InvalidData`.
  `DeflateDecompressorConfig::window_bits` (15 by default) sets the window
  it keeps: a match reaching farther back fails with `LimitExceeded`.
- `set_dictionary` on either side makes bytes the history before the data
  (a preset dictionary), before the first call.
- After the last block (BFINAL), `DeflateDecompressor::resume` reads the
  blocks that follow at the next byte boundary with the history kept, as
  permessage-deflate's messages need (RFC 7692 §7.2.1).
- `DeflateBlock`, `DeflateSymbol`, `DeflateFormat` (the tables of section
  3.2.5, the fixed codes and the order of the code length code) are the
  parts the compressor is built from.

## zlib (`zlib`)

`ZlibCompressor` writes the header (CMF with CINFO from the window, FLG
with FLEVEL as zlib sets it and FCHECK), the Deflate stream and the
Adler-32 of the data. `ZlibCompressor::with_dictionary` sets FDICT and
writes the Adler-32 of the dictionary. `ZlibDecompressor` checks the
method, the window (larger than its own: `LimitExceeded`), FCHECK and the
Adler-32 (`ChecksumMismatch`); a stream that names a dictionary needs
`ZlibDecompressor::with_dictionary` with that dictionary, otherwise it
fails with `MissingDictionary { identifier }`.

## gzip (`gzip`)

`GzipCompressor` writes one member: a header (`GzipHeader`: the text flag,
the modification time, XFL — 2 at level 9 and 4 at level 1 unless set —,
the operating system, 255 by default, and the optional extra field, name,
comment and header CRC), the Deflate stream, then the CRC-32 and the size
of the data. Names and comments may not hold zero bytes (`InvalidParameter`).

`GzipDecompressor` reads gzip files: by default
(`GzipDecompressorConfig::multiple_members`) any number of members, one
after the other, and zero bytes after the last one (padding); such a file
ends with its input, so call `finish` (as `decompress_to_vec` does). With
`multiple_members: false` it reads one member and leaves what follows. It
checks the magic, the method, the reserved flags, the header CRC and the
trailer (`ChecksumMismatch`), and bounds the optional fields by
`maximum_field` (64 KiB by default; `LimitExceeded`). Its `deflate` field
sets the window kept, as for zlib: gzip does not announce the window a
member uses, so a window below the default 32 KiB saves memory but fails
members whose matches reach farther (`LimitExceeded`). `header()` gives the
header of the member read, `members()` the number of members.

## C and Python

The constructors are `umilib_codec_deflate_deflate_compressor_new(level,
window_bits)`, `_deflate_decompressor_new(window_bits)` and their
`_set_dictionary`; `umilib_codec_zlib_zlib_compressor_new(level,
window_bits, dictionary, length)` and `_zlib_decompressor_new(window_bits,
dictionary, length)`, a null dictionary meaning none;
`umilib_codec_gzip_gzip_compressor_new` with the fields of the header and
`_gzip_decompressor_new(multiple_members, maximum_field, window_bits)`, whose header is
read with `_gzip_decompressor_header` and `_header_field` (0 extra, 1 name,
2 comment). Python mirrors them with `DeflateConfig`,
`DeflateDecompressorConfig`, `GzipHeader`, `GzipConfig` and
`GzipDecompressorConfig`; its tests check both directions against Python's
`zlib` and `gzip` modules.
