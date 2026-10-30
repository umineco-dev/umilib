# `umilib::codec::huffman`

Huffman coding. Features: `codec-huffman-canonical` and
`codec-huffman-adaptive` (both use `bytes`); `codec-huffman` enables both.

## Canonical codes (`canonical`)

- `HuffmanCode` is a canonical prefix code (RFC 1951 section 3.2.2): the
  lengths of the codes of the symbols 0, 1, ... define the codes.
  `from_lengths` checks the lengths (at most 32, as HPACK's codes of up
  to 30 bits need; over-subscribed lengths
  fail with `InvalidLengths`) and accepts incomplete codes, which
  `is_complete` tells. `from_frequencies(frequencies, maximum_length)`
  builds an optimal code within a length limit (package-merge); symbols of
  frequency 0 get no code and a single used symbol gets a code of 1 bit.
  `code` gives a code first bit most significant, `reversed_code` first bit
  least significant, for writing with `BitWriter`.
- `HuffmanTable` decodes the codes of a `HuffmanCode` from a bit stream of
  either `bytes::BitOrder`: `LeastSignificantFirst` (Deflate and Brotli,
  where a code starts at the least significant bit) uses a first table of
  10 bits and second tables for longer codes; `MostSignificantFirst`
  (Zstandard's backward streams, HPACK) one table of the longest code. A
  code longer than 15 bits (`HuffmanTable::DIRECT_BITS`) would make tables
  of millions of entries: then codes of up to 10 bits are found in one
  lookup and longer ones by searching the canonical order a length at a
  time. `decode(bits)` takes the next `peek_bits()` bits; `peek` and `read`
  decode straight from a `BitQueue`.

```rust
use umilib::bytes::BitOrder;
use umilib::codec::huffman::canonical::{HuffmanCode, HuffmanTable};

let code = HuffmanCode::from_lengths(&[3, 3, 3, 3, 3, 2, 4, 4])?;      // codes 010, 011, …, 00, 1110, 1111
let table = HuffmanTable::new(&code, BitOrder::LeastSignificantFirst);
let (symbol, length) = table.decode(0b1110)?;                          // the bits 0, 1, 1, 1: (6, 4)
```

### Block format

`CanonicalHuffmanCompressor` and `CanonicalHuffmanDecompressor` compress
bytes in a format of this library (`CanonicalHuffmanFormat`); no standard
defines one. A stream is a sequence of blocks, each:

1. 1 bit, 1 for the last block;
2. the code lengths of 257 symbols (the bytes 0 to 255, then the end of the
   block, 256), 4 bits each: a complete code, or a code of a single symbol
   of 1 bit, in which the end of the block has a code;
3. the codes of the bytes of the block, then the code of the end of the block;
4. zero bits to the next byte boundary.

Bits are packed least significant first and codes start with their first
bit, as in Deflate. The compressor ends a block every
`CanonicalHuffmanConfig::block_size` bytes (64 KiB by default) and at each
sync flush; each block costs 129 bytes of code lengths.

## Adaptive coding (`adaptive`)

`AdaptiveHuffmanTree` is the code tree of Vitter's algorithm Λ (J. S.
Vitter, "Design and Analysis of Dynamic Huffman Codes", JACM 34(4), 1987):
`update(symbol)` keeps it a Huffman tree of the counts so far.
`code(symbol)` gives the code of a symbol (with the fixed-length index that
follows the code of the unseen leaf for a new symbol: with symbols = 2^e +
r, the symbol s in e + 1 bits if s < 2r, else s - r in e bits, most
significant bit first).

`AdaptiveHuffmanCompressor` and `AdaptiveHuffmanDecompressor` compress bytes
in a format of this library (`AdaptiveHuffmanFormat`): the codes of the
symbols of a tree of 258 symbols (the bytes, `END` = 256 and `FLUSH` = 257),
the tree updated after each symbol. After `FLUSH` (written by a sync flush)
and after `END`, which ends the stream, zero bits pad to a byte boundary.
Bits are packed as in the block format.

## Behavior

- The decompressors need no buffer: codes are decoded straight into the
  output, and they take an input byte only when the bits of a code need it,
  so they stop at the last byte of their stream.
- Nonzero padding, code lengths the format does not allow and codes that
  are not in the code fail with `InvalidData`.

## C and Python

The C ABI exports the compressors and decompressors as described in
[codec-compression.md](codec-compression.md), with the constructors
`umilib_codec_huffman_canonical_canonical_huffman_compressor_new(block_size)`,
`_canonical_huffman_decompressor_new`,
`umilib_codec_huffman_adaptive_adaptive_huffman_compressor_new` and
`_adaptive_huffman_decompressor_new`; `HuffmanCode`, `HuffmanTable` (bit
order 0 for `LeastSignificantFirst`, 1 for `MostSignificantFirst`) and
`AdaptiveHuffmanTree` with their functions. Errors of codes have the domain
`codec.huffman`. Python mirrors them in `umilib.codec.huffman.canonical`
and `umilib.codec.huffman.adaptive`.
