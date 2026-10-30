# `umilib::codec::brotli`

Brotli (RFC 7932). Feature: `codec-brotli` (uses `bytes`,
`codec-huffman-canonical` and `codec-lz77`). The streaming interface is
that of [codec-compression.md](codec-compression.md).

## Compression

`BrotliCompressor` writes one stream: the window size (WBITS), meta-blocks
of up to 256 KiB (the window, kept within 64 KiB to 256 KiB), and an empty
last meta-block. Each meta-block is the smaller of:

- a compressed meta-block: one block type per category, one prefix code
  each for literals, insert-and-copy lengths and distances (simple codes
  for up to 4 symbols, complex codes otherwise), matches found by hash
  chains, the last four distances preferred (the distance code 0 implicit
  when the command allows it, and the short codes of section 4);
- an uncompressed meta-block, for data that does not compress (random data
  grows by a few bytes per meta-block).

`BrotliConfig` sets the level (0 to 11, 6 by default: `BrotliLevel` gives
the candidates examined and the length that ends a search; levels from 4
on defer a match when the next position has a longer one) and WBITS (10 to
24, 22 by default): matches reach back 2^WBITS - 16 bytes, and a
decompressor keeps that much history. A sync flush ends the data so far at
a byte boundary, with an empty metadata meta-block when needed (RFC 7932
section 11.2); a sync flush right after another emits nothing.

The compressor does not model literal contexts or search the static
dictionary: at level 11 its streams are within an eighth of those of the
brotli tool at quality 11 on English text, and close on repetitive data.

## Decompression

`BrotliDecompressor` reads one stream. The stream marks its end (its last
meta-block): the bytes after it are not consumed. It checks every rule of
the format and those the reference decoder adds:

- WBITS (the pattern 1000100 of the large-window extension is rejected),
  reserved bits, and fill bits that must be zero (after metadata and
  uncompressed meta-block headers, and after the last meta-block);
- lengths written with a superfluous zero byte or nibble;
- prefix codes: distinct symbols within the alphabet for simple codes,
  complete codes (and code length codes) for complex ones, repeats within
  the alphabet; context map runs within the map;
- commands within their meta-block (insert lengths, copy lengths and
  dictionary words), short distance codes that resolve to a positive
  distance, dictionary references of a valid length and transform.

`BrotliDecompressorConfig::maximum_window_bits` (10 to 24, 24 by default,
the largest of the format, so that every stream decodes) bounds the window
a stream may ask for: a larger one fails with `LimitExceeded`. The history
grows with the data up to the window. Besides the window, the prefix codes
of a meta-block are held (at most 256 for literals, for insert-and-copy
lengths and for distances).

Metadata meta-blocks are skipped.

## The static dictionary

The 122,784-byte dictionary of RFC 7932 Appendix A is part of the library
(`BrotliFormat::DICTIONARY`, with `BrotliFormat::word` and
`BrotliFormat::transform` for its words and the 121 transformations of
Appendix B). It is code of the RFC, under the license of its code
components (Section 4.c of the IETF Trust Legal Provisions, a BSD license):
the third-party notice in LICENSE must accompany copies of the library.

## Parts

`BrotliPrefixCode` and `BrotliPrefixReader` (prefix codes and their
descriptions), `BrotliContextMap` and `BrotliContextMapReader` (context
maps, move-to-front), `BrotliBlockSwitch` (block types and counts),
`BrotliDistances` (distance codes and the ring of last distances) and
`BrotliFormat` (the constants, context lookup tables, insert-and-copy
length cells, dictionary and transforms) are usable on their own. The
readers resume where their input ended, so they work on streamed input.

## C and Python

`umilib_codec_brotli_brotli_compressor_new(level, window_bits)`,
`_brotli_decompressor_new(maximum_window_bits)` and
`_brotli_config_defaults(level, window_bits, maximum_window_bits)`, with the
functions every compressed format has. Python mirrors them with
`BrotliConfig` and `BrotliDecompressorConfig`; its tests check both
directions against the `brotli` command line utility when it is installed.
