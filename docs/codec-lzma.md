# `umilib::codec::lzma`

LZMA (the lzma-specification of Igor Pavlov) and LZMA2. Feature:
`codec-lzma` (uses `codec-lz77`). The streaming interface is that of
[codec-compression.md](codec-compression.md).

| Format | Types | Notes |
| --- | --- | --- |
| .lzma files | `LZMACompressor`, `LZMADecompressor` | A header (properties, dictionary size, uncompressed size), then one LZMA stream |
| Raw LZMA2 | `LZMA2Compressor`, `LZMA2Decompressor` | Chunks of at most 2 MiB of data and 64 KiB compressed, ended by 0; the dictionary size is given out of band |

The .xz container, which holds LZMA2 streams with filters, checks and an
index, is in [codec-xz.md](codec-xz.md).

## Compression

`LZMAConfig` sets the level (0 to 9, 6 by default), the properties
(`LZMAProperties`: lc 0 to 8, lp 0 to 4, pb 0 to 4; 3, 0, 2 by default;
LZMA2 requires lc + lp at most 4), the dictionary size (by default that of
xz's preset of the level: 256 KiB at 0, 8 MiB at 6, 64 MiB at 9) and, for
.lzma files, the size of the data. The encoder parses greedily with hash
chains (`LZMALevel` sets the candidates and the length that ends a
search), prefers the last four distances, and defers a match when the next
position has a longer one; its streams are within about a fifth of
liblzma's at the same preset.

- .lzma files end with an end marker, unless the size of the data is set
  (then finishing a stream of another size fails with `InvalidParameter`).
  LZMA cannot be flushed without ending the stream: a sync flush fails with
  `InvalidParameter`.
- LZMA2 chunks are LZMA-compressed or, when that is not smaller, stored;
  a sync flush ends the chunk. `LZMA2Compressor::dictionary_size` is the
  dictionary its decompressor needs (`LZMAFormat::lzma2_dictionary_byte`
  gives the byte the xz format records it as).

## Decompression

`LZMADecompressor` checks the properties, the first byte of the range
coder, every distance (within the data and the dictionary), the
uncompressed size of the header (the stream may end there, or with an end
marker after it) and that the range decoder ends with a zero code.
`LZMADecompressorConfig::maximum_dictionary_size` (64 MiB by default)
bounds the dictionary a file may ask for (`LimitExceeded`); the window
grows with the data up to it.

`LZMA2Decompressor` needs the dictionary size of the stream
(`LZMA2DecompressorConfig::dictionary_size`, 8 MiB by default) and checks
the chunks as liblzma does: the first chunk resets the dictionary, an LZMA
chunk after a dictionary reset sets properties, control bytes 3 to 0x7F
are invalid, and each LZMA chunk holds exactly its sizes, has no end
marker and leaves the range decoder finished.

Both decoders hold at most the input of one symbol (64 bytes) between
calls: a symbol cut by the end of the input is undone and decoded again
with more input.

## Parts

`LZMARangeEncoder` and `LZMARangeDecoder` (the range coder), `LZMAModel`
(the probabilities, the state and the last distances), `LZMAEncoder` and
`LZMADecoder` (symbol coding) can be used to build other LZMA containers.

## C and Python

`umilib_codec_lzma_lzma_compressor_new(level, lc, lp, pb,
has_dictionary_size, dictionary_size, has_uncompressed_size, size)`,
`_lzma_decompressor_new(maximum_dictionary_size)`,
`_lzma2_compressor_new(level, lc, lp, pb, has_dictionary_size,
dictionary_size)` with `_lzma2_compressor_dictionary_size`, and
`_lzma2_decompressor_new(dictionary_size)`. Python mirrors them with
`LZMAConfig`, `LZMAProperties`, `LZMADecompressorConfig` and
`LZMA2DecompressorConfig`; its tests check both directions against
Python's `lzma` module (liblzma).
