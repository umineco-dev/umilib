# `umilib::codec::xz`

The .xz file format (The .xz File Format, version 1.2.1). Feature:
`codec-xz` (uses `codec-lzma`, `codec-filter-bcj`, `codec-filter-delta`,
`hash-crc` and `hash-sha-v2`). The streaming interface is that of
[codec-compression.md](codec-compression.md).

A .xz file is one or more Streams with Stream Padding (null bytes in
multiples of four) between and after them. A Stream is a Stream Header
(magic bytes and the Check type), Blocks, an Index of the Blocks and a
Stream Footer. A Block is a Block Header (its filter chain and, optionally,
its sizes), the data compressed by the filter chain (Delta and BCJ filters,
then LZMA2), padding, and the Check of the uncompressed data.

## Compression

`XZCompressor` writes one Stream. `XZConfig` sets:

- `lzma`: the LZMA2 compression ([codec-lzma.md](codec-lzma.md): level 6
  by default, properties, dictionary size);
- `check`: `XZCheck::None`, `CRC32`, `CRC64` (the default, as xz) or `SHA256`;
- `filters`: up to three filters before LZMA2, in the order they see the
  data: `XZFilter::Delta { distance }` (1 to 256) and
  `XZFilter::BCJ { architecture, start_offset }` (see
  [codec-filter.md](codec-filter.md));
- `block_size`: the uncompressed bytes of a Block; `None` (the default)
  writes one Block, as xz does without threads.

Block Headers do not record sizes (the Index does). The empty input gives
the 32-byte Stream xz writes. A sync flush makes the data so far
decodable: without filters by an LZMA2 flush within the Block; with filters,
which may hold back their last bytes, by ending the Block (the next data
starts a new one). The streams are within a fifth of the size of xz's at the
same level.

## Decompression

`XZDecompressor` reads .xz files. By default
(`XZDecompressorConfig::multiple_streams`) the input is a file of Streams and
Stream Padding that ends with it (call `finish`, as `decompress_to_vec`
does); otherwise it reads one Stream and leaves what follows, as an
embedded .xz Stream is read. Every requirement of the specification is
checked:

- the magic bytes, the CRC32 of the Stream Header, the Block Headers and
  the Stream Footer, the Stream Flags of the header against those of the
  footer, and the Backward Size against the Index;
- integers of at most 9 bytes without a superfluous zero byte; Block
  Headers whose filters, sizes and padding fill them exactly;
- the Compressed Size and Uncompressed Size a Block Header records (data
  beyond them fails as soon as it is decoded), Block Padding of null bytes,
  and the Check of each Block;
- the Index against the Blocks decoded (their number, Unpadded Sizes and
  Uncompressed Sizes, summarized in constant memory with SHA-256, as the
  specification suggests), its padding and its CRC32;
- Stream Padding of multiples of four null bytes.

Errors:

- `InvalidData { reason }` for a corrupt file; `ChecksumMismatch` for a
  Check that does not match the data; `UnexpectedEnd` for an input that
  ends inside a Stream or inside a four-byte unit of Stream Padding;
- `Unsupported { feature }` for what the specification lets newer files use
  and this implementation does not know (the CRC32 of the field matching):
  reserved bits of the Stream Flags and Block Flags, a reserved Check type,
  non-null Header Padding, an unknown filter, a filter chain other than up
  to three Delta or BCJ filters then LZMA2;
- `LimitExceeded` for an LZMA2 dictionary above
  `XZDecompressorConfig::maximum_dictionary_size` (64 MiB by default, the
  dictionary of xz -9; xz -9e and custom dictionaries up to 1.5 GiB need a
  larger limit). The window grows with the data up to the dictionary.

## Parts

`XZFormat` (constants, the CRC32 and the variable-length integers, with
`XZIntegerReader`), `XZCheck` and `XZChecksum`, `XZFilter` (Filter Flags)
and `XZFilterCoder`, `XZBlockHeader`, `XZIndex` (the Index a compressor
writes), `XZIndexReader` and `XZIndexHash` (reading and verifying an Index)
are usable on their own.

## C and Python

`umilib_codec_xz_xz_compressor_new(level, dictionary_size, check,
block_size, filters, filter_count)` (0 for the level's dictionary and for
one Block; the Check as its ID: 0 none, 1 CRC32, 4 CRC64, 10 SHA-256;
filters as `umilib_codec_xz_XZFilterFlags { id, value }` with the Filter
IDs of the specification), `_xz_decompressor_new(maximum_dictionary_size,
multiple_streams)`, `_xz_decompressor_streams` and `_xz_config_defaults`.
Python mirrors them with `XZConfig`, `XZDecompressorConfig`, `XZCheck` and
`XZFilter`; its tests check both directions against Python's `lzma` module
(liblzma), and the ARM64 and RISC-V filters against the `xz` tool.
