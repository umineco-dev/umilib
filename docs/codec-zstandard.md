# `umilib::codec::zstandard`

Zstandard (RFC 8878). Feature: `codec-zstandard` (uses `bytes`,
`codec-fse`, `codec-huffman-canonical`, `codec-lz77` and
`hash-xxhash-xxh64`). The
streaming interface is that of [codec-compression.md](codec-compression.md).

## Compression

`ZstandardCompressor` writes one frame: a header with a window descriptor
(and the content size and the dictionary identifier when known), blocks of
at most 128 KiB (or the window, if smaller) and the content checksum (the
low 32 bits of the XXH64 of the data). Each block is the smallest of a
compressed block, a raw block and an RLE block; compressed blocks hold
literals (raw, RLE or Huffman-coded in 1 or 4 streams) and sequences whose
tables are RLE, predefined or FSE-compressed.

`ZstandardConfig` sets the level (1 to 19, 3 by default: `ZstandardLevel`
gives the window, the candidates examined and the length that ends a
search; levels from 4 on defer a match when the next position has a longer
one), the window log (10 to 30, overriding the level's), the checksum (on),
the content size (finishing a stream of another size fails with
`InvalidParameter`) and a dictionary. A sync flush ends the block. Frames
are within about a fifth of the reference encoder's at the same level.

## Decompression

`ZstandardDecompressor` reads frames and skippable frames. By default
(`ZstandardDecompressorConfig::multiple_frames`) the input is a series of
frames, as the `zstd` tool reads, which ends with the input (call `finish`,
as `decompress_to_vec` does); otherwise it reads one frame and leaves what
follows. It checks every structure of the format: the reserved bit and
block type, block sizes, literals and sequences sections, Huffman and FSE
tables (accuracy logs, totals, complete codes), the exact consumption of
every bitstream, offsets within the window (and the dictionary while the
frame is within its window), the content size and the checksum, and fails
with:

- `LimitExceeded` for a window above `maximum_window` (128 MiB by default,
  the default limit of the reference decoder); the history grows with the
  data up to the window;
- `MissingDictionary { identifier }` for a frame that names a dictionary
  the decompressor was not given.

Blocks are held whole while they are read and decoded (at most 128 KiB).

## Dictionaries

`ZstandardDictionary::new(bytes)` reads a formatted dictionary (as `zstd
--train` makes: an identifier, entropy tables, repeat offsets and content)
or raw content (any other bytes, at least 8). The decompressor gives it to
the frames that name its identifier, and a raw dictionary to the frames
that name none; the compressor uses its content as the history before the
data and writes its identifier.

## Parts

`ZstandardHuffman` (the Huffman codes of literals and their descriptions),
`ZstandardLiterals`, `ZstandardSequences` and `ZstandardOffsets` (the
sections of a block and the repeat offsets) are usable on their own. The
entropy coder of the sequences and of the Huffman weights is the general
FSE module ([codec-fse.md](codec-fse.md)), and the backward bitstreams are
`bytes::BackwardBitReader` and `bytes::BackwardBitWriter`
([bytes.md](bytes.md)).

Note: two tables of RFC 8878 have errors. Table 18 (repeat offsets) shows
offset value 1 where 3 was meant in one row and a wrong third offset in the
next; Table 26 (Huffman example) gives the symbols 4 and 5 each other's
code. This implementation follows the text of sections 3.1.1.5 and 4.2.1.3,
as the reference implementation does.

## C and Python

`umilib_codec_zstandard_zstandard_dictionary_new` (and `_free`,
`_identifier`), `_zstandard_compressor_new(level, has_window_log,
window_log, content_checksum, has_content_size, content_size, dictionary)`
and `_zstandard_decompressor_new(maximum_window, multiple_frames,
dictionary)`, a null dictionary meaning none. Python mirrors them with
`ZstandardDictionary`, `ZstandardConfig` and `ZstandardDecompressorConfig`;
its tests check both directions against Python's `compression.zstd`.
