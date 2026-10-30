# `umilib::codec::lz4`

LZ4: the block format (lz4_Block_format.md) and the frame format
(lz4_Frame_format.md, version 1.6). Feature: `codec-lz4` (uses
`codec-lz77` and `hash-xxhash-xxh32`). The streaming interface is that of
[codec-compression.md](codec-compression.md).

## Blocks

`LZ4Block` encodes and decodes blocks, which carry no sizes:

- `LZ4Block::compress(data, level)` and `LZ4Block::decompress(block,
  limit)` work on one block with no history; `decompress` reads the whole
  block and fails with `LimitExceeded` beyond `limit` bytes, and with
  `InvalidData` for an offset of 0 or beyond the data, or a truncated block.
- `LZ4Block::new(level)`, `reset(prefix)` and `encode(data, out)` encode
  blocks that refer to a history (a dictionary, or the previous blocks of a
  frame, up to 65535 bytes back); `LZ4Block::decode(block, out, limit)`
  appends a block's data to `out`, whose bytes are its history.
- The encoder follows the end-of-block rules of the format (the last 5
  bytes are literals; the last match starts at least 12 bytes before the
  end); the decoder does not require them of other encoders.
- Levels 0 to 12: the encoder examines 1 candidate per position at levels
  0 to 2 and up to 4096 at level 12 (`LZ4Block::CHAIN_LIMITS`).

## Frames

`LZ4Compressor` writes a frame: the header, blocks of
`LZ4Config::block_size` (64 KiB by default), each compressed or, when that
is not smaller, stored uncompressed, the end mark and the checksums.
`LZ4Config` sets the level (1 by default), independent blocks (the
default) or blocks linked to the 64 KiB before them, the block checksum
(off), the content checksum (on), the content size (absent; a stream of
another size fails with `InvalidParameter` when it finishes) and a
dictionary with an optional identifier.

`LZ4Decompressor` reads frames, skippable frames and legacy frames. By
default (`LZ4DecompressorConfig::multiple_frames`) the input is a series
of frames, as the `lz4` tool reads, which ends with the input (call
`finish`, as `decompress_to_vec` does); otherwise it reads one frame and
leaves what follows. It checks the version, the reserved bits, the header
checksum, the block sizes, the block and content checksums and the content
size, and fails with:

- `LimitExceeded` for a block maximum size above `maximum_block_size`
  (4 MiB by default; legacy frames need 8 MiB, so they are refused unless
  the limit allows them);
- `MissingDictionary { identifier }` for a frame that names a dictionary
  when the decompressor has none, or one of another identifier. A
  dictionary given without an identifier is used for every frame.

Blocks are held whole while they are read and decoded (at most the block
maximum size, plus the 64 KiB of history of linked blocks).

## C and Python

`umilib_codec_lz4_lz4_block_compress` and `_lz4_block_decompress` work on
blocks; `umilib_codec_lz4_lz4_compressor_new` and `_lz4_decompressor_new`
take the fields of the configurations (block sizes as the codes 4 to 7 of
the format, a null dictionary for none). Python has `LZ4Block`,
`LZ4BlockSize`, `LZ4Config` and `LZ4DecompressorConfig`.
