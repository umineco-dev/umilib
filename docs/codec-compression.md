# Compression in `umilib::codec`

Every compressed format of `umilib::codec` has a compressor and a
decompressor with the same streaming interface, the traits `Compressor` and
`Decompressor` (always compiled with any `codec-*` feature). They do no
I/O: each call takes a slice of input and a slice of output, does what it
can, and says what it did in a `Progress`.

| Format | Module | Feature | Specification |
| --- | --- | --- | --- |
| Canonical Huffman blocks | `huffman::canonical` | `codec-huffman-canonical` | A format of this library ([codec-huffman.md](codec-huffman.md)) |
| Adaptive Huffman | `huffman::adaptive` | `codec-huffman-adaptive` | A format of this library, Vitter's algorithm Λ ([codec-huffman.md](codec-huffman.md)) |
| PackBits | `rle` | `codec-rle` | Apple TN1023 ([codec-rle.md](codec-rle.md)) |
| LZ77 | `lz77` | `codec-lz77` | A format of this library ([codec-lz.md](codec-lz.md)) |
| LZ78 | `lz78` | `codec-lz78` | A format of this library ([codec-lz.md](codec-lz.md)) |
| LZSS | `lzss` | `codec-lzss` | Haruhiko Okumura's `lzss.c` ([codec-lz.md](codec-lz.md)) |
| Deflate | `deflate` | `codec-deflate` | RFC 1951 ([codec-deflate.md](codec-deflate.md)) |
| zlib | `zlib` | `codec-zlib` | RFC 1950 ([codec-deflate.md](codec-deflate.md)) |
| gzip | `gzip` | `codec-gzip` | RFC 1952 ([codec-deflate.md](codec-deflate.md)) |
| LZMA, LZMA2 | `lzma` | `codec-lzma` | lzma-specification ([codec-lzma.md](codec-lzma.md)) |
| .xz | `xz` | `codec-xz` | The .xz File Format 1.2.1 ([codec-xz.md](codec-xz.md)) |
| Zstandard | `zstandard` | `codec-zstandard` | RFC 8878 ([codec-zstandard.md](codec-zstandard.md)) |
| Brotli | `brotli` | `codec-brotli` | RFC 7932 ([codec-brotli.md](codec-brotli.md)) |
| LZ4 | `lz4` | `codec-lz4` | lz4_Block_format.md, lz4_Frame_format.md ([codec-lz4.md](codec-lz4.md)) |

```rust
use umilib::codec::{Compressor, Decompressor};
use umilib::codec::huffman::adaptive::{AdaptiveHuffmanCompressor, AdaptiveHuffmanDecompressor};

let stream = AdaptiveHuffmanCompressor::new().compress_to_vec(b"data")?;
let data = AdaptiveHuffmanDecompressor::new().decompress_to_vec(&stream, 1 << 20)?;  // at most 1 MiB
```

## Streaming

```rust
let mut output = [0u8; 4096];
loop {
    let progress = compressor.compress(input, &mut output, Flush::Finish)?;
    input = &input[progress.consumed..];
    sink.write_all(&output[..progress.produced])?;
    if progress.finished {
        break;
    }
}
```

- `compress(input, output, flush)` consumes what it can of `input`,
  buffering up to a block of its format, and writes what it can into
  `output`. `Flush::None` keeps input for the best compression,
  `Flush::Sync` makes everything consumed so far decodable without ending
  the stream, and `Flush::Finish` ends it: keep calling with `Finish` (and
  the rest of the input) until `progress.finished`, then `reset` to start a
  new stream.
- `decompress(input, output)` consumes what it can and writes what it can.
  It returns when it needs more input or more room; `finished` is set when
  the stream ended, and the bytes after the stream are left unconsumed, so a
  container can read what follows. An output of exactly the size of the
  data is enough to reach the end of the stream.
- `finish()` tells a decompressor that the input ended. The streams of most
  formats mark their end, and `finish` only checks that it was reached; the
  streams of PackBits and LZSS, and gzip and .xz files and LZ4 and Zstandard inputs
  of several members or frames, end with
  their input, and `finish` ends them (failing with `UnexpectedEnd` inside a unit).
- A call that consumed and produced nothing needs more input (for a
  decompressor) or more room. If the input is complete, the stream is
  truncated (or, for PackBits and LZSS, ended): `decompress_to_vec` calls
  `finish`, which reports `UnexpectedEnd` for a truncated stream.
- `compress_to_vec(input)` and `decompress_to_vec(input, limit)` work on
  whole streams. `limit` bounds the output: a stream that decompresses to
  more fails with `LimitExceeded` as soon as the limit is passed.
- After an error the state is undefined: `reset` before reusing it.

## Limits

Decompressing data from an untrusted source must not let a small input use
unbounded memory or time:

- Decompressors write only into the output they are given, and keep no more
  than the units of their format require (a block, a window), each bounded
  by the format or by their configuration; `decompress_to_vec` stops at its
  `limit`.
- Compressors buffer at most one block of input and its compressed form.
- A format that cannot make a sync point (LZSS, .lzma files) fails a sync
  flush with `InvalidParameter`.

## Errors

`CompressionError`: `InvalidData { reason }` (the data break their format),
`ChecksumMismatch`, `LimitExceeded { limit }`, `UnexpectedEnd`,
`InvalidParameter` (a level, a size or a dictionary outside the format),
`MissingDictionary { identifier }` (a stream needs a preset dictionary the
decompressor was not given), `Allocation` and `Unsupported { feature }` (a
stream uses a feature its format reserves or allows that this library does
not support, such as a reserved check type of .xz; the data may be intact).

## C and Python

The C ABI exports, for each compressor type, `_free`, `_clone`, `_reset`,
`_compress` and `_compress_to_vec`, and for each decompressor `_free`,
`_clone`, `_reset`, `_decompress`, `_finish` and `_decompress_to_vec`; the
constructors are those of each format. `_compress` and `_decompress` write
a `umilib_codec_Progress` (`consumed`, `produced`, `finished`); flushes are
0 (none), 1 (sync) and 2 (finish). Errors have the domain `codec`.

In Python, `umilib.codec.Compressor` and `Decompressor` are the bases of the
types of every format, with the same methods; `compress` and `decompress`
write into a `bytearray` and return a `Progress`, and `Flush.None_` stands
for `Flush::None`.
