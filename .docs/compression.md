# Compression internals

How the compressed formats of `umilib::codec` are built, and what each one
must keep true. The user-facing interface is in
[docs/codec-compression.md](../docs/codec-compression.md).

## Shared parts

| Part | Where | Used for |
| --- | --- | --- |
| `Compressor`, `Decompressor`, `Flush`, `Progress`, `CompressionError` | `src/codec/*.rs` | The interface of every format |
| `PendingOutput` | `src/codec/pending_output.rs` | Bytes made but not yet delivered (a compressed block, a decoded match) |
| `BitReader`, `BitWriter`, `BitQueue` | `src/bytes/` | LSB-first bit I/O: slices, vectors, and streaming input |
| `BackwardBitReader`, `BackwardBitWriter` | `src/bytes/` | The backward bitstreams of FSE and Zstandard |
| `HuffmanCode`, `HuffmanTable` | `src/codec/huffman/canonical/` | Canonical codes of every Huffman-based format |
| `FSEDistribution`, `FSEDecodingTable`, `FSEEncodingTable` | `src/codec/fse/` | Finite State Entropy (tANS), used by Zstandard |
| `LZ77Window`, `LZ77MatchFinder` | `src/codec/lz77/` | The history of LZ77 decompressors and the match search of their compressors |

Each format module depends on these, never on another format, unless the
format is defined on top of the other (zlib and gzip on Deflate).

## Rules for decompressors

- **Never take a byte past the stream.** Containers (zlib, gzip, frames)
  read what follows, and the interface promises the bytes after a stream
  stay unconsumed. `BitQueue::fill` takes a byte only while fewer bits than
  requested are queued, and `HuffmanTable::peek` asks for one more byte at a
  time only while the queued bits do not hold a whole code. With exact
  requests, fewer than 8 bits are queued when a stream ends.
- **Resume anywhere.** A call may end in the middle of any field. State
  machines keep the field they are in (and the bits already taken, in the
  `BitQueue`), so the next call resumes there; units that must be whole
  before decoding (a block of Zstandard, a chunk of LZMA2) are buffered,
  bounded by the limit the format gives.
- **Finish without spare room.** The end of a stream must be reachable with
  an output of exactly the size of the data: a symbol that ends a block is
  decoded with `peek` and consumed even when the output is full; only
  symbols that produce bytes wait for room.
- **Bounded memory.** Nothing a decompressor allocates may grow with the
  input beyond what its format bounds (window sizes, block sizes); window
  sizes a stream asks for are checked against the configured maximum before
  allocating.
- **Errors are final.** After an error the state need not be consistent;
  callers `reset`.

## Rules for compressors

- Buffer at most a block of input and its encoding (`PendingOutput`);
  deliver pending output before taking more input.
- `Flush::Sync` must leave every consumed byte decodable from the output so
  far, and must not emit anything when nothing was consumed since the last
  flush (callers may repeat it). Formats without a native sync point define
  one (the `FLUSH` symbol of the adaptive Huffman format, the byte-aligned
  blocks of the canonical one).

## Formats that end with their input

PackBits and LZSS mark no end: their decompressors accept the end of the
input between units in `finish`. LZSS's last byte is padded with zero bits,
which must not be readable as a token; that is why `LZSSConfig` requires
EI + EJ >= 7 (a match token then has at least 8 bits). LZSS also has no way
to pad mid-stream, so its compressor refuses `Flush::Sync`.

## Formats without a standard

Huffman-only coding, LZ77 triples and LZ78 pairs have no standard
container, so their formats are defined by this library and documented in
[docs/codec-huffman.md](../docs/codec-huffman.md) and
[docs/codec-lz.md](../docs/codec-lz.md). LZSS follows the reference of its
author, Okumura's `lzss.c`, whose streams are the test vectors. Their tests check the
exact bits of small streams, so a change of the format is a visible,
deliberate change.

## Brotli

The decoder follows the reference decoder where RFC 7932 leaves a choice:

- A category with one block type has no block switches; its block never
  ends (the reference decoder lets the count wrap), even past 2^24
  elements. `BrotliBlockSwitch::switch` restarts the block.
- The RFC says NTREES "must equal" the number of distinct values of a
  context map but lists no rejection; like the reference decoder, maps
  that leave a prefix code unused are accepted.
- Metadata meta-blocks may be the last one (ISLAST set): the stream ends
  after their bytes.

Every header field is read by a reader that resumes where its input ended
(`BrotliPrefixReader`, `BrotliContextMapReader`, `BrotliBlockSwitch`):
nothing is buffered beyond the `BitQueue`, so a header split across inputs
of one byte costs no more than one read whole. A symbol and its extra bits
are consumed together (`BrotliPrefixCode::read_with_extra`, at most
15 + 24 bits); the copy length extra bits of a command are read in their own
state because the command code and both extra bit fields can exceed the 56
bits a `BitQueue` holds.

The compressor writes repeat codes 16 and 17 of complex prefix codes one at
a time, never two in a row, so the extension of a repeat by the next one
(section 3.5) never applies; the reader implements that extension for
streams of other encoders.

## .xz

The decoder follows liblzma where the specification leaves a choice:

- Problems the CRC32 of a field rules out as corruption (reserved bits,
  reserved Check types, non-null Header Padding, unknown filters, chains
  that are not Delta/BCJ then LZMA2) are `Unsupported`, as liblzma reports
  them as unsupported options, so callers can tell a newer file from a
  broken one. A reserved Check type fails rather than being skipped.
- The Index is verified against the Blocks with an `XZIndexHash` (counts,
  sums and SHA-256 of the Records), in constant memory however many Blocks
  there are.
- An input ending inside a four-byte unit of Stream Padding is
  `UnexpectedEnd` (it may be a truncated file); padding of another length
  before a Stream is `InvalidData`.

Filters run in a `FilterChain` after LZMA2 when a Block has any; without
filters, LZMA2 writes straight into the caller's output. The data a
recorded size allows are the most LZMA2 is given room or input for, so a
Block that goes beyond them is caught without decoding further.

The BCJ conversions follow liblzma's code (XZ Utils, 0BSD), the de facto
definition the specification refers to; the RISC-V filter's encoder and
decoder differ (its special AUIPC format), the others share one function
with a direction flag.

## Finite State Entropy and backward bitstreams

FSE and the backward bitstreams were written inside the Zstandard module,
with the tables taking `ZstandardBitReader` and `ZstandardBitWriter`. FSE
is not Zstandard's: it is Yann Collet's implementation of Jarek Duda's
tabled ANS, a library of its own that other formats use, and the backward
bitstream (read from the end, ended by a 1 bit and zero padding) is that
library's `BIT_DStream`. Under the rule that no part exists only for
another module, both became general parts:

- `bytes::BackwardBitReader` and `bytes::BackwardBitWriter`, next to the
  other bit readers. Their constructor returns `Option`, because
  `bytes` cannot use `CompressionError` and a `BytesError` variant would
  be the only one about bits; callers map `None` to their own error
  (Zstandard: `InvalidData`, "bitstream without its final bit").
  Reading past the start saturates: it gives zero bits, keeps the position
  at the start and sets `overflowed`. An earlier version let the position
  wrap below zero and derived `overflowed` from the wrapped value;
  saturating keeps every later read and `is_finished` well defined.
- `codec::fse` (feature `codec-fse`, which `codec-zstandard` depends on):
  `FSEDistribution` (validated by `new`, read and written in the table
  description format of RFC 8878 section 4.1.1, which is also the FSE
  library's `FSE_readNCount`, normalized from counts),
  `FSEDecodingTable` and `FSEEncodingTable`. The tables drive the backward
  bitstreams (`initial_state`, `next_state`, `encode`, `flush`) and expose
  each step without them (`FSEDecodingEntry::next_state`,
  `FSEEncodingTable::transition`), so another bit source or the C ABI can
  drive them. The accuracy log is limited to 15 (`MAXIMUM_LOG`, the FSE
  library's hard limit), which keeps states in 16 bits and probabilities in
  `i16`, and symbols to 256 (`MAXIMUM_SYMBOLS`); `read` applies these limits
  whatever the caller passes. Errors stay `CompressionError` (`InvalidData`
  for descriptions, `InvalidParameter` for parameters): an FSE description
  is compressed data, and a separate `FSEError` would only be converted
  back by every caller.

Rejected: keeping the types in `zstandard` and re-exporting them from a
general module (two paths for one type, and the general module would
depend on a format); making FSE generic over a bit reader trait (one
implementation exists, and the per-step methods already serve other
sources); re-exporting the old names from `zstandard` (the crate is
unreleased, and duplicate names contradict one module per feature).

`ZstandardHuffman` keeps its own decoding table instead of
`huffman::canonical::HuffmanTable`: Zstandard assigns prefix codes from the
lowest weight (the longest codes) up, the longest codes numerically
smallest (RFC 8878 section 4.2.1.3), while `HuffmanCode` is the canonical
code of RFC 1951 with the shortest codes smallest. Building a
`HuffmanTable` would need the codes of another assignment, which
`HuffmanCode` cannot express without a new constructor, for a table that is
already a single lookup of `maximum_bits` (at most 11) bits.

## Tests

`tests/codec/compression.rs` drives every pair: round trips of the sample
sets whole and in pieces with sync flushes, decompression fed and drained
in many piece sizes (stopping exactly at the end of the stream, with output
of exactly the data size), limits, truncation and sync flushes. Each format
adds the vectors of its specification and exact-bit checks. Fuzz targets use
`fuzz/codec.rs` `compression::check`, which compares whole and piecewise
decompression of arbitrary input and round trips the input.
