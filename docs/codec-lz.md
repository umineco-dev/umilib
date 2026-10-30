# `umilib::codec::lz77`, `lz78` and `lzss`

The dictionary coders of Ziv and Lempel and their shared parts. Features:
`codec-lz77`, `codec-lz78` (uses `bytes`) and `codec-lzss` (uses `bytes`
and `codec-lz77`). The streaming interface is that of
[codec-compression.md](codec-compression.md).

## Shared parts (`lz77`)

The other LZ77 formats (LZSS, and Deflate, LZ4, Zstandard, LZMA and Brotli)
are built on two components of `lz77`, which can be used on their own:

- `LZ77Window` is the history a decompressor copies matches from: the last
  `capacity` bytes of its output, after an optional dictionary. It grows with
  the data up to its capacity, then keeps the latest bytes in a ring.
  `copy(distance, length, output)` copies a match (which may overlap the
  bytes it produces) into the output and the history, as far as the output
  has room, and fails with `InvalidData` for a distance beyond the history.
- `LZ77MatchFinder` finds matches for a compressor with hash chains: data
  are appended after the history, and `find(position, maximum_length)`
  gives the longest match among the positions before `position` that share
  the hash of its first bytes, newest first, within `chain_limit`
  candidates. `LZ77MatchFinderConfig` sets the window, the chains and the
  hash table sizes, the distance and length limits and the search effort;
  `discard` drops data more than a window back.

## LZ77 (`lz77`)

`LZ77Compressor` and `LZ77Decompressor` code the triples of the original
algorithm (Ziv and Lempel, 1977) in a format of this library
(`LZ77Format`): tokens of 2 bytes, most significant first, holding a 12-bit
field D and a 4-bit length L, then

- for L = 1 to 15, the L bytes D + 1 bytes back (1 to 4096), then 1 byte;
- for L = 0 and D = 0, 1 byte;
- for L = 0 and D = 0xFFF, the end of the stream (no byte follows).

The compressor takes the longest match at each position (`LZ77Config::
chain_limit` candidates, 64 by default).

## LZ78 (`lz78`)

`LZ78Compressor` and `LZ78Decompressor` code the pairs of the original
algorithm (Ziv and Lempel, 1978) in a format of this library (`LZ78Format`):

1. 1 byte B: the dictionary holds at most 2^B phrases (1 to 24; 16 by
   default, `LZ78Config::dictionary_bits`);
2. bits, least significant first, of tokens whose fields are w bits wide,
   w being the bits of n + 1 for the n phrases of the dictionary:
   - a phrase i (0, the empty phrase, to n), then a byte c: writes phrase
     i then c and adds phrase n + 1 = i + c; a full dictionary is emptied;
   - n + 1, a phrase i, then 1 bit: writes phrase i; the bit is 1 at the end
     of the stream and 0 at a sync flush; zero bits pad to a byte.

`LZ78Dictionary` holds the phrases (with an index from a phrase and a byte
to its extension, for the compressor). `LZ78DecompressorConfig::
maximum_dictionary_bits` (20 by default) bounds the dictionary a stream may
ask for: a larger one fails with `LimitExceeded`.

## LZSS (`lzss`)

`LZSSCompressor` and `LZSSDecompressor` follow Haruhiko Okumura's
public-domain `lzss.c` (`LZSSFormat`): bits packed most significant first
of tokens

- 1, then a byte: a literal;
- 0, then a position i of EI bits and a length j of EJ bits: the j + 2
  bytes at the positions i, i + 1, ... of a ring buffer of N = 2^EI bytes.

The ring starts with spaces before the position N - F (F = 2^EJ + 1), where
the first byte goes. `LZSSConfig` holds EI and EJ (11 and 4 by default, as
in the reference); streams do not record them, so both sides must use the
same, with EI + EJ at least 7.

- The streams have no end marker: they end with their input, padded with
  fewer than 8 zero bits. Call `finish` when the input ended (as
  `decompress_to_vec` does); it fails with `UnexpectedEnd` inside a token.
- The format cannot pad in the middle of a stream, so a sync flush fails
  with `InvalidParameter`.
- The compressor takes the nearest of the longest matches within N - F
  bytes, as the reference does, and writes the same streams on its test
  inputs.

## C and Python

The constructors are `umilib_codec_lz77_lz77_compressor_new(chain_limit)`,
`umilib_codec_lz78_lz78_compressor_new(dictionary_bits)`,
`umilib_codec_lz78_lz78_decompressor_new(maximum_dictionary_bits)`,
`umilib_codec_lzss_lzss_compressor_new(position_bits, length_bits)` and the
decompressors' `_new`; Python has `LZ77Config`, `LZ78Config`,
`LZ78DecompressorConfig` and `LZSSConfig` with the same fields.
