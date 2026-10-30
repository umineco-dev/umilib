# `umilib::codec::rle`

Run-length encoding: PackBits (Apple Technical Note TN1023; TIFF 6.0
section 9). Feature: `codec-rle`. The streaming interface is that of
[codec-compression.md](codec-compression.md).

`PackBitsCompressor` and `PackBitsDecompressor` code runs, each a header
byte n read as signed, then

- n = 0 to 127: the n + 1 bytes that follow;
- n = -1 to -127: the byte that follows, 1 - n times (2 to 128);
- n = -128: nothing (the decompressor skips it; the compressor never writes it).

The compressor writes a repeat for 3 or more equal bytes, as PackBits does,
and copies the other bytes in runs of at most 128.

The format has no end marker: a stream ends with its input. Call `finish`
when the input ended (as `decompress_to_vec` does); it fails with
`UnexpectedEnd` inside a run. Applications usually know the unpacked size
(a row of an image) and decompress into an output of exactly that size.

In C, `umilib_codec_rle_pack_bits_compressor_new` and
`umilib_codec_rle_pack_bits_decompressor_new`; in Python,
`umilib.codec.rle.PackBitsCompressor` and `PackBitsDecompressor`.
