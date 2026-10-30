# `umilib::codec::filter`

Filters: reversible transformations that keep the size of data and make it
compress better, done in place on successive pieces of a stream. Features:
`codec-filter-delta` and `codec-filter-bcj` (`codec-filter` for both). The
.xz format chains them before LZMA2 ([codec-xz.md](codec-xz.md)); they are
usable before any compressor.

## The `Filter` trait

```rust
use umilib::codec::filter::Filter;
use umilib::codec::filter::bcj::{BCJArchitecture, BCJFilter};

let mut filter = BCJFilter::new(BCJArchitecture::X86, 0)?;
let converted = filter.encode(&mut piece);   // in place; the rest waits for more data
```

`encode` and `decode` convert what they can of a piece of the stream and
return how many bytes they converted. A filter may need the bytes after a
position to convert the bytes at it (an instruction that continues in the
next piece): the bytes after those converted, at most `lookahead()` of
them, must be given again, at the start of the next call, with the bytes
that follow. At the end of the stream they stay as they are (the same on
both sides). A filter object encodes or decodes one stream; `reset` starts
a new one.

`FilterChain` runs several filters over a stream in one buffer: encoding
in their order, decoding in the reverse order (the order of a .xz chain).
`extend` (or `fill`, for a decompressor writing into it) appends data,
`encode(end)` or `decode(end)` runs the filters (`end` at the end of the
stream), `ready` gives the bytes every filter converted and `consume` drops
them.

## Delta

`DeltaFilter::new(distance)` (1 to 256): each byte becomes its difference
with the byte `distance` before it (.xz specification, section 5.3.3).
Data of fixed-size samples (16-bit audio: distance 2 or 4, RGB images: 3)
compresses better.

## BCJ

`BCJFilter::new(architecture, start_offset)`: the relative addresses of the
branch, call and jump instructions of executables become absolute (.xz
specification, section 5.3.2), which repeat more and so compress better.
The conversions are those of XZ Utils (whose code is under the 0BSD
license), for the eight `BCJArchitecture`s:

| Architecture | Alignment | Instructions |
| --- | --- | --- |
| `X86` | 1 | CALL and JMP with 32-bit displacements |
| `PowerPC` | 4 | B and BL (big endian) |
| `IA64` | 16 | branches in bundles |
| `ARM` | 4 | BL |
| `ARMThumb` | 2 | BL |
| `SPARC` | 4 | CALL |
| `ARM64` | 4 | BL and ADRP |
| `RISCV` | 2 | JAL, AUIPC with the next instruction |

`start_offset` is the address of the first byte (a multiple of the
alignment; `InvalidParameter` otherwise); addresses wrap at 2^32. The
filters are bijective: any data, not only code, comes back.

## C and Python

`umilib_codec_filter_delta_delta_filter_new(distance)` and
`umilib_codec_filter_bcj_bcj_filter_new(architecture, start_offset)` (the
architecture as its index in the table above, 0 to 7), with `_encode`,
`_decode`, `_lookahead`, `_reset`, `_clone` and `_free`; `FilterChain` is
not exported. Python mirrors the filters with `DeltaFilter`, `BCJFilter` and
`BCJArchitecture`, and implements `FilterChain` over them.
