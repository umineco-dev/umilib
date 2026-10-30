# HPACK: `umilib::codec::hpack`

`codec-hpack` (no `std`) is HPACK (RFC 7541), the compression of the field
sections of HTTP/2. HTTP/2 (`protocol-http-v2`) uses it; it works on its
own too, for tools that read or write field blocks.

| Type | What it is |
| --- | --- |
| `HPACKEncoder` | Writes field blocks, keeping its dynamic table in step with the decoder's |
| `HPACKDecoder` | Reads field blocks |
| `HPACKEncoderConfig`, `HPACKDecoderConfig` | Their limits: table sizes, string lengths, field list sizes, Huffman coding |
| `HPACKField` | A field: name, value, and whether it is never indexed (RFC 7541 §7.1.3) |
| `HPACKError` | Why a block does not decode |
| `HPACKInteger`, `HPACKString` | The primitives (RFC 7541 §5), which QPACK uses too (RFC 9204 §4.1) |
| `HPACKHuffman` | The Huffman code of Appendix B, made with `codec-huffman-canonical` |
| `HPACKStaticTable`, `HPACKDynamicTable`, `HPACKEntry` | The tables (§2.3) |

## Encoding and decoding

```rust
use umilib::codec::hpack::{HPACKDecoder, HPACKDecoderConfig, HPACKEncoder, HPACKEncoderConfig, HPACKField};

let mut encoder = HPACKEncoder::new(HPACKEncoderConfig::default(), 4096);
let mut decoder = HPACKDecoder::new(HPACKDecoderConfig::default());
let fields = vec![
    HPACKField::new(b":method", b"GET"),
    HPACKField::new(b":path", b"/"),
    HPACKField::sensitive(b"authorization", b"secret"),
];
let mut block = Vec::new();
encoder.encode(&fields, &mut block);
assert_eq!(decoder.decode(&block).unwrap(), fields);
```

The second argument of `HPACKEncoder::new` is the decoder's limit of its
table (HTTP/2's SETTINGS_HEADER_TABLE_SIZE, 4096 at first); call
`set_limit` when the peer changes it. The encoder uses at most
`HPACKEncoderConfig::maximum_table_size` of it, and the next block starts
with the size updates the change calls for (RFC 7541 §4.2, §6.3).

## What the encoder does

- A field of the static or dynamic table is indexed; a field whose name is
  in a table refers to the name.
- A field is added to the dynamic table if its size (name, value and 32
  bytes) is at most `maximum_indexed_size` (1024 by default), so that one
  large value does not evict every other entry.
- A sensitive field (`HPACKField::sensitive`) is a literal never indexed,
  so intermediaries keep it out of their tables too (§7.1.3). Mark
  credentials and cookies of low entropy sensitive.
- Strings are Huffman-coded when that makes them shorter (`huffman`, on by
  default).

## Limits of the decoder

| Field of `HPACKDecoderConfig` | Default | What it limits |
| --- | --- | --- |
| `maximum_table_size` | 4096 | The dynamic table at the start |
| `maximum_string_length` | 64 KiB | Each string, coded or decoded |
| `maximum_field_list_size` | 64 KiB | The sum of the sizes of a block's fields |

A block larger than `maximum_field_list_size` fails with
`FieldListTooLarge` *after* it was decoded whole, so the table is still in
step with the encoder's and the connection can go on (HTTP/2 answers 431 to
such a request, RFC 9113 §8.2.3). Every other error leaves the table out of
step: HTTP/2 closes the connection with COMPRESSION_ERROR.

## C and Python

The C ABI is `include/umilib/codec/hpack.h`: an encoder, a decoder and a
list of fields (`umilib_codec_hpack_HPACKFields`) are handles; the
configurations are structures passed by value. Python has the same names in
`umilib.codec.hpack`; a block decodes to a list of `HPACKField`.
