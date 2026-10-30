# QPACK: `umilib::codec::qpack`

`codec-qpack` (no `std`) is QPACK (RFC 9204), the compression of the field
sections of HTTP/3. HTTP/3 (`protocol-http-v3`) uses it; it works on its own
too. Its integers, strings and Huffman code are HPACK's (`codec-hpack`), as
RFC 9204 §4.1 defines them.

| Type | What it is |
| --- | --- |
| `QPACKEncoder` | Writes field sections and the instructions of the encoder stream |
| `QPACKDecoder` | Reads field sections and the encoder stream, and writes the instructions of the decoder stream |
| `QPACKEncoderConfig`, `QPACKDecoderConfig` | Their limits |
| `QPACKDecoded` | A section's fields, or `Blocked` until the inserts it refers to arrive |
| `QPACKError` | Why decoding failed, with its HTTP/3 error code |
| `QPACKStaticTable`, `QPACKDynamicTable` | The tables (RFC 9204 §3, Appendix A) |

## The two streams

QPACK's dynamic table changes through two unidirectional streams that the
caller carries: what `QPACKEncoder::take_instructions` returns goes on the
encoder stream to `QPACKDecoder::receive_encoder_stream`, and what
`QPACKDecoder::take_instructions` returns goes on the decoder stream to
`QPACKEncoder::receive_decoder_stream`.

```rust
use umilib::codec::hpack::HPACKField;
use umilib::codec::qpack::{QPACKDecoded, QPACKDecoder, QPACKDecoderConfig, QPACKEncoder, QPACKEncoderConfig};

let mut encoder = QPACKEncoder::new(QPACKEncoderConfig::default());
let mut decoder = QPACKDecoder::new(QPACKDecoderConfig::default());
// The decoder's SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS.
encoder.set_peer_settings(4096, 16);
let fields = vec![HPACKField::new(b":method", b"GET"), HPACKField::new(b"x-request", b"one")];
let section = encoder.encode(0, &fields);
// The section refers to inserts: until they arrive, its stream is blocked.
assert_eq!(decoder.decode(0, &section).unwrap(), QPACKDecoded::Blocked);
decoder.receive_encoder_stream(&encoder.take_instructions()).unwrap();
assert_eq!(decoder.decode(0, &section).unwrap(), QPACKDecoded::Fields(fields));
encoder.receive_decoder_stream(&decoder.take_instructions()).unwrap();
```

Until `set_peer_settings`, the encoder uses no dynamic table (the peer's
capacity is 0 until its SETTINGS arrive, RFC 9204 §3.2.3). With
`blocking` (on by default) a section may refer to entries the decoder has
not acknowledged, on at most the decoder's SETTINGS_QPACK_BLOCKED_STREAMS
streams; without it, sections refer only to acknowledged entries and never
block. Call `QPACKDecoder::cancel_stream` for a stream abandoned before its
section decoded, so the encoder learns of it (§4.4.2).

## Errors

`DecompressionFailed`, `EncoderStream` and `DecoderStream` are connection
errors of HTTP/3 (`QPACKError::code` gives 0x200, 0x201, 0x202).
`FieldListTooLarge` is a section larger than `maximum_field_list_size`,
decoded whole and acknowledged so the encoder can release its entries:
HTTP/3 answers 431 and goes on.

## C and Python

The C ABI is `include/umilib/codec/qpack.h`; sections cross as the lists of
fields of `codec/hpack.h`. Python has the same names in `umilib.codec.qpack`;
`QPACKDecoder.decode` returns a `QPACKDecoded` with `fields` or `blocked`.
