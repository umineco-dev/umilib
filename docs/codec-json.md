# `umilib::codec::json`

JSON (RFC 8259). Feature: `codec-json`.

| Type | Purpose |
| --- | --- |
| `JSONReader` | Pull parser: `next_event()` yields `JSONEvent`s (`BeginObject`, `Key`, `String`, `Number`, ...) that borrow the input. Validates without building a tree; keeps an explicit stack, so deep nesting cannot overflow the call stack. |
| `JSONValue` | A tree: `Null`, `Bool`, `Number`, `String`, `Array`, `Object`. `decode(bytes, config)`, `parse(text)`, `encode()`, accessors such as `get`, `index`, `as_str`. |
| `JSONObject` | Members in order; `get`, `insert`, `remove`. |
| `JSONNumber` | The number as written (no precision lost); `as_i64`, `as_u64`, `as_i128`, `as_f64`, `from_f64` (shortest text that reads back as the same `f64`). |
| `JSONString` | A string as written, with escapes; `as_str()` without copying when there are none, `decode()` otherwise. |
| `JSONEncoder` | `COMPACT`, `PRETTY`, or `{ indent, ascii_only }` with `indent` up to 255 spaces per level. |
| `JSONConfig` | `maximum_depth` (128), `maximum_length`, `allow_byte_order_mark` (false), `duplicate_keys`. |

## Strictness

Parsing follows the grammar of RFC 8259 exactly and accepts every valid text
of JSONTestSuite while rejecting every invalid one. Beyond the grammar:

- Text must be valid UTF-8 (RFC 8259 §8.1), and `\u` escapes of surrogates
  must form pairs: Rust strings cannot hold anything else.
- **Duplicate keys** are rejected by default (`DuplicateKeys::Reject`). RFC
  8259 says names SHOULD be unique and lets implementations reject
  duplicates; I-JSON (RFC 7493) requires uniqueness, and ambiguous objects
  cause security problems when two parsers keep different values. Choose
  `KeepFirst`, `KeepLast` or `KeepAll` if you must accept them.
- A byte order mark is rejected unless `allow_byte_order_mark` is set.
- Nesting deeper than `maximum_depth` is rejected. Decoding, dropping,
  cloning, comparing, formatting (`Debug` writes compact JSON) and encoding
  use explicit stacks, so a raised limit never exhausts the call stack.
- `-0` is the integer zero for `as_i64`, `as_u64` and `as_i128`.
