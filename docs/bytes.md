# `umilib::bytes`

Reading and writing integers and byte sequences. Feature: `bytes`.

- `Reader<'a>` parses a borrowed slice without copying. Every read either
  succeeds completely or fails with `BytesError` and leaves the cursor where it
  was, so a parser can try an alternative after a failure.
- `Writer` is implemented by `Buffer` (a growable buffer with an optional size
  limit, for data from untrusted peers) and `SliceWriter` (fills a slice you
  provide). Every write either succeeds completely or writes nothing.
- `Integer` is implemented by `u8`…`u128` and `i8`…`i128`.

| Method | Meaning |
| --- | --- |
| `read_be::<T>()` / `write_be(value)` | `T::SIZE` bytes, most significant first (network byte order) |
| `read_le::<T>()` / `write_le(value)` | `T::SIZE` bytes, least significant first |
| `read_be_sized::<T>(n)` / `write_be_sized(value, n)` | `n` bytes (`1..=T::SIZE`), for example the 24-bit lengths of TLS; signed values are sign-extended when read, and a write fails with `ValueTooLarge` if the value does not survive the round trip |
| `read_slice(n)`, `peek(n)`, `read_array::<N>()`, `read_reader(n)`, `read_rest()`, `skip(n)` | Byte sequences |

```rust
use umilib::bytes::{Buffer, Reader, Writer};

let mut buffer = Buffer::with_limit(1024);
buffer.write_be(0x0303u16)?;
buffer.write_be_sized(3u32, 3)?;
buffer.write(b"abc")?;

let mut reader = Reader::new(buffer.as_slice());
assert_eq!(reader.read_be::<u16>()?, 0x0303);
let length = reader.read_be_sized::<u32>(3)? as usize;
let mut body = reader.read_reader(length)?;
assert_eq!(body.read_rest(), b"abc");
# Ok::<(), umilib::bytes::BytesError>(())
```

## Bits

The compressed formats pack bits into bytes least significant bit first
(RFC 1951 section 3.1.1); a value of several bits is written least
significant bit first.

- `BitReader<'a>` reads bits from a borrowed slice. `peek`, `read`, `skip`
  and `read_bytes` either take all their bits or fail without moving;
  `peek_padded` reads past the end as zeros; `align` skips to a byte.
- `BitWriter` appends bits to a vector: `write(value, count)`, `align`,
  `write_bytes`, and `completed`, `clear_completed`, `take_completed` and
  `finish` for the bytes written. `BitWriter::new()` fills each byte from
  its least significant bit (Deflate); `BitWriter::with_order(order)` takes
  a `BitOrder`, most significant bit first for HPACK's strings, say.
- `BitQueue` holds up to 64 bits, in either `BitOrder` (least or most
  significant bit of each byte first), for a streaming decoder that receives its
  input in pieces: `fill(count, &mut input)` moves bytes from the front of
  `input` only until `count` bits are queued, so a decoder that asks for the
  bits it needs never takes a byte past the end of its stream; `peek`,
  `read`, `read_from`, `consume` and `align` take the bits.

Each operation takes at most 56 bits (`MAXIMUM_BITS`).

The backward bitstreams of Finite State Entropy and Zstandard (RFC 8878
sections 4.1 and 4.2.2) are read from the end towards the start: the last
byte ends with a 1 bit followed by zero padding, and a value of several
bits has the first bit read as its most significant.

- `BackwardBitReader<'a>::new(bytes)` finds the final 1 bit (`None` for an
  empty slice or a last byte of 0); `peek` and `read` take up to 32 bits.
  Reading past the start gives zero bits, as decoders of these formats
  expect at their last symbols, and sets `overflowed`; the position stays
  at the start. `is_finished` holds when every bit was read, exactly, so a
  decoder checks that its stream held the bits of its symbols and no more.
- `BackwardBitWriter` appends values least significant bit first, in the
  reverse of the order they will be read (`write(value, count)`, up to 32
  bits); `finish` adds the final 1 bit and the padding.

## Lines

`LineBuffer` holds received bytes not yet read, for the line protocols
(SMTP, POP3, IMAP, FTP): `push` adds what arrived, `line(maximum)` takes
the next line ended by CRLF, its CRLF removed, and `take(n)` or
`consume(n)` the counted bytes of a literal or a chunk.

- Only CRLF ends a line. A CR or an LF alone is part of the line, so the
  protocols built on it see what the peer sent and decide (SMTP refuses a
  bare LF in mail data, for one).
- A line of more than `maximum` octets, its CRLF counted, fails once with
  `BytesError::LineTooLong`, and the rest of it is skipped as it arrives,
  so a peer cannot make the buffer hold an endless line.
