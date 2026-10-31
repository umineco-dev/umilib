# `umilib::codec::fse`

Finite State Entropy (FSE): the tabled asymmetric numeral system (tANS) of
Jarek Duda, as Yann Collet's FSE library implements it and Zstandard uses
it (RFC 8878 section 4.1). Feature: `codec-fse` (uses `bytes`).
[codec-zstandard.md](codec-zstandard.md) builds on it.

## Distributions

`FSEDistribution` holds the probabilities of the symbols 0 to the last
present one on a scale of 2^`accuracy_log`; -1 means "less than 1" and
counts as 1.

- `FSEDistribution::new(accuracy_log, probabilities)` checks them: an
  accuracy log of at most 15 (`MAXIMUM_LOG`), at most 256 symbols
  (`MAXIMUM_SYMBOLS`), no probability below -1, and a total equal to the
  scale; otherwise `InvalidParameter`.
- `FSEDistribution::normalize(counts, accuracy_log)` scales symbol counts:
  every present symbol gets at least 1. It needs 2 or more present symbols,
  at most the scale of them.
- `read(bytes, maximum_log, maximum_symbols)` reads a table description
  (section 4.1.1) and returns the distribution and the bytes it took;
  `write(&mut out)` writes one (accuracy logs 5 to 15). Descriptions above
  the given limits (themselves capped at 15 and 256), of a single symbol or
  truncated fail with `InvalidData`.
- `spread()` gives the symbol of each table position.

The fields are public, for constant distributions such as Zstandard's
predefined ones; the tables expect a distribution that `new` would accept.

## Tables

`FSEDecodingTable::new(&distribution)` has one `FSEDecodingEntry` per state:
its symbol, the bits to read and the baseline they are added to for the
next state (`entry.next_state(value)`). `single(symbol)` is the table of one
state that reads no bits. On a backward bitstream
(`bytes::BackwardBitReader`, [bytes.md](bytes.md)), `initial_state` reads
the first state and `next_state` the next one.

`FSEEncodingTable::new(&distribution)` is the reverse. Symbols are encoded
in the reverse of the order they are decoded in, and encoder states are
decoder states plus 2^`accuracy_log`: `initial_state(symbol)` starts with
the symbol decoded last, `encode(state, symbol, &mut writer)` writes the
bits of each other symbol to a `bytes::BackwardBitWriter` and returns the
state before it, and `flush(state, &mut writer)` writes the final state,
which the decoder reads first. `transition(state, symbol)` gives the number
of low bits of `state` to write and the state before it, without writing.
`contains(symbol)` tells whether a symbol can be encoded, `is_state(state)`
whether a value is an encoder state.

```rust
use umilib::bytes::{BackwardBitReader, BackwardBitWriter};
use umilib::codec::fse::{FSEDecodingTable, FSEDistribution, FSEEncodingTable};

let distribution = FSEDistribution::normalize(&[10, 3, 0, 1], 5)?;
let message = [0usize, 1, 0, 3, 0];
let encoding = FSEEncodingTable::new(&distribution);
let mut writer = BackwardBitWriter::new();
let mut state = encoding.initial_state(message[4]);
for symbol in message[..4].iter().rev() {
    state = encoding.encode(state, *symbol, &mut writer);
}
encoding.flush(state, &mut writer);
let stream = writer.finish();

let decoding = FSEDecodingTable::new(&distribution);
let mut reader = BackwardBitReader::new(&stream).unwrap();
let mut state = decoding.initial_state(&mut reader);
for index in 0..5 {
    assert_eq!(decoding.entries[state].symbol as usize, message[index]);
    if index < 4 {
        state = decoding.next_state(state, &mut reader);
    }
}
assert!(reader.is_finished());
```

## C and Python

`umilib_codec_fse_fse_distribution_new(accuracy_log, probabilities, count)`,
`_read(data, length, maximum_log, maximum_symbols, out, used)`,
`_normalize(counts, count, accuracy_log)`, `_accuracy_log`, `_symbols`,
`_probability`, `_write`, `_spread` and `_free`;
`umilib_codec_fse_fse_decoding_table_new(distribution)`, `_single(symbol)`,
`_accuracy_log`, `_entry(state, symbol, bits, baseline)` and `_free`;
`umilib_codec_fse_fse_encoding_table_new(distribution)`, `_accuracy_log`,
`_initial_state(symbol)`, `_transition(state, symbol, bits, previous)` and
`_free`. A C caller drives the tables with its own bits. A state or symbol
outside the table fails with `InvalidArgument`; invalid distributions and
descriptions with the statuses of `CompressionError` (domain `codec`).
Python mirrors them in `umilib.codec.fse` (`FSEDecodingTable.entry` returns
`(symbol, bits, baseline)`, `FSEEncodingTable.transition` `(bits,
previous)`).
