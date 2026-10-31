//! The C ABI of [`crate::codec::fse`]. Distributions and tables are
//! handles; a table exposes the step of each state (decoding) or of each
//! state and symbol (encoding), so that C drives it with its own bits.

use alloc::vec::Vec;

use crate::codec::fse::{FSEDecodingTable, FSEDistribution, FSEEncodingTable};
use crate::ffi::{Buffer, Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for FSEDistribution {
    const TYPE: Type = Type::Named("umilib_codec_fse_FSEDistribution");
}

impl Value for FSEDecodingTable {
    const TYPE: Type = Type::Named("umilib_codec_fse_FSEDecodingTable");
}

impl Value for FSEEncodingTable {
    const TYPE: Type = Type::Named("umilib_codec_fse_FSEEncodingTable");
}

crate::ffi_functions! {
    const DISTRIBUTION;

    /// Writes a new distribution of the `count` probabilities at `probabilities` (-1 for "less
    /// than 1") on a scale of 2^`accuracy_log` into `out`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_distribution_new(accuracy_log: u32, probabilities: *const i16, count: usize, out: *mut *mut FSEDistribution) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes `count` readable probabilities and a writable pointer.
            let probabilities = unsafe { Pointer::slice_of(probabilities, count) }?;
            let distribution = FSEDistribution::new(accuracy_log, probabilities.to_vec()).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, distribution) }
        })())
    }

    /// Reads a table description from the start of the `length` bytes at `data`, of an accuracy
    /// log of at most `maximum_log` and at most `maximum_symbols` symbols: writes the new
    /// distribution into `out` and the bytes it took into `used`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_distribution_read(data: *const u8, length: usize, maximum_log: u32, maximum_symbols: usize, out: *mut *mut FSEDistribution, used: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(used, 1)])?;
            // Both outputs are checked before either is written.
            Pointer::check_range(used, 1)?;
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let data = unsafe { Pointer::slice(data, length) }?;
            let (distribution, taken) = FSEDistribution::read(data, maximum_log, maximum_symbols).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(used, taken) }?;
            unsafe { Pointer::write_handle(out, distribution) }
        })())
    }

    /// Writes a new distribution of the `count` symbol counts at `counts` on a scale of
    /// 2^`accuracy_log` into `out`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_distribution_normalize(counts: *const u32, count: usize, accuracy_log: u32, out: *mut *mut FSEDistribution) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes `count` readable counts and a writable pointer.
            let counts = unsafe { Pointer::slice_of(counts, count) }?;
            let distribution = FSEDistribution::normalize(counts, accuracy_log).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, distribution) }
        })())
    }

    /// Releases a distribution. Does nothing if `distribution` is null.
    pub unsafe extern "C" fn umilib_codec_fse_fse_distribution_free(distribution: *mut FSEDistribution) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(distribution) }
    }

    /// Writes the accuracy log of `distribution` into `out`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_distribution_accuracy_log(distribution: *const FSEDistribution, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let distribution = unsafe { Pointer::reference(distribution) }?;
            unsafe { Pointer::write(out, distribution.accuracy_log) }
        })())
    }

    /// Writes the number of probabilities of `distribution` (the last present symbol plus 1) into `out`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_distribution_symbols(distribution: *const FSEDistribution, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let distribution = unsafe { Pointer::reference(distribution) }?;
            unsafe { Pointer::write(out, distribution.probabilities.len()) }
        })())
    }

    /// Writes the probability of `symbol` (-1 for "less than 1") into `out`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_distribution_probability(distribution: *const FSEDistribution, symbol: usize, out: *mut i16) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let distribution = unsafe { Pointer::reference(distribution) }?;
            let probability = *distribution.probabilities.get(symbol).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, probability) }
        })())
    }

    /// Writes the table description of `distribution` into `out`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_distribution_write(distribution: *const FSEDistribution, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let distribution = unsafe { Pointer::reference(distribution) }?;
            let mut description = Vec::new();
            distribution.write(&mut description).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(description)) }
        })())
    }

    /// Writes the symbol of each table position, one byte each, into `out`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_distribution_spread(distribution: *const FSEDistribution, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let distribution = unsafe { Pointer::reference(distribution) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(distribution.spread())) }
        })())
    }
}

crate::ffi_functions! {
    const DECODING;

    /// Writes a new decoding table of `distribution` into `out`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_decoding_table_new(distribution: *const FSEDistribution, out: *mut *mut FSEDecodingTable) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let distribution = unsafe { Pointer::reference(distribution) }?;
            unsafe { Pointer::write_handle(out, FSEDecodingTable::new(distribution)) }
        })())
    }

    /// Writes a new table of the single `symbol` (one state, no bits) into `out`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_decoding_table_single(symbol: u8, out: *mut *mut FSEDecodingTable) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, FSEDecodingTable::single(symbol)) })
    }

    /// Releases a table. Does nothing if `table` is null.
    pub unsafe extern "C" fn umilib_codec_fse_fse_decoding_table_free(table: *mut FSEDecodingTable) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(table) }
    }

    /// Writes the accuracy log of `table` (the bits of the initial state) into `out`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_decoding_table_accuracy_log(table: *const FSEDecodingTable, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let table = unsafe { Pointer::reference(table) }?;
            unsafe { Pointer::write(out, table.accuracy_log) }
        })())
    }

    /// Writes the entry of `state`: its symbol into `symbol`, and the bits to read and the
    /// baseline to add to them for the next state into `bits` and `baseline`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_decoding_table_entry(table: *const FSEDecodingTable, state: usize, symbol: *mut u8, bits: *mut u8, baseline: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(symbol, 1), Pointer::range(bits, 1), Pointer::range(baseline, 1)])?;
            // Every output is checked before any is written.
            Pointer::check_range(symbol, 1)?;
            Pointer::check_range(bits, 1)?;
            Pointer::check_range(baseline, 1)?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let table = unsafe { Pointer::reference(table) }?;
            let entry = *table.entries.get(state).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(symbol, entry.symbol) }?;
            unsafe { Pointer::write(bits, entry.bits) }?;
            unsafe { Pointer::write(baseline, entry.baseline) }
        })())
    }
}

crate::ffi_functions! {
    const ENCODING;

    /// Writes a new encoding table of `distribution` into `out`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_encoding_table_new(distribution: *const FSEDistribution, out: *mut *mut FSEEncodingTable) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let distribution = unsafe { Pointer::reference(distribution) }?;
            unsafe { Pointer::write_handle(out, FSEEncodingTable::new(distribution)) }
        })())
    }

    /// Releases a table. Does nothing if `table` is null.
    pub unsafe extern "C" fn umilib_codec_fse_fse_encoding_table_free(table: *mut FSEEncodingTable) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(table) }
    }

    /// Writes the accuracy log of `table` (the bits of the final state) into `out`.
    pub unsafe extern "C" fn umilib_codec_fse_fse_encoding_table_accuracy_log(table: *const FSEEncodingTable, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let table = unsafe { Pointer::reference(table) }?;
            unsafe { Pointer::write(out, table.accuracy_log) }
        })())
    }

    /// Writes the first state, for `symbol` (the symbol decoded last), into `out`; fails with
    /// `InvalidArgument` if `symbol` has no probability.
    pub unsafe extern "C" fn umilib_codec_fse_fse_encoding_table_initial_state(table: *const FSEEncodingTable, symbol: usize, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let table = unsafe { Pointer::reference(table) }?;
            if !table.contains(symbol) {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write(out, table.initial_state(symbol)) }
        })())
    }

    /// Writes the step from the encoder state `state` for `symbol`: the number of low bits of
    /// `state` to write into `bits`, and the state before it into `previous`; fails with
    /// `InvalidArgument` if `state` is not an encoder state or `symbol` has no probability.
    pub unsafe extern "C" fn umilib_codec_fse_fse_encoding_table_transition(table: *const FSEEncodingTable, state: u32, symbol: usize, bits: *mut u32, previous: *mut u32) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(bits, 1), Pointer::range(previous, 1)])?;
            // Both outputs are checked before either is written.
            Pointer::check_range(bits, 1)?;
            Pointer::check_range(previous, 1)?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let table = unsafe { Pointer::reference(table) }?;
            if !table.is_state(state) || !table.contains(symbol) {
                return Err(&Status::INVALID_ARGUMENT);
            }
            let (count, before) = table.transition(state, symbol);
            unsafe { Pointer::write(bits, count) }?;
            unsafe { Pointer::write(previous, before) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "fse",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_fse_FSEDistribution",
            documentation: " A normalized distribution of Finite State Entropy.",
        },
        Definition::Opaque {
            name: "umilib_codec_fse_FSEDecodingTable",
            documentation: " The decoding table of a distribution of Finite State Entropy.",
        },
        Definition::Opaque {
            name: "umilib_codec_fse_FSEEncodingTable",
            documentation: " The encoding table of a distribution of Finite State Entropy.",
        },
    ],
    functions: &Function::concat::<{ DISTRIBUTION.len() + DECODING.len() + ENCODING.len() }>(&[
        DISTRIBUTION,
        DECODING,
        ENCODING,
    ]),
    modules: &[],
};
