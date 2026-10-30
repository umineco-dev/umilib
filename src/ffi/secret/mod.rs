//! The C ABI of [`crate::secret`].
//!
//! A [`Choice`] is passed as a `uint8_t` holding `0` or `1`: functions that
//! return a status reject other values ([`ChoiceArgument`]), and the
//! operations on choices themselves use the lowest bit, as
//! [`Choice::from_bit`] does. The traits are
//! exported for byte sequences, which is how C code holds secrets, and
//! [`Secret`] is exported as `Secret<Vec<u8>>`, and [`ConstantTimeTable`]
//! as `ConstantTimeTable<32, 8>` (`ConstantTimeTable32_8`), the shape of a
//! table of 256 bytes such as an S-box.

use alloc::vec::Vec;

use crate::ffi::{Definition, Module, Pointer, Status, Type, Value};
use crate::secret::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeTable, DataIndependentTiming, Secret, Zeroize,
};

/// A [`Choice`] argument of the C ABI.
pub struct ChoiceArgument;

impl ChoiceArgument {
    /// The choice that `value` (0 or 1) stands for; other values are rejected,
    /// because C code may pass any non-zero value for true. Only whether the
    /// argument is valid shows in the time.
    pub fn decode(value: u8) -> Result<Choice, &'static Status> {
        if value > 1 {
            return Err(&Status::INVALID_ARGUMENT);
        }
        Ok(Choice::from_bit(value))
    }
}

impl Value for DataIndependentTiming {
    const TYPE: Type = Type::Named("umilib_secret_DataIndependentTiming");
}

impl Value for Secret<Vec<u8>> {
    const TYPE: Type = Type::Named("umilib_secret_Secret");
}

impl Value for ConstantTimeTable<32, 8> {
    const TYPE: Type = Type::Named("umilib_secret_ConstantTimeTable32_8");
}

crate::ffi_functions! {
    /// Returns the lowest bit of `bit` as a choice.
    pub unsafe extern "C" fn umilib_secret_choice_from_bit(bit: u8) -> u8 {
        Choice::from_bit(bit).bit()
    }

    /// Returns the logical AND of two choices.
    pub unsafe extern "C" fn umilib_secret_choice_and(a: u8, b: u8) -> u8 {
        (Choice::from_bit(a) & Choice::from_bit(b)).bit()
    }

    /// Returns the logical OR of two choices.
    pub unsafe extern "C" fn umilib_secret_choice_or(a: u8, b: u8) -> u8 {
        (Choice::from_bit(a) | Choice::from_bit(b)).bit()
    }

    /// Returns the logical XOR of two choices.
    pub unsafe extern "C" fn umilib_secret_choice_xor(a: u8, b: u8) -> u8 {
        (Choice::from_bit(a) ^ Choice::from_bit(b)).bit()
    }

    /// Returns the logical NOT of a choice.
    pub unsafe extern "C" fn umilib_secret_choice_not(choice: u8) -> u8 {
        (!Choice::from_bit(choice)).bit()
    }

    /// Reveals a choice as a boolean.
    pub unsafe extern "C" fn umilib_secret_choice_into_bool(choice: u8) -> bool {
        Choice::from_bit(choice).into_bool()
    }

    /// Compares two byte sequences in time that depends only on their lengths
    /// and writes the resulting choice into `out`.
    pub unsafe extern "C" fn umilib_secret_constant_time_eq_ct_eq(a: *const u8, a_length: usize, b: *const u8, b_length: usize, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable byte sequences and a writable pointer.
            let a = unsafe { Pointer::slice(a, a_length) }?;
            let b = unsafe { Pointer::slice(b, b_length) }?;
            unsafe { Pointer::write(out, a.ct_eq(b).bit()) }
        })())
    }

    /// Like `umilib_secret_constant_time_eq_ct_eq`, but writes whether the sequences differ.
    pub unsafe extern "C" fn umilib_secret_constant_time_eq_ct_ne(a: *const u8, a_length: usize, b: *const u8, b_length: usize, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable byte sequences and a writable pointer.
            let a = unsafe { Pointer::slice(a, a_length) }?;
            let b = unsafe { Pointer::slice(b, b_length) }?;
            unsafe { Pointer::write(out, a.ct_ne(b).bit()) }
        })())
    }

    /// Writes `a` into `out` if `choice` is 0 and `b` if it is 1; all three hold `length` bytes.
    /// `out` may be `a` or `b`; partially overlapping ranges are rejected.
    pub unsafe extern "C" fn umilib_secret_conditionally_selectable_select(a: *const u8, b: *const u8, length: usize, choice: u8, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(a, length)?;
            Pointer::check_range(b, length)?;
            Pointer::check_range(out, length)?;
            for other in [a, b] {
                if other != out.cast_const() && Pointer::overlaps(other, length, out, length) {
                    return Err(&Status::INVALID_ARGUMENT);
                }
            }
            let choice = ChoiceArgument::decode(choice)?;
            // Raw reads and writes, not slices, because `out` may alias `a` or `b`.
            for index in 0..length {
                // SAFETY: the caller passes `length` readable bytes at `a` and `b` and writable bytes at `out`.
                unsafe {
                    let selected = u8::select(&a.add(index).read(), &b.add(index).read(), choice);
                    out.add(index).write(selected);
                }
            }
            Ok(())
        })())
    }

    /// Overwrites the `length` bytes at `target` with those at `source` if `choice` is 1.
    /// `target` may be `source`; partially overlapping ranges are rejected.
    pub unsafe extern "C" fn umilib_secret_conditionally_selectable_conditional_assign(target: *mut u8, source: *const u8, length: usize, choice: u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(target, length)?;
            Pointer::check_range(source, length)?;
            if source != target.cast_const() && Pointer::overlaps(source, length, target, length) {
                return Err(&Status::INVALID_ARGUMENT);
            }
            let choice = ChoiceArgument::decode(choice)?;
            for index in 0..length {
                // SAFETY: the caller passes `length` writable bytes at `target` and readable bytes at `source`.
                unsafe {
                    let mut value = target.add(index).read();
                    value.conditional_assign(&source.add(index).read(), choice);
                    target.add(index).write(value);
                }
            }
            Ok(())
        })())
    }

    /// Swaps the `length` bytes at `a` and `b` if `choice` is 1.
    /// `a` may be `b`; partially overlapping ranges are rejected.
    pub unsafe extern "C" fn umilib_secret_conditionally_selectable_conditional_swap(a: *mut u8, b: *mut u8, length: usize, choice: u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(a, length)?;
            Pointer::check_range(b, length)?;
            if a != b && Pointer::overlaps(a, length, b, length) {
                return Err(&Status::INVALID_ARGUMENT);
            }
            let choice = ChoiceArgument::decode(choice)?;
            for index in 0..length {
                // SAFETY: the caller passes `length` writable bytes at `a` and `b`.
                unsafe {
                    let (mut x, mut y) = (a.add(index).read(), b.add(index).read());
                    u8::conditional_swap(&mut x, &mut y, choice);
                    a.add(index).write(x);
                    b.add(index).write(y);
                }
            }
            Ok(())
        })())
    }

    /// Overwrites the `length` bytes at `data` with zeros in a way the compiler does not remove.
    pub unsafe extern "C" fn umilib_secret_zeroize_zeroize(data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes `length` writable bytes.
            unsafe { Pointer::slice_mut(data, length) }?.zeroize();
            Ok(())
        })())
    }

    /// Copies `length` bytes at `data` into a new secret, which zeroizes them when released.
    pub unsafe extern "C" fn umilib_secret_secret_new(data: *const u8, length: usize, out: *mut *mut Secret<Vec<u8>>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes `length` readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(data, length) }?;
            unsafe { Pointer::write_handle(out, Secret::new(Vec::from(bytes))) }
        })())
    }

    /// Zeroizes and releases a secret. Does nothing if `secret` is null.
    pub unsafe extern "C" fn umilib_secret_secret_free(secret: *mut Secret<Vec<u8>>) {
        // SAFETY: the caller passes a handle from `umilib_secret_secret_new`.
        unsafe { Pointer::free(secret) }
    }

    /// Writes a pointer to the secret bytes into `out_data` and their number into `out_length`.
    /// The pointer is valid until the secret is released.
    pub unsafe extern "C" fn umilib_secret_secret_expose(secret: *const Secret<Vec<u8>>, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let secret = unsafe { Pointer::reference(secret) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out_data, secret.expose().as_ptr()) }?;
            unsafe { Pointer::write(out_length, secret.expose().len()) }
        })())
    }

    /// Like `umilib_secret_secret_expose`, but the bytes may be modified in place.
    pub unsafe extern "C" fn umilib_secret_secret_expose_mut(secret: *mut Secret<Vec<u8>>, out_data: *mut *mut u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let secret = unsafe { Pointer::reference_mut(secret) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes = secret.expose_mut();
            unsafe { Pointer::write(out_length, bytes.len()) }?;
            unsafe { Pointer::write(out_data, bytes.as_mut_ptr()) }
        })())
    }

    /// Whether data-independent timing guards set the mode of the processor on this target.
    pub unsafe extern "C" fn umilib_secret_data_independent_timing_available() -> bool {
        DataIndependentTiming::AVAILABLE
    }

    /// Whether the data-independent timing mode is set for the calling thread.
    pub unsafe extern "C" fn umilib_secret_data_independent_timing_is_enabled() -> bool {
        DataIndependentTiming::is_enabled()
    }

    /// Sets the data-independent timing mode for the calling thread until the guard written to
    /// `out` is released, which must happen on the same thread.
    pub unsafe extern "C" fn umilib_secret_data_independent_timing_enable(out: *mut *mut DataIndependentTiming) -> *const Status {
        if out.is_null() {
            return &Status::NULL_POINTER;
        }
        // SAFETY: the caller passes a writable pointer, checked to be non-null above.
        Status::from_result(unsafe { Pointer::write_handle(out, DataIndependentTiming::enable()) })
    }

    /// Restores the mode found when `guard` was created and releases it, on the thread that
    /// created it. Does nothing if `guard` is null.
    pub unsafe extern "C" fn umilib_secret_data_independent_timing_free(guard: *mut DataIndependentTiming) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(guard) }
    }
}

crate::ffi_functions! {
    const TABLE;
    /// Creates the table of 256 entries of 8 bits from the `length` bytes at `entries`, which must be 256.
    pub unsafe extern "C" fn umilib_secret_constant_time_table32_8_from_bytes(entries: *const u8, length: usize, out: *mut *mut ConstantTimeTable<32, 8>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let entries = unsafe { Pointer::slice(entries, length) }?;
            if entries.len() != ConstantTimeTable::<32, 8>::ENTRIES {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write_handle(out, ConstantTimeTable::<32, 8>::from_bytes(entries)) }
        })())
    }

    /// Creates the table whose entries are all zero.
    pub unsafe extern "C" fn umilib_secret_constant_time_table32_8_new(out: *mut *mut ConstantTimeTable<32, 8>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, ConstantTimeTable::<32, 8>::new()) })
    }

    /// Releases the table, zeroizing it. Does nothing if `table` is null.
    pub unsafe extern "C" fn umilib_secret_constant_time_table32_8_free(table: *mut ConstantTimeTable<32, 8>) {
        // The table has no `Drop`, because the ciphers keep their tables in constants: zeroize it here.
        // SAFETY: the caller passes null or a handle created by this module, which it does not use again.
        if let Ok(entries) = unsafe { Pointer::reference_mut(table) } {
            entries.zeroize();
        }
        unsafe { Pointer::free(table) }
    }

    /// Writes a copy of `table` into `out`.
    pub unsafe extern "C" fn umilib_secret_constant_time_table32_8_clone(table: *const ConstantTimeTable<32, 8>, out: *mut *mut ConstantTimeTable<32, 8>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let table = unsafe { Pointer::reference(table) }?;
            unsafe { Pointer::write_handle(out, table.clone()) }
        })())
    }

    /// Writes the entry at `index` (modulo 256) into `out`, reading every word of the table.
    pub unsafe extern "C" fn umilib_secret_constant_time_table32_8_get(table: *const ConstantTimeTable<32, 8>, index: usize, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let table = unsafe { Pointer::reference(table) }?;
            unsafe { Pointer::write(out, table.get(index)) }
        })())
    }

    /// Replaces the entry at `index` (modulo 256) with the low 8 bits of `value`, writing every word of
    /// the table.
    pub unsafe extern "C" fn umilib_secret_constant_time_table32_8_set(table: *mut ConstantTimeTable<32, 8>, index: usize, value: u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(table) }?.set(index, value);
            Ok(())
        })())
    }

    /// Exchanges the entries at `first` and `second` (modulo 256).
    pub unsafe extern "C" fn umilib_secret_constant_time_table32_8_swap(table: *mut ConstantTimeTable<32, 8>, first: usize, second: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(table) }?.swap(first, second);
            Ok(())
        })())
    }

    /// Writes the 32 packed words of the table into the 32 words at `out`: entry `i` is bits
    /// 8 × (`i` mod 8) and up of word `i` / 8.
    pub unsafe extern "C" fn umilib_secret_constant_time_table32_8_words(table: *const ConstantTimeTable<32, 8>, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and 32 writable words.
            let table = unsafe { Pointer::reference(table) }?;
            let out = unsafe { Pointer::slice_of_mut(out, 32) }?;
            out.copy_from_slice(table.words());
            Ok(())
        })())
    }

    /// Returns all ones if `a` equals `b` and zero otherwise, without branching on them.
    pub unsafe extern "C" fn umilib_secret_constant_time_table32_8_mask(a: usize, b: usize) -> u64 {
        ConstantTimeTable::<32, 8>::mask(a, b)
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "secret",
    definitions: &[
        Definition::Opaque { name: "umilib_secret_Secret", documentation: " Bytes that are zeroized when released." },
        Definition::Opaque {
            name: "umilib_secret_DataIndependentTiming",
            documentation: " Keeps the data-independent timing mode set for the thread that created it.",
        },
        Definition::Opaque {
            name: "umilib_secret_ConstantTimeTable32_8",
            documentation: " A table of 256 entries of 8 bits whose reads and writes take the same time for every index.",
        },
    ],
    functions: &crate::ffi::Function::concat::<{ FUNCTIONS.len() + TABLE.len() }>(&[FUNCTIONS, TABLE]),
    modules: &[],
};
