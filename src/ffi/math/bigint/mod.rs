//! The C ABI of [`crate::math::bigint`].
//!
//! [`BoxedUint`] is exported as an opaque handle; a
//! [`Choice`](crate::secret::Choice) is passed as a `uint8_t` holding 0 or 1,
//! and other values are rejected. [`Uint`](crate::math::bigint::Uint) has its
//! precision in a const generic parameter, which C cannot name: use
//! `BoxedUint` of the same precision, which computes the same results.
//! [`Limbs`](crate::math::bigint::Limbs) works on native words, whose size
//! differs between platforms, and is not exported either. The bitwise
//! operators of Rust are exported under the names of their traits (`bitand`,
//! `bitor`, `bitxor`, `not`).

use crate::ffi::secret::ChoiceArgument;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};
use crate::math::bigint::{BoxedUint, MathError};
use crate::secret::{ConstantTimeEq, Zeroize};

impl Value for BoxedUint {
    const TYPE: Type = Type::Named("umilib_math_bigint_BoxedUint");
}

/// The integers that the C ABI of other modules passes as big-endian bytes.
pub struct BigEndianInteger;

impl BigEndianInteger {
    /// The integer of big-endian `bytes`, in the precision of their bits;
    /// fails with InvalidArgument beyond the largest precision.
    pub fn integer(bytes: &[u8]) -> Result<BoxedUint, &'static Status> {
        let bits = bytes.len().max(1).checked_mul(8).and_then(|bits| u32::try_from(bits).ok());
        let bits = bits.ok_or(&Status::INVALID_ARGUMENT)?;
        BoxedUint::from_be_bytes(bytes, bits).map_err(|_| &Status::INVALID_ARGUMENT)
    }

    /// The big-endian bytes of `value`, without leading zeros.
    pub fn bytes(value: &BoxedUint) -> alloc::vec::Vec<u8> {
        let mut bytes = value.to_be_bytes();
        let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
        bytes.drain(..zeros);
        bytes
    }
}

/// The statuses of [`MathError`], one per variant.
pub struct MathStatus;

impl MathStatus {
    pub const OVERFLOW: Status = Status::new(c"math.bigint", c"Overflow", c"the value does not fit");
    pub const SIZE_MISMATCH: Status =
        Status::new(c"math.bigint", c"SizeMismatch", c"the operands have different precisions");
    pub const DIVISION_BY_ZERO: Status = Status::new(c"math.bigint", c"DivisionByZero", c"division by zero");
    pub const NOT_INVERTIBLE: Status = Status::new(c"math.bigint", c"NotInvertible", c"the value is not invertible");
    pub const INVALID_MODULUS: Status =
        Status::new(c"math.bigint", c"InvalidModulus", c"the modulus must be odd and at least 3");
    pub const INVALID_DIGIT: Status =
        Status::new(c"math.bigint", c"InvalidDigit", c"the text is not a hexadecimal number");
    pub const INVALID_PRECISION: Status =
        Status::new(c"math.bigint", c"InvalidPrecision", c"the precision exceeds the maximum");
    pub const ALLOCATION_FAILED: Status =
        Status::new(c"math.bigint", c"AllocationFailed", c"memory could not be allocated");
}

impl ToStatus for MathError {
    fn to_status(&self) -> &'static Status {
        match self {
            MathError::Overflow => &MathStatus::OVERFLOW,
            MathError::SizeMismatch => &MathStatus::SIZE_MISMATCH,
            MathError::DivisionByZero => &MathStatus::DIVISION_BY_ZERO,
            MathError::NotInvertible => &MathStatus::NOT_INVERTIBLE,
            MathError::InvalidModulus => &MathStatus::INVALID_MODULUS,
            MathError::InvalidDigit { .. } => &MathStatus::INVALID_DIGIT,
            MathError::InvalidPrecision { .. } => &MathStatus::INVALID_PRECISION,
            MathError::AllocationFailed => &MathStatus::ALLOCATION_FAILED,
        }
    }
}

crate::ffi_functions! {
    /// Zeroizes and releases `value`. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_free(value: *mut BoxedUint) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(value) }
    }

    /// Writes the multiple of bits that precisions are rounded up to into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_precision_unit(out: *mut u32) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, BoxedUint::PRECISION_UNIT) })
    }

    /// Writes the largest precision in bits into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_maximum_precision(out: *mut u32) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, BoxedUint::MAXIMUM_PRECISION) })
    }

    /// Creates zero of `precision` bits, rounded up to a multiple of 64 (at least 64).
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_zero(precision: u32, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a writable pointer.
            let value = BoxedUint::zero(precision).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, value) }
        })())
    }

    /// Creates one of `precision` bits.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_one(precision: u32, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a writable pointer.
            let value = BoxedUint::one(precision).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, value) }
        })())
    }

    /// Creates `value` in `precision` bits.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_from_u64(value: u64, precision: u32, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a writable pointer.
            let value = BoxedUint::from_u64(value, precision).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, value) }
        })())
    }

    /// Creates the big-endian number of `length` bytes at `data` in `precision` bits.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_from_be_bytes(data: *const u8, length: usize, precision: u32, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let value = BoxedUint::from_be_bytes(data, precision).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, value) }
        })())
    }

    /// Creates the little-endian number of `length` bytes at `data` in `precision` bits.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_from_le_bytes(data: *const u8, length: usize, precision: u32, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let value = BoxedUint::from_le_bytes(data, precision).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, value) }
        })())
    }

    /// Creates the number of the big-endian hexadecimal UTF-8 `text` in `precision` bits.
    /// The time depends on the digits: use it for public values.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_from_hex_vartime(text: *const u8, length: usize, precision: u32, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let value = BoxedUint::from_hex_vartime(text, precision).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, value) }
        })())
    }

    /// Creates a copy of `value`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_clone(value: *const BoxedUint, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            let result = value.clone();
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `value` in `precision` bits; fails if it does not fit.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_resize(value: *const BoxedUint, precision: u32, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            let result = value.resize(precision).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `value << bits`, discarding the bits shifted out; the time depends on `bits` only.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_shl(value: *const BoxedUint, bits: u32, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            let result = value.shl(bits);
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `value >> bits`; the time depends on `bits` only.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_shr(value: *const BoxedUint, bits: u32, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            let result = value.shr(bits);
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `value` with every bit of the precision inverted.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_not(value: *const BoxedUint, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            let result = !value;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Writes the precision in bits into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_precision(value: *const BoxedUint, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            unsafe { Pointer::write(out, value.precision()) }
        })())
    }

    /// Writes the number of bytes of the precision into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_bytes(value: *const BoxedUint, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            unsafe { Pointer::write(out, value.bytes()) }
        })())
    }

    /// Writes whether `value` is zero, as a choice, into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_is_zero(value: *const BoxedUint, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            unsafe { Pointer::write(out, value.is_zero().bit()) }
        })())
    }

    /// Writes whether `value` is odd, as a choice, into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_is_odd(value: *const BoxedUint, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            unsafe { Pointer::write(out, value.is_odd().bit()) }
        })())
    }

    /// Writes bit `index`, counted from the least significant, as a choice, into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_bit(value: *const BoxedUint, index: u32, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            unsafe { Pointer::write(out, value.bit(index).bit()) }
        })())
    }

    /// Writes the number of bits up to the highest set bit into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_bit_length(value: *const BoxedUint, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            unsafe { Pointer::write(out, value.bit_length()) }
        })())
    }

    /// Writes the value big-endian in the bytes of its precision into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_to_be_bytes(value: *const BoxedUint, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let value = unsafe { Pointer::reference(value) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(value.to_be_bytes())) }
        })())
    }

    /// Writes the value big-endian into all `length` bytes at `data`, padded with zeros;
    /// fails if it needs more bytes.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_write_be_bytes(value: *const BoxedUint, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable bytes.
            let value = unsafe { Pointer::reference(value) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            value.write_be_bytes(data).map_err(|error| error.to_status())
        })())
    }

    /// Writes the value little-endian in the bytes of its precision into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_to_le_bytes(value: *const BoxedUint, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let value = unsafe { Pointer::reference(value) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(value.to_le_bytes())) }
        })())
    }

    /// Writes the value little-endian into all `length` bytes at `data`, padded with zeros;
    /// fails if it needs more bytes.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_write_le_bytes(value: *const BoxedUint, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable bytes.
            let value = unsafe { Pointer::reference(value) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            value.write_le_bytes(data).map_err(|error| error.to_status())
        })())
    }

    /// Writes whether `a == b`, as a choice, into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_ct_eq(a: *const BoxedUint, b: *const BoxedUint, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            unsafe { Pointer::write(out, a.ct_eq(b).bit()) }
        })())
    }

    /// Writes whether `a < b`, as a choice, into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_ct_lt(a: *const BoxedUint, b: *const BoxedUint, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            unsafe { Pointer::write(out, a.ct_lt(b).bit()) }
        })())
    }

    /// Writes whether `a > b`, as a choice, into `out`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_ct_gt(a: *const BoxedUint, b: *const BoxedUint, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            unsafe { Pointer::write(out, a.ct_gt(b).bit()) }
        })())
    }

    /// Writes -1, 0 or 1 as `a` is below, equal to or above `b` into `out`; the time depends on the values.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_compare_vartime(a: *const BoxedUint, b: *const BoxedUint, out: *mut i8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            unsafe { Pointer::write(out, a.compare_vartime(b) as i8) }
        })())
    }

    /// Creates `a + b` modulo 2^precision, the larger precision of the two.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_wrapping_add(a: *const BoxedUint, b: *const BoxedUint, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            let result = a.wrapping_add(b);
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `a - b` modulo 2^precision.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_wrapping_sub(a: *const BoxedUint, b: *const BoxedUint, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            let result = a.wrapping_sub(b);
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `a * b` modulo 2^precision.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_wrapping_mul(a: *const BoxedUint, b: *const BoxedUint, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            let result = a.wrapping_mul(b);
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `a & b`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_bitand(a: *const BoxedUint, b: *const BoxedUint, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            let result = a & b;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `a | b`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_bitor(a: *const BoxedUint, b: *const BoxedUint, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            let result = a | b;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `a ^ b`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_bitxor(a: *const BoxedUint, b: *const BoxedUint, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            let result = a ^ b;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `a mod modulus` in the precision of the modulus; fails if it is zero.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_rem(a: *const BoxedUint, modulus: *const BoxedUint, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let result = a.rem(modulus).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `a + b` modulo 2^precision and writes whether it carried, as a choice, into `out_carry`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_overflowing_add(a: *const BoxedUint, b: *const BoxedUint, out: *mut *mut BoxedUint, out_carry: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and writable pointers.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            if out.is_null() || out_carry.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let (result, carry) = a.overflowing_add(b);
            unsafe { Pointer::write(out_carry, carry.bit()) }?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `a - b` modulo 2^precision and writes whether it borrowed, as a choice, into `out_borrow`.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_overflowing_sub(a: *const BoxedUint, b: *const BoxedUint, out: *mut *mut BoxedUint, out_borrow: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and writable pointers.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            if out.is_null() || out_borrow.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let (result, borrow) = a.overflowing_sub(b);
            unsafe { Pointer::write(out_borrow, borrow.bit()) }?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates the low and the high half of the full product `a * b`; the two outputs must differ.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_widening_mul(a: *const BoxedUint, b: *const BoxedUint, out_low: *mut *mut BoxedUint, out_high: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and writable pointers.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            if out_low.is_null() || out_high.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            if core::ptr::eq(out_low, out_high) {
                // One output would overwrite, and leak, the other.
                return Err(&Status::INVALID_ARGUMENT);
            }
            let (low, high) = a.widening_mul(b);
            unsafe { Pointer::write_handle(out_low, low) }?;
            unsafe { Pointer::write_handle(out_high, high) }
        })())
    }

    /// Creates the quotient, in the precision of `a`, and the remainder, in that of the
    /// divisor, of `a / divisor`; fails if the divisor is zero. The two outputs must differ.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_div_rem(a: *const BoxedUint, divisor: *const BoxedUint, out_quotient: *mut *mut BoxedUint, out_remainder: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and writable pointers.
            let a = unsafe { Pointer::reference(a) }?;
            let divisor = unsafe { Pointer::reference(divisor) }?;
            if out_quotient.is_null() || out_remainder.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            if core::ptr::eq(out_quotient, out_remainder) {
                // One output would overwrite, and leak, the other.
                return Err(&Status::INVALID_ARGUMENT);
            }
            let (quotient, remainder) = a.div_rem(divisor).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out_quotient, quotient) }?;
            unsafe { Pointer::write_handle(out_remainder, remainder) }
        })())
    }

    /// Creates `(low + high * 2^precision(low)) mod modulus` in the precision of the modulus;
    /// fails if it is zero.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_rem_wide(low: *const BoxedUint, high: *const BoxedUint, modulus: *const BoxedUint, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let low = unsafe { Pointer::reference(low) }?;
            let high = unsafe { Pointer::reference(high) }?;
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let result = BoxedUint::rem_wide(low, high, modulus).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Sets `target` to `source` if `choice` is 1; both must have the same precision.
    /// Does nothing if they are the same object.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_conditional_assign(target: *mut BoxedUint, source: *const BoxedUint, choice: u8) -> *const Status {
        Status::from_result((|| {
            let choice = ChoiceArgument::decode(choice)?;
            // SAFETY: the caller passes valid handles; distinct handles never alias.
            if core::ptr::eq(target, source) {
                return Ok(());
            }
            let target = unsafe { Pointer::reference_mut(target) }?;
            let source = unsafe { Pointer::reference(source) }?;
            target.conditional_assign(source, choice).map_err(|error| error.to_status())
        })())
    }

    /// Swaps `a` and `b` if `choice` is 1; both must have the same precision.
    /// Does nothing if they are the same object.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_conditional_swap(a: *mut BoxedUint, b: *mut BoxedUint, choice: u8) -> *const Status {
        Status::from_result((|| {
            let choice = ChoiceArgument::decode(choice)?;
            // SAFETY: the caller passes valid handles; distinct handles never alias.
            if core::ptr::eq(a, b) {
                return Ok(());
            }
            let a = unsafe { Pointer::reference_mut(a) }?;
            let b = unsafe { Pointer::reference_mut(b) }?;
            BoxedUint::conditional_swap(a, b, choice).map_err(|error| error.to_status())
        })())
    }

    /// Sets `value` to zero, keeping its precision.
    pub unsafe extern "C" fn umilib_math_bigint_boxed_uint_zeroize(value: *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let value = unsafe { Pointer::reference_mut(value) }?;
            value.zeroize();
            Ok(())
        })())
    }

}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "bigint",
    definitions: &[Definition::Opaque {
        name: "umilib_math_bigint_BoxedUint",
        documentation: " An unsigned integer of a precision chosen at run time, zeroized when released.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
