//! The C ABI of [`crate::math::modular`].
//!
//! [`BoxedModulus`] and [`BoxedResidue`] are exported as opaque handles.
//! [`Modulus`](crate::math::modular::Modulus) and
//! [`Residue`](crate::math::modular::Residue) have their precision in a const
//! generic parameter, which C cannot name, and
//! [`ModularLimbs`](crate::math::modular::ModularLimbs) works on native words
//! of a platform-dependent size; use the boxed types, which compute the same
//! results. Errors are those of `math.bigint`.

use crate::ffi::secret::ChoiceArgument;
use crate::ffi::{Definition, Module, Pointer, Status, ToStatus, Type, Value};
use crate::math::bigint::BoxedUint;
use crate::math::modular::{BoxedModulus, BoxedResidue};
use crate::secret::{ConstantTimeEq, Zeroize};

impl Value for BoxedModulus {
    const TYPE: Type = Type::Named("umilib_math_modular_BoxedModulus");
}

impl Value for BoxedResidue {
    const TYPE: Type = Type::Named("umilib_math_modular_BoxedResidue");
}

crate::ffi_functions! {
    /// Zeroizes and releases `modulus`. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_free(modulus: *mut BoxedModulus) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(modulus) }
    }

    /// Zeroizes and releases `residue`. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_math_modular_boxed_residue_free(residue: *mut BoxedResidue) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(residue) }
    }

    /// Prepares a copy of `value` as a modulus; fails if it is even or below 3.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_new(value: *const BoxedUint, out: *mut *mut BoxedModulus) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            let modulus = BoxedModulus::new(value.clone()).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, modulus) }
        })())
    }

    /// Creates a copy of `modulus`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_clone(modulus: *const BoxedModulus, out: *mut *mut BoxedModulus) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            unsafe { Pointer::write_handle(out, modulus.clone()) }
        })())
    }

    /// Creates a copy of the value of `modulus`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_value(modulus: *const BoxedModulus, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            unsafe { Pointer::write_handle(out, modulus.value().clone()) }
        })())
    }

    /// Writes the precision in bits of `modulus` and its residues into `out`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_precision(modulus: *const BoxedModulus, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            unsafe { Pointer::write(out, modulus.precision()) }
        })())
    }

    /// Fails unless `residue` has the precision of `modulus`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_check(modulus: *const BoxedModulus, residue: *const BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let residue = unsafe { Pointer::reference(residue) }?;
            modulus.check(residue).map_err(|error| error.to_status())
        })())
    }

    /// Creates the residue zero.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_zero(modulus: *const BoxedModulus, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            unsafe { Pointer::write_handle(out, modulus.zero()) }
        })())
    }

    /// Creates the residue one.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_one(modulus: *const BoxedModulus, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            unsafe { Pointer::write_handle(out, modulus.one()) }
        })())
    }

    /// Creates `x mod modulus` as a residue; `x` may have any precision.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_residue(modulus: *const BoxedModulus, x: *const BoxedUint, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let x = unsafe { Pointer::reference(x) }?;
            unsafe { Pointer::write_handle(out, modulus.residue(x)) }
        })())
    }

    /// Creates the value of `residue`, below the modulus.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_retrieve(modulus: *const BoxedModulus, residue: *const BoxedResidue, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let residue = unsafe { Pointer::reference(residue) }?;
            let value = modulus.retrieve(residue).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, value) }
        })())
    }

    /// Creates the residue whose Montgomery form is `montgomery`; fails if it is not below the
    /// modulus or has another precision.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_from_montgomery(modulus: *const BoxedModulus, montgomery: *const BoxedUint, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let montgomery = unsafe { Pointer::reference(montgomery) }?;
            let residue = modulus.from_montgomery(montgomery).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, residue) }
        })())
    }

    /// Creates `a + b`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_add(modulus: *const BoxedModulus, a: *const BoxedResidue, b: *const BoxedResidue, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            let result = modulus.add(a, b).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `a - b`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_sub(modulus: *const BoxedModulus, a: *const BoxedResidue, b: *const BoxedResidue, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            let result = modulus.sub(a, b).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `a * b`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_mul(modulus: *const BoxedModulus, a: *const BoxedResidue, b: *const BoxedResidue, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            let result = modulus.mul(a, b).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `-a`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_neg(modulus: *const BoxedModulus, a: *const BoxedResidue, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let a = unsafe { Pointer::reference(a) }?;
            let result = modulus.neg(a).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `a^2`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_square(modulus: *const BoxedModulus, a: *const BoxedResidue, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let a = unsafe { Pointer::reference(a) }?;
            let result = modulus.square(a).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `a^-1`; fails if `a` is not invertible, which is the one fact the time reveals.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_invert(modulus: *const BoxedModulus, a: *const BoxedResidue, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let a = unsafe { Pointer::reference(a) }?;
            let result = modulus.invert(a).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `base^exponent`, over every bit of the exponent's precision, in constant time.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_pow(modulus: *const BoxedModulus, base: *const BoxedResidue, exponent: *const BoxedUint, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let base = unsafe { Pointer::reference(base) }?;
            let exponent = unsafe { Pointer::reference(exponent) }?;
            let result = modulus.pow(base, exponent).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Creates `base^exponent` in time that depends on the exponent, which must be public.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_pow_vartime(modulus: *const BoxedModulus, base: *const BoxedResidue, exponent: *const BoxedUint, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let modulus = unsafe { Pointer::reference(modulus) }?;
            let base = unsafe { Pointer::reference(base) }?;
            let exponent = unsafe { Pointer::reference(exponent) }?;
            let result = modulus.pow_vartime(base, exponent).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Writes whether the moduli are equal, as a choice, into `out`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_ct_eq(a: *const BoxedModulus, b: *const BoxedModulus, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            unsafe { Pointer::write(out, a.ct_eq(b).bit()) }
        })())
    }

    /// Zeroizes `modulus`, which is unusable afterwards except to be released.
    pub unsafe extern "C" fn umilib_math_modular_boxed_modulus_zeroize(modulus: *mut BoxedModulus) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let modulus = unsafe { Pointer::reference_mut(modulus) }?;
            modulus.zeroize();
            Ok(())
        })())
    }

    /// Creates the residue whose Montgomery form is a copy of `montgomery`, which must be below the
    /// modulus and of its precision; `umilib_math_modular_boxed_modulus_from_montgomery` checks both.
    pub unsafe extern "C" fn umilib_math_modular_boxed_residue_from_montgomery_unchecked(montgomery: *const BoxedUint, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let montgomery = unsafe { Pointer::reference(montgomery) }?;
            unsafe { Pointer::write_handle(out, BoxedResidue::from_montgomery_unchecked(montgomery.clone())) }
        })())
    }

    /// Creates a copy of `residue`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_residue_clone(residue: *const BoxedResidue, out: *mut *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let residue = unsafe { Pointer::reference(residue) }?;
            unsafe { Pointer::write_handle(out, residue.clone()) }
        })())
    }

    /// Creates a copy of the Montgomery form of `residue`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_residue_as_montgomery(residue: *const BoxedResidue, out: *mut *mut BoxedUint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let residue = unsafe { Pointer::reference(residue) }?;
            unsafe { Pointer::write_handle(out, residue.as_montgomery().clone()) }
        })())
    }

    /// Writes the precision in bits of `residue` into `out`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_residue_precision(residue: *const BoxedResidue, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let residue = unsafe { Pointer::reference(residue) }?;
            unsafe { Pointer::write(out, residue.precision()) }
        })())
    }

    /// Writes whether the residues are equal, as a choice, into `out`.
    pub unsafe extern "C" fn umilib_math_modular_boxed_residue_ct_eq(a: *const BoxedResidue, b: *const BoxedResidue, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let a = unsafe { Pointer::reference(a) }?;
            let b = unsafe { Pointer::reference(b) }?;
            unsafe { Pointer::write(out, a.ct_eq(b).bit()) }
        })())
    }

    /// Sets `residue` to zero.
    pub unsafe extern "C" fn umilib_math_modular_boxed_residue_zeroize(residue: *mut BoxedResidue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let residue = unsafe { Pointer::reference_mut(residue) }?;
            residue.zeroize();
            Ok(())
        })())
    }


    /// Sets `target` to `source` if `choice` is 1 (other values are rejected); both must have
    /// the same precision. Does nothing if they are the same object.
    pub unsafe extern "C" fn umilib_math_modular_boxed_residue_conditional_assign(target: *mut BoxedResidue, source: *const BoxedResidue, choice: u8) -> *const Status {
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

    /// Swaps `a` and `b` if `choice` is 1 (other values are rejected); both must have the same
    /// precision. Does nothing if they are the same object.
    pub unsafe extern "C" fn umilib_math_modular_boxed_residue_conditional_swap(a: *mut BoxedResidue, b: *mut BoxedResidue, choice: u8) -> *const Status {
        Status::from_result((|| {
            let choice = ChoiceArgument::decode(choice)?;
            // SAFETY: the caller passes valid handles; distinct handles never alias.
            if core::ptr::eq(a, b) {
                return Ok(());
            }
            let a = unsafe { Pointer::reference_mut(a) }?;
            let b = unsafe { Pointer::reference_mut(b) }?;
            BoxedResidue::conditional_swap(a, b, choice).map_err(|error| error.to_status())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "modular",
    definitions: &[
        Definition::Opaque {
            name: "umilib_math_modular_BoxedModulus",
            documentation: " An odd modulus with its Montgomery constants, zeroized when released.",
        },
        Definition::Opaque {
            name: "umilib_math_modular_BoxedResidue",
            documentation: " A value modulo a BoxedModulus in the Montgomery form, zeroized when released.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
