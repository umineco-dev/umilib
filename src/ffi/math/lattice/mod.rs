//! The C ABI of [`crate::math::lattice`].
//!
//! The transforms of [`Polynomial`] in the rings named by the C type names
//! `umilib_math_lattice_MLKEMRing` and `umilib_math_lattice_MLDSARing`, on
//! arrays of the n coefficients as `uint32_t` (reduced modulo q on input):
//! `umilib_math_lattice_polynomial_ntt`, `_inverse_ntt` and
//! `_multiply_ntt`.

use crate::ffi::{Module, Pointer, Status};
use crate::math::lattice::{LatticeCoefficient, LatticeRing, MLDSARing, MLKEMRing, Polynomial};

/// An operation on a ring chosen at run time.
pub trait LatticeRingCall {
    type Output;

    fn call<R: LatticeRing>(self) -> Self::Output;
}

/// The rings of the C ABI, by their C type names; `None` for a name that is unknown.
pub struct LatticeRegistry;

impl LatticeRegistry {
    pub fn ring<V: LatticeRingCall>(name: &str, call: V) -> Option<V::Output> {
        match name {
            "umilib_math_lattice_MLKEMRing" => Some(call.call::<MLKEMRing>()),
            "umilib_math_lattice_MLDSARing" => Some(call.call::<MLDSARing>()),
            _ => None,
        }
    }
}

/// A transform of polynomials given as coefficients: of `a` alone, or of
/// `a` and `b` for the product.
pub enum LatticeTransform<'a> {
    NTT { a: &'a [u32], out: &'a mut [u32] },
    InverseNTT { a: &'a [u32], out: &'a mut [u32] },
    MultiplyNTT { a: &'a [u32], b: &'a [u32], out: &'a mut [u32] },
}

impl LatticeRingCall for LatticeTransform<'_> {
    type Output = Result<(), &'static Status>;

    fn call<R: LatticeRing>(self) -> Result<(), &'static Status> {
        let polynomial = |values: &[u32]| Polynomial::<R>::from_values(values).map_err(|_| &Status::INVALID_ARGUMENT);
        let (result, out) = match self {
            LatticeTransform::NTT { a, out } => (polynomial(a)?.ntt(), out),
            LatticeTransform::InverseNTT { a, out } => (polynomial(a)?.inverse_ntt(), out),
            LatticeTransform::MultiplyNTT { a, b, out } => (polynomial(a)?.multiply_ntt(&polynomial(b)?), out),
        };
        if out.len() != R::N {
            return Err(&Status::INVALID_ARGUMENT);
        }
        for (target, coefficient) in out.iter_mut().zip(result.coefficients()) {
            *target = coefficient.to_u32();
        }
        Ok(())
    }
}

crate::ffi_functions! {
    /// Writes the NTT of the polynomial of the n coefficients `a` (n of them, reduced modulo q) in the ring named
    /// by `ring` into `out` (n elements).
    pub unsafe extern "C" fn umilib_math_lattice_polynomial_ntt(ring: *const u8, ring_length: usize, a: *const u32, a_count: usize, out: *mut u32, out_count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and elements and writable elements.
            let element = core::mem::size_of::<u32>();
            Pointer::check_ranges(&[(ring, ring_length), (a.cast(), a_count * element)], &[(out.cast_const().cast(), out_count * element)])?;
            let name = unsafe { Pointer::text(ring, ring_length) }?;
            let transform = LatticeTransform::NTT { a: unsafe { Pointer::slice_of(a, a_count) }?, out: unsafe { Pointer::slice_of_mut(out, out_count) }? };
            LatticeRegistry::ring(name, transform).ok_or(&Status::INVALID_ARGUMENT)?
        })())
    }

    /// Writes the inverse NTT of the representation `a` (n elements) into `out` (n elements).
    pub unsafe extern "C" fn umilib_math_lattice_polynomial_inverse_ntt(ring: *const u8, ring_length: usize, a: *const u32, a_count: usize, out: *mut u32, out_count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and elements and writable elements.
            let element = core::mem::size_of::<u32>();
            Pointer::check_ranges(&[(ring, ring_length), (a.cast(), a_count * element)], &[(out.cast_const().cast(), out_count * element)])?;
            let name = unsafe { Pointer::text(ring, ring_length) }?;
            let transform = LatticeTransform::InverseNTT { a: unsafe { Pointer::slice_of(a, a_count) }?, out: unsafe { Pointer::slice_of_mut(out, out_count) }? };
            LatticeRegistry::ring(name, transform).ok_or(&Status::INVALID_ARGUMENT)?
        })())
    }

    /// Writes the product in T_q of the NTT representations `a` and `b` (n elements each) into `out` (n elements).
    pub unsafe extern "C" fn umilib_math_lattice_polynomial_multiply_ntt(ring: *const u8, ring_length: usize, a: *const u32, a_count: usize, b: *const u32, b_count: usize, out: *mut u32, out_count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and elements and writable elements.
            let element = core::mem::size_of::<u32>();
            let inputs = [(ring, ring_length), (a.cast(), a_count * element), (b.cast(), b_count * element)];
            Pointer::check_ranges(&inputs, &[(out.cast_const().cast(), out_count * element)])?;
            let name = unsafe { Pointer::text(ring, ring_length) }?;
            let transform = LatticeTransform::MultiplyNTT {
                a: unsafe { Pointer::slice_of(a, a_count) }?,
                b: unsafe { Pointer::slice_of(b, b_count) }?,
                out: unsafe { Pointer::slice_of_mut(out, out_count) }?,
            };
            LatticeRegistry::ring(name, transform).ok_or(&Status::INVALID_ARGUMENT)?
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "lattice", definitions: &[], functions: FUNCTIONS, modules: &[] };
