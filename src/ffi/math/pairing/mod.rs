//! The C ABI of [`crate::math::pairing`].
//!
//! The pairing e: G_1 × G_2 → G_T of every curve of
//! [`ffi_pairing_curves!`](crate::ffi_pairing_curves), named by the C type
//! name of its type, on encoded points: G_1 in SEC 1 (compressed or not),
//! G_2 as [`G2Affine::write_encoded`] and G_T as [`GT::write_bytes`].

use crate::ffi::{Module, Pointer, Status, ToStatus};
use crate::math::ec::AffinePoint;
use crate::math::pairing::{G2Affine, GT, Pairing, PairingCurve};

/// The registry of the pairing-friendly curves of the C ABI: calls
/// `$callback!` with `Variant => type, "C type name";` for each.
#[macro_export]
macro_rules! ffi_pairing_curves {
    ($callback:ident) => {
        $callback! {
            BLS12381 => $crate::math::pairing::BLS12381, "umilib_math_pairing_BLS12381";
            BN254 => $crate::math::pairing::BN254, "umilib_math_pairing_BN254";
            BN462 => $crate::math::pairing::BN462, "umilib_math_pairing_BN462";
            SM9BN256 => $crate::math::pairing::SM9BN256, "umilib_math_pairing_SM9BN256";
        }
    };
}

/// An operation on a curve chosen at run time.
pub enum PairingCall<'a> {
    /// Writes the sizes in bytes of an uncompressed point of G_1, a point of G_2 and an element of G_T.
    Sizes { out: &'a mut [usize; 3] },
    /// Writes e(P, Q) for P of G_1 and Q of G_2, both in their subgroups of order r.
    Pairing { p: &'a [u8], q: &'a [u8], out: &'a mut [u8] },
}

impl PairingCall<'_> {
    pub fn call<C: PairingCurve>(self) -> Result<(), &'static Status> {
        match self {
            PairingCall::Sizes { out } => {
                *out = [
                    AffinePoint::<C::G1>::encoded_length(false),
                    G2Affine::<C>::encoded_length(),
                    GT::<C>::encoded_length(),
                ];
                Ok(())
            }
            PairingCall::Pairing { p, q, out } => {
                let p = AffinePoint::<C::G1>::from_encoded(p).map_err(|_| &Status::INVALID_ARGUMENT)?;
                let q = G2Affine::<C>::from_encoded(q).map_err(|_| &Status::INVALID_ARGUMENT)?;
                if !(p.is_in_subgroup() & q.is_in_subgroup()).into_bool() {
                    return Err(&Status::INVALID_ARGUMENT);
                }
                let value = Pairing::<C>::pairing(&p, &q).map_err(|error| error.to_status())?;
                value.write_bytes(out).map_err(|error| error.to_status())
            }
        }
    }
}

/// Defines [`PairingCall::dispatch`] over the curves of the registry.
macro_rules! pairing_curves {
    ($($variant:ident => $type:path, $name:literal;)*) => {
        impl PairingCall<'_> {
            /// The operation on the curve named `curve`; fails with InvalidArgument if it is unknown.
            pub fn dispatch(self, curve: &str) -> Result<(), &'static Status> {
                match curve {
                    $($name => self.call::<$type>(),)*
                    _ => Err(&Status::INVALID_ARGUMENT),
                }
            }
        }
    };
}

crate::ffi_pairing_curves!(pairing_curves);

crate::ffi_functions! {
    /// Writes the sizes in bytes of an uncompressed point of G_1, a point of G_2 and an element of G_T of the
    /// curve named by `curve` into `sizes` (three elements).
    pub unsafe extern "C" fn umilib_math_pairing_pairing_sizes(curve: *const u8, curve_length: usize, sizes: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(curve, curve_length)], &[(sizes.cast_const().cast(), 3 * core::mem::size_of::<usize>())])?;
            // SAFETY: the caller passes readable text and three writable elements.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let out = unsafe { Pointer::slice_of_mut(sizes, 3) }?;
            let out = out.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            PairingCall::Sizes { out }.dispatch(curve)
        })())
    }

    /// Writes e(P, Q) on the curve named by `curve` into `out` of the size of an element of G_T; fails with
    /// InvalidArgument for points that are not on the curve or not in their subgroups of order r.
    pub unsafe extern "C" fn umilib_math_pairing_pairing_pairing(curve: *const u8, curve_length: usize, p: *const u8, p_length: usize, q: *const u8, q_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(curve, curve_length), (p, p_length), (q, q_length)], &[(out.cast_const(), out_length)])?;
            // SAFETY: the caller passes readable text and bytes and writable bytes.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let p = unsafe { Pointer::slice(p, p_length) }?;
            let q = unsafe { Pointer::slice(q, q_length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            PairingCall::Pairing { p, q, out }.dispatch(curve)
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "pairing", definitions: &[], functions: FUNCTIONS, modules: &[] };
