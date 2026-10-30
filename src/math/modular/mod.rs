//! Arithmetic modulo an odd number, in constant time, by Montgomery
//! multiplication.
//!
//! A modulus ([`Modulus`] for [`Uint`](crate::math::bigint::Uint), or
//! [`BoxedModulus`] for [`BoxedUint`](crate::math::bigint::BoxedUint)) holds
//! the precomputed constants and performs every operation; values modulo it
//! are residues ([`Residue`], [`BoxedResidue`]), kept in the Montgomery form.
//! A residue does not remember its modulus: pass it only to the modulus that
//! made it. Another modulus of the same precision gives meaningless results
//! (never undefined behavior); one of another precision fails with
//! [`MathError::SizeMismatch`](crate::math::bigint::MathError::SizeMismatch).
//! The algorithms are written once, on slices of limbs, in [`ModularLimbs`].
//! [`ModularArithmetic`] is the interface of `Modulus` for code generic over
//! the precision, and `Modulus::new_vartime` and `Modulus::residue_vartime`
//! build constants at compile time.

mod boxed_modulus;
mod boxed_residue;
mod modular_arithmetic;
mod modular_limbs;
mod modulus;
mod residue;

pub use boxed_modulus::BoxedModulus;
pub use boxed_residue::BoxedResidue;
pub use modular_arithmetic::ModularArithmetic;
pub use modular_limbs::ModularLimbs;
pub use modulus::Modulus;
pub use residue::Residue;
