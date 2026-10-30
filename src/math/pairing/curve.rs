use core::fmt;

use super::{Fp2, PairingField};
use crate::math::ec::{PrimeField, WeierstrassCurve};

/// The family of a pairing-friendly curve, which chooses the Miller loop of
/// its optimal ate pairing (draft-irtf-cfrg-pairing-friendly-curves
/// appendix A).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingFamily {
    /// Barreto–Naehrig: the loop over 6t + 2 and two Frobenius lines.
    BN,
    /// Barreto–Lynn–Scott of embedding degree 12: the loop over t.
    BLS12,
}

/// The kind of the sextic twist E' of E over GF(p^2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwistType {
    /// E': y^2 = x^3 + b / ξ, untwisted by (x, y) ↦ (x w^2, y w^3).
    D,
    /// E': y^2 = x^3 + b ξ, untwisted by (x, y) ↦ (x w^-2, y w^-3).
    M,
}

/// A pairing-friendly curve of embedding degree 12: E over GF(p) (`G1`,
/// whose generator spans G_1), its twist E' over GF(p^2) of the
/// coefficient [`PairingCurve::TWIST_B`] with the generator of G_2, and
/// the tower GF(p^2) = GF(p)\[u\]/(u^2 - β) of the non-square β of its
/// field ([`PairingField`]), GF(p^6) = GF(p^2)\[v\]/(v^3 - ξ),
/// GF(p^12) = GF(p^6)\[w\]/(w^2 - v).
pub trait PairingCurve: Copy + fmt::Debug + 'static {
    type Field: PairingField;
    type Scalar: PrimeField;
    /// E with the generator of G_1 and the order r of the scalars.
    type G1: WeierstrassCurve<Field = Self::Field, Scalar = Self::Scalar>;
    const FAMILY: PairingFamily;
    const TWIST: TwistType;
    /// |t|, the parameter of the family.
    const PARAMETER: u128;
    /// Whether t is negative.
    const PARAMETER_NEGATIVE: bool;
    /// ξ, with v^3 = ξ.
    const XI: Fp2<Self::Field>;
    /// The coefficient b' of E': y^2 = x^3 + b'.
    const TWIST_B: Fp2<Self::Field>;
    const G2_GENERATOR_X: Fp2<Self::Field>;
    const G2_GENERATOR_Y: Fp2<Self::Field>;
}
