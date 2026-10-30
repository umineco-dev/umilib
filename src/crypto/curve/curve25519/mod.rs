//! Curve25519 and edwards25519 (RFC 7748 section 4.1, RFC 8032 section
//! 5.1): the Montgomery curve v^2 = u^3 + 486662u^2 + u and the birationally
//! equivalent twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2, over the
//! integers modulo p = 2^255 - 19, of cofactor 8.
//!
//! [`Curve25519`] implements [`MontgomeryCurve`] (the ladder of X25519) and
//! [`Edwards25519`] implements [`EdwardsCurve`] (the group of Ed25519). Both
//! share the field [`Curve25519Field`] and the scalars [`Curve25519Scalar`]
//! modulo the order L of the base point.

use crate::math::bigint::U256;
use crate::math::ec::{EdwardsCurve, FieldElement, MontgomeryCurve, PrimeField};
use crate::math::modular::Modulus;

/// The field of the coordinates of curve25519 and edwards25519: the integers modulo p = 2^255 - 19.
#[derive(Clone, Copy, Debug)]
pub struct Curve25519Field;

impl Curve25519Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<Curve25519Field> {
        FieldElement::from_residue(
            <Curve25519Field as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for Curve25519Field {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
    ));
    const BYTES: usize = 32;
}

/// The field of the scalars: the integers modulo L = 2^252 + 27742317777372353535851937790883648493,
/// the order of the base point.
#[derive(Clone, Copy, Debug)]
pub struct Curve25519Scalar;

impl Curve25519Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<Curve25519Scalar> {
        FieldElement::from_residue(
            <Curve25519Scalar as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for Curve25519Scalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
    ));
    const BYTES: usize = 32;
}

/// curve25519, the Montgomery curve of X25519.
#[derive(Clone, Copy, Debug)]
pub struct Curve25519;

impl MontgomeryCurve for Curve25519 {
    type Field = Curve25519Field;
    /// (486662 - 2) / 4 = 121665.
    const A24: FieldElement<Curve25519Field> = Curve25519Field::element("1db41");
    const BASE_U: FieldElement<Curve25519Field> = Curve25519Field::element("9");
    const SCALAR_BITS: u32 = 255;
    const COFACTOR: u32 = 8;
}

/// edwards25519, the twisted Edwards curve of Ed25519, with the base point B
/// = (x, 4/5) of RFC 8032 section 5.1.
#[derive(Clone, Copy, Debug)]
pub struct Edwards25519;

impl EdwardsCurve for Edwards25519 {
    type Field = Curve25519Field;
    type Scalar = Curve25519Scalar;
    /// -1.
    const A: FieldElement<Curve25519Field> =
        Curve25519Field::element("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec");
    /// -121665 / 121666.
    const D: FieldElement<Curve25519Field> =
        Curve25519Field::element("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3");
    const GENERATOR_X: FieldElement<Curve25519Field> =
        Curve25519Field::element("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a");
    const GENERATOR_Y: FieldElement<Curve25519Field> =
        Curve25519Field::element("6666666666666666666666666666666666666666666666666666666666666658");
    const COFACTOR: u32 = 8;
    const ENCODED_BYTES: usize = 32;
}
