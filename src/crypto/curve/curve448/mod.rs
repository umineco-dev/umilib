//! Curve448 and edwards448 (RFC 7748 section 4.2, RFC 8032 section 5.2):
//! the Montgomery curve v^2 = u^3 + 156326u^2 + u and the 4-isogenous
//! Edwards curve x^2 + y^2 = 1 - 39081x^2y^2, over the integers modulo
//! p = 2^448 - 2^224 - 1, of cofactor 4.
//!
//! [`Curve448`] implements [`MontgomeryCurve`] (the ladder of X448) and
//! [`Edwards448`] implements [`EdwardsCurve`] (the group of Ed448). Both
//! share the field [`Curve448Field`] and the scalars [`Curve448Scalar`]
//! modulo the order L of the base point.

use crate::math::bigint::U448;
use crate::math::ec::{EdwardsCurve, FieldElement, MontgomeryCurve, PrimeField};
use crate::math::modular::Modulus;

/// The field of the coordinates of curve448 and edwards448: the integers modulo p = 2^448 - 2^224 - 1.
#[derive(Clone, Copy, Debug)]
pub struct Curve448Field;

impl Curve448Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<Curve448Field> {
        FieldElement::from_residue(
            <Curve448Field as PrimeField>::MODULUS.residue_vartime(&U448::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for Curve448Field {
    type Modulus = Modulus<{ U448::LIMBS }>;
    const MODULUS: Modulus<{ U448::LIMBS }> = Modulus::new_vartime_or_panic(U448::from_hex_vartime_or_panic(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ));
    const BYTES: usize = 56;
}

/// The field of the scalars: the integers modulo
/// L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885,
/// the order of the base point.
#[derive(Clone, Copy, Debug)]
pub struct Curve448Scalar;

impl Curve448Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<Curve448Scalar> {
        FieldElement::from_residue(
            <Curve448Scalar as PrimeField>::MODULUS.residue_vartime(&U448::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for Curve448Scalar {
    type Modulus = Modulus<{ U448::LIMBS }>;
    const MODULUS: Modulus<{ U448::LIMBS }> = Modulus::new_vartime_or_panic(U448::from_hex_vartime_or_panic(
        "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
    ));
    const BYTES: usize = 56;
}

/// curve448, the Montgomery curve of X448.
#[derive(Clone, Copy, Debug)]
pub struct Curve448;

impl MontgomeryCurve for Curve448 {
    type Field = Curve448Field;
    /// (156326 - 2) / 4 = 39081.
    const A24: FieldElement<Curve448Field> = Curve448Field::element("98a9");
    const BASE_U: FieldElement<Curve448Field> = Curve448Field::element("5");
    const SCALAR_BITS: u32 = 448;
    const COFACTOR: u32 = 4;
}

/// edwards448, the Edwards curve of Ed448, with the base point of RFC 8032
/// section 5.2, which the 4-isogeny of RFC 7748 maps to u = 5.
#[derive(Clone, Copy, Debug)]
pub struct Edwards448;

impl EdwardsCurve for Edwards448 {
    type Field = Curve448Field;
    type Scalar = Curve448Scalar;
    const A: FieldElement<Curve448Field> = Curve448Field::element("1");
    /// -39081.
    const D: FieldElement<Curve448Field> = Curve448Field::element(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6756",
    );
    const GENERATOR_X: FieldElement<Curve448Field> = Curve448Field::element(
        "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e",
    );
    const GENERATOR_Y: FieldElement<Curve448Field> = Curve448Field::element(
        "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14",
    );
    const COFACTOR: u32 = 4;
    const ENCODED_BYTES: usize = 57;
}
