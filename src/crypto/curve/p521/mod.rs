//! NIST P-521 (secp521r1): y^2 = x^3 - 3x + b over the integers modulo
//! p = 2^521 - 1 (FIPS 186-5, SP 800-186 section 3.2.1.5; SEC 2 section
//! 2.6.1; RFC 5903 section 3.3). Its coordinates and scalars take 66 bytes.
//!
//! [`P521`] implements [`WeierstrassCurve`]: its points are
//! `AffinePoint<P521>` and `ProjectivePoint<P521>` and its scalars
//! `FieldElement<P521Scalar>` (see [`crate::math::ec`]).

use crate::math::bigint::U576;
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field of the coordinates of NIST P-521: the integers modulo the prime p.
#[derive(Clone, Copy, Debug)]
pub struct P521Field;

impl P521Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<P521Field> {
        FieldElement::from_residue(
            <P521Field as PrimeField>::MODULUS.residue_vartime(&U576::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for P521Field {
    type Modulus = Modulus<{ U576::LIMBS }>;
    const MODULUS: Modulus<{ U576::LIMBS }> = Modulus::new_vartime_or_panic(U576::from_hex_vartime_or_panic(
        "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ));
    const BYTES: usize = 66;
}

/// The field of the scalars of NIST P-521: the integers modulo the order n of its generator.
#[derive(Clone, Copy, Debug)]
pub struct P521Scalar;

impl P521Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<P521Scalar> {
        FieldElement::from_residue(
            <P521Scalar as PrimeField>::MODULUS.residue_vartime(&U576::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for P521Scalar {
    type Modulus = Modulus<{ U576::LIMBS }>;
    const MODULUS: Modulus<{ U576::LIMBS }> = Modulus::new_vartime_or_panic(U576::from_hex_vartime_or_panic(
        "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    ));
    const BYTES: usize = 66;
}

/// NIST P-521, with the coefficients and the generator of its specification.
#[derive(Clone, Copy, Debug)]
pub struct P521;

impl WeierstrassCurve for P521 {
    type Field = P521Field;
    type Scalar = P521Scalar;
    const A: FieldElement<P521Field> = P521Field::element(
        "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
    );
    const B: FieldElement<P521Field> = P521Field::element(
        "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
    );
    const SHAPE: CoefficientA = CoefficientA::MinusThree;
    const GENERATOR_X: FieldElement<P521Field> = P521Field::element(
        "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
    );
    const GENERATOR_Y: FieldElement<P521Field> = P521Field::element(
        "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
    );
    const COFACTOR: u128 = 1;
}
