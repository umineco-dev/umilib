use crate::math::lattice::{MLDSARing, Polynomial, PolynomialMatrix, PolynomialVector};

/// A parameter set of ML-DSA (FIPS 204 table 1): the dimensions (k, ℓ) of
/// Â, the bound η of the secret coefficients, the weight τ of the
/// challenge, the collision strength λ, the ranges γ1 of the mask and γ2 of
/// the low bits, β = τ η and the most ω ones of a hint. A parameter set is
/// a type of no value, given to [`MLDSA`](super::MLDSA).
pub trait MLDSAParameters: 'static {
    /// The name of the parameter set, such as `ML-DSA-65`.
    const NAME: &'static str;
    const K: usize;
    const L: usize;
    const ETA: u32;
    const TAU: usize;
    /// λ, in bits.
    const LAMBDA: usize;
    const GAMMA1: u32;
    const GAMMA2: u32;
    const OMEGA: usize;
    /// `[Polynomial<MLDSARing>; K]`.
    type VectorK: PolynomialVector<MLDSARing>;
    /// `[Polynomial<MLDSARing>; L]`.
    type VectorL: PolynomialVector<MLDSARing>;
    /// `[Self::VectorL; K]`: Â, k rows of ℓ entries.
    type Matrix: PolynomialMatrix<MLDSARing, Row = Self::VectorL>;

    /// The bits d dropped from t.
    const D: u32 = 13;
    /// β = τ η.
    const BETA: u32 = Self::TAU as u32 * Self::ETA;
    /// bitlen(2η), the bits of a coefficient of s1 and s2.
    const ETA_BITS: u32 = u32::BITS - (2 * Self::ETA).leading_zeros();
    /// 1 + bitlen(γ1 - 1), the bits of a coefficient of z.
    const GAMMA1_BITS: u32 = 1 + u32::BITS - (Self::GAMMA1 - 1).leading_zeros();
    /// bitlen((q - 1) / (2 γ2) - 1), the bits of a coefficient of w1.
    const W1_BITS: u32 = u32::BITS - ((8380417 - 1) / (2 * Self::GAMMA2) - 1).leading_zeros();
    /// The bytes of c̃: λ / 4.
    const CHALLENGE_SIZE: usize = Self::LAMBDA / 4;
    /// The bytes of a public key: 32 + 32 k (bitlen(q - 1) - d).
    const PUBLIC_KEY_SIZE: usize = 32 + 32 * Self::K * (23 - Self::D as usize);
    /// The bytes of a private key: 32 + 32 + 64 + 32 ((k + ℓ) bitlen(2η) + d k).
    const PRIVATE_KEY_SIZE: usize =
        128 + 32 * ((Self::K + Self::L) * Self::ETA_BITS as usize + Self::D as usize * Self::K);
    /// The bytes of a signature: λ / 4 + 32 ℓ (1 + bitlen(γ1 - 1)) + ω + k.
    const SIGNATURE_SIZE: usize =
        Self::CHALLENGE_SIZE + 32 * Self::L * Self::GAMMA1_BITS as usize + Self::OMEGA + Self::K;
}

/// Defines a parameter set of FIPS 204 table 1.
macro_rules! mldsa_parameters {
    ($(#[$documentation:meta])* $name:ident, $text:literal, $k:literal, $l:literal, $eta:literal, $tau:literal, $lambda:literal, $gamma1:expr, $gamma2:expr, $omega:literal) => {
        $(#[$documentation])*
        pub struct $name;

        impl MLDSAParameters for $name {
            const NAME: &'static str = $text;
            const K: usize = $k;
            const L: usize = $l;
            const ETA: u32 = $eta;
            const TAU: usize = $tau;
            const LAMBDA: usize = $lambda;
            const GAMMA1: u32 = $gamma1;
            const GAMMA2: u32 = $gamma2;
            const OMEGA: usize = $omega;
            type VectorK = [Polynomial<MLDSARing>; $k];
            type VectorL = [Polynomial<MLDSARing>; $l];
            type Matrix = [[Polynomial<MLDSARing>; $l]; $k];
        }
    };
}

mldsa_parameters!(
    /// ML-DSA-44, of security category 2: (k, ℓ) = (4, 4), η = 2, τ = 39, λ = 128, γ1 = 2^17, γ2 = (q - 1) / 88, ω = 80.
    MLDSA44, "ML-DSA-44", 4, 4, 2, 39, 128, 1 << 17, (8380417 - 1) / 88, 80
);
mldsa_parameters!(
    /// ML-DSA-65, of security category 3: (k, ℓ) = (6, 5), η = 4, τ = 49, λ = 192, γ1 = 2^19, γ2 = (q - 1) / 32, ω = 55.
    MLDSA65, "ML-DSA-65", 6, 5, 4, 49, 192, 1 << 19, (8380417 - 1) / 32, 55
);
mldsa_parameters!(
    /// ML-DSA-87, of security category 5: (k, ℓ) = (8, 7), η = 2, τ = 60, λ = 256, γ1 = 2^19, γ2 = (q - 1) / 32, ω = 75.
    MLDSA87, "ML-DSA-87", 8, 7, 2, 60, 256, 1 << 19, (8380417 - 1) / 32, 75
);
