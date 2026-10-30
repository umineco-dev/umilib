use crate::math::lattice::{MLKEMRing, Polynomial, PolynomialMatrix, PolynomialVector};

/// A parameter set of ML-KEM (FIPS 203 table 2): the rank k of the module,
/// the parameters η1 and η2 of the centered binomial distributions and the
/// bits d_u and d_v of the compressed ciphertext. A parameter set is a type
/// of no value, given to [`MLKEM`](super::MLKEM).
pub trait MLKEMParameters: 'static {
    /// The name of the parameter set, such as `ML-KEM-768`.
    const NAME: &'static str;
    const K: usize;
    const ETA1: usize;
    const ETA2: usize;
    const DU: u32;
    const DV: u32;
    /// `[Polynomial<MLKEMRing>; K]`.
    type Vector: PolynomialVector<MLKEMRing>;
    /// `[Self::Vector; K]`.
    type Matrix: PolynomialMatrix<MLKEMRing, Row = Self::Vector>;

    /// The bytes of an encapsulation key: 384 k + 32 (FIPS 203 table 3).
    const ENCAPSULATION_KEY_SIZE: usize = 384 * Self::K + 32;
    /// The bytes of a decapsulation key: 768 k + 96.
    const DECAPSULATION_KEY_SIZE: usize = 768 * Self::K + 96;
    /// The bytes of a ciphertext: 32 (d_u k + d_v).
    const CIPHERTEXT_SIZE: usize = 32 * (Self::DU as usize * Self::K + Self::DV as usize);
}

/// Defines a parameter set of FIPS 203 table 2.
macro_rules! mlkem_parameters {
    ($(#[$documentation:meta])* $name:ident, $text:literal, $k:literal, $eta1:literal, $eta2:literal, $du:literal, $dv:literal) => {
        $(#[$documentation])*
        pub struct $name;

        impl MLKEMParameters for $name {
            const NAME: &'static str = $text;
            const K: usize = $k;
            const ETA1: usize = $eta1;
            const ETA2: usize = $eta2;
            const DU: u32 = $du;
            const DV: u32 = $dv;
            type Vector = [Polynomial<MLKEMRing>; $k];
            type Matrix = [[Polynomial<MLKEMRing>; $k]; $k];
        }
    };
}

mlkem_parameters!(
    /// ML-KEM-512, of security category 1: k = 2, η1 = 3, η2 = 2, d_u = 10, d_v = 4.
    MLKEM512, "ML-KEM-512", 2, 3, 2, 10, 4
);
mlkem_parameters!(
    /// ML-KEM-768, of security category 3: k = 3, η1 = 2, η2 = 2, d_u = 10, d_v = 4.
    MLKEM768, "ML-KEM-768", 3, 2, 2, 10, 4
);
mlkem_parameters!(
    /// ML-KEM-1024, of security category 5: k = 4, η1 = 2, η2 = 2, d_u = 11, d_v = 5.
    MLKEM1024, "ML-KEM-1024", 4, 2, 2, 11, 5
);
