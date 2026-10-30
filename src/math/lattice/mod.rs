//! Polynomial rings of module lattices: R_q = Z_q\[X\]/(X^n + 1) with its
//! number-theoretic transform, the arithmetic of ML-KEM (FIPS 203) and
//! ML-DSA (FIPS 204).
//!
//! [`LatticeRing`] describes a ring by its constants (q, n, the root ζ and
//! the number of layers of the NTT), from which [`LatticeTables`] computes
//! the tables at compile time; [`Polynomial`] computes in it in constant
//! time, and [`LatticePacking`] writes integers as the bit strings of the
//! standards. The rings are [`MLKEMRing`] and [`MLDSARing`].

mod coefficient;
mod error;
mod mldsa_ring;
mod mlkem_ring;
mod packing;
mod polynomial;
mod ring;
mod vector;

pub use coefficient::{CoefficientArray, LatticeCoefficient};
pub use error::LatticeError;
pub use mldsa_ring::MLDSARing;
pub use mlkem_ring::MLKEMRing;
pub use packing::LatticePacking;
pub use polynomial::Polynomial;
pub use ring::{LatticeRing, LatticeTables};
pub use vector::{PolynomialMatrix, PolynomialVector};
