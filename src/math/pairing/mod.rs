//! Pairings on curves of embedding degree 12.
//!
//! [`PairingCurve`] describes a pairing-friendly curve of the BN or BLS12
//! family: its group G_1 on E over GF(p) (a [`WeierstrassCurve`](crate::math::ec::WeierstrassCurve)),
//! its group G_2 on the sextic twist E' over GF(p^2) ([`G2Affine`],
//! [`G2Projective`]) and the tower [`Fp2`], [`Fp6`], [`Fp12`]. [`Pairing`]
//! computes the optimal ate pairing of draft-irtf-cfrg-pairing-friendly-curves
//! appendix A into [`GT`]. The curves are [`BLS12381`], [`BN462`] (the two
//! the draft recommends), [`BN254`] (of Ethereum) and [`SM9BN256`] (of SM9,
//! with its tower GF(p^2) = GF(p)\[u\]/(u^2 + 2)).
//!
//! Arithmetic in the fields and in the groups is constant time; the Miller
//! loop is not (see [`Pairing`]).

mod bls12_381;
mod bn254;
mod bn462;
mod curve;
mod fp12;
mod fp2;
mod fp6;
mod g2;
// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod pairing;
mod sm9_bn256;

pub use bls12_381::{BLS12381, BLS12381Field, BLS12381G1, BLS12381Scalar};
pub use bn254::{BN254, BN254Field, BN254G1, BN254Scalar};
pub use bn462::{BN462, BN462Field, BN462G1, BN462Scalar};
pub use curve::{PairingCurve, PairingFamily, TwistType};
pub use fp2::{Fp2, PairingField};
pub use fp6::Fp6;
pub use fp12::Fp12;
pub use g2::{G2Affine, G2Projective};
pub use pairing::{GT, Pairing};
pub use sm9_bn256::{SM9BN256, SM9BN256Field, SM9BN256G1, SM9BN256Scalar};
