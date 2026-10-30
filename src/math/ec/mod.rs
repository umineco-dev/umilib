//! Elliptic curves over prime fields, in constant time.
//!
//! [`PrimeField`] describes a prime field by its modulus (from
//! [`math-modular`](crate::math::modular)) and [`FieldElement`] computes in
//! it. A curve is a type implementing [`WeierstrassCurve`],
//! [`MontgomeryCurve`] or [`EdwardsCurve`], with its fields and constants;
//! the points of a curve `C` are `AffinePoint<C>` and `ProjectivePoint<C>`
//! (Weierstrass), `MontgomeryPoint<C>` or `EdwardsPoint<C>`, and its scalars
//! are `FieldElement<C::Scalar>`. The curves themselves are defined in
//! `crypto::curve`. Unless a function name ends in `_vartime`, its time
//! depends only on the curve and on public arguments.

mod edwards;
mod error;
mod field;
mod montgomery;
mod weierstrass;
mod window;

pub use edwards::{EdwardsCurve, EdwardsPoint};
pub use error::ECError;
pub use field::{FieldElement, FieldResidue, FieldValue, PrimeField};
pub use montgomery::{MontgomeryCurve, MontgomeryPoint};
pub use weierstrass::{AffinePoint, CoefficientA, ProjectivePoint, WeierstrassCurve};
pub use window::Window;
