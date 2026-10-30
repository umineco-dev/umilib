//! Arithmetic for cryptography: big integers, modular arithmetic, elliptic
//! curves, pairings and polynomial rings of lattices.

#[cfg(umilib_feature = "math-bigint")]
pub mod bigint;
#[cfg(umilib_feature = "math-ec")]
pub mod ec;
#[cfg(umilib_feature = "math-lattice")]
pub mod lattice;
#[cfg(umilib_feature = "math-modular")]
pub mod modular;
#[cfg(umilib_feature = "math-pairing")]
pub mod pairing;
