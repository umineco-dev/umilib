//! ML-KEM, the module-lattice-based key-encapsulation mechanism of FIPS 203,
//! with the parameter sets [`MLKEM512`], [`MLKEM768`] and [`MLKEM1024`]:
//! `MLKEM<MLKEM768>` implements [`KeyEncapsulation`](crate::crypto::KeyEncapsulation).
//!
//! An encapsulation key ([`MLKEMEncapsulationKey`]) is read only if it passes
//! the checks of section 7.2, a decapsulation key
//! ([`MLKEMDecapsulationKey`]) only if it passes those of section 7.3; a
//! decapsulation key can also be kept as the seed d || z of 64 bytes it is
//! generated from (`decapsulation_key_from_seed`, `write_seed`).
//! Decapsulation rejects implicitly: a ciphertext that was not made for the
//! key gives a pseudorandom secret, chosen in constant time. The arithmetic
//! is that of [`MLKEMRing`](crate::math::lattice::MLKEMRing).

mod functions;
mod keys;
// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod mlkem;
mod parameters;

pub use functions::MLKEMFunctions;
pub use keys::{MLKEMDecapsulationKey, MLKEMEncapsulationKey};
pub use mlkem::MLKEM;
pub use parameters::{MLKEM512, MLKEM768, MLKEM1024, MLKEMParameters};
