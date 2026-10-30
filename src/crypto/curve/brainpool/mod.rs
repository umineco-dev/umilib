//! The Brainpool curves of RFC 5639 whose coefficient A makes them the
//! "random" (r1) curves: brainpoolP256r1, brainpoolP384r1, brainpoolP512r1.

#[cfg(umilib_feature = "crypto-curve-brainpool-p256r1")]
pub mod p256r1;
#[cfg(umilib_feature = "crypto-curve-brainpool-p384r1")]
pub mod p384r1;
#[cfg(umilib_feature = "crypto-curve-brainpool-p512r1")]
pub mod p512r1;
