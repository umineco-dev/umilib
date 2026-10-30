//! The C ABI of [`crate::crypto::curve::brainpool`].
//!
//! Each curve exports its points and scalars.

#[cfg(umilib_feature = "crypto-curve-brainpool-p256r1")]
pub mod p256r1;
#[cfg(umilib_feature = "crypto-curve-brainpool-p384r1")]
pub mod p384r1;
#[cfg(umilib_feature = "crypto-curve-brainpool-p512r1")]
pub mod p512r1;

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "brainpool",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "crypto-curve-brainpool-p256r1")]
        p256r1::MODULE,
        #[cfg(umilib_feature = "crypto-curve-brainpool-p384r1")]
        p384r1::MODULE,
        #[cfg(umilib_feature = "crypto-curve-brainpool-p512r1")]
        p512r1::MODULE,
    ],
};
