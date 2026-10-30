//! The C ABI of [`crate::math`].

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

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "math",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "math-bigint")]
        bigint::MODULE,
        #[cfg(umilib_feature = "math-ec")]
        ec::MODULE,
        #[cfg(umilib_feature = "math-lattice")]
        lattice::MODULE,
        #[cfg(umilib_feature = "math-modular")]
        modular::MODULE,
        #[cfg(umilib_feature = "math-pairing")]
        pairing::MODULE,
    ],
};
