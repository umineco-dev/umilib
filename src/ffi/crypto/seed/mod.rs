//! The C ABI of [`crate::crypto::seed`].

use crate::ffi::Module;

/// [`SEED`](crate::crypto::seed::SEED).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod seed {
    crate::ffi_block_cipher!(
        crate::crypto::seed::SEED,
        "umilib_crypto_seed_seed",
        "umilib_crypto_seed_SEED",
        "SEED (RFC 4269): a 128-bit key and 16 rounds."
    );
}

/// The manifest node of this module.
pub const MODULE: Module =
    Module { name: "seed", definitions: &[seed::DEFINITION], functions: seed::FUNCTIONS, modules: &[] };
