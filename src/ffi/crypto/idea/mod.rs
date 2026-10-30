//! The C ABI of [`crate::crypto::idea`].

use crate::ffi::Module;

/// [`IDEA`](crate::crypto::idea::IDEA).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod idea {
    crate::ffi_block_cipher!(
        crate::crypto::idea::IDEA,
        "umilib_crypto_idea_idea",
        "umilib_crypto_idea_IDEA",
        "IDEA: a 128-bit key, 64-bit blocks and 8.5 rounds."
    );
}

/// The manifest node of this module.
pub const MODULE: Module =
    Module { name: "idea", definitions: &[idea::DEFINITION], functions: idea::FUNCTIONS, modules: &[] };
