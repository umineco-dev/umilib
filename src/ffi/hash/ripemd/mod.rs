//! The C ABI of [`crate::hash::ripemd`].

use crate::ffi::Module;

/// [`RIPEMD128`](crate::hash::ripemd::RIPEMD128).
pub mod ripemd128 {
    crate::ffi_digest!(default crate::hash::ripemd::RIPEMD128, "umilib_hash_ripemd_ripemd128", "umilib_hash_ripemd_RIPEMD128", "RIPEMD-128.");
}

/// [`RIPEMD160`](crate::hash::ripemd::RIPEMD160).
pub mod ripemd160 {
    crate::ffi_digest!(default crate::hash::ripemd::RIPEMD160, "umilib_hash_ripemd_ripemd160", "umilib_hash_ripemd_RIPEMD160", "RIPEMD-160.");
}

/// [`RIPEMD256`](crate::hash::ripemd::RIPEMD256).
pub mod ripemd256 {
    crate::ffi_digest!(default crate::hash::ripemd::RIPEMD256, "umilib_hash_ripemd_ripemd256", "umilib_hash_ripemd_RIPEMD256", "RIPEMD-256.");
}

/// [`RIPEMD320`](crate::hash::ripemd::RIPEMD320).
pub mod ripemd320 {
    crate::ffi_digest!(default crate::hash::ripemd::RIPEMD320, "umilib_hash_ripemd_ripemd320", "umilib_hash_ripemd_RIPEMD320", "RIPEMD-320.");
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ripemd",
    definitions: &[ripemd128::DEFINITION, ripemd160::DEFINITION, ripemd256::DEFINITION, ripemd320::DEFINITION],
    functions: &crate::ffi::Function::concat::<
        {
            ripemd128::FUNCTIONS.len()
                + ripemd160::FUNCTIONS.len()
                + ripemd256::FUNCTIONS.len()
                + ripemd320::FUNCTIONS.len()
        },
    >(&[ripemd128::FUNCTIONS, ripemd160::FUNCTIONS, ripemd256::FUNCTIONS, ripemd320::FUNCTIONS]),
    modules: &[],
};
