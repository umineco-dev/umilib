//! The C ABI of [`crate::hash::sha::v2`].

use crate::ffi::Module;

/// [`SHA224`](crate::hash::sha::v2::SHA224).
pub mod sha224 {
    crate::ffi_digest!(default crate::hash::sha::v2::SHA224, "umilib_hash_sha_v2_sha224", "umilib_hash_sha_v2_SHA224", "SHA-224 (FIPS 180-4).");
}

/// [`SHA256`](crate::hash::sha::v2::SHA256).
pub mod sha256 {
    crate::ffi_digest!(default crate::hash::sha::v2::SHA256, "umilib_hash_sha_v2_sha256", "umilib_hash_sha_v2_SHA256", "SHA-256 (FIPS 180-4).");
}

/// [`SHA384`](crate::hash::sha::v2::SHA384).
pub mod sha384 {
    crate::ffi_digest!(default crate::hash::sha::v2::SHA384, "umilib_hash_sha_v2_sha384", "umilib_hash_sha_v2_SHA384", "SHA-384 (FIPS 180-4).");
}

/// [`SHA512`](crate::hash::sha::v2::SHA512).
pub mod sha512 {
    crate::ffi_digest!(default crate::hash::sha::v2::SHA512, "umilib_hash_sha_v2_sha512", "umilib_hash_sha_v2_SHA512", "SHA-512 (FIPS 180-4).");
}

/// [`SHA512_224`](crate::hash::sha::v2::SHA512_224).
pub mod sha512_224 {
    crate::ffi_digest!(default crate::hash::sha::v2::SHA512_224, "umilib_hash_sha_v2_sha512_224", "umilib_hash_sha_v2_SHA512_224", "SHA-512/224 (FIPS 180-4).");
}

/// [`SHA512_256`](crate::hash::sha::v2::SHA512_256).
pub mod sha512_256 {
    crate::ffi_digest!(default crate::hash::sha::v2::SHA512_256, "umilib_hash_sha_v2_sha512_256", "umilib_hash_sha_v2_SHA512_256", "SHA-512/256 (FIPS 180-4).");
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v2",
    definitions: &[
        sha224::DEFINITION,
        sha256::DEFINITION,
        sha384::DEFINITION,
        sha512::DEFINITION,
        sha512_224::DEFINITION,
        sha512_256::DEFINITION,
    ],
    functions: &crate::ffi::Function::concat::<
        {
            sha224::FUNCTIONS.len()
                + sha256::FUNCTIONS.len()
                + sha384::FUNCTIONS.len()
                + sha512::FUNCTIONS.len()
                + sha512_224::FUNCTIONS.len()
                + sha512_256::FUNCTIONS.len()
        },
    >(&[
        sha224::FUNCTIONS,
        sha256::FUNCTIONS,
        sha384::FUNCTIONS,
        sha512::FUNCTIONS,
        sha512_224::FUNCTIONS,
        sha512_256::FUNCTIONS,
    ]),
    modules: &[],
};
