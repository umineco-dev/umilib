//! The C ABI of [`crate::crypto::aes`].

use crate::crypto::aes::AESBitslice;
use crate::ffi::{Module, Pointer, Status};

/// [`AES128`](crate::crypto::aes::AES128).
pub mod aes128 {
    crate::ffi_block_cipher!(
        crate::crypto::aes::AES128,
        "umilib_crypto_aes_aes128",
        "umilib_crypto_aes_AES128",
        "AES-128 (FIPS 197): a 128-bit key and 10 rounds, bitsliced."
    );
}

/// [`AES192`](crate::crypto::aes::AES192).
pub mod aes192 {
    crate::ffi_block_cipher!(
        crate::crypto::aes::AES192,
        "umilib_crypto_aes_aes192",
        "umilib_crypto_aes_AES192",
        "AES-192 (FIPS 197): a 192-bit key and 12 rounds, bitsliced."
    );
}

/// [`AES256`](crate::crypto::aes::AES256).
pub mod aes256 {
    crate::ffi_block_cipher!(
        crate::crypto::aes::AES256,
        "umilib_crypto_aes_aes256",
        "umilib_crypto_aes_AES256",
        "AES-256 (FIPS 197): a 256-bit key and 14 rounds, bitsliced."
    );
}

crate::ffi_functions! {
    const ROUND;
    /// Applies one round of the AES cipher (SubBytes, ShiftRows, MixColumns, AddRoundKey) to each
    /// 16-byte block of the `length` bytes at `blocks` in place, with the key of the same position in
    /// the `length` bytes at `keys`, which must not overlap `blocks`: AESRound of AEGIS.
    pub unsafe extern "C" fn umilib_crypto_aes_aes_bitslice_round(blocks: *mut u8, keys: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(blocks, length, keys, length)?;
            // SAFETY: the caller passes a writable and a readable byte range of `length` bytes.
            let blocks = unsafe { Pointer::slice_mut(blocks, length) }?;
            let keys = unsafe { Pointer::slice(keys, length) }?;
            crate::ffi::crypto::BlockData::check(blocks, 16)?;
            AESBitslice::round(blocks.as_chunks_mut::<16>().0, keys.as_chunks::<16>().0);
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "aes",
    definitions: &[aes128::DEFINITION, aes192::DEFINITION, aes256::DEFINITION],
    functions: &crate::ffi::Function::concat::<
        { aes128::FUNCTIONS.len() + aes192::FUNCTIONS.len() + aes256::FUNCTIONS.len() + ROUND.len() },
    >(&[aes128::FUNCTIONS, aes192::FUNCTIONS, aes256::FUNCTIONS, ROUND]),
    modules: &[],
};
