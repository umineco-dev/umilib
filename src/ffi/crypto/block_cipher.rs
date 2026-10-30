use core::fmt;

use crate::crypto::{BlockCipher, CryptoError};
use crate::ffi::{Status, ToStatus};
use crate::secret::Zeroize;

/// The block ciphers of the C ABI, by block size, for the generic types
/// (modes, CMAC): `$callback! { [16] entries... [8] entries... }` with one
/// entry `"feature" Variant => path, "C type name";` per cipher, in the
/// same form as [`ffi_digest_algorithms!`](crate::ffi_digest_algorithms).
#[macro_export]
macro_rules! ffi_block_ciphers {
    ($callback:ident) => {
        $callback! {
            [16]
            "crypto-aes" AES128 => $crate::crypto::aes::AES128, "umilib_crypto_aes_AES128";
            "crypto-aes" AES192 => $crate::crypto::aes::AES192, "umilib_crypto_aes_AES192";
            "crypto-aes" AES256 => $crate::crypto::aes::AES256, "umilib_crypto_aes_AES256";
            "crypto-aria" ARIA128 => $crate::crypto::aria::ARIA128, "umilib_crypto_aria_ARIA128";
            "crypto-aria" ARIA192 => $crate::crypto::aria::ARIA192, "umilib_crypto_aria_ARIA192";
            "crypto-aria" ARIA256 => $crate::crypto::aria::ARIA256, "umilib_crypto_aria_ARIA256";
            "crypto-camellia" Camellia128 => $crate::crypto::camellia::Camellia128, "umilib_crypto_camellia_Camellia128";
            "crypto-camellia" Camellia192 => $crate::crypto::camellia::Camellia192, "umilib_crypto_camellia_Camellia192";
            "crypto-camellia" Camellia256 => $crate::crypto::camellia::Camellia256, "umilib_crypto_camellia_Camellia256";
            "crypto-gost-kuznyechik" Kuznyechik => $crate::crypto::gost::kuznyechik::Kuznyechik, "umilib_crypto_gost_kuznyechik_Kuznyechik";
            "crypto-seed" SEED => $crate::crypto::seed::SEED, "umilib_crypto_seed_SEED";
            "crypto-sm4" SM4 => $crate::crypto::sm4::SM4, "umilib_crypto_sm4_SM4";
            [8]
            "crypto-des" DES => $crate::crypto::des::DES, "umilib_crypto_des_DES";
            "crypto-des" TDES => $crate::crypto::des::TDES, "umilib_crypto_des_TDES";
            "crypto-gost-magma" Magma => $crate::crypto::gost::magma::Magma, "umilib_crypto_gost_magma_Magma";
            "crypto-idea" IDEA => $crate::crypto::idea::IDEA, "umilib_crypto_idea_IDEA";
            "crypto-rc2" RC2 => $crate::crypto::rc2::RC2, "umilib_crypto_rc2_RC2";
        }
    };
}

/// Defines an enum of the block ciphers of one block size of the registry.
macro_rules! block_cipher_enum {
    ($(#[$documentation:meta])* $name:ident, $size:literal; $($feature:literal $variant:ident => $type:path, $c_name:literal;)*) => {
        $(#[$documentation])*
        #[derive(Clone)]
        // The enum is held by value in the modes: boxing the variants would add an allocation.
        #[allow(clippy::large_enum_variant)]
        pub enum $name {
            $(
                #[cfg(umilib_feature = $feature)]
                $variant($type),
            )*
        }

        impl $name {
            /// The cipher whose C type is named `cipher`, with `key`; fails
            /// with InvalidArgument if the cipher is unknown or not enabled.
            pub fn new(cipher: &str, key: &[u8]) -> Result<$name, &'static Status> {
                match cipher {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $c_name => <$type as crate::crypto::KeyInit>::new_from_slice(key).map($name::$variant).map_err(|error| error.to_status()),
                    )*
                    _ => {
                        let _ = key;
                        Err(&Status::INVALID_ARGUMENT)
                    }
                }
            }

            /// The C type names of the enabled ciphers.
            pub const NAMES: &[&str] = &[$(
                #[cfg(umilib_feature = $feature)]
                $c_name,
            )*];
        }

        // The enum is empty when no algorithm of the registry is enabled, leaving the arguments unused.
        #[allow(unused_variables)]
        impl BlockCipher for $name {
            const BLOCK_SIZE: usize = $size;
            type Block = [u8; $size];

            fn encrypt_block(&self, block: &mut [u8; $size]) {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name::$variant(ref cipher) => cipher.encrypt_block(block),
                    )*
                }
            }

            fn decrypt_block(&self, block: &mut [u8; $size]) {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name::$variant(ref cipher) => cipher.decrypt_block(block),
                    )*
                }
            }

            fn encrypt_blocks(&self, blocks: &mut [[u8; $size]]) {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name::$variant(ref cipher) => cipher.encrypt_blocks(blocks),
                    )*
                }
            }

            fn decrypt_blocks(&self, blocks: &mut [[u8; $size]]) {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name::$variant(ref cipher) => cipher.decrypt_blocks(blocks),
                    )*
                }
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name::$variant(ref mut cipher) => cipher.zeroize(),
                    )*
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

/// Defines [`BlockCipher128`] and [`BlockCipher64`] from the registry.
macro_rules! block_cipher_enums {
    ([16] $($feature16:literal $variant16:ident => $type16:path, $name16:literal;)* [8] $($feature8:literal $variant8:ident => $type8:path, $name8:literal;)*) => {
        block_cipher_enum!(
            /// A block cipher with 128-bit blocks of the registry, chosen by
            /// the C type name of its type when it is created: the cipher of
            /// the generic types of the C ABI (modes, CMAC).
            BlockCipher128, 16; $($feature16 $variant16 => $type16, $name16;)*
        );
        block_cipher_enum!(
            /// A block cipher with 64-bit blocks of the registry, as [`BlockCipher128`].
            BlockCipher64, 8; $($feature8 $variant8 => $type8, $name8;)*
        );
    };
}

crate::ffi_block_ciphers!(block_cipher_enums);

/// A block cipher of the registry of either block size, chosen by the C type
/// name of its type: the cipher of the modes that take both.
#[derive(Clone, Debug)]
// The cipher is moved once, into the handle of a mode: boxing it would add an allocation.
#[allow(clippy::large_enum_variant)]
pub enum BlockCipherChoice {
    Block128(BlockCipher128),
    Block64(BlockCipher64),
}

impl BlockCipherChoice {
    /// The cipher whose C type is named `cipher`, with `key`; fails with
    /// InvalidArgument if the cipher is unknown or not enabled.
    pub fn new(cipher: &str, key: &[u8]) -> Result<BlockCipherChoice, &'static Status> {
        if BlockCipher128::NAMES.contains(&cipher) {
            return BlockCipher128::new(cipher, key).map(BlockCipherChoice::Block128);
        }
        if BlockCipher64::NAMES.contains(&cipher) {
            return BlockCipher64::new(cipher, key).map(BlockCipherChoice::Block64);
        }
        Err(&Status::INVALID_ARGUMENT)
    }
}

/// The check of the block arguments of the exported block cipher functions.
pub struct BlockData;

impl BlockData {
    /// Fails with InputLength unless `data` is a whole number of blocks of `size` bytes.
    pub fn check(data: &[u8], size: usize) -> Result<(), &'static Status> {
        if !data.len().is_multiple_of(size) {
            return Err(CryptoError::InputLength { length: data.len() }.to_status());
        }
        Ok(())
    }
}

/// Exports a block cipher type (implementing [`BlockCipher`] and [`KeyInit`](crate::crypto::KeyInit))
/// under `$prefix`: `_new`, `_free`, `_clone`, `_encrypt_blocks` and
/// `_decrypt_blocks` (in place, whole blocks, one block included),
/// `_block_size`, `_minimum_key_size` and `_maximum_key_size`.
#[macro_export]
macro_rules! ffi_block_cipher {
    ($type:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        impl $crate::ffi::Value for $type {
            const TYPE: $crate::ffi::Type = $crate::ffi::Type::Named($c_type);
        }

        /// The C type of this module.
        pub const DEFINITION: $crate::ffi::Definition =
            $crate::ffi::Definition::Opaque { name: $c_type, documentation: concat!(" ", $documentation) };

        $crate::ffi_exports! {
            const KEYED;
            /// Creates the cipher with the `key_length` bytes at `key`.
            pub unsafe extern "C" fn new = concat!($prefix, "_new"); (key: *const u8, key_length: usize, out: *mut *mut $type) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes readable bytes and a writable pointer.
                    let key = unsafe { $crate::ffi::Pointer::slice(key, key_length) }?;
                    let cipher = <$type as $crate::crypto::KeyInit>::new_from_slice(key).map_err(|error| $crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { $crate::ffi::Pointer::write_handle(out, cipher) }
                })())
            }
        }

        $crate::ffi_block_cipher!(@common $type, $prefix, COMMON);

        /// The functions exported by this module, in declaration order.
        pub const FUNCTIONS: &[$crate::ffi::Function] =
            &$crate::ffi::Function::concat::<{ KEYED.len() + COMMON.len() }>(&[KEYED, COMMON]);
    };
    (@common $type:ty, $prefix:literal, $constant:ident) => {
        $crate::ffi_exports! {
            const $constant;
            /// Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
            pub unsafe extern "C" fn free = concat!($prefix, "_free"); (cipher: *mut $type) {
                // SAFETY: the caller passes null or a handle created by this module.
                unsafe { $crate::ffi::Pointer::free(cipher) }
            }

            /// Writes a copy of `cipher` into `out`.
            pub unsafe extern "C" fn clone = concat!($prefix, "_clone"); (cipher: *const $type, out: *mut *mut $type) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let cipher = unsafe { $crate::ffi::Pointer::reference(cipher) }?;
                    unsafe { $crate::ffi::Pointer::write_handle(out, cipher.clone()) }
                })())
            }

            /// Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
            pub unsafe extern "C" fn encrypt_blocks = concat!($prefix, "_encrypt_blocks"); (cipher: *const $type, data: *mut u8, length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable byte range.
                    let cipher = unsafe { $crate::ffi::Pointer::reference(cipher) }?;
                    let data = unsafe { $crate::ffi::Pointer::slice_mut(data, length) }?;
                    $crate::ffi::crypto::BlockData::check(data, <$type as $crate::crypto::BlockCipher>::BLOCK_SIZE)?;
                    let blocks = data.as_chunks_mut::<{ <$type as $crate::crypto::BlockCipher>::BLOCK_SIZE }>().0;
                    $crate::crypto::BlockCipher::encrypt_blocks(cipher, blocks);
                    Ok(())
                })())
            }

            /// Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
            pub unsafe extern "C" fn decrypt_blocks = concat!($prefix, "_decrypt_blocks"); (cipher: *const $type, data: *mut u8, length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable byte range.
                    let cipher = unsafe { $crate::ffi::Pointer::reference(cipher) }?;
                    let data = unsafe { $crate::ffi::Pointer::slice_mut(data, length) }?;
                    $crate::ffi::crypto::BlockData::check(data, <$type as $crate::crypto::BlockCipher>::BLOCK_SIZE)?;
                    let blocks = data.as_chunks_mut::<{ <$type as $crate::crypto::BlockCipher>::BLOCK_SIZE }>().0;
                    $crate::crypto::BlockCipher::decrypt_blocks(cipher, blocks);
                    Ok(())
                })())
            }

            /// The number of bytes of a block.
            pub unsafe extern "C" fn block_size = concat!($prefix, "_block_size"); () -> usize {
                <$type as $crate::crypto::BlockCipher>::BLOCK_SIZE
            }

            /// The shortest key in bytes.
            pub unsafe extern "C" fn minimum_key_size = concat!($prefix, "_minimum_key_size"); () -> usize {
                <$type as $crate::crypto::KeyInit>::MINIMUM_KEY_SIZE
            }

            /// The longest key in bytes.
            pub unsafe extern "C" fn maximum_key_size = concat!($prefix, "_maximum_key_size"); () -> usize {
                <$type as $crate::crypto::KeyInit>::MAXIMUM_KEY_SIZE
            }
        }
    };
}
