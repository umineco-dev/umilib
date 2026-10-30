//! The C ABI of [`crate::crypto::aegis`].
//!
//! Each family is exported as one type whose degree of parallelism D (1, 2
//! or 4) and tag size (16 or 32 bytes) are chosen when it is created.

use crate::crypto::CryptoError;
use crate::crypto::aegis::{AEGIS128X, AEGIS128XState, AEGIS256X, AEGIS256XState, AEGISMAC128X, AEGISMAC256X};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};

/// Exports the AEAD, the MAC and the key stream of one family of AEGIS.
macro_rules! aegis_family {
    (
        $module:ident, $mac_module:ident, $aead_enum:ident, $aead:ident, $mac_enum:ident, $mac:ident, $state:ident, $size:literal,
        $aead_prefix:literal, $aead_c_type:literal, $mac_prefix:literal, $mac_c_type:literal, $title:literal
    ) => {
        crate::ffi_aead_enum! {
            #[doc = concat!(" [`", stringify!($aead), "`] with each degree and tag size.")]
            $aead_enum {
                Degree1Tag16($aead<1, 16>),
                Degree1Tag32($aead<1, 32>),
                Degree2Tag16($aead<2, 16>),
                Degree2Tag32($aead<2, 32>),
                Degree4Tag16($aead<4, 16>),
                Degree4Tag32($aead<4, 32>),
            }
        }

        impl $aead_enum {
            /// The AEAD of degree `degree` with tags of `tag_size` bytes and `key`; fails with
            /// InvalidParameter for another degree and with TagLength for another tag size.
            pub fn new(degree: usize, tag_size: usize, key: &[u8; $size]) -> Result<$aead_enum, CryptoError> {
                Ok(match (degree, tag_size) {
                    (1, 16) => $aead_enum::Degree1Tag16($aead::new(key)),
                    (1, 32) => $aead_enum::Degree1Tag32($aead::new(key)),
                    (2, 16) => $aead_enum::Degree2Tag16($aead::new(key)),
                    (2, 32) => $aead_enum::Degree2Tag32($aead::new(key)),
                    (4, 16) => $aead_enum::Degree4Tag16($aead::new(key)),
                    (4, 32) => $aead_enum::Degree4Tag32($aead::new(key)),
                    (1 | 2 | 4, _) => return Err(CryptoError::TagLength { length: tag_size, minimum: 16, maximum: 32 }),
                    _ => return Err(CryptoError::InvalidParameter),
                })
            }
        }

        impl Value for $aead_enum {
            const TYPE: Type = Type::Named($aead_c_type);
        }

        crate::ffi_mac_enum! {
            #[doc = concat!(" [`", stringify!($mac), "`] with each degree and tag size.")]
            $mac_enum {
                Degree1Tag16($mac<1, 16>),
                Degree1Tag32($mac<1, 32>),
                Degree2Tag16($mac<2, 16>),
                Degree2Tag32($mac<2, 32>),
                Degree4Tag16($mac<4, 16>),
                Degree4Tag32($mac<4, 32>),
            }
        }

        impl $mac_enum {
            /// The MAC of degree `degree` with tags of `tag_size` bytes, `key` and `nonce`; fails
            /// with InvalidParameter for another degree and with TagLength for another tag size.
            pub fn new(degree: usize, tag_size: usize, key: &[u8; $size], nonce: &[u8; $size]) -> Result<$mac_enum, CryptoError> {
                Ok(match (degree, tag_size) {
                    (1, 16) => $mac_enum::Degree1Tag16($mac::new(key, nonce)),
                    (1, 32) => $mac_enum::Degree1Tag32($mac::new(key, nonce)),
                    (2, 16) => $mac_enum::Degree2Tag16($mac::new(key, nonce)),
                    (2, 32) => $mac_enum::Degree2Tag32($mac::new(key, nonce)),
                    (4, 16) => $mac_enum::Degree4Tag16($mac::new(key, nonce)),
                    (4, 32) => $mac_enum::Degree4Tag32($mac::new(key, nonce)),
                    (1 | 2 | 4, _) => return Err(CryptoError::TagLength { length: tag_size, minimum: 16, maximum: 32 }),
                    _ => return Err(CryptoError::InvalidParameter),
                })
            }
        }

        impl Value for $mac_enum {
            const TYPE: Type = Type::Named($mac_c_type);
        }

        #[doc = concat!(" The functions of ", $title, ".")]
        pub mod $module {
            use super::{$aead_enum, $state, CryptoError, Pointer, Status, ToStatus};
            use crate::ffi::crypto::CryptoInput;

            crate::ffi_exports! {
                const AEAD_CONSTRUCTORS;
                #[doc = concat!(" Creates ", $title, " of degree `degree` (1, 2 or 4) with tags of `tag_size` bytes (16 or 32)")]
                #[doc = concat!(" and the ", $size, "-byte key at `key`; nonces have ", $size, " bytes.")]
                pub unsafe extern "C" fn new = concat!($aead_prefix, "_new"); (degree: usize, tag_size: usize, key: *const u8, key_length: usize, out: *mut *mut $aead_enum) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes readable bytes and a writable pointer.
                        let key = CryptoInput::key::<$size>(unsafe { Pointer::slice(key, key_length) }?)?;
                        let aead = $aead_enum::new(degree, tag_size, key).map_err(|error| error.to_status())?;
                        unsafe { Pointer::write_handle(out, aead) }
                    })())
                }

                #[doc = concat!(" Writes the key stream of degree `degree` (1, 2 or 4) for the ", $size, "-byte key at `key` and")]
                #[doc = concat!(" the ", $size, "-byte nonce at `nonce` into the `length` bytes at `out` (Stream, section 7), which")]
                #[doc = " must not overlap them."]
                pub unsafe extern "C" fn stream = concat!($aead_prefix, "_stream"); (degree: usize, key: *const u8, key_length: usize, nonce: *const u8, nonce_length: usize, out: *mut u8, length: usize) -> *const Status {
                    Status::from_result((|| {
                        Pointer::check_disjoint(key, key_length, out, length)?;
                        Pointer::check_disjoint(nonce, nonce_length, out, length)?;
                        // SAFETY: the caller passes readable bytes and a writable byte range.
                        let key = CryptoInput::key::<$size>(unsafe { Pointer::slice(key, key_length) }?)?;
                        let nonce = CryptoInput::nonce::<$size>(unsafe { Pointer::slice(nonce, nonce_length) }?)?;
                        let out = unsafe { Pointer::slice_mut(out, length) }?;
                        match degree {
                            1 => $state::<1>::stream(key, nonce, out),
                            2 => $state::<2>::stream(key, nonce, out),
                            4 => $state::<4>::stream(key, nonce, out),
                            _ => return Err(CryptoError::InvalidParameter.to_status()),
                        }
                        Ok(())
                    })())
                }
            }

            crate::ffi_aead!($aead_enum, $aead_prefix, AEAD_COMMON);

            /// The functions of the AEAD, in declaration order.
            pub const FUNCTIONS: &[crate::ffi::Function] =
                &crate::ffi::Function::concat::<{ AEAD_CONSTRUCTORS.len() + AEAD_COMMON.len() }>(&[AEAD_CONSTRUCTORS, AEAD_COMMON]);
        }

        #[doc = concat!(" The functions of the MAC of ", $title, ".")]
        pub mod $mac_module {
            use super::{$mac_enum, Pointer, Status, ToStatus};
            use crate::ffi::crypto::CryptoInput;

            crate::ffi_exports! {
                const MAC_CONSTRUCTORS;
                #[doc = concat!(" Creates the MAC of ", $title, " of degree `degree` (1, 2 or 4) with tags of `tag_size` bytes")]
                #[doc = concat!(" (16 or 32), the ", $size, "-byte key at `key` and the ", $size, "-byte nonce at `nonce`.")]
                pub unsafe extern "C" fn new = concat!($mac_prefix, "_new"); (degree: usize, tag_size: usize, key: *const u8, key_length: usize, nonce: *const u8, nonce_length: usize, out: *mut *mut $mac_enum) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes readable bytes and a writable pointer.
                        let key = CryptoInput::key::<$size>(unsafe { Pointer::slice(key, key_length) }?)?;
                        let nonce = CryptoInput::nonce::<$size>(unsafe { Pointer::slice(nonce, nonce_length) }?)?;
                        let mac = $mac_enum::new(degree, tag_size, key, nonce).map_err(|error| error.to_status())?;
                        unsafe { Pointer::write_handle(out, mac) }
                    })())
                }
            }

            crate::ffi_mac!($mac_enum, $mac_prefix, MAC_COMMON);

            /// The functions of the MAC, in declaration order.
            pub const FUNCTIONS: &[crate::ffi::Function] =
                &crate::ffi::Function::concat::<{ MAC_CONSTRUCTORS.len() + MAC_COMMON.len() }>(&[MAC_CONSTRUCTORS, MAC_COMMON]);
        }
    };
}

aegis_family!(
    aegis128x,
    aegis_mac128x,
    AEGIS128XAEAD,
    AEGIS128X,
    AEGISMAC128XState,
    AEGISMAC128X,
    AEGIS128XState,
    16,
    "umilib_crypto_aegis_aegis128x",
    "umilib_crypto_aegis_AEGIS128X",
    "umilib_crypto_aegis_aegis_mac128x",
    "umilib_crypto_aegis_AEGISMAC128X",
    "AEGIS-128X (AEGIS-128L for degree 1)"
);

aegis_family!(
    aegis256x,
    aegis_mac256x,
    AEGIS256XAEAD,
    AEGIS256X,
    AEGISMAC256XState,
    AEGISMAC256X,
    AEGIS256XState,
    32,
    "umilib_crypto_aegis_aegis256x",
    "umilib_crypto_aegis_AEGIS256X",
    "umilib_crypto_aegis_aegis_mac256x",
    "umilib_crypto_aegis_AEGISMAC256X",
    "AEGIS-256X (AEGIS-256 for degree 1)"
);

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "aegis",
    definitions: &[
        Definition::Opaque {
            name: "umilib_crypto_aegis_AEGIS128X",
            documentation: " AEGIS-128X (draft-irtf-cfrg-aegis-aead) of degree 1 (AEGIS-128L), 2 or 4, with 16- or 32-byte tags: a 16-byte key and 16-byte nonces.",
        },
        Definition::Opaque {
            name: "umilib_crypto_aegis_AEGISMAC128X",
            documentation: " The MAC of AEGIS-128X, of degree 1, 2 or 4, with 16- or 32-byte tags and a key and a nonce of 16 bytes.",
        },
        Definition::Opaque {
            name: "umilib_crypto_aegis_AEGIS256X",
            documentation: " AEGIS-256X (draft-irtf-cfrg-aegis-aead) of degree 1 (AEGIS-256), 2 or 4, with 16- or 32-byte tags: a 32-byte key and 32-byte nonces.",
        },
        Definition::Opaque {
            name: "umilib_crypto_aegis_AEGISMAC256X",
            documentation: " The MAC of AEGIS-256X, of degree 1, 2 or 4, with 16- or 32-byte tags and a key and a nonce of 32 bytes.",
        },
    ],
    functions: &Function::concat::<
        {
            aegis128x::FUNCTIONS.len()
                + aegis_mac128x::FUNCTIONS.len()
                + aegis256x::FUNCTIONS.len()
                + aegis_mac256x::FUNCTIONS.len()
        },
    >(&[
        aegis128x::FUNCTIONS,
        aegis_mac128x::FUNCTIONS,
        aegis256x::FUNCTIONS,
        aegis_mac256x::FUNCTIONS,
    ]),
    modules: &[],
};
