//! The C ABI of [`crate::crypto::ibs::sm9`].
//!
//! [`SM9<C, H>`](crate::crypto::ibs::sm9::SM9) is exported once
//! (`umilib_crypto_ibs_sm9_sm9_*`) for every curve of
//! [`ffi_pairing_curves!`](crate::ffi_pairing_curves) and hash function of
//! [`ffi_standard_digests!`](crate::ffi_standard_digests) and SM3, named by
//! their C type names; its keys are the handles of [`crate::ffi::crypto::ibs`].
//! GM/T 0044 specifies `umilib_math_pairing_SM9BN256` with
//! `umilib_hash_sm3_SM3`, hid 0x01, and the master public key 04 || x || y
//! with the u-coefficients first.

use crate::ffi::Module;

/// [`SM9`](crate::crypto::ibs::sm9::SM9).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod sm9 {
    use crate::ffi::crypto::ibs::IBSCall;
    use crate::ffi::{Pointer, Status};
    use crate::math::pairing::PairingCurve;

    /// Defines [`scheme`] over the curves of the registry.
    macro_rules! sm9_curves {
        ($($variant:ident => $type:path, $name:literal;)*) => {
            /// Calls `call` with `SM9<C, H>` for the curve named `names.0` and the hash function named
            /// `names.1`; `None` if either is unknown or not enabled.
            pub fn scheme<V: IBSCall>(names: (&str, &str), call: V) -> Option<V::Output> {
                match names.0 {
                    $($name => with_hash::<$type, V>(names.1, call),)*
                    _ => None,
                }
            }
        };
    }

    /// Defines [`with_hash`] over the hash functions of the registry.
    macro_rules! sm9_hashes {
        ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
            /// Calls `call` with `SM9<C, H>` for the hash function named `hash`; `None` if it is unknown.
            // The registry may enable no hash function, leaving the arguments unused.
            #[allow(unused_variables, dead_code)]
            pub fn with_hash<C: PairingCurve, V: IBSCall>(hash: &str, call: V) -> Option<V::Output> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(call.call::<crate::crypto::ibs::sm9::SM9<C, $type>>()),
                    )*
                    // The hash function GM/T 0044 specifies, beside those of the registry.
                    #[cfg(umilib_feature = "hash-sm3")]
                    "umilib_hash_sm3_SM3" => Some(call.call::<crate::crypto::ibs::sm9::SM9<C, crate::hash::sm3::SM3>>()),
                    _ => None,
                }
            }
        };
    }

    crate::ffi_pairing_curves!(sm9_curves);
    crate::ffi_standard_digests!(sm9_hashes);
    crate::ffi_identity_based_signature!("umilib_crypto_ibs_sm9_sm9", "the signatures of SM9 (GM/T 0044.2)");
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "sm9", definitions: &[], functions: sm9::FUNCTIONS, modules: &[] };
