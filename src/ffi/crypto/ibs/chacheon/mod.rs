//! The C ABI of [`crate::crypto::ibs::chacheon`].
//!
//! [`ChaCheon<C, H>`](crate::crypto::ibs::chacheon::ChaCheon) is exported once
//! (`umilib_crypto_ibs_chacheon_chacheon_*`) for every curve of
//! [`ffi_pairing_curves!`](crate::ffi_pairing_curves) and hash function of
//! [`ffi_standard_digests!`](crate::ffi_standard_digests), named by their C
//! type names; its keys are the handles of [`crate::ffi::crypto::ibs`].

use crate::ffi::Module;

/// [`ChaCheon`](crate::crypto::ibs::chacheon::ChaCheon).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod chacheon {
    use crate::ffi::crypto::ibs::IBSCall;
    use crate::ffi::{Pointer, Status};
    use crate::math::pairing::PairingCurve;

    /// Defines [`scheme`] over the curves of the registry.
    macro_rules! chacheon_curves {
        ($($variant:ident => $type:path, $name:literal;)*) => {
            /// Calls `call` with `ChaCheon<C, H>` for the curve named `names.0` and the hash function named
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
    macro_rules! chacheon_hashes {
        ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
            /// Calls `call` with `ChaCheon<C, H>` for the hash function named `hash`; `None` if it is unknown.
            // The registry may enable no hash function, leaving the arguments unused.
            #[allow(unused_variables, dead_code)]
            pub fn with_hash<C: PairingCurve, V: IBSCall>(hash: &str, call: V) -> Option<V::Output> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(call.call::<crate::crypto::ibs::chacheon::ChaCheon<C, $type>>()),
                    )*
                    _ => None,
                }
            }
        };
    }

    crate::ffi_pairing_curves!(chacheon_curves);
    crate::ffi_standard_digests!(chacheon_hashes);
    crate::ffi_identity_based_signature!("umilib_crypto_ibs_chacheon_chacheon", "the scheme of Cha and Cheon");
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "chacheon", definitions: &[], functions: chacheon::FUNCTIONS, modules: &[] };
