//! The C ABI of [`crate::crypto::gostr3410`].
//!
//! [`GOSTR3410<C, H>`](crate::crypto::gostr3410::GOSTR3410) is exported once
//! (`umilib_crypto_gostr3410_gostr3410_*`) for every curve of
//! [`ffi_gost_curves!`](crate::ffi_gost_curves) with the Streebog of its
//! size, named by the C type names of the curve and of the hash function.
//! Keys and signatures are the encodings of RFC 9215.

use crate::ffi::Module;

/// [`GOSTR3410`](crate::crypto::gostr3410::GOSTR3410).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod gostr3410 {
    use crate::ffi::crypto::SignatureSchemeCall;
    use crate::ffi::{Pointer, Status};

    /// Defines [`scheme`] over the curves of the registry.
    macro_rules! gost_curves {
        ($($feature:literal $variant:ident => $type:path, $name:literal, $hash:path, $hash_name:literal;)*) => {
            /// Calls `call` with `GOSTR3410<C, H>` for the curve named `names.0` with its hash function,
            /// named `names.1`; `None` for other names or a disabled curve.
            // The registry may enable no curve, leaving `call` unused.
            #[allow(unused_variables)]
            pub fn scheme<V: SignatureSchemeCall>(names: (&str, &str), call: V) -> Option<V::Output> {
                match names {
                    $(
                        #[cfg(all(umilib_feature = $feature, umilib_feature = "hash-streebog"))]
                        ($name, $hash_name) => Some(call.call::<crate::crypto::gostr3410::GOSTR3410<$type, $hash>>()),
                    )*
                    _ => None,
                }
            }
        };
    }

    crate::ffi_gost_curves!(gost_curves);
    crate::ffi_signature_scheme!(
        "umilib_crypto_gostr3410_gostr3410",
        "GOST R 34.10-2012 on the curve named by `curve` with the hash function named by `hash`",
        [curve curve_length, hash hash_length]
    );
}

/// The manifest node of this module.
pub const MODULE: Module =
    Module { name: "gostr3410", definitions: &[], functions: gostr3410::FUNCTIONS, modules: &[] };
