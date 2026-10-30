//! The C ABI of [`crate::crypto::ecdh`].
//!
//! [`ECDH<C>`](crate::crypto::ecdh::ECDH) is exported once
//! (`umilib_crypto_ecdh_ecdh_*`) for every curve of
//! [`ffi_weierstrass_curves!`](crate::ffi_weierstrass_curves), named by the
//! C type name of the curve; [`XDH<C>`](crate::crypto::ecdh::XDH) once
//! (`umilib_crypto_ecdh_xdh_*`) for `umilib_crypto_curve_curve25519_Curve25519`
//! (X25519) and `umilib_crypto_curve_curve448_Curve448` (X448). Keys and
//! shared secrets are the encodings of [`KeyAgreement`](crate::crypto::KeyAgreement).

use crate::ffi::{Function, Module};

/// [`ECDH`](crate::crypto::ecdh::ECDH).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod ecdh {
    use crate::ffi::crypto::KeyAgreementCall;
    use crate::ffi::{Pointer, Status};

    /// Defines [`scheme`] over the curves of the registry.
    macro_rules! ecdh_scheme {
        ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
            /// Calls `call` with `ECDH<C>` for the curve named `names.0`; `None` if it is unknown or not enabled.
            // The registry may enable no curve, leaving `call` unused.
            #[allow(unused_variables)]
            pub fn scheme<V: KeyAgreementCall>(names: (&str,), call: V) -> Option<V::Output> {
                match names.0 {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(call.call::<crate::crypto::ecdh::ECDH<$type>>()),
                    )*
                    _ => None,
                }
            }
        };
    }

    crate::ffi_weierstrass_curves!(ecdh_scheme);
    crate::ffi_key_agreement!("umilib_crypto_ecdh_ecdh", "ECDH on the curve named by `curve`", [curve curve_length]);
}

/// [`XDH`](crate::crypto::ecdh::XDH).
pub mod xdh {
    use crate::ffi::crypto::KeyAgreementCall;
    use crate::ffi::{Pointer, Status};

    /// Calls `call` with `XDH<C>` for the curve named `names.0`; `None` if it is unknown or not enabled.
    // No curve may be enabled, leaving `call` unused.
    #[allow(unused_variables)]
    pub fn scheme<V: KeyAgreementCall>(names: (&str,), call: V) -> Option<V::Output> {
        match names.0 {
            #[cfg(umilib_feature = "crypto-curve-curve25519")]
            "umilib_crypto_curve_curve25519_Curve25519" => Some(call.call::<crate::crypto::ecdh::X25519>()),
            #[cfg(umilib_feature = "crypto-curve-curve448")]
            "umilib_crypto_curve_curve448_Curve448" => Some(call.call::<crate::crypto::ecdh::X448>()),
            _ => None,
        }
    }

    crate::ffi_key_agreement!("umilib_crypto_ecdh_xdh", "XDH on the curve named by `curve`", [curve curve_length]);
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ecdh",
    definitions: &[],
    functions: &Function::concat::<{ ecdh::FUNCTIONS.len() + xdh::FUNCTIONS.len() }>(&[
        ecdh::FUNCTIONS,
        xdh::FUNCTIONS,
    ]),
    modules: &[],
};
