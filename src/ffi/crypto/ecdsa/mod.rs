//! The C ABI of [`crate::crypto::ecdsa`].
//!
//! [`ECDSA<C, H>`](crate::crypto::ecdsa::ECDSA) is exported once
//! (`umilib_crypto_ecdsa_ecdsa_*`) for every curve of
//! [`ffi_weierstrass_curves!`](crate::ffi_weierstrass_curves) and hash
//! function of [`ffi_standard_digests!`](crate::ffi_standard_digests), named
//! by the C type names of the curve and of the hash function. Keys and
//! signatures (r || s) are the encodings of
//! [`SignatureScheme`](crate::crypto::SignatureScheme); signatures are
//! converted to and from DER with `codec-asn1-der`.

use crate::ffi::Module;

/// [`ECDSA`](crate::crypto::ecdsa::ECDSA).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod ecdsa {
    use crate::ffi::crypto::SignatureSchemeCall;
    use crate::ffi::{Pointer, Status};
    use crate::math::ec::WeierstrassCurve;

    /// Defines [`scheme`] over the curves of the registry.
    macro_rules! ecdsa_curves {
        ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
            /// Calls `call` with `ECDSA<C, H>` for the curve named `names.0` and the hash function named
            /// `names.1`; `None` if either is unknown or not enabled.
            // The registry may enable no curve, leaving the arguments unused.
            #[allow(unused_variables)]
            pub fn scheme<V: SignatureSchemeCall>(names: (&str, &str), call: V) -> Option<V::Output> {
                match names.0 {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => with_hash::<$type, V>(names.1, call),
                    )*
                    _ => None,
                }
            }
        };
    }

    /// Defines [`with_hash`] over the hash functions of the registry.
    macro_rules! ecdsa_hashes {
        ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
            /// Calls `call` with `ECDSA<C, H>` for the hash function named `hash`; `None` if it is unknown.
            // The registry may enable no hash function, leaving the arguments unused.
            #[allow(unused_variables, dead_code)]
            pub fn with_hash<C: WeierstrassCurve, V: SignatureSchemeCall>(hash: &str, call: V) -> Option<V::Output> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(call.call::<crate::crypto::ecdsa::ECDSA<C, $type>>()),
                    )*
                    _ => None,
                }
            }
        };
    }

    crate::ffi_weierstrass_curves!(ecdsa_curves);
    crate::ffi_standard_digests!(ecdsa_hashes);
    crate::ffi_signature_scheme!(
        "umilib_crypto_ecdsa_ecdsa",
        "ECDSA on the curve named by `curve` with the hash function named by `hash`",
        [curve curve_length, hash hash_length]
    );

    /// The DER encoding of signatures (RFC 3279 section 2.2.3 `ECDSA-Sig-Value`).
    #[cfg(umilib_feature = "codec-asn1-der")]
    pub mod der {
        use alloc::vec::Vec;

        use crate::crypto::CryptoError;
        use crate::crypto::ecdsa::ECDSASignature;
        use crate::ffi::{Buffer, Pointer, Status};
        use crate::math::ec::{PrimeField, WeierstrassCurve};

        /// A conversion of a signature, generic over the curve.
        pub enum DERCall<'a> {
            /// r || s of the DER.
            FromDER { der: &'a [u8] },
            /// The DER of r || s.
            ToDER { signature: &'a [u8] },
        }

        impl DERCall<'_> {
            /// The conversion on `C`.
            pub fn call<C: WeierstrassCurve>(self) -> Result<Vec<u8>, CryptoError> {
                match self {
                    DERCall::FromDER { der } => {
                        let mut out = alloc::vec![0u8; 2 * <C::Scalar as PrimeField>::BYTES];
                        ECDSASignature::<C>::from_der(der)?.write_bytes(&mut out)?;
                        Ok(out)
                    }
                    DERCall::ToDER { signature } => Ok(ECDSASignature::<C>::from_bytes(signature)?.to_der()),
                }
            }
        }

        /// Defines [`DERCall::dispatch`] over the curves of the registry.
        macro_rules! der_curves {
            ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
                // The registry may enable no curve, leaving the arguments unused.
                #[allow(unused_variables)]
                impl DERCall<'_> {
                    /// The conversion on the curve named `curve`; fails with InvalidArgument if it is unknown.
                    pub fn dispatch(self, curve: &str) -> Result<Vec<u8>, &'static Status> {
                        match curve {
                            $(
                                #[cfg(umilib_feature = $feature)]
                                $name => self.call::<$type>().map_err(|error| crate::ffi::ToStatus::to_status(&error)),
                            )*
                            _ => Err(&Status::INVALID_ARGUMENT),
                        }
                    }
                }
            };
        }

        crate::ffi_weierstrass_curves!(der_curves);

        crate::ffi_functions! {
            /// Writes the signature r || s of the DER `ECDSA-Sig-Value` on the curve named by `curve` into a new
            /// buffer; fails with InvalidSignature for another encoding or values out of range.
            pub unsafe extern "C" fn umilib_crypto_ecdsa_ecdsa_signature_from_der(curve: *const u8, curve_length: usize, der: *const u8, der_length: usize, out: *mut Buffer) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes and a writable buffer.
                    let curve = unsafe { Pointer::text(curve, curve_length) }?;
                    let der = unsafe { Pointer::slice(der, der_length) }?;
                    let signature = DERCall::FromDER { der }.dispatch(curve)?;
                    unsafe { Pointer::write(out, Buffer::from_vec(signature)) }
                })())
            }

            /// Writes the DER `ECDSA-Sig-Value` of the signature r || s on the curve named by `curve` into a new
            /// buffer.
            pub unsafe extern "C" fn umilib_crypto_ecdsa_ecdsa_signature_to_der(curve: *const u8, curve_length: usize, signature: *const u8, signature_length: usize, out: *mut Buffer) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes and a writable buffer.
                    let curve = unsafe { Pointer::text(curve, curve_length) }?;
                    let signature = unsafe { Pointer::slice(signature, signature_length) }?;
                    let der = DERCall::ToDER { signature }.dispatch(curve)?;
                    unsafe { Pointer::write(out, Buffer::from_vec(der)) }
                })())
            }
        }
    }

    #[cfg(umilib_feature = "codec-asn1-der")]
    pub const ENCODINGS: &[crate::ffi::Function] = der::FUNCTIONS;
    #[cfg(not(umilib_feature = "codec-asn1-der"))]
    pub const ENCODINGS: &[crate::ffi::Function] = &[];
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ecdsa",
    definitions: &[],
    functions: &crate::ffi::Function::concat::<{ ecdsa::FUNCTIONS.len() + ecdsa::ENCODINGS.len() }>(&[
        ecdsa::FUNCTIONS,
        ecdsa::ENCODINGS,
    ]),
    modules: &[],
};
