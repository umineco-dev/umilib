//! The C ABI of [`crate::crypto::dsa`].
//!
//! [`DSAParameters`], [`DSASigningKey`] and [`DSAVerifyingKey`] are opaque
//! handles; integers are big-endian bytes. [`DSA<H>`](crate::crypto::dsa::DSA)
//! takes the hash function by the C type name of its type, among those of
//! [`ffi_standard_digests!`](crate::ffi_standard_digests). Signatures are
//! r || s, each of the bytes of q, converted to and from DER with
//! `codec-asn1-der`.

use crate::crypto::CryptoError;
use crate::crypto::dsa::{DSA, DSAParameters, DSASignature, DSASigningKey, DSAVerifyingKey};
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::math::bigint::BigEndianInteger;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};
use crate::hash::CryptographicDigest;

impl Value for DSAParameters {
    const TYPE: Type = Type::Named("umilib_crypto_dsa_DSAParameters");
}

impl Value for DSASigningKey {
    const TYPE: Type = Type::Named("umilib_crypto_dsa_DSASigningKey");
}

impl Value for DSAVerifyingKey {
    const TYPE: Type = Type::Named("umilib_crypto_dsa_DSAVerifyingKey");
}

/// A signature operation generic over the hash function.
pub enum DSACall<'a> {
    Sign { key: &'a DSASigningKey, message: &'a [u8] },
    Verify { key: &'a DSAVerifyingKey, message: &'a [u8], signature: &'a DSASignature },
}

impl DSACall<'_> {
    /// The operation with `H`: the signature, or `None` after a successful verification.
    pub fn call<H: CryptographicDigest + Default>(self) -> Result<Option<DSASignature>, CryptoError> {
        match self {
            DSACall::Sign { key, message } => DSA::<H>::sign(key, message).map(Some),
            DSACall::Verify { key, message, signature } => DSA::<H>::verify(key, message, signature).map(|_| None),
        }
    }
}

/// Defines [`DSACall::dispatch`] over the hash functions of the registry.
macro_rules! dsa_digests {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        // The registry may enable no hash function, leaving the arguments unused.
        #[allow(unused_variables)]
        impl DSACall<'_> {
            /// The operation with the hash function named `hash`; fails with InvalidArgument if it is unknown.
            pub fn dispatch(self, hash: &str) -> Result<Option<DSASignature>, &'static Status> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => self.call::<$type>().map_err(|error| error.to_status()),
                    )*
                    _ => Err(&Status::INVALID_ARGUMENT),
                }
            }
        }
    };
}

crate::ffi_standard_digests!(dsa_digests);

crate::ffi_functions! {
    /// Creates the domain parameters (p, q, g) of the big-endian integers; fails with InvalidParameter for
    /// sizes other than those of FIPS 186-4 or inconsistent values.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_parameters_new(p: *const u8, p_length: usize, q: *const u8, q_length: usize, g: *const u8, g_length: usize, out: *mut *mut DSAParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let p = BigEndianInteger::integer(unsafe { Pointer::slice(p, p_length) }?)?;
            let q = BigEndianInteger::integer(unsafe { Pointer::slice(q, q_length) }?)?;
            let g = BigEndianInteger::integer(unsafe { Pointer::slice(g, g_length) }?)?;
            let parameters = DSAParameters::new(&p, &q, &g).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, parameters) }
        })())
    }

    /// Releases the parameters. Does nothing if they are null.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_parameters_free(parameters: *mut DSAParameters) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(parameters) }
    }

    /// The bytes of each half of a signature: those of q.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_parameters_q_bytes(parameters: *const DSAParameters, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable element.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            unsafe { Pointer::write(out, parameters.q_bytes()) }
        })())
    }

    /// Writes p big-endian, without leading zeros, into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_parameters_p(parameters: *const DSAParameters, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(BigEndianInteger::bytes(parameters.p().value()))) }
        })())
    }

    /// Writes q big-endian, without leading zeros, into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_parameters_q(parameters: *const DSAParameters, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(BigEndianInteger::bytes(parameters.q().value()))) }
        })())
    }

    /// Writes g big-endian, of the bytes of p, into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_parameters_g(parameters: *const DSAParameters, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            let mut bytes = alloc::vec![0u8; parameters.p_bytes()];
            parameters.g().write_be_bytes(&mut bytes).map_err(|_| &Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// Creates the signing key x (big-endian, 1 ≤ x < q) under a copy of the parameters.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_signing_key_new(parameters: *const DSAParameters, x: *const u8, x_length: usize, out: *mut *mut DSASigningKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            let mut x = BigEndianInteger::integer(unsafe { Pointer::slice(x, x_length) }?)?;
            let key = DSASigningKey::new(parameters.clone(), &x).map_err(|error| error.to_status());
            crate::secret::Zeroize::zeroize(&mut x);
            unsafe { Pointer::write_handle(out, key?) }
        })())
    }

    /// Generates a signing key under a copy of the parameters from the generator handle `random` of the type
    /// named by `random_type`.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_signing_key_generate(parameters: *const DSAParameters, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut DSASigningKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, a live generator of the named type and a writable pointer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let key = DSASigningKey::generate(parameters.clone(), &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Releases the signing key, zeroizing it. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_signing_key_free(key: *mut DSASigningKey) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(key) }
    }

    /// Creates a copy of the verifying key of the signing key.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_signing_key_verifying_key(key: *const DSASigningKey, out: *mut *mut DSAVerifyingKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write_handle(out, key.verifying_key().clone()) }
        })())
    }

    /// Writes x big-endian, of the bytes of q, into a new buffer, which zeroizes it when it is released.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_signing_key_x(key: *const DSASigningKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let mut bytes = alloc::vec![0u8; key.parameters().q_bytes()];
            key.x().write_be_bytes(&mut bytes).map_err(|_| &Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// Creates a copy of the parameters of the signing key.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_signing_key_parameters(key: *const DSASigningKey, out: *mut *mut DSAParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write_handle(out, key.parameters().clone()) }
        })())
    }

    /// Creates the verifying key y (big-endian) under a copy of the parameters; fails with InvalidKey unless
    /// 2 ≤ y ≤ p - 2 and y^q = 1 mod p.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_verifying_key_new(parameters: *const DSAParameters, y: *const u8, y_length: usize, out: *mut *mut DSAVerifyingKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            let y = BigEndianInteger::integer(unsafe { Pointer::slice(y, y_length) }?)?;
            let key = DSAVerifyingKey::new(parameters.clone(), &y).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, key) }
        })())
    }

    /// Releases the verifying key. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_verifying_key_free(key: *mut DSAVerifyingKey) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(key) }
    }

    /// Writes y big-endian, of the bytes of p, into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_verifying_key_y(key: *const DSAVerifyingKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let mut bytes = alloc::vec![0u8; key.parameters().p_bytes()];
            key.y().write_be_bytes(&mut bytes).map_err(|_| &Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// Creates a copy of the parameters of the verifying key.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_verifying_key_parameters(key: *const DSAVerifyingKey, out: *mut *mut DSAParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write_handle(out, key.parameters().clone()) }
        })())
    }

    /// Writes the signature r || s of the message with the hash function named by `hash` (and the nonce of
    /// RFC 6979) into `out` of twice the bytes of q.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_sign(key: *const DSASigningKey, hash: *const u8, hash_length: usize, message: *const u8, message_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(hash, hash_length), (message, message_length)], &[(out.cast_const(), out_length)])?;
            // SAFETY: the caller passes a valid handle, readable text and bytes and writable bytes.
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let message = unsafe { Pointer::slice(message, message_length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            let signature = DSACall::Sign { key, message }.dispatch(hash)?.ok_or(&Status::INVALID_ARGUMENT)?;
            signature.write_bytes(key.parameters(), out).map_err(|error| error.to_status())
        })())
    }

    /// Succeeds if r || s is a signature of the message with the hash function named by `hash`; fails with
    /// InvalidSignature otherwise.
    pub unsafe extern "C" fn umilib_crypto_dsa_dsa_verify(key: *const DSAVerifyingKey, hash: *const u8, hash_length: usize, message: *const u8, message_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text and bytes.
            let key = unsafe { Pointer::reference(key) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let message = unsafe { Pointer::slice(message, message_length) }?;
            let signature = DSASignature::from_bytes(key.parameters(), unsafe { Pointer::slice(signature, signature_length) }?)
                .map_err(|error| error.to_status())?;
            DSACall::Verify { key, message, signature: &signature }.dispatch(hash).map(|_| ())
        })())
    }
}

/// The DER encoding of signatures (RFC 3279 section 2.2.2 `Dss-Sig-Value`).
#[cfg(umilib_feature = "codec-asn1-der")]
pub mod der {
    use super::{DSAParameters, DSASignature};
    use crate::ffi::{Buffer, Pointer, Status, ToStatus};

    crate::ffi_functions! {
        /// Writes the signature r || s of the DER `Dss-Sig-Value` into a new buffer; fails with InvalidSignature
        /// for another encoding or values out of range.
        pub unsafe extern "C" fn umilib_crypto_dsa_dsa_signature_from_der(parameters: *const DSAParameters, der: *const u8, der_length: usize, out: *mut Buffer) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
                let parameters = unsafe { Pointer::reference(parameters) }?;
                let der = unsafe { Pointer::slice(der, der_length) }?;
                let signature = DSASignature::from_der(parameters, der).map_err(|error| error.to_status())?;
                let mut bytes = alloc::vec![0u8; 2 * parameters.q_bytes()];
                signature.write_bytes(parameters, &mut bytes).map_err(|error| error.to_status())?;
                unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
            })())
        }

        /// Writes the DER `Dss-Sig-Value` of the signature r || s into a new buffer.
        pub unsafe extern "C" fn umilib_crypto_dsa_dsa_signature_to_der(parameters: *const DSAParameters, signature: *const u8, signature_length: usize, out: *mut Buffer) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
                let parameters = unsafe { Pointer::reference(parameters) }?;
                let signature = DSASignature::from_bytes(parameters, unsafe { Pointer::slice(signature, signature_length) }?)
                    .map_err(|error| error.to_status())?;
                unsafe { Pointer::write(out, Buffer::from_vec(signature.to_der())) }
            })())
        }
    }
}

#[cfg(umilib_feature = "codec-asn1-der")]
const ENCODINGS: &[crate::ffi::Function] = der::FUNCTIONS;
#[cfg(not(umilib_feature = "codec-asn1-der"))]
const ENCODINGS: &[crate::ffi::Function] = &[];

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "dsa",
    definitions: &[
        Definition::Opaque {
            name: "umilib_crypto_dsa_DSAParameters",
            documentation: " The domain parameters (p, q, g) of DSA (FIPS 186-4 section 4.3).",
        },
        Definition::Opaque {
            name: "umilib_crypto_dsa_DSASigningKey",
            documentation: " A signing key x of DSA with its parameters and verifying key.",
        },
        Definition::Opaque {
            name: "umilib_crypto_dsa_DSAVerifyingKey",
            documentation: " A verifying key y of DSA with its parameters.",
        },
    ],
    functions: &crate::ffi::Function::concat::<{ FUNCTIONS.len() + ENCODINGS.len() }>(&[FUNCTIONS, ENCODINGS]),
    modules: &[],
};
