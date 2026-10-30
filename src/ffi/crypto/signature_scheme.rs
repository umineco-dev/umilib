use super::random::RandomSource;
use crate::crypto::SignatureScheme;
use crate::ffi::{Status, ToStatus};

/// An operation of the C ABI on a [`SignatureScheme`] chosen at run time:
/// the registry of a module calls `call` with the scheme its names choose.
pub trait SignatureSchemeCall {
    type Output;

    fn call<S: SignatureScheme>(self) -> Self::Output;
}

/// The sizes of the encodings: signing key, verifying key, signature.
pub struct SignatureSchemeSizes;

impl SignatureSchemeCall for SignatureSchemeSizes {
    type Output = [usize; 3];

    fn call<S: SignatureScheme>(self) -> [usize; 3] {
        [S::SIGNING_KEY_SIZE, S::VERIFYING_KEY_SIZE, S::SIGNATURE_SIZE]
    }
}

/// Generates a signing key from `random` and writes its encoding into `out`.
pub struct SignatureSchemeGenerate<'a> {
    pub random: RandomSource<'a>,
    pub out: &'a mut [u8],
}

impl SignatureSchemeCall for SignatureSchemeGenerate<'_> {
    type Output = Result<(), &'static Status>;

    fn call<S: SignatureScheme>(mut self) -> Result<(), &'static Status> {
        let key = S::generate(&mut self.random).map_err(|error| error.to_status())?;
        S::write_signing_key(&key, self.out).map_err(|error| error.to_status())
    }
}

/// Writes the verifying key of the encoded signing key `key` into `out`.
pub struct SignatureSchemeVerifyingKey<'a> {
    pub key: &'a [u8],
    pub out: &'a mut [u8],
}

impl SignatureSchemeCall for SignatureSchemeVerifyingKey<'_> {
    type Output = Result<(), &'static Status>;

    fn call<S: SignatureScheme>(self) -> Result<(), &'static Status> {
        let key = S::signing_key_from_bytes(self.key).map_err(|error| error.to_status())?;
        S::write_verifying_key(&S::verifying_key(&key), self.out).map_err(|error| error.to_status())
    }
}

/// Validates the encoded signing key `key`.
pub struct SignatureSchemeCheckSigning<'a> {
    pub key: &'a [u8],
}

impl SignatureSchemeCall for SignatureSchemeCheckSigning<'_> {
    type Output = Result<(), &'static Status>;

    fn call<S: SignatureScheme>(self) -> Result<(), &'static Status> {
        S::signing_key_from_bytes(self.key).map(|_| ()).map_err(|error| error.to_status())
    }
}

/// Validates the encoded verifying key `key`.
pub struct SignatureSchemeCheckVerifying<'a> {
    pub key: &'a [u8],
}

impl SignatureSchemeCall for SignatureSchemeCheckVerifying<'_> {
    type Output = Result<(), &'static Status>;

    fn call<S: SignatureScheme>(self) -> Result<(), &'static Status> {
        S::verifying_key_from_bytes(self.key).map(|_| ()).map_err(|error| error.to_status())
    }
}

/// Writes the signature of `message` under the encoded signing key `key` into `out`.
pub struct SignatureSchemeSign<'a> {
    pub key: &'a [u8],
    pub message: &'a [u8],
    pub out: &'a mut [u8],
}

impl SignatureSchemeCall for SignatureSchemeSign<'_> {
    type Output = Result<(), &'static Status>;

    fn call<S: SignatureScheme>(self) -> Result<(), &'static Status> {
        let key = S::signing_key_from_bytes(self.key).map_err(|error| error.to_status())?;
        S::sign(&key, self.message, self.out).map_err(|error| error.to_status())
    }
}

/// Verifies `signature` of `message` under the encoded verifying key `key`.
pub struct SignatureSchemeVerify<'a> {
    pub key: &'a [u8],
    pub message: &'a [u8],
    pub signature: &'a [u8],
}

impl SignatureSchemeCall for SignatureSchemeVerify<'_> {
    type Output = Result<(), &'static Status>;

    fn call<S: SignatureScheme>(self) -> Result<(), &'static Status> {
        let key = S::verifying_key_from_bytes(self.key).map_err(|error| error.to_status())?;
        S::verify(&key, self.message, self.signature).map_err(|error| error.to_status())
    }
}

/// Exports the functions of a signature scheme chosen by the names of its
/// parameters (`$parameter` with its length `$length`), whose registry the
/// module defines as `fn scheme<V: SignatureSchemeCall>(names, call)`.
#[macro_export]
macro_rules! ffi_signature_scheme {
    ($prefix:literal, $what:literal, [$($parameter:ident $length:ident),+]) => {
        $crate::ffi_exports! {
            const FUNCTIONS;
            #[doc = concat!(" Writes the sizes in bytes of a signing key, a verifying key and a signature of ", $what, " into")]
            /// `sizes` (three elements); fails with InvalidArgument for names that are unknown or not enabled.
            pub unsafe extern "C" fn sizes = concat!($prefix, "_sizes"); ($($parameter: *const u8, $length: usize,)+ sizes: *mut usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and three writable elements.
                    Pointer::check_ranges(&[$(($parameter, $length),)+], &[(sizes.cast(), 3 * core::mem::size_of::<usize>())])?;
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    let values = scheme(names, $crate::ffi::crypto::SignatureSchemeSizes).ok_or(&Status::INVALID_ARGUMENT)?;
                    let out = unsafe { Pointer::slice_of_mut(sizes, 3) }?;
                    out.copy_from_slice(&values);
                    Ok(())
                })())
            }

            /// Generates a signing key from the generator handle `random`, whose C type is named by the UTF-8
            /// text at `random_type` (such as `umilib_crypto_random_HMACDRBG`), and writes its encoding into
            /// `out` of the size of a signing key.
            pub unsafe extern "C" fn generate = concat!($prefix, "_generate"); ($($parameter: *const u8, $length: usize,)+ random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut u8, out_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text, a live generator of the named type and writable bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    Pointer::check_ranges(&[$(($parameter, $length),)+ (random_type, random_type_length)], &[(out, out_length)])?;
                    let random = unsafe { $crate::ffi::crypto::random::RandomSource::from_handle(random, random_type, random_type_length) }?;
                    let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                    scheme(names, $crate::ffi::crypto::SignatureSchemeGenerate { random, out }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Writes the verifying key of the encoded signing key into `out` of the size of a verifying key.
            pub unsafe extern "C" fn verifying_key = concat!($prefix, "_verifying_key"); ($($parameter: *const u8, $length: usize,)+ key: *const u8, key_length: usize, out: *mut u8, out_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes and writable bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    Pointer::check_ranges(&[$(($parameter, $length),)+ (key, key_length)], &[(out, out_length)])?;
                    let key = unsafe { Pointer::slice(key, key_length) }?;
                    let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                    scheme(names, $crate::ffi::crypto::SignatureSchemeVerifyingKey { key, out }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Succeeds if the encoded signing key is valid; fails with InvalidKey otherwise.
            pub unsafe extern "C" fn check_signing_key = concat!($prefix, "_check_signing_key"); ($($parameter: *const u8, $length: usize,)+ key: *const u8, key_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    let key = unsafe { Pointer::slice(key, key_length) }?;
                    scheme(names, $crate::ffi::crypto::SignatureSchemeCheckSigning { key }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Succeeds if the encoded verifying key is valid; fails with InvalidKey otherwise.
            pub unsafe extern "C" fn check_verifying_key = concat!($prefix, "_check_verifying_key"); ($($parameter: *const u8, $length: usize,)+ key: *const u8, key_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    let key = unsafe { Pointer::slice(key, key_length) }?;
                    scheme(names, $crate::ffi::crypto::SignatureSchemeCheckVerifying { key }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Writes the signature of the message under the encoded signing key into `out` of the size of a signature.
            pub unsafe extern "C" fn sign = concat!($prefix, "_sign"); ($($parameter: *const u8, $length: usize,)+ key: *const u8, key_length: usize, message: *const u8, message_length: usize, out: *mut u8, out_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes and writable bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    Pointer::check_ranges(&[$(($parameter, $length),)+ (key, key_length), (message, message_length)], &[(out, out_length)])?;
                    let key = unsafe { Pointer::slice(key, key_length) }?;
                    let message = unsafe { Pointer::slice(message, message_length) }?;
                    let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                    scheme(names, $crate::ffi::crypto::SignatureSchemeSign { key, message, out }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Succeeds if the signature is a signature of the message under the encoded verifying key; fails
            /// with InvalidSignature otherwise and with InvalidKey for a key the scheme refuses.
            pub unsafe extern "C" fn verify = concat!($prefix, "_verify"); ($($parameter: *const u8, $length: usize,)+ key: *const u8, key_length: usize, message: *const u8, message_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    let key = unsafe { Pointer::slice(key, key_length) }?;
                    let message = unsafe { Pointer::slice(message, message_length) }?;
                    let signature = unsafe { Pointer::slice(signature, signature_length) }?;
                    scheme(names, $crate::ffi::crypto::SignatureSchemeVerify { key, message, signature }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }
        }
    };
}
