use super::random::RandomSource;
use crate::crypto::KeyAgreement;
use crate::ffi::{Status, ToStatus};

/// An operation of the C ABI on a [`KeyAgreement`] chosen at run time: the
/// registry of a module calls `call` with the scheme its names choose.
pub trait KeyAgreementCall {
    type Output;

    fn call<K: KeyAgreement>(self) -> Self::Output;
}

/// The sizes of the encodings: private key, public key, shared secret.
pub struct KeyAgreementSizes;

impl KeyAgreementCall for KeyAgreementSizes {
    type Output = [usize; 3];

    fn call<K: KeyAgreement>(self) -> [usize; 3] {
        [K::PRIVATE_KEY_SIZE, K::PUBLIC_KEY_SIZE, K::SHARED_SECRET_SIZE]
    }
}

/// Generates a private key from `random` and writes its encoding into `out`.
pub struct KeyAgreementGenerate<'a> {
    pub random: RandomSource<'a>,
    pub out: &'a mut [u8],
}

impl KeyAgreementCall for KeyAgreementGenerate<'_> {
    type Output = Result<(), &'static Status>;

    fn call<K: KeyAgreement>(mut self) -> Result<(), &'static Status> {
        let key = K::generate(&mut self.random).map_err(|error| error.to_status())?;
        K::write_private_key(&key, self.out).map_err(|error| error.to_status())
    }
}

/// Writes the public key of the encoded private key `private_key` into `out`.
pub struct KeyAgreementPublicKey<'a> {
    pub private_key: &'a [u8],
    pub out: &'a mut [u8],
}

impl KeyAgreementCall for KeyAgreementPublicKey<'_> {
    type Output = Result<(), &'static Status>;

    fn call<K: KeyAgreement>(self) -> Result<(), &'static Status> {
        let key = K::private_key_from_bytes(self.private_key).map_err(|error| error.to_status())?;
        K::write_public_key(&K::public_key(&key), self.out).map_err(|error| error.to_status())
    }
}

/// Validates the encoded private key `private_key`.
pub struct KeyAgreementCheckPrivate<'a> {
    pub private_key: &'a [u8],
}

impl KeyAgreementCall for KeyAgreementCheckPrivate<'_> {
    type Output = Result<(), &'static Status>;

    fn call<K: KeyAgreement>(self) -> Result<(), &'static Status> {
        K::private_key_from_bytes(self.private_key).map(|_| ()).map_err(|error| error.to_status())
    }
}

/// Validates the encoded public key `public_key`.
pub struct KeyAgreementCheckPublic<'a> {
    pub public_key: &'a [u8],
}

impl KeyAgreementCall for KeyAgreementCheckPublic<'_> {
    type Output = Result<(), &'static Status>;

    fn call<K: KeyAgreement>(self) -> Result<(), &'static Status> {
        K::public_key_from_bytes(self.public_key).map(|_| ()).map_err(|error| error.to_status())
    }
}

/// Writes the secret shared by the encoded `private_key` and `public_key` into `out`.
pub struct KeyAgreementAgree<'a> {
    pub private_key: &'a [u8],
    pub public_key: &'a [u8],
    pub out: &'a mut [u8],
}

impl KeyAgreementCall for KeyAgreementAgree<'_> {
    type Output = Result<(), &'static Status>;

    fn call<K: KeyAgreement>(self) -> Result<(), &'static Status> {
        let private_key = K::private_key_from_bytes(self.private_key).map_err(|error| error.to_status())?;
        let public_key = K::public_key_from_bytes(self.public_key).map_err(|error| error.to_status())?;
        K::agree(&private_key, &public_key, self.out).map_err(|error| error.to_status())
    }
}

/// Exports the functions of a key agreement chosen by the names of its
/// parameters (`$parameter` with its length `$length`), whose registry the
/// module defines as `fn scheme<V: KeyAgreementCall>(names, call)`.
#[macro_export]
macro_rules! ffi_key_agreement {
    ($prefix:literal, $what:literal, [$($parameter:ident $length:ident),+]) => {
        $crate::ffi_exports! {
            const FUNCTIONS;
            #[doc = concat!(" Writes the sizes in bytes of a private key, a public key and a shared secret of ", $what, " into")]
            /// `sizes` (three elements); fails with InvalidArgument for names that are unknown or not enabled.
            pub unsafe extern "C" fn sizes = concat!($prefix, "_sizes"); ($($parameter: *const u8, $length: usize,)+ sizes: *mut usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and three writable elements.
                    Pointer::check_ranges(&[$(($parameter, $length),)+], &[(sizes.cast(), 3 * core::mem::size_of::<usize>())])?;
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    let values = scheme(names, $crate::ffi::crypto::KeyAgreementSizes).ok_or(&Status::INVALID_ARGUMENT)?;
                    let out = unsafe { Pointer::slice_of_mut(sizes, 3) }?;
                    out.copy_from_slice(&values);
                    Ok(())
                })())
            }

            /// Generates a private key from the generator handle `random`, whose C type is named by the UTF-8
            /// text at `random_type` (such as `umilib_crypto_random_HMACDRBG`), and writes its encoding into
            /// `out` of the size of a private key.
            pub unsafe extern "C" fn generate = concat!($prefix, "_generate"); ($($parameter: *const u8, $length: usize,)+ random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut u8, out_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text, a live generator of the named type and writable bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    Pointer::check_ranges(&[$(($parameter, $length),)+ (random_type, random_type_length)], &[(out, out_length)])?;
                    let random = unsafe { $crate::ffi::crypto::random::RandomSource::from_handle(random, random_type, random_type_length) }?;
                    let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                    scheme(names, $crate::ffi::crypto::KeyAgreementGenerate { random, out }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Writes the public key of the encoded private key into `out` of the size of a public key.
            pub unsafe extern "C" fn public_key = concat!($prefix, "_public_key"); ($($parameter: *const u8, $length: usize,)+ private_key: *const u8, private_key_length: usize, out: *mut u8, out_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes and writable bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    Pointer::check_ranges(&[$(($parameter, $length),)+ (private_key, private_key_length)], &[(out, out_length)])?;
                    let private_key = unsafe { Pointer::slice(private_key, private_key_length) }?;
                    let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                    scheme(names, $crate::ffi::crypto::KeyAgreementPublicKey { private_key, out }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Succeeds if the encoded private key is valid; fails with InvalidKey otherwise.
            pub unsafe extern "C" fn check_private_key = concat!($prefix, "_check_private_key"); ($($parameter: *const u8, $length: usize,)+ private_key: *const u8, private_key_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    let private_key = unsafe { Pointer::slice(private_key, private_key_length) }?;
                    scheme(names, $crate::ffi::crypto::KeyAgreementCheckPrivate { private_key }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Succeeds if the encoded public key is valid; fails with InvalidKey otherwise.
            pub unsafe extern "C" fn check_public_key = concat!($prefix, "_check_public_key"); ($($parameter: *const u8, $length: usize,)+ public_key: *const u8, public_key_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    let public_key = unsafe { Pointer::slice(public_key, public_key_length) }?;
                    scheme(names, $crate::ffi::crypto::KeyAgreementCheckPublic { public_key }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Writes the secret shared by the encoded private key and the peer's encoded public key into
            /// `out` of the size of a shared secret; fails with InvalidKey for a key the scheme refuses.
            pub unsafe extern "C" fn agree = concat!($prefix, "_agree"); ($($parameter: *const u8, $length: usize,)+ private_key: *const u8, private_key_length: usize, public_key: *const u8, public_key_length: usize, out: *mut u8, out_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes and writable bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    Pointer::check_ranges(&[$(($parameter, $length),)+ (private_key, private_key_length), (public_key, public_key_length)], &[(out, out_length)])?;
                    let private_key = unsafe { Pointer::slice(private_key, private_key_length) }?;
                    let public_key = unsafe { Pointer::slice(public_key, public_key_length) }?;
                    let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                    scheme(names, $crate::ffi::crypto::KeyAgreementAgree { private_key, public_key, out }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }
        }
    };
}
