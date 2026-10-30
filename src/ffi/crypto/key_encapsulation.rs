use super::random::RandomSource;
use crate::crypto::KeyEncapsulation;
use crate::ffi::{Status, ToStatus};

/// An operation of the C ABI on a [`KeyEncapsulation`] chosen at run time:
/// the registry of a module calls `call` with the scheme its names choose.
pub trait KeyEncapsulationCall {
    type Output;

    fn call<K: KeyEncapsulation>(self) -> Self::Output;
}

/// The sizes of the encodings: decapsulation key, encapsulation key, ciphertext, shared secret.
pub struct KeyEncapsulationSizes;

impl KeyEncapsulationCall for KeyEncapsulationSizes {
    type Output = [usize; 4];

    fn call<K: KeyEncapsulation>(self) -> [usize; 4] {
        [K::DECAPSULATION_KEY_SIZE, K::ENCAPSULATION_KEY_SIZE, K::CIPHERTEXT_SIZE, K::SHARED_SECRET_SIZE]
    }
}

/// Generates a decapsulation key from `random` and writes its encoding into `out`.
pub struct KeyEncapsulationGenerate<'a> {
    pub random: RandomSource<'a>,
    pub out: &'a mut [u8],
}

impl KeyEncapsulationCall for KeyEncapsulationGenerate<'_> {
    type Output = Result<(), &'static Status>;

    fn call<K: KeyEncapsulation>(mut self) -> Result<(), &'static Status> {
        let key = K::generate(&mut self.random).map_err(|error| error.to_status())?;
        K::write_decapsulation_key(&key, self.out).map_err(|error| error.to_status())
    }
}

/// Writes the encapsulation key of the encoded decapsulation key `key` into `out`.
pub struct KeyEncapsulationEncapsulationKey<'a> {
    pub key: &'a [u8],
    pub out: &'a mut [u8],
}

impl KeyEncapsulationCall for KeyEncapsulationEncapsulationKey<'_> {
    type Output = Result<(), &'static Status>;

    fn call<K: KeyEncapsulation>(self) -> Result<(), &'static Status> {
        let key = K::decapsulation_key_from_bytes(self.key).map_err(|error| error.to_status())?;
        K::write_encapsulation_key(&K::encapsulation_key(&key), self.out).map_err(|error| error.to_status())
    }
}

/// Validates the encoded decapsulation key `key`.
pub struct KeyEncapsulationCheckDecapsulation<'a> {
    pub key: &'a [u8],
}

impl KeyEncapsulationCall for KeyEncapsulationCheckDecapsulation<'_> {
    type Output = Result<(), &'static Status>;

    fn call<K: KeyEncapsulation>(self) -> Result<(), &'static Status> {
        K::decapsulation_key_from_bytes(self.key).map(|_| ()).map_err(|error| error.to_status())
    }
}

/// Validates the encoded encapsulation key `key`.
pub struct KeyEncapsulationCheckEncapsulation<'a> {
    pub key: &'a [u8],
}

impl KeyEncapsulationCall for KeyEncapsulationCheckEncapsulation<'_> {
    type Output = Result<(), &'static Status>;

    fn call<K: KeyEncapsulation>(self) -> Result<(), &'static Status> {
        K::encapsulation_key_from_bytes(self.key).map(|_| ()).map_err(|error| error.to_status())
    }
}

/// Encapsulates to the encoded encapsulation key `key` with `random`: the
/// ciphertext into `ciphertext`, the shared secret into `shared`.
pub struct KeyEncapsulationEncapsulate<'a> {
    pub key: &'a [u8],
    pub random: RandomSource<'a>,
    pub ciphertext: &'a mut [u8],
    pub shared: &'a mut [u8],
}

impl KeyEncapsulationCall for KeyEncapsulationEncapsulate<'_> {
    type Output = Result<(), &'static Status>;

    fn call<K: KeyEncapsulation>(mut self) -> Result<(), &'static Status> {
        let key = K::encapsulation_key_from_bytes(self.key).map_err(|error| error.to_status())?;
        K::encapsulate(&key, &mut self.random, self.ciphertext, self.shared).map_err(|error| error.to_status())
    }
}

/// Writes the shared secret of `ciphertext` for the encoded decapsulation key `key` into `shared`.
pub struct KeyEncapsulationDecapsulate<'a> {
    pub key: &'a [u8],
    pub ciphertext: &'a [u8],
    pub shared: &'a mut [u8],
}

impl KeyEncapsulationCall for KeyEncapsulationDecapsulate<'_> {
    type Output = Result<(), &'static Status>;

    fn call<K: KeyEncapsulation>(self) -> Result<(), &'static Status> {
        let key = K::decapsulation_key_from_bytes(self.key).map_err(|error| error.to_status())?;
        K::decapsulate(&key, self.ciphertext, self.shared).map_err(|error| error.to_status())
    }
}

/// Exports the functions of a KEM chosen by the names of its parameters
/// (`$parameter` with its length `$length`), whose registry the module
/// defines as `fn scheme<V: KeyEncapsulationCall>(names, call)`.
#[macro_export]
macro_rules! ffi_key_encapsulation {
    ($prefix:literal, $what:literal, [$($parameter:ident $length:ident),+]) => {
        $crate::ffi_exports! {
            const FUNCTIONS;
            #[doc = concat!(" Writes the sizes in bytes of a decapsulation key, an encapsulation key, a ciphertext and a shared secret of ", $what)]
            /// into `sizes` (four elements); fails with InvalidArgument for names that are unknown or not enabled.
            pub unsafe extern "C" fn sizes = concat!($prefix, "_sizes"); ($($parameter: *const u8, $length: usize,)+ sizes: *mut usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and four writable elements.
                    Pointer::check_ranges(&[$(($parameter, $length),)+], &[(sizes.cast(), 4 * core::mem::size_of::<usize>())])?;
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    let values = scheme(names, $crate::ffi::crypto::KeyEncapsulationSizes).ok_or(&Status::INVALID_ARGUMENT)?;
                    let out = unsafe { Pointer::slice_of_mut(sizes, 4) }?;
                    out.copy_from_slice(&values);
                    Ok(())
                })())
            }

            /// Generates a decapsulation key from the generator handle `random`, whose C type is named by the
            /// UTF-8 text at `random_type`, and writes its encoding into `out` of the size of a decapsulation key.
            pub unsafe extern "C" fn generate = concat!($prefix, "_generate"); ($($parameter: *const u8, $length: usize,)+ random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut u8, out_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text, a live generator of the named type and writable bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    Pointer::check_ranges(&[$(($parameter, $length),)+ (random_type, random_type_length)], &[(out, out_length)])?;
                    let random = unsafe { $crate::ffi::crypto::random::RandomSource::from_handle(random, random_type, random_type_length) }?;
                    let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                    scheme(names, $crate::ffi::crypto::KeyEncapsulationGenerate { random, out }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Writes the encapsulation key of the encoded decapsulation key into `out` of the size of an
            /// encapsulation key.
            pub unsafe extern "C" fn encapsulation_key = concat!($prefix, "_encapsulation_key"); ($($parameter: *const u8, $length: usize,)+ key: *const u8, key_length: usize, out: *mut u8, out_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes and writable bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    Pointer::check_ranges(&[$(($parameter, $length),)+ (key, key_length)], &[(out, out_length)])?;
                    let key = unsafe { Pointer::slice(key, key_length) }?;
                    let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                    scheme(names, $crate::ffi::crypto::KeyEncapsulationEncapsulationKey { key, out }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Succeeds if the encoded decapsulation key passes the checks of the scheme; fails with
            /// InvalidKey otherwise.
            pub unsafe extern "C" fn check_decapsulation_key = concat!($prefix, "_check_decapsulation_key"); ($($parameter: *const u8, $length: usize,)+ key: *const u8, key_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    let key = unsafe { Pointer::slice(key, key_length) }?;
                    scheme(names, $crate::ffi::crypto::KeyEncapsulationCheckDecapsulation { key }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Succeeds if the encoded encapsulation key passes the checks of the scheme; fails with
            /// InvalidKey otherwise.
            pub unsafe extern "C" fn check_encapsulation_key = concat!($prefix, "_check_encapsulation_key"); ($($parameter: *const u8, $length: usize,)+ key: *const u8, key_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    let key = unsafe { Pointer::slice(key, key_length) }?;
                    scheme(names, $crate::ffi::crypto::KeyEncapsulationCheckEncapsulation { key }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Encapsulates to the encoded encapsulation key with random values from the generator handle
            /// `random`: the ciphertext into `ciphertext` and the shared secret into `shared`, of their sizes.
            pub unsafe extern "C" fn encapsulate = concat!($prefix, "_encapsulate"); ($($parameter: *const u8, $length: usize,)+ key: *const u8, key_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, ciphertext: *mut u8, ciphertext_length: usize, shared: *mut u8, shared_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes, a live generator of the named type and
                    // writable bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    let inputs = [$(($parameter, $length),)+ (key, key_length), (random_type, random_type_length)];
                    Pointer::check_ranges(&inputs, &[(ciphertext, ciphertext_length), (shared, shared_length)])?;
                    let key = unsafe { Pointer::slice(key, key_length) }?;
                    let random = unsafe { $crate::ffi::crypto::random::RandomSource::from_handle(random, random_type, random_type_length) }?;
                    let ciphertext = unsafe { Pointer::slice_mut(ciphertext, ciphertext_length) }?;
                    let shared = unsafe { Pointer::slice_mut(shared, shared_length) }?;
                    let call = $crate::ffi::crypto::KeyEncapsulationEncapsulate { key, random, ciphertext, shared };
                    scheme(names, call).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }

            /// Writes the shared secret of the ciphertext for the encoded decapsulation key into `shared` of
            /// the size of a shared secret.
            pub unsafe extern "C" fn decapsulate = concat!($prefix, "_decapsulate"); ($($parameter: *const u8, $length: usize,)+ key: *const u8, key_length: usize, ciphertext: *const u8, ciphertext_length: usize, shared: *mut u8, shared_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes and writable bytes.
                    let names = ($(unsafe { Pointer::text($parameter, $length) }?,)+);
                    Pointer::check_ranges(&[$(($parameter, $length),)+ (key, key_length), (ciphertext, ciphertext_length)], &[(shared, shared_length)])?;
                    let key = unsafe { Pointer::slice(key, key_length) }?;
                    let ciphertext = unsafe { Pointer::slice(ciphertext, ciphertext_length) }?;
                    let shared = unsafe { Pointer::slice_mut(shared, shared_length) }?;
                    scheme(names, $crate::ffi::crypto::KeyEncapsulationDecapsulate { key, ciphertext, shared }).ok_or(&Status::INVALID_ARGUMENT)?
                })())
            }
        }
    };
}
