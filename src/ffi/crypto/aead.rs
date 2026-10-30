use crate::crypto::{AEAD, CryptoError};

/// An AEAD of the C ABI whose sizes may be chosen at run time (a mode over a
/// cipher of the registry, a tag size): the functions of [`AEAD`] with the
/// tag written into a slice of [`AEADState::tag_size`] bytes.
pub trait AEADState: Clone {
    /// The recommended nonce size.
    fn nonce_size(&self) -> usize;

    fn tag_size(&self) -> usize;

    /// Encrypts `buffer` in place and writes the tag into `tag`, which has the tag size.
    fn encrypt_in_place(
        &self,
        nonce: &[u8],
        associated: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), CryptoError>;

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        associated: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError>;
}

impl<A: AEAD + Clone> AEADState for A {
    fn nonce_size(&self) -> usize {
        A::NONCE_SIZE
    }

    fn tag_size(&self) -> usize {
        A::TAG_SIZE
    }

    fn encrypt_in_place(
        &self,
        nonce: &[u8],
        associated: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), CryptoError> {
        if tag.len() != A::TAG_SIZE {
            return Err(CryptoError::TagLength { length: tag.len(), minimum: A::TAG_SIZE, maximum: A::TAG_SIZE });
        }
        let computed = AEAD::encrypt_in_place(self, nonce, associated, buffer)?;
        tag.copy_from_slice(computed.as_ref());
        Ok(())
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        associated: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        AEAD::decrypt_in_place(self, nonce, associated, buffer, tag)
    }
}

/// Defines `$name` as an enum of AEADs whose variants share the C ABI
/// (`Variant(Type),` for each), implementing [`AEADState`] by delegation.
#[macro_export]
macro_rules! ffi_aead_enum {
    ($(#[$documentation:meta])* $name:ident { $($(#[$attribute:meta])* $variant:ident($type:ty),)* }) => {
        $(#[$documentation])*
        #[derive(Clone)]
        // The enum lives behind a handle: boxing the variants would add an allocation.
        #[allow(clippy::large_enum_variant)]
        pub enum $name {
            $($(#[$attribute])* $variant($type),)*
        }

        // The enum is empty when no algorithm of the registry is enabled, leaving the arguments unused.
        #[allow(unused_variables)]
        impl $crate::ffi::crypto::AEADState for $name {
            fn nonce_size(&self) -> usize {
                match *self {
                    $($(#[$attribute])* $name::$variant(ref aead) => $crate::ffi::crypto::AEADState::nonce_size(aead),)*
                }
            }

            fn tag_size(&self) -> usize {
                match *self {
                    $($(#[$attribute])* $name::$variant(ref aead) => $crate::ffi::crypto::AEADState::tag_size(aead),)*
                }
            }

            fn encrypt_in_place(&self, nonce: &[u8], associated: &[u8], buffer: &mut [u8], tag: &mut [u8]) -> Result<(), $crate::crypto::CryptoError> {
                match *self {
                    $($(#[$attribute])* $name::$variant(ref aead) => $crate::ffi::crypto::AEADState::encrypt_in_place(aead, nonce, associated, buffer, tag),)*
                }
            }

            fn decrypt_in_place(&self, nonce: &[u8], associated: &[u8], buffer: &mut [u8], tag: &[u8]) -> Result<(), $crate::crypto::CryptoError> {
                match *self {
                    $($(#[$attribute])* $name::$variant(ref aead) => $crate::ffi::crypto::AEADState::decrypt_in_place(aead, nonce, associated, buffer, tag),)*
                }
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

/// Exports the functions of an [`AEADState`] type under `$prefix`, after its
/// constructors: `_free`, `_clone`, `_nonce_size`, `_tag_size`,
/// `_encrypt_in_place` and `_decrypt_in_place`.
#[macro_export]
macro_rules! ffi_aead {
    ($type:ty, $prefix:literal, $constant:ident) => {
        $crate::ffi_exports! {
            const $constant;
            /// Releases the AEAD, zeroizing its key. Does nothing if `aead` is null.
            pub unsafe extern "C" fn free = concat!($prefix, "_free"); (aead: *mut $type) {
                // SAFETY: the caller passes null or a handle created by this module.
                unsafe { $crate::ffi::Pointer::free(aead) }
            }

            /// Writes a copy of `aead` into `out`.
            pub unsafe extern "C" fn clone = concat!($prefix, "_clone"); (aead: *const $type, out: *mut *mut $type) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let aead = unsafe { $crate::ffi::Pointer::reference(aead) }?;
                    unsafe { $crate::ffi::Pointer::write_handle(out, aead.clone()) }
                })())
            }

            /// Writes the recommended nonce size into `out`.
            pub unsafe extern "C" fn nonce_size = concat!($prefix, "_nonce_size"); (aead: *const $type, out: *mut usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let aead = unsafe { $crate::ffi::Pointer::reference(aead) }?;
                    unsafe { $crate::ffi::Pointer::write(out, $crate::ffi::crypto::AEADState::nonce_size(aead)) }
                })())
            }

            /// Writes the tag size into `out`.
            pub unsafe extern "C" fn tag_size = concat!($prefix, "_tag_size"); (aead: *const $type, out: *mut usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let aead = unsafe { $crate::ffi::Pointer::reference(aead) }?;
                    unsafe { $crate::ffi::Pointer::write(out, $crate::ffi::crypto::AEADState::tag_size(aead)) }
                })())
            }

            /// Encrypts the `length` bytes at `buffer` in place and writes the tag into the `tag_length`
            /// bytes at `tag`, which must be the tag size. The nonce and the associated data must not
            /// overlap `buffer` or `tag`.
            pub unsafe extern "C" fn encrypt_in_place = concat!($prefix, "_encrypt_in_place"); (aead: *const $type, nonce: *const u8, nonce_length: usize, associated: *const u8, associated_length: usize, buffer: *mut u8, length: usize, tag: *mut u8, tag_length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    for (input, input_length) in [(nonce, nonce_length), (associated, associated_length)] {
                        $crate::ffi::Pointer::check_disjoint(input, input_length, buffer, length)?;
                        $crate::ffi::Pointer::check_disjoint(input, input_length, tag, tag_length)?;
                    }
                    $crate::ffi::Pointer::check_disjoint(buffer, length, tag, tag_length)?;
                    // SAFETY: the caller passes a valid handle, readable bytes and writable byte ranges.
                    let aead = unsafe { $crate::ffi::Pointer::reference(aead) }?;
                    let nonce = unsafe { $crate::ffi::Pointer::slice(nonce, nonce_length) }?;
                    let associated = unsafe { $crate::ffi::Pointer::slice(associated, associated_length) }?;
                    let buffer = unsafe { $crate::ffi::Pointer::slice_mut(buffer, length) }?;
                    let tag = unsafe { $crate::ffi::Pointer::slice_mut(tag, tag_length) }?;
                    $crate::ffi::crypto::AEADState::encrypt_in_place(aead, nonce, associated, buffer, tag).map_err(|error| $crate::ffi::ToStatus::to_status(&error))
                })())
            }

            /// Decrypts the `length` bytes at `buffer` in place if the `tag_length` bytes at `tag`
            /// authenticate them and the associated data; otherwise fails with AuthenticationFailed and
            /// leaves no plaintext in `buffer`. The other inputs must not overlap `buffer`.
            pub unsafe extern "C" fn decrypt_in_place = concat!($prefix, "_decrypt_in_place"); (aead: *const $type, nonce: *const u8, nonce_length: usize, associated: *const u8, associated_length: usize, buffer: *mut u8, length: usize, tag: *const u8, tag_length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    for (input, input_length) in [(nonce, nonce_length), (associated, associated_length), (tag, tag_length)] {
                        $crate::ffi::Pointer::check_disjoint(input, input_length, buffer, length)?;
                    }
                    // SAFETY: the caller passes a valid handle, readable bytes and a writable byte range.
                    let aead = unsafe { $crate::ffi::Pointer::reference(aead) }?;
                    let nonce = unsafe { $crate::ffi::Pointer::slice(nonce, nonce_length) }?;
                    let associated = unsafe { $crate::ffi::Pointer::slice(associated, associated_length) }?;
                    let tag = unsafe { $crate::ffi::Pointer::slice(tag, tag_length) }?;
                    let buffer = unsafe { $crate::ffi::Pointer::slice_mut(buffer, length) }?;
                    $crate::ffi::crypto::AEADState::decrypt_in_place(aead, nonce, associated, buffer, tag).map_err(|error| $crate::ffi::ToStatus::to_status(&error))
                })())
            }
        }
    };
}
