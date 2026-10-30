/// Exports the stream cipher functions of a type implementing
/// [`StreamCipher`](crate::crypto::StreamCipher) under `$prefix`, after its
/// constructors: `_free`, `_clone` and `_apply_keystream`.
#[macro_export]
macro_rules! ffi_stream_cipher {
    ($type:ty, $prefix:literal, $constant:ident) => {
        $crate::ffi_exports! {
            const $constant;
            /// Releases the cipher, zeroizing its state. Does nothing if `cipher` is null.
            pub unsafe extern "C" fn free = concat!($prefix, "_free"); (cipher: *mut $type) {
                // SAFETY: the caller passes null or a handle created by this module.
                unsafe { $crate::ffi::Pointer::free(cipher) }
            }

            /// Writes a copy of `cipher` into `out`; the copy continues the same key stream.
            pub unsafe extern "C" fn clone = concat!($prefix, "_clone"); (cipher: *const $type, out: *mut *mut $type) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let cipher = unsafe { $crate::ffi::Pointer::reference(cipher) }?;
                    unsafe { $crate::ffi::Pointer::write_handle(out, cipher.clone()) }
                })())
            }

            /// Xors the next `length` bytes of the key stream into the bytes at `data`.
            pub unsafe extern "C" fn apply_keystream = concat!($prefix, "_apply_keystream"); (cipher: *mut $type, data: *mut u8, length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable byte range.
                    let cipher = unsafe { $crate::ffi::Pointer::reference_mut(cipher) }?;
                    let data = unsafe { $crate::ffi::Pointer::slice_mut(data, length) }?;
                    $crate::crypto::StreamCipher::apply_keystream(cipher, data).map_err(|error| $crate::ffi::ToStatus::to_status(&error))
                })())
            }
        }
    };
}
