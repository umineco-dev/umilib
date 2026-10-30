/// Exports a [`Decompressor`](crate::codec::Decompressor) type `$type` as
/// the opaque C type `$c_type`, with the functions named `$prefix` followed
/// by the method name, into the module `$module` as the list `FUNCTIONS`:
/// `_free`, `_clone`, `_reset`, `_decompress`, `_finish` and `_decompress_to_vec`. The
/// constructors are left to the module.
#[macro_export]
macro_rules! ffi_decompressor {
    ($module:ident; $type:ty, $prefix:literal, $c_type:literal) => {
        impl $crate::ffi::Value for $type {
            const TYPE: $crate::ffi::Type = $crate::ffi::Type::Named($c_type);
        }

        /// The functions of the type, in their own module so that their Rust names are unique.
        pub mod $module {
            use super::*;

            $crate::ffi_exports! {
                const FUNCTIONS;
                /// Releases the decompressor. Does nothing if `state` is null.
                pub unsafe extern "C" fn free = concat!($prefix, "_free"); (state: *mut $type) {
                    // SAFETY: the caller passes null or a handle created by this module.
                    unsafe { $crate::ffi::Pointer::free(state) }
                }

                /// Writes a copy of `state` into `out`.
                pub unsafe extern "C" fn clone = concat!($prefix, "_clone"); (state: *const $type, out: *mut *mut $type) -> *const $crate::ffi::Status {
                    $crate::ffi::Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle and a writable pointer.
                        let state = unsafe { $crate::ffi::Pointer::reference(state) }?;
                        unsafe { $crate::ffi::Pointer::write_handle(out, state.clone()) }
                    })())
                }

                /// Returns the decompressor to the state of a new stream, keeping its configuration.
                pub unsafe extern "C" fn reset = concat!($prefix, "_reset"); (state: *mut $type) -> *const $crate::ffi::Status {
                    $crate::ffi::Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle.
                        $crate::codec::Decompressor::reset(unsafe { $crate::ffi::Pointer::reference_mut(state) }?);
                        Ok(())
                    })())
                }

                /// Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
                /// at `output` (which must not overlap) and writes what the call did into `progress`.
                pub unsafe extern "C" fn decompress = concat!($prefix, "_decompress"); (state: *mut $type, input: *const u8, input_length: usize, output: *mut u8, output_length: usize, progress: *mut $crate::codec::Progress) -> *const $crate::ffi::Status {
                    $crate::ffi::Status::from_result((|| {
                        $crate::ffi::Pointer::check_disjoint(input, input_length, output, output_length)?;
                        // SAFETY: the caller passes a valid handle, readable and writable byte ranges and a writable progress.
                        let state = unsafe { $crate::ffi::Pointer::reference_mut(state) }?;
                        let input = unsafe { $crate::ffi::Pointer::slice(input, input_length) }?;
                        let output = unsafe { $crate::ffi::Pointer::slice_mut(output, output_length) }?;
                        let result = $crate::codec::Decompressor::decompress(state, input, output).map_err(|error| $crate::ffi::ToStatus::to_status(&error))?;
                        unsafe { $crate::ffi::Pointer::write(progress, result) }
                    })())
                }

                /// Tells the decompressor that the input ended with the bytes it consumed; fails with
                /// `UnexpectedEnd` unless the stream may end there.
                pub unsafe extern "C" fn finish = concat!($prefix, "_finish"); (state: *mut $type) -> *const $crate::ffi::Status {
                    $crate::ffi::Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle.
                        let state = unsafe { $crate::ffi::Pointer::reference_mut(state) }?;
                        $crate::codec::Decompressor::finish(state).map_err(|error| $crate::ffi::ToStatus::to_status(&error))
                    })())
                }

                /// Writes the data of the stream in the `input_length` bytes at `input`, which must hold
                /// all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
                pub unsafe extern "C" fn decompress_to_vec = concat!($prefix, "_decompress_to_vec"); (state: *mut $type, input: *const u8, input_length: usize, limit: usize, out: *mut $crate::ffi::Buffer) -> *const $crate::ffi::Status {
                    $crate::ffi::Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
                        let state = unsafe { $crate::ffi::Pointer::reference_mut(state) }?;
                        let input = unsafe { $crate::ffi::Pointer::slice(input, input_length) }?;
                        let data = $crate::codec::Decompressor::decompress_to_vec(state, input, limit).map_err(|error| $crate::ffi::ToStatus::to_status(&error))?;
                        unsafe { $crate::ffi::Pointer::write(out, $crate::ffi::Buffer::from_vec(data)) }
                    })())
                }
            }
        }
    };
}
