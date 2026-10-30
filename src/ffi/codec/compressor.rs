use crate::codec::Flush;
use crate::ffi::Status;

/// The values of [`Flush`] in the C ABI.
pub struct FlushKind;

impl FlushKind {
    pub const NONE: u8 = 0;
    pub const SYNC: u8 = 1;
    pub const FINISH: u8 = 2;

    pub fn decode(kind: u8) -> Result<Flush, &'static Status> {
        match kind {
            FlushKind::NONE => Ok(Flush::None),
            FlushKind::SYNC => Ok(Flush::Sync),
            FlushKind::FINISH => Ok(Flush::Finish),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    pub fn encode(flush: Flush) -> u8 {
        match flush {
            Flush::None => FlushKind::NONE,
            Flush::Sync => FlushKind::SYNC,
            Flush::Finish => FlushKind::FINISH,
        }
    }
}

/// Exports a [`Compressor`](crate::codec::Compressor) type `$type` as the
/// opaque C type `$c_type`, with the functions named `$prefix` followed by
/// the method name, into the module `$module` as the list `FUNCTIONS`:
/// `_free`, `_clone`, `_reset`, `_compress` and `_compress_to_vec`. The
/// constructors are left to the module.
#[macro_export]
macro_rules! ffi_compressor {
    ($module:ident; $type:ty, $prefix:literal, $c_type:literal) => {
        impl $crate::ffi::Value for $type {
            const TYPE: $crate::ffi::Type = $crate::ffi::Type::Named($c_type);
        }

        /// The functions of the type, in their own module so that their Rust names are unique.
        pub mod $module {
            use super::*;

            $crate::ffi_exports! {
                const FUNCTIONS;
                /// Releases the compressor. Does nothing if `state` is null.
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

                /// Returns the compressor to the state of a new stream, keeping its parameters.
                pub unsafe extern "C" fn reset = concat!($prefix, "_reset"); (state: *mut $type) -> *const $crate::ffi::Status {
                    $crate::ffi::Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle.
                        $crate::codec::Compressor::reset(unsafe { $crate::ffi::Pointer::reference_mut(state) }?);
                        Ok(())
                    })())
                }

                /// Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
                /// `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
                /// writes what the call did into `progress`.
                pub unsafe extern "C" fn compress = concat!($prefix, "_compress"); (state: *mut $type, input: *const u8, input_length: usize, output: *mut u8, output_length: usize, flush: u8, progress: *mut $crate::codec::Progress) -> *const $crate::ffi::Status {
                    $crate::ffi::Status::from_result((|| {
                        $crate::ffi::Pointer::check_disjoint(input, input_length, output, output_length)?;
                        // SAFETY: the caller passes a valid handle, readable and writable byte ranges and a writable progress.
                        let state = unsafe { $crate::ffi::Pointer::reference_mut(state) }?;
                        let input = unsafe { $crate::ffi::Pointer::slice(input, input_length) }?;
                        let output = unsafe { $crate::ffi::Pointer::slice_mut(output, output_length) }?;
                        let flush = $crate::ffi::codec::FlushKind::decode(flush)?;
                        let result = $crate::codec::Compressor::compress(state, input, output, flush).map_err(|error| $crate::ffi::ToStatus::to_status(&error))?;
                        unsafe { $crate::ffi::Pointer::write(progress, result) }
                    })())
                }

                /// Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
                pub unsafe extern "C" fn compress_to_vec = concat!($prefix, "_compress_to_vec"); (state: *mut $type, input: *const u8, input_length: usize, out: *mut $crate::ffi::Buffer) -> *const $crate::ffi::Status {
                    $crate::ffi::Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
                        let state = unsafe { $crate::ffi::Pointer::reference_mut(state) }?;
                        let input = unsafe { $crate::ffi::Pointer::slice(input, input_length) }?;
                        let stream = $crate::codec::Compressor::compress_to_vec(state, input).map_err(|error| $crate::ffi::ToStatus::to_status(&error))?;
                        unsafe { $crate::ffi::Pointer::write(out, $crate::ffi::Buffer::from_vec(stream)) }
                    })())
                }
            }
        }
    };
}
