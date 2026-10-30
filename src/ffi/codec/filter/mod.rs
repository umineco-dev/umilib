//! The C ABI of [`crate::codec::filter`].
//!
//! Every filter type exports, with the functions of [`ffi_filter!`](crate::ffi_filter),
//! `_encode` and `_decode` (in place, writing the bytes converted), `_lookahead`,
//! `_reset`, `_clone` and `_free`. The generic [`FilterChain`](crate::codec::filter::FilterChain)
//! is not exported: a caller chains the filters it holds.

#[cfg(umilib_feature = "codec-filter-bcj")]
pub mod bcj;
#[cfg(umilib_feature = "codec-filter-delta")]
pub mod delta;

use crate::ffi::Module;

/// Exports a [`Filter`](crate::codec::filter::Filter) type `$type` as the
/// opaque C type `$c_type`, with the functions named `$prefix` followed by
/// the method name, into the module `$module` as the list `FUNCTIONS`:
/// `_free`, `_clone`, `_reset`, `_lookahead`, `_encode` and `_decode`. The
/// constructors are left to the module.
#[macro_export]
macro_rules! ffi_filter {
    ($module:ident; $type:ty, $prefix:literal, $c_type:literal) => {
        impl $crate::ffi::Value for $type {
            const TYPE: $crate::ffi::Type = $crate::ffi::Type::Named($c_type);
        }

        /// The functions of the type, in their own module so that their Rust names are unique.
        pub mod $module {
            use super::*;

            $crate::ffi_exports! {
                const FUNCTIONS;
                /// Releases the filter. Does nothing if `state` is null.
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

                /// Starts a new stream with the same parameters.
                pub unsafe extern "C" fn reset = concat!($prefix, "_reset"); (state: *mut $type) -> *const $crate::ffi::Status {
                    $crate::ffi::Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle.
                        $crate::codec::filter::Filter::reset(unsafe { $crate::ffi::Pointer::reference_mut(state) }?);
                        Ok(())
                    })())
                }

                /// Writes into `out` the most bytes at the end of a piece the filter may leave unconverted.
                pub unsafe extern "C" fn lookahead = concat!($prefix, "_lookahead"); (state: *const $type, out: *mut usize) -> *const $crate::ffi::Status {
                    $crate::ffi::Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle and a writable pointer.
                        let state = unsafe { $crate::ffi::Pointer::reference(state) }?;
                        unsafe { $crate::ffi::Pointer::write(out, $crate::codec::filter::Filter::lookahead(state)) }
                    })())
                }

                /// Encodes in place the bytes it can of the `length` bytes at `data` (the stream after
                /// what it converted before) and writes how many into `converted`.
                pub unsafe extern "C" fn encode = concat!($prefix, "_encode"); (state: *mut $type, data: *mut u8, length: usize, converted: *mut usize) -> *const $crate::ffi::Status {
                    $crate::ffi::Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle, writable bytes and a writable pointer.
                        let state = unsafe { $crate::ffi::Pointer::reference_mut(state) }?;
                        let data = unsafe { $crate::ffi::Pointer::slice_mut(data, length) }?;
                        let done = $crate::codec::filter::Filter::encode(state, data);
                        unsafe { $crate::ffi::Pointer::write(converted, done) }
                    })())
                }

                /// Decodes in place the bytes it can of the `length` bytes at `data` and writes how many into `converted`.
                pub unsafe extern "C" fn decode = concat!($prefix, "_decode"); (state: *mut $type, data: *mut u8, length: usize, converted: *mut usize) -> *const $crate::ffi::Status {
                    $crate::ffi::Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle, writable bytes and a writable pointer.
                        let state = unsafe { $crate::ffi::Pointer::reference_mut(state) }?;
                        let data = unsafe { $crate::ffi::Pointer::slice_mut(data, length) }?;
                        let done = $crate::codec::filter::Filter::decode(state, data);
                        unsafe { $crate::ffi::Pointer::write(converted, done) }
                    })())
                }
            }
        }
    };
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "filter",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "codec-filter-bcj")]
        bcj::MODULE,
        #[cfg(umilib_feature = "codec-filter-delta")]
        delta::MODULE,
    ],
};
