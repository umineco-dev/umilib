//! The C ABI of [`crate::codec::filter::delta`].

use crate::codec::filter::delta::DeltaFilter;
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus};

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new Delta filter of `distance` (1 to 256) bytes into `out`.
    pub unsafe extern "C" fn umilib_codec_filter_delta_delta_filter_new(distance: usize, out: *mut *mut DeltaFilter) -> *const Status {
        Status::from_result((|| {
            let filter = DeltaFilter::new(distance).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, filter) }
        })())
    }
}

crate::ffi_filter!(filter; DeltaFilter, "umilib_codec_filter_delta_delta_filter", "umilib_codec_filter_delta_DeltaFilter");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "delta",
    definitions: &[Definition::Opaque {
        name: "umilib_codec_filter_delta_DeltaFilter",
        documentation: " The Delta filter (.xz format specification, section 5.3.3).",
    }],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + filter::FUNCTIONS.len() }>(&[
        CONSTRUCTORS,
        filter::FUNCTIONS,
    ]),
    modules: &[],
};
