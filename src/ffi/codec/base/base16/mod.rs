//! The C ABI of [`crate::codec::base::base16`].

use crate::codec::base::base16::Base16;
use crate::codec::base::{Alphabet, BitEncoding};
use crate::ffi::Status;
use crate::ffi::{Definition, Function, Module, Pointer, Type, Value};

impl Value for Base16 {
    const TYPE: Type = Type::Named("umilib_codec_base_base16_Base16");
}

crate::ffi_preset_functions! {
    PRESETS: Base16;
    umilib_codec_base_base16_base16_upper = Base16::UPPER, " A new handle holding `Base16::UPPER`.";
    umilib_codec_base_base16_base16_lower = Base16::LOWER, " A new handle holding `Base16::LOWER`.";
}

crate::ffi_functions! {
    const METHODS;

    /// Releases an encoding. Does nothing if `encoding` is null.
    pub unsafe extern "C" fn umilib_codec_base_base16_base16_free(encoding: *mut Base16) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(encoding) }
    }


    /// Creates a Base16 encoding with the static `alphabet`, which must encode 16 values.
    pub unsafe extern "C" fn umilib_codec_base_base16_base16_new(alphabet: *const Alphabet, out: *mut *mut Base16) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a static alphabet and a writable pointer.
            let alphabet = unsafe { Pointer::reference(alphabet) }?;

            let encoding = Base16::new(*alphabet);
            // The alphabet must have 16 characters, none of them the padding character.
            if !encoding.encoding.is_valid() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write_handle(out, encoding) }
        })())
    }

    /// Writes a new handle holding a copy of the bit encoding of `encoding` into `out`.
    pub unsafe extern "C" fn umilib_codec_base_base16_base16_encoding(encoding: *const Base16, out: *mut *mut BitEncoding) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            unsafe { Pointer::write_handle(out, encoding.encoding) }
        })())
    }
}

crate::ffi_encoding_functions! { Base16; umilib_codec_base_base16_base16_maximum_encoded_length, umilib_codec_base_base16_base16_maximum_decoded_length, umilib_codec_base_base16_base16_encode_to_slice, umilib_codec_base_base16_base16_decode_to_slice, umilib_codec_base_base16_base16_try_encode, umilib_codec_base_base16_base16_encode, umilib_codec_base_base16_base16_decode; }

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "base16",
    definitions: &[Definition::Opaque {
        name: "umilib_codec_base_base16_Base16",
        documentation: " A Base16 encoding.",
    }],
    functions: &Function::concat::<{ PRESETS.len() + METHODS.len() + ENCODING.len() }>(&[PRESETS, METHODS, ENCODING]),
    modules: &[],
};
