//! The C ABI of [`crate::codec::base::base64`].

use super::PaddingKind;
use crate::codec::base::base64::Base64;
use crate::codec::base::{Alphabet, BitEncoding};
use crate::ffi::Status;
use crate::ffi::{Definition, Function, Module, Pointer, Type, Value};

impl Value for Base64 {
    const TYPE: Type = Type::Named("umilib_codec_base_base64_Base64");
}

crate::ffi_preset_functions! {
    PRESETS: Base64;
    umilib_codec_base_base64_base64_standard = Base64::STANDARD, " A new handle holding `Base64::STANDARD`.";
    umilib_codec_base_base64_base64_standard_no_padding = Base64::STANDARD_NO_PADDING, " A new handle holding `Base64::STANDARD_NO_PADDING`.";
    umilib_codec_base_base64_base64_url_safe = Base64::URL_SAFE, " A new handle holding `Base64::URL_SAFE`.";
    umilib_codec_base_base64_base64_url_safe_no_padding = Base64::URL_SAFE_NO_PADDING, " A new handle holding `Base64::URL_SAFE_NO_PADDING`.";
}

crate::ffi_functions! {
    const METHODS;

    /// Releases an encoding. Does nothing if `encoding` is null.
    pub unsafe extern "C" fn umilib_codec_base_base64_base64_free(encoding: *mut Base64) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(encoding) }
    }

    /// Returns the static alphabet `Base64::STANDARD_ALPHABET`.
    pub unsafe extern "C" fn umilib_codec_base_base64_base64_standard_alphabet() -> *const Alphabet {
        static ALPHABET: Alphabet = Base64::STANDARD_ALPHABET;
        &ALPHABET
    }

    /// Returns the static alphabet `Base64::URL_SAFE_ALPHABET`.
    pub unsafe extern "C" fn umilib_codec_base_base64_base64_url_safe_alphabet() -> *const Alphabet {
        static ALPHABET: Alphabet = Base64::URL_SAFE_ALPHABET;
        &ALPHABET
    }

    /// Creates an encoding with the static `alphabet`, which must encode 64 values, and `padding`.
    pub unsafe extern "C" fn umilib_codec_base_base64_base64_new(alphabet: *const Alphabet, padding: u8, out: *mut *mut Base64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a static alphabet and a writable pointer.
            let alphabet = unsafe { Pointer::reference(alphabet) }?;

            let padding = PaddingKind::decode(padding)?;
            let encoding = Base64::new(*alphabet, padding);
            // The alphabet must have 64 characters, none of them the padding character.
            if !encoding.encoding.is_valid() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write_handle(out, encoding) }
        })())
    }

    /// Writes a new handle holding a copy of the bit encoding of `encoding` into `out`.
    pub unsafe extern "C" fn umilib_codec_base_base64_base64_encoding(encoding: *const Base64, out: *mut *mut BitEncoding) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            unsafe { Pointer::write_handle(out, encoding.encoding) }
        })())
    }
}

crate::ffi_encoding_functions! { Base64; umilib_codec_base_base64_base64_maximum_encoded_length, umilib_codec_base_base64_base64_maximum_decoded_length, umilib_codec_base_base64_base64_encode_to_slice, umilib_codec_base_base64_base64_decode_to_slice, umilib_codec_base_base64_base64_try_encode, umilib_codec_base_base64_base64_encode, umilib_codec_base_base64_base64_decode; }

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "base64",
    definitions: &[Definition::Opaque {
        name: "umilib_codec_base_base64_Base64",
        documentation: " A Base64 encoding.",
    }],
    functions: &Function::concat::<{ PRESETS.len() + METHODS.len() + ENCODING.len() }>(&[PRESETS, METHODS, ENCODING]),
    modules: &[],
};
