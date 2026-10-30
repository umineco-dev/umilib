//! The C ABI of [`crate::codec::base::base32`].

use super::PaddingKind;
use crate::codec::base::base32::Base32;
use crate::codec::base::{Alphabet, BitEncoding};
use crate::ffi::Status;
use crate::ffi::{Definition, Function, Module, Pointer, Type, Value};

impl Value for Base32 {
    const TYPE: Type = Type::Named("umilib_codec_base_base32_Base32");
}

crate::ffi_preset_functions! {
    PRESETS: Base32;
    umilib_codec_base_base32_base32_standard = Base32::STANDARD, " A new handle holding `Base32::STANDARD`.";
    umilib_codec_base_base32_base32_standard_no_padding = Base32::STANDARD_NO_PADDING, " A new handle holding `Base32::STANDARD_NO_PADDING`.";
    umilib_codec_base_base32_base32_hex = Base32::HEX, " A new handle holding `Base32::HEX`.";
    umilib_codec_base_base32_base32_hex_no_padding = Base32::HEX_NO_PADDING, " A new handle holding `Base32::HEX_NO_PADDING`.";
}

crate::ffi_functions! {
    const METHODS;

    /// Releases an encoding. Does nothing if `encoding` is null.
    pub unsafe extern "C" fn umilib_codec_base_base32_base32_free(encoding: *mut Base32) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(encoding) }
    }

    /// Returns the static alphabet `Base32::STANDARD_ALPHABET`.
    pub unsafe extern "C" fn umilib_codec_base_base32_base32_standard_alphabet() -> *const Alphabet {
        static ALPHABET: Alphabet = Base32::STANDARD_ALPHABET;
        &ALPHABET
    }

    /// Returns the static alphabet `Base32::STANDARD_ALPHABET_ANY_CASE`.
    pub unsafe extern "C" fn umilib_codec_base_base32_base32_standard_alphabet_any_case() -> *const Alphabet {
        static ALPHABET: Alphabet = Base32::STANDARD_ALPHABET_ANY_CASE;
        &ALPHABET
    }

    /// Returns the static alphabet `Base32::HEX_ALPHABET`.
    pub unsafe extern "C" fn umilib_codec_base_base32_base32_hex_alphabet() -> *const Alphabet {
        static ALPHABET: Alphabet = Base32::HEX_ALPHABET;
        &ALPHABET
    }

    /// Returns the static alphabet `Base32::HEX_ALPHABET_ANY_CASE`.
    pub unsafe extern "C" fn umilib_codec_base_base32_base32_hex_alphabet_any_case() -> *const Alphabet {
        static ALPHABET: Alphabet = Base32::HEX_ALPHABET_ANY_CASE;
        &ALPHABET
    }

    /// Creates an encoding with the static `alphabet`, which must encode 32 values, and `padding`.
    pub unsafe extern "C" fn umilib_codec_base_base32_base32_new(alphabet: *const Alphabet, padding: u8, out: *mut *mut Base32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a static alphabet and a writable pointer.
            let alphabet = unsafe { Pointer::reference(alphabet) }?;

            let padding = PaddingKind::decode(padding)?;
            let encoding = Base32::new(*alphabet, padding);
            // The alphabet must have 32 characters, none of them the padding character.
            if !encoding.encoding.is_valid() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write_handle(out, encoding) }
        })())
    }

    /// Writes a new handle holding a copy of the bit encoding of `encoding` into `out`.
    pub unsafe extern "C" fn umilib_codec_base_base32_base32_encoding(encoding: *const Base32, out: *mut *mut BitEncoding) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            unsafe { Pointer::write_handle(out, encoding.encoding) }
        })())
    }
}

crate::ffi_encoding_functions! { Base32; umilib_codec_base_base32_base32_maximum_encoded_length, umilib_codec_base_base32_base32_maximum_decoded_length, umilib_codec_base_base32_base32_encode_to_slice, umilib_codec_base_base32_base32_decode_to_slice, umilib_codec_base_base32_base32_try_encode, umilib_codec_base_base32_base32_encode, umilib_codec_base_base32_base32_decode; }

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "base32",
    definitions: &[Definition::Opaque {
        name: "umilib_codec_base_base32_Base32",
        documentation: " A Base32 encoding.",
    }],
    functions: &Function::concat::<{ PRESETS.len() + METHODS.len() + ENCODING.len() }>(&[PRESETS, METHODS, ENCODING]),
    modules: &[],
};
