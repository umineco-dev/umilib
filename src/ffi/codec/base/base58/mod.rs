//! The C ABI of [`crate::codec::base::base58`].

use crate::codec::base::Alphabet;
use crate::codec::base::base58::Base58;
use crate::ffi::Status;
use crate::ffi::{Definition, Function, Module, Pointer, Type, Value};

impl Value for Base58 {
    const TYPE: Type = Type::Named("umilib_codec_base_base58_Base58");
}

crate::ffi_preset_functions! {
    PRESETS: Base58;
    umilib_codec_base_base58_base58_bitcoin = Base58::BITCOIN, " A new handle holding `Base58::BITCOIN`.";
    umilib_codec_base_base58_base58_flickr = Base58::FLICKR, " A new handle holding `Base58::FLICKR`.";
    umilib_codec_base_base58_base58_ripple = Base58::RIPPLE, " A new handle holding `Base58::RIPPLE`.";
}

crate::ffi_functions! {
    const METHODS;

    /// Releases an encoding. Does nothing if `encoding` is null.
    pub unsafe extern "C" fn umilib_codec_base_base58_base58_free(encoding: *mut Base58) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(encoding) }
    }

    /// Returns the static alphabet `Base58::BITCOIN_ALPHABET`.
    pub unsafe extern "C" fn umilib_codec_base_base58_base58_bitcoin_alphabet() -> *const Alphabet {
        static ALPHABET: Alphabet = Base58::BITCOIN_ALPHABET;
        &ALPHABET
    }

    /// Returns the static alphabet `Base58::FLICKR_ALPHABET`.
    pub unsafe extern "C" fn umilib_codec_base_base58_base58_flickr_alphabet() -> *const Alphabet {
        static ALPHABET: Alphabet = Base58::FLICKR_ALPHABET;
        &ALPHABET
    }

    /// Returns the static alphabet `Base58::RIPPLE_ALPHABET`.
    pub unsafe extern "C" fn umilib_codec_base_base58_base58_ripple_alphabet() -> *const Alphabet {
        static ALPHABET: Alphabet = Base58::RIPPLE_ALPHABET;
        &ALPHABET
    }

    /// Creates a Base58 encoding with the static `alphabet`, which must encode 58 values.
    pub unsafe extern "C" fn umilib_codec_base_base58_base58_new(alphabet: *const Alphabet, out: *mut *mut Base58) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a static alphabet and a writable pointer.
            let alphabet = unsafe { Pointer::reference(alphabet) }?;
            if alphabet.size() != 58 {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write_handle(out, Base58::new(*alphabet)) }
        })())
    }

    /// Writes a new handle holding `encoding` with another length limit into `out`.
    pub unsafe extern "C" fn umilib_codec_base_base58_base58_with_maximum_length(encoding: *const Base58, maximum_length: usize, out: *mut *mut Base58) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            unsafe { Pointer::write_handle(out, encoding.with_maximum_length(maximum_length)) }
        })())
    }

    /// Writes the length limit of `encoding` into `out`.
    pub unsafe extern "C" fn umilib_codec_base_base58_base58_maximum_length(encoding: *const Base58, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            unsafe { Pointer::write(out, encoding.maximum_length) }
        })())
    }

    /// Fails with `InputTooLong` if `length` exceeds the limit of `encoding`.
    pub unsafe extern "C" fn umilib_codec_base_base58_base58_check_length(encoding: *const Base58, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            encoding.check_length(length).map_err(|error| crate::ffi::ToStatus::to_status(&error))
        })())
    }
}

crate::ffi_encoding_functions! { Base58; umilib_codec_base_base58_base58_maximum_encoded_length, umilib_codec_base_base58_base58_maximum_decoded_length, umilib_codec_base_base58_base58_encode_to_slice, umilib_codec_base_base58_base58_decode_to_slice, umilib_codec_base_base58_base58_try_encode, umilib_codec_base_base58_base58_encode, umilib_codec_base_base58_base58_decode; }

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "base58",
    definitions: &[Definition::Opaque {
        name: "umilib_codec_base_base58_Base58",
        documentation: " A Base58 encoding.",
    }],
    functions: &Function::concat::<{ PRESETS.len() + METHODS.len() + ENCODING.len() }>(&[PRESETS, METHODS, ENCODING]),
    modules: &[],
};
