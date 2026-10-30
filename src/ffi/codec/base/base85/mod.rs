//! The C ABI of [`crate::codec::base::base85`].

use crate::codec::base::Alphabet;
use crate::codec::base::base85::Base85;
use crate::ffi::Status;
use crate::ffi::{Definition, Function, Module, Pointer, Type, Value};

impl Value for Base85 {
    const TYPE: Type = Type::Named("umilib_codec_base_base85_Base85");
}

crate::ffi_preset_functions! {
    PRESETS: Base85;
    umilib_codec_base_base85_base85_ascii85 = Base85::ASCII85, " A new handle holding `Base85::ASCII85`.";
    umilib_codec_base_base85_base85_ascii85_adobe = Base85::ASCII85_ADOBE, " A new handle holding `Base85::ASCII85_ADOBE`.";
    umilib_codec_base_base85_base85_z85 = Base85::Z85, " A new handle holding `Base85::Z85`.";
    umilib_codec_base_base85_base85_rfc1924 = Base85::RFC1924, " A new handle holding `Base85::RFC1924`.";
}

crate::ffi_functions! {
    const METHODS;

    /// Releases an encoding. Does nothing if `encoding` is null.
    pub unsafe extern "C" fn umilib_codec_base_base85_base85_free(encoding: *mut Base85) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(encoding) }
    }

    /// Returns the static alphabet `Base85::ASCII85_ALPHABET`.
    pub unsafe extern "C" fn umilib_codec_base_base85_base85_ascii85_alphabet() -> *const Alphabet {
        static ALPHABET: Alphabet = Base85::ASCII85_ALPHABET;
        &ALPHABET
    }

    /// Returns the static alphabet `Base85::Z85_ALPHABET`.
    pub unsafe extern "C" fn umilib_codec_base_base85_base85_z85_alphabet() -> *const Alphabet {
        static ALPHABET: Alphabet = Base85::Z85_ALPHABET;
        &ALPHABET
    }

    /// Returns the static alphabet `Base85::RFC1924_ALPHABET`.
    pub unsafe extern "C" fn umilib_codec_base_base85_base85_rfc1924_alphabet() -> *const Alphabet {
        static ALPHABET: Alphabet = Base85::RFC1924_ALPHABET;
        &ALPHABET
    }


    /// Writes the delimiter lengths of `encoding`, before and after, into `out_start` and `out_end`.
    pub unsafe extern "C" fn umilib_codec_base_base85_base85_delimiter_lengths(encoding: *const Base85, out_start: *mut usize, out_end: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            if out_start.is_null() || out_end.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let (start, end) = encoding.delimiter_lengths();
            unsafe { Pointer::write(out_start, start) }?;
            unsafe { Pointer::write(out_end, end) }
        })())
    }

    /// Writes whether `encoding` has delimiters into `out_has_delimiters`, and copies of the
    /// delimiters before and after the text into `out_start` and `out_end`.
    pub unsafe extern "C" fn umilib_codec_base_base85_base85_delimiters(encoding: *const Base85, out_has_delimiters: *mut bool, out_start: *mut crate::ffi::Buffer, out_end: *mut crate::ffi::Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            if out_has_delimiters.is_null() || out_start.is_null() || out_end.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let (start, end) = encoding.delimiters.unwrap_or((b"", b""));
            unsafe { Pointer::write(out_has_delimiters, encoding.delimiters.is_some()) }?;
            unsafe { Pointer::write(out_start, crate::ffi::Buffer::from_vec(start.to_vec())) }?;
            unsafe { Pointer::write(out_end, crate::ffi::Buffer::from_vec(end.to_vec())) }
        })())
    }

    /// Writes the five digits of `value`, most significant first, into the 5 bytes at `out`.
    pub unsafe extern "C" fn umilib_codec_base_base85_base85_encode_group(encoding: *const Base85, value: u32, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and 5 writable bytes.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            let out = unsafe { Pointer::slice_mut(out, 5) }?;
            let mut digits = [0u8; 5];
            encoding.encode_group(value, &mut digits);
            out.copy_from_slice(&digits);
            Ok(())
        })())
    }

    /// Writes the settings of `encoding`: whether it has a zero-group character and which,
    /// whether partial groups are allowed and whether white space is ignored.
    pub unsafe extern "C" fn umilib_codec_base_base85_base85_settings(encoding: *const Base85, out_has_zero_group: *mut bool, out_zero_group: *mut u8, out_partial_groups: *mut bool, out_ignore_whitespace: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            if out_has_zero_group.is_null() || out_zero_group.is_null() || out_partial_groups.is_null() || out_ignore_whitespace.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out_has_zero_group, encoding.zero_group.is_some()) }?;
            unsafe { Pointer::write(out_zero_group, encoding.zero_group.unwrap_or(0)) }?;
            unsafe { Pointer::write(out_partial_groups, encoding.partial_groups) }?;
            unsafe { Pointer::write(out_ignore_whitespace, encoding.ignore_whitespace) }
        })())
    }
}

crate::ffi_encoding_functions! { Base85; umilib_codec_base_base85_base85_maximum_encoded_length, umilib_codec_base_base85_base85_maximum_decoded_length, umilib_codec_base_base85_base85_encode_to_slice, umilib_codec_base_base85_base85_decode_to_slice, umilib_codec_base_base85_base85_try_encode, umilib_codec_base_base85_base85_encode, umilib_codec_base_base85_base85_decode; }

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "base85",
    definitions: &[Definition::Opaque {
        name: "umilib_codec_base_base85_Base85",
        documentation: " A Base85 encoding.",
    }],
    functions: &Function::concat::<{ PRESETS.len() + METHODS.len() + ENCODING.len() }>(&[PRESETS, METHODS, ENCODING]),
    modules: &[],
};
