//! The C ABI of [`crate::codec::base`].
//!
//! Encodings are handles holding a copy of a preset (such as
//! `umilib_codec_base_base64_base64_standard`). The methods of
//! [`Encoding`](crate::codec::base::Encoding) are exported for every
//! encoding type. [`Padding`] is passed as `0` (required), `1` (forbidden) or
//! `2` (indifferent). Alphabets are static and never freed; custom alphabets
//! are only available in Rust, because they borrow `'static` data.

/// Defines the methods of [`Encoding`](crate::codec::base::Encoding) for one encoding type.
#[macro_export]
macro_rules! ffi_encoding_functions {
    ($handle:ty; $maximum_encoded_length:ident, $maximum_decoded_length:ident, $encode_to_slice:ident, $decode_to_slice:ident, $try_encode:ident, $encode:ident, $decode:ident;) => {
        $crate::ffi_functions! {
            const ENCODING;

            /// Writes whether the largest encoded length of `length` bytes fits in `size_t` into
            /// `out_has_length`, and the length into `out_length`.
            pub unsafe extern "C" fn $maximum_encoded_length(encoding: *const $handle, length: usize, out_has_length: *mut bool, out_length: *mut usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    use $crate::codec::base::Encoding;
                    // SAFETY: the caller passes a valid handle and writable pointers.
                    let encoding = unsafe { $crate::ffi::Pointer::reference(encoding) }?;
                    if out_has_length.is_null() || out_length.is_null() {
                        return Err(&$crate::ffi::Status::NULL_POINTER);
                    }
                    let maximum = encoding.maximum_encoded_length(length);
                    unsafe { $crate::ffi::Pointer::write(out_has_length, maximum.is_some()) }?;
                    unsafe { $crate::ffi::Pointer::write(out_length, maximum.unwrap_or(0)) }
                })())
            }

            /// Writes the largest number of bytes decoding `length` characters can produce into `out`.
            pub unsafe extern "C" fn $maximum_decoded_length(encoding: *const $handle, length: usize, out: *mut usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    use $crate::codec::base::Encoding;
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let encoding = unsafe { $crate::ffi::Pointer::reference(encoding) }?;
                    unsafe { $crate::ffi::Pointer::write(out, encoding.maximum_decoded_length(length)) }
                })())
            }

            /// Encodes `length` bytes at `data` into the `output_length` bytes at `output`,
            /// which must not overlap them, and writes the number of characters into `out_written`.
            pub unsafe extern "C" fn $encode_to_slice(encoding: *const $handle, data: *const u8, length: usize, output: *mut u8, output_length: usize, out_written: *mut usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    use $crate::codec::base::Encoding;
                    if $crate::ffi::Pointer::overlaps(data, length, output, output_length) {
                        return Err(&$crate::ffi::Status::INVALID_ARGUMENT);
                    }
                    // SAFETY: the caller passes a valid handle, readable input, writable output and a writable pointer.
                    let encoding = unsafe { $crate::ffi::Pointer::reference(encoding) }?;
                    let input = unsafe { $crate::ffi::Pointer::slice(data, length) }?;
                    let output = unsafe { $crate::ffi::Pointer::slice_mut(output, output_length) }?;
                    if out_written.is_null() {
                        return Err(&$crate::ffi::Status::NULL_POINTER);
                    }
                    let written = encoding.encode_to_slice(input, output).map_err(|error| $crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { $crate::ffi::Pointer::write(out_written, written) }
                })())
            }

            /// Decodes `length` characters at `data` into the `output_length` bytes at `output`,
            /// which must not overlap them, and writes the number of bytes into `out_written`.
            pub unsafe extern "C" fn $decode_to_slice(encoding: *const $handle, data: *const u8, length: usize, output: *mut u8, output_length: usize, out_written: *mut usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    use $crate::codec::base::Encoding;
                    if $crate::ffi::Pointer::overlaps(data, length, output, output_length) {
                        return Err(&$crate::ffi::Status::INVALID_ARGUMENT);
                    }
                    // SAFETY: the caller passes a valid handle, readable input, writable output and a writable pointer.
                    let encoding = unsafe { $crate::ffi::Pointer::reference(encoding) }?;
                    let input = unsafe { $crate::ffi::Pointer::slice(data, length) }?;
                    let output = unsafe { $crate::ffi::Pointer::slice_mut(output, output_length) }?;
                    if out_written.is_null() {
                        return Err(&$crate::ffi::Status::NULL_POINTER);
                    }
                    let written = encoding.decode_to_slice(input, output).map_err(|error| $crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { $crate::ffi::Pointer::write(out_written, written) }
                })())
            }

            /// Encodes `length` bytes at `data` into `out`; fails only if memory cannot be allocated.
            pub unsafe extern "C" fn $try_encode(encoding: *const $handle, data: *const u8, length: usize, out: *mut $crate::ffi::Buffer) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    use $crate::codec::base::Encoding;
                    // SAFETY: the caller passes a valid handle, readable input and a writable buffer.
                    let encoding = unsafe { $crate::ffi::Pointer::reference(encoding) }?;
                    let input = unsafe { $crate::ffi::Pointer::slice(data, length) }?;
                    if out.is_null() {
                        return Err(&$crate::ffi::Status::NULL_POINTER);
                    }
                    let text = encoding.try_encode(input).map_err(|error| $crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { $crate::ffi::Pointer::write(out, $crate::ffi::Buffer::from_vec(text.into_bytes())) }
                })())
            }

            /// Like the `try_encode` function: in C, encoding reports allocation failure instead of aborting.
            pub unsafe extern "C" fn $encode(encoding: *const $handle, data: *const u8, length: usize, out: *mut $crate::ffi::Buffer) -> *const $crate::ffi::Status {
                // SAFETY: the same contract as the `try_encode` function.
                unsafe { $try_encode(encoding, data, length, out) }
            }

            /// Decodes `length` characters at `data` into `out`.
            pub unsafe extern "C" fn $decode(encoding: *const $handle, data: *const u8, length: usize, out: *mut $crate::ffi::Buffer) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    use $crate::codec::base::Encoding;
                    // SAFETY: the caller passes a valid handle, readable input and a writable buffer.
                    let encoding = unsafe { $crate::ffi::Pointer::reference(encoding) }?;
                    let input = unsafe { $crate::ffi::Pointer::slice(data, length) }?;
                    if out.is_null() {
                        return Err(&$crate::ffi::Status::NULL_POINTER);
                    }
                    let bytes = encoding.decode(input).map_err(|error| $crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { $crate::ffi::Pointer::write(out, $crate::ffi::Buffer::from_vec(bytes)) }
                })())
            }
        }
    };
}

/// Defines functions that return a new handle holding a copy of a constant.
#[macro_export]
macro_rules! ffi_preset_functions {
    ($constant:ident: $handle:ty; $($name:ident = $value:expr, $documentation:literal;)*) => {
        $crate::ffi_functions! {
            const $constant;
            $(
                #[doc = $documentation]
                pub unsafe extern "C" fn $name(out: *mut *mut $handle) -> *const $crate::ffi::Status {
                    let value: $handle = $value;
                    // SAFETY: the caller passes a writable pointer.
                    $crate::ffi::Status::from_result(unsafe { $crate::ffi::Pointer::write_handle(out, value) })
                }
            )*
        }
    };
}

#[cfg(umilib_feature = "codec-base-base16")]
pub mod base16;
#[cfg(umilib_feature = "codec-base-base32")]
pub mod base32;
#[cfg(umilib_feature = "codec-base-base58")]
pub mod base58;
#[cfg(umilib_feature = "codec-base-base64")]
pub mod base64;
#[cfg(umilib_feature = "codec-base-base85")]
pub mod base85;

use crate::codec::base::{Alphabet, AlphabetRange, BaseError, BitEncoding, Padding};
use crate::ffi::{Definition, Function, Module, Parameter, Pointer, Status, ToStatus, Type, Value};

impl Value for Alphabet {
    const TYPE: Type = Type::Named("umilib_codec_base_Alphabet");
}

impl Value for AlphabetRange {
    const TYPE: Type = Type::Named("umilib_codec_base_AlphabetRange");
}

impl Value for BitEncoding {
    const TYPE: Type = Type::Named("umilib_codec_base_BitEncoding");
}

/// The [`Padding`] values of the C ABI.
pub struct PaddingKind;

impl PaddingKind {
    pub const REQUIRED: u8 = 0;
    pub const FORBIDDEN: u8 = 1;
    pub const INDIFFERENT: u8 = 2;

    pub fn decode(kind: u8) -> Result<Padding, &'static Status> {
        match kind {
            PaddingKind::REQUIRED => Ok(Padding::Required),
            PaddingKind::FORBIDDEN => Ok(Padding::Forbidden),
            PaddingKind::INDIFFERENT => Ok(Padding::Indifferent),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    pub fn encode(padding: Padding) -> u8 {
        match padding {
            Padding::Required => PaddingKind::REQUIRED,
            Padding::Forbidden => PaddingKind::FORBIDDEN,
            Padding::Indifferent => PaddingKind::INDIFFERENT,
        }
    }
}

/// The statuses of [`BaseError`], one per variant.
pub struct BaseStatus;

impl BaseStatus {
    pub const INVALID_CHARACTER: Status =
        Status::new(c"codec.base", c"InvalidCharacter", c"a character is not part of the encoding");
    pub const INVALID_LENGTH: Status =
        Status::new(c"codec.base", c"InvalidLength", c"no valid encoding has this length");
    pub const INVALID_PADDING: Status =
        Status::new(c"codec.base", c"InvalidPadding", c"the padding is missing, misplaced or not allowed");
    pub const NON_CANONICAL: Status =
        Status::new(c"codec.base", c"NonCanonical", c"the text sets bits that must be zero");
    pub const OVERFLOW: Status =
        Status::new(c"codec.base", c"Overflow", c"a group encodes a value larger than its bytes can hold");
    pub const OUTPUT_TOO_SMALL: Status = Status::new(c"codec.base", c"OutputTooSmall", c"the output is too small");
    pub const INPUT_TOO_LONG: Status =
        Status::new(c"codec.base", c"InputTooLong", c"the input is longer than the configured maximum");
    pub const ALLOCATION_FAILED: Status =
        Status::new(c"codec.base", c"AllocationFailed", c"the output could not be allocated");
}

impl ToStatus for BaseError {
    fn to_status(&self) -> &'static Status {
        match self {
            BaseError::InvalidCharacter { .. } => &BaseStatus::INVALID_CHARACTER,
            BaseError::InvalidLength { .. } => &BaseStatus::INVALID_LENGTH,
            BaseError::InvalidPadding { .. } => &BaseStatus::INVALID_PADDING,
            BaseError::NonCanonical { .. } => &BaseStatus::NON_CANONICAL,
            BaseError::Overflow { .. } => &BaseStatus::OVERFLOW,
            BaseError::OutputTooSmall { .. } => &BaseStatus::OUTPUT_TOO_SMALL,
            BaseError::InputTooLong { .. } => &BaseStatus::INPUT_TOO_LONG,
            BaseError::AllocationFailed { .. } => &BaseStatus::ALLOCATION_FAILED,
        }
    }
}

crate::ffi_functions! {
    const METHODS;

    /// Writes the number of values `alphabet` encodes into `out`.
    pub unsafe extern "C" fn umilib_codec_base_alphabet_size(alphabet: *const Alphabet, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a static alphabet and a writable pointer.
            let alphabet = unsafe { Pointer::reference(alphabet) }?;
            unsafe { Pointer::write(out, alphabet.size()) }
        })())
    }

    /// Writes the character encoding `value`, which must be smaller than the alphabet size, into `out`.
    pub unsafe extern "C" fn umilib_codec_base_alphabet_encode(alphabet: *const Alphabet, value: u8, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a static alphabet and a writable pointer.
            let alphabet = unsafe { Pointer::reference(alphabet) }?;
            if value as usize >= alphabet.size() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write(out, alphabet.encode(value)) }
        })())
    }

    /// Writes whether `character` is part of `alphabet` into `out_valid` and its value into `out_value`.
    pub unsafe extern "C" fn umilib_codec_base_alphabet_decode(alphabet: *const Alphabet, character: u8, out_valid: *mut bool, out_value: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a static alphabet and writable pointers.
            let alphabet = unsafe { Pointer::reference(alphabet) }?;
            if out_valid.is_null() || out_value.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let value = alphabet.decode(character);
            unsafe { Pointer::write(out_valid, value.is_some()) }?;
            unsafe { Pointer::write(out_value, value.unwrap_or(0)) }
        })())
    }

    /// Returns `0xFF` if `value` is in `start..start + count` and `0` otherwise, without branching.
    pub unsafe extern "C" fn umilib_codec_base_alphabet_mask_in(value: u8, start: u8, count: u8) -> u8 {
        Alphabet::mask_in(value, start, count)
    }

    /// Writes the number of runs of `alphabet` into `out`.
    pub unsafe extern "C" fn umilib_codec_base_alphabet_range_count(alphabet: *const Alphabet, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a static alphabet and a writable pointer.
            let alphabet = unsafe { Pointer::reference(alphabet) }?;
            unsafe { Pointer::write(out, alphabet.ranges.len()) }
        })())
    }

    /// Writes the run of `alphabet` at `index` into `out`.
    pub unsafe extern "C" fn umilib_codec_base_alphabet_ranges(alphabet: *const Alphabet, index: usize, out: *mut AlphabetRange) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a static alphabet and a writable pointer.
            let alphabet = unsafe { Pointer::reference(alphabet) }?;
            let range = alphabet.ranges.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, *range) }
        })())
    }

    /// Creates a bit encoding: `bits` (1 to 7) bits per character of the static `alphabet`, which
    /// must encode `2^bits` values, with `padding` and a `padding_character` outside the alphabet.
    pub unsafe extern "C" fn umilib_codec_base_bit_encoding_new(alphabet: *const Alphabet, bits: u32, padding: u8, padding_character: u8, out: *mut *mut BitEncoding) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a static alphabet and a writable pointer.
            let alphabet = unsafe { Pointer::reference(alphabet) }?;
            let padding = PaddingKind::decode(padding)?;
            let encoding = BitEncoding { alphabet: *alphabet, bits, padding, padding_character };
            if !encoding.is_valid() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write_handle(out, encoding) }
        })())
    }

    /// Releases a bit encoding. Does nothing if `encoding` is null.
    pub unsafe extern "C" fn umilib_codec_base_bit_encoding_free(encoding: *mut BitEncoding) {
        // SAFETY: the caller passes a handle created by this library.
        unsafe { Pointer::free(encoding) }
    }

    /// Writes the bits per character, the padding and the padding character of `encoding`.
    pub unsafe extern "C" fn umilib_codec_base_bit_encoding_parameters(encoding: *const BitEncoding, out_bits: *mut u32, out_padding: *mut u8, out_padding_character: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            if out_bits.is_null() || out_padding.is_null() || out_padding_character.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out_bits, encoding.bits) }?;
            unsafe { Pointer::write(out_padding, PaddingKind::encode(encoding.padding)) }?;
            unsafe { Pointer::write(out_padding_character, encoding.padding_character) }
        })())
    }

    /// Writes a pointer to a static copy of the alphabet of `encoding`, valid until the encoding is released, into `out`.
    pub unsafe extern "C" fn umilib_codec_base_bit_encoding_alphabet(encoding: *const BitEncoding, out: *mut *const Alphabet) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            unsafe { Pointer::write(out, &encoding.alphabet as *const Alphabet) }
        })())
    }

    /// Writes the number of characters in a group into `out`.
    pub unsafe extern "C" fn umilib_codec_base_bit_encoding_group_characters(encoding: *const BitEncoding, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            unsafe { Pointer::write(out, encoding.group_characters()) }
        })())
    }

    /// Writes the number of bytes in a group into `out`.
    pub unsafe extern "C" fn umilib_codec_base_bit_encoding_group_bytes(encoding: *const BitEncoding, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            unsafe { Pointer::write(out, encoding.group_bytes()) }
        })())
    }

    /// Writes whether `remainder` characters can end the text after the last full group into `out`.
    pub unsafe extern "C" fn umilib_codec_base_bit_encoding_is_valid_remainder(encoding: *const BitEncoding, remainder: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            unsafe { Pointer::write(out, encoding.is_valid_remainder(remainder)) }
        })())
    }

    /// Writes whether the fields of `encoding` form an encoding (1 to 7 bits, an alphabet of
    /// `2^bits` characters, a padding character outside it) into `out`.
    pub unsafe extern "C" fn umilib_codec_base_bit_encoding_is_valid(encoding: *const BitEncoding, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let encoding = unsafe { Pointer::reference(encoding) }?;
            unsafe { Pointer::write(out, encoding.is_valid()) }
        })())
    }
}

crate::ffi_encoding_functions! { BitEncoding; umilib_codec_base_bit_encoding_maximum_encoded_length, umilib_codec_base_bit_encoding_maximum_decoded_length, umilib_codec_base_bit_encoding_encode_to_slice, umilib_codec_base_bit_encoding_decode_to_slice, umilib_codec_base_bit_encoding_try_encode, umilib_codec_base_bit_encoding_encode, umilib_codec_base_bit_encoding_decode; }

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "base",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_base_Alphabet",
            documentation: " The characters of an encoding; alphabets are static and never freed.",
        },
        Definition::Structure {
            name: "umilib_codec_base_AlphabetRange",
            documentation: " A run of `count` consecutive characters from `first`, encoding values from `value`;\n only used for decoding unless `canonical`.",
            fields: &[
                Parameter { name: "first", value: Type::U8 },
                Parameter { name: "count", value: Type::U8 },
                Parameter { name: "value", value: Type::U8 },
                Parameter { name: "canonical", value: Type::Bool },
            ],
        },
        Definition::Opaque {
            name: "umilib_codec_base_BitEncoding",
            documentation: " An encoding of a fixed number of bits per character.",
        },
    ],
    functions: &Function::concat::<{ METHODS.len() + ENCODING.len() }>(&[METHODS, ENCODING]),
    modules: &[
        #[cfg(umilib_feature = "codec-base-base16")]
        base16::MODULE,
        #[cfg(umilib_feature = "codec-base-base32")]
        base32::MODULE,
        #[cfg(umilib_feature = "codec-base-base58")]
        base58::MODULE,
        #[cfg(umilib_feature = "codec-base-base64")]
        base64::MODULE,
        #[cfg(umilib_feature = "codec-base-base85")]
        base85::MODULE,
    ],
};
