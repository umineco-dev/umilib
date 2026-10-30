//! The C ABI of [`crate::codec::asn1`].
//!
//! Tags are passed as [`CTag`] (`umilib_codec_asn1_Tag`), times as
//! [`ASN1Time`] structures. Integers, bit strings and strings are passed as
//! their contents octets, which the functions of this module check and
//! convert; object identifiers are handles because they own their contents.

#[cfg(umilib_feature = "codec-asn1-ber")]
pub mod ber;
#[cfg(umilib_feature = "codec-asn1-der")]
pub mod der;

use alloc::vec::Vec;

use crate::codec::asn1::{
    ASN1Error, ASN1Integer, ASN1Real, ASN1String, ASN1Time, BitString, ObjectIdentifier, Tag, TagClass,
};
use crate::ffi::{Buffer, Definition, Function, I128, Module, Parameter, Pointer, Status, ToStatus, Type, U128, Value};

/// The C form of a [`Tag`]: `tag_class` is 0 (universal), 1 (application),
/// 2 (context-specific) or 3 (private). It is not named `class`, which C++ reserves.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CTag {
    pub tag_class: u8,
    pub constructed: bool,
    pub number: u32,
}

impl CTag {
    pub fn decode(self) -> Result<Tag, &'static Status> {
        let class = match self.tag_class {
            0 => TagClass::Universal,
            1 => TagClass::Application,
            2 => TagClass::ContextSpecific,
            3 => TagClass::Private,
            _ => return Err(&Status::INVALID_ARGUMENT),
        };
        Ok(Tag { class, constructed: self.constructed, number: self.number })
    }

    pub fn encode(tag: Tag) -> CTag {
        CTag { tag_class: tag.class as u8, constructed: tag.constructed, number: tag.number }
    }
}

impl Value for CTag {
    const TYPE: Type = Type::Named("umilib_codec_asn1_Tag");
}

impl Value for ASN1Time {
    const TYPE: Type = Type::Named("umilib_codec_asn1_ASN1Time");
}

impl Value for ObjectIdentifier<'static> {
    const TYPE: Type = Type::Named("umilib_codec_asn1_ObjectIdentifier");
}

/// The statuses of [`ASN1Error`], one per variant.
pub struct ASN1Status;

impl ASN1Status {
    pub const UNEXPECTED_END: Status =
        Status::new(c"codec.asn1", c"UnexpectedEnd", c"the input ends inside an element");
    pub const INVALID_TAG: Status = Status::new(c"codec.asn1", c"InvalidTag", c"the identifier octets are invalid");
    pub const INVALID_LENGTH: Status = Status::new(c"codec.asn1", c"InvalidLength", c"the length octets are invalid");
    pub const UNEXPECTED_TAG: Status =
        Status::new(c"codec.asn1", c"UnexpectedTag", c"the element has another tag than expected");
    pub const INVALID_CONTENT: Status =
        Status::new(c"codec.asn1", c"InvalidContent", c"the contents are invalid for the type");
    pub const NON_CANONICAL: Status =
        Status::new(c"codec.asn1", c"NonCanonical", c"the encoding is not the DER encoding");
    pub const TRAILING_DATA: Status =
        Status::new(c"codec.asn1", c"TrailingData", c"data follows the last expected element");
    pub const TOO_DEEP: Status = Status::new(c"codec.asn1", c"TooDeep", c"elements nest too deeply");
    pub const OUT_OF_RANGE: Status =
        Status::new(c"codec.asn1", c"OutOfRange", c"a value does not fit in the requested type");
    pub const ALLOCATION_FAILED: Status =
        Status::new(c"codec.asn1", c"AllocationFailed", c"memory could not be allocated");
}

impl ToStatus for ASN1Error {
    fn to_status(&self) -> &'static Status {
        match self {
            ASN1Error::UnexpectedEnd { .. } => &ASN1Status::UNEXPECTED_END,
            ASN1Error::InvalidTag { .. } => &ASN1Status::INVALID_TAG,
            ASN1Error::InvalidLength { .. } => &ASN1Status::INVALID_LENGTH,
            ASN1Error::UnexpectedTag { .. } => &ASN1Status::UNEXPECTED_TAG,
            ASN1Error::InvalidContent { .. } => &ASN1Status::INVALID_CONTENT,
            ASN1Error::NonCanonical { .. } => &ASN1Status::NON_CANONICAL,
            ASN1Error::TrailingData { .. } => &ASN1Status::TRAILING_DATA,
            ASN1Error::TooDeep { .. } => &ASN1Status::TOO_DEEP,
            ASN1Error::OutOfRange => &ASN1Status::OUT_OF_RANGE,
            ASN1Error::AllocationFailed => &ASN1Status::ALLOCATION_FAILED,
        }
    }
}

/// Defines functions that check bytes against a character set.
macro_rules! string_checks {
    ($($name:ident = $check:path, $documentation:literal;)*) => {
        crate::ffi_functions! {
            const STRING_CHECKS;
            $(
                #[doc = $documentation]
                pub unsafe extern "C" fn $name(data: *const u8, length: usize, out: *mut bool) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes readable bytes and a writable pointer.
                        let bytes = unsafe { Pointer::slice(data, length) }?;
                        unsafe { Pointer::write(out, $check(bytes)) }
                    })())
                }
            )*
        }
    };
}

string_checks! {
    umilib_codec_asn1_asn1_string_is_printable = ASN1String::is_printable, " Writes whether the bytes are PrintableString characters into `out`.";
    umilib_codec_asn1_asn1_string_is_ia5 = ASN1String::is_ia5, " Writes whether the bytes are IA5String (ASCII) characters into `out`.";
    umilib_codec_asn1_asn1_string_is_visible = ASN1String::is_visible, " Writes whether the bytes are VisibleString characters into `out`.";
    umilib_codec_asn1_asn1_string_is_numeric = ASN1String::is_numeric, " Writes whether the bytes are NumericString characters into `out`.";
}

crate::ffi_functions! {
    const METHODS;

    /// Reads the identifier octets at byte `position` of `data`; writes the tag into `out`
    /// and the position after them into `out_next`.
    pub unsafe extern "C" fn umilib_codec_asn1_tag_decode(data: *const u8, length: usize, position: usize, out: *mut CTag, out_next: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and writable pointers.
            let input = unsafe { Pointer::slice(data, length) }?;
            if out.is_null() || out_next.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let (tag, next) = Tag::decode(input, position).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, CTag::encode(tag)) }?;
            unsafe { Pointer::write(out_next, next) }
        })())
    }

    /// Writes the identifier octets of `tag` into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_tag_encode(tag: CTag, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let tag = tag.decode()?;
            let mut encoded = Vec::new();
            tag.encode(&mut encoded);
            // SAFETY: the caller passes a writable buffer.
            unsafe { Pointer::write(out, Buffer::from_vec(encoded)) }
        })())
    }

    /// Creates an object identifier from contents octets, which are validated.
    pub unsafe extern "C" fn umilib_codec_asn1_object_identifier_new(data: *const u8, length: usize, out: *mut *mut ObjectIdentifier<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let content = unsafe { Pointer::slice(data, length) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let identifier = ObjectIdentifier::new(content).map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write_handle(out, identifier) }
        })())
    }

    /// Creates an object identifier from `count` arcs.
    pub unsafe extern "C" fn umilib_codec_asn1_object_identifier_from_arcs(arcs: *const U128, count: usize, out: *mut *mut ObjectIdentifier<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes `count` readable arcs and a writable pointer.
            let arcs: Vec<u128> = unsafe { Pointer::slice_of(arcs, count) }?.iter().map(|&arc| u128::from(arc)).collect();
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let identifier = ObjectIdentifier::from_arcs(&arcs).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, identifier) }
        })())
    }

    /// Parses dotted decimal UTF-8 `text` such as `1.2.840.113549`.
    pub unsafe extern "C" fn umilib_codec_asn1_object_identifier_parse(text: *const u8, length: usize, out: *mut *mut ObjectIdentifier<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let identifier = ObjectIdentifier::parse(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, identifier) }
        })())
    }

    /// Releases an object identifier. Does nothing if `identifier` is null.
    pub unsafe extern "C" fn umilib_codec_asn1_object_identifier_free(identifier: *mut ObjectIdentifier<'static>) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(identifier) }
    }

    /// Writes a pointer to the contents octets, valid until the identifier is released, and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_object_identifier_as_bytes(identifier: *const ObjectIdentifier<'static>, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let identifier = unsafe { Pointer::reference(identifier) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out_data, identifier.as_bytes().as_ptr()) }?;
            unsafe { Pointer::write(out_length, identifier.as_bytes().len()) }
        })())
    }

    /// Writes the dotted decimal form into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_object_identifier_to_string(identifier: *const ObjectIdentifier<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let identifier = unsafe { Pointer::reference(identifier) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(alloc::string::ToString::to_string(identifier).into_bytes())) }
        })())
    }

    /// Writes the number of arcs into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_object_identifier_arc_count(identifier: *const ObjectIdentifier<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let identifier = unsafe { Pointer::reference(identifier) }?;
            unsafe { Pointer::write(out, identifier.arcs().len()) }
        })())
    }

    /// Writes the arc at `index` into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_object_identifier_arcs(identifier: *const ObjectIdentifier<'static>, index: usize, out: *mut U128) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let identifier = unsafe { Pointer::reference(identifier) }?;
            let arc = *identifier.arcs().get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, U128::from(arc)) }
        })())
    }

    /// Writes whether two identifiers are equal into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_object_identifier_equal(a: *const ObjectIdentifier<'static>, b: *const ObjectIdentifier<'static>, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let (a, b) = (unsafe { Pointer::reference(a) }?, unsafe { Pointer::reference(b) }?);
            unsafe { Pointer::write(out, a == b) }
        })())
    }

    /// Fails with `InvalidContent` unless the bytes are valid INTEGER contents (the fewest octets).
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_integer_new(data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes.
            let bytes = unsafe { Pointer::slice(data, length) }?;
            ASN1Integer::new(bytes).map(drop).map_err(|error| error.to_status())
        })())
    }

    /// Writes the value of INTEGER contents into `out`; fails with `OutOfRange` if it does not fit.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_integer_as_i128(data: *const u8, length: usize, out: *mut I128) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(data, length) }?;
            let value = ASN1Integer::new(bytes).and_then(|integer| integer.as_i128()).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, I128::from(value)) }
        })())
    }

    /// Writes the value of non-negative INTEGER contents into `out`; fails with `OutOfRange` if it does not fit.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_integer_as_u128(data: *const u8, length: usize, out: *mut U128) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(data, length) }?;
            let value = ASN1Integer::new(bytes).and_then(|integer| integer.as_u128()).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, U128::from(value)) }
        })())
    }

    /// Writes the magnitude of non-negative INTEGER contents (without the sign octet) as a
    /// pointer into `data` and a length; fails with `OutOfRange` for negative integers.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_integer_magnitude(data: *const u8, length: usize, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(data, length) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let integer = ASN1Integer::new(bytes).map_err(|error| error.to_status())?;
            let magnitude = integer.magnitude().ok_or(&ASN1Status::OUT_OF_RANGE)?;
            unsafe { Pointer::write(out_data, magnitude.as_ptr()) }?;
            unsafe { Pointer::write(out_length, magnitude.len()) }
        })())
    }

    /// Writes the INTEGER contents of `value` into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_integer_encode_i128(value: I128, out: *mut Buffer) -> *const Status {
        let mut content = Vec::new();
        ASN1Integer::encode_i128(i128::from(value), &mut content);
        // SAFETY: the caller passes a writable buffer.
        Status::from_result(unsafe { Pointer::write(out, Buffer::from_vec(content)) })
    }

    /// Writes the INTEGER contents of the non-negative integer with the big-endian `magnitude` into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_integer_encode_unsigned(magnitude: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let magnitude = unsafe { Pointer::slice(magnitude, length) }?;
            let mut content = Vec::new();
            ASN1Integer::encode_unsigned(magnitude, &mut content);
            unsafe { Pointer::write(out, Buffer::from_vec(content)) }
        })())
    }

    /// Reads BIT STRING contents: writes the unused bits into `out_unused_bits` and a pointer
    /// into `data` to the octets, with their length.
    pub unsafe extern "C" fn umilib_codec_asn1_bit_string_decode_content(data: *const u8, length: usize, out_unused_bits: *mut u8, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and writable pointers.
            let content = unsafe { Pointer::slice(data, length) }?;
            if out_unused_bits.is_null() || out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bits = BitString::decode_content(content).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_unused_bits, bits.unused_bits()) }?;
            unsafe { Pointer::write(out_data, content[1..].as_ptr()) }?;
            unsafe { Pointer::write(out_length, bits.bytes().len()) }
        })())
    }

    /// Fails with `InvalidContent` unless `unused_bits` is 0 to 7, and 0 when `length` is 0.
    pub unsafe extern "C" fn umilib_codec_asn1_bit_string_new(unused_bits: u8, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes.
            let bytes = unsafe { Pointer::slice(data, length) }?;
            BitString::new(unused_bits, bytes).map(drop).map_err(|error| error.to_status())
        })())
    }

    /// Writes whether the unused bits of the bit string are zero, as DER requires, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_bit_string_has_zero_padding(unused_bits: u8, data: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(data, length) }?;
            let bits = BitString::new(unused_bits, bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, bits.has_zero_padding()) }
        })())
    }

    /// Writes the text of BMPString contents, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_string_decode_bmp(data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let bytes = unsafe { Pointer::slice(data, length) }?;
            let text = ASN1String::decode_bmp(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(text.into_bytes())) }
        })())
    }

    /// Writes the text of UniversalString contents, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_string_decode_universal(data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let bytes = unsafe { Pointer::slice(data, length) }?;
            let text = ASN1String::decode_universal(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(text.into_bytes())) }
        })())
    }

    /// Writes the BMPString contents holding the UTF-8 `text` into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_string_encode_bmp(text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable buffer.
            let text = unsafe { Pointer::text(text, length) }?;
            let content = ASN1String::encode_bmp(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(content)) }
        })())
    }

    /// Writes the UniversalString contents holding the UTF-8 `text` into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_string_encode_universal(text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable buffer.
            let text = unsafe { Pointer::text(text, length) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(ASN1String::encode_universal(text))) }
        })())
    }

    /// Creates a time, checking the calendar and the ranges of every field.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_time_new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8, nanosecond: u32, out: *mut ASN1Time) -> *const Status {
        Status::from_result((|| {
            let time = ASN1Time::new(year, month, day, hour, minute, second, nanosecond).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, time) }
        })())
    }

    /// Returns whether `year` is a leap year.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_time_is_leap_year(year: u16) -> bool {
        ASN1Time::is_leap_year(year)
    }

    /// Returns the number of days of `month` (1 to 12) in `year`, or 0 for other months.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_time_days_in_month(year: u16, month: u8) -> u8 {
        ASN1Time::days_in_month(year, month)
    }

    /// Writes the seconds since 1970-01-01T00:00:00Z, ignoring the fraction, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_time_to_unix_seconds(time: ASN1Time, out: *mut i64) -> *const Status {
        Status::from_result((|| {
            let time = ASN1Time::new(time.year, time.month, time.day, time.hour, time.minute, time.second, time.nanosecond).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, time.to_unix_seconds()) }
        })())
    }

    /// Writes the time `seconds` after 1970-01-01T00:00:00Z into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_time_from_unix_seconds(seconds: i64, out: *mut ASN1Time) -> *const Status {
        Status::from_result((|| {
            let time = ASN1Time::from_unix_seconds(seconds).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, time) }
        })())
    }

    /// Writes -1, 0 or 1 into `out` as `a` comes before, with or after `b` in the canonical
    /// order of X.680 section 8.6 (class, then number; the form is ignored).
    pub unsafe extern "C" fn umilib_codec_asn1_tag_compare_order(a: CTag, b: CTag, out: *mut i8) -> *const Status {
        Status::from_result((|| {
            let (a, b) = (a.decode()?, b.decode()?);
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, a.compare_order(&b) as i8) }
        })())
    }

    /// Checks `length` bytes at `data` as a list of subidentifiers (the contents of an OBJECT
    /// IDENTIFIER or a RELATIVE-OID): at least one, each minimal and within 128 bits.
    pub unsafe extern "C" fn umilib_codec_asn1_object_identifier_validate_subidentifiers(data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes.
            let content = unsafe { Pointer::slice(data, length) }?;
            ObjectIdentifier::validate_subidentifiers(content).map_err(|error| error.to_status())
        })())
    }

    /// Writes the DER contents of the REAL whose BER contents are the `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_real_to_der(data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let content = unsafe { Pointer::slice(data, length) }?;
            let der = ASN1Real::to_der(content).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Fails unless the `length` bytes at `data` are the DER contents of a REAL.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_real_validate_der(data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes.
            let content = unsafe { Pointer::slice(data, length) }?;
            ASN1Real::validate_der(content).map_err(|error| error.to_status())
        })())
    }

    /// Writes the DER contents of the GeneralizedTime whose BER contents (with a zone) are the
    /// `length` bytes at `data` into `out`, keeping every digit of the fraction.
    pub unsafe extern "C" fn umilib_codec_asn1_asn1_time_generalized_time_ber_to_der(data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let content = unsafe { Pointer::slice(data, length) }?;
            let der = ASN1Time::generalized_time_ber_to_der(content).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }
}

/// Defines functions that read times from contents octets with one of the decoders of [`ASN1Time`].
macro_rules! time_decoders {
    ($($name:ident = $decode:path, $documentation:literal;)*) => {
        crate::ffi_functions! {
            const TIME_DECODERS;
            $(
                #[doc = $documentation]
                pub unsafe extern "C" fn $name(data: *const u8, length: usize, out: *mut ASN1Time) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes readable bytes and a writable pointer.
                        let content = unsafe { Pointer::slice(data, length) }?;
                        if out.is_null() {
                            return Err(&Status::NULL_POINTER);
                        }
                        let time = $decode(content).map_err(|error| error.to_status())?;
                        unsafe { Pointer::write(out, time) }
                    })())
                }
            )*
        }
    };
}

time_decoders! {
    umilib_codec_asn1_asn1_time_decode_utc_time = ASN1Time::decode_utc_time, " Reads UTCTime contents in the DER form `YYMMDDhhmmssZ`.";
    umilib_codec_asn1_asn1_time_decode_generalized_time = ASN1Time::decode_generalized_time, " Reads GeneralizedTime contents in the DER form.";
    umilib_codec_asn1_asn1_time_decode_utc_time_ber = ASN1Time::decode_utc_time_ber, " Reads UTCTime contents in any BER form with a zone, converted to UTC.";
    umilib_codec_asn1_asn1_time_decode_generalized_time_ber = ASN1Time::decode_generalized_time_ber, " Reads GeneralizedTime contents in any BER form with a zone, converted to UTC.";
}

/// Defines functions that write the contents of a time with one of the encoders of [`ASN1Time`].
macro_rules! time_encoders {
    ($($name:ident = $method:ident, $documentation:literal;)*) => {
        crate::ffi_functions! {
            const TIME_ENCODERS;
            $(
                #[doc = $documentation]
                pub unsafe extern "C" fn $name(time: ASN1Time, out: *mut Buffer) -> *const Status {
                    Status::from_result((|| {
                        let time = ASN1Time::new(time.year, time.month, time.day, time.hour, time.minute, time.second, time.nanosecond)
                            .map_err(|error| error.to_status())?;
                        if out.is_null() {
                            return Err(&Status::NULL_POINTER);
                        }
                        let mut content = Vec::new();
                        time.$method(&mut content).map_err(|error| error.to_status())?;
                        // SAFETY: the caller passes a writable buffer, checked to be non-null above.
                        unsafe { Pointer::write(out, Buffer::from_vec(content)) }
                    })())
                }
            )*
        }
    };
}

time_encoders! {
    umilib_codec_asn1_asn1_time_encode_utc_time = encode_utc_time, " Writes UTCTime contents; fails outside 1950 to 2049 or with a fraction.";
    umilib_codec_asn1_asn1_time_encode_generalized_time = encode_generalized_time, " Writes GeneralizedTime contents in the DER form.";
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "asn1",
    definitions: &[
        Definition::Structure {
            name: "umilib_codec_asn1_Tag",
            documentation: " An identifier: tag_class (0 universal, 1 application, 2 context-specific, 3 private), form and number.",
            fields: &[
                Parameter { name: "tag_class", value: Type::U8 },
                Parameter { name: "constructed", value: Type::Bool },
                Parameter { name: "number", value: Type::U32 },
            ],
        },
        Definition::Structure {
            name: "umilib_codec_asn1_ASN1Time",
            documentation: " A moment in UTC.",
            fields: &[
                Parameter { name: "year", value: Type::U16 },
                Parameter { name: "month", value: Type::U8 },
                Parameter { name: "day", value: Type::U8 },
                Parameter { name: "hour", value: Type::U8 },
                Parameter { name: "minute", value: Type::U8 },
                Parameter { name: "second", value: Type::U8 },
                Parameter { name: "nanosecond", value: Type::U32 },
            ],
        },
        Definition::Opaque {
            name: "umilib_codec_asn1_ObjectIdentifier",
            documentation: " An OBJECT IDENTIFIER owning its contents octets.",
        },
    ],
    functions: &Function::concat::<{ STRING_CHECKS.len() + METHODS.len() + TIME_DECODERS.len() + TIME_ENCODERS.len() }>(
        &[STRING_CHECKS, METHODS, TIME_DECODERS, TIME_ENCODERS],
    ),
    modules: &[
        #[cfg(umilib_feature = "codec-asn1-ber")]
        ber::MODULE,
        #[cfg(umilib_feature = "codec-asn1-der")]
        der::MODULE,
    ],
};
