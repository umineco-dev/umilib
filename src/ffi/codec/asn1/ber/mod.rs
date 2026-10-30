//! The C ABI of [`crate::codec::asn1::ber`].
//!
//! Elements are [`CBERElement`] structures whose pointers borrow the input
//! of the reader they were read from. Strings that BER may split into
//! segments are returned as joined copies in buffers.

use alloc::vec::Vec;

use super::CTag;
use crate::codec::asn1::ber::{BERElement, BERReader};
use crate::codec::asn1::{ASN1Time, ObjectIdentifier, Tag};
use crate::ffi::{Buffer, Definition, Function, Module, Parameter, Pointer, Status, ToStatus, Type, Value};

/// The C form of a [`BERElement`], borrowing the input of its reader.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CBERElement {
    pub tag: CTag,
    pub content: *const u8,
    pub content_length: usize,
    pub encoding: *const u8,
    pub encoding_length: usize,
    pub position: usize,
    pub content_position: usize,
    pub indefinite: bool,
    pub depth: usize,
    pub maximum_depth: usize,
}

impl CBERElement {
    pub fn encode(element: &BERElement<'_>) -> CBERElement {
        CBERElement {
            tag: CTag::encode(element.tag),
            content: element.content.as_ptr(),
            content_length: element.content.len(),
            encoding: element.encoding.as_ptr(),
            encoding_length: element.encoding.len(),
            position: element.position,
            content_position: element.content_position,
            indefinite: element.indefinite,
            depth: element.depth,
            maximum_depth: element.maximum_depth,
        }
    }

    /// The element again, borrowing the input it points into.
    ///
    /// # Safety
    ///
    /// The structure must come from a reader of this module whose input is still valid.
    pub unsafe fn decode(&self) -> Result<BERElement<'static>, &'static Status> {
        let tag = self.tag.decode()?;
        // SAFETY: guaranteed by the caller.
        let content = unsafe { Pointer::slice(self.content, self.content_length) }?;
        let encoding = unsafe { Pointer::slice(self.encoding, self.encoding_length) }?;
        Ok(BERElement {
            tag,
            content,
            encoding,
            position: self.position,
            content_position: self.content_position,
            indefinite: self.indefinite,
            depth: self.depth,
            maximum_depth: self.maximum_depth,
        })
    }
}

impl Value for CBERElement {
    const TYPE: Type = Type::Named("umilib_codec_asn1_ber_BERElement");
}

impl Value for BERReader<'static> {
    const TYPE: Type = Type::Named("umilib_codec_asn1_ber_BERReader");
}

crate::ffi_functions! {
    const READER;

    /// Creates a reader over `length` bytes at `data`, which must stay valid and unchanged
    /// while the reader, readers nested in it and elements read from it are used.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_new(data: *const u8, length: usize, out: *mut *mut BERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller keeps `data` valid while the reader is used, and passes a writable pointer.
            let input = unsafe { Pointer::slice(data, length) }?;
            unsafe { Pointer::write_handle(out, BERReader::new(input)) }
        })())
    }
    /// Writes a new reader equal to `reader` with another nesting limit into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_with_maximum_depth(reader: *const BERReader<'static>, maximum_depth: usize, out: *mut *mut BERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write_handle(out, reader.with_maximum_depth(maximum_depth)) }
        })())
    }
    /// Writes the offset of the next element in the outermost input into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_position(reader: *const BERReader<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.position()) }
        })())
    }
    /// Writes the nesting depth into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_depth(reader: *const BERReader<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.depth()) }
        })())
    }
    /// Writes whether no element is left into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_is_empty(reader: *const BERReader<'static>, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.is_empty()) }
        })())
    }
    /// Fails with `TrailingData` if any element is left.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_finish(reader: *const BERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference(reader) }?.finish().map_err(|error| error.to_status())
        })())
    }
    /// Writes the next element into `out` without moving.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_peek(reader: *const BERReader<'static>, out: *mut CBERElement) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let element = reader.peek().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, CBERElement::encode(&element)) }
        })())
    }
    /// Reads the next element of any type into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_read_element(reader: *mut BERReader<'static>, out: *mut CBERElement) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let element = reader.read_element().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, CBERElement::encode(&element)) }
        })())
    }
    /// Reads the next element, which must have `tag`, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_read_expected(reader: *mut BERReader<'static>, tag: CTag, out: *mut CBERElement) -> *const Status {
        Status::from_result((|| {
            let tag = tag.decode()?;
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let element = reader.read_expected(tag).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, CBERElement::encode(&element)) }
        })())
    }
    /// Writes whether an element is left into `out_has_tag` and its tag into `out_tag`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_peek_tag(reader: *const BERReader<'static>, out_has_tag: *mut bool, out_tag: *mut CTag) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference(reader) }?;
            if out_has_tag.is_null() || out_tag.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let tag = reader.peek_tag();
            unsafe { Pointer::write(out_has_tag, tag.is_some()) }?;
            unsafe { Pointer::write(out_tag, CTag::encode(tag.unwrap_or(Tag::universal(0, false)))) }
        })())
    }
    /// Reads the next element if it has `tag`: writes whether it did into `out_found` and the element into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_read_optional(reader: *mut BERReader<'static>, tag: CTag, out_found: *mut bool, out: *mut CBERElement) -> *const Status {
        Status::from_result((|| {
            let tag = tag.decode()?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_found.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let element = reader.read_optional(tag).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_found, element.is_some()) }?;
            if let Some(element) = element {
                unsafe { Pointer::write(out, CBERElement::encode(&element)) }?;
            }
            Ok(())
        })())
    }
    /// Reads a constructed element with `tag` and writes a new reader over its contents into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_read_constructed(reader: *mut BERReader<'static>, tag: CTag, out: *mut *mut BERReader<'static>) -> *const Status {
        Status::from_result((|| {
            let tag = tag.decode()?;
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let nested = reader.read_constructed(tag).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, nested) }
        })())
    }
    /// Reads a SEQUENCE and writes a new reader over its contents into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_read_sequence(reader: *mut BERReader<'static>, out: *mut *mut BERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let nested = reader.read_sequence().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, nested) }
        })())
    }
    /// Reads a SET and writes a new reader over its contents into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_read_set(reader: *mut BERReader<'static>, out: *mut *mut BERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let nested = reader.read_set().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, nested) }
        })())
    }
    /// Reads `[number] EXPLICIT` and writes a new reader over the tagged contents into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_read_explicit(reader: *mut BERReader<'static>, number: u32, out: *mut *mut BERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let nested = reader.read_explicit(number).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, nested) }
        })())
    }
    /// Converts the single element of `length` bytes at `data` to its DER encoding, written into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_to_der(data: *const u8, length: usize, maximum_depth: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let input = unsafe { Pointer::slice(data, length) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let der = BERReader::to_der(input, maximum_depth).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(der)) }
        })())
    }

    /// Releases a reader. Does nothing if `reader` is null.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_free(reader: *mut BERReader<'static>) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(reader) }
    }

    /// Returns whether elements of the universal type `number` are strings, which BER may split into segments.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_is_string_type(number: u32) -> bool {
        BERReader::is_string_type(number)
    }

    /// Whether elements of the universal type `number` must be constructed (SEQUENCE, SET,
    /// EXTERNAL, EMBEDDED PDV and CHARACTER STRING).
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_reader_must_be_constructed(number: u32) -> bool {
        BERReader::must_be_constructed(number)
    }
}

crate::ffi_functions! {
    const ELEMENT;

    /// Writes a new reader over the contents of a constructed `element` into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_children(element: *const CBERElement, out: *mut *mut BERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable pointer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let children = element.children().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, children) }
        })())
    }
    /// Reads the contents as a BOOLEAN (any non-zero octet is true) into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_boolean(element: *const CBERElement, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable pointer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let value = element.as_boolean().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, value) }
        })())
    }
    /// Reads the contents as a UTCTime in any BER form, converted to UTC, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_utc_time(element: *const CBERElement, out: *mut ASN1Time) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable pointer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let value = element.as_utc_time().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, value) }
        })())
    }
    /// Reads the contents as a GeneralizedTime in any BER form, converted to UTC, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_generalized_time(element: *const CBERElement, out: *mut ASN1Time) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable pointer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let value = element.as_generalized_time().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, value) }
        })())
    }
    /// Writes the contents of a string type, joining constructed segments whose tag must be `segment`, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_string_content(element: *const CBERElement, segment: CTag, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable buffer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: Vec<u8> = element.string_content(segment.decode()?).map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }
    /// Reads the contents as an OCTET STRING, joining segments, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_octet_string(element: *const CBERElement, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable buffer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: Vec<u8> = element.as_octet_string().map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }
    /// Reads the contents as a UTF8String into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_utf8_string(element: *const CBERElement, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable buffer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: Vec<u8> = element.as_utf8_string().map_err(|error| error.to_status())?.into_bytes();
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }
    /// Reads the contents as a PrintableString into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_printable_string(element: *const CBERElement, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable buffer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: Vec<u8> = element.as_printable_string().map_err(|error| error.to_status())?.into_bytes();
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }
    /// Reads the contents as an IA5String into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_ia5_string(element: *const CBERElement, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable buffer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: Vec<u8> = element.as_ia5_string().map_err(|error| error.to_status())?.into_bytes();
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }
    /// Reads the contents as a VisibleString into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_visible_string(element: *const CBERElement, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable buffer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: Vec<u8> = element.as_visible_string().map_err(|error| error.to_status())?.into_bytes();
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }
    /// Reads the contents as a NumericString into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_numeric_string(element: *const CBERElement, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable buffer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: Vec<u8> = element.as_numeric_string().map_err(|error| error.to_status())?.into_bytes();
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }
    /// Reads the contents as a BMPString, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_bmp_string(element: *const CBERElement, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable buffer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: Vec<u8> = element.as_bmp_string().map_err(|error| error.to_status())?.into_bytes();
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }
    /// Reads the contents as a UniversalString, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_universal_string(element: *const CBERElement, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable buffer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: Vec<u8> = element.as_universal_string().map_err(|error| error.to_status())?.into_bytes();
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }
    /// Checks the contents as an INTEGER and writes a pointer to them and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_integer(element: *const CBERElement, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and writable pointers.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes = element.as_integer().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads the contents as a BIT STRING, joining segments: writes the unused bits and the octets into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_bit_string(element: *const CBERElement, out_unused_bits: *mut u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and writable pointers.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out_unused_bits.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bits = element.as_bit_string().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_unused_bits, bits.unused_bits()) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(Vec::from(bits.bytes()))) }
        })())
    }
    /// Checks that the contents are a NULL.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_null(element: *const CBERElement) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            element.as_null().map_err(|error| error.to_status())
        })())
    }
    /// Reads the contents as an OBJECT IDENTIFIER into a new handle written into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_ber_ber_element_as_object_identifier(element: *const CBERElement, out: *mut *mut ObjectIdentifier<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable pointer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let identifier = element.as_object_identifier().map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write_handle(out, identifier) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ber",
    definitions: &[
        Definition::Structure {
            name: "umilib_codec_asn1_ber_BERElement",
            documentation: " One BER element; its pointers borrow the input of the reader it was read from.",
            fields: &[
                Parameter { name: "tag", value: Type::Named("umilib_codec_asn1_Tag") },
                Parameter { name: "content", value: <*const u8 as Value>::TYPE },
                Parameter { name: "content_length", value: Type::USize },
                Parameter { name: "encoding", value: <*const u8 as Value>::TYPE },
                Parameter { name: "encoding_length", value: Type::USize },
                Parameter { name: "position", value: Type::USize },
                Parameter { name: "content_position", value: Type::USize },
                Parameter { name: "indefinite", value: Type::Bool },
                Parameter { name: "depth", value: Type::USize },
                Parameter { name: "maximum_depth", value: Type::USize },
            ],
        },
        Definition::Opaque {
            name: "umilib_codec_asn1_ber_BERReader",
            documentation: " A cursor over BER elements of caller-owned bytes.",
        },
    ],
    functions: &Function::concat::<{ READER.len() + ELEMENT.len() }>(&[READER, ELEMENT]),
    modules: &[],
};
