//! The C ABI of [`crate::codec::asn1::der`].
//!
//! Elements are [`CDERElement`] structures whose pointers borrow the input
//! of the reader they were read from: the input must stay valid while they
//! are used. Constructed elements are written from a second writer holding
//! their contents.

use alloc::vec::Vec;

use super::CTag;
use crate::codec::asn1::der::{DERElement, DERReader, DERWriter};
use crate::codec::asn1::{ASN1Time, BitString, ObjectIdentifier, Tag};
use crate::ffi::{Buffer, Definition, Function, I128, Module, Parameter, Pointer, Status, ToStatus, Type, Value};

/// The C form of a [`DERElement`], borrowing the input of its reader.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CDERElement {
    pub tag: CTag,
    pub content: *const u8,
    pub content_length: usize,
    pub encoding: *const u8,
    pub encoding_length: usize,
    pub position: usize,
}

impl CDERElement {
    pub fn encode(element: &DERElement<'_>) -> CDERElement {
        CDERElement {
            tag: CTag::encode(element.tag),
            content: element.content.as_ptr(),
            content_length: element.content.len(),
            encoding: element.encoding.as_ptr(),
            encoding_length: element.encoding.len(),
            position: element.position,
        }
    }

    /// The element again, borrowing the input it points into.
    ///
    /// # Safety
    ///
    /// The structure must come from a reader of this module whose input is still valid.
    pub unsafe fn decode(&self) -> Result<DERElement<'static>, &'static Status> {
        let tag = self.tag.decode()?;
        // SAFETY: guaranteed by the caller.
        let content = unsafe { Pointer::slice(self.content, self.content_length) }?;
        let encoding = unsafe { Pointer::slice(self.encoding, self.encoding_length) }?;
        Ok(DERElement { tag, content, encoding, position: self.position })
    }
}

impl Value for CDERElement {
    const TYPE: Type = Type::Named("umilib_codec_asn1_der_DERElement");
}

impl Value for DERReader<'static> {
    const TYPE: Type = Type::Named("umilib_codec_asn1_der_DERReader");
}

/// Borrowed input of the `der_writer_write_*` functions, which must not lie in
/// the bytes the writer owns: appending reallocates them, and the C contract
/// forbids reading memory the call also modifies.
pub struct DERWriterInput;

impl DERWriterInput {
    /// The `length` bytes at `data`, if they are not part of the bytes of `writer`.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn slice<'a>(
        writer: *const DERWriter,
        data: *const u8,
        length: usize,
    ) -> Result<&'a [u8], &'static Status> {
        // SAFETY: the caller passes a valid handle; the reference ends here.
        let bytes = unsafe { Pointer::reference(writer) }?.as_bytes();
        if Pointer::overlaps(data, length, bytes.as_ptr(), bytes.len()) {
            return Err(&Status::INVALID_ARGUMENT);
        }
        // SAFETY: the caller passes readable bytes.
        unsafe { Pointer::slice(data, length) }
    }

    /// Like [`DERWriterInput::slice`], for UTF-8 text.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn text<'a>(
        writer: *const DERWriter,
        data: *const u8,
        length: usize,
    ) -> Result<&'a str, &'static Status> {
        // SAFETY: the same contract.
        let bytes = unsafe { DERWriterInput::slice(writer, data, length) }?;
        core::str::from_utf8(bytes).map_err(|_| &Status::INVALID_UTF8)
    }
}

impl Value for DERWriter {
    const TYPE: Type = Type::Named("umilib_codec_asn1_der_DERWriter");
}

crate::ffi_functions! {
    const READER;

    /// Creates a reader over `length` bytes at `data`, which must stay valid and unchanged
    /// while the reader, readers nested in it and elements read from it are used.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_new(data: *const u8, length: usize, out: *mut *mut DERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller keeps `data` valid while the reader is used, and passes a writable pointer.
            let input = unsafe { Pointer::slice(data, length) }?;
            unsafe { Pointer::write_handle(out, DERReader::new(input)) }
        })())
    }
    /// Writes a new reader equal to `reader` with another nesting limit into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_with_maximum_depth(reader: *const DERReader<'static>, maximum_depth: usize, out: *mut *mut DERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write_handle(out, reader.with_maximum_depth(maximum_depth)) }
        })())
    }
    /// Writes the offset of the next element in the outermost input into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_position(reader: *const DERReader<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.position()) }
        })())
    }
    /// Writes the nesting depth into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_depth(reader: *const DERReader<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.depth()) }
        })())
    }
    /// Writes whether no element is left into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_is_empty(reader: *const DERReader<'static>, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.is_empty()) }
        })())
    }
    /// Fails with `TrailingData` if any element is left.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_finish(reader: *const DERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference(reader) }?.finish().map_err(|error| error.to_status())
        })())
    }
    /// Writes the next element into `out` without moving.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_peek(reader: *const DERReader<'static>, out: *mut CDERElement) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let element = reader.peek().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, CDERElement::encode(&element)) }
        })())
    }
    /// Writes whether an element is left into `out_has_tag` and its tag into `out_tag`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_peek_tag(reader: *const DERReader<'static>, out_has_tag: *mut bool, out_tag: *mut CTag) -> *const Status {
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
    /// Reads the next element of any type into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_element(reader: *mut DERReader<'static>, out: *mut CDERElement) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let element = reader.read_element().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, CDERElement::encode(&element)) }
        })())
    }
    /// Reads the next element, which must have `tag`, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_expected(reader: *mut DERReader<'static>, tag: CTag, out: *mut CDERElement) -> *const Status {
        Status::from_result((|| {
            let tag = tag.decode()?;
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let element = reader.read_expected(tag).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, CDERElement::encode(&element)) }
        })())
    }
    /// Reads the next element if it has `tag`: writes whether it did into `out_found` and the element into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_optional(reader: *mut DERReader<'static>, tag: CTag, out_found: *mut bool, out: *mut CDERElement) -> *const Status {
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
                unsafe { Pointer::write(out, CDERElement::encode(&element)) }?;
            }
            Ok(())
        })())
    }
    /// Writes a new reader over the contents of `element`, one level deeper than `reader`, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_nested(reader: *const DERReader<'static>, element: *const CDERElement, out: *mut *mut DERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, an element read from it and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let nested = reader.nested(&element).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, nested) }
        })())
    }
    /// Reads a constructed element with `tag` and writes a new reader over its contents into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_constructed(reader: *mut DERReader<'static>, tag: CTag, out: *mut *mut DERReader<'static>) -> *const Status {
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
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_sequence(reader: *mut DERReader<'static>, out: *mut *mut DERReader<'static>) -> *const Status {
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
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_set(reader: *mut DERReader<'static>, out: *mut *mut DERReader<'static>) -> *const Status {
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
    /// Reads a SET OF, whose components must be sorted, and writes a new reader over them into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_set_of(reader: *mut DERReader<'static>, out: *mut *mut DERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let nested = reader.read_set_of().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, nested) }
        })())
    }
    /// Reads `[number] EXPLICIT` and writes a new reader over the tagged contents into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_explicit(reader: *mut DERReader<'static>, number: u32, out: *mut *mut DERReader<'static>) -> *const Status {
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
    /// Reads `[number] EXPLICIT` if it is next: writes whether it was into `out_found` and a new reader (or null) into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_optional_explicit(reader: *mut DERReader<'static>, number: u32, out_found: *mut bool, out: *mut *mut DERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_found.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let nested = reader.read_optional_explicit(number).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_found, nested.is_some()) }?;
            match nested {
                Some(nested) => unsafe { Pointer::write_handle(out, nested) },
                None => unsafe { Pointer::write(out, core::ptr::null_mut()) },
            }
        })())
    }
    /// Reads an INTEGER and writes a pointer to its contents into the input, and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_integer(reader: *mut DERReader<'static>, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = reader.read_integer().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads an ENUMERATED and writes a pointer to its contents into the input, and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_enumerated(reader: *mut DERReader<'static>, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = reader.read_enumerated().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads an OCTET STRING and writes a pointer to its contents into the input, and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_octet_string(reader: *mut DERReader<'static>, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = reader.read_octet_string().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads a UTF8String and writes a pointer to its contents into the input, and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_utf8_string(reader: *mut DERReader<'static>, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = reader.read_utf8_string().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads a PrintableString and writes a pointer to its contents into the input, and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_printable_string(reader: *mut DERReader<'static>, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = reader.read_printable_string().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads an IA5String and writes a pointer to its contents into the input, and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_ia5_string(reader: *mut DERReader<'static>, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = reader.read_ia5_string().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads a VisibleString and writes a pointer to its contents into the input, and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_visible_string(reader: *mut DERReader<'static>, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = reader.read_visible_string().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads a NumericString and writes a pointer to its contents into the input, and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_numeric_string(reader: *mut DERReader<'static>, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = reader.read_numeric_string().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads a BOOLEAN into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_boolean(reader: *mut DERReader<'static>, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let value = reader.read_boolean().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, value) }
        })())
    }
    /// Reads a UTCTime into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_utc_time(reader: *mut DERReader<'static>, out: *mut ASN1Time) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let value = reader.read_utc_time().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, value) }
        })())
    }
    /// Reads a GeneralizedTime into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_generalized_time(reader: *mut DERReader<'static>, out: *mut ASN1Time) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let value = reader.read_generalized_time().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, value) }
        })())
    }
    /// Reads a BMPString and writes its text, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_bmp_string(reader: *mut DERReader<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let text = reader.read_bmp_string().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(text.into_bytes())) }
        })())
    }
    /// Reads a UniversalString and writes its text, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_universal_string(reader: *mut DERReader<'static>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let text = reader.read_universal_string().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(text.into_bytes())) }
        })())
    }
    /// Reads a NULL.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_null(reader: *mut DERReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(reader) }?.read_null().map_err(|error| error.to_status())
        })())
    }
    /// Reads a BIT STRING: writes its unused bits, a pointer to its octets in the input and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_bit_string(reader: *mut DERReader<'static>, out_unused_bits: *mut u8, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_unused_bits.is_null() || out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let element = reader.peek().map_err(|error| error.to_status())?;
            let bits = reader.read_bit_string().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_unused_bits, bits.unused_bits()) }?;
            // The octets follow the unused-bits octet in the contents, which borrow the input.
            unsafe { Pointer::write(out_data, element.content[1..].as_ptr()) }?;
            unsafe { Pointer::write(out_length, bits.bytes().len()) }
        })())
    }
    /// Reads an OBJECT IDENTIFIER into a new handle written into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_read_object_identifier(reader: *mut DERReader<'static>, out: *mut *mut ObjectIdentifier<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let identifier = reader.read_object_identifier().map_err(|error| error.to_status())?.into_owned();
            unsafe { Pointer::write_handle(out, identifier) }
        })())
    }
    /// Reads length octets at byte `position` of `data`, rejecting non-minimal forms if `strict`. Writes whether
    /// the length is definite, the length, and the position after the length octets.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_decode_length(data: *const u8, length: usize, position: usize, strict: bool, out_definite: *mut bool, out_length: *mut usize, out_next: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and writable pointers.
            let input = unsafe { Pointer::slice(data, length) }?;
            if out_definite.is_null() || out_length.is_null() || out_next.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let (value, next) = DERReader::decode_length(input, position, strict).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_definite, value.is_some()) }?;
            unsafe { Pointer::write(out_length, value.unwrap_or(0)) }?;
            unsafe { Pointer::write(out_next, next) }
        })())
    }
    /// Writes -1, 0 or 1 into `out` as encodings `a` and `b` order in a DER SET OF.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_compare_encodings(a: *const u8, a_length: usize, b: *const u8, b_length: usize, out: *mut i8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let (a, b) = (unsafe { Pointer::slice(a, a_length) }?, unsafe { Pointer::slice(b, b_length) }?);
            unsafe { Pointer::write(out, DERReader::compare_encodings(a, b) as i8) }
        })())
    }
    /// Validates `length` bytes at `data` as one DER element, nested up to `maximum_depth` levels.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_validate(data: *const u8, length: usize, maximum_depth: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes.
            let input = unsafe { Pointer::slice(data, length) }?;
            DERReader::validate(input, maximum_depth).map_err(|error| error.to_status())
        })())
    }

    /// Releases a reader. Does nothing if `reader` is null.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_free(reader: *mut DERReader<'static>) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(reader) }
    }

    /// Checks the form of `element` and, for a universal primitive whose rules are known, its
    /// contents, without looking inside constructed elements.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_reader_validate_shallow(element: *const CDERElement) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            DERReader::validate_shallow(&element).map_err(|error| error.to_status())
        })())
    }
}

crate::ffi_functions! {
    const ELEMENT;

    /// Writes the offset of the contents octets in the outermost input into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_content_position(element: *const CDERElement, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable pointer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let value = element.content_position();
            unsafe { Pointer::write(out, value) }
        })())
    }
    /// Reads the contents as a BOOLEAN into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_boolean(element: *const CDERElement, out: *mut bool) -> *const Status {
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
    /// Reads the contents as a UTCTime into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_utc_time(element: *const CDERElement, out: *mut ASN1Time) -> *const Status {
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
    /// Reads the contents as a GeneralizedTime into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_generalized_time(element: *const CDERElement, out: *mut ASN1Time) -> *const Status {
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
    /// Fails with `NonCanonical` unless the element is primitive; writes its contents.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_primitive(element: *const CDERElement, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and writable pointers.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = element.primitive().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Checks the contents as an INTEGER and writes them.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_integer(element: *const CDERElement, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and writable pointers.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = element.as_integer().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads the contents as an OCTET STRING.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_octet_string(element: *const CDERElement, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and writable pointers.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = element.as_octet_string().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads the contents as a UTF8String.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_utf8_string(element: *const CDERElement, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and writable pointers.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = element.as_utf8_string().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads the contents as a PrintableString.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_printable_string(element: *const CDERElement, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and writable pointers.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = element.as_printable_string().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads the contents as an IA5String.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_ia5_string(element: *const CDERElement, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and writable pointers.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = element.as_ia5_string().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads the contents as a VisibleString.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_visible_string(element: *const CDERElement, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and writable pointers.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = element.as_visible_string().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads the contents as a NumericString.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_numeric_string(element: *const CDERElement, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and writable pointers.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = element.as_numeric_string().map_err(|error| error.to_status())?.as_bytes();
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads the contents as a TeletexString, whose octets are not interpreted.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_teletex_string(element: *const CDERElement, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and writable pointers.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bytes: &[u8] = element.as_teletex_string().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_data, bytes.as_ptr()) }?;
            unsafe { Pointer::write(out_length, bytes.len()) }
        })())
    }
    /// Reads the contents as a BMPString and writes its text, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_bmp_string(element: *const CDERElement, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable buffer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let text = element.as_bmp_string().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(text.into_bytes())) }
        })())
    }
    /// Reads the contents as a UniversalString and writes its text, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_universal_string(element: *const CDERElement, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and a writable buffer.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let text = element.as_universal_string().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(text.into_bytes())) }
        })())
    }
    /// Checks that the contents are a NULL.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_null(element: *const CDERElement) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            element.as_null().map_err(|error| error.to_status())
        })())
    }
    /// Reads the contents as a BIT STRING: writes the unused bits, a pointer to the octets and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_bit_string(element: *const CDERElement, out_unused_bits: *mut u8, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes an element read from a live reader and writable pointers.
            let element = unsafe { Pointer::reference(element)?.decode() }?;
            if out_unused_bits.is_null() || out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let bits = element.as_bit_string().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_unused_bits, bits.unused_bits()) }?;
            unsafe { Pointer::write(out_data, element.content[1..].as_ptr()) }?;
            unsafe { Pointer::write(out_length, bits.bytes().len()) }
        })())
    }
    /// Reads the contents as an OBJECT IDENTIFIER into a new handle written into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_element_as_object_identifier(element: *const CDERElement, out: *mut *mut ObjectIdentifier<'static>) -> *const Status {
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

crate::ffi_functions! {
    const WRITER;

    /// Creates an empty writer.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_new(out: *mut *mut DERWriter) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, DERWriter::new()) })
    }
    /// Writes a pointer to the bytes written so far, valid until the writer is next used, and their length.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_as_bytes(writer: *const DERWriter, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let writer = unsafe { Pointer::reference(writer) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out_data, writer.as_bytes().as_ptr()) }?;
            unsafe { Pointer::write(out_length, writer.as_bytes().len()) }
        })())
    }
    /// Moves the bytes written into `out` and releases the writer. On failure the handle is not released.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_into_bytes(writer: *mut DERWriter, out: *mut Buffer) -> *const Status {
        if writer.is_null() || out.is_null() {
            return &Status::NULL_POINTER;
        }
        // SAFETY: the caller passes a handle created by this module, which is not used afterwards.
        let writer = unsafe { alloc::boxed::Box::from_raw(writer) };
        // SAFETY: the caller passes a writable buffer, checked to be non-null above.
        Status::from_result(unsafe { Pointer::write(out, Buffer::from_vec(writer.into_bytes())) })
    }
    /// Writes the length octets of `length` in the fewest octets into `out`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_encode_length(length: usize, out: *mut Buffer) -> *const Status {
        let mut octets = Vec::new();
        DERWriter::encode_length(length, &mut octets);
        // SAFETY: the caller passes a writable buffer.
        Status::from_result(unsafe { Pointer::write(out, Buffer::from_vec(octets)) })
    }
    /// Appends an element with `tag` and the `length` bytes at `data` as contents.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_element(writer: *mut DERWriter, tag: CTag, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            let tag = tag.decode()?;
            // SAFETY: the caller passes a valid handle and readable bytes.
            let content = unsafe { DERWriterInput::slice(writer, data, length) }?;
            unsafe { Pointer::reference_mut(writer) }?.write_element(tag, content);
            Ok(())
        })())
    }
    /// Appends an encoding produced elsewhere, which must be a valid DER element.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_raw(writer: *mut DERWriter, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let encoding = unsafe { DERWriterInput::slice(writer, data, length) }?;
            unsafe { Pointer::reference_mut(writer) }?.write_raw(encoding);
            Ok(())
        })())
    }
    /// Appends a constructed element with `tag` whose contents are the bytes written to `inner`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_constructed(writer: *mut DERWriter, tag: CTag, inner: *const DERWriter) -> *const Status {
        Status::from_result((|| {
            let tag = tag.decode()?;
            // SAFETY: the caller passes two valid handles, which must differ.
            if core::ptr::eq(writer.cast_const(), inner) {
                return Err(&Status::INVALID_ARGUMENT);
            }
            let inner = unsafe { Pointer::reference(inner) }?;
            let outer = unsafe { Pointer::reference_mut(writer) }?;
            outer.write_constructed(tag, |nested| { nested.write_raw(inner.as_bytes()); Ok(()) }).map_err(|error| error.to_status())
        })())
    }
    /// Appends a SEQUENCE whose contents are the bytes written to `inner`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_sequence(writer: *mut DERWriter, inner: *const DERWriter) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes two valid handles, which must differ.
            if core::ptr::eq(writer.cast_const(), inner) {
                return Err(&Status::INVALID_ARGUMENT);
            }
            let inner = unsafe { Pointer::reference(inner) }?;
            let outer = unsafe { Pointer::reference_mut(writer) }?;
            outer.write_sequence(|nested| { nested.write_raw(inner.as_bytes()); Ok(()) }).map_err(|error| error.to_status())
        })())
    }
    /// Appends a SET whose contents are the bytes written to `inner`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_set(writer: *mut DERWriter, inner: *const DERWriter) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes two valid handles, which must differ.
            if core::ptr::eq(writer.cast_const(), inner) {
                return Err(&Status::INVALID_ARGUMENT);
            }
            let inner = unsafe { Pointer::reference(inner) }?;
            let outer = unsafe { Pointer::reference_mut(writer) }?;
            outer.write_set(|nested| { nested.write_raw(inner.as_bytes()); Ok(()) }).map_err(|error| error.to_status())
        })())
    }
    /// Appends a SET OF holding the elements written to `inner`, sorted by encoding.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_set_of(writer: *mut DERWriter, inner: *const DERWriter) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes two valid handles, which must differ.
            if core::ptr::eq(writer.cast_const(), inner) {
                return Err(&Status::INVALID_ARGUMENT);
            }
            let inner = unsafe { Pointer::reference(inner) }?;
            let outer = unsafe { Pointer::reference_mut(writer) }?;
            outer.write_set_of(|nested| { nested.write_raw(inner.as_bytes()); Ok(()) }).map_err(|error| error.to_status())
        })())
    }
    /// Appends `[number] EXPLICIT` around the element written to `inner`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_explicit(writer: *mut DERWriter, number: u32, inner: *const DERWriter) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes two valid handles, which must differ.
            if core::ptr::eq(writer.cast_const(), inner) {
                return Err(&Status::INVALID_ARGUMENT);
            }
            let inner = unsafe { Pointer::reference(inner) }?;
            let outer = unsafe { Pointer::reference_mut(writer) }?;
            outer.write_explicit(number, |nested| { nested.write_raw(inner.as_bytes()); Ok(()) }).map_err(|error| error.to_status())
        })())
    }
    /// Appends a BOOLEAN.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_boolean(writer: *mut DERWriter, value: bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let writer = unsafe { Pointer::reference_mut(writer) }?;
            writer.write_boolean(value);
            Ok(())
        })())
    }
    /// Appends an INTEGER.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_integer_i128(writer: *mut DERWriter, value: I128) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let writer = unsafe { Pointer::reference_mut(writer) }?;
            writer.write_integer_i128(i128::from(value));
            Ok(())
        })())
    }
    /// Appends an ENUMERATED.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_enumerated(writer: *mut DERWriter, value: I128) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let writer = unsafe { Pointer::reference_mut(writer) }?;
            writer.write_enumerated(i128::from(value));
            Ok(())
        })())
    }
    /// Appends a NULL.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_null(writer: *mut DERWriter) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let writer = unsafe { Pointer::reference_mut(writer) }?;
            writer.write_null();
            Ok(())
        })())
    }
    /// Appends the non-negative INTEGER with the big-endian magnitude at `data`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_integer_unsigned(writer: *mut DERWriter, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let bytes = unsafe { DERWriterInput::slice(writer, data, length) }?;
            let writer = unsafe { Pointer::reference_mut(writer) }?;
            writer.write_integer_unsigned(bytes);
            Ok(())
        })())
    }
    /// Appends an OCTET STRING.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_octet_string(writer: *mut DERWriter, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let bytes = unsafe { DERWriterInput::slice(writer, data, length) }?;
            let writer = unsafe { Pointer::reference_mut(writer) }?;
            writer.write_octet_string(bytes);
            Ok(())
        })())
    }
    /// Appends a BIT STRING; fails if its unused bits are not zero.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_bit_string(writer: *mut DERWriter, unused_bits: u8, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let bytes = unsafe { DERWriterInput::slice(writer, data, length) }?;
            let bits = BitString::new(unused_bits, bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::reference_mut(writer) }?.write_bit_string(&bits).map_err(|error| error.to_status())
        })())
    }
    /// Appends an OBJECT IDENTIFIER.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_object_identifier(writer: *mut DERWriter, identifier: *const ObjectIdentifier<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let identifier = unsafe { Pointer::reference(identifier) }?;
            unsafe { Pointer::reference_mut(writer) }?.write_object_identifier(identifier);
            Ok(())
        })())
    }
    /// Appends a UTF8String holding the UTF-8 `text`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_utf8_string(writer: *mut DERWriter, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let text = unsafe { DERWriterInput::text(writer, text, length) }?;
            unsafe { Pointer::reference_mut(writer) }?.write_utf8_string(text);
            Ok(())
        })())
    }
    /// Appends a PrintableString; fails if a character is not allowed.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_printable_string(writer: *mut DERWriter, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let text = unsafe { DERWriterInput::text(writer, text, length) }?;
            unsafe { Pointer::reference_mut(writer) }?.write_printable_string(text).map_err(|error| error.to_status())
        })())
    }
    /// Appends an IA5String; fails for characters outside ASCII.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_ia5_string(writer: *mut DERWriter, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let text = unsafe { DERWriterInput::text(writer, text, length) }?;
            unsafe { Pointer::reference_mut(writer) }?.write_ia5_string(text).map_err(|error| error.to_status())
        })())
    }
    /// Appends a VisibleString; fails if a character is not allowed.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_visible_string(writer: *mut DERWriter, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let text = unsafe { DERWriterInput::text(writer, text, length) }?;
            unsafe { Pointer::reference_mut(writer) }?.write_visible_string(text).map_err(|error| error.to_status())
        })())
    }
    /// Appends a NumericString; fails if a character is not a digit or space.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_numeric_string(writer: *mut DERWriter, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let text = unsafe { DERWriterInput::text(writer, text, length) }?;
            unsafe { Pointer::reference_mut(writer) }?.write_numeric_string(text).map_err(|error| error.to_status())
        })())
    }
    /// Appends a BMPString; fails for characters above U+FFFF.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_bmp_string(writer: *mut DERWriter, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let text = unsafe { DERWriterInput::text(writer, text, length) }?;
            unsafe { Pointer::reference_mut(writer) }?.write_bmp_string(text).map_err(|error| error.to_status())
        })())
    }
    /// Appends a UniversalString holding the UTF-8 `text`.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_universal_string(writer: *mut DERWriter, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let text = unsafe { DERWriterInput::text(writer, text, length) }?;
            unsafe { Pointer::reference_mut(writer) }?.write_universal_string(text);
            Ok(())
        })())
    }
    /// Appends a UTCTime; fails outside 1950 to 2049 or with a fraction.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_utc_time(writer: *mut DERWriter, time: ASN1Time) -> *const Status {
        Status::from_result((|| {
            let time = ASN1Time::new(time.year, time.month, time.day, time.hour, time.minute, time.second, time.nanosecond).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(writer) }?.write_utc_time(&time).map_err(|error| error.to_status())
        })())
    }
    /// Appends a GeneralizedTime.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_write_generalized_time(writer: *mut DERWriter, time: ASN1Time) -> *const Status {
        Status::from_result((|| {
            let time = ASN1Time::new(time.year, time.month, time.day, time.hour, time.minute, time.second, time.nanosecond).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(writer) }?.write_generalized_time(&time).map_err(|error| error.to_status())
        })())
    }

    /// Releases a writer. Does nothing if `writer` is null.
    pub unsafe extern "C" fn umilib_codec_asn1_der_der_writer_free(writer: *mut DERWriter) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(writer) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "der",
    definitions: &[
        Definition::Structure {
            name: "umilib_codec_asn1_der_DERElement",
            documentation: " One DER element; its pointers borrow the input of the reader it was read from.",
            fields: &[
                Parameter { name: "tag", value: Type::Named("umilib_codec_asn1_Tag") },
                Parameter { name: "content", value: <*const u8 as Value>::TYPE },
                Parameter { name: "content_length", value: Type::USize },
                Parameter { name: "encoding", value: <*const u8 as Value>::TYPE },
                Parameter { name: "encoding_length", value: Type::USize },
                Parameter { name: "position", value: Type::USize },
            ],
        },
        Definition::Opaque {
            name: "umilib_codec_asn1_der_DERReader",
            documentation: " A cursor over DER elements of caller-owned bytes.",
        },
        Definition::Opaque { name: "umilib_codec_asn1_der_DERWriter", documentation: " Writes DER elements." },
    ],
    functions: &Function::concat::<{ READER.len() + ELEMENT.len() + WRITER.len() }>(&[READER, ELEMENT, WRITER]),
    modules: &[],
};
