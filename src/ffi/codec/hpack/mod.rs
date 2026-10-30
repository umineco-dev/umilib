//! The C ABI of [`crate::codec::hpack`].
//!
//! An encoder, a decoder and a list of fields are handles; the
//! configurations are structures passed by value. A list of fields keeps
//! each field's name, value and whether it is sensitive (never indexed,
//! RFC 7541 §7.1.3).

use alloc::vec::Vec;

use crate::codec::hpack::{HPACKDecoder, HPACKDecoderConfig, HPACKEncoder, HPACKEncoderConfig, HPACKError, HPACKField};
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};

/// The statuses of [`HPACKError`], one per variant.
pub struct HPACKStatus;

impl HPACKStatus {
    pub const TRUNCATED: Status =
        Status::new(c"codec.hpack", c"Truncated", c"the field block ends inside a representation");
    pub const INTEGER_OVERFLOW: Status =
        Status::new(c"codec.hpack", c"IntegerOverflow", c"an integer larger than HPACK takes");
    pub const INVALID_INDEX: Status = Status::new(c"codec.hpack", c"InvalidIndex", c"an index of no table entry");
    pub const INVALID_HUFFMAN: Status =
        Status::new(c"codec.hpack", c"InvalidHuffman", c"a Huffman-coded string that is not valid");
    pub const INVALID_TABLE_SIZE_UPDATE: Status =
        Status::new(c"codec.hpack", c"InvalidTableSizeUpdate", c"a dynamic table size update that is not allowed");
    pub const STRING_TOO_LONG: Status =
        Status::new(c"codec.hpack", c"StringTooLong", c"a string longer than the decoder's limit");
    pub const FIELD_LIST_TOO_LARGE: Status =
        Status::new(c"codec.hpack", c"FieldListTooLarge", c"the fields are larger than the decoder's limit");
    pub const NO_SUCH_FIELD: Status =
        Status::new(c"codec.hpack", c"NoSuchField", c"the list has no field of that index");

    /// The field `index` of `fields`.
    pub fn field(fields: &[HPACKField], index: usize) -> Result<&HPACKField, &'static Status> {
        fields.get(index).ok_or(&HPACKStatus::NO_SUCH_FIELD)
    }
}

impl ToStatus for HPACKError {
    fn to_status(&self) -> &'static Status {
        match self {
            HPACKError::Truncated => &HPACKStatus::TRUNCATED,
            HPACKError::IntegerOverflow => &HPACKStatus::INTEGER_OVERFLOW,
            HPACKError::InvalidIndex => &HPACKStatus::INVALID_INDEX,
            HPACKError::InvalidHuffman => &HPACKStatus::INVALID_HUFFMAN,
            HPACKError::InvalidTableSizeUpdate => &HPACKStatus::INVALID_TABLE_SIZE_UPDATE,
            HPACKError::StringTooLong => &HPACKStatus::STRING_TOO_LONG,
            HPACKError::FieldListTooLarge => &HPACKStatus::FIELD_LIST_TOO_LARGE,
        }
    }
}

impl Value for HPACKEncoderConfig {
    const TYPE: Type = Type::Named("umilib_codec_hpack_HPACKEncoderConfig");
}

impl Value for HPACKDecoderConfig {
    const TYPE: Type = Type::Named("umilib_codec_hpack_HPACKDecoderConfig");
}

impl Value for Vec<HPACKField> {
    const TYPE: Type = Type::Named("umilib_codec_hpack_HPACKFields");
}

impl Value for HPACKEncoder {
    const TYPE: Type = Type::Named("umilib_codec_hpack_HPACKEncoder");
}

impl Value for HPACKDecoder {
    const TYPE: Type = Type::Named("umilib_codec_hpack_HPACKDecoder");
}

crate::ffi_functions! {
    /// Writes the default configuration of an encoder into `out`.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_encoder_config_default(out: *mut HPACKEncoderConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, HPACKEncoderConfig::default()) })
    }

    /// Writes the default configuration of a decoder into `out`.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_decoder_config_default(out: *mut HPACKDecoderConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, HPACKDecoderConfig::default()) })
    }

    /// Writes an empty list of fields into `out`.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_fields_new(out: *mut *mut Vec<HPACKField>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Vec::<HPACKField>::new()) })
    }

    /// Appends the field of the `name_length` bytes at `name` and the `value_length` bytes at
    /// `value`, never indexed if `sensitive`.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_fields_push(fields: *mut Vec<HPACKField>, name: *const u8, name_length: usize, value: *const u8, value_length: usize, sensitive: bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let fields = unsafe { Pointer::reference_mut(fields) }?;
            let name = unsafe { Pointer::slice(name, name_length) }?;
            let value = unsafe { Pointer::slice(value, value_length) }?;
            fields.push(if sensitive { HPACKField::sensitive(name, value) } else { HPACKField::new(name, value) });
            Ok(())
        })())
    }

    /// Writes the number of fields of the list into `out`.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_fields_count(fields: *const Vec<HPACKField>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let fields = unsafe { Pointer::reference(fields) }?;
            unsafe { Pointer::write(out, fields.len()) }
        })())
    }

    /// Writes the name of the field `index` into `out_name`, its value into `out_value` and
    /// whether it is sensitive into `out_sensitive`; fails with NoSuchField past the end.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_fields_get(fields: *const Vec<HPACKField>, index: usize, out_name: *mut Buffer, out_value: *mut Buffer, out_sensitive: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let fields = unsafe { Pointer::reference(fields) }?;
            Pointer::check_range(out_name, 1)?;
            Pointer::check_range(out_value, 1)?;
            Pointer::check_range(out_sensitive, 1)?;
            let field = HPACKStatus::field(fields, index)?;
            unsafe { Pointer::write(out_sensitive, field.sensitive) }?;
            unsafe { Pointer::write(out_name, Buffer::from_vec(field.name.clone())) }?;
            unsafe { Pointer::write(out_value, Buffer::from_vec(field.value.clone())) }
        })())
    }

    /// Releases a list of fields. Does nothing if `fields` is null.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_fields_free(fields: *mut Vec<HPACKField>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(fields) }
    }

    /// Writes an encoder of `config` for a decoder whose table is limited to `limit` bytes into `out`.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_encoder_new(config: HPACKEncoderConfig, limit: usize, out: *mut *mut HPACKEncoder) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, HPACKEncoder::new(config, limit)) })
    }

    /// Takes the decoder's new limit of the table (SETTINGS_HEADER_TABLE_SIZE); the next block
    /// starts with the size updates it calls for.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_encoder_set_limit(encoder: *mut HPACKEncoder, limit: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(encoder) }?.set_limit(limit);
            Ok(())
        })())
    }

    /// Resizes the table to `size` bytes, within the limit; the next block says so.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_encoder_resize(encoder: *mut HPACKEncoder, size: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(encoder) }?.resize(size);
            Ok(())
        })())
    }

    /// Writes the field block of `fields` into `out`.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_encoder_encode(encoder: *mut HPACKEncoder, fields: *const Vec<HPACKField>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let encoder = unsafe { Pointer::reference_mut(encoder) }?;
            let fields = unsafe { Pointer::reference(fields) }?;
            Pointer::check_range(out, 1)?;
            let mut block = Vec::new();
            encoder.encode(fields, &mut block);
            unsafe { Pointer::write(out, Buffer::from_vec(block)) }
        })())
    }

    /// Releases an encoder. Does nothing if `encoder` is null.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_encoder_free(encoder: *mut HPACKEncoder) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(encoder) }
    }

    /// Writes a decoder of `config` into `out`.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_decoder_new(config: HPACKDecoderConfig, out: *mut *mut HPACKDecoder) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, HPACKDecoder::new(config)) })
    }

    /// Sets the limit of the table this end advertised; a lower one must be confirmed by the
    /// encoder's next block (RFC 7541 §4.2).
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_decoder_set_limit(decoder: *mut HPACKDecoder, limit: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(decoder) }?.set_limit(limit);
            Ok(())
        })())
    }

    /// Decodes the field block of `length` bytes at `block` and writes its fields into `out`;
    /// after FieldListTooLarge the table is still in step and nothing is written.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_decoder_decode(decoder: *mut HPACKDecoder, block: *const u8, length: usize, out: *mut *mut Vec<HPACKField>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let decoder = unsafe { Pointer::reference_mut(decoder) }?;
            let block = unsafe { Pointer::slice(block, length) }?;
            Pointer::check_range(out, 1)?;
            let fields = decoder.decode(block).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, fields) }
        })())
    }

    /// Releases a decoder. Does nothing if `decoder` is null.
    pub unsafe extern "C" fn umilib_codec_hpack_hpack_decoder_free(decoder: *mut HPACKDecoder) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(decoder) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "hpack",
    definitions: &[
        Definition::Structure {
            name: "umilib_codec_hpack_HPACKEncoderConfig",
            documentation: " The configuration of an HPACK encoder.",
            fields: &[
                Parameter { name: "maximum_table_size", value: <usize as Value>::TYPE },
                Parameter { name: "huffman", value: <bool as Value>::TYPE },
                Parameter { name: "maximum_indexed_size", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_codec_hpack_HPACKDecoderConfig",
            documentation: " The configuration of an HPACK decoder.",
            fields: &[
                Parameter { name: "maximum_table_size", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_string_length", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_field_list_size", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Opaque { name: "umilib_codec_hpack_HPACKFields", documentation: " A list of HPACK fields." },
        Definition::Opaque {
            name: "umilib_codec_hpack_HPACKEncoder",
            documentation: " An HPACK encoder and its table.",
        },
        Definition::Opaque {
            name: "umilib_codec_hpack_HPACKDecoder",
            documentation: " An HPACK decoder and its table.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
