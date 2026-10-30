//! The C ABI of [`crate::codec::qpack`].
//!
//! An encoder and a decoder are handles; their configurations are
//! structures passed by value, and field sections cross as the lists of
//! fields of [`crate::ffi::codec::hpack`]. The caller moves the bytes of
//! the encoder and decoder streams: each side writes its instructions for
//! the caller to send (`take_instructions`) and reads those that arrive.

use alloc::vec::Vec;

use crate::codec::hpack::HPACKField;
use crate::codec::qpack::{
    QPACKDecoded, QPACKDecoder, QPACKDecoderConfig, QPACKEncoder, QPACKEncoderConfig, QPACKError,
};
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};

/// The statuses of [`QPACKError`], one per variant.
pub struct QPACKStatus;

impl QPACKStatus {
    pub const DECOMPRESSION_FAILED: Status =
        Status::new(c"codec.qpack", c"DecompressionFailed", c"a field section cannot be decoded");
    pub const ENCODER_STREAM: Status =
        Status::new(c"codec.qpack", c"EncoderStream", c"an encoder instruction cannot be processed");
    pub const DECODER_STREAM: Status =
        Status::new(c"codec.qpack", c"DecoderStream", c"a decoder instruction cannot be processed");
    pub const FIELD_LIST_TOO_LARGE: Status =
        Status::new(c"codec.qpack", c"FieldListTooLarge", c"the field section is larger than the decoder's limit");
}

impl ToStatus for QPACKError {
    fn to_status(&self) -> &'static Status {
        match self {
            QPACKError::DecompressionFailed(_) => &QPACKStatus::DECOMPRESSION_FAILED,
            QPACKError::EncoderStream(_) => &QPACKStatus::ENCODER_STREAM,
            QPACKError::DecoderStream(_) => &QPACKStatus::DECODER_STREAM,
            QPACKError::FieldListTooLarge => &QPACKStatus::FIELD_LIST_TOO_LARGE,
        }
    }
}

impl Value for QPACKEncoderConfig {
    const TYPE: Type = Type::Named("umilib_codec_qpack_QPACKEncoderConfig");
}

impl Value for QPACKDecoderConfig {
    const TYPE: Type = Type::Named("umilib_codec_qpack_QPACKDecoderConfig");
}

impl Value for QPACKEncoder {
    const TYPE: Type = Type::Named("umilib_codec_qpack_QPACKEncoder");
}

impl Value for QPACKDecoder {
    const TYPE: Type = Type::Named("umilib_codec_qpack_QPACKDecoder");
}

crate::ffi_functions! {
    /// Writes the default configuration of an encoder into `out`.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_encoder_config_default(out: *mut QPACKEncoderConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, QPACKEncoderConfig::default()) })
    }

    /// Writes the default configuration of a decoder into `out`.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_decoder_config_default(out: *mut QPACKDecoderConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, QPACKDecoderConfig::default()) })
    }

    /// Writes an encoder of `config` into `out`; it uses no dynamic table until the peer's settings arrive.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_encoder_new(config: QPACKEncoderConfig, out: *mut *mut QPACKEncoder) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, QPACKEncoder::new(config)) })
    }

    /// Takes the decoder's SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_encoder_set_peer_settings(encoder: *mut QPACKEncoder, maximum_table_capacity: usize, blocked_streams: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(encoder) }?.set_peer_settings(maximum_table_capacity, blocked_streams);
            Ok(())
        })())
    }

    /// Writes the encoded field section of `fields` on `stream` into `out`, after writing the
    /// inserts it uses to the encoder stream's instructions.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_encoder_encode(encoder: *mut QPACKEncoder, stream: u64, fields: *const Vec<HPACKField>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let encoder = unsafe { Pointer::reference_mut(encoder) }?;
            let fields = unsafe { Pointer::reference(fields) }?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out, Buffer::from_vec(encoder.encode(stream, fields))) }
        })())
    }

    /// Takes the `length` bytes at `bytes` of the decoder stream.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_encoder_receive_decoder_stream(encoder: *mut QPACKEncoder, bytes: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let encoder = unsafe { Pointer::reference_mut(encoder) }?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            encoder.receive_decoder_stream(bytes).map_err(|error| error.to_status())
        })())
    }

    /// Writes the encoder stream's instructions to send into `out`.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_encoder_take_instructions(encoder: *mut QPACKEncoder, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let encoder = unsafe { Pointer::reference_mut(encoder) }?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out, Buffer::from_vec(encoder.take_instructions())) }
        })())
    }

    /// Releases an encoder. Does nothing if `encoder` is null.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_encoder_free(encoder: *mut QPACKEncoder) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(encoder) }
    }

    /// Writes a decoder of `config` into `out`.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_decoder_new(config: QPACKDecoderConfig, out: *mut *mut QPACKDecoder) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, QPACKDecoder::new(config)) })
    }

    /// Takes the `length` bytes at `bytes` of the encoder stream.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_decoder_receive_encoder_stream(decoder: *mut QPACKDecoder, bytes: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let decoder = unsafe { Pointer::reference_mut(decoder) }?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            decoder.receive_encoder_stream(bytes).map_err(|error| error.to_status())
        })())
    }

    /// Decodes the field section of `length` bytes at `section` on `stream`: writes whether it
    /// waits for inserts not received yet into `out_blocked` (decode it again once they arrive),
    /// else its fields into `out` (null if blocked).
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_decoder_decode(decoder: *mut QPACKDecoder, stream: u64, section: *const u8, length: usize, out_blocked: *mut bool, out: *mut *mut Vec<HPACKField>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and writable pointers.
            let decoder = unsafe { Pointer::reference_mut(decoder) }?;
            let section = unsafe { Pointer::slice(section, length) }?;
            Pointer::check_range(out_blocked, 1)?;
            Pointer::check_range(out, 1)?;
            match decoder.decode(stream, section).map_err(|error| error.to_status())? {
                QPACKDecoded::Blocked => {
                    unsafe { Pointer::write(out_blocked, true) }?;
                    unsafe { Pointer::write(out, core::ptr::null_mut()) }
                }
                QPACKDecoded::Fields(fields) => {
                    unsafe { Pointer::write(out_blocked, false) }?;
                    unsafe { Pointer::write_handle(out, fields) }
                }
            }
        })())
    }

    /// Abandons `stream`: its blocked section, if any, and a Stream Cancellation for the encoder.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_decoder_cancel_stream(decoder: *mut QPACKDecoder, stream: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(decoder) }?.cancel_stream(stream);
            Ok(())
        })())
    }

    /// Writes the decoder stream's instructions to send into `out`.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_decoder_take_instructions(decoder: *mut QPACKDecoder, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let decoder = unsafe { Pointer::reference_mut(decoder) }?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out, Buffer::from_vec(decoder.take_instructions())) }
        })())
    }

    /// Releases a decoder. Does nothing if `decoder` is null.
    pub unsafe extern "C" fn umilib_codec_qpack_qpack_decoder_free(decoder: *mut QPACKDecoder) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(decoder) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "qpack",
    definitions: &[
        Definition::Structure {
            name: "umilib_codec_qpack_QPACKEncoderConfig",
            documentation: " The configuration of a QPACK encoder.",
            fields: &[
                Parameter { name: "maximum_table_capacity", value: <usize as Value>::TYPE },
                Parameter { name: "huffman", value: <bool as Value>::TYPE },
                Parameter { name: "maximum_indexed_size", value: <usize as Value>::TYPE },
                Parameter { name: "blocking", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_codec_qpack_QPACKDecoderConfig",
            documentation: " The configuration of a QPACK decoder.",
            fields: &[
                Parameter { name: "maximum_table_capacity", value: <usize as Value>::TYPE },
                Parameter { name: "blocked_streams", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_string_length", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_field_list_size", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_codec_qpack_QPACKEncoder",
            documentation: " A QPACK encoder and its table.",
        },
        Definition::Opaque {
            name: "umilib_codec_qpack_QPACKDecoder",
            documentation: " A QPACK decoder and its table.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
