//! The C ABI of [`crate::codec::pem`].
//!
//! [`PEMStrictness`] is passed as `0` (strict), `1` (standard) or `2` (lax),
//! and [`PEMLineEnding`] as `0` (LF) or `1` (CRLF). Documents are read one at
//! a time with `umilib_codec_pem_pem_document_decode_next`. The parsing steps
//! that `PEMDocument` exposes in Rust (`line`, `collect`, ...) work on
//! positions in borrowed text and are not exported.

use alloc::string::String;
use alloc::vec::Vec;

use crate::codec::pem::{PEMConfig, PEMDocument, PEMError, PEMLabel, PEMLineEnding, PEMStrictness};
use crate::ffi::{Buffer, Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for PEMConfig {
    const TYPE: Type = Type::Named("umilib_codec_pem_PEMConfig");
}

impl Value for PEMDocument {
    const TYPE: Type = Type::Named("umilib_codec_pem_PEMDocument");
}

/// The [`PEMStrictness`] values of the C ABI.
pub struct PEMStrictnessKind;

impl PEMStrictnessKind {
    pub const STRICT: u8 = 0;
    pub const STANDARD: u8 = 1;
    pub const LAX: u8 = 2;

    pub fn decode(kind: u8) -> Result<PEMStrictness, &'static Status> {
        match kind {
            PEMStrictnessKind::STRICT => Ok(PEMStrictness::Strict),
            PEMStrictnessKind::STANDARD => Ok(PEMStrictness::Standard),
            PEMStrictnessKind::LAX => Ok(PEMStrictness::Lax),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    pub fn encode(strictness: PEMStrictness) -> u8 {
        match strictness {
            PEMStrictness::Strict => PEMStrictnessKind::STRICT,
            PEMStrictness::Standard => PEMStrictnessKind::STANDARD,
            PEMStrictness::Lax => PEMStrictnessKind::LAX,
        }
    }
}

/// The statuses of [`PEMError`], one per variant (base64 errors keep their own status).
pub struct PEMStatus;

impl PEMStatus {
    pub const NOT_FOUND: Status = Status::new(c"codec.pem", c"NotFound", c"no PEM document found");
    pub const INVALID_LABEL: Status = Status::new(c"codec.pem", c"InvalidLabel", c"a label is not valid");
    pub const MISSING_END: Status = Status::new(c"codec.pem", c"MissingEnd", c"a document has no END line");
    pub const LABEL_MISMATCH: Status = Status::new(c"codec.pem", c"LabelMismatch", c"the END line has another label");
    pub const INVALID_LINE: Status = Status::new(c"codec.pem", c"InvalidLine", c"a line does not follow the grammar");
    pub const TOO_LONG: Status = Status::new(c"codec.pem", c"TooLong", c"the text is too long");
    pub const ALLOCATION_FAILED: Status =
        Status::new(c"codec.pem", c"AllocationFailed", c"memory could not be allocated");
}

impl ToStatus for PEMError {
    fn to_status(&self) -> &'static Status {
        match self {
            PEMError::NotFound => &PEMStatus::NOT_FOUND,
            PEMError::InvalidLabel { .. } => &PEMStatus::INVALID_LABEL,
            PEMError::MissingEnd { .. } => &PEMStatus::MISSING_END,
            PEMError::LabelMismatch { .. } => &PEMStatus::LABEL_MISMATCH,
            PEMError::InvalidLine { .. } => &PEMStatus::INVALID_LINE,
            PEMError::Base64(error) => error.to_status(),
            PEMError::TooLong { .. } => &PEMStatus::TOO_LONG,
            PEMError::AllocationFailed => &PEMStatus::ALLOCATION_FAILED,
        }
    }
}

crate::ffi_functions! {
    /// Creates the default configuration (standard grammar, matching labels, 16 MiB).
    pub unsafe extern "C" fn umilib_codec_pem_pem_config_new(out: *mut *mut PEMConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, PEMConfig::default()) })
    }

    /// Releases a configuration. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_codec_pem_pem_config_free(config: *mut PEMConfig) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Writes the settings of `config`: the grammar (0 strict, 1 standard, 2 lax), whether END
    /// labels must match, and the longest text accepted.
    pub unsafe extern "C" fn umilib_codec_pem_pem_config_settings(config: *const PEMConfig, out_strictness: *mut u8, out_require_matching_label: *mut bool, out_maximum_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let config = unsafe { Pointer::reference(config) }?;
            if out_strictness.is_null() || out_require_matching_label.is_null() || out_maximum_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out_strictness, PEMStrictnessKind::encode(config.strictness)) }?;
            unsafe { Pointer::write(out_require_matching_label, config.require_matching_label) }?;
            unsafe { Pointer::write(out_maximum_length, config.maximum_length) }
        })())
    }

    /// Changes every setting of `config` (see `umilib_codec_pem_pem_config_settings`).
    pub unsafe extern "C" fn umilib_codec_pem_pem_config_set(config: *mut PEMConfig, strictness: u8, require_matching_label: bool, maximum_length: usize) -> *const Status {
        Status::from_result((|| {
            let strictness = PEMStrictnessKind::decode(strictness)?;
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            *config = PEMConfig { strictness, require_matching_label, maximum_length };
            Ok(())
        })())
    }

    /// Writes whether the UTF-8 `label` follows the grammar of RFC 7468 section 3 into `out`.
    pub unsafe extern "C" fn umilib_codec_pem_pem_label_is_valid(label: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let label = unsafe { Pointer::slice(label, length) }?;
            let valid = core::str::from_utf8(label).is_ok_and(PEMLabel::is_valid);
            unsafe { Pointer::write(out, valid) }
        })())
    }

    /// Creates a document with the UTF-8 `label` and a copy of `length` bytes at `data`.
    pub unsafe extern "C" fn umilib_codec_pem_pem_document_new(label: *const u8, label_length: usize, data: *const u8, length: usize, out: *mut *mut PEMDocument) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let label = unsafe { Pointer::text(label, label_length) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let document = PEMDocument::new(label, Vec::from(data)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, document) }
        })())
    }

    /// Zeroizes and releases a document. Does nothing if `document` is null.
    pub unsafe extern "C" fn umilib_codec_pem_pem_document_free(document: *mut PEMDocument) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(document) }
    }

    /// Writes the label of `document`, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_codec_pem_pem_document_label(document: *const PEMDocument, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let document = unsafe { Pointer::reference(document) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(Vec::from(document.label().as_bytes()))) }
        })())
    }

    /// Writes a pointer to the data of `document`, valid until it is released, into
    /// `out_data` and its length into `out_length`. No copy is made.
    pub unsafe extern "C" fn umilib_codec_pem_pem_document_data(document: *const PEMDocument, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let document = unsafe { Pointer::reference(document) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out_data, document.data().as_ptr()) }?;
            unsafe { Pointer::write(out_length, document.data().len()) }
        })())
    }

    /// Moves the data of `document` into `out` and releases the document; the
    /// caller becomes responsible for zeroizing it. On failure the handle is not released.
    pub unsafe extern "C" fn umilib_codec_pem_pem_document_into_data(document: *mut PEMDocument, out: *mut Buffer) -> *const Status {
        if document.is_null() || out.is_null() {
            return &Status::NULL_POINTER;
        }
        // SAFETY: the caller passes a handle created by this module, which is not used afterwards.
        let document = unsafe { alloc::boxed::Box::from_raw(document) };
        // SAFETY: the caller passes a writable buffer, checked to be non-null above.
        Status::from_result(unsafe { Pointer::write(out, Buffer::from_vec(document.into_data())) })
    }

    /// Parses the first document of `length` bytes at `text` with `config` (null for the defaults).
    pub unsafe extern "C" fn umilib_codec_pem_pem_document_decode(text: *const u8, length: usize, config: *const PEMConfig, out: *mut *mut PEMDocument) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes, a valid or null configuration and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let config = if config.is_null() { PEMConfig::default() } else { *unsafe { Pointer::reference(config) }? };
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let document = PEMDocument::decode(text, config).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, document) }
        })())
    }

    /// Parses the next document at or after byte `start` of `text`. Writes whether one was
    /// found into `out_found`, the document into `out` (null if none) and the position after
    /// it into `out_next`.
    pub unsafe extern "C" fn umilib_codec_pem_pem_document_decode_next(text: *const u8, length: usize, start: usize, config: *const PEMConfig, out_found: *mut bool, out: *mut *mut PEMDocument, out_next: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes, a valid or null configuration and writable pointers.
            let text = unsafe { Pointer::slice(text, length) }?;
            let config = if config.is_null() { PEMConfig::default() } else { *unsafe { Pointer::reference(config) }? };
            if out_found.is_null() || out.is_null() || out_next.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            if start > text.len() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            match PEMDocument::decode_next(text, start, config).map_err(|error| error.to_status())? {
                Some((document, next)) => {
                    unsafe { Pointer::write(out_found, true) }?;
                    unsafe { Pointer::write(out_next, next) }?;
                    unsafe { Pointer::write_handle(out, document) }
                }
                None => {
                    unsafe { Pointer::write(out_found, false) }?;
                    unsafe { Pointer::write(out_next, text.len()) }?;
                    unsafe { Pointer::write(out, core::ptr::null_mut()) }
                }
            }
        })())
    }

    /// Writes `document` in the strict format with `line_ending` (0 LF, 1 CRLF) into `out`.
    pub unsafe extern "C" fn umilib_codec_pem_pem_document_encode_with(document: *const PEMDocument, line_ending: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let document = unsafe { Pointer::reference(document) }?;
            let line_ending = match line_ending {
                0 => PEMLineEnding::LF,
                1 => PEMLineEnding::CRLF,
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            let text: String = document.encode_with(line_ending);
            unsafe { Pointer::write(out, Buffer::from_vec(text.into_bytes())) }
        })())
    }

    /// Writes `document` in the strict format with LF line endings into `out`.
    pub unsafe extern "C" fn umilib_codec_pem_pem_document_encode(document: *const PEMDocument, out: *mut Buffer) -> *const Status {
        // SAFETY: the same contract as `umilib_codec_pem_pem_document_encode_with`.
        unsafe { umilib_codec_pem_pem_document_encode_with(document, 0, out) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "pem",
    definitions: &[
        Definition::Opaque { name: "umilib_codec_pem_PEMConfig", documentation: " Options of PEM parsing." },
        Definition::Opaque {
            name: "umilib_codec_pem_PEMDocument",
            documentation: " A label and its data, zeroized when released.",
        },
    ],
    functions: &Function::concat::<{ FUNCTIONS.len() }>(&[FUNCTIONS]),
    modules: &[],
};
