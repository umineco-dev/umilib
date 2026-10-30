//! The C ABI of [`crate::codec::json`].
//!
//! Values are handles owning a tree. Functions that read a child
//! (`*_index`, `*_get`, `*_member_value`) and functions that add one
//! (`*_push`, `*_insert`) copy it, so the caller always releases exactly the
//! handles it created. Kinds and policies are passed as small integers:
//! [`JSONValueKind`], [`JSONEventKind`] and [`DuplicateKeysKind`].

use alloc::string::String;
use alloc::vec::Vec;

use crate::codec::json::{
    DuplicateKeys, JSONConfig, JSONEncoder, JSONError, JSONEvent, JSONNumber, JSONObject, JSONReader, JSONString,
    JSONValue,
};
use crate::ffi::{Buffer, Definition, Function, I128, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for JSONValue {
    const TYPE: Type = Type::Named("umilib_codec_json_JSONValue");
}

impl Value for JSONNumber {
    const TYPE: Type = Type::Named("umilib_codec_json_JSONNumber");
}

impl Value for JSONConfig {
    const TYPE: Type = Type::Named("umilib_codec_json_JSONConfig");
}

impl Value for JSONEncoder {
    const TYPE: Type = Type::Named("umilib_codec_json_JSONEncoder");
}

impl Value for JSONReader<'static> {
    const TYPE: Type = Type::Named("umilib_codec_json_JSONReader");
}

/// The kinds of [`JSONValue`] in the C ABI.
pub struct JSONValueKind;

impl JSONValueKind {
    pub const NULL: u8 = 0;
    pub const BOOL: u8 = 1;
    pub const NUMBER: u8 = 2;
    pub const STRING: u8 = 3;
    pub const ARRAY: u8 = 4;
    pub const OBJECT: u8 = 5;

    pub fn of(value: &JSONValue) -> u8 {
        match value {
            JSONValue::Null => JSONValueKind::NULL,
            JSONValue::Bool(_) => JSONValueKind::BOOL,
            JSONValue::Number(_) => JSONValueKind::NUMBER,
            JSONValue::String(_) => JSONValueKind::STRING,
            JSONValue::Array(_) => JSONValueKind::ARRAY,
            JSONValue::Object(_) => JSONValueKind::OBJECT,
        }
    }
}

/// The kinds of [`JSONEvent`] in the C ABI.
pub struct JSONEventKind;

impl JSONEventKind {
    pub const BEGIN_OBJECT: u8 = 0;
    pub const END_OBJECT: u8 = 1;
    pub const BEGIN_ARRAY: u8 = 2;
    pub const END_ARRAY: u8 = 3;
    pub const KEY: u8 = 4;
    pub const STRING: u8 = 5;
    pub const NUMBER: u8 = 6;
    pub const BOOL: u8 = 7;
    pub const NULL: u8 = 8;
}

/// The [`DuplicateKeys`] policies in the C ABI.
pub struct DuplicateKeysKind;

impl DuplicateKeysKind {
    pub const REJECT: u8 = 0;
    pub const KEEP_FIRST: u8 = 1;
    pub const KEEP_LAST: u8 = 2;
    pub const KEEP_ALL: u8 = 3;

    pub fn decode(kind: u8) -> Result<DuplicateKeys, &'static Status> {
        match kind {
            DuplicateKeysKind::REJECT => Ok(DuplicateKeys::Reject),
            DuplicateKeysKind::KEEP_FIRST => Ok(DuplicateKeys::KeepFirst),
            DuplicateKeysKind::KEEP_LAST => Ok(DuplicateKeys::KeepLast),
            DuplicateKeysKind::KEEP_ALL => Ok(DuplicateKeys::KeepAll),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    pub fn encode(policy: DuplicateKeys) -> u8 {
        match policy {
            DuplicateKeys::Reject => DuplicateKeysKind::REJECT,
            DuplicateKeys::KeepFirst => DuplicateKeysKind::KEEP_FIRST,
            DuplicateKeys::KeepLast => DuplicateKeysKind::KEEP_LAST,
            DuplicateKeys::KeepAll => DuplicateKeysKind::KEEP_ALL,
        }
    }
}

/// The statuses of [`JSONError`], one per variant, and of using a value as the wrong kind.
pub struct JSONStatus;

impl JSONStatus {
    pub const UNEXPECTED_CHARACTER: Status =
        Status::new(c"codec.json", c"UnexpectedCharacter", c"a character is not allowed there");
    pub const UNEXPECTED_END: Status =
        Status::new(c"codec.json", c"UnexpectedEnd", c"the input ends before the value is complete");
    pub const TRAILING_DATA: Status =
        Status::new(c"codec.json", c"TrailingData", c"something other than white space follows the value");
    pub const INVALID_NUMBER: Status =
        Status::new(c"codec.json", c"InvalidNumber", c"a number does not follow the grammar");
    pub const INVALID_ESCAPE: Status = Status::new(c"codec.json", c"InvalidEscape", c"an escape sequence is invalid");
    pub const CONTROL_CHARACTER: Status =
        Status::new(c"codec.json", c"ControlCharacter", c"a control character is not escaped");
    pub const INVALID_UTF8: Status = Status::new(c"codec.json", c"InvalidUTF8", c"the text is not valid UTF-8");
    pub const LONE_SURROGATE: Status = Status::new(c"codec.json", c"LoneSurrogate", c"a surrogate escape has no pair");
    pub const TOO_DEEP: Status = Status::new(c"codec.json", c"TooDeep", c"arrays and objects nest too deeply");
    pub const TOO_LONG: Status = Status::new(c"codec.json", c"TooLong", c"the input is too long");
    pub const DUPLICATE_KEY: Status = Status::new(c"codec.json", c"DuplicateKey", c"an object has the same key twice");
    pub const OUT_OF_RANGE: Status =
        Status::new(c"codec.json", c"OutOfRange", c"a number does not fit in the requested type");
    pub const ALLOCATION_FAILED: Status =
        Status::new(c"codec.json", c"AllocationFailed", c"memory could not be allocated");
    /// The value is not of the kind the function needs (only in the C ABI).
    pub const WRONG_KIND: Status = Status::new(c"codec.json", c"WrongKind", c"the value is not of the required kind");
}

impl ToStatus for JSONError {
    fn to_status(&self) -> &'static Status {
        match self {
            JSONError::UnexpectedCharacter { .. } => &JSONStatus::UNEXPECTED_CHARACTER,
            JSONError::UnexpectedEnd { .. } => &JSONStatus::UNEXPECTED_END,
            JSONError::TrailingData { .. } => &JSONStatus::TRAILING_DATA,
            JSONError::InvalidNumber { .. } => &JSONStatus::INVALID_NUMBER,
            JSONError::InvalidEscape { .. } => &JSONStatus::INVALID_ESCAPE,
            JSONError::ControlCharacter { .. } => &JSONStatus::CONTROL_CHARACTER,
            JSONError::InvalidUTF8 { .. } => &JSONStatus::INVALID_UTF8,
            JSONError::LoneSurrogate { .. } => &JSONStatus::LONE_SURROGATE,
            JSONError::TooDeep { .. } => &JSONStatus::TOO_DEEP,
            JSONError::TooLong { .. } => &JSONStatus::TOO_LONG,
            JSONError::DuplicateKey { .. } => &JSONStatus::DUPLICATE_KEY,
            JSONError::OutOfRange => &JSONStatus::OUT_OF_RANGE,
            JSONError::AllocationFailed => &JSONStatus::ALLOCATION_FAILED,
        }
    }
}

/// Defines a function that copies one field of a [`JSONConfig`] into `out`, and one that sets it.
macro_rules! config_fields {
    ($($getter:ident, $setter:ident: $field:ident: $type:ty, $documentation:literal;)*) => {
        crate::ffi_functions! {
            const CONFIG;
            $(
                #[doc = $documentation]
                pub unsafe extern "C" fn $getter(config: *const JSONConfig, out: *mut $type) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle and a writable pointer.
                        let config = unsafe { Pointer::reference(config) }?;
                        unsafe { Pointer::write(out, config.$field) }
                    })())
                }

                #[doc = $documentation]
                pub unsafe extern "C" fn $setter(config: *mut JSONConfig, value: $type) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle.
                        unsafe { Pointer::reference_mut(config) }?.$field = value;
                        Ok(())
                    })())
                }
            )*
        }
    };
}

config_fields! {
    umilib_codec_json_json_config_maximum_depth, umilib_codec_json_json_config_set_maximum_depth: maximum_depth: usize, " The deepest nesting of arrays and objects.";
    umilib_codec_json_json_config_maximum_length, umilib_codec_json_json_config_set_maximum_length: maximum_length: usize, " The longest input, in bytes.";
    umilib_codec_json_json_config_allow_byte_order_mark, umilib_codec_json_json_config_set_allow_byte_order_mark: allow_byte_order_mark: bool, " Whether a UTF-8 byte order mark before the text is skipped.";
}

crate::ffi_functions! {
    const METHODS;

    /// Creates the default configuration.
    pub unsafe extern "C" fn umilib_codec_json_json_config_new(out: *mut *mut JSONConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JSONConfig::default()) })
    }

    /// Releases a configuration. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_codec_json_json_config_free(config: *mut JSONConfig) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Writes the duplicate key policy (0 reject, 1 keep first, 2 keep last, 3 keep all) into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_config_duplicate_keys(config: *const JSONConfig, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write(out, DuplicateKeysKind::encode(config.duplicate_keys)) }
        })())
    }

    /// Sets the duplicate key policy (0 reject, 1 keep first, 2 keep last, 3 keep all).
    pub unsafe extern "C" fn umilib_codec_json_json_config_set_duplicate_keys(config: *mut JSONConfig, policy: u8) -> *const Status {
        Status::from_result((|| {
            let policy = DuplicateKeysKind::decode(policy)?;
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(config) }?.duplicate_keys = policy;
            Ok(())
        })())
    }

    /// Parses `length` bytes at `data` with `config` (null for the defaults) into a new value.
    pub unsafe extern "C" fn umilib_codec_json_json_value_decode(data: *const u8, length: usize, config: *const JSONConfig, out: *mut *mut JSONValue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes, a valid or null configuration and a writable pointer.
            let input = unsafe { Pointer::slice(data, length) }?;
            let config = if config.is_null() { JSONConfig::default() } else { *unsafe { Pointer::reference(config) }? };
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let value = JSONValue::decode(input, config).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, value) }
        })())
    }

    /// Parses the UTF-8 `text` with the default limits into a new value.
    pub unsafe extern "C" fn umilib_codec_json_json_value_parse(text: *const u8, length: usize, out: *mut *mut JSONValue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let value = JSONValue::parse(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, value) }
        })())
    }

    /// Releases a value and everything it contains. Does nothing if `value` is null.
    pub unsafe extern "C" fn umilib_codec_json_json_value_free(value: *mut JSONValue) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(value) }
    }

    /// Writes a new handle holding a copy of `value` into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_clone(value: *const JSONValue, out: *mut *mut JSONValue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            unsafe { Pointer::write_handle(out, value.clone()) }
        })())
    }

    /// Writes whether two values are equal into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_equal(a: *const JSONValue, b: *const JSONValue, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let (a, b) = (unsafe { Pointer::reference(a) }?, unsafe { Pointer::reference(b) }?);
            unsafe { Pointer::write(out, a == b) }
        })())
    }

    /// Writes the kind of `value` (0 null, 1 bool, 2 number, 3 string, 4 array, 5 object) into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_kind(value: *const JSONValue, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?;
            unsafe { Pointer::write(out, JSONValueKind::of(value)) }
        })())
    }

    /// Creates `null`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_null(out: *mut *mut JSONValue) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JSONValue::Null) })
    }

    /// Creates a boolean.
    pub unsafe extern "C" fn umilib_codec_json_json_value_from_bool(value: bool, out: *mut *mut JSONValue) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JSONValue::Bool(value)) })
    }

    /// Creates a number holding a copy of `number`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_from_number(number: *const JSONNumber, out: *mut *mut JSONValue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let number = unsafe { Pointer::reference(number) }?;
            unsafe { Pointer::write_handle(out, JSONValue::Number(number.clone())) }
        })())
    }

    /// Creates a string from UTF-8 `text`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_from_string(text: *const u8, length: usize, out: *mut *mut JSONValue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            unsafe { Pointer::write_handle(out, JSONValue::from(text)) }
        })())
    }

    /// Creates an empty array.
    pub unsafe extern "C" fn umilib_codec_json_json_value_array(out: *mut *mut JSONValue) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JSONValue::Array(Vec::new())) })
    }

    /// Creates an empty object.
    pub unsafe extern "C" fn umilib_codec_json_json_value_object(out: *mut *mut JSONValue) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JSONValue::Object(JSONObject::new())) })
    }

    /// Writes the value of a boolean into `out`; fails with `WrongKind` for other values.
    pub unsafe extern "C" fn umilib_codec_json_json_value_as_bool(value: *const JSONValue, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(value) }?.as_bool().ok_or(&JSONStatus::WRONG_KIND)?;
            unsafe { Pointer::write(out, value) }
        })())
    }

    /// Writes a new handle holding a copy of a number into `out`; fails with `WrongKind` for other values.
    pub unsafe extern "C" fn umilib_codec_json_json_value_as_number(value: *const JSONValue, out: *mut *mut JSONNumber) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let number = unsafe { Pointer::reference(value) }?.as_number().ok_or(&JSONStatus::WRONG_KIND)?;
            unsafe { Pointer::write_handle(out, number.clone()) }
        })())
    }

    /// Writes a copy of a string, as UTF-8, into `out`; fails with `WrongKind` for other values.
    pub unsafe extern "C" fn umilib_codec_json_json_value_as_str(value: *const JSONValue, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let text = unsafe { Pointer::reference(value) }?.as_str().ok_or(&JSONStatus::WRONG_KIND)?;
            unsafe { Pointer::write(out, Buffer::from_vec(Vec::from(text.as_bytes()))) }
        })())
    }

    /// Writes the number of elements of an array or members of an object into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_len(value: *const JSONValue, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let length = match unsafe { Pointer::reference(value) }? {
                JSONValue::Array(values) => values.len(),
                JSONValue::Object(object) => object.len(),
                _ => return Err(&JSONStatus::WRONG_KIND),
            };
            unsafe { Pointer::write(out, length) }
        })())
    }

    /// Writes a new handle holding a copy of the array element at `index` into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_index(value: *const JSONValue, index: usize, out: *mut *mut JSONValue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let values = unsafe { Pointer::reference(value) }?.as_array().ok_or(&JSONStatus::WRONG_KIND)?;
            let element = values.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, element.clone()) }
        })())
    }

    /// Appends a copy of `element` to an array.
    pub unsafe extern "C" fn umilib_codec_json_json_value_push(value: *mut JSONValue, element: *const JSONValue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles; a copy is taken first, so they may be the same.
            let element = unsafe { Pointer::reference(element) }?.clone();
            let values = unsafe { Pointer::reference_mut(value) }?.as_array_mut().ok_or(&JSONStatus::WRONG_KIND)?;
            values.try_reserve(1).map_err(|_| &JSONStatus::ALLOCATION_FAILED)?;
            values.push(element);
            Ok(())
        })())
    }

    /// Writes the key of the object member at `index`, as UTF-8, into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_member_key(value: *const JSONValue, index: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let object = unsafe { Pointer::reference(value) }?.as_object().ok_or(&JSONStatus::WRONG_KIND)?;
            let (key, _) = object.members.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, Buffer::from_vec(Vec::from(key.as_bytes()))) }
        })())
    }

    /// Writes a new handle holding a copy of the value of the object member at `index` into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_member_value(value: *const JSONValue, index: usize, out: *mut *mut JSONValue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let object = unsafe { Pointer::reference(value) }?.as_object().ok_or(&JSONStatus::WRONG_KIND)?;
            let (_, member) = object.members.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, member.clone()) }
        })())
    }

    /// Writes whether an object has the UTF-8 `key` into `out_found`, and a new handle holding a
    /// copy of its first value into `out` (null if not found).
    pub unsafe extern "C" fn umilib_codec_json_json_value_get(value: *const JSONValue, key: *const u8, key_length: usize, out_found: *mut bool, out: *mut *mut JSONValue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and writable pointers.
            let object = unsafe { Pointer::reference(value) }?.as_object().ok_or(&JSONStatus::WRONG_KIND)?;
            let key = unsafe { Pointer::text(key, key_length) }?;
            if out_found.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let member = object.get(key);
            unsafe { Pointer::write(out_found, member.is_some()) }?;
            match member {
                Some(member) => unsafe { Pointer::write_handle(out, member.clone()) },
                None => unsafe { Pointer::write(out, core::ptr::null_mut()) },
            }
        })())
    }

    /// Sets the member named by the UTF-8 `key` of an object to a copy of `member`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_insert(value: *mut JSONValue, key: *const u8, key_length: usize, member: *const JSONValue) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable text; a copy is taken first.
            let member = unsafe { Pointer::reference(member) }?.clone();
            let key = String::from(unsafe { Pointer::text(key, key_length) }?);
            let object = unsafe { Pointer::reference_mut(value) }?.as_object_mut().ok_or(&JSONStatus::WRONG_KIND)?;
            object.insert(key, member);
            Ok(())
        })())
    }

    /// Removes every member named by the UTF-8 `key` of an object and writes whether one existed into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_remove(value: *mut JSONValue, key: *const u8, key_length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and a writable pointer.
            let key = unsafe { Pointer::text(key, key_length) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let object = unsafe { Pointer::reference_mut(value) }?.as_object_mut().ok_or(&JSONStatus::WRONG_KIND)?;
            let removed = object.remove(key).is_some();
            unsafe { Pointer::write(out, removed) }
        })())
    }

    /// Writes `value` as compact JSON text into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_value_encode(value: *const JSONValue, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let value = unsafe { Pointer::reference(value) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(value.encode().into_bytes())) }
        })())
    }

    /// Creates a number from UTF-8 `text`, which must follow the JSON grammar exactly.
    pub unsafe extern "C" fn umilib_codec_json_json_number_new(text: *const u8, length: usize, out: *mut *mut JSONNumber) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let number = JSONNumber::new(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, number) }
        })())
    }

    /// Creates a number from a finite `value`; fails with `OutOfRange` for NaN and infinities.
    pub unsafe extern "C" fn umilib_codec_json_json_number_from_f64(value: f64, out: *mut *mut JSONNumber) -> *const Status {
        Status::from_result((|| {
            let number = JSONNumber::from_f64(value).ok_or(&JSONStatus::OUT_OF_RANGE)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, number) }
        })())
    }

    /// Creates a number from `value`.
    pub unsafe extern "C" fn umilib_codec_json_json_number_from_i64(value: i64, out: *mut *mut JSONNumber) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JSONNumber::from(value)) })
    }

    /// Creates a number from `value`.
    pub unsafe extern "C" fn umilib_codec_json_json_number_from_u64(value: u64, out: *mut *mut JSONNumber) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JSONNumber::from(value)) })
    }

    /// Creates a number from `value`.
    pub unsafe extern "C" fn umilib_codec_json_json_number_from_i128(value: I128, out: *mut *mut JSONNumber) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JSONNumber::from(i128::from(value))) })
    }

    /// Releases a number. Does nothing if `number` is null.
    pub unsafe extern "C" fn umilib_codec_json_json_number_free(number: *mut JSONNumber) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(number) }
    }

    /// Writes the text of `number` into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_number_as_str(number: *const JSONNumber, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let number = unsafe { Pointer::reference(number) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(Vec::from(number.as_str().as_bytes()))) }
        })())
    }

    /// Writes whether `number` is written without fraction or exponent into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_number_is_integer(number: *const JSONNumber, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let number = unsafe { Pointer::reference(number) }?;
            unsafe { Pointer::write(out, number.is_integer()) }
        })())
    }

    /// Writes the nearest `f64` into `out`; fails with `OutOfRange` if it is too large for `f64`.
    pub unsafe extern "C" fn umilib_codec_json_json_number_as_f64(number: *const JSONNumber, out: *mut f64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(number) }?.as_f64().ok_or(&JSONStatus::OUT_OF_RANGE)?;
            unsafe { Pointer::write(out, value) }
        })())
    }

    /// Writes the number as an `int64_t` into `out`; fails with `OutOfRange` if it is not an integer in range.
    pub unsafe extern "C" fn umilib_codec_json_json_number_as_i64(number: *const JSONNumber, out: *mut i64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(number) }?.as_i64().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, value) }
        })())
    }

    /// Writes the number as a `uint64_t` into `out`; fails with `OutOfRange` if it is not a non-negative integer in range.
    pub unsafe extern "C" fn umilib_codec_json_json_number_as_u64(number: *const JSONNumber, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(number) }?.as_u64().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, value) }
        })())
    }

    /// Writes the number as a 128-bit integer into `out`; fails with `OutOfRange` if it is not an integer in range.
    pub unsafe extern "C" fn umilib_codec_json_json_number_as_i128(number: *const JSONNumber, out: *mut I128) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let value = unsafe { Pointer::reference(number) }?.as_i128().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, I128::from(value)) }
        })())
    }

    /// Creates the compact encoder (one line, no spaces, UTF-8).
    pub unsafe extern "C" fn umilib_codec_json_json_encoder_compact(out: *mut *mut JSONEncoder) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JSONEncoder::COMPACT) })
    }

    /// Creates the pretty encoder (two spaces per level).
    pub unsafe extern "C" fn umilib_codec_json_json_encoder_pretty(out: *mut *mut JSONEncoder) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, JSONEncoder::PRETTY) })
    }

    /// Creates an encoder: `indent` spaces per level if `has_indent`, and `\u` escapes for non-ASCII if `ascii_only`.
    pub unsafe extern "C" fn umilib_codec_json_json_encoder_new(has_indent: bool, indent: u8, ascii_only: bool, out: *mut *mut JSONEncoder) -> *const Status {
        let encoder = JSONEncoder { indent: has_indent.then_some(indent), ascii_only };
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, encoder) })
    }

    /// Writes the settings of `encoder`: whether it indents, by how many spaces, and whether it escapes non-ASCII.
    pub unsafe extern "C" fn umilib_codec_json_json_encoder_settings(encoder: *const JSONEncoder, out_has_indent: *mut bool, out_indent: *mut u8, out_ascii_only: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let encoder = unsafe { Pointer::reference(encoder) }?;
            if out_has_indent.is_null() || out_indent.is_null() || out_ascii_only.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out_has_indent, encoder.indent.is_some()) }?;
            unsafe { Pointer::write(out_indent, encoder.indent.unwrap_or(0)) }?;
            unsafe { Pointer::write(out_ascii_only, encoder.ascii_only) }
        })())
    }

    /// Releases an encoder. Does nothing if `encoder` is null.
    pub unsafe extern "C" fn umilib_codec_json_json_encoder_free(encoder: *mut JSONEncoder) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(encoder) }
    }

    /// Writes `value` as text with `encoder` into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_encoder_encode(encoder: *const JSONEncoder, value: *const JSONValue, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable buffer.
            let encoder = unsafe { Pointer::reference(encoder) }?;
            let value = unsafe { Pointer::reference(value) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(encoder.encode(value).into_bytes())) }
        })())
    }

    /// Writes the UTF-8 `text` as a JSON string literal with `encoder` into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_encoder_write_string(encoder: *const JSONEncoder, text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and a writable buffer.
            let encoder = unsafe { Pointer::reference(encoder) }?;
            let text = unsafe { Pointer::text(text, length) }?;
            let mut literal = String::new();
            encoder.write_string(text, &mut literal);
            unsafe { Pointer::write(out, Buffer::from_vec(literal.into_bytes())) }
        })())
    }

    /// Creates a reader over `length` bytes at `data`, which must stay valid and
    /// unchanged while the reader is used, with `config` (null for the defaults).
    pub unsafe extern "C" fn umilib_codec_json_json_reader_new(data: *const u8, length: usize, config: *const JSONConfig, out: *mut *mut JSONReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller keeps `data` valid while the reader exists and passes a valid or null configuration.
            let input = unsafe { Pointer::slice(data, length) }?;
            let config = if config.is_null() { JSONConfig::default() } else { *unsafe { Pointer::reference(config) }? };
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let reader = JSONReader::new(input, config).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, reader) }
        })())
    }

    /// Releases a reader. Does nothing if `reader` is null.
    pub unsafe extern "C" fn umilib_codec_json_json_reader_free(reader: *mut JSONReader<'static>) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(reader) }
    }

    /// Reads the next event. Writes whether there was one into `out_has_event` and its kind
    /// (0 begin object, 1 end object, 2 begin array, 3 end array, 4 key, 5 string, 6 number,
    /// 7 bool, 8 null) into `out_kind`. For keys, strings and numbers, `out_data` and
    /// `out_length` describe the text as written in the input (without quotes, with escapes),
    /// and `out_escaped` whether it has escape sequences; for booleans, `out_escaped` holds the value.
    pub unsafe extern "C" fn umilib_codec_json_json_reader_next_event(reader: *mut JSONReader<'static>, out_has_event: *mut bool, out_kind: *mut u8, out_data: *mut *const u8, out_length: *mut usize, out_escaped: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_has_event.is_null() || out_kind.is_null() || out_data.is_null() || out_length.is_null() || out_escaped.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let event = reader.next_event().map_err(|error| error.to_status())?;
            let (kind, text, flag): (u8, &str, bool) = match event {
                None => (0, "", false),
                Some(JSONEvent::BeginObject) => (JSONEventKind::BEGIN_OBJECT, "", false),
                Some(JSONEvent::EndObject) => (JSONEventKind::END_OBJECT, "", false),
                Some(JSONEvent::BeginArray) => (JSONEventKind::BEGIN_ARRAY, "", false),
                Some(JSONEvent::EndArray) => (JSONEventKind::END_ARRAY, "", false),
                Some(JSONEvent::Key(key)) => (JSONEventKind::KEY, key.raw(), key.is_escaped()),
                Some(JSONEvent::String(string)) => (JSONEventKind::STRING, string.raw(), string.is_escaped()),
                Some(JSONEvent::Number(number)) => (JSONEventKind::NUMBER, number, false),
                Some(JSONEvent::Bool(value)) => (JSONEventKind::BOOL, "", value),
                Some(JSONEvent::Null) => (JSONEventKind::NULL, "", false),
            };
            unsafe { Pointer::write(out_has_event, event.is_some()) }?;
            unsafe { Pointer::write(out_kind, kind) }?;
            unsafe { Pointer::write(out_data, text.as_ptr()) }?;
            unsafe { Pointer::write(out_length, text.len()) }?;
            unsafe { Pointer::write(out_escaped, flag) }
        })())
    }

    /// Writes the byte offset of the next unread byte into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_reader_position(reader: *const JSONReader<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.position()) }
        })())
    }

    /// Writes the number of open arrays and objects into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_reader_depth(reader: *const JSONReader<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.depth()) }
        })())
    }

    /// Reads every remaining event, which validates the rest of the text.
    pub unsafe extern "C" fn umilib_codec_json_json_reader_validate(reader: *mut JSONReader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            while reader.next_event().map_err(|error| error.to_status())?.is_some() {}
            Ok(())
        })())
    }

    /// Decodes the escape sequences of a string as written in JSON text (without
    /// quotes), validating it first, and writes the result as UTF-8 into `out`.
    pub unsafe extern "C" fn umilib_codec_json_json_string_decode(raw: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let raw = unsafe { Pointer::slice(raw, length) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // Validate the text exactly as the reader would, closing quote included.
            let mut quoted = Vec::new();
            quoted.try_reserve_exact(length + 1).map_err(|_| &JSONStatus::ALLOCATION_FAILED)?;
            quoted.extend_from_slice(raw);
            quoted.push(b'"');
            let (string, end) = JSONString::scan(&quoted, 0).map_err(|error| error.to_status())?;
            if end != quoted.len() {
                return Err(&JSONStatus::UNEXPECTED_CHARACTER);
            }
            let decoded = string.decode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(decoded.into_bytes())) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "json",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_json_JSONValue",
            documentation: " A JSON value and everything it contains.",
        },
        Definition::Opaque {
            name: "umilib_codec_json_JSONNumber",
            documentation: " A JSON number, kept exactly as written.",
        },
        Definition::Opaque { name: "umilib_codec_json_JSONConfig", documentation: " Limits and options of parsing." },
        Definition::Opaque { name: "umilib_codec_json_JSONEncoder", documentation: " How values are written as text." },
        Definition::Opaque {
            name: "umilib_codec_json_JSONReader",
            documentation: " A pull parser over caller-owned bytes.",
        },
    ],
    functions: &Function::concat::<{ CONFIG.len() + METHODS.len() }>(&[CONFIG, METHODS]),
    modules: &[],
};
