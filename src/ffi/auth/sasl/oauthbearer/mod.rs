//! The C ABI of [`crate::auth::sasl::oauthbearer`].

use alloc::string::String;

use crate::auth::sasl::GS2Header;
use crate::auth::sasl::oauthbearer::{OAUTHBEARERErrorResult, OAUTHBEARERMessage};
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for OAUTHBEARERMessage {
    const TYPE: Type = Type::Named("umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage");
}

impl Value for OAUTHBEARERErrorResult {
    const TYPE: Type = Type::Named("umilib_auth_sasl_oauthbearer_OAUTHBEARERErrorResult");
}

crate::ffi_functions! {
    /// Writes the response of the bearer token at `token`, with the authorization identity at
    /// `authzid` and the host at `host` (null for none) and `port` (if `has_port`), into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_message_new(authzid: *const u8, authzid_length: usize, token: *const u8, token_length: usize, host: *const u8, host_length: usize, port: u16, has_port: bool, out: *mut *mut OAUTHBEARERMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes null or readable text and a writable pointer.
            let authzid = unsafe { Pointer::optional_text(authzid, authzid_length) }?;
            let token = unsafe { Pointer::text(token, token_length) }?;
            let host = unsafe { Pointer::optional_text(host, host_length) }?;
            let message = OAUTHBEARERMessage::new(authzid, token, host, has_port.then_some(port));
            unsafe { Pointer::write_handle(out, message) }
        })())
    }

    /// Writes the response of the `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_message_decode(data: *const u8, length: usize, out: *mut *mut OAUTHBEARERMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let message = OAUTHBEARERMessage::decode(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, message) }
        })())
    }

    /// Writes the bytes of the response into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_message_encode(message: *const OAUTHBEARERMessage, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let message = unsafe { Pointer::reference(message) }?;
            let encoded = message.encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(encoded)) }
        })())
    }

    /// Writes whether the `length` bytes at `data` are the dummy response into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_message_is_dummy(data: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            unsafe { Pointer::write(out, OAUTHBEARERMessage::is_dummy(data)) }
        })())
    }

    /// Writes a copy of the GS2 header into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_message_header(message: *const OAUTHBEARERMessage, out: *mut *mut GS2Header) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write_handle(out, message.header.clone()) }
        })())
    }

    /// Writes the value of the key named by the UTF-8 text at `key`, if present, into `out_has` and `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_message_get(message: *const OAUTHBEARERMessage, key: *const u8, key_length: usize, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and writable pointers.
            let message = unsafe { Pointer::reference(message) }?;
            let key = unsafe { Pointer::text(key, key_length) }?;
            unsafe { Pointer::write_optional_text(out_has, out, message.get(key)) }
        })())
    }

    /// Writes the number of key/value pairs into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_message_pair_count(message: *const OAUTHBEARERMessage, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write(out, message.pairs.len()) }
        })())
    }

    /// Writes the key of the pair at `index` into `out_key` and its value into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_message_pair(message: *const OAUTHBEARERMessage, index: usize, out_key: *mut Buffer, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable buffers.
            let message = unsafe { Pointer::reference(message) }?;
            let (key, value) = message.pairs.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_text(out_key, key.clone()) }?;
            unsafe { Pointer::write_text(out, value.clone()) }
        })())
    }

    /// Writes the port, if present and valid, into `out_has` and `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_message_port(message: *const OAUTHBEARERMessage, out_has: *mut bool, out: *mut u16) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let message = unsafe { Pointer::reference(message) }?;
            let port = message.port();
            unsafe { Pointer::write(out_has, port.is_some()) }?;
            unsafe { Pointer::write(out, port.unwrap_or_default()) }
        })())
    }

    /// Writes the bearer token of `auth`, if it is one, into `out_has` and `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_message_bearer_token(message: *const OAUTHBEARERMessage, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write_optional_text(out_has, out, message.bearer_token()) }
        })())
    }

    /// Releases a response. Does nothing if `message` is null.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_message_free(message: *mut OAUTHBEARERMessage) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(message) }
    }

    /// Writes the error result of the status at `status`, with the scope at `scope` and the OpenID
    /// configuration URL at `configuration` (null for none), into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_error_result_new(status: *const u8, status_length: usize, scope: *const u8, scope_length: usize, configuration: *const u8, configuration_length: usize, out: *mut *mut OAUTHBEARERErrorResult) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable or null text and a writable pointer.
            let status = unsafe { Pointer::text(status, status_length) }?;
            let mut result = OAUTHBEARERErrorResult::new(status);
            result.scope = unsafe { Pointer::optional_text(scope, scope_length) }?.map(String::from);
            result.openid_configuration = unsafe { Pointer::optional_text(configuration, configuration_length) }?.map(String::from);
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Writes the error result of the JSON at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_error_result_decode(data: *const u8, length: usize, out: *mut *mut OAUTHBEARERErrorResult) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let result = OAUTHBEARERErrorResult::decode(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, result) }
        })())
    }

    /// Writes the JSON of the error result into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_error_result_encode(result: *const OAUTHBEARERErrorResult, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let result = unsafe { Pointer::reference(result) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(result.encode())) }
        })())
    }

    /// Writes the status into `out_status`, the scope (if any) into `out_has_scope` and `out_scope`,
    /// and the OpenID configuration URL (if any) into `out_has_configuration` and `out_configuration`.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_error_result_parts(result: *const OAUTHBEARERErrorResult, out_status: *mut Buffer, out_has_scope: *mut bool, out_scope: *mut Buffer, out_has_configuration: *mut bool, out_configuration: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let result = unsafe { Pointer::reference(result) }?;
            unsafe { Pointer::write_text(out_status, result.status.clone()) }?;
            unsafe { Pointer::write_optional_text(out_has_scope, out_scope, result.scope.as_deref()) }?;
            unsafe { Pointer::write_optional_text(out_has_configuration, out_configuration, result.openid_configuration.as_deref()) }
        })())
    }

    /// Releases an error result. Does nothing if `result` is null.
    pub unsafe extern "C" fn umilib_auth_sasl_oauthbearer_oauthbearer_error_result_free(result: *mut OAUTHBEARERErrorResult) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(result) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "oauthbearer",
    definitions: &[
        Definition::Opaque {
            name: "umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage",
            documentation: " The initial client response of OAUTHBEARER (RFC 7628).",
        },
        Definition::Opaque {
            name: "umilib_auth_sasl_oauthbearer_OAUTHBEARERErrorResult",
            documentation: " The error result of a failed OAUTHBEARER exchange (RFC 7628).",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
