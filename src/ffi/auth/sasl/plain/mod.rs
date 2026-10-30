//! The C ABI of [`crate::auth::sasl::plain`].

use crate::auth::sasl::plain::PLAINMessage;
use crate::ffi::codec::stringprep::UnassignedKind;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for PLAINMessage {
    const TYPE: Type = Type::Named("umilib_auth_sasl_plain_PLAINMessage");
}

crate::ffi_functions! {
    /// Writes the message of the authorization identity at `authzid` (null for none), the
    /// authentication identity at `authcid` and the password at `password` (UTF-8) into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_plain_plain_message_new(authzid: *const u8, authzid_length: usize, authcid: *const u8, authcid_length: usize, password: *const u8, password_length: usize, out: *mut *mut PLAINMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes null or readable text and a writable pointer.
            let authzid = unsafe { Pointer::optional_text(authzid, authzid_length) }?;
            let authcid = unsafe { Pointer::text(authcid, authcid_length) }?;
            let password = unsafe { Pointer::text(password, password_length) }?;
            unsafe { Pointer::write_handle(out, PLAINMessage::new(authzid, authcid, password)) }
        })())
    }

    /// Writes the message of the `length` bytes at `data` (RFC 4616 §2) into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_plain_plain_message_decode(data: *const u8, length: usize, out: *mut *mut PLAINMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let message = PLAINMessage::decode(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, message) }
        })())
    }

    /// Writes the bytes of the message, which hold the password, into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_plain_plain_message_encode(message: *const PLAINMessage, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let message = unsafe { Pointer::reference(message) }?;
            let encoded = message.encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(encoded.expose().clone())) }
        })())
    }

    /// Writes the authorization identity, if any, into `out_has` and `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_plain_plain_message_authzid(message: *const PLAINMessage, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write_optional_text(out_has, out, message.authzid.as_deref()) }
        })())
    }

    /// Writes the authentication identity into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_plain_plain_message_authcid(message: *const PLAINMessage, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write_text(out, message.authcid.clone()) }
        })())
    }

    /// Writes the password into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_plain_plain_message_password(message: *const PLAINMessage, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write_text(out, message.password.expose().clone()) }
        })())
    }

    /// Writes the authentication identity prepared with SASLprep as a query into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_plain_plain_message_prepared_authcid(message: *const PLAINMessage, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let message = unsafe { Pointer::reference(message) }?;
            let prepared = message.prepared_authcid().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, prepared) }
        })())
    }

    /// Writes whether the password matches the stored password at `stored` (both prepared with
    /// SASLprep, compared in constant time) into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_plain_plain_message_verify_password(message: *const PLAINMessage, stored: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            let stored = unsafe { Pointer::text(stored, length) }?;
            unsafe { Pointer::write(out, message.verify_password(stored)) }
        })())
    }

    /// Writes the UTF-8 text at `text` prepared with SASLprep (`unassigned`: 0 for a query, 1 for a
    /// stored string) into `out`; fails with Length for an empty result.
    pub unsafe extern "C" fn umilib_auth_sasl_plain_plain_message_prepare(text: *const u8, length: usize, unassigned: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable buffer.
            let text = unsafe { Pointer::text(text, length) }?;
            let prepared = PLAINMessage::prepare(text, UnassignedKind::decode(unassigned)?).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, prepared) }
        })())
    }

    /// Releases a message, zeroizing its password. Does nothing if `message` is null.
    pub unsafe extern "C" fn umilib_auth_sasl_plain_plain_message_free(message: *mut PLAINMessage) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(message) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "plain",
    definitions: &[Definition::Opaque {
        name: "umilib_auth_sasl_plain_PLAINMessage",
        documentation: " The message of PLAIN (RFC 4616).",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
