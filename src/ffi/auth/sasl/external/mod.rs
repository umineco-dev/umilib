//! The C ABI of [`crate::auth::sasl::external`].

use crate::auth::sasl::external::EXTERNALMessage;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for EXTERNALMessage {
    const TYPE: Type = Type::Named("umilib_auth_sasl_external_EXTERNALMessage");
}

crate::ffi_functions! {
    /// Writes the message of the authorization identity at `authzid` (null for none) into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_external_external_message_new(authzid: *const u8, length: usize, out: *mut *mut EXTERNALMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes null or readable text and a writable pointer.
            let authzid = unsafe { Pointer::optional_text(authzid, length) }?;
            unsafe { Pointer::write_handle(out, EXTERNALMessage::new(authzid)) }
        })())
    }

    /// Writes the message of the `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_external_external_message_decode(data: *const u8, length: usize, out: *mut *mut EXTERNALMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let message = EXTERNALMessage::decode(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, message) }
        })())
    }

    /// Writes the bytes of the message into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_external_external_message_encode(message: *const EXTERNALMessage, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let message = unsafe { Pointer::reference(message) }?;
            let encoded = message.encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(encoded)) }
        })())
    }

    /// Writes the authorization identity, if any, into `out_has` and `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_external_external_message_authzid(message: *const EXTERNALMessage, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write_optional_text(out_has, out, message.authzid.as_deref()) }
        })())
    }

    /// Releases a message. Does nothing if `message` is null.
    pub unsafe extern "C" fn umilib_auth_sasl_external_external_message_free(message: *mut EXTERNALMessage) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(message) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "external",
    definitions: &[Definition::Opaque {
        name: "umilib_auth_sasl_external_EXTERNALMessage",
        documentation: " The message of EXTERNAL (RFC 4422 appendix A).",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
