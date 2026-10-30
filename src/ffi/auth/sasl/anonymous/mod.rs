//! The C ABI of [`crate::auth::sasl::anonymous`].

use crate::auth::sasl::anonymous::ANONYMOUSMessage;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for ANONYMOUSMessage {
    const TYPE: Type = Type::Named("umilib_auth_sasl_anonymous_ANONYMOUSMessage");
}

crate::ffi_functions! {
    /// Writes the message of the trace information at `trace` (null for none) into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_anonymous_anonymous_message_new(trace: *const u8, length: usize, out: *mut *mut ANONYMOUSMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes null or readable text and a writable pointer.
            let trace = unsafe { Pointer::optional_text(trace, length) }?;
            unsafe { Pointer::write_handle(out, ANONYMOUSMessage::new(trace)) }
        })())
    }

    /// Writes the message of the `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_anonymous_anonymous_message_decode(data: *const u8, length: usize, out: *mut *mut ANONYMOUSMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let message = ANONYMOUSMessage::decode(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, message) }
        })())
    }

    /// Writes the bytes of the message into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_anonymous_anonymous_message_encode(message: *const ANONYMOUSMessage, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let message = unsafe { Pointer::reference(message) }?;
            let encoded = message.encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(encoded)) }
        })())
    }

    /// Writes the trace information, if any, into `out_has` and `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_anonymous_anonymous_message_trace(message: *const ANONYMOUSMessage, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write_optional_text(out_has, out, message.trace.as_deref()) }
        })())
    }

    /// Writes whether the trace information has the form of an email address (it holds `@`) into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_anonymous_anonymous_message_is_email(message: *const ANONYMOUSMessage, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write(out, message.is_email()) }
        })())
    }

    /// Releases a message. Does nothing if `message` is null.
    pub unsafe extern "C" fn umilib_auth_sasl_anonymous_anonymous_message_free(message: *mut ANONYMOUSMessage) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(message) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "anonymous",
    definitions: &[Definition::Opaque {
        name: "umilib_auth_sasl_anonymous_ANONYMOUSMessage",
        documentation: " The message of ANONYMOUS (RFC 4505).",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
