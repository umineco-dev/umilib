//! The C ABI of [`crate::auth::sasl`].
//!
//! Messages are handles; texts are UTF-8 (a null text is an absent one),
//! written into buffers. A mechanism crosses as its index in
//! [`SASLMechanism::ALL`]; the channel binding flag of a GS2 header as `0`
//! (`n`), `1` (`y`) or `2` (`p`, with the type's name).

#[cfg(umilib_feature = "auth-sasl-anonymous")]
pub mod anonymous;
#[cfg(umilib_feature = "auth-sasl-external")]
pub mod external;
#[cfg(umilib_feature = "auth-sasl-oauthbearer")]
pub mod oauthbearer;
#[cfg(umilib_feature = "auth-sasl-plain")]
pub mod plain;
#[cfg(umilib_feature = "auth-sasl-scram")]
pub mod scram;

use alloc::string::String;

use crate::auth::sasl::{GS2ChannelBinding, GS2Header, SASLError, SASLMechanism};
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};

/// The statuses of this module, one per variant of [`SASLError`]
/// (stringprep errors keep those of `codec.stringprep`).
pub struct SASLStatus;

impl SASLStatus {
    pub const FORMAT: Status = Status::new(c"auth.sasl", c"Format", c"malformed SASL message");
    pub const LENGTH: Status =
        Status::new(c"auth.sasl", c"Length", c"a field of the SASL message is empty or too long");

    /// The channel binding flag of `kind` (0, 1, 2) with the type `name` for 2.
    pub fn channel_binding(kind: u8, name: Option<&str>) -> Result<GS2ChannelBinding, &'static Status> {
        match (kind, name) {
            (0, None) => Ok(GS2ChannelBinding::Unsupported),
            (1, None) => Ok(GS2ChannelBinding::NotOffered),
            (2, Some(name)) => Ok(GS2ChannelBinding::Required(String::from(name))),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    /// The C values of `binding`: the kind and the type's name (empty unless `p`).
    pub fn channel_binding_kind(binding: &GS2ChannelBinding) -> (u8, &str) {
        match binding {
            GS2ChannelBinding::Unsupported => (0, ""),
            GS2ChannelBinding::NotOffered => (1, ""),
            GS2ChannelBinding::Required(name) => (2, name),
        }
    }
}

impl ToStatus for SASLError {
    fn to_status(&self) -> &'static Status {
        match self {
            SASLError::Format => &SASLStatus::FORMAT,
            SASLError::Length => &SASLStatus::LENGTH,
            SASLError::Prepare(error) => error.to_status(),
        }
    }
}

impl Value for GS2Header {
    const TYPE: Type = Type::Named("umilib_auth_sasl_GS2Header");
}

crate::ffi_functions! {
    /// Writes the registered name of the mechanism at `index` into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_sasl_mechanism_name(index: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let mechanism = SASLMechanism::ALL.get(index as usize).ok_or(&Status::INVALID_ARGUMENT)?;
            // SAFETY: the caller passes a writable buffer.
            unsafe { Pointer::write_text(out, String::from(mechanism.name())) }
        })())
    }

    /// Writes whether the UTF-8 text at `name` names a mechanism this library implements into
    /// `out_found` and, if so, its index into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_sasl_mechanism_from_name(name: *const u8, length: usize, out_found: *mut bool, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and writable pointers.
            let name = unsafe { Pointer::text(name, length) }?;
            let index = SASLMechanism::from_name(name).and_then(|mechanism| SASLMechanism::ALL.iter().position(|own| *own == mechanism));
            unsafe { Pointer::write(out_found, index.is_some()) }?;
            unsafe { Pointer::write(out, index.unwrap_or_default() as u8) }
        })())
    }

    /// Writes whether the UTF-8 text at `name` has the syntax of a mechanism name (RFC 4422 §3.1) into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_sasl_mechanism_is_name(name: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let name = unsafe { Pointer::text(name, length) }?;
            unsafe { Pointer::write(out, SASLMechanism::is_name(name)) }
        })())
    }

    /// Writes the GS2 header of the channel binding flag `kind` (with the type's name at `name`
    /// for `p`, null otherwise), the non-standard flag `nonstandard` and the authorization identity
    /// at `authzid` (null for none) into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_gs2_header_new(kind: u8, name: *const u8, name_length: usize, nonstandard: bool, authzid: *const u8, authzid_length: usize, out: *mut *mut GS2Header) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes null or readable text and a writable pointer.
            let name = unsafe { Pointer::optional_text(name, name_length) }?;
            let authzid = unsafe { Pointer::optional_text(authzid, authzid_length) }?;
            let mut header = GS2Header::new(SASLStatus::channel_binding(kind, name)?, authzid);
            header.nonstandard = nonstandard;
            unsafe { Pointer::write_handle(out, header) }
        })())
    }

    /// Writes the length of the header at the start of the UTF-8 text at `text` (where the rest
    /// begins) into `out_length` and the header into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_gs2_header_decode(text: *const u8, length: usize, out_length: *mut usize, out: *mut *mut GS2Header) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and writable pointers.
            let text = unsafe { Pointer::text(text, length) }?;
            let (header, rest) = GS2Header::decode(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_length, text.len() - rest.len()) }?;
            unsafe { Pointer::write_handle(out, header) }
        })())
    }

    /// Writes the text of the header into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_gs2_header_encode(header: *const GS2Header, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let header = unsafe { Pointer::reference(header) }?;
            let text = header.encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, text) }
        })())
    }

    /// Writes the channel binding flag (0, 1 or 2) into `out_kind` and the type's name (empty unless
    /// 2) into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_gs2_header_channel_binding(header: *const GS2Header, out_kind: *mut u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let header = unsafe { Pointer::reference(header) }?;
            let (kind, name) = SASLStatus::channel_binding_kind(&header.channel_binding);
            unsafe { Pointer::write(out_kind, kind) }?;
            unsafe { Pointer::write_text(out, String::from(name)) }
        })())
    }

    /// Writes the non-standard flag into `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_gs2_header_nonstandard(header: *const GS2Header, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let header = unsafe { Pointer::reference(header) }?;
            unsafe { Pointer::write(out, header.nonstandard) }
        })())
    }

    /// Writes the authorization identity, if any, into `out_has` and `out`.
    pub unsafe extern "C" fn umilib_auth_sasl_gs2_header_authzid(header: *const GS2Header, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let header = unsafe { Pointer::reference(header) }?;
            unsafe { Pointer::write_optional_text(out_has, out, header.authzid.as_deref()) }
        })())
    }

    /// Releases a header. Does nothing if `header` is null.
    pub unsafe extern "C" fn umilib_auth_sasl_gs2_header_free(header: *mut GS2Header) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(header) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "sasl",
    definitions: &[Definition::Opaque {
        name: "umilib_auth_sasl_GS2Header",
        documentation: " A GS2 header (RFC 5801 §4).",
    }],
    functions: FUNCTIONS,
    modules: &[
        #[cfg(umilib_feature = "auth-sasl-anonymous")]
        anonymous::MODULE,
        #[cfg(umilib_feature = "auth-sasl-external")]
        external::MODULE,
        #[cfg(umilib_feature = "auth-sasl-oauthbearer")]
        oauthbearer::MODULE,
        #[cfg(umilib_feature = "auth-sasl-plain")]
        plain::MODULE,
        #[cfg(umilib_feature = "auth-sasl-scram")]
        scram::MODULE,
    ],
};
