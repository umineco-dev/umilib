//! The C ABI of [`crate::protocol::dns::tls`].
//!
//! The messages of DNS over TLS are those of a TCP stream
//! ([`crate::ffi::protocol::dns::tcp`]) as the application data of a TLS
//! connection of [`crate::ffi::protocol::tls`].

use crate::ffi::{Buffer, Module, Pointer, Status};
use crate::protocol::dns::tls::DNSTLS;
use crate::protocol::tls::TLSConnection;

crate::ffi_functions! {
    /// Writes the ALPN of DNS over TLS, "dot", into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_tls_dns_tls_alpn(out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, Buffer::from_vec(DNSTLS::ALPN.to_vec())) })
    }

    /// Writes whether the application protocol `connection` negotiated is none or "dot" into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_tls_dns_tls_check_protocol(connection: *const TLSConnection, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write(out, DNSTLS::check_protocol(connection).is_ok()) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "tls", definitions: &[], functions: FUNCTIONS, modules: &[] };
