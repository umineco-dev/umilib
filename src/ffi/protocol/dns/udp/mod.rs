//! The C ABI of [`crate::protocol::dns::udp`].

use crate::ffi::protocol::ip::FFIIPEndpoint;
use crate::ffi::{Module, Pointer, Status};
use crate::protocol::dns::udp::DNSUDP;

crate::ffi_functions! {
    /// Writes whether a datagram from `source` may be the response to a query sent to `destination`
    /// (RFC 5452 §9.1: the same address and port) into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_udp_dns_udp_accepts(source: FFIIPEndpoint, destination: FFIIPEndpoint, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            let accepts = DNSUDP::accepts(&source.endpoint()?, &destination.endpoint()?);
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, accepts) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "udp", definitions: &[], functions: FUNCTIONS, modules: &[] };
