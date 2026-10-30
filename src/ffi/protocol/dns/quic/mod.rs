//! The C ABI of [`crate::protocol::dns::quic`].
//!
//! A connection's DNS is a handle of its state ([`DNSQUICConnection`]);
//! its QUIC connection is one of an endpoint of
//! [`crate::ffi::protocol::quic`], named by the endpoint and the
//! connection's number in every call. An event is a structure and its
//! message a buffer. Times are nanoseconds of the caller's monotonic clock.

use alloc::vec::Vec;

use crate::ffi::protocol::dns::DNSStatus;
use crate::ffi::protocol::quic::{FFIQUICEvent, QUICStatus};
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::dns::quic::{DNSQUICConnection, DNSQUICError, DNSQUICEvent};
use crate::protocol::dns::tcp::DNSTCPFramer;
use crate::protocol::quic::{QUICEndpoint, QUICRole, QUICStreamID};
use crate::runtime::Instant;

/// The statuses of this module.
pub struct DNSQUICStatus;

impl DNSQUICStatus {
    pub const PROTOCOL: Status = Status::new(
        c"protocol.dns.quic",
        c"Protocol",
        c"a breach of DNS over QUIC: the connection is closed with PROTOCOL_ERROR",
    );
}

impl ToStatus for DNSQUICError {
    fn to_status(&self) -> &'static Status {
        match self {
            DNSQUICError::DNS(error) => error.to_status(),
            DNSQUICError::QUIC(error) => error.to_status(),
            DNSQUICError::Protocol(_) => &DNSQUICStatus::PROTOCOL,
        }
    }
}

/// A [`DNSQUICEvent`]: `kind` 0 a query (on `stream`), 1 a response, 2 a
/// stream cancelled with `error`, 3 an event of QUIC itself (to read with
/// the QUIC connection); the message is beside it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDNSQUICEvent {
    pub kind: u8,
    pub stream: u64,
    pub error: u64,
}

impl Value for FFIDNSQUICEvent {
    const TYPE: Type = Type::Named("umilib_protocol_dns_quic_DNSQUICEvent");
}

impl Value for DNSQUICConnection {
    const TYPE: Type = Type::Named("umilib_protocol_dns_quic_DNSQUICConnection");
}

crate::ffi_functions! {
    /// Writes the DNS of a connection of a client (or, if `server`, of a server) into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_quic_dns_quic_connection_new(server: bool, out: *mut *mut DNSQUICConnection) -> *const Status {
        let role = if server { QUICRole::Server } else { QUICRole::Client };
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, DNSQUICConnection::new(role)) })
    }

    /// Releases a connection's DNS. Does nothing if `connection` is null.
    pub unsafe extern "C" fn umilib_protocol_dns_quic_dns_quic_connection_free(connection: *mut DNSQUICConnection) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(connection) }
    }

    /// Sends the query of the `length` bytes at `query` on a new stream of the QUIC connection `quic`
    /// of `endpoint` (its ID made 0, RFC 9250 §4.2.1), and writes the stream into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_quic_dns_quic_connection_send_query(connection: *mut DNSQUICConnection, endpoint: *mut QUICEndpoint, quic: u64, query: *const u8, length: usize, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(query, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes valid handles, readable bytes and a writable pointer.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let query = crate::protocol::dns::DNSMessage::decode(unsafe { Pointer::slice(query, length) }?).map_err(|error| error.to_status())?;
            let quic = QUICStatus::connection(endpoint, quic)?;
            let stream = connection.send_query(quic, &query).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, stream.0) }
        })())
    }

    /// Sends the responses of the `length` bytes at `responses` (each after its 2-byte length, as
    /// `dns_authority_respond` writes them: one, or the messages of a zone transfer) to the query of
    /// `stream`, the stream ended after them; fails with Malformed for bytes not so framed.
    pub unsafe extern "C" fn umilib_protocol_dns_quic_dns_quic_connection_send_response(connection: *mut DNSQUICConnection, endpoint: *mut QUICEndpoint, quic: u64, stream: u64, responses: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable bytes.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let mut framer = DNSTCPFramer::new();
            framer.receive(unsafe { Pointer::slice(responses, length) }?);
            let responses = core::iter::from_fn(|| framer.next_message()).collect::<Result<Vec<_>, _>>().map_err(|error| error.to_status())?;
            if framer.is_partial() {
                return Err(&DNSStatus::MALFORMED);
            }
            let quic = QUICStatus::connection(endpoint, quic)?;
            connection.send_response(quic, QUICStreamID(stream), &responses).map_err(|error| error.to_status())
        })())
    }

    /// Takes the events of the QUIC connection `quic` of `endpoint` at `now`; a breach of RFC 9250
    /// closes the connection and fails with Protocol.
    pub unsafe extern "C" fn umilib_protocol_dns_quic_dns_quic_connection_process(connection: *mut DNSQUICConnection, endpoint: *mut QUICEndpoint, quic: u64, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let quic = QUICStatus::connection(endpoint, quic)?;
            connection.process(quic, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Writes whether an event is pending into `out_found`, the event into `out`, and its message (or,
    /// for an event of QUIC, its token or reason phrase) into `out_message`; an event of QUIC itself
    /// into `out_quic`.
    pub unsafe extern "C" fn umilib_protocol_dns_quic_dns_quic_connection_poll_event(connection: *mut DNSQUICConnection, out_found: *mut bool, out: *mut FFIDNSQUICEvent, out_quic: *mut FFIQUICEvent, out_message: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[Pointer::range(out_found, 1), Pointer::range(out, 1), Pointer::range(out_quic, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_message, 1)?;
            Pointer::check_range(out_quic, 1)?;
            let event = connection.poll_event();
            let mut quic_event = FFIQUICEvent::default();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let (structure, message) = match event {
                Some(DNSQUICEvent::Query { stream, message }) => (FFIDNSQUICEvent { kind: 0, stream: stream.0, error: 0 }, message),
                Some(DNSQUICEvent::Response { stream, message }) => {
                    (FFIDNSQUICEvent { kind: 1, stream: stream.0, error: 0 }, message.encode(crate::protocol::dns::DNSMessage::MAXIMUM_SIZE).unwrap_or_default())
                }
                Some(DNSQUICEvent::Cancelled { stream, error }) => (FFIDNSQUICEvent { kind: 2, stream: stream.0, error: error.0 }, alloc::vec::Vec::new()),
                Some(DNSQUICEvent::QUIC(event)) => {
                    let (structure, bytes) = FFIQUICEvent::of(event);
                    quic_event = structure;
                    (FFIDNSQUICEvent { kind: 3, stream: 0, error: 0 }, bytes)
                }
                None => (FFIDNSQUICEvent::default(), alloc::vec::Vec::new()),
            };
            unsafe { Pointer::write(out, structure) }?;
            unsafe { Pointer::write(out_quic, quic_event) }?;
            unsafe { Pointer::write(out_message, Buffer::from_vec(message)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "quic",
    definitions: &[
        Definition::Opaque {
            name: "umilib_protocol_dns_quic_DNSQUICConnection",
            documentation: " The DNS of a QUIC connection.",
        },
        Definition::Structure {
            name: "umilib_protocol_dns_quic_DNSQUICEvent",
            documentation: " An event: 0 a query, 1 a response, 2 a stream cancelled, 3 an event of QUIC.",
            fields: &[
                Parameter { name: "kind", value: <u8 as Value>::TYPE },
                Parameter { name: "stream", value: <u64 as Value>::TYPE },
                Parameter { name: "error", value: <u64 as Value>::TYPE },
            ],
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
