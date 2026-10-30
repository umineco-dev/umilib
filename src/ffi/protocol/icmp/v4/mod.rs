//! The C ABI of [`crate::protocol::icmp::v4`].
//!
//! A message is an [`FFIICMPHeader`] and its body; the functions that read a
//! field take the header (and the body when the field is in it).

use super::{FFIICMPHeader, ICMPStatus};
use crate::ffi::{Buffer, Module, Pointer, Status, ToStatus};
use crate::protocol::icmp::v4::{ICMPv4Message, ICMPv4Type};
use crate::protocol::ip::IPv4Address;
use crate::protocol::ip::v4::IPv4Header;

impl FFIICMPHeader {
    /// The ICMP message of this header and `body`.
    pub fn v4<'a>(&self, body: &'a [u8]) -> ICMPv4Message<'a> {
        ICMPv4Message { kind: ICMPv4Type(self.kind), code: self.code, rest: self.rest, body }
    }

    /// The header of `message`.
    pub fn from_v4(message: &ICMPv4Message) -> FFIICMPHeader {
        FFIICMPHeader { kind: message.kind.0, code: message.code, rest: message.rest }
    }
}

crate::ffi_functions! {
    /// Reads the message of the `length` bytes at `bytes`, whose checksum must be right, into `out`
    /// (its body is the bytes after the first eight); fails with Length or Checksum.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_message_decode(bytes: *const u8, length: usize, out: *mut FFIICMPHeader) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let message = ICMPv4Message::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, FFIICMPHeader::from_v4(&message)) }
        })())
    }

    /// Writes the message of `header` and the `length` bytes of body at `body`, with its checksum, into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_message_encode(header: FFIICMPHeader, body: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let body = unsafe { Pointer::slice(body, length) }?;
            unsafe { ICMPStatus::write_bytes(out, |bytes| header.v4(body).encode(bytes)) }
        })())
    }

    /// The header of an Echo Request of `identifier` and `sequence`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_message_echo_request(identifier: u16, sequence: u16) -> FFIICMPHeader {
        FFIICMPHeader::from_v4(&ICMPv4Message::echo_request(identifier, sequence, &[]))
    }

    /// Writes whether `header` is an Echo Request into `out_found` and the header of its reply into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_message_echo_reply(header: FFIICMPHeader, out_found: *mut bool, out: *mut FFIICMPHeader) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            let reply = header.v4(&[]).echo_reply();
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(out_found, reply.is_some()) }?;
            unsafe { Pointer::write(out, reply.map_or(header, |reply| FFIICMPHeader::from_v4(&reply))) }
        })())
    }

    /// Writes whether `header` is of an Echo, a Timestamp or their replies into `out_found`, and its
    /// identifier and sequence number into `out_identifier` and `out_sequence`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_message_query(header: FFIICMPHeader, out_found: *mut bool, out_identifier: *mut u16, out_sequence: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[Pointer::range(out_found, 1), Pointer::range(out_identifier, 1), Pointer::range(out_sequence, 1)],
            )?;
            let message = header.v4(&[]);
            Pointer::check_range(out_identifier, 1)?;
            Pointer::check_range(out_sequence, 1)?;
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(out_found, message.is_query()) }?;
            unsafe { Pointer::write(out_identifier, message.identifier().unwrap_or(0)) }?;
            unsafe { Pointer::write(out_sequence, message.sequence().unwrap_or(0)) }
        })())
    }

    /// Writes whether the message of `header` and the `length` bytes at `body` is a Timestamp or
    /// Timestamp Reply with its timestamps into `out_found`, and the originate, receive and transmit
    /// timestamps into the 3 values at `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_message_timestamps(header: FFIICMPHeader, body: *const u8, length: usize, out_found: *mut bool, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(body, length)],
                &[Pointer::range(out_found, 1), Pointer::range(out, 3)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let body = unsafe { Pointer::slice(body, length) }?;
            let out = unsafe { Pointer::slice_of_mut(out, 3) }?;
            Pointer::check_range(out_found, 1)?;
            let timestamps = header.v4(body).timestamps();
            out.copy_from_slice(&timestamps.unwrap_or_default());
            unsafe { Pointer::write(out_found, timestamps.is_some()) }
        })())
    }

    /// Writes whether `header` is a Fragmentation Needed message into `out_found` and the MTU of the
    /// next hop into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_message_next_hop_mtu(header: FFIICMPHeader, out_found: *mut bool, out: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            let mtu = header.v4(&[]).next_hop_mtu();
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(out_found, mtu.is_some()) }?;
            unsafe { Pointer::write(out, mtu.unwrap_or(0)) }
        })())
    }

    /// Writes whether `header` is a Parameter Problem into `out_found` and its pointer into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_message_pointer(header: FFIICMPHeader, out_found: *mut bool, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            let pointer = header.v4(&[]).pointer();
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(out_found, pointer.is_some()) }?;
            unsafe { Pointer::write(out, pointer.unwrap_or(0)) }
        })())
    }

    /// Writes whether `header` is a Redirect into `out_found` and its gateway into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_message_gateway(header: FFIICMPHeader, out_found: *mut bool, out: *mut IPv4Address) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            let gateway = header.v4(&[]).gateway();
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(out_found, gateway.is_some()) }?;
            unsafe { Pointer::write(out, gateway.unwrap_or_default()) }
        })())
    }

    /// Writes the length of the original datagram an error message of `header` and the `length`
    /// bytes at `body` quotes into `out_original` and whether an extension structure follows it into
    /// `out_found`; fails with Length, Version or Checksum.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_message_original(header: FFIICMPHeader, body: *const u8, length: usize, out_original: *mut usize, out_found: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(body, length)],
                &[Pointer::range(out_original, 1), Pointer::range(out_found, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let body = unsafe { Pointer::slice(body, length) }?;
            Pointer::check_range(out_original, 1)?;
            Pointer::check_range(out_found, 1)?;
            let (original, extensions) = header.v4(body).original().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_original, original.len()) }?;
            unsafe { Pointer::write(out_found, extensions.is_some()) }
        })())
    }

    /// The bytes of a datagram of `length` bytes that an error message quotes under an IPv4 header
    /// of `header_length` bytes, within 576 bytes (RFC 1812 §4.3.2.3).
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_message_quote_length(length: usize, header_length: usize) -> usize {
        ICMPv4Message::quote_length(length, header_length)
    }

    /// Writes whether an error message may be sent about the datagram of `header` and the `length`
    /// bytes of data at `payload`, received as a broadcast if `broadcast` (RFC 1122 §3.2.2), into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_message_may_report(header: *const IPv4Header, payload: *const u8, length: usize, broadcast: bool, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(header, 1), Pointer::range(payload, length)],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes a valid structure, readable bytes and a writable pointer.
            let header = unsafe { Pointer::reference(header) }?;
            let payload = unsafe { Pointer::slice(payload, length) }?;
            unsafe { Pointer::write(out, ICMPv4Message::may_report(header, payload, broadcast)) }
        })())
    }

    /// Whether the type `kind` is that of an error message.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_type_is_error(kind: u8) -> bool {
        ICMPv4Type(kind).is_error()
    }

    /// Whether the type `kind` is deprecated (RFC 6633, RFC 6918).
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_type_is_deprecated(kind: u8) -> bool {
        ICMPv4Type(kind).is_deprecated()
    }

    /// Whether an error of the type `kind` carries the length attribute of RFC 4884.
    pub unsafe extern "C" fn umilib_protocol_icmp_v4_icmpv4_type_is_extensible(kind: u8) -> bool {
        ICMPv4Type(kind).is_extensible()
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "v4", definitions: &[], functions: FUNCTIONS, modules: &[] };
