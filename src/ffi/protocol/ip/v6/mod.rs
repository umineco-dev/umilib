//! The C ABI of [`crate::protocol::ip::v6`].
//!
//! Headers are structures; an extension header chain is walked by the
//! caller, who keeps the Next Header value and the offset between calls.
//! The fragmenter keeps a copy of the packet and gives each fragment as
//! its bytes; the reassembler is a handle, and an abandoned packet is a
//! handle of its own. Instants and durations are nanoseconds.

use alloc::vec::Vec;
use core::time::Duration;

use crate::bytes::Buffer as Bytes;
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::ip::v6::{
    IPv6Error, IPv6ExtensionHeader, IPv6ExtensionHeaders, IPv6FragmentHeader, IPv6Fragmenter, IPv6Header, IPv6Option,
    IPv6OptionKind, IPv6OptionsHeader, IPv6Reassembler, IPv6Reassembly, IPv6ReassemblyConfig, IPv6ReassemblyKey,
    IPv6RoutingHeader,
};
use crate::protocol::ip::{IPProtocol, IPv6Address};
use crate::runtime::Instant;

/// The statuses of this module, one per variant of [`IPv6Error`] that is not
/// another module's.
pub struct IPv6Status;

impl IPv6Status {
    pub const VERSION: Status = Status::new(c"protocol.ip.v6", c"Version", c"the packet is not of IP version 6");
    pub const LENGTH: Status =
        Status::new(c"protocol.ip.v6", c"Length", c"the lengths of the packet are not consistent");
    pub const EXTENSION_HEADER: Status =
        Status::new(c"protocol.ip.v6", c"ExtensionHeader", c"an extension header is out of place");
    pub const OPTION: Status = Status::new(c"protocol.ip.v6", c"Option", c"the options are malformed");
    pub const HEADER_CHAIN: Status =
        Status::new(c"protocol.ip.v6", c"HeaderChain", c"the first fragment does not hold the whole header chain");
    pub const FRAGMENT: Status =
        Status::new(c"protocol.ip.v6", c"Fragment", c"the packet cannot be fragmented to fit the MTU");
    pub const LIMIT: Status =
        Status::new(c"protocol.ip.v6", c"Limit", c"the fragment does not fit the reassembly limits");
    pub const EXPIRED: Status =
        Status::new(c"protocol.ip.v6", c"Expired", c"the reassembly deadline of the datagram is past");
}

impl ToStatus for IPv6Error {
    fn to_status(&self) -> &'static Status {
        match self {
            IPv6Error::Version => &IPv6Status::VERSION,
            IPv6Error::Length => &IPv6Status::LENGTH,
            IPv6Error::ExtensionHeader => &IPv6Status::EXTENSION_HEADER,
            IPv6Error::Option => &IPv6Status::OPTION,
            IPv6Error::HeaderChain => &IPv6Status::HEADER_CHAIN,
            IPv6Error::Fragment => &IPv6Status::FRAGMENT,
            IPv6Error::Reassembly(error) => error.to_status(),
            IPv6Error::Limit => &IPv6Status::LIMIT,
            IPv6Error::Expired => &IPv6Status::EXPIRED,
            IPv6Error::Write(error) => error.to_status(),
        }
    }
}

/// The C form of an [`IPv6ReassemblyConfig`], the timeout in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FFIIPv6ReassemblyConfig {
    pub timeout: u64,
    pub maximum_length: usize,
    pub maximum_datagrams: usize,
    pub maximum_buffered: usize,
}

impl From<FFIIPv6ReassemblyConfig> for IPv6ReassemblyConfig {
    fn from(config: FFIIPv6ReassemblyConfig) -> IPv6ReassemblyConfig {
        IPv6ReassemblyConfig {
            timeout: Duration::from_nanos(config.timeout),
            maximum_length: config.maximum_length,
            maximum_datagrams: config.maximum_datagrams,
            maximum_buffered: config.maximum_buffered,
        }
    }
}

impl From<IPv6ReassemblyConfig> for FFIIPv6ReassemblyConfig {
    fn from(config: IPv6ReassemblyConfig) -> FFIIPv6ReassemblyConfig {
        FFIIPv6ReassemblyConfig {
            timeout: u64::try_from(config.timeout.as_nanos()).unwrap_or(u64::MAX),
            maximum_length: config.maximum_length,
            maximum_datagrams: config.maximum_datagrams,
            maximum_buffered: config.maximum_buffered,
        }
    }
}

/// An [`IPv6Fragmenter`] that owns the payload it cuts.
#[derive(Clone, Debug)]
pub struct FFIIPv6Fragmenter {
    pub header: IPv6Header,
    pub payload: Vec<u8>,
    pub identification: u32,
    pub mtu: usize,
    pub position: usize,
    pub done: bool,
}

impl Value for IPv6Header {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v6_IPv6Header");
}

impl Value for IPv6FragmentHeader {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v6_IPv6FragmentHeader");
}

impl Value for FFIIPv6ReassemblyConfig {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v6_IPv6ReassemblyConfig");
}

impl Value for IPv6ReassemblyKey {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v6_IPv6ReassemblyKey");
}

impl Value for FFIIPv6Fragmenter {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v6_IPv6Fragmenter");
}

impl Value for IPv6Reassembler {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v6_IPv6Reassembler");
}

impl Value for IPv6Reassembly {
    const TYPE: Type = Type::Named("umilib_protocol_ip_v6_IPv6Reassembly");
}

impl IPv6Status {
    /// Writes what `write` writes into a new buffer at `out`.
    ///
    /// # Safety
    /// As [`Pointer::write`].
    pub unsafe fn write_bytes(
        out: *mut Buffer,
        write: impl FnOnce(&mut Bytes) -> Result<(), IPv6Error>,
    ) -> Result<(), &'static Status> {
        Pointer::check_range(out, 1)?;
        let mut bytes = Bytes::new();
        write(&mut bytes).map_err(|error| error.to_status())?;
        // SAFETY: the caller's promise.
        unsafe { Pointer::write(out, Buffer::from_vec(bytes.into_vec())) }
    }
}

crate::ffi_functions! {
    /// Writes the header of a packet of `payload_length` bytes starting with `next_header` into
    /// `out`; fails with Length beyond 65,535 bytes.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_header_new(source: IPv6Address, destination: IPv6Address, next_header: u8, payload_length: usize, out: *mut IPv6Header) -> *const Status {
        Status::from_result((|| {
            let header = IPv6Header::new(source, destination, IPProtocol(next_header), payload_length).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, header) }
        })())
    }

    /// Reads the header at the start of the `length` bytes at `bytes` into `out` and the offset and
    /// length of its payload into `out_offset` and `out_length`; fails with Version or Length.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_header_decode(bytes: *const u8, length: usize, out: *mut IPv6Header, out_offset: *mut usize, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(bytes, length)],
                &[Pointer::range(out, 1), Pointer::range(out_offset, 1), Pointer::range(out_length, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out_offset, 1)?;
            Pointer::check_range(out_length, 1)?;
            let (header, payload) = IPv6Header::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, header) }?;
            unsafe { Pointer::write(out_offset, IPv6Header::LENGTH) }?;
            unsafe { Pointer::write(out_length, payload.len()) }
        })())
    }

    /// Reads the header at the start of the `length` bytes at `bytes`, whose payload may be cut short
    /// (as an ICMP error quotes it), into `out` and the offset and length of the payload present into
    /// `out_offset` and `out_length`; fails with Version or Length.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_header_decode_truncated(bytes: *const u8, length: usize, out: *mut IPv6Header, out_offset: *mut usize, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(bytes, length)],
                &[Pointer::range(out, 1), Pointer::range(out_offset, 1), Pointer::range(out_length, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out_offset, 1)?;
            Pointer::check_range(out_length, 1)?;
            let (header, data) = IPv6Header::decode_truncated(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, header) }?;
            unsafe { Pointer::write(out_offset, IPv6Header::LENGTH) }?;
            unsafe { Pointer::write(out_length, data.len()) }
        })())
    }

    /// Writes the 40 bytes of the header into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_header_encode(header: *const IPv6Header, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure and a writable buffer.
            let header = unsafe { Pointer::reference(header) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(header.to_bytes().to_vec())) }
        })())
    }

    /// Whether `kind` names an extension header that a chain continues after.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_extension_header_is_extension(kind: u8) -> bool {
        IPv6ExtensionHeader::is_extension(IPProtocol(kind))
    }

    /// Writes the length of the extension header of `kind` that the `length` bytes at `bytes` start
    /// with into `out`; fails with Length.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_extension_header_length(kind: u8, bytes: *const u8, length: usize, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let length = IPv6ExtensionHeader::length(IPProtocol(kind), bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, length) }
        })())
    }

    /// Reads the extension header at `*offset` of the `length` bytes of payload at `payload`, named
    /// by `*next_header`: writes whether there is one into `out_found` and its length into
    /// `out_length`, and moves `*next_header` and `*offset` past it. At the end of the chain,
    /// `*next_header` is the upper layer and `*offset` its start. Fails with Length or
    /// ExtensionHeader.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_extension_headers_next(next_header: *mut u8, payload: *const u8, length: usize, offset: *mut usize, out_found: *mut bool, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(payload, length)],
                &[
                    Pointer::range(next_header, 1),
                    Pointer::range(offset, 1),
                    Pointer::range(out_found, 1),
                    Pointer::range(out_length, 1),
                ],
            )?;
            // SAFETY: the caller passes readable bytes and valid, writable pointers.
            let kind = unsafe { Pointer::reference_mut(next_header) }?;
            let position = unsafe { Pointer::reference_mut(offset) }?;
            let payload = unsafe { Pointer::slice(payload, length) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_length, 1)?;
            let bytes = payload.get(*position..).ok_or(&Status::INVALID_ARGUMENT)?;
            let mut headers = IPv6ExtensionHeaders { next_header: IPProtocol(*kind), bytes, offset: *position, failed: false };
            let header = headers.next().transpose().map_err(|error| error.to_status())?;
            if let Some(header) = header {
                (*kind, *position) = (headers.next_header.0, headers.offset);
                unsafe { Pointer::write(out_length, header.bytes.len()) }?;
            }
            unsafe { Pointer::write(out_found, header.is_some()) }
        })())
    }

    /// Writes the upper layer of the `length` bytes of payload at `payload`, whose first header is
    /// named by `next_header`, into `out_protocol` and the offset of its data into `out_offset`.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_extension_headers_upper_layer(next_header: u8, payload: *const u8, length: usize, out_protocol: *mut u8, out_offset: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(payload, length)],
                &[Pointer::range(out_protocol, 1), Pointer::range(out_offset, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let payload = unsafe { Pointer::slice(payload, length) }?;
            Pointer::check_range(out_protocol, 1)?;
            Pointer::check_range(out_offset, 1)?;
            let (protocol, offset) = IPv6ExtensionHeaders::upper_layer(IPProtocol(next_header), payload).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_protocol, protocol.0) }?;
            unsafe { Pointer::write(out_offset, offset) }
        })())
    }

    /// What a node that does not recognize an option of `kind` does (0 to 3).
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_option_kind_action(kind: u8) -> u8 {
        IPv6OptionKind(kind).action()
    }

    /// Whether the data of an option of `kind` may change en route.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_option_kind_may_change(kind: u8) -> bool {
        IPv6OptionKind(kind).may_change()
    }

    /// Writes an option of `kind` with the `length` bytes of data at `data` into `out`; fails with Option.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_option_encode(kind: u8, data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            unsafe { IPv6Status::write_bytes(out, |bytes| IPv6Option::encode(IPv6OptionKind(kind), data, bytes)) }
        })())
    }

    /// Writes `length` bytes of padding (Pad1 or PadN) into `out`; fails with Option beyond 257.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_option_encode_padding(length: usize, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable buffer.
        Status::from_result(unsafe { IPv6Status::write_bytes(out, |bytes| IPv6Option::encode_padding(length, bytes)) })
    }

    /// Checks the Hop-by-Hop or Destination Options header of the `length` bytes at `bytes` and
    /// writes its Next Header value into `out`; fails with Length or Option.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_options_header_decode(bytes: *const u8, length: usize, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let header = IPv6OptionsHeader::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, header.next_header.0) }
        })())
    }

    /// Writes whether the options header of the `length` bytes at `bytes` has an option at `index`
    /// (padding not counted) into `out_found`, its type into `out_kind`, the offset of its type in
    /// the header into `out_offset` and its data into `out`; fails with Length or Option.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_options_header_get(bytes: *const u8, length: usize, index: usize, out_found: *mut bool, out_kind: *mut u8, out_offset: *mut usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(bytes, length)],
                &[Pointer::range(out_found, 1), Pointer::range(out_kind, 1), Pointer::range(out_offset, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out_offset, 1)?;
            Pointer::check_range(out, 1)?;
            let header = IPv6OptionsHeader::decode(bytes).map_err(|error| error.to_status())?;
            let option = header.iter().nth(index).transpose().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_found, option.is_some()) }?;
            unsafe { Pointer::write(out_kind, option.map_or(0, |option| option.kind.0)) }?;
            unsafe { Pointer::write(out_offset, option.map_or(0, |option| option.offset)) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(option.map(|option| option.data.to_vec()).unwrap_or_default())) }
        })())
    }

    /// Writes an options header of `next_header` with the `length` bytes of encoded options at
    /// `options`, padded to a multiple of 8 bytes, into `out`; fails with Length.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_options_header_encode(next_header: u8, options: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let options = unsafe { Pointer::slice(options, length) }?;
            unsafe { IPv6Status::write_bytes(out, |bytes| IPv6OptionsHeader { next_header: IPProtocol(next_header), options }.encode(bytes)) }
        })())
    }

    /// Reads the Routing header of the `length` bytes at `bytes`: its Next Header value into
    /// `out_next_header`, its type into `out_routing_type`, its Segments Left into
    /// `out_segments_left` and the bytes after the first four into `out`; fails with Length.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_routing_header_decode(bytes: *const u8, length: usize, out_next_header: *mut u8, out_routing_type: *mut u8, out_segments_left: *mut u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(bytes, length)],
                &[
                    Pointer::range(out_next_header, 1),
                    Pointer::range(out_routing_type, 1),
                    Pointer::range(out_segments_left, 1),
                ],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            for pointer in [out_next_header, out_routing_type, out_segments_left] {
                Pointer::check_range(pointer, 1)?;
            }
            Pointer::check_range(out, 1)?;
            let header = IPv6RoutingHeader::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_next_header, header.next_header.0) }?;
            unsafe { Pointer::write(out_routing_type, header.routing_type) }?;
            unsafe { Pointer::write(out_segments_left, header.segments_left) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(header.data.to_vec())) }
        })())
    }

    /// Writes the Routing header of `next_header`, `routing_type`, `segments_left` and the `length`
    /// bytes at `data` into `out`; fails with Length.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_routing_header_encode(next_header: u8, routing_type: u8, segments_left: u8, data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let header = IPv6RoutingHeader { next_header: IPProtocol(next_header), routing_type, segments_left, data };
            unsafe { IPv6Status::write_bytes(out, |bytes| header.encode(bytes)) }
        })())
    }

    /// Reads the Fragment header at the start of the `length` bytes at `bytes` into `out`; fails with Length.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_fragment_header_decode(bytes: *const u8, length: usize, out: *mut IPv6FragmentHeader) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let header = IPv6FragmentHeader::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, header) }
        })())
    }

    /// Writes the 8 bytes of the Fragment header into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_fragment_header_encode(header: IPv6FragmentHeader, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable buffer.
        Status::from_result(unsafe { Pointer::write(out, Buffer::from_vec(header.to_bytes().to_vec())) })
    }

    /// Whether the fragment is a whole packet (RFC 6946).
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_fragment_header_is_atomic(header: IPv6FragmentHeader) -> bool {
        header.is_atomic()
    }

    /// Writes a fragmenter of a copy of the `length` bytes of payload at `payload` after `header`,
    /// identified by `identification`, for `mtu` into `out`; fails with Fragment, HeaderChain or Length.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_fragmenter_new(header: *const IPv6Header, payload: *const u8, length: usize, identification: u32, mtu: usize, out: *mut *mut FFIIPv6Fragmenter) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, readable bytes and a writable pointer.
            let header = unsafe { Pointer::reference(header) }?;
            let payload = unsafe { Pointer::slice(payload, length) }?;
            IPv6Fragmenter::new(*header, payload, identification, mtu).map_err(|error| error.to_status())?;
            let fragmenter = FFIIPv6Fragmenter { header: *header, payload: payload.to_vec(), identification, mtu, position: 0, done: false };
            unsafe { Pointer::write_handle(out, fragmenter) }
        })())
    }

    /// Releases a fragmenter. Does nothing if `fragmenter` is null.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_fragmenter_free(fragmenter: *mut FFIIPv6Fragmenter) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(fragmenter) }
    }

    /// Writes whether there is a next packet into `out_found` and its bytes into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_fragmenter_next(fragmenter: *mut FFIIPv6Fragmenter, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let state = unsafe { Pointer::reference_mut(fragmenter) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let mut fragmenter = IPv6Fragmenter::new(state.header, &state.payload, state.identification, state.mtu).map_err(|error| error.to_status())?;
            (fragmenter.position, fragmenter.done) = (state.position, state.done);
            let next = fragmenter.next();
            (state.position, state.done) = (fragmenter.position, fragmenter.done);
            unsafe { Pointer::write(out_found, next.is_some()) }?;
            match next {
                Some(fragment) => unsafe { IPv6Status::write_bytes(out, |bytes| fragment.encode(bytes)) },
                None => Ok(()),
            }
        })())
    }

    /// Writes the default limits of a reassembler into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_reassembly_config_default(out: *mut FFIIPv6ReassemblyConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, IPv6ReassemblyConfig::default().into()) })
    }

    /// Writes a reassembler with the limits `config` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_reassembler_new(config: FFIIPv6ReassemblyConfig, out: *mut *mut IPv6Reassembler) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, IPv6Reassembler::new(config.into())) })
    }

    /// Releases a reassembler. Does nothing if `reassembler` is null.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_reassembler_free(reassembler: *mut IPv6Reassembler) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(reassembler) }
    }

    /// Adds the packet of `header` and the `length` bytes of payload at `payload`, received at `now`,
    /// and writes whether it completes a packet into `out_complete`, and that packet's header and
    /// payload into `out` and `out_payload`; fails with Length, HeaderChain, Limit, ExtensionHeader,
    /// Overlap (the packet is discarded) or the Length of `protocol.ip`.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_reassembler_receive(reassembler: *mut IPv6Reassembler, header: *const IPv6Header, payload: *const u8, length: usize, now: u64, out_complete: *mut bool, out: *mut IPv6Header, out_payload: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(header, 1), Pointer::range(payload, length)],
                &[Pointer::range(out_complete, 1), Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and structure, readable bytes and writable pointers.
            let reassembler = unsafe { Pointer::reference_mut(reassembler) }?;
            let header = unsafe { Pointer::reference(header) }?;
            let payload = unsafe { Pointer::slice(payload, length) }?;
            Pointer::check_range(out_complete, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_payload, 1)?;
            let result = reassembler.receive(header, payload, Instant::from_nanos(now)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_complete, result.is_some()) }?;
            if let Some((header, payload)) = result {
                unsafe { Pointer::write(out, header) }?;
                unsafe { Pointer::write(out_payload, Buffer::from_vec(payload)) }?;
            }
            Ok(())
        })())
    }

    /// Writes whether a packet is being reassembled into `out_found` and the earliest deadline into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_reassembler_poll_timeout(reassembler: *const IPv6Reassembler, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reassembler = unsafe { Pointer::reference(reassembler) }?;
            let deadline = reassembler.poll_timeout();
            unsafe { Pointer::write(out_found, deadline.is_some()) }?;
            unsafe { Pointer::write(out, deadline.map_or(0, Instant::as_nanos)) }
        })())
    }

    /// Removes a packet whose deadline is at or before `now` and writes whether there was one into
    /// `out_found`, its key into `out_key` and it into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_reassembler_expire(reassembler: *mut IPv6Reassembler, now: u64, out_found: *mut bool, out_key: *mut IPv6ReassemblyKey, out: *mut *mut IPv6Reassembly) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out_key, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reassembler = unsafe { Pointer::reference_mut(reassembler) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_key, 1)?;
            Pointer::check_range(out, 1)?;
            let expired = reassembler.expire(Instant::from_nanos(now));
            unsafe { Pointer::write(out_found, expired.is_some()) }?;
            if let Some((key, reassembly)) = expired {
                unsafe { Pointer::write(out_key, key) }?;
                unsafe { Pointer::write_handle(out, reassembly) }?;
            }
            Ok(())
        })())
    }

    /// Writes whether fragments of the packet overlapped (RFC 5722) into `out`: it then has no
    /// first fragment, and no ICMP message is sent for it.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_reassembly_abandoned(reassembly: *const IPv6Reassembly, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reassembly = unsafe { Pointer::reference(reassembly) }?;
            unsafe { Pointer::write(out, reassembly.abandoned) }
        })())
    }

    /// Releases a packet given back by expire. Does nothing if `reassembly` is null.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_reassembly_free(reassembly: *mut IPv6Reassembly) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(reassembly) }
    }

    /// Writes whether the first fragment was received into `out_found`, the bytes of its packet up
    /// to its data (the IPv6 header, the per-fragment headers and the Fragment header) into
    /// `out_headers`, and the data received (zeros between the fragments) into `out_data`.
    pub unsafe extern "C" fn umilib_protocol_ip_v6_ipv6_reassembly_first(reassembly: *const IPv6Reassembly, out_found: *mut bool, out_headers: *mut Buffer, out_data: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reassembly = unsafe { Pointer::reference(reassembly) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_headers, 1)?;
            Pointer::check_range(out_data, 1)?;
            if let Some(first) = &reassembly.first {
                let mut headers = first.header.to_bytes().to_vec();
                headers.extend_from_slice(&first.per_fragment);
                match first.next_header_offset {
                    Some(offset) => headers[IPv6Header::LENGTH + offset] = IPProtocol::IPV6_FRAGMENT.0,
                    None => headers[6] = IPProtocol::IPV6_FRAGMENT.0,
                }
                headers.extend_from_slice(&first.fragment.to_bytes());
                unsafe { Pointer::write(out_headers, Buffer::from_vec(headers)) }?;
            }
            unsafe { Pointer::write(out_found, reassembly.first.is_some()) }?;
            unsafe { Pointer::write(out_data, Buffer::from_vec(reassembly.buffer.data.clone())) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v6",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_ip_v6_IPv6Header",
            documentation: " The fixed header of an IPv6 packet (RFC 8200 §3).",
            fields: &[
                Parameter { name: "dscp", value: <u8 as Value>::TYPE },
                Parameter { name: "ecn", value: <u8 as Value>::TYPE },
                Parameter { name: "flow_label", value: <u32 as Value>::TYPE },
                Parameter { name: "payload_length", value: <u16 as Value>::TYPE },
                Parameter { name: "next_header", value: <u8 as Value>::TYPE },
                Parameter { name: "hop_limit", value: <u8 as Value>::TYPE },
                Parameter { name: "source", value: <IPv6Address as Value>::TYPE },
                Parameter { name: "destination", value: <IPv6Address as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_ip_v6_IPv6FragmentHeader",
            documentation: " A Fragment header (RFC 8200 §4.5); the offset in units of 8 bytes.",
            fields: &[
                Parameter { name: "next_header", value: <u8 as Value>::TYPE },
                Parameter { name: "fragment_offset", value: <u16 as Value>::TYPE },
                Parameter { name: "more_fragments", value: <bool as Value>::TYPE },
                Parameter { name: "identification", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_ip_v6_IPv6ReassemblyConfig",
            documentation: " The limits of a reassembler; the timeout in nanoseconds.",
            fields: &[
                Parameter { name: "timeout", value: <u64 as Value>::TYPE },
                Parameter { name: "maximum_length", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_datagrams", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_buffered", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_ip_v6_IPv6ReassemblyKey",
            documentation: " What identifies the fragments of one packet.",
            fields: &[
                Parameter { name: "source", value: <IPv6Address as Value>::TYPE },
                Parameter { name: "destination", value: <IPv6Address as Value>::TYPE },
                Parameter { name: "identification", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_ip_v6_IPv6Fragmenter",
            documentation: " The fragments of a packet that fit an MTU.",
        },
        Definition::Opaque {
            name: "umilib_protocol_ip_v6_IPv6Reassembler",
            documentation: " The reassembly of IPv6 packets from their fragments.",
        },
        Definition::Opaque {
            name: "umilib_protocol_ip_v6_IPv6Reassembly",
            documentation: " A packet given back by the reassembler at its deadline.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
