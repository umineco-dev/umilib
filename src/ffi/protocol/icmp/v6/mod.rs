//! The C ABI of [`crate::protocol::icmp::v6`], with Neighbor Discovery for
//! 6-byte link-layer addresses (those of Ethernet).
//!
//! A message is an [`FFIICMPHeader`] and its body; a Neighbor Discovery
//! message is read from them into a structure of its fields and the offset
//! of its options in the body. The neighbor cache is a handle; the packets
//! and events it gives are handles of their own. A reachability state
//! crosses as 0 (INCOMPLETE), 1 (REACHABLE), 2 (STALE), 3 (DELAY) or 4
//! (PROBE). Instants and durations are nanoseconds.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::time::Duration;

use super::{FFIICMPHeader, ICMPStatus};
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::icmp::v6::{
    ICMPv6Message, ICMPv6Type, NDPMessage, NDPNeighborAdvertisement, NDPNeighborSolicitation, NDPOption, NDPOptionKind,
    NDPOptions, NDPPrefixInformation, NDPRecursiveDNSServers, NDPRedirect, NDPRouteInformation, NDPRouterAdvertisement,
    NDPRouterSolicitation, NeighborCache, NeighborConfig, NeighborEvent, NeighborResolution, NeighborState,
};
use crate::protocol::ip::IPv6Address;
use crate::protocol::ip::v6::IPv6Header;
use crate::runtime::Instant;

impl FFIICMPHeader {
    /// The ICMPv6 message of this header and `body`.
    pub fn v6<'a>(&self, body: &'a [u8]) -> ICMPv6Message<'a> {
        ICMPv6Message { kind: ICMPv6Type(self.kind), code: self.code, rest: self.rest, body }
    }

    /// The header of `message`.
    pub fn from_v6(message: &ICMPv6Message) -> FFIICMPHeader {
        FFIICMPHeader { kind: message.kind.0, code: message.code, rest: message.rest }
    }
}

/// The fields of a Router Advertisement but its options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct FFINDPRouterAdvertisement {
    pub current_hop_limit: u8,
    pub managed_flag: bool,
    pub other_flag: bool,
    pub preference: u8,
    pub flags: u8,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retransmission_timer: u32,
}

impl FFINDPRouterAdvertisement {
    pub fn with<'a>(&self, options: &'a [u8]) -> NDPRouterAdvertisement<'a> {
        NDPRouterAdvertisement {
            current_hop_limit: self.current_hop_limit,
            managed_flag: self.managed_flag,
            other_flag: self.other_flag,
            preference: self.preference,
            flags: self.flags,
            router_lifetime: self.router_lifetime,
            reachable_time: self.reachable_time,
            retransmission_timer: self.retransmission_timer,
            options,
        }
    }

    pub fn of(advertisement: &NDPRouterAdvertisement) -> FFINDPRouterAdvertisement {
        FFINDPRouterAdvertisement {
            current_hop_limit: advertisement.current_hop_limit,
            managed_flag: advertisement.managed_flag,
            other_flag: advertisement.other_flag,
            preference: advertisement.preference,
            flags: advertisement.flags,
            router_lifetime: advertisement.router_lifetime,
            reachable_time: advertisement.reachable_time,
            retransmission_timer: advertisement.retransmission_timer,
        }
    }
}

/// The fields of a Neighbor Advertisement but its options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct FFINDPNeighborAdvertisement {
    pub router_flag: bool,
    pub solicited_flag: bool,
    pub override_flag: bool,
    pub target: IPv6Address,
}

impl FFINDPNeighborAdvertisement {
    pub fn with<'a>(&self, options: &'a [u8]) -> NDPNeighborAdvertisement<'a> {
        NDPNeighborAdvertisement {
            router_flag: self.router_flag,
            solicited_flag: self.solicited_flag,
            override_flag: self.override_flag,
            target: self.target,
            options,
        }
    }

    pub fn of(advertisement: &NDPNeighborAdvertisement) -> FFINDPNeighborAdvertisement {
        FFINDPNeighborAdvertisement {
            router_flag: advertisement.router_flag,
            solicited_flag: advertisement.solicited_flag,
            override_flag: advertisement.override_flag,
            target: advertisement.target,
        }
    }
}

/// The C form of a [`NeighborConfig`], the durations in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FFINeighborConfig {
    pub reachable_time: u64,
    pub retransmission_timer: u64,
    pub delay_first_probe_time: u64,
    pub maximum_multicast_solicitations: u32,
    pub maximum_unicast_solicitations: u32,
    pub maximum_entries: usize,
    pub maximum_queued: usize,
}

impl From<FFINeighborConfig> for NeighborConfig {
    fn from(config: FFINeighborConfig) -> NeighborConfig {
        NeighborConfig {
            reachable_time: Duration::from_nanos(config.reachable_time),
            retransmission_timer: Duration::from_nanos(config.retransmission_timer),
            delay_first_probe_time: Duration::from_nanos(config.delay_first_probe_time),
            maximum_multicast_solicitations: config.maximum_multicast_solicitations,
            maximum_unicast_solicitations: config.maximum_unicast_solicitations,
            maximum_entries: config.maximum_entries,
            maximum_queued: config.maximum_queued,
        }
    }
}

impl From<NeighborConfig> for FFINeighborConfig {
    fn from(config: NeighborConfig) -> FFINeighborConfig {
        let nanoseconds = |duration: Duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        FFINeighborConfig {
            reachable_time: nanoseconds(config.reachable_time),
            retransmission_timer: nanoseconds(config.retransmission_timer),
            delay_first_probe_time: nanoseconds(config.delay_first_probe_time),
            maximum_multicast_solicitations: config.maximum_multicast_solicitations,
            maximum_unicast_solicitations: config.maximum_unicast_solicitations,
            maximum_entries: config.maximum_entries,
            maximum_queued: config.maximum_queued,
        }
    }
}

/// Packets the neighbor cache gives back, in the form of a handle.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FFINeighborPackets {
    pub packets: VecDeque<Vec<u8>>,
}

/// What [`NeighborCache::poll`] reports, in the form of a handle: the kind
/// (1 for a solicitation to send, 2 for an unreachable neighbor), the
/// target, the link-layer address of a unicast solicitation, and the
/// packets dropped with an unreachable neighbor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FFINeighborEvent {
    pub kind: u8,
    pub target: IPv6Address,
    pub link: Option<[u8; 6]>,
    pub packets: VecDeque<Vec<u8>>,
}

impl FFINeighborEvent {
    pub fn of(event: NeighborEvent<[u8; 6]>) -> FFINeighborEvent {
        match event {
            NeighborEvent::Solicit { target, link } => {
                FFINeighborEvent { kind: 1, target, link, packets: VecDeque::new() }
            }
            NeighborEvent::Unreachable { target, packets } => FFINeighborEvent { kind: 2, target, link: None, packets },
        }
    }
}

/// The C number of a reachability state.
pub struct FFINeighborState;

impl FFINeighborState {
    pub fn of(state: &NeighborState<[u8; 6]>) -> u8 {
        match state {
            NeighborState::Incomplete { .. } => 0,
            NeighborState::Reachable { .. } => 1,
            NeighborState::Stale { .. } => 2,
            NeighborState::Delay { .. } => 3,
            NeighborState::Probe { .. } => 4,
        }
    }
}

impl Value for FFINDPRouterAdvertisement {
    const TYPE: Type = Type::Named("umilib_protocol_icmp_v6_NDPRouterAdvertisement");
}

impl Value for FFINDPNeighborAdvertisement {
    const TYPE: Type = Type::Named("umilib_protocol_icmp_v6_NDPNeighborAdvertisement");
}

impl Value for NDPPrefixInformation {
    const TYPE: Type = Type::Named("umilib_protocol_icmp_v6_NDPPrefixInformation");
}

impl Value for NDPRouteInformation {
    const TYPE: Type = Type::Named("umilib_protocol_icmp_v6_NDPRouteInformation");
}

impl Value for FFINeighborConfig {
    const TYPE: Type = Type::Named("umilib_protocol_icmp_v6_NeighborConfig");
}

impl Value for NeighborCache<[u8; 6]> {
    const TYPE: Type = Type::Named("umilib_protocol_icmp_v6_NeighborCache");
}

impl Value for FFINeighborPackets {
    const TYPE: Type = Type::Named("umilib_protocol_icmp_v6_NeighborPackets");
}

impl Value for FFINeighborEvent {
    const TYPE: Type = Type::Named("umilib_protocol_icmp_v6_NeighborEvent");
}

impl FFINeighborPackets {
    /// Writes a handle of `packets` into `out`.
    ///
    /// # Safety
    /// As [`Pointer::write_handle`].
    pub unsafe fn write(out: *mut *mut FFINeighborPackets, packets: VecDeque<Vec<u8>>) -> Result<(), &'static Status> {
        // SAFETY: the caller's promise.
        unsafe { Pointer::write_handle(out, FFINeighborPackets { packets }) }
    }
}

crate::ffi_functions! {
    /// Reads the message of the `length` bytes at `bytes`, carried from `source` to `destination`,
    /// whose checksum must be right, into `out` (its body is the bytes after the first eight); fails
    /// with Length or Checksum.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_icmpv6_message_decode(bytes: *const u8, length: usize, source: IPv6Address, destination: IPv6Address, out: *mut FFIICMPHeader) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let message = ICMPv6Message::decode(bytes, source, destination).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, FFIICMPHeader::from_v6(&message)) }
        })())
    }

    /// Writes the message of `header` and the `length` bytes of body at `body`, with its checksum
    /// for `source` and `destination`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_icmpv6_message_encode(header: FFIICMPHeader, body: *const u8, length: usize, source: IPv6Address, destination: IPv6Address, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let body = unsafe { Pointer::slice(body, length) }?;
            unsafe { ICMPStatus::write_bytes(out, |bytes| header.v6(body).encode(source, destination, bytes)) }
        })())
    }

    /// The header of an Echo Request of `identifier` and `sequence`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_icmpv6_message_echo_request(identifier: u16, sequence: u16) -> FFIICMPHeader {
        FFIICMPHeader::from_v6(&ICMPv6Message::echo_request(identifier, sequence, &[]))
    }

    /// Writes whether `header` is an Echo Request into `out_found` and the header of its reply into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_icmpv6_message_echo_reply(header: FFIICMPHeader, out_found: *mut bool, out: *mut FFIICMPHeader) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            let reply = header.v6(&[]).echo_reply();
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(out_found, reply.is_some()) }?;
            unsafe { Pointer::write(out, reply.map_or(header, |reply| FFIICMPHeader::from_v6(&reply))) }
        })())
    }

    /// Writes whether `header` is of an Echo Request or Reply into `out_found`, and its identifier and
    /// sequence number into `out_identifier` and `out_sequence`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_icmpv6_message_echo(header: FFIICMPHeader, out_found: *mut bool, out_identifier: *mut u16, out_sequence: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[Pointer::range(out_found, 1), Pointer::range(out_identifier, 1), Pointer::range(out_sequence, 1)],
            )?;
            let message = header.v6(&[]);
            Pointer::check_range(out_identifier, 1)?;
            Pointer::check_range(out_sequence, 1)?;
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(out_found, message.is_echo()) }?;
            unsafe { Pointer::write(out_identifier, message.identifier().unwrap_or(0)) }?;
            unsafe { Pointer::write(out_sequence, message.sequence().unwrap_or(0)) }
        })())
    }

    /// Writes whether `header` is a Packet Too Big into `out_found` and its MTU into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_icmpv6_message_mtu(header: FFIICMPHeader, out_found: *mut bool, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            let mtu = header.v6(&[]).mtu();
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(out_found, mtu.is_some()) }?;
            unsafe { Pointer::write(out, mtu.unwrap_or(0)) }
        })())
    }

    /// Writes whether `header` is a Parameter Problem into `out_found` and its pointer into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_icmpv6_message_pointer(header: FFIICMPHeader, out_found: *mut bool, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            let pointer = header.v6(&[]).pointer();
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(out_found, pointer.is_some()) }?;
            unsafe { Pointer::write(out, pointer.unwrap_or(0)) }
        })())
    }

    /// Writes the length of the invoking packet an error message of `header` and the `length` bytes
    /// at `body` quotes into `out_original` and whether an extension structure follows it into
    /// `out_found`; fails with Length, Version or Checksum.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_icmpv6_message_original(header: FFIICMPHeader, body: *const u8, length: usize, out_original: *mut usize, out_found: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(body, length)],
                &[Pointer::range(out_original, 1), Pointer::range(out_found, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let body = unsafe { Pointer::slice(body, length) }?;
            Pointer::check_range(out_original, 1)?;
            Pointer::check_range(out_found, 1)?;
            let (original, extensions) = header.v6(body).original().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_original, original.len()) }?;
            unsafe { Pointer::write(out_found, extensions.is_some()) }
        })())
    }

    /// The bytes of a packet of `length` bytes that an error message quotes after an IPv6 header and
    /// `headers` bytes of extension headers, within 1,280 bytes (RFC 4443 §2.4 (c)).
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_icmpv6_message_quote_length(length: usize, headers: usize) -> usize {
        ICMPv6Message::quote_length(length, headers)
    }

    /// Writes whether the error of the header `error` may be sent about the packet of `header` and
    /// the `length` bytes of payload at `payload`, received as a link-layer multicast or broadcast if
    /// `multicast` (RFC 4443 §2.4 (e)), into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_icmpv6_message_may_report(header: *const IPv6Header, payload: *const u8, length: usize, multicast: bool, error: FFIICMPHeader, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(header, 1), Pointer::range(payload, length)],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes a valid structure, readable bytes and a writable pointer.
            let header = unsafe { Pointer::reference(header) }?;
            let payload = unsafe { Pointer::slice(payload, length) }?;
            unsafe { Pointer::write(out, ICMPv6Message::may_report(header, payload, multicast, &error.v6(&[]))) }
        })())
    }

    /// Whether the type `kind` is that of an error message (below 128).
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_icmpv6_type_is_error(kind: u8) -> bool {
        ICMPv6Type(kind).is_error()
    }

    /// Whether an error of the type `kind` carries the length attribute of RFC 4884.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_icmpv6_type_is_extensible(kind: u8) -> bool {
        ICMPv6Type(kind).is_extensible()
    }

    /// Whether `address` is a solicited-node multicast address.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_message_is_solicited_node(address: IPv6Address) -> bool {
        NDPMessage::is_solicited_node(&address)
    }

    /// Checks that the message of `header` and the `length` bytes at `body`, carried by the packet of
    /// `packet`, is a valid Router Solicitation (RFC 4861 §6.1.1); its options are its body. Fails
    /// with Invalid.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_router_solicitation_decode(header: FFIICMPHeader, body: *const u8, length: usize, packet: *const IPv6Header) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a valid structure.
            let body = unsafe { Pointer::slice(body, length) }?;
            let packet = unsafe { Pointer::reference(packet) }?;
            NDPRouterSolicitation::decode(&header.v6(body), packet).map(|_| ()).map_err(|error| error.to_status())
        })())
    }

    /// Writes the Router Solicitation of the `length` bytes of options at `options`, from `source`
    /// to `destination`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_router_solicitation_encode(options: *const u8, length: usize, source: IPv6Address, destination: IPv6Address, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let options = unsafe { Pointer::slice(options, length) }?;
            unsafe { ICMPStatus::write_bytes(out, |bytes| NDPRouterSolicitation { options }.encode(source, destination, bytes)) }
        })())
    }

    /// Reads the valid Router Advertisement (RFC 4861 §6.1.2) of `header` and the `length` bytes at
    /// `body`, carried by the packet of `packet`, into `out` and the offset of its options in the body
    /// into `out_offset`; fails with Invalid.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_router_advertisement_decode(header: FFIICMPHeader, body: *const u8, length: usize, packet: *const IPv6Header, out: *mut FFINDPRouterAdvertisement, out_offset: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(body, length), Pointer::range(packet, 1)],
                &[Pointer::range(out, 1), Pointer::range(out_offset, 1)],
            )?;
            // SAFETY: the caller passes readable bytes, a valid structure and writable pointers.
            let body = unsafe { Pointer::slice(body, length) }?;
            let packet = unsafe { Pointer::reference(packet) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_offset, 1)?;
            let advertisement = NDPRouterAdvertisement::decode(&header.v6(body), packet).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, FFINDPRouterAdvertisement::of(&advertisement)) }?;
            unsafe { Pointer::write(out_offset, body.len() - advertisement.options.len()) }
        })())
    }

    /// Writes the Router Advertisement of `advertisement` and the `length` bytes of options at
    /// `options`, from `source` to `destination`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_router_advertisement_encode(advertisement: *const FFINDPRouterAdvertisement, options: *const u8, length: usize, source: IPv6Address, destination: IPv6Address, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, readable bytes and a writable buffer.
            let advertisement = unsafe { Pointer::reference(advertisement) }?;
            let options = unsafe { Pointer::slice(options, length) }?;
            unsafe { ICMPStatus::write_bytes(out, |bytes| advertisement.with(options).encode(source, destination, bytes)) }
        })())
    }

    /// Reads the valid Neighbor Solicitation (RFC 4861 §7.1.1) of `header` and the `length` bytes at
    /// `body`, carried by the packet of `packet`: its target into `out` and the offset of its options
    /// in the body into `out_offset`; fails with Invalid.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_neighbor_solicitation_decode(header: FFIICMPHeader, body: *const u8, length: usize, packet: *const IPv6Header, out: *mut IPv6Address, out_offset: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(body, length), Pointer::range(packet, 1)],
                &[Pointer::range(out, 1), Pointer::range(out_offset, 1)],
            )?;
            // SAFETY: the caller passes readable bytes, a valid structure and writable pointers.
            let body = unsafe { Pointer::slice(body, length) }?;
            let packet = unsafe { Pointer::reference(packet) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_offset, 1)?;
            let solicitation = NDPNeighborSolicitation::decode(&header.v6(body), packet).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, solicitation.target) }?;
            unsafe { Pointer::write(out_offset, body.len() - solicitation.options.len()) }
        })())
    }

    /// Writes the Neighbor Solicitation for `target` with the `length` bytes of options at `options`,
    /// from `source` to `destination`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_neighbor_solicitation_encode(target: IPv6Address, options: *const u8, length: usize, source: IPv6Address, destination: IPv6Address, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let options = unsafe { Pointer::slice(options, length) }?;
            let solicitation = NDPNeighborSolicitation { target, options };
            unsafe { ICMPStatus::write_bytes(out, |bytes| solicitation.encode(source, destination, bytes)) }
        })())
    }

    /// Reads the valid Neighbor Advertisement (RFC 4861 §7.1.2) of `header` and the `length` bytes at
    /// `body`, carried by the packet of `packet`, into `out` and the offset of its options in the body
    /// into `out_offset`; fails with Invalid.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_neighbor_advertisement_decode(header: FFIICMPHeader, body: *const u8, length: usize, packet: *const IPv6Header, out: *mut FFINDPNeighborAdvertisement, out_offset: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(body, length), Pointer::range(packet, 1)],
                &[Pointer::range(out, 1), Pointer::range(out_offset, 1)],
            )?;
            // SAFETY: the caller passes readable bytes, a valid structure and writable pointers.
            let body = unsafe { Pointer::slice(body, length) }?;
            let packet = unsafe { Pointer::reference(packet) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_offset, 1)?;
            let advertisement = NDPNeighborAdvertisement::decode(&header.v6(body), packet).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, FFINDPNeighborAdvertisement::of(&advertisement)) }?;
            unsafe { Pointer::write(out_offset, body.len() - advertisement.options.len()) }
        })())
    }

    /// Writes the Neighbor Advertisement of `advertisement` and the `length` bytes of options at
    /// `options`, from `source` to `destination`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_neighbor_advertisement_encode(advertisement: *const FFINDPNeighborAdvertisement, options: *const u8, length: usize, source: IPv6Address, destination: IPv6Address, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, readable bytes and a writable buffer.
            let advertisement = unsafe { Pointer::reference(advertisement) }?;
            let options = unsafe { Pointer::slice(options, length) }?;
            unsafe { ICMPStatus::write_bytes(out, |bytes| advertisement.with(options).encode(source, destination, bytes)) }
        })())
    }

    /// Reads the Redirect (RFC 4861 §8.1, but for its first hop) of `header` and the `length` bytes at
    /// `body`, carried by the packet of `packet`: its target and destination into `out_target` and
    /// `out_destination` and the offset of its options in the body into `out_offset`; fails with Invalid.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_redirect_decode(header: FFIICMPHeader, body: *const u8, length: usize, packet: *const IPv6Header, out_target: *mut IPv6Address, out_destination: *mut IPv6Address, out_offset: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(body, length), Pointer::range(packet, 1)],
                &[Pointer::range(out_target, 1), Pointer::range(out_destination, 1), Pointer::range(out_offset, 1)],
            )?;
            // SAFETY: the caller passes readable bytes, a valid structure and writable pointers.
            let body = unsafe { Pointer::slice(body, length) }?;
            let packet = unsafe { Pointer::reference(packet) }?;
            for pointer in [out_target, out_destination] {
                Pointer::check_range(pointer, 1)?;
            }
            Pointer::check_range(out_offset, 1)?;
            let redirect = NDPRedirect::decode(&header.v6(body), packet).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_target, redirect.target) }?;
            unsafe { Pointer::write(out_destination, redirect.destination) }?;
            unsafe { Pointer::write(out_offset, body.len() - redirect.options.len()) }
        })())
    }

    /// Writes the Redirect to `target` for `destination` with the `length` bytes of options at
    /// `options`, from `source` to `to`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_redirect_encode(target: IPv6Address, destination: IPv6Address, options: *const u8, length: usize, source: IPv6Address, to: IPv6Address, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let options = unsafe { Pointer::slice(options, length) }?;
            let redirect = NDPRedirect { target, destination, options };
            unsafe { ICMPStatus::write_bytes(out, |bytes| redirect.encode(source, to, bytes)) }
        })())
    }

    /// Writes whether the `length` bytes of options at `options` have an option at `index` into
    /// `out_found`, its type into `out_kind` and its data into `out`; fails with Invalid for an
    /// option of length zero before it.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_options_get(options: *const u8, length: usize, index: usize, out_found: *mut bool, out_kind: *mut u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(options, length)],
                &[Pointer::range(out_found, 1), Pointer::range(out_kind, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let options = unsafe { Pointer::slice(options, length) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out, 1)?;
            let option = NDPOptions::new(options).nth(index).transpose().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_found, option.is_some()) }?;
            unsafe { Pointer::write(out_kind, option.map_or(0, |option| option.kind.0)) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(option.map(|option| option.data.to_vec()).unwrap_or_default())) }
        })())
    }

    /// Writes an option of `kind` with the `length` bytes of data at `data`, padded to 8 bytes, into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_option_encode(kind: u8, data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            unsafe { ICMPStatus::write_bytes(out, |bytes| NDPOption::encode(NDPOptionKind(kind), data, bytes)) }
        })())
    }

    /// Writes whether the option of `kind` and the `length` bytes of data at `data` is an MTU option
    /// into `out_found` and its MTU into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_option_mtu(kind: u8, data: *const u8, length: usize, out_found: *mut bool, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(data, length)],
                &[Pointer::range(out_found, 1), Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let data = unsafe { Pointer::slice(data, length) }?;
            let mtu = NDPOption { kind: NDPOptionKind(kind), data }.mtu();
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out_found, mtu.is_some()) }?;
            unsafe { Pointer::write(out, mtu.unwrap_or(0)) }
        })())
    }

    /// Checks the prefix length, the lifetimes and the flags of `information`; fails with Invalid.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_prefix_information_check(information: NDPPrefixInformation) -> *const Status {
        Status::from_result(information.check().map_err(|error| error.to_status()))
    }

    /// Reads the Prefix Information option of the `length` bytes of data at `data` into `out`; fails with Invalid.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_prefix_information_decode(data: *const u8, length: usize, out: *mut NDPPrefixInformation) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let information = NDPPrefixInformation::decode(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, information) }
        })())
    }

    /// Writes the Prefix Information option of `information` into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_prefix_information_encode(information: NDPPrefixInformation, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable buffer.
        Status::from_result(unsafe { ICMPStatus::write_bytes(out, |bytes| information.encode(bytes)) })
    }

    /// Reads the Route Information option of the `length` bytes of data at `data` into `out`; fails with Invalid.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_route_information_decode(data: *const u8, length: usize, out: *mut NDPRouteInformation) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let information = NDPRouteInformation::decode(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, information) }
        })())
    }

    /// Writes the Route Information option of `information` into `out`; fails with Invalid for a
    /// prefix length beyond 128.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_route_information_encode(information: NDPRouteInformation, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable buffer.
        Status::from_result(unsafe { ICMPStatus::write_bytes(out, |bytes| information.encode(bytes)) })
    }

    /// Reads the Recursive DNS Server option of the `length` bytes of data at `data`: its lifetime
    /// into `out_lifetime` and its addresses, 16 bytes each, into `out`; fails with Invalid.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_recursive_dns_servers_decode(data: *const u8, length: usize, out_lifetime: *mut u32, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out_lifetime, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out_lifetime, 1)?;
            Pointer::check_range(out, 1)?;
            let servers = NDPRecursiveDNSServers::decode(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_lifetime, servers.lifetime) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(servers.addresses.to_vec())) }
        })())
    }

    /// Writes the Recursive DNS Server option of `lifetime` and the `length` bytes of addresses at
    /// `addresses` into `out`; fails with Invalid unless there is at least one whole address.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_ndp_recursive_dns_servers_encode(lifetime: u32, addresses: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let addresses = unsafe { Pointer::slice(addresses, length) }?;
            unsafe { ICMPStatus::write_bytes(out, |bytes| NDPRecursiveDNSServers { lifetime, addresses }.encode(bytes)) }
        })())
    }

    /// Writes the default parameters of a neighbor cache (RFC 4861 §10) into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_config_default(out: *mut FFINeighborConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, NeighborConfig::default().into()) })
    }

    /// Writes a neighbor cache with the parameters `config` into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_cache_new(config: FFINeighborConfig, out: *mut *mut NeighborCache<[u8; 6]>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, NeighborCache::new(config.into())) })
    }

    /// Releases a neighbor cache. Does nothing if `cache` is null.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_cache_free(cache: *mut NeighborCache<[u8; 6]>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(cache) }
    }

    /// Resolves `address` at `now`, keeping the `length` bytes at `packet` (none if `packet` is null):
    /// writes 0 (resolved), 1 (send a multicast solicitation now) or 2 (pending) into `out_kind` and,
    /// for 0, the 6 bytes of the link-layer address into `out`; fails with Limit.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_cache_resolve(cache: *mut NeighborCache<[u8; 6]>, address: IPv6Address, packet: *const u8, length: usize, now: u64, out_kind: *mut u8, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(packet, length)],
                &[Pointer::range(out_kind, 1), Pointer::range(out, 6)],
            )?;
            // SAFETY: the caller passes a valid handle, null or readable bytes and writable pointers.
            let cache = unsafe { Pointer::reference_mut(cache) }?;
            let packet = if packet.is_null() { None } else { Some(unsafe { Pointer::slice(packet, length) }?.to_vec()) };
            Pointer::check_range(out_kind, 1)?;
            let out = unsafe { Pointer::slice_mut(out, 6) }?;
            let resolution = cache.resolve(address, packet, Instant::from_nanos(now)).map_err(|error| error.to_status())?;
            let (kind, link) = match resolution {
                NeighborResolution::Resolved(link) => (0, link),
                NeighborResolution::Solicit => (1, [0; 6]),
                NeighborResolution::Pending => (2, [0; 6]),
            };
            out.copy_from_slice(&link);
            unsafe { Pointer::write(out_kind, kind) }
        })())
    }

    /// Writes whether `address` is resolved into `out_found`, its state into `out_state` and its 6
    /// bytes of link-layer address into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_cache_lookup(cache: *const NeighborCache<[u8; 6]>, address: IPv6Address, out_found: *mut bool, out_state: *mut u8, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[Pointer::range(out_found, 1), Pointer::range(out_state, 1), Pointer::range(out, 6)],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let cache = unsafe { Pointer::reference(cache) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_state, 1)?;
            let out = unsafe { Pointer::slice_mut(out, 6) }?;
            let found = cache.lookup(&address);
            out.copy_from_slice(&found.map_or([0; 6], |(link, _)| link));
            unsafe { Pointer::write(out_state, found.map_or(0, |(_, state)| FFINeighborState::of(&state))) }?;
            unsafe { Pointer::write(out_found, found.is_some()) }
        })())
    }

    /// A confirmation from an upper layer that `address` is reachable at `now`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_cache_confirm(cache: *mut NeighborCache<[u8; 6]>, address: IPv6Address, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let cache = unsafe { Pointer::reference_mut(cache) }?;
            cache.confirm(&address, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Processes the valid Neighbor Advertisement of `advertisement` and the `length` bytes of options
    /// at `options`, received at `now`, and writes the packets now resolved into `out` and whether
    /// the target stopped being a router into `out_no_longer_router`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_cache_receive_advertisement(cache: *mut NeighborCache<[u8; 6]>, advertisement: *const FFINDPNeighborAdvertisement, options: *const u8, length: usize, now: u64, out: *mut *mut FFINeighborPackets, out_no_longer_router: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(advertisement, 1), Pointer::range(options, length)],
                &[Pointer::range(out_no_longer_router, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and structure, readable bytes and writable pointers.
            let cache = unsafe { Pointer::reference_mut(cache) }?;
            let advertisement = unsafe { Pointer::reference(advertisement) }?;
            let options = unsafe { Pointer::slice(options, length) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_no_longer_router, 1)?;
            let reception = cache.receive_advertisement(&advertisement.with(options), Instant::from_nanos(now));
            unsafe { Pointer::write(out_no_longer_router, reception.no_longer_router) }?;
            unsafe { FFINeighborPackets::write(out, reception.packets) }
        })())
    }

    /// Learns what a message received at `now` says of `address`: the 6 bytes of link-layer address
    /// at `link` (none if `link` is null), and that the sender is a router (`router` 2), a host (1)
    /// or nothing (0). Writes the packets now resolved into `out` and whether the neighbor stopped
    /// being a router into `out_no_longer_router`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_cache_learn(cache: *mut NeighborCache<[u8; 6]>, address: IPv6Address, link: *const u8, router: u8, now: u64, out: *mut *mut FFINeighborPackets, out_no_longer_router: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, null or 6 readable bytes and writable pointers.
            let cache = unsafe { Pointer::reference_mut(cache) }?;
            let link: Option<[u8; 6]> = if link.is_null() {
                None
            } else {
                Some(unsafe { Pointer::slice(link, 6) }?.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?)
            };
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_no_longer_router, 1)?;
            let router = match router {
                0 => None,
                1 => Some(false),
                2 => Some(true),
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            let reception = cache.learn(address, link, router, Instant::from_nanos(now));
            unsafe { Pointer::write(out_no_longer_router, reception.no_longer_router) }?;
            unsafe { FFINeighborPackets::write(out, reception.packets) }
        })())
    }

    /// Forgets `address` and writes whether it was known into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_cache_remove(cache: *mut NeighborCache<[u8; 6]>, address: IPv6Address, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let cache = unsafe { Pointer::reference_mut(cache) }?;
            Pointer::check_range(out, 1)?;
            let removed = cache.remove(&address).is_some();
            unsafe { Pointer::write(out, removed) }
        })())
    }

    /// Writes whether the cache has something to do into `out_found` and when into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_cache_poll_timeout(cache: *const NeighborCache<[u8; 6]>, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let cache = unsafe { Pointer::reference(cache) }?;
            let deadline = cache.poll_timeout();
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out_found, deadline.is_some()) }?;
            unsafe { Pointer::write(out, deadline.map_or(0, Instant::as_nanos)) }
        })())
    }

    /// Advances the cache to `now` and writes whether something is due into `out_found` and what into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_cache_poll(cache: *mut NeighborCache<[u8; 6]>, now: u64, out_found: *mut bool, out: *mut *mut FFINeighborEvent) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let cache = unsafe { Pointer::reference_mut(cache) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let event = cache.poll(Instant::from_nanos(now)).map(FFINeighborEvent::of);
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            match event {
                Some(event) => unsafe { Pointer::write_handle(out, event) },
                None => Ok(()),
            }
        })())
    }

    /// Releases packets. Does nothing if `packets` is null.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_packets_free(packets: *mut FFINeighborPackets) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(packets) }
    }

    /// Writes the number of packets into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_packets_count(packets: *const FFINeighborPackets, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let packets = unsafe { Pointer::reference(packets) }?;
            unsafe { Pointer::write(out, packets.packets.len()) }
        })())
    }

    /// Writes a copy of the packet at `index` into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_packets_get(packets: *const FFINeighborPackets, index: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let packets = unsafe { Pointer::reference(packets) }?;
            let packet = packets.packets.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, Buffer::from_vec(packet.clone())) }
        })())
    }

    /// Releases an event. Does nothing if `event` is null.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_event_free(event: *mut FFINeighborEvent) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(event) }
    }

    /// Writes the kind of the event (1: solicit, 2: unreachable) into `out_kind`, its target into
    /// `out_target`, whether the solicitation is unicast into `out_unicast` and the 6 bytes of its
    /// link-layer address into `out_link`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_event_target(event: *const FFINeighborEvent, out_kind: *mut u8, out_target: *mut IPv6Address, out_unicast: *mut bool, out_link: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[
                    Pointer::range(out_kind, 1),
                    Pointer::range(out_target, 1),
                    Pointer::range(out_unicast, 1),
                    Pointer::range(out_link, 6),
                ],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let event = unsafe { Pointer::reference(event) }?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out_target, 1)?;
            Pointer::check_range(out_unicast, 1)?;
            let out_link = unsafe { Pointer::slice_mut(out_link, 6) }?;
            out_link.copy_from_slice(&event.link.unwrap_or_default());
            unsafe { Pointer::write(out_kind, event.kind) }?;
            unsafe { Pointer::write(out_target, event.target) }?;
            unsafe { Pointer::write(out_unicast, event.link.is_some()) }
        })())
    }

    /// Writes a handle of the packets dropped with an unreachable neighbor into `out`.
    pub unsafe extern "C" fn umilib_protocol_icmp_v6_neighbor_event_packets(event: *const FFINeighborEvent, out: *mut *mut FFINeighborPackets) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let event = unsafe { Pointer::reference(event) }?;
            unsafe { FFINeighborPackets::write(out, event.packets.clone()) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v6",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_icmp_v6_NDPRouterAdvertisement",
            documentation: " The fields of a Router Advertisement (RFC 4861 §4.2, RFC 4191) but its options.",
            fields: &[
                Parameter { name: "current_hop_limit", value: <u8 as Value>::TYPE },
                Parameter { name: "managed_flag", value: <bool as Value>::TYPE },
                Parameter { name: "other_flag", value: <bool as Value>::TYPE },
                Parameter { name: "preference", value: <u8 as Value>::TYPE },
                Parameter { name: "flags", value: <u8 as Value>::TYPE },
                Parameter { name: "router_lifetime", value: <u16 as Value>::TYPE },
                Parameter { name: "reachable_time", value: <u32 as Value>::TYPE },
                Parameter { name: "retransmission_timer", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_icmp_v6_NDPNeighborAdvertisement",
            documentation: " The fields of a Neighbor Advertisement (RFC 4861 §4.4) but its options.",
            fields: &[
                Parameter { name: "router_flag", value: <bool as Value>::TYPE },
                Parameter { name: "solicited_flag", value: <bool as Value>::TYPE },
                Parameter { name: "override_flag", value: <bool as Value>::TYPE },
                Parameter { name: "target", value: <IPv6Address as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_icmp_v6_NDPPrefixInformation",
            documentation: " A Prefix Information option (RFC 4861 §4.6.2); lifetimes in seconds.",
            fields: &[
                Parameter { name: "prefix_length", value: <u8 as Value>::TYPE },
                Parameter { name: "on_link", value: <bool as Value>::TYPE },
                Parameter { name: "autonomous", value: <bool as Value>::TYPE },
                Parameter { name: "flags", value: <u8 as Value>::TYPE },
                Parameter { name: "valid_lifetime", value: <u32 as Value>::TYPE },
                Parameter { name: "preferred_lifetime", value: <u32 as Value>::TYPE },
                Parameter { name: "prefix", value: <IPv6Address as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_icmp_v6_NDPRouteInformation",
            documentation: " A Route Information option (RFC 4191 §2.3); the lifetime in seconds.",
            fields: &[
                Parameter { name: "prefix_length", value: <u8 as Value>::TYPE },
                Parameter { name: "preference", value: <u8 as Value>::TYPE },
                Parameter { name: "lifetime", value: <u32 as Value>::TYPE },
                Parameter { name: "prefix", value: <IPv6Address as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_icmp_v6_NeighborConfig",
            documentation: " The parameters of a neighbor cache (RFC 4861 §10); durations in nanoseconds.",
            fields: &[
                Parameter { name: "reachable_time", value: <u64 as Value>::TYPE },
                Parameter { name: "retransmission_timer", value: <u64 as Value>::TYPE },
                Parameter { name: "delay_first_probe_time", value: <u64 as Value>::TYPE },
                Parameter { name: "maximum_multicast_solicitations", value: <u32 as Value>::TYPE },
                Parameter { name: "maximum_unicast_solicitations", value: <u32 as Value>::TYPE },
                Parameter { name: "maximum_entries", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_queued", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_icmp_v6_NeighborCache",
            documentation: " The Neighbor Cache of RFC 4861 for 6-byte link-layer addresses.",
        },
        Definition::Opaque {
            name: "umilib_protocol_icmp_v6_NeighborPackets",
            documentation: " Packets the neighbor cache gives back.",
        },
        Definition::Opaque {
            name: "umilib_protocol_icmp_v6_NeighborEvent",
            documentation: " A solicitation to send, or a neighbor that did not answer.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
