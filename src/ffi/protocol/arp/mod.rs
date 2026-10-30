//! The C ABI of [`crate::protocol::arp`], for MAC and IPv4 addresses (the
//! address types of C cannot be generic).
//!
//! A packet is a structure; the cache is a handle, and what it makes of a
//! received packet and of the passing of time are handles of their own.
//! Instants and durations are nanoseconds.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::time::Duration;

use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::arp::{
    ARPCache, ARPConfig, ARPError, ARPEvent, ARPHardwareType, ARPPacket, ARPReception, ARPResolution,
};
use crate::protocol::ethernet::{EtherType, MACAddress};
use crate::protocol::ip::IPv4Address;
use crate::runtime::Instant;

/// The statuses of this module, one per variant of [`ARPError`] that is not
/// another module's.
pub struct ARPStatus;

impl ARPStatus {
    pub const LENGTH: Status =
        Status::new(c"protocol.arp", c"Length", c"the lengths of the ARP packet are not consistent");
    pub const LIMIT: Status = Status::new(c"protocol.arp", c"Limit", c"the ARP cache is full");
}

impl ToStatus for ARPError {
    fn to_status(&self) -> &'static Status {
        match self {
            ARPError::Length => &ARPStatus::LENGTH,
            ARPError::Limit => &ARPStatus::LIMIT,
            ARPError::Write(error) => error.to_status(),
        }
    }
}

/// The C form of an [`ARPConfig`], the durations in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FFIARPConfig {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub timeout: u64,
    pub retransmission_interval: u64,
    pub maximum_requests: u32,
    pub maximum_entries: usize,
    pub maximum_queued: usize,
}

impl From<FFIARPConfig> for ARPConfig {
    fn from(config: FFIARPConfig) -> ARPConfig {
        ARPConfig {
            hardware_type: ARPHardwareType(config.hardware_type),
            protocol_type: EtherType(config.protocol_type),
            timeout: Duration::from_nanos(config.timeout),
            retransmission_interval: Duration::from_nanos(config.retransmission_interval),
            maximum_requests: config.maximum_requests,
            maximum_entries: config.maximum_entries,
            maximum_queued: config.maximum_queued,
        }
    }
}

impl From<ARPConfig> for FFIARPConfig {
    fn from(config: ARPConfig) -> FFIARPConfig {
        let nanoseconds = |duration: Duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        FFIARPConfig {
            hardware_type: config.hardware_type.0,
            protocol_type: config.protocol_type.0,
            timeout: nanoseconds(config.timeout),
            retransmission_interval: nanoseconds(config.retransmission_interval),
            maximum_requests: config.maximum_requests,
            maximum_entries: config.maximum_entries,
            maximum_queued: config.maximum_queued,
        }
    }
}

/// What [`ARPCache::poll`] reports, in the form of a handle: the kind (1 for
/// a request to send again, 2 for an unreachable address), the address and
/// the packets kept for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FFIARPEvent {
    pub kind: u8,
    pub address: IPv4Address,
    pub packets: VecDeque<Vec<u8>>,
}

impl Value for ARPPacket<MACAddress, IPv4Address> {
    const TYPE: Type = Type::Named("umilib_protocol_arp_ARPPacket");
}

impl Value for FFIARPConfig {
    const TYPE: Type = Type::Named("umilib_protocol_arp_ARPConfig");
}

impl Value for ARPCache<MACAddress, IPv4Address> {
    const TYPE: Type = Type::Named("umilib_protocol_arp_ARPCache");
}

impl Value for ARPReception<MACAddress, IPv4Address> {
    const TYPE: Type = Type::Named("umilib_protocol_arp_ARPReception");
}

impl Value for FFIARPEvent {
    const TYPE: Type = Type::Named("umilib_protocol_arp_ARPEvent");
}

crate::ffi_functions! {
    /// Reads the packet at the start of the `length` bytes at `bytes` into `out`; fails with Length
    /// for address lengths other than 6 and 4.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_packet_decode(bytes: *const u8, length: usize, out: *mut ARPPacket) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let packet = ARPPacket::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, packet) }
        })())
    }

    /// Writes the 28 bytes of the packet into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_packet_encode(packet: ARPPacket, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(out, 1)?;
            let mut bytes = crate::bytes::Buffer::new();
            packet.encode(&mut bytes).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable buffer.
            unsafe { Pointer::write(out, Buffer::from_vec(bytes.into_vec())) }
        })())
    }

    /// A request on Ethernet for the hardware address of `target` from `sender_hardware` and
    /// `sender_protocol` (0.0.0.0 for a probe).
    pub unsafe extern "C" fn umilib_protocol_arp_arp_packet_ethernet_request(sender_hardware: MACAddress, sender_protocol: IPv4Address, target: IPv4Address) -> ARPPacket {
        ARPPacket::ethernet_request(sender_hardware, sender_protocol, target)
    }

    /// The reply to the request `packet` from `hardware`, the hardware address of its target.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_packet_reply(packet: ARPPacket, hardware: MACAddress) -> ARPPacket {
        packet.reply(hardware)
    }

    /// Whether `packet` is a probe (RFC 5227 §2.1.1).
    pub unsafe extern "C" fn umilib_protocol_arp_arp_packet_is_probe(packet: ARPPacket) -> bool {
        packet.is_probe()
    }

    /// Whether `packet` is an announcement (RFC 5227 §2.3).
    pub unsafe extern "C" fn umilib_protocol_arp_arp_packet_is_announcement(packet: ARPPacket) -> bool {
        packet.is_announcement()
    }

    /// Writes the default parameters of a cache into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_config_default(out: *mut FFIARPConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, ARPConfig::default().into()) })
    }

    /// Writes a cache with the parameters `config` into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_cache_new(config: FFIARPConfig, out: *mut *mut ARPCache) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, ARPCache::new(config.into())) })
    }

    /// Releases a cache. Does nothing if `cache` is null.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_cache_free(cache: *mut ARPCache) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(cache) }
    }

    /// Resolves `address` at `now`, keeping the `length` bytes at `packet` (none if `packet` is
    /// null) until the resolution ends: writes 0 (resolved), 1 (send a request now) or 2 (pending)
    /// into `out_kind` and the hardware address of 0 into `out`; fails with Limit.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_cache_resolve(cache: *mut ARPCache, address: IPv4Address, packet: *const u8, length: usize, now: u64, out_kind: *mut u8, out: *mut MACAddress) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(packet, length)],
                &[Pointer::range(out_kind, 1), Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes a valid handle, null or readable bytes and writable pointers.
            let cache = unsafe { Pointer::reference_mut(cache) }?;
            let packet = if packet.is_null() { None } else { Some(unsafe { Pointer::slice(packet, length) }?.to_vec()) };
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out, 1)?;
            let resolution = cache.resolve(address, packet, Instant::from_nanos(now)).map_err(|error| error.to_status())?;
            let (kind, hardware) = match resolution {
                ARPResolution::Resolved(hardware) => (0, hardware),
                ARPResolution::Request => (1, MACAddress::ZERO),
                ARPResolution::Pending => (2, MACAddress::ZERO),
            };
            unsafe { Pointer::write(out_kind, kind) }?;
            unsafe { Pointer::write(out, hardware) }
        })())
    }

    /// Writes whether the hardware address of `address` is known at `now` into `out_found` and it into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_cache_lookup(cache: *const ARPCache, address: IPv4Address, now: u64, out_found: *mut bool, out: *mut MACAddress) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let cache = unsafe { Pointer::reference(cache) }?;
            let hardware = cache.lookup(&address, Instant::from_nanos(now));
            unsafe { Pointer::write(out_found, hardware.is_some()) }?;
            unsafe { Pointer::write(out, hardware.unwrap_or_default()) }
        })())
    }

    /// Sets the hardware address of `address` to `hardware` until it is removed.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_cache_insert_static(cache: *mut ARPCache, address: IPv4Address, hardware: MACAddress) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let cache = unsafe { Pointer::reference_mut(cache) }?;
            cache.insert_static(address, hardware);
            Ok(())
        })())
    }

    /// Removes what the cache knows of `address` and writes whether it knew anything into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_cache_remove(cache: *mut ARPCache, address: IPv4Address, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let cache = unsafe { Pointer::reference_mut(cache) }?;
            Pointer::check_range(out, 1)?;
            let removed = cache.remove(&address).is_some();
            unsafe { Pointer::write(out, removed) }
        })())
    }

    /// Processes `packet`, received at `now` on an interface of the hardware address `hardware` and
    /// the `count` protocol addresses at `local`, and writes what it makes of it into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_cache_receive(cache: *mut ARPCache, packet: ARPPacket, hardware: MACAddress, local: *const IPv4Address, count: usize, now: u64, out: *mut *mut ARPReception) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable addresses and a writable pointer.
            let cache = unsafe { Pointer::reference_mut(cache) }?;
            let local = unsafe { Pointer::slice_of(local, count) }?;
            Pointer::check_range(out, 1)?;
            let reception = cache.receive(&packet, hardware, local, Instant::from_nanos(now));
            unsafe { Pointer::write_handle(out, reception) }
        })())
    }

    /// Writes whether the cache has something to do into `out_found` and when into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_cache_poll_timeout(cache: *const ARPCache, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let cache = unsafe { Pointer::reference(cache) }?;
            let deadline = cache.poll_timeout();
            unsafe { Pointer::write(out_found, deadline.is_some()) }?;
            unsafe { Pointer::write(out, deadline.map_or(0, Instant::as_nanos)) }
        })())
    }

    /// Advances the cache to `now` and writes whether something is due into `out_found` and what into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_cache_poll(cache: *mut ARPCache, now: u64, out_found: *mut bool, out: *mut *mut FFIARPEvent) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let cache = unsafe { Pointer::reference_mut(cache) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let event = cache.poll(Instant::from_nanos(now)).map(|event| match event {
                ARPEvent::Request(address) => FFIARPEvent { kind: 1, address, packets: VecDeque::new() },
                ARPEvent::Unreachable(address, packets) => FFIARPEvent { kind: 2, address, packets },
            });
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            match event {
                Some(event) => unsafe { Pointer::write_handle(out, event) },
                None => Ok(()),
            }
        })())
    }

    /// Releases a reception. Does nothing if `reception` is null.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_reception_free(reception: *mut ARPReception) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(reception) }
    }

    /// Writes whether there is a reply to send into `out_found` and it into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_reception_reply(reception: *const ARPReception, out_found: *mut bool, out: *mut ARPPacket) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reception = unsafe { Pointer::reference(reception) }?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out_found, reception.reply.is_some()) }?;
            match reception.reply {
                Some(reply) => unsafe { Pointer::write(out, reply) },
                None => Ok(()),
            }
        })())
    }

    /// Whether the packet claimed a local address from another hardware address.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_reception_conflict(reception: *const ARPReception, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reception = unsafe { Pointer::reference(reception) }?;
            unsafe { Pointer::write(out, reception.conflict) }
        })())
    }

    /// Writes the number of packets kept for the sender's address, now resolved, into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_reception_resolved_count(reception: *const ARPReception, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reception = unsafe { Pointer::reference(reception) }?;
            unsafe { Pointer::write(out, reception.resolved.len()) }
        })())
    }

    /// Writes a copy of the resolved packet at `index` into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_reception_resolved_get(reception: *const ARPReception, index: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let reception = unsafe { Pointer::reference(reception) }?;
            let packet = reception.resolved.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, Buffer::from_vec(packet.clone())) }
        })())
    }

    /// Releases an event. Does nothing if `event` is null.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_event_free(event: *mut FFIARPEvent) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(event) }
    }

    /// Writes the kind of the event (1: send a request again, 2: unreachable) into `out_kind` and
    /// its address into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_event_address(event: *const FFIARPEvent, out_kind: *mut u8, out: *mut IPv4Address) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_kind, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let event = unsafe { Pointer::reference(event) }?;
            unsafe { Pointer::write(out_kind, event.kind) }?;
            unsafe { Pointer::write(out, event.address) }
        })())
    }

    /// Writes the number of packets dropped with an unreachable address into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_event_packet_count(event: *const FFIARPEvent, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let event = unsafe { Pointer::reference(event) }?;
            unsafe { Pointer::write(out, event.packets.len()) }
        })())
    }

    /// Writes a copy of the dropped packet at `index` into `out`.
    pub unsafe extern "C" fn umilib_protocol_arp_arp_event_packet_get(event: *const FFIARPEvent, index: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let event = unsafe { Pointer::reference(event) }?;
            let packet = event.packets.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, Buffer::from_vec(packet.clone())) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "arp",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_arp_ARPPacket",
            documentation: " An ARP packet (RFC 826) of MAC and IPv4 addresses.",
            fields: &[
                Parameter { name: "hardware_type", value: <u16 as Value>::TYPE },
                Parameter { name: "protocol_type", value: <u16 as Value>::TYPE },
                Parameter { name: "operation", value: <u16 as Value>::TYPE },
                Parameter { name: "sender_hardware", value: <MACAddress as Value>::TYPE },
                Parameter { name: "sender_protocol", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "target_hardware", value: <MACAddress as Value>::TYPE },
                Parameter { name: "target_protocol", value: <IPv4Address as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_arp_ARPConfig",
            documentation: " The parameters of a cache; durations in nanoseconds.",
            fields: &[
                Parameter { name: "hardware_type", value: <u16 as Value>::TYPE },
                Parameter { name: "protocol_type", value: <u16 as Value>::TYPE },
                Parameter { name: "timeout", value: <u64 as Value>::TYPE },
                Parameter { name: "retransmission_interval", value: <u64 as Value>::TYPE },
                Parameter { name: "maximum_requests", value: <u32 as Value>::TYPE },
                Parameter { name: "maximum_entries", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_queued", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_arp_ARPCache",
            documentation: " The translation table of ARP from IPv4 to MAC addresses.",
        },
        Definition::Opaque {
            name: "umilib_protocol_arp_ARPReception",
            documentation: " What the cache makes of a received packet.",
        },
        Definition::Opaque {
            name: "umilib_protocol_arp_ARPEvent",
            documentation: " A request to send again, or an address that did not answer.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
