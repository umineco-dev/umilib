//! The C ABI of [`crate::protocol::udp`].
//!
//! A header is a structure passed by value. A datagram is an
//! [`FFIUDPDatagram`] of its fields and its payload, passed beside it. The
//! addresses that carry it are their octets (4 or 16) and their number. The
//! ports of [`UDPConfig`] that a call needs are an array: those that may
//! receive a zero checksum over IPv6 to decode, and those that may send one
//! to encode.

use alloc::vec::Vec;

use crate::bytes::Buffer as Bytes;
use crate::ffi::protocol::ip::{FFIIPEndpoint, FFIIPEndpointPattern, IPStatus};
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::ip::IPAddress;
use crate::protocol::udp::{UDPConfig, UDPDatagram, UDPError, UDPHeader, UDPRequest, UDPRule};
use crate::service::Rule;

/// The statuses of this module, one per variant of [`UDPError`] that is not
/// another module's.
pub struct UDPStatus;

impl UDPStatus {
    pub const LENGTH: Status = Status::new(c"protocol.udp", c"Length", c"the UDP datagram's length is wrong");
    pub const CHECKSUM: Status = Status::new(c"protocol.udp", c"Checksum", c"the UDP checksum is wrong");
    pub const ZERO_CHECKSUM: Status =
        Status::new(c"protocol.udp", c"ZeroChecksum", c"the UDP datagram over IPv6 has no checksum");
    pub const FAMILY: Status = Status::new(c"protocol.udp", c"Family", c"the addresses are of different IP versions");
    pub const SOURCE: Status = Status::new(c"protocol.udp", c"Source", c"the source address names no single host");

    /// The addresses of the `source_length` octets at `source` and the
    /// `destination_length` octets at `destination`.
    ///
    /// # Safety
    /// As [`Pointer::slice`].
    pub unsafe fn addresses(
        source: *const u8,
        source_length: usize,
        destination: *const u8,
        destination_length: usize,
    ) -> Result<(IPAddress, IPAddress), &'static Status> {
        // SAFETY: the caller's promise.
        let source = unsafe { IPStatus::address(source, source_length) }?;
        let destination = unsafe { IPStatus::address(destination, destination_length) }?;
        Ok((source, destination))
    }

    /// A copy of the `count` ports at `ports`; fails with InvalidArgument if it cannot be allocated.
    ///
    /// # Safety
    /// As [`Pointer::slice_of`].
    pub unsafe fn ports(ports: *const u16, count: usize) -> Result<Vec<u16>, &'static Status> {
        // SAFETY: the caller's promise.
        let ports = unsafe { Pointer::slice_of(ports, count) }?;
        let mut copied = Vec::new();
        copied.try_reserve_exact(ports.len()).map_err(|_| &Status::INVALID_ARGUMENT)?;
        copied.extend_from_slice(ports);
        Ok(copied)
    }
}

impl ToStatus for UDPError {
    fn to_status(&self) -> &'static Status {
        match self {
            UDPError::Length => &UDPStatus::LENGTH,
            UDPError::Checksum => &UDPStatus::CHECKSUM,
            UDPError::ZeroChecksum => &UDPStatus::ZERO_CHECKSUM,
            UDPError::Family => &UDPStatus::FAMILY,
            UDPError::Source => &UDPStatus::SOURCE,
            UDPError::Write(error) => error.to_status(),
        }
    }
}

/// The fields of a [`UDPDatagram`] but its payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIUDPDatagram {
    pub source_port: u16,
    pub destination_port: u16,
    pub checksummed: bool,
}

impl FFIUDPDatagram {
    pub fn with<'a>(&self, payload: &'a [u8]) -> UDPDatagram<'a> {
        UDPDatagram {
            source_port: self.source_port,
            destination_port: self.destination_port,
            checksummed: self.checksummed,
            payload,
        }
    }

    pub fn of(datagram: &UDPDatagram) -> FFIUDPDatagram {
        FFIUDPDatagram {
            source_port: datagram.source_port,
            destination_port: datagram.destination_port,
            checksummed: datagram.checksummed,
        }
    }
}

/// A [`UDPRule`]: the patterns of the local and the remote endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIUDPRule {
    pub local: FFIIPEndpointPattern,
    pub remote: FFIIPEndpointPattern,
}

impl Value for UDPHeader {
    const TYPE: Type = Type::Named("umilib_protocol_udp_UDPHeader");
}

impl Value for FFIUDPDatagram {
    const TYPE: Type = Type::Named("umilib_protocol_udp_UDPDatagram");
}

impl Value for FFIUDPRule {
    const TYPE: Type = Type::Named("umilib_protocol_udp_UDPRule");
}

crate::ffi_functions! {
    /// Reads the header at the start of the `length` bytes at `bytes` into `out`; fails with Length.
    pub unsafe extern "C" fn umilib_protocol_udp_udp_header_decode(bytes: *const u8, length: usize, out: *mut UDPHeader) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let header = UDPHeader::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, header) }
        })())
    }

    /// Writes the 8 bytes of `header` into `out`.
    pub unsafe extern "C" fn umilib_protocol_udp_udp_header_encode(header: UDPHeader, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable buffer.
        Status::from_result(unsafe { Pointer::write(out, Buffer::from_vec(header.to_bytes().to_vec())) })
    }

    /// Reads the datagram of the `length` bytes at `bytes`, carried from the address of the
    /// `source_length` octets at `source` to that of the `destination_length` octets at
    /// `destination`, into `out`, and the length of its payload, which starts 8 bytes in, into
    /// `out_length`. A zero checksum over IPv6 needs the destination port among the `count` ports at
    /// `ports`. Fails with Length, Checksum, ZeroChecksum, Family or Source, and with the ip module's
    /// Length for an address of other than 4 or 16 octets.
    pub unsafe extern "C" fn umilib_protocol_udp_udp_datagram_decode(bytes: *const u8, length: usize, source: *const u8, source_length: usize, destination: *const u8, destination_length: usize, ports: *const u16, count: usize, out: *mut FFIUDPDatagram, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[
                    Pointer::range(bytes, length),
                    Pointer::range(source, source_length),
                    Pointer::range(destination, destination_length),
                    Pointer::range(ports, count),
                ],
                &[Pointer::range(out, 1), Pointer::range(out_length, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and ports and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let (source, destination) = unsafe { UDPStatus::addresses(source, source_length, destination, destination_length) }?;
            let config = UDPConfig { zero_checksum_receive_ports: unsafe { UDPStatus::ports(ports, count) }?, ..UDPConfig::default() };
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_length, 1)?;
            let datagram = UDPDatagram::decode(bytes, source, destination, &config).map_err(|error| error.to_status())?;
            let (fields, payload) = (FFIUDPDatagram::of(&datagram), datagram.payload.len());
            unsafe { Pointer::write(out, fields) }?;
            unsafe { Pointer::write(out_length, payload) }
        })())
    }

    /// Writes the header of the datagram of `datagram` and the `length` bytes of payload at `payload`
    /// from the address at `source` to that at `destination` into `out`. Without a checksum over IPv6,
    /// the source port must be among the `count` ports at `ports`. Fails with Length, ZeroChecksum,
    /// Family or Source, and with the ip module's Length for an address of other than 4 or 16 octets.
    pub unsafe extern "C" fn umilib_protocol_udp_udp_datagram_header(datagram: FFIUDPDatagram, payload: *const u8, length: usize, source: *const u8, source_length: usize, destination: *const u8, destination_length: usize, ports: *const u16, count: usize, out: *mut UDPHeader) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[
                    Pointer::range(payload, length),
                    Pointer::range(source, source_length),
                    Pointer::range(destination, destination_length),
                    Pointer::range(ports, count),
                ],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and ports and a writable pointer.
            let payload = unsafe { Pointer::slice(payload, length) }?;
            let (source, destination) = unsafe { UDPStatus::addresses(source, source_length, destination, destination_length) }?;
            let config = UDPConfig { zero_checksum_send_ports: unsafe { UDPStatus::ports(ports, count) }?, ..UDPConfig::default() };
            Pointer::check_range(out, 1)?;
            let header = datagram.with(payload).header(source, destination, &config).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, header) }
        })())
    }

    /// Writes the datagram of `datagram` and the `length` bytes of payload at `payload`, as
    /// `umilib_protocol_udp_udp_datagram_header` makes its header, into `out`; fails as it does.
    pub unsafe extern "C" fn umilib_protocol_udp_udp_datagram_encode(datagram: FFIUDPDatagram, payload: *const u8, length: usize, source: *const u8, source_length: usize, destination: *const u8, destination_length: usize, ports: *const u16, count: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and ports and a writable buffer.
            let payload = unsafe { Pointer::slice(payload, length) }?;
            let (source, destination) = unsafe { UDPStatus::addresses(source, source_length, destination, destination_length) }?;
            let config = UDPConfig { zero_checksum_send_ports: unsafe { UDPStatus::ports(ports, count) }?, ..UDPConfig::default() };
            Pointer::check_range(out, 1)?;
            let mut bytes = Bytes::new();
            datagram.with(payload).encode(source, destination, &config, &mut bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes.into_vec())) }
        })())
    }

    /// Writes whether the rule at `rule` matches a datagram to the endpoint at `local` from the
    /// endpoint at `remote` into `out`; fails with the ip module's Length for a bad address length.
    pub unsafe extern "C" fn umilib_protocol_udp_udp_rule_matches(rule: *const FFIUDPRule, local: *const FFIIPEndpoint, remote: *const FFIIPEndpoint, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(rule, 1), Pointer::range(local, 1), Pointer::range(remote, 1)],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes valid structures and a writable pointer.
            let rule = unsafe { Pointer::reference(rule) }?;
            let rule = UDPRule { local: rule.local.pattern()?, remote: rule.remote.pattern()? };
            let local = unsafe { Pointer::reference(local) }?.endpoint()?;
            let remote = unsafe { Pointer::reference(remote) }?.endpoint()?;
            let request = UDPRequest { local, remote, payload: Vec::new() };
            unsafe { Pointer::write(out, rule.matches(&request)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "udp",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_udp_UDPHeader",
            documentation: " The header of a UDP datagram (RFC 768), its fields as they are.",
            fields: &[
                Parameter { name: "source_port", value: <u16 as Value>::TYPE },
                Parameter { name: "destination_port", value: <u16 as Value>::TYPE },
                Parameter { name: "length", value: <u16 as Value>::TYPE },
                Parameter { name: "checksum", value: <u16 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_udp_UDPDatagram",
            documentation: " The fields of a UDP datagram but its payload.",
            fields: &[
                Parameter { name: "source_port", value: <u16 as Value>::TYPE },
                Parameter { name: "destination_port", value: <u16 as Value>::TYPE },
                Parameter { name: "checksummed", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_udp_UDPRule",
            documentation: " A rule that routes datagrams by their local and remote endpoints.",
            fields: &[
                Parameter { name: "local", value: <FFIIPEndpointPattern as Value>::TYPE },
                Parameter { name: "remote", value: <FFIIPEndpointPattern as Value>::TYPE },
            ],
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
