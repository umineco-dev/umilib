//! The C ABI of [`crate::protocol::ip`].
//!
//! Addresses are structures of their octets passed by value; an
//! [`InternetChecksum`] is a structure updated through a pointer; an
//! [`IPFragmentBuffer`] is a handle. A protocol number crosses as its `u8`.
//! An endpoint or a pattern of endpoints is a structure of the octets of an
//! address, the number of them used (4 or 16), and the ports.

#[cfg(umilib_feature = "protocol-ip-v4")]
pub mod v4;
#[cfg(umilib_feature = "protocol-ip-v6")]
pub mod v6;

use alloc::string::ToString;

use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::ip::{
    IPAddress, IPEndpoint, IPEndpointPattern, IPError, IPFragmentBuffer, IPProtocol, IPPseudoHeader, IPv4Address,
    IPv6Address, InternetChecksum,
};

/// The statuses of this module, one per variant of [`IPError`].
pub struct IPStatus;

impl IPStatus {
    pub const SYNTAX: Status = Status::new(c"protocol.ip", c"Syntax", c"the text is not an IP address");
    pub const FAMILY: Status = Status::new(c"protocol.ip", c"Family", c"the addresses are of different IP versions");
    pub const LENGTH: Status =
        Status::new(c"protocol.ip", c"Length", c"the length does not fit its field or the datagram");
    pub const OVERLAP: Status = Status::new(c"protocol.ip", c"Overlap", c"the fragment overlaps another fragment");
}

impl ToStatus for IPError {
    fn to_status(&self) -> &'static Status {
        match self {
            IPError::Syntax => &IPStatus::SYNTAX,
            IPError::Family => &IPStatus::FAMILY,
            IPError::Length => &IPStatus::LENGTH,
            IPError::Overlap => &IPStatus::OVERLAP,
        }
    }
}

impl Value for IPv4Address {
    const TYPE: Type = Type::Named("umilib_protocol_ip_IPv4Address");
}

impl Value for IPv6Address {
    const TYPE: Type = Type::Named("umilib_protocol_ip_IPv6Address");
}

impl Value for IPProtocol {
    const TYPE: Type = Type::U8;
}

impl Value for InternetChecksum {
    const TYPE: Type = Type::Named("umilib_protocol_ip_InternetChecksum");
}

impl Value for IPFragmentBuffer {
    const TYPE: Type = Type::Named("umilib_protocol_ip_IPFragmentBuffer");
}

/// An [`IPEndpoint`]: the first `length` (4 or 16) of `octets` are the address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIIPEndpoint {
    pub octets: [u8; 16],
    pub length: u8,
    pub port: u16,
}

impl FFIIPEndpoint {
    pub fn of(endpoint: &IPEndpoint) -> FFIIPEndpoint {
        let (octets, length) = FFIIPEndpoint::octets(&endpoint.address);
        FFIIPEndpoint { octets, length, port: endpoint.port }
    }

    /// The octets of `address` in 16 bytes, and how many are used.
    pub fn octets(address: &IPAddress) -> ([u8; 16], u8) {
        let mut octets = [0u8; 16];
        let used = address.octets();
        octets[..used.len()].copy_from_slice(used);
        (octets, used.len() as u8)
    }

    /// The endpoint; fails with Length unless `length` is 4 or 16.
    pub fn endpoint(&self) -> Result<IPEndpoint, &'static Status> {
        let octets = self.octets.get(..self.length as usize).ok_or(&IPStatus::LENGTH)?;
        let address = IPAddress::from_octets(octets).map_err(|error| error.to_status())?;
        Ok(IPEndpoint { address, port: self.port })
    }
}

/// An [`IPEndpointPattern`]: a `length` of 0 is any address; otherwise the
/// first `length` (4 or 16) of `octets` are the address of the prefix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIIPEndpointPattern {
    pub octets: [u8; 16],
    pub length: u8,
    pub prefix_length: u8,
    pub first_port: u16,
    pub last_port: u16,
}

impl FFIIPEndpointPattern {
    pub fn of(pattern: &IPEndpointPattern) -> FFIIPEndpointPattern {
        let ((octets, length), prefix_length) = match pattern.prefix {
            Some((address, prefix_length)) => (FFIIPEndpoint::octets(&address), prefix_length),
            None => (([0; 16], 0), 0),
        };
        FFIIPEndpointPattern {
            octets,
            length,
            prefix_length,
            first_port: pattern.first_port,
            last_port: pattern.last_port,
        }
    }

    /// The pattern; fails with Length unless `length` is 0, 4 or 16.
    pub fn pattern(&self) -> Result<IPEndpointPattern, &'static Status> {
        let prefix = match self.length {
            0 => None,
            length => {
                let octets = self.octets.get(..length as usize).ok_or(&IPStatus::LENGTH)?;
                Some((IPAddress::from_octets(octets).map_err(|error| error.to_status())?, self.prefix_length))
            }
        };
        Ok(IPEndpointPattern { prefix, first_port: self.first_port, last_port: self.last_port })
    }
}

impl Value for FFIIPEndpoint {
    const TYPE: Type = Type::Named("umilib_protocol_ip_IPEndpoint");
}

impl Value for FFIIPEndpointPattern {
    const TYPE: Type = Type::Named("umilib_protocol_ip_IPEndpointPattern");
}

impl IPStatus {
    /// The address of the `length` octets at `octets`: 4 for IPv4, 16 for IPv6.
    ///
    /// # Safety
    /// As [`Pointer::slice`].
    pub unsafe fn address(octets: *const u8, length: usize) -> Result<IPAddress, &'static Status> {
        // SAFETY: the caller's promise.
        let octets = unsafe { Pointer::slice(octets, length) }?;
        IPAddress::from_octets(octets).map_err(|error| error.to_status())
    }
}

crate::ffi_functions! {
    /// Reads the endpoint of the UTF-8 text at `text`, `address:port` or `[address]:port` (RFC 3986
    /// §3.2.2), into `out`; fails with Syntax.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_endpoint_parse(text: *const u8, length: usize, out: *mut FFIIPEndpoint) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let endpoint = text.parse::<IPEndpoint>().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, FFIIPEndpoint::of(&endpoint)) }
        })())
    }

    /// Writes the text of the endpoint at `endpoint` into `out`; fails with Length.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_endpoint_to_string(endpoint: *const FFIIPEndpoint, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure and a writable buffer.
            let endpoint = unsafe { Pointer::reference(endpoint) }?.endpoint()?;
            unsafe { Pointer::write_text(out, endpoint.to_string()) }
        })())
    }

    /// Writes the canonical prefix of `length` bits of the address of the `octets_length` octets at
    /// `octets` (an IPv4 prefix for at least 96 bits of an IPv4-mapped address, RFC 4291 §2.5.5.2)
    /// into the 16 bytes at `out`, the number of them used into `out_octets` and its length into
    /// `out_length`; fails with Length.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_address_to_canonical_prefix(octets: *const u8, octets_length: usize, length: u8, out: *mut u8, out_octets: *mut u8, out_length: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(octets, octets_length)],
                &[Pointer::range(out, 16), Pointer::range(out_octets, 1), Pointer::range(out_length, 1)],
            )?;
            // SAFETY: the caller passes readable octets and writable pointers.
            let address = unsafe { IPStatus::address(octets, octets_length) }?;
            let out = unsafe { Pointer::slice_mut(out, 16) }?;
            Pointer::check_range(out_octets, 1)?;
            Pointer::check_range(out_length, 1)?;
            let (prefix, length) = address.to_canonical_prefix(length);
            let (bytes, used) = FFIIPEndpoint::octets(&prefix);
            out.copy_from_slice(&bytes);
            unsafe { Pointer::write(out_octets, used) }?;
            unsafe { Pointer::write(out_length, length) }
        })())
    }

    /// Writes whether the pattern at `pattern` matches the endpoint at `endpoint` into `out`; fails with Length.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_endpoint_pattern_matches(pattern: *const FFIIPEndpointPattern, endpoint: *const FFIIPEndpoint, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(pattern, 1), Pointer::range(endpoint, 1)],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes valid structures and a writable pointer.
            let pattern = unsafe { Pointer::reference(pattern) }?.pattern()?;
            let endpoint = unsafe { Pointer::reference(endpoint) }?.endpoint()?;
            unsafe { Pointer::write(out, pattern.matches(&endpoint)) }
        })())
    }

    /// Reads the dotted decimal UTF-8 text at `text` into `out`; fails with Syntax.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv4_address_parse(text: *const u8, length: usize, out: *mut IPv4Address) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let address = text.parse::<IPv4Address>().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, address) }
        })())
    }

    /// Writes the dotted decimal text of `address` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv4_address_to_string(address: IPv4Address, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable buffer.
        Status::from_result(unsafe { Pointer::write_text(out, address.to_string()) })
    }

    /// `address` with every bit after the first `length` cleared.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv4_address_prefix(address: IPv4Address, length: u8) -> IPv4Address {
        address.prefix(length)
    }

    /// Whether the first `length` bits of `address` are those of `prefix`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv4_address_has_prefix(address: IPv4Address, prefix: IPv4Address, length: u8) -> bool {
        address.has_prefix(&prefix, length)
    }

    /// 0.0.0.0.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv4_address_is_unspecified(address: IPv4Address) -> bool {
        address.is_unspecified()
    }

    /// 127.0.0.0/8.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv4_address_is_loopback(address: IPv4Address) -> bool {
        address.is_loopback()
    }

    /// 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16 (RFC 1918).
    pub unsafe extern "C" fn umilib_protocol_ip_ipv4_address_is_private(address: IPv4Address) -> bool {
        address.is_private()
    }

    /// 169.254.0.0/16.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv4_address_is_link_local(address: IPv4Address) -> bool {
        address.is_link_local()
    }

    /// 224.0.0.0/4.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv4_address_is_multicast(address: IPv4Address) -> bool {
        address.is_multicast()
    }

    /// 255.255.255.255.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv4_address_is_broadcast(address: IPv4Address) -> bool {
        address.is_broadcast()
    }

    /// 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 (RFC 5737).
    pub unsafe extern "C" fn umilib_protocol_ip_ipv4_address_is_documentation(address: IPv4Address) -> bool {
        address.is_documentation()
    }

    /// The IPv4-mapped IPv6 address `::ffff:a.b.c.d` of `address`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv4_address_to_ipv6_mapped(address: IPv4Address) -> IPv6Address {
        address.to_ipv6_mapped()
    }

    /// Reads an IPv6 address in any form of RFC 4291 §2.2 from the UTF-8 text at `text` into `out`;
    /// fails with Syntax.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_parse(text: *const u8, length: usize, out: *mut IPv6Address) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let address = text.parse::<IPv6Address>().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, address) }
        })())
    }

    /// Writes the text form of RFC 5952 of `address` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_to_string(address: IPv6Address, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable buffer.
        Status::from_result(unsafe { Pointer::write_text(out, address.to_string()) })
    }

    /// `address` with every bit after the first `length` cleared.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_prefix(address: IPv6Address, length: u8) -> IPv6Address {
        address.prefix(length)
    }

    /// Whether the first `length` bits of `address` are those of `prefix`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_has_prefix(address: IPv6Address, prefix: IPv6Address, length: u8) -> bool {
        address.has_prefix(&prefix, length)
    }

    /// The address of the 64-bit prefix at `prefix` and the interface identifier at
    /// `interface_identifier` (8 bytes each).
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_from_interface_identifier(prefix: *const u8, interface_identifier: *const u8, out: *mut IPv6Address) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes 8 readable bytes each and a writable pointer.
            let prefix = unsafe { Pointer::slice(prefix, 8) }?;
            let identifier = unsafe { Pointer::slice(interface_identifier, 8) }?;
            let prefix: [u8; 8] = prefix.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            let identifier: [u8; 8] = identifier.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, IPv6Address::from_interface_identifier(prefix, identifier)) }
        })())
    }

    /// The solicited-node multicast address of `address` (RFC 4291 §2.7.1).
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_solicited_node(address: IPv6Address) -> IPv6Address {
        address.solicited_node()
    }

    /// `::`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_is_unspecified(address: IPv6Address) -> bool {
        address.is_unspecified()
    }

    /// `::1`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_is_loopback(address: IPv6Address) -> bool {
        address.is_loopback()
    }

    /// `ff00::/8`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_is_multicast(address: IPv6Address) -> bool {
        address.is_multicast()
    }

    /// `fe80::/10`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_is_link_local(address: IPv6Address) -> bool {
        address.is_link_local()
    }

    /// `fc00::/7`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_is_unique_local(address: IPv6Address) -> bool {
        address.is_unique_local()
    }

    /// `2001:db8::/32` and `3fff::/20`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_is_documentation(address: IPv6Address) -> bool {
        address.is_documentation()
    }

    /// Writes whether `address` is multicast into `out_found` and its scope into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_multicast_scope(address: IPv6Address, out_found: *mut bool, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            let scope = address.multicast_scope();
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(out_found, scope.is_some()) }?;
            unsafe { Pointer::write(out, scope.unwrap_or(0)) }
        })())
    }

    /// Writes whether `address` is IPv4-mapped into `out_found` and its IPv4 address into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_ipv6_address_to_ipv4_mapped(address: IPv6Address, out_found: *mut bool, out: *mut IPv4Address) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            let mapped = address.to_ipv4_mapped();
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(out_found, mapped.is_some()) }?;
            unsafe { Pointer::write(out, mapped.unwrap_or_default()) }
        })())
    }

    /// Writes the keyword of the IANA registry of protocol `number`, if it has one here, into
    /// `out_found` and `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_protocol_name(number: u8, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes writable pointers.
        Status::from_result(unsafe { Pointer::write_optional_text(out_found, out, IPProtocol(number).name()) })
    }

    /// Adds the `length` bytes at `data`, which follow those added before, to `checksum`.
    pub unsafe extern "C" fn umilib_protocol_ip_internet_checksum_update(checksum: *mut InternetChecksum, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(checksum, 1)])?;
            // SAFETY: the caller passes a valid structure and readable bytes.
            let checksum = unsafe { Pointer::reference_mut(checksum) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            checksum.update(data);
            Ok(())
        })())
    }

    /// The one's complement sum of the bytes added, folded to 16 bits.
    pub unsafe extern "C" fn umilib_protocol_ip_internet_checksum_sum16(checksum: InternetChecksum) -> u16 {
        checksum.sum16()
    }

    /// The checksum of the bytes added.
    pub unsafe extern "C" fn umilib_protocol_ip_internet_checksum_finish(checksum: InternetChecksum) -> u16 {
        checksum.finish()
    }

    /// Writes the checksum of the `length` bytes at `data` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_internet_checksum_checksum(data: *const u8, length: usize, out: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            unsafe { Pointer::write(out, InternetChecksum::checksum(data)) }
        })())
    }

    /// Writes whether the `length` bytes at `data`, their checksum field included, sum to all ones
    /// into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_internet_checksum_verify(data: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            unsafe { Pointer::write(out, InternetChecksum::verify(data)) }
        })())
    }

    /// `sum` folded to 16 bits by adding the carries back.
    pub unsafe extern "C" fn umilib_protocol_ip_internet_checksum_fold(sum: u64) -> u16 {
        InternetChecksum::fold(sum)
    }

    /// The checksum `checksum` after a 16-bit word changes from `before` to `after` (RFC 1624 §3).
    pub unsafe extern "C" fn umilib_protocol_ip_internet_checksum_adjust(checksum: u16, before: u16, after: u16) -> u16 {
        InternetChecksum::adjust(checksum, before, after)
    }

    /// Writes the checksum `checksum` after the `length` bytes at `before`, at an even offset of the
    /// data, change to the `length` bytes at `after` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_internet_checksum_adjust_bytes(checksum: u16, before: *const u8, after: *const u8, length: usize, out: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(before, length), Pointer::range(after, length)],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let before = unsafe { Pointer::slice(before, length) }?;
            let after = unsafe { Pointer::slice(after, length) }?;
            let adjusted = InternetChecksum::adjust_bytes(checksum, before, after).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, adjusted) }
        })())
    }

    /// Writes the pseudo-header of `length` upper-layer bytes of `protocol` between the addresses of
    /// `source_length` octets at `source` and `destination_length` octets at `destination` (4 for
    /// IPv4, 16 for IPv6) into `out`; fails with Family or Length.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_pseudo_header_to_bytes(source: *const u8, source_length: usize, destination: *const u8, destination_length: usize, protocol: u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let source = unsafe { IPStatus::address(source, source_length) }?;
            let destination = unsafe { IPStatus::address(destination, destination_length) }?;
            let header = IPPseudoHeader::new(source, destination, IPProtocol(protocol), length).map_err(|error| error.to_status())?;
            let (bytes, length) = header.to_bytes();
            unsafe { Pointer::write(out, Buffer::from_vec(bytes[..length].to_vec())) }
        })())
    }

    /// Writes an empty reassembly buffer into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_fragment_buffer_new(out: *mut *mut IPFragmentBuffer) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, IPFragmentBuffer::new()) })
    }

    /// Releases a buffer. Does nothing if `buffer` is null.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_fragment_buffer_free(buffer: *mut IPFragmentBuffer) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(buffer) }
    }

    /// Adds the `length` bytes at `data` at `offset`, the last ones if `last`, the data being at
    /// most `maximum` bytes, and writes whether every byte is received into `out`; fails with
    /// Overlap or Length.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_fragment_buffer_insert(buffer: *mut IPFragmentBuffer, offset: usize, data: *const u8, length: usize, last: bool, maximum: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let buffer = unsafe { Pointer::reference_mut(buffer) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            let complete = buffer.insert(offset, data, last, maximum).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, complete) }
        })())
    }

    /// Checks the `length` bytes at `data` at `offset`, the last ones if `last`, against the
    /// fragments received, the data being at most `maximum` bytes, without adding them, and writes
    /// how much the buffer's memory would grow into `out`; fails with Overlap or Length.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_fragment_buffer_check(buffer: *const IPFragmentBuffer, offset: usize, data: *const u8, length: usize, last: bool, maximum: usize, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let buffer = unsafe { Pointer::reference(buffer) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            let growth = buffer.check(offset, data, last, maximum).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, growth) }
        })())
    }

    /// Writes a copy of the bytes received at their offsets (zeros between them) into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_fragment_buffer_data(buffer: *const IPFragmentBuffer, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let buffer = unsafe { Pointer::reference(buffer) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(buffer.data.clone())) }
        })())
    }

    /// Writes whether the length of the data is known into `out_found` and it into `out`.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_fragment_buffer_length(buffer: *const IPFragmentBuffer, out_found: *mut bool, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let buffer = unsafe { Pointer::reference(buffer) }?;
            unsafe { Pointer::write(out_found, buffer.length.is_some()) }?;
            unsafe { Pointer::write(out, buffer.length.unwrap_or(0)) }
        })())
    }

    /// The bytes the buffer holds, approximately: its data and the record of its fragments.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_fragment_buffer_memory(buffer: *const IPFragmentBuffer, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let buffer = unsafe { Pointer::reference(buffer) }?;
            unsafe { Pointer::write(out, buffer.memory()) }
        })())
    }

    /// Writes whether every byte is received into `out_complete` and how many are into `out_received`.
    pub unsafe extern "C" fn umilib_protocol_ip_ip_fragment_buffer_progress(buffer: *const IPFragmentBuffer, out_complete: *mut bool, out_received: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_complete, 1), Pointer::range(out_received, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let buffer = unsafe { Pointer::reference(buffer) }?;
            unsafe { Pointer::write(out_complete, buffer.is_complete()) }?;
            unsafe { Pointer::write(out_received, buffer.received_length()) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ip",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_ip_IPv4Address",
            documentation: " An IPv4 address, in network byte order.",
            fields: &[Parameter { name: "octets", value: <[u8; 4] as Value>::TYPE }],
        },
        Definition::Structure {
            name: "umilib_protocol_ip_IPv6Address",
            documentation: " An IPv6 address, in network byte order.",
            fields: &[Parameter { name: "octets", value: <[u8; 16] as Value>::TYPE }],
        },
        Definition::Structure {
            name: "umilib_protocol_ip_InternetChecksum",
            documentation: " The Internet checksum (RFC 1071) being computed: start with zeros.",
            fields: &[
                Parameter { name: "sum", value: <u64 as Value>::TYPE },
                Parameter { name: "odd", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_ip_IPEndpoint",
            documentation: " An endpoint of a transport protocol: the first `length` (4 or 16) of `octets` are the address.",
            fields: &[
                Parameter { name: "octets", value: <[u8; 16] as Value>::TYPE },
                Parameter { name: "length", value: <u8 as Value>::TYPE },
                Parameter { name: "port", value: <u16 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_ip_IPEndpointPattern",
            documentation: " Endpoints by address prefix and port range; a `length` of 0 is any address.",
            fields: &[
                Parameter { name: "octets", value: <[u8; 16] as Value>::TYPE },
                Parameter { name: "length", value: <u8 as Value>::TYPE },
                Parameter { name: "prefix_length", value: <u8 as Value>::TYPE },
                Parameter { name: "first_port", value: <u16 as Value>::TYPE },
                Parameter { name: "last_port", value: <u16 as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_ip_IPFragmentBuffer",
            documentation: " The data of a datagram being reassembled from fragments.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[
        #[cfg(umilib_feature = "protocol-ip-v4")]
        v4::MODULE,
        #[cfg(umilib_feature = "protocol-ip-v6")]
        v6::MODULE,
    ],
};
