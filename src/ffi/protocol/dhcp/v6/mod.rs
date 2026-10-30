//! The C ABI of [`crate::protocol::dhcp::v6`].
//!
//! A message, a relay agent's message, an IA (IA_NA or IA_PD), an IA
//! Address and an IA Prefix are structures of their fixed fields beside
//! their options, which cross as the bytes of their wire format (RFC 9915
//! §21.1: each a code, a length and the data). A DUID crosses as its bytes.
//! A client and a server are handles; a client's messages go to
//! All_DHCP_Relay_Agents_and_Servers (ff02::1:2), port 547. Option codes,
//! message types and status codes cross as their numbers. The functions
//! that draw randomness take a generator of the crypto.random module by its
//! handle and the C name of its type.

use alloc::vec::Vec;
use core::ffi::c_void;

use super::DHCPStatus;
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Function, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::dhcp::DHCPDUID;
use crate::protocol::dhcp::v6::{
    DHCPv6Binding, DHCPv6Client, DHCPv6ClientConfig, DHCPv6ClientEvent, DHCPv6ClientState, DHCPv6IA, DHCPv6IAAddress,
    DHCPv6IAPrefix, DHCPv6Lease, DHCPv6Message, DHCPv6MessageType, DHCPv6OptionCode, DHCPv6Options, DHCPv6RelayMessage,
    DHCPv6Server, DHCPv6ServerConfig, DHCPv6StatusCode,
};
use crate::protocol::ip::IPv6Address;
use crate::runtime::Instant;

/// The header of a [`DHCPv6Message`] (RFC 9915 §8): its type and its transaction ID of 24 bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv6Message {
    pub kind: u8,
    pub transaction: u32,
}

impl FFIDHCPv6Message {
    /// The options of the `length` bytes at `options`; fails with Malformed for an option cut short.
    ///
    /// # Safety
    /// As [`Pointer::slice`].
    pub unsafe fn options(options: *const u8, length: usize) -> Result<DHCPv6Options, &'static Status> {
        // SAFETY: the caller's promise.
        let bytes = unsafe { Pointer::slice(options, length) }?;
        DHCPv6Options::decode(bytes).map_err(|error| error.to_status())
    }

    /// The bytes of `options`; fails with TooLarge for an option of more than 65535 bytes.
    pub fn bytes(options: &DHCPv6Options) -> Result<Vec<u8>, &'static Status> {
        let mut out = Vec::new();
        options.encode(&mut out).map_err(|error| error.to_status())?;
        Ok(out)
    }

    /// The message of this header, as it is, and `options`.
    pub fn with(&self, options: DHCPv6Options) -> DHCPv6Message {
        DHCPv6Message { kind: DHCPv6MessageType(self.kind), transaction: self.transaction, options }
    }
}

/// The header of a [`DHCPv6RelayMessage`] (RFC 9915 §9).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv6RelayMessage {
    pub kind: u8,
    pub hops: u8,
    pub link: IPv6Address,
    pub peer: IPv6Address,
}

impl FFIDHCPv6RelayMessage {
    pub fn of(message: &DHCPv6RelayMessage) -> FFIDHCPv6RelayMessage {
        FFIDHCPv6RelayMessage { kind: message.kind.0, hops: message.hops, link: message.link, peer: message.peer }
    }

    /// The message of this header and `options`.
    pub fn with(&self, options: DHCPv6Options) -> DHCPv6RelayMessage {
        DHCPv6RelayMessage {
            kind: DHCPv6MessageType(self.kind),
            hops: self.hops,
            link: self.link,
            peer: self.peer,
            options,
        }
    }
}

/// A [`DHCPv6IA`] but its options: `kind` the code of its option (3 IA_NA, 25 IA_PD).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv6IA {
    pub kind: u16,
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
}

impl FFIDHCPv6IA {
    pub fn of(ia: &DHCPv6IA) -> FFIDHCPv6IA {
        FFIDHCPv6IA { kind: ia.kind.0, iaid: ia.iaid, t1: ia.t1, t2: ia.t2 }
    }

    pub fn with(&self, options: DHCPv6Options) -> DHCPv6IA {
        DHCPv6IA { kind: DHCPv6OptionCode(self.kind), iaid: self.iaid, t1: self.t1, t2: self.t2, options }
    }

    /// The bytes of the options of `ias`, one option each.
    pub fn bytes(ias: &[DHCPv6IA]) -> Result<Vec<u8>, &'static Status> {
        let mut options = DHCPv6Options::new();
        for ia in ias {
            options.entries.push(ia.encode().map_err(|error| error.to_status())?);
        }
        FFIDHCPv6Message::bytes(&options)
    }
}

/// A [`DHCPv6IAAddress`] but its options (RFC 9915 §21.6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv6IAAddress {
    pub address: IPv6Address,
    pub preferred: u32,
    pub valid: u32,
}

/// A [`DHCPv6IAPrefix`] but its options (RFC 9915 §21.22).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv6IAPrefix {
    pub preferred: u32,
    pub valid: u32,
    pub length: u8,
    pub prefix: IPv6Address,
}

/// The fields of a [`DHCPv6ClientConfig`] but its DUID and the codes of the
/// options it asks for: it asks for a prefix (IA_PD) if `prefix`, of
/// `prefix_length` bits if `prefix_hint`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv6ClientConfig {
    pub iaid: u32,
    pub addresses: bool,
    pub prefix: bool,
    pub prefix_hint: bool,
    pub prefix_length: u8,
    pub rapid_commit: bool,
}

impl FFIDHCPv6ClientConfig {
    pub fn config(&self, duid: DHCPDUID, requested: &[u16]) -> DHCPv6ClientConfig {
        DHCPv6ClientConfig {
            duid,
            iaid: self.iaid,
            addresses: self.addresses,
            prefix: self.prefix.then_some(self.prefix_hint.then_some(self.prefix_length)),
            requested: requested.iter().copied().map(DHCPv6OptionCode).collect(),
            rapid_commit: self.rapid_commit,
        }
    }
}

/// A [`DHCPv6Lease`] but its server, IAs and options: `acquired` in
/// nanoseconds, the durations in milliseconds ([`super::DHCPStatus::INFINITY`] for infinity).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv6Lease {
    pub acquired: u64,
    pub renewal: u64,
    pub rebinding: u64,
    pub valid: u64,
}

/// The bytes beside a lease: the options of its IAs, the options of its
/// Reply (or of an Information-request's), and the DUID of its server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FFIDHCPv6LeaseBytes {
    pub ias: Vec<u8>,
    pub options: Vec<u8>,
    pub server: Vec<u8>,
}

impl FFIDHCPv6LeaseBytes {
    /// Writes the bytes into `out_ias`, `out_options` and `out_server`.
    ///
    /// # Safety
    /// As [`Pointer::write`].
    pub unsafe fn write(
        self,
        out_ias: *mut Buffer,
        out_options: *mut Buffer,
        out_server: *mut Buffer,
    ) -> Result<(), &'static Status> {
        // SAFETY: the caller's promise.
        unsafe { Pointer::write(out_ias, Buffer::from_vec(self.ias)) }?;
        unsafe { Pointer::write(out_options, Buffer::from_vec(self.options)) }?;
        unsafe { Pointer::write(out_server, Buffer::from_vec(self.server)) }
    }
}

impl FFIDHCPv6Lease {
    /// The structure of `lease` and its bytes.
    pub fn of(lease: &DHCPv6Lease) -> Result<(FFIDHCPv6Lease, FFIDHCPv6LeaseBytes), &'static Status> {
        let structure = FFIDHCPv6Lease {
            acquired: lease.acquired.as_nanos(),
            renewal: DHCPStatus::milliseconds(lease.renewal),
            rebinding: DHCPStatus::milliseconds(lease.rebinding),
            valid: DHCPStatus::milliseconds(lease.valid),
        };
        let bytes = FFIDHCPv6LeaseBytes {
            ias: FFIDHCPv6IA::bytes(&lease.ias)?,
            options: FFIDHCPv6Message::bytes(&lease.options)?,
            server: lease.server.encode().map_err(|error| error.to_status())?,
        };
        Ok((structure, bytes))
    }
}

/// A [`DHCPv6ClientEvent`]: `kind` the number of its variant (0 Bound, 1
/// Expired, 2 Informed, 3 Released, 4 Unanswered), with the lease of Bound;
/// the fields a variant has not are zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv6ClientEvent {
    pub kind: u8,
    pub lease: FFIDHCPv6Lease,
}

impl FFIDHCPv6ClientEvent {
    /// The structure of `event` and its bytes: of the lease of Bound, the options of Informed.
    pub fn of(event: &DHCPv6ClientEvent) -> Result<(FFIDHCPv6ClientEvent, FFIDHCPv6LeaseBytes), &'static Status> {
        let mut out = FFIDHCPv6ClientEvent::default();
        let mut bytes = FFIDHCPv6LeaseBytes::default();
        match event {
            DHCPv6ClientEvent::Bound(lease) => (out.kind, (out.lease, bytes)) = (0, FFIDHCPv6Lease::of(lease)?),
            DHCPv6ClientEvent::Expired => out.kind = 1,
            DHCPv6ClientEvent::Informed(options) => (out.kind, bytes.options) = (2, FFIDHCPv6Message::bytes(options)?),
            DHCPv6ClientEvent::Released => out.kind = 3,
            DHCPv6ClientEvent::Unanswered => out.kind = 4,
        }
        Ok((out, bytes))
    }
}

/// The number of a [`DHCPv6ClientState`], its place from 0 for Init.
pub struct FFIDHCPv6ClientState;

impl FFIDHCPv6ClientState {
    pub fn of(state: DHCPv6ClientState) -> u8 {
        match state {
            DHCPv6ClientState::Init => 0,
            DHCPv6ClientState::Soliciting => 1,
            DHCPv6ClientState::Requesting => 2,
            DHCPv6ClientState::Bound => 3,
            DHCPv6ClientState::Renewing => 4,
            DHCPv6ClientState::Rebinding => 5,
            DHCPv6ClientState::Confirming => 6,
            DHCPv6ClientState::Releasing => 7,
            DHCPv6ClientState::Declining => 8,
            DHCPv6ClientState::Informing => 9,
            DHCPv6ClientState::Informed => 10,
        }
    }
}

/// The fields of a [`DHCPv6ServerConfig`] but its DUID and options: it
/// leases the addresses from `first` to `last` if `addresses`, and delegates
/// prefixes of `delegated_length` bits from `prefix` of `prefix_length` bits
/// if `prefixes`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv6ServerConfig {
    pub first: IPv6Address,
    pub last: IPv6Address,
    pub prefix: IPv6Address,
    pub addresses: bool,
    pub prefixes: bool,
    pub prefix_length: u8,
    pub delegated_length: u8,
    pub preference: u8,
    pub rapid_commit: bool,
    pub preferred: u32,
    pub valid: u32,
    pub t1: u32,
    pub t2: u32,
}

impl FFIDHCPv6ServerConfig {
    /// The fields of `config`.
    pub fn of(config: &DHCPv6ServerConfig) -> FFIDHCPv6ServerConfig {
        let (first, last) = config.addresses.unwrap_or_default();
        let (prefix, prefix_length, delegated_length) = config.prefixes.unwrap_or_default();
        FFIDHCPv6ServerConfig {
            first,
            last,
            prefix,
            addresses: config.addresses.is_some(),
            prefixes: config.prefixes.is_some(),
            prefix_length,
            delegated_length,
            preference: config.preference,
            rapid_commit: config.rapid_commit,
            preferred: config.preferred,
            valid: config.valid,
            t1: config.t1,
            t2: config.t2,
        }
    }

    pub fn config(&self, duid: DHCPDUID, options: DHCPv6Options) -> DHCPv6ServerConfig {
        DHCPv6ServerConfig {
            duid,
            addresses: self.addresses.then_some((self.first, self.last)),
            prefixes: self.prefixes.then_some((self.prefix, self.prefix_length, self.delegated_length)),
            preferred: self.preferred,
            valid: self.valid,
            t1: self.t1,
            t2: self.t2,
            preference: self.preference,
            rapid_commit: self.rapid_commit,
            options,
        }
    }
}

impl Value for FFIDHCPv6Message {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v6_DHCPv6Message");
}

impl Value for FFIDHCPv6RelayMessage {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v6_DHCPv6RelayMessage");
}

impl Value for FFIDHCPv6IA {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v6_DHCPv6IA");
}

impl Value for FFIDHCPv6IAAddress {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v6_DHCPv6IAAddress");
}

impl Value for FFIDHCPv6IAPrefix {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v6_DHCPv6IAPrefix");
}

impl Value for FFIDHCPv6ClientConfig {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v6_DHCPv6ClientConfig");
}

impl Value for FFIDHCPv6Lease {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v6_DHCPv6Lease");
}

impl Value for FFIDHCPv6ClientEvent {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v6_DHCPv6ClientEvent");
}

impl Value for DHCPv6Client {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v6_DHCPv6Client");
}

impl Value for FFIDHCPv6ServerConfig {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v6_DHCPv6ServerConfig");
}

/// A [`DHCPv6Binding`] but its client's key: its IA (`kind` the IA's
/// option code, `iaid`), the address or prefix (`length` its length when
/// `has_length`), until `expires` (nanoseconds, UINT64_MAX for never), and
/// whether it is declined.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv6Binding {
    pub address: IPv6Address,
    pub iaid: u32,
    pub kind: u16,
    pub length: u8,
    pub has_length: bool,
    pub declined: bool,
    pub expires: u64,
}

impl FFIDHCPv6Binding {
    pub fn of(binding: &DHCPv6Binding) -> FFIDHCPv6Binding {
        FFIDHCPv6Binding {
            address: binding.address,
            iaid: binding.iaid,
            kind: binding.kind.0,
            length: binding.length.unwrap_or(0),
            has_length: binding.length.is_some(),
            declined: binding.declined,
            expires: binding.expires.map_or(DHCPStatus::INFINITY, Instant::as_nanos),
        }
    }

    /// The binding of this structure and the key of its client.
    pub fn binding(&self, client: Vec<u8>) -> DHCPv6Binding {
        DHCPv6Binding {
            client,
            kind: DHCPv6OptionCode(self.kind),
            iaid: self.iaid,
            address: self.address,
            length: self.has_length.then_some(self.length),
            expires: (self.expires != DHCPStatus::INFINITY).then(|| Instant::from_nanos(self.expires)),
            declined: self.declined,
        }
    }
}

impl Value for FFIDHCPv6Binding {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v6_DHCPv6Binding");
}

impl Value for DHCPv6Server {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v6_DHCPv6Server");
}

crate::ffi_functions! {
    const MESSAGE;

    /// Reads the message of the `length` bytes at `bytes` (RFC 9915 §8) into `out` and its options into
    /// `out_options`; fails with Malformed for one shorter than 4 bytes, of a relay agent's type, or
    /// with an option cut short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_message_decode(bytes: *const u8, length: usize, out: *mut FFIDHCPv6Message, out_options: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_options, 1)?;
            let message = DHCPv6Message::decode(bytes).map_err(|error| error.to_status())?;
            let options = FFIDHCPv6Message::bytes(&message.options)?;
            unsafe { Pointer::write(out, FFIDHCPv6Message { kind: message.kind.0, transaction: message.transaction }) }?;
            unsafe { Pointer::write(out_options, Buffer::from_vec(options)) }
        })())
    }

    /// Writes the message of `message` and the options of `length` bytes at `options` into `out`; fails
    /// with Malformed for a relay agent's type, a transaction ID of more than 24 bits or an option cut
    /// short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_message_encode(message: FFIDHCPv6Message, options: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let options = unsafe { FFIDHCPv6Message::options(options, length) }?;
            Pointer::check_range(out, 1)?;
            let bytes = message.with(options).encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// Reads the relay agent's message of the `length` bytes at `bytes` (RFC 9915 §9) into `out` and
    /// its options, the relayed message in its Relay Message option (§21.10), into `out_options`;
    /// fails with Malformed for one shorter than 34 bytes, of a type of no relay agent, or with an
    /// option cut short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_relay_message_decode(bytes: *const u8, length: usize, out: *mut FFIDHCPv6RelayMessage, out_options: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_options, 1)?;
            let message = DHCPv6RelayMessage::decode(bytes).map_err(|error| error.to_status())?;
            let options = FFIDHCPv6Message::bytes(&message.options)?;
            unsafe { Pointer::write(out, FFIDHCPv6RelayMessage::of(&message)) }?;
            unsafe { Pointer::write(out_options, Buffer::from_vec(options)) }
        })())
    }

    /// Writes the relay agent's message of the header at `message` and the options of `length` bytes
    /// at `options` into `out`; fails with Malformed for a type of no relay agent or an option cut short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_relay_message_encode(message: *const FFIDHCPv6RelayMessage, options: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, readable bytes and a writable buffer.
            let message = unsafe { Pointer::reference(message) }?;
            let options = unsafe { FFIDHCPv6Message::options(options, length) }?;
            Pointer::check_range(out, 1)?;
            let bytes = message.with(options).encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// Reads the IA of the option `kind` (3 IA_NA, §21.4; 25 IA_PD, §21.21) whose data are the `length`
    /// bytes at `data` into `out` and its options into `out_options`; fails with Malformed for data
    /// shorter than 12 bytes or an option cut short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_ia_decode(kind: u16, data: *const u8, length: usize, out: *mut FFIDHCPv6IA, out_options: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_options, 1)?;
            let ia = DHCPv6IA::decode(DHCPv6OptionCode(kind), data).map_err(|error| error.to_status())?;
            let options = FFIDHCPv6Message::bytes(&ia.options)?;
            unsafe { Pointer::write(out, FFIDHCPv6IA::of(&ia)) }?;
            unsafe { Pointer::write(out_options, Buffer::from_vec(options)) }
        })())
    }

    /// Writes the data of the option of the IA `ia` and the options of `length` bytes at `options`
    /// into `out`; fails with Malformed for an option cut short and with TooLarge.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_ia_encode(ia: FFIDHCPv6IA, options: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let options = unsafe { FFIDHCPv6Message::options(options, length) }?;
            Pointer::check_range(out, 1)?;
            let option = ia.with(options).encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(option.data)) }
        })())
    }

    /// Reads the IA Address option (RFC 9915 §21.6) whose data are the `length` bytes at `data` into
    /// `out` and its options into `out_options`; fails with Malformed for data shorter than 24 bytes or
    /// an option cut short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_ia_address_decode(data: *const u8, length: usize, out: *mut FFIDHCPv6IAAddress, out_options: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_options, 1)?;
            let address = DHCPv6IAAddress::decode(data).map_err(|error| error.to_status())?;
            let options = FFIDHCPv6Message::bytes(&address.options)?;
            let structure = FFIDHCPv6IAAddress { address: address.address, preferred: address.preferred, valid: address.valid };
            unsafe { Pointer::write(out, structure) }?;
            unsafe { Pointer::write(out_options, Buffer::from_vec(options)) }
        })())
    }

    /// Writes the data of the IA Address option of `address` and the options of `length` bytes at
    /// `options` into `out`; fails with Malformed for an option cut short and with TooLarge.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_ia_address_encode(address: FFIDHCPv6IAAddress, options: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let options = unsafe { FFIDHCPv6Message::options(options, length) }?;
            Pointer::check_range(out, 1)?;
            let address = DHCPv6IAAddress { address: address.address, preferred: address.preferred, valid: address.valid, options };
            let data = address.encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Reads the IA Prefix option (RFC 9915 §21.22) whose data are the `length` bytes at `data` into
    /// `out` and its options into `out_options`; fails with Malformed for data shorter than 25 bytes, a
    /// prefix longer than 128 bits, or an option cut short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_ia_prefix_decode(data: *const u8, length: usize, out: *mut FFIDHCPv6IAPrefix, out_options: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_options, 1)?;
            let prefix = DHCPv6IAPrefix::decode(data).map_err(|error| error.to_status())?;
            let options = FFIDHCPv6Message::bytes(&prefix.options)?;
            let structure = FFIDHCPv6IAPrefix { preferred: prefix.preferred, valid: prefix.valid, length: prefix.length, prefix: prefix.prefix };
            unsafe { Pointer::write(out, structure) }?;
            unsafe { Pointer::write(out_options, Buffer::from_vec(options)) }
        })())
    }

    /// Writes the data of the IA Prefix option of `prefix` and the options of `length` bytes at
    /// `options` into `out`; fails with Malformed for a prefix longer than 128 bits or an option cut
    /// short, and with TooLarge.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_ia_prefix_encode(prefix: FFIDHCPv6IAPrefix, options: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let options = unsafe { FFIDHCPv6Message::options(options, length) }?;
            Pointer::check_range(out, 1)?;
            let prefix = DHCPv6IAPrefix { preferred: prefix.preferred, valid: prefix.valid, length: prefix.length, prefix: prefix.prefix, options };
            let data = prefix.encode().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Reads the Status Code option (RFC 9915 §21.13) whose data are the `length` bytes at `data`: its
    /// code into `out_code` and its UTF-8 message, text not UTF-8 replaced, into `out_message`; fails
    /// with Malformed for data shorter than 2 bytes.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_status_code_decode(data: *const u8, length: usize, out_code: *mut u16, out_message: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out_code, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out_code, 1)?;
            Pointer::check_range(out_message, 1)?;
            let status = DHCPv6StatusCode::decode(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_code, status.code) }?;
            unsafe { Pointer::write_text(out_message, status.message) }
        })())
    }

    /// Writes the data of the Status Code option of `code` and the UTF-8 message of `length` bytes at
    /// `message` into `out`; fails with InvalidUTF8.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_status_code_encode(code: u16, message: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable buffer.
            let message = unsafe { Pointer::text(message, length) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(DHCPv6StatusCode::new(code, message).encode())) }
        })())
    }
}

crate::ffi_functions! {
    const CLIENT;

    /// Writes a client of the configuration at `config` into `out`: of the DUID of `duid_length` bytes
    /// at `duid`, asking for the `count` option codes at `requested` (RFC 9915 §21.7); `now` is in
    /// nanoseconds. Fails with Malformed for a DUID that umilib_protocol_dhcp_dhcp_duid_decode refuses.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_new(config: *const FFIDHCPv6ClientConfig, duid: *const u8, duid_length: usize, requested: *const u16, count: usize, now: u64, out: *mut *mut DHCPv6Client) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, readable bytes and codes, and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            let duid = DHCPDUID::decode(unsafe { Pointer::slice(duid, duid_length) }?).map_err(|error| error.to_status())?;
            let requested = unsafe { Pointer::slice_of(requested, count) }?;
            Pointer::check_range(out, 1)?;
            let client = DHCPv6Client::new(config.config(duid, requested), Instant::from_nanos(now));
            unsafe { Pointer::write_handle(out, client) }
        })())
    }

    /// Releases a client. Does nothing if `client` is null.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_free(client: *mut DHCPv6Client) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(client) }
    }

    /// Starts the client at `now`: a Solicit for addresses or prefixes, or, asking for neither, an
    /// Information-request (RFC 9915 §18.2.6), the first after a random delay of up to a second; its
    /// transaction ID and delays are drawn from `random`. Fails with Random if `random` fails.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_start(client: *mut DHCPv6Client, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable text.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            client.start(Instant::from_nanos(now), &mut random).map_err(|error| error.to_status())
        })())
    }

    /// Takes the server's message of `length` bytes at `bytes`, received at `now`; one not of the
    /// exchange's transaction, with the client's DUID and a server's (RFC 9915 §16), is ignored, as is
    /// a Reconfigure (§18.2.11). A new exchange draws from `random`.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_receive(client: *mut DHCPv6Client, bytes: *const u8, length: usize, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, readable bytes and readable text.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            client.receive(bytes, Instant::from_nanos(now), &mut random);
            Ok(())
        })())
    }

    /// Writes whether a message is due into `out_found` and its bytes into `out`; it goes to
    /// All_DHCP_Relay_Agents_and_Servers, port 547. Fails with TooLarge for an option too long to write.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_transmit(client: *mut DHCPv6Client, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference_mut(client) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let bytes = client.transmit().map(|message| message.encode()).transpose().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_found, bytes.is_some()) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes.unwrap_or_default())) }
        })())
    }

    /// Writes whether a timer is set into `out_found` and when umilib_protocol_dhcp_v6_dhcpv6_client_expire
    /// is due (nanoseconds) into `out`.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_poll_timeout(client: *const DHCPv6Client, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference(client) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let timeout = client.poll_timeout();
            unsafe { Pointer::write(out_found, timeout.is_some()) }?;
            unsafe { Pointer::write(out, timeout.map_or(0, Instant::as_nanos)) }
        })())
    }

    /// Does what is due at `now`: a delayed first message, a retransmission or the end of an exchange
    /// (RFC 9915 §15), Renew at T1, Rebind at T2, the end of the lease, or a refresh of stateless
    /// configuration (§18.2.12); drawing from `random`.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_expire(client: *mut DHCPv6Client, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable text.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            client.expire(Instant::from_nanos(now), &mut random);
            Ok(())
        })())
    }

    /// Writes whether an event is pending into `out_found` and the event into `out`; of a Bound event,
    /// the options of its IAs into `out_ias`, of its Reply into `out_options` and its server's DUID
    /// into `out_server`; of an Informed event, its options into `out_options`. The buffers of what an
    /// event has not are empty.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_poll_event(client: *mut DHCPv6Client, out_found: *mut bool, out: *mut FFIDHCPv6ClientEvent, out_ias: *mut Buffer, out_options: *mut Buffer, out_server: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference_mut(client) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_ias, 1)?;
            Pointer::check_range(out_options, 1)?;
            Pointer::check_range(out_server, 1)?;
            let event = client.poll_event();
            let (structure, bytes) = event.as_ref().map(FFIDHCPv6ClientEvent::of).transpose()?.unwrap_or_default();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            unsafe { Pointer::write(out, structure) }?;
            unsafe { bytes.write(out_ias, out_options, out_server) }
        })())
    }

    /// Writes the number of the client's state into `out`: 0 Init, 1 Soliciting, 2 Requesting, 3
    /// Bound, 4 Renewing, 5 Rebinding, 6 Confirming, 7 Releasing, 8 Declining, 9 Informing, 10 Informed.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_state(client: *const DHCPv6Client, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write(out, FFIDHCPv6ClientState::of(client.state)) }
        })())
    }

    /// Writes whether the client holds a lease into `out_found`, the lease into `out`, the options of
    /// its IAs into `out_ias`, of its Reply into `out_options` and its server's DUID into `out_server`.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_lease(client: *const DHCPv6Client, out_found: *mut bool, out: *mut FFIDHCPv6Lease, out_ias: *mut Buffer, out_options: *mut Buffer, out_server: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference(client) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_ias, 1)?;
            Pointer::check_range(out_options, 1)?;
            Pointer::check_range(out_server, 1)?;
            let lease = client.lease.as_ref();
            let (structure, bytes) = lease.map(FFIDHCPv6Lease::of).transpose()?.unwrap_or_default();
            unsafe { Pointer::write(out_found, lease.is_some()) }?;
            unsafe { Pointer::write(out, structure) }?;
            unsafe { bytes.write(out_ias, out_options, out_server) }
        })())
    }

    /// Releases the lease (RFC 9915 §18.2.7), in an exchange whose transaction ID is drawn from
    /// `random`; the client stops. Fails with State without a lease, and with Random if `random` fails.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_release(client: *mut DHCPv6Client, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable text.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            client.release(Instant::from_nanos(now), &mut random).map_err(|error| error.to_status())
        })())
    }

    /// Declines the `count` addresses at `addresses` of the lease, which DAD found in use (RFC 9915
    /// §18.2.8), drawing from `random`. Fails with State without a lease or without addresses, and
    /// with Random if `random` fails.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_decline(client: *mut DHCPv6Client, addresses: *const IPv6Address, count: usize, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, readable addresses and readable text.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let addresses = unsafe { Pointer::slice_of(addresses, count) }?.to_vec();
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            client.decline(addresses, Instant::from_nanos(now), &mut random).map_err(|error| error.to_status())
        })())
    }

    /// Confirms the lease after the link may have changed (RFC 9915 §18.2.3), after a random delay of
    /// up to a second drawn from `random`. Fails with State without a lease, and with Random if
    /// `random` fails.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_client_confirm(client: *mut DHCPv6Client, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable text.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            client.confirm(Instant::from_nanos(now), &mut random).map_err(|error| error.to_status())
        })())
    }
}

crate::ffi_functions! {
    const SERVER;

    /// Writes the configuration of a server that leases nothing yet into `out`: lifetimes of a day
    /// preferred and two valid, T1 and T2 of 0 (derived, RFC 9915 §21.4), preference 0, no Rapid Commit.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_server_config_new(out: *mut FFIDHCPv6ServerConfig) -> *const Status {
        let config = DHCPv6ServerConfig::new(DHCPDUID::UUID([0; 16]));
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFIDHCPv6ServerConfig::of(&config)) })
    }

    /// Writes a server of the configuration at `config` into `out`: of the DUID of `duid_length` bytes
    /// at `duid`, giving the options of `length` bytes at `options`, each to a client that asks for it
    /// (RFC 9915 §18.3.9). Fails with Malformed for a DUID that umilib_protocol_dhcp_dhcp_duid_decode
    /// refuses or an option cut short, and with Config for a pool whose first address is after its
    /// last, or prefixes longer than their delegated length, longer than 128 bits or more than 2^32.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_server_new(config: *const FFIDHCPv6ServerConfig, duid: *const u8, duid_length: usize, options: *const u8, length: usize, out: *mut *mut DHCPv6Server) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, readable bytes and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            let duid = DHCPDUID::decode(unsafe { Pointer::slice(duid, duid_length) }?).map_err(|error| error.to_status())?;
            let options = unsafe { FFIDHCPv6Message::options(options, length) }?;
            Pointer::check_range(out, 1)?;
            let server = DHCPv6Server::new(config.config(duid, options)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, server) }
        })())
    }

    /// Releases a server. Does nothing if `server` is null.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_server_free(server: *mut DHCPv6Server) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(server) }
    }

    /// Takes the message of `length` bytes at `bytes`, a client's or a Relay-forward, received at `now`
    /// (nanoseconds); writes whether a reply is due into `out_found` and its bytes into `out`: to a
    /// Relay-forward, a Relay-reply of the same addresses and Interface-Id (RFC 9915 §19.3).
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_server_receive(server: *mut DHCPv6Server, bytes: *const u8, length: usize, now: u64, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out_found, 1)])?;
            // SAFETY: the caller passes a valid handle, readable bytes and writable pointers.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let reply = server.receive(bytes, Instant::from_nanos(now));
            unsafe { Pointer::write(out_found, reply.is_some()) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(reply.unwrap_or_default())) }
        })())
    }

    /// Forgets the bindings expired at `now`, but the declined addresses.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_server_expire(server: *mut DHCPv6Server, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes how many bindings the server has into `out`.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_server_bindings_count(server: *const DHCPv6Server, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.bindings.len()) }
        })())
    }

    /// Writes the binding of `index`, in the order of addresses, into `out` and the key of its client
    /// into `out_client`; fails with InvalidArgument for an index past the last.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_server_binding_entry(server: *const DHCPv6Server, index: usize, out: *mut FFIDHCPv6Binding, out_client: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_client, 1)?;
            let binding = server.bindings.values().nth(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, FFIDHCPv6Binding::of(binding)) }?;
            unsafe { Pointer::write(out_client, Buffer::from_vec(binding.client.clone())) }
        })())
    }

    /// Sets the binding of its address (and prefix length) to `binding`, of the client of the key of
    /// the `length` bytes at `client`: a binding kept elsewhere, given back.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_server_set_binding(server: *mut DHCPv6Server, binding: FFIDHCPv6Binding, client: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let binding = binding.binding(unsafe { Pointer::slice(client, length) }?.to_vec());
            server.bindings.insert((binding.address, binding.length), binding);
            Ok(())
        })())
    }

    /// Removes the binding of `address` (and of `length` if `has_length`), if any.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v6_dhcpv6_server_remove_binding(server: *mut DHCPv6Server, address: IPv6Address, length: u8, has_length: bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(server) }?.bindings.remove(&(address, has_length.then_some(length)));
            Ok(())
        })())
    }
}

/// The functions of this module, in declaration order.
pub const FUNCTIONS: &[Function] =
    &Function::concat::<{ MESSAGE.len() + CLIENT.len() + SERVER.len() }>(&[MESSAGE, CLIENT, SERVER]);

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v6",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_dhcp_v6_DHCPv6Message",
            documentation: " The header of a DHCPv6 message (RFC 9915 §8); the options are beside it.",
            fields: &[
                Parameter { name: "kind", value: <u8 as Value>::TYPE },
                Parameter { name: "transaction", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v6_DHCPv6RelayMessage",
            documentation: " The header of a DHCPv6 relay agent's message (RFC 9915 §9); the options are beside it.",
            fields: &[
                Parameter { name: "kind", value: <u8 as Value>::TYPE },
                Parameter { name: "hops", value: <u8 as Value>::TYPE },
                Parameter { name: "link", value: <IPv6Address as Value>::TYPE },
                Parameter { name: "peer", value: <IPv6Address as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v6_DHCPv6IA",
            documentation: " An Identity Association: kind 3 IA_NA (RFC 9915 §21.4) or 25 IA_PD (§21.21); T1 and T2 in\n \
                            seconds; the options are beside it.",
            fields: &[
                Parameter { name: "kind", value: <u16 as Value>::TYPE },
                Parameter { name: "iaid", value: <u32 as Value>::TYPE },
                Parameter { name: "t1", value: <u32 as Value>::TYPE },
                Parameter { name: "t2", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v6_DHCPv6IAAddress",
            documentation: " An IA Address option (RFC 9915 §21.6), lifetimes in seconds; the options are beside it.",
            fields: &[
                Parameter { name: "address", value: <IPv6Address as Value>::TYPE },
                Parameter { name: "preferred", value: <u32 as Value>::TYPE },
                Parameter { name: "valid", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v6_DHCPv6IAPrefix",
            documentation: " An IA Prefix option (RFC 9915 §21.22), lifetimes in seconds; the options are beside it.",
            fields: &[
                Parameter { name: "preferred", value: <u32 as Value>::TYPE },
                Parameter { name: "valid", value: <u32 as Value>::TYPE },
                Parameter { name: "length", value: <u8 as Value>::TYPE },
                Parameter { name: "prefix", value: <IPv6Address as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v6_DHCPv6ClientConfig",
            documentation: " How a DHCPv6 client asks, but its DUID and option codes: for a prefix if prefix, of\n \
                            prefix_length bits if prefix_hint.",
            fields: &[
                Parameter { name: "iaid", value: <u32 as Value>::TYPE },
                Parameter { name: "addresses", value: <bool as Value>::TYPE },
                Parameter { name: "prefix", value: <bool as Value>::TYPE },
                Parameter { name: "prefix_hint", value: <bool as Value>::TYPE },
                Parameter { name: "prefix_length", value: <u8 as Value>::TYPE },
                Parameter { name: "rapid_commit", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v6_DHCPv6Lease",
            documentation: " The bindings of a DHCPv6 client: acquired in nanoseconds, durations in milliseconds\n \
                            (UINT64_MAX for infinity).",
            fields: &[
                Parameter { name: "acquired", value: <u64 as Value>::TYPE },
                Parameter { name: "renewal", value: <u64 as Value>::TYPE },
                Parameter { name: "rebinding", value: <u64 as Value>::TYPE },
                Parameter { name: "valid", value: <u64 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v6_DHCPv6ClientEvent",
            documentation: " What a DHCPv6 client tells: kind 0 Bound (with its lease), 1 Expired, 2 Informed, 3 Released,\n \
                            4 Unanswered.",
            fields: &[
                Parameter { name: "kind", value: <u8 as Value>::TYPE },
                Parameter { name: "lease", value: <FFIDHCPv6Lease as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_dhcp_v6_DHCPv6Client",
            documentation: " A DHCPv6 client without I/O (RFC 9915 §18.2).",
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v6_DHCPv6ServerConfig",
            documentation: " What a DHCPv6 server leases and delegates, but its DUID and options: lifetimes, T1 and T2\n \
                            in seconds (0xFFFFFFFF for infinity; T1 and T2 of 0 let the client choose).",
            fields: &[
                Parameter { name: "first", value: <IPv6Address as Value>::TYPE },
                Parameter { name: "last", value: <IPv6Address as Value>::TYPE },
                Parameter { name: "prefix", value: <IPv6Address as Value>::TYPE },
                Parameter { name: "addresses", value: <bool as Value>::TYPE },
                Parameter { name: "prefixes", value: <bool as Value>::TYPE },
                Parameter { name: "prefix_length", value: <u8 as Value>::TYPE },
                Parameter { name: "delegated_length", value: <u8 as Value>::TYPE },
                Parameter { name: "preference", value: <u8 as Value>::TYPE },
                Parameter { name: "rapid_commit", value: <bool as Value>::TYPE },
                Parameter { name: "preferred", value: <u32 as Value>::TYPE },
                Parameter { name: "valid", value: <u32 as Value>::TYPE },
                Parameter { name: "t1", value: <u32 as Value>::TYPE },
                Parameter { name: "t2", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v6_DHCPv6Binding",
            documentation: " An address or a prefix a DHCPv6 server gave to an IA (kind its option code); until\n \
                            expires (nanoseconds, UINT64_MAX for never).",
            fields: &[
                Parameter { name: "address", value: <IPv6Address as Value>::TYPE },
                Parameter { name: "iaid", value: <u32 as Value>::TYPE },
                Parameter { name: "kind", value: <u16 as Value>::TYPE },
                Parameter { name: "length", value: <u8 as Value>::TYPE },
                Parameter { name: "has_length", value: <bool as Value>::TYPE },
                Parameter { name: "declined", value: <bool as Value>::TYPE },
                Parameter { name: "expires", value: <u64 as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_dhcp_v6_DHCPv6Server",
            documentation: " A DHCPv6 server without I/O (RFC 9915 §18.3) and its bindings.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
