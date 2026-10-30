//! The C ABI of [`crate::protocol::dhcp::v4`].
//!
//! A message is an [`FFIDHCPv4Message`] of its header beside its options,
//! which cross as an options area (RFC 2132 §2) as [`DHCPv4Options::encode`]
//! writes it: each option once, in the order first seen, one longer than
//! 255 bytes in consecutive parts (RFC 3396 §6), then END. A client and a
//! server are handles; a client's messages go to port 67, a server's to the
//! destination and port of its reply. Option codes and message types cross
//! as their numbers. The functions that draw randomness take a generator of
//! the crypto.random module by its handle and the C name of its type.

use alloc::vec::Vec;
use core::time::Duration;

use core::ffi::c_void;

use super::DHCPStatus;
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Function, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::dhcp::v4::{
    DHCPv4Binding, DHCPv4BindingState, DHCPv4Client, DHCPv4ClientConfig, DHCPv4ClientEvent, DHCPv4ClientState,
    DHCPv4Lease, DHCPv4Message, DHCPv4OptionCode, DHCPv4Options, DHCPv4Reply, DHCPv4Route, DHCPv4Server,
    DHCPv4ServerConfig, DHCPv4Transmission,
};
use crate::protocol::ethernet::MACAddress;
use crate::protocol::ip::IPv4Address;
use crate::runtime::Instant;

/// The header of a [`DHCPv4Message`] (RFC 2131 §2), its fields as they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv4Message {
    pub op: u8,
    pub hardware_type: u8,
    pub hardware_length: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: IPv4Address,
    pub yiaddr: IPv4Address,
    pub siaddr: IPv4Address,
    pub giaddr: IPv4Address,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
}

impl FFIDHCPv4Message {
    /// The header of `message`.
    pub fn of(message: &DHCPv4Message) -> FFIDHCPv4Message {
        FFIDHCPv4Message {
            op: message.op,
            hardware_type: message.hardware_type,
            hardware_length: message.hardware_length,
            hops: message.hops,
            xid: message.xid,
            secs: message.secs,
            flags: message.flags,
            ciaddr: message.ciaddr,
            yiaddr: message.yiaddr,
            siaddr: message.siaddr,
            giaddr: message.giaddr,
            chaddr: message.chaddr,
            sname: message.sname,
            file: message.file,
        }
    }

    /// The message of this header and `options`.
    pub fn with(&self, options: DHCPv4Options) -> DHCPv4Message {
        DHCPv4Message {
            op: self.op,
            hardware_type: self.hardware_type,
            hardware_length: self.hardware_length,
            hops: self.hops,
            xid: self.xid,
            secs: self.secs,
            flags: self.flags,
            ciaddr: self.ciaddr,
            yiaddr: self.yiaddr,
            siaddr: self.siaddr,
            giaddr: self.giaddr,
            chaddr: self.chaddr,
            sname: self.sname,
            file: self.file,
            options,
        }
    }

    /// The options of the options area `area`; fails with Malformed for an option cut short.
    pub fn options(area: &[u8]) -> Result<DHCPv4Options, &'static Status> {
        let mut options = DHCPv4Options::new();
        options.decode_area(area).map_err(|error| error.to_status())?;
        Ok(options)
    }

    /// The options area of `options`.
    pub fn area(options: &DHCPv4Options) -> Vec<u8> {
        let mut area = Vec::new();
        options.encode(&mut area);
        area
    }
}

/// A [`DHCPv4Route`] of the classless static route option (RFC 3442 §2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv4Route {
    pub destination: IPv4Address,
    pub prefix: u8,
    pub router: IPv4Address,
}

impl FFIDHCPv4Route {
    pub fn of(route: &DHCPv4Route) -> FFIDHCPv4Route {
        FFIDHCPv4Route { destination: route.destination, prefix: route.prefix, router: route.router }
    }

    pub fn route(&self) -> DHCPv4Route {
        DHCPv4Route { destination: self.destination, prefix: self.prefix, router: self.router }
    }
}

/// The fields of a [`DHCPv4ClientConfig`] but its byte strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv4ClientConfig {
    pub hardware: MACAddress,
    pub broadcast: bool,
    pub ipv6_only: bool,
    pub maximum_message_size: u16,
    pub retransmissions: usize,
}

impl FFIDHCPv4ClientConfig {
    /// The configuration of these fields, the client identifier, the host
    /// name and the codes of the options asked for.
    pub fn config(
        &self,
        client_identifier: Option<&[u8]>,
        host_name: Option<&[u8]>,
        parameters: &[u8],
    ) -> DHCPv4ClientConfig {
        DHCPv4ClientConfig {
            hardware: self.hardware,
            client_identifier: client_identifier.map(<[u8]>::to_vec),
            host_name: host_name.map(<[u8]>::to_vec),
            parameters: parameters.iter().copied().map(DHCPv4OptionCode).collect(),
            broadcast: self.broadcast,
            maximum_message_size: self.maximum_message_size,
            retransmissions: self.retransmissions,
            ipv6_only: self.ipv6_only,
        }
    }
}

/// A [`DHCPv4Lease`] but its options: the durations in milliseconds
/// ([`DHCPStatus::INFINITY`] for infinity), `acquired` in nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv4Lease {
    pub address: IPv4Address,
    pub server: IPv4Address,
    pub lease: u64,
    pub renewal: u64,
    pub rebinding: u64,
    pub acquired: u64,
}

impl FFIDHCPv4Lease {
    /// The structure of `lease` and the options area of its ACK.
    pub fn of(lease: &DHCPv4Lease) -> (FFIDHCPv4Lease, Vec<u8>) {
        let structure = FFIDHCPv4Lease {
            address: lease.address,
            server: lease.server,
            lease: DHCPStatus::milliseconds(lease.lease),
            renewal: DHCPStatus::milliseconds(lease.renewal),
            rebinding: DHCPStatus::milliseconds(lease.rebinding),
            acquired: lease.acquired.as_nanos(),
        };
        (structure, FFIDHCPv4Message::area(&lease.options))
    }
}

/// A [`DHCPv4ClientEvent`]: `kind` the number of its variant (0 Bound, 1
/// Refused, 2 Expired, 3 Unanswered, 4 IPv6Only), the lease of Bound, and
/// the milliseconds of IPv6Only in `wait`; the fields a variant has not are zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv4ClientEvent {
    pub kind: u8,
    pub lease: FFIDHCPv4Lease,
    pub wait: u64,
}

impl FFIDHCPv4ClientEvent {
    /// The structure of `event` and the options area of its lease (empty without one).
    pub fn of(event: &DHCPv4ClientEvent) -> (FFIDHCPv4ClientEvent, Vec<u8>) {
        let mut out = FFIDHCPv4ClientEvent::default();
        let mut options = Vec::new();
        match event {
            DHCPv4ClientEvent::Bound(lease) => (out.kind, (out.lease, options)) = (0, FFIDHCPv4Lease::of(lease)),
            DHCPv4ClientEvent::Refused => out.kind = 1,
            DHCPv4ClientEvent::Expired => out.kind = 2,
            DHCPv4ClientEvent::Unanswered => out.kind = 3,
            DHCPv4ClientEvent::IPv6Only(wait) => (out.kind, out.wait) = (4, DHCPStatus::milliseconds(Some(*wait))),
        }
        (out, options)
    }
}

/// The number of a [`DHCPv4ClientState`], its place from 0 for Init.
pub struct FFIDHCPv4ClientState;

impl FFIDHCPv4ClientState {
    pub fn of(state: DHCPv4ClientState) -> u8 {
        match state {
            DHCPv4ClientState::Init => 0,
            DHCPv4ClientState::Selecting => 1,
            DHCPv4ClientState::Requesting => 2,
            DHCPv4ClientState::Rebooting => 3,
            DHCPv4ClientState::Bound => 4,
            DHCPv4ClientState::Renewing => 5,
            DHCPv4ClientState::Rebinding => 6,
        }
    }
}

/// A [`DHCPv4Transmission`] crosses as its destination and the bytes of its message.
pub struct FFIDHCPv4Transmission;

impl FFIDHCPv4Transmission {
    /// Writes the destination of `transmission` into `out_destination` and its message into `out`.
    ///
    /// # Safety
    /// As [`Pointer::write`].
    pub unsafe fn write(
        transmission: &DHCPv4Transmission,
        out_destination: *mut IPv4Address,
        out: *mut Buffer,
    ) -> Result<(), &'static Status> {
        // SAFETY: the caller's promise.
        unsafe { Pointer::write(out_destination, transmission.destination) }?;
        unsafe { Pointer::write(out, Buffer::from_vec(transmission.message.encode())) }
    }
}

/// The fields of a [`DHCPv4ServerConfig`] but its reservations and options:
/// the durations in milliseconds, [`DHCPStatus::INFINITY`] for a lease for ever.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv4ServerConfig {
    pub address: IPv4Address,
    pub first: IPv4Address,
    pub last: IPv4Address,
    pub authoritative: bool,
    pub lease: u64,
    pub offer_time: u64,
    pub decline_time: u64,
}

impl FFIDHCPv4ServerConfig {
    /// The fields of `config`.
    pub fn of(config: &DHCPv4ServerConfig) -> FFIDHCPv4ServerConfig {
        FFIDHCPv4ServerConfig {
            address: config.address,
            first: config.first,
            last: config.last,
            authoritative: config.authoritative,
            lease: DHCPStatus::milliseconds(config.lease),
            offer_time: DHCPStatus::milliseconds(Some(config.offer_time)),
            decline_time: DHCPStatus::milliseconds(Some(config.decline_time)),
        }
    }

    pub fn config(&self, reservations: Vec<(Vec<u8>, IPv4Address)>, options: DHCPv4Options) -> DHCPv4ServerConfig {
        DHCPv4ServerConfig {
            address: self.address,
            first: self.first,
            last: self.last,
            reservations,
            lease: DHCPStatus::duration(self.lease),
            offer_time: DHCPStatus::duration(self.offer_time).unwrap_or(Duration::MAX),
            decline_time: DHCPStatus::duration(self.decline_time).unwrap_or(Duration::MAX),
            options,
            authoritative: self.authoritative,
        }
    }
}

/// A [`DHCPv4Reply`] but its message: the hardware address `link` to send
/// it to without ARP if `has_link` (RFC 2131 §4.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv4Reply {
    pub destination: IPv4Address,
    pub port: u16,
    pub link: MACAddress,
    pub has_link: bool,
}

impl FFIDHCPv4Reply {
    pub fn of(reply: &DHCPv4Reply) -> FFIDHCPv4Reply {
        FFIDHCPv4Reply {
            destination: reply.destination,
            port: reply.port,
            link: reply.link.unwrap_or_default(),
            has_link: reply.link.is_some(),
        }
    }
}

/// A [`DHCPv4Binding`] but its client: `state` the number of its
/// [`DHCPv4BindingState`] (0 Offered, 1 Bound, 2 Declined), `expires` in
/// nanoseconds, [`DHCPStatus::INFINITY`] for never.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDHCPv4Binding {
    pub state: u8,
    pub expires: u64,
}

impl FFIDHCPv4Binding {
    /// The binding of this structure and the key of its client; fails with InvalidArgument for a state of no number.
    pub fn binding(&self, client: Vec<u8>) -> Result<DHCPv4Binding, &'static Status> {
        let state = match self.state {
            0 => DHCPv4BindingState::Offered,
            1 => DHCPv4BindingState::Bound,
            2 => DHCPv4BindingState::Declined,
            _ => return Err(&Status::INVALID_ARGUMENT),
        };
        let expires = (self.expires != DHCPStatus::INFINITY).then(|| Instant::from_nanos(self.expires));
        Ok(DHCPv4Binding { client, state, expires })
    }

    pub fn of(binding: &DHCPv4Binding) -> FFIDHCPv4Binding {
        FFIDHCPv4Binding {
            state: match binding.state {
                DHCPv4BindingState::Offered => 0,
                DHCPv4BindingState::Bound => 1,
                DHCPv4BindingState::Declined => 2,
            },
            expires: binding.expires.map_or(DHCPStatus::INFINITY, |expires| expires.as_nanos()),
        }
    }
}

impl Value for FFIDHCPv4Message {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v4_DHCPv4Message");
}

impl Value for FFIDHCPv4Route {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v4_DHCPv4Route");
}

impl Value for FFIDHCPv4ClientConfig {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v4_DHCPv4ClientConfig");
}

impl Value for FFIDHCPv4Lease {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v4_DHCPv4Lease");
}

impl Value for FFIDHCPv4ClientEvent {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v4_DHCPv4ClientEvent");
}

impl Value for DHCPv4Client {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v4_DHCPv4Client");
}

impl Value for FFIDHCPv4ServerConfig {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v4_DHCPv4ServerConfig");
}

impl Value for FFIDHCPv4Reply {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v4_DHCPv4Reply");
}

impl Value for FFIDHCPv4Binding {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v4_DHCPv4Binding");
}

impl Value for DHCPv4Server {
    const TYPE: Type = Type::Named("umilib_protocol_dhcp_v4_DHCPv4Server");
}

crate::ffi_functions! {
    const MESSAGE;

    /// Reads the message of the `length` bytes at `bytes` (RFC 2131 §2) into `out` and its options area
    /// into `out_options`: the options of the options field, then, as the overload option says, of
    /// `file` and of `sname`, which are then zero (RFC 2131 §4.1); the overload option itself is not
    /// kept. Fails with Malformed for a message shorter than 240 bytes, without the magic cookie, of
    /// an op other than 1 and 2, or with an option cut short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_message_decode(bytes: *const u8, length: usize, out: *mut FFIDHCPv4Message, out_options: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_options, 1)?;
            let message = DHCPv4Message::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, FFIDHCPv4Message::of(&message)) }?;
            unsafe { Pointer::write(out_options, Buffer::from_vec(FFIDHCPv4Message::area(&message.options))) }
        })())
    }

    /// Writes the message of the header at `message` and the options area of `length` bytes at
    /// `options` into `out`: the options after the magic cookie, each once, then END, padded to at
    /// least 300 bytes (RFC 1542 §2.1). Fails with Malformed for an option cut short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_message_encode(message: *const FFIDHCPv4Message, options: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, readable bytes and a writable buffer.
            let message = unsafe { Pointer::reference(message) }?;
            let options = FFIDHCPv4Message::options(unsafe { Pointer::slice(options, length) }?)?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out, Buffer::from_vec(message.with(options).encode())) }
        })())
    }

    /// Writes the key a server knows the client of the message at `message` and the options area at
    /// `options` by into `out`: its client identifier, or 0, its hardware type and its hardware
    /// address (RFC 2131 §4.2, RFC 4361 §6.1). Fails with Malformed for an option cut short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_message_client_key(message: *const FFIDHCPv4Message, options: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, readable bytes and a writable buffer.
            let message = unsafe { Pointer::reference(message) }?;
            let options = FFIDHCPv4Message::options(unsafe { Pointer::slice(options, length) }?)?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out, Buffer::from_vec(message.with(options).client_key())) }
        })())
    }

    /// Writes the options of the options area of `length` bytes at `area` (RFC 2132 §2) as an options
    /// area of this module into `out`: PAD dropped, the parts of an option given in several joined
    /// (RFC 3396 §7). Fails with Malformed for an option cut short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_options_decode(area: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let options = FFIDHCPv4Message::options(unsafe { Pointer::slice(area, length) }?)?;
            unsafe { Pointer::write(out, Buffer::from_vec(FFIDHCPv4Message::area(&options))) }
        })())
    }

    /// Writes the routes of the classless static route option (RFC 3442 §2) of the options area of
    /// `length` bytes at `area` into the `capacity` structures at `out`, and their number into
    /// `out_count`; there are at most `length / 5`. Fails with Malformed for an option cut short or a
    /// route of a prefix longer than 32, and with InvalidArgument if `capacity` is less than their number.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_options_routes(area: *const u8, length: usize, out: *mut FFIDHCPv4Route, capacity: usize, out_count: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(area, length)],
                &[Pointer::range(out, capacity), Pointer::range(out_count, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable structures.
            let options = FFIDHCPv4Message::options(unsafe { Pointer::slice(area, length) }?)?;
            Pointer::check_range(out_count, 1)?;
            let routes = options.routes().map_err(|error| error.to_status())?;
            if routes.len() > capacity {
                return Err(&Status::INVALID_ARGUMENT);
            }
            let out = unsafe { Pointer::slice_of_mut(out, routes.len()) }?;
            for (slot, route) in out.iter_mut().zip(&routes) {
                *slot = FFIDHCPv4Route::of(route);
            }
            unsafe { Pointer::write(out_count, routes.len()) }
        })())
    }

    /// Writes the options area of `length` bytes at `area` with its classless static route option set
    /// to the `count` routes at `routes` (RFC 3442 §2: the bits of a destination beyond its prefix are
    /// not sent) into `out`. Fails with Malformed for an option cut short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_options_set_routes(area: *const u8, length: usize, routes: *const FFIDHCPv4Route, count: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and structures and a writable buffer.
            let mut options = FFIDHCPv4Message::options(unsafe { Pointer::slice(area, length) }?)?;
            let routes: Vec<DHCPv4Route> = unsafe { Pointer::slice_of(routes, count) }?.iter().map(FFIDHCPv4Route::route).collect();
            Pointer::check_range(out, 1)?;
            options.set_routes(&routes);
            unsafe { Pointer::write(out, Buffer::from_vec(FFIDHCPv4Message::area(&options))) }
        })())
    }
}

crate::ffi_functions! {
    const CLIENT;

    /// Writes a client of the configuration at `config` into `out`: known by the client identifier of
    /// `client_identifier_length` bytes at `client_identifier` (option 61; by its hardware address if
    /// null), naming itself by the host name at `host_name` (none if null), asking for the `count`
    /// option codes at `parameters` (RFC 2132 §9.8); `now` is in nanoseconds.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_new(config: *const FFIDHCPv4ClientConfig, client_identifier: *const u8, client_identifier_length: usize, host_name: *const u8, host_name_length: usize, parameters: *const u8, count: usize, now: u64, out: *mut *mut DHCPv4Client) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, readable bytes and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            let client_identifier = unsafe { DHCPStatus::optional(client_identifier, client_identifier_length) }?;
            let host_name = unsafe { DHCPStatus::optional(host_name, host_name_length) }?;
            let parameters = unsafe { Pointer::slice(parameters, count) }?;
            Pointer::check_range(out, 1)?;
            let client = DHCPv4Client::new(config.config(client_identifier, host_name, parameters), Instant::from_nanos(now));
            unsafe { Pointer::write_handle(out, client) }
        })())
    }

    /// Releases a client. Does nothing if `client` is null.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_free(client: *mut DHCPv4Client) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(client) }
    }

    /// Starts the client at `now`: asking again for the address at `previous` it had (INIT-REBOOT,
    /// RFC 2131 §3.2), or discovering servers if `previous` is null; its xid and the jitter of its
    /// retransmission are drawn from `random`. Fails with Random if `random` fails.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_start(client: *mut DHCPv4Client, previous: *const IPv4Address, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, a valid address or null, and readable text.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let previous = unsafe { Pointer::optional_reference(previous) }?.copied();
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            client.start(previous, Instant::from_nanos(now), &mut random).map_err(|error| error.to_status())
        })())
    }

    /// Takes the server's message of `length` bytes at `bytes`, received at `now`; one that is not a
    /// reply to the client's exchange, of its hardware address and client identifier (RFC 6842 §3),
    /// of a type its state expects, is ignored. A new exchange draws from `random`.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_receive(client: *mut DHCPv4Client, bytes: *const u8, length: usize, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, readable bytes and readable text.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            client.receive(bytes, Instant::from_nanos(now), &mut random);
            Ok(())
        })())
    }

    /// Writes whether a message is due into `out_found`, its destination (255.255.255.255 to
    /// broadcast) into `out_destination` and its bytes into `out`; it goes to port 67.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_transmit(client: *mut DHCPv4Client, out_found: *mut bool, out_destination: *mut IPv4Address, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out_destination, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference_mut(client) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_destination, 1)?;
            Pointer::check_range(out, 1)?;
            let transmission = client.transmit();
            unsafe { Pointer::write(out_found, transmission.is_some()) }?;
            match transmission {
                Some(transmission) => unsafe { FFIDHCPv4Transmission::write(&transmission, out_destination, out) },
                None => unsafe { Pointer::write(out, Buffer::EMPTY) },
            }
        })())
    }

    /// Writes whether a timer is set into `out_found` and when umilib_protocol_dhcp_v4_dhcpv4_client_expire
    /// is due (nanoseconds) into `out`.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_poll_timeout(client: *const DHCPv4Client, out_found: *mut bool, out: *mut u64) -> *const Status {
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

    /// Does what is due at `now`: a retransmission, giving up an exchange, or the next step of the
    /// lease — RENEWING at T1, REBINDING at T2, and its end (RFC 2131 §4.4.5); drawing from `random`.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_expire(client: *mut DHCPv4Client, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable text.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            client.expire(Instant::from_nanos(now), &mut random);
            Ok(())
        })())
    }

    /// Writes whether an event is pending into `out_found`, the event into `out`, and the options area
    /// of the ACK of a Bound event (empty for another) into `out_options`.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_poll_event(client: *mut DHCPv4Client, out_found: *mut bool, out: *mut FFIDHCPv4ClientEvent, out_options: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference_mut(client) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_options, 1)?;
            let event = client.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let (structure, options) = event.as_ref().map(FFIDHCPv4ClientEvent::of).unwrap_or_default();
            unsafe { Pointer::write(out, structure) }?;
            unsafe { Pointer::write(out_options, Buffer::from_vec(options)) }
        })())
    }

    /// Writes the number of the client's state into `out`: 0 Init, 1 Selecting, 2 Requesting, 3
    /// Rebooting, 4 Bound, 5 Renewing, 6 Rebinding (RFC 2131 §4.4, figure 5).
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_state(client: *const DHCPv4Client, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let client = unsafe { Pointer::reference(client) }?;
            unsafe { Pointer::write(out, FFIDHCPv4ClientState::of(client.state)) }
        })())
    }

    /// Writes whether the client holds a lease into `out_found`, the lease into `out`, and the options
    /// area of its ACK into `out_options`.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_lease(client: *const DHCPv4Client, out_found: *mut bool, out: *mut FFIDHCPv4Lease, out_options: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let client = unsafe { Pointer::reference(client) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_options, 1)?;
            let lease = client.lease.as_ref();
            unsafe { Pointer::write(out_found, lease.is_some()) }?;
            let (structure, options) = lease.map(FFIDHCPv4Lease::of).unwrap_or_default();
            unsafe { Pointer::write(out, structure) }?;
            unsafe { Pointer::write(out_options, Buffer::from_vec(options)) }
        })())
    }

    /// Declines the address of the lease, which another host has (RFC 2131 §4.4.1): a DECLINE, then
    /// discovery again after ten seconds (§3.1.5), of an xid from `random`. Fails with State without a
    /// lease, and with Random if `random` fails.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_decline(client: *mut DHCPv4Client, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable text.
            let client = unsafe { Pointer::reference_mut(client) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            client.decline(Instant::from_nanos(now), &mut random).map_err(|error| error.to_status())
        })())
    }

    /// Gives the address back (RFC 2131 §4.4.6): a RELEASE to the server; the client stops. Fails with
    /// State without a lease.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_release(client: *mut DHCPv4Client, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let client = unsafe { Pointer::reference_mut(client) }?;
            client.release(Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Writes the DHCPINFORM of a client whose address `address` is configured otherwise (RFC 2131
    /// §3.4), of an xid of its own from `random` and secs 0: its destination into `out_destination`
    /// and its bytes into `out`. The client's exchange goes on; the ACK, of that xid, is the caller's
    /// to read. Fails with Random if `random` fails.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_client_inform(client: *const DHCPv4Client, address: IPv4Address, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize, out_destination: *mut IPv4Address, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(random_type, random_type_length)],
                &[Pointer::range(out_destination, 1)],
            )?;
            // SAFETY: the caller passes valid handles, readable text and writable pointers.
            let client = unsafe { Pointer::reference(client) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            Pointer::check_range(out_destination, 1)?;
            Pointer::check_range(out, 1)?;
            let transmission = client.inform(address, Instant::from_nanos(now), &mut random).map_err(|error| error.to_status())?;
            unsafe { FFIDHCPv4Transmission::write(&transmission, out_destination, out) }
        })())
    }
}

crate::ffi_functions! {
    const SERVER;

    /// Writes the configuration of a server at `address` leasing `first` to `last` into `out`: for a
    /// day, an offer kept a minute, a declined address an hour, not authoritative; with no
    /// reservations and no options.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_server_config_new(address: IPv4Address, first: IPv4Address, last: IPv4Address, out: *mut FFIDHCPv4ServerConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFIDHCPv4ServerConfig::of(&DHCPv4ServerConfig::new(address, first, last))) })
    }

    /// Writes a server of the configuration at `config` into `out`: with `count` reservations, each
    /// the client key of `key_lengths[index]` bytes at `keys[index]` (see
    /// umilib_protocol_dhcp_v4_dhcpv4_message_client_key) and the address at `addresses[index]`, and
    /// the options area of `length` bytes at `options`, given to every client, those it asks for
    /// first. Fails with Config for a pool whose first address is after its last, and with Malformed
    /// for an option cut short.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_server_new(config: *const FFIDHCPv4ServerConfig, keys: *const *const u8, key_lengths: *const usize, addresses: *const IPv4Address, count: usize, options: *const u8, length: usize, out: *mut *mut DHCPv4Server) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, readable arrays and bytes, and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            let keys = unsafe { Pointer::slices(keys, key_lengths, count) }?;
            let addresses = unsafe { Pointer::slice_of(addresses, count) }?;
            let options = FFIDHCPv4Message::options(unsafe { Pointer::slice(options, length) }?)?;
            Pointer::check_range(out, 1)?;
            let reservations = keys.iter().zip(addresses).map(|(key, address)| (key.to_vec(), *address)).collect();
            let server = DHCPv4Server::new(config.config(reservations, options)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, server) }
        })())
    }

    /// Releases a server. Does nothing if `server` is null.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_server_free(server: *mut DHCPv4Server) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(server) }
    }

    /// Takes the client's message of `length` bytes at `bytes`, received at `now` (nanoseconds); writes
    /// whether a reply is due into `out_found`, where it goes into `out_reply` and its bytes into `out`
    /// (RFC 2131 §4.3).
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_server_receive(server: *mut DHCPv4Server, bytes: *const u8, length: usize, now: u64, out_found: *mut bool, out_reply: *mut FFIDHCPv4Reply, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(bytes, length)],
                &[Pointer::range(out_found, 1), Pointer::range(out_reply, 1)],
            )?;
            // SAFETY: the caller passes a valid handle, readable bytes and writable pointers.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_reply, 1)?;
            Pointer::check_range(out, 1)?;
            let reply = server.receive(bytes, Instant::from_nanos(now));
            unsafe { Pointer::write(out_found, reply.is_some()) }?;
            unsafe { Pointer::write(out_reply, reply.as_ref().map(FFIDHCPv4Reply::of).unwrap_or_default()) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(reply.map(|reply| reply.message.encode()).unwrap_or_default())) }
        })())
    }

    /// Forgets the bindings expired at `now`, but the leases bound.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_server_expire(server: *mut DHCPv4Server, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let server = unsafe { Pointer::reference_mut(server) }?;
            server.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the server has a binding of `address` into `out_found`, the binding into `out`
    /// and the key of its client (empty for a declined address) into `out_client`.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_server_binding(server: *const DHCPv4Server, address: IPv4Address, out_found: *mut bool, out: *mut FFIDHCPv4Binding, out_client: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_client, 1)?;
            let binding = server.bindings.get(&address);
            unsafe { Pointer::write(out_found, binding.is_some()) }?;
            unsafe { Pointer::write(out, binding.map(FFIDHCPv4Binding::of).unwrap_or_default()) }?;
            unsafe { Pointer::write(out_client, Buffer::from_vec(binding.map(|binding| binding.client.clone()).unwrap_or_default())) }
        })())
    }

    /// Writes how many bindings the server has into `out`.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_server_bindings_count(server: *const DHCPv4Server, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.bindings.len()) }
        })())
    }

    /// Writes the binding of `index`, in the order of addresses, into `out_address`, `out` and
    /// `out_client`; fails with InvalidArgument for an index past the last.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_server_binding_entry(server: *const DHCPv4Server, index: usize, out_address: *mut IPv4Address, out: *mut FFIDHCPv4Binding, out_client: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_address, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let server = unsafe { Pointer::reference(server) }?;
            Pointer::check_range(out_address, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_client, 1)?;
            let (address, binding) = server.bindings.iter().nth(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out_address, *address) }?;
            unsafe { Pointer::write(out, FFIDHCPv4Binding::of(binding)) }?;
            unsafe { Pointer::write(out_client, Buffer::from_vec(binding.client.clone())) }
        })())
    }

    /// Sets the binding of `address` to `binding`, of the client of the key of the `length` bytes at
    /// `client`: a binding kept elsewhere, given back (a server's bindings are its caller's to keep).
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_server_set_binding(server: *mut DHCPv4Server, address: IPv4Address, binding: FFIDHCPv4Binding, client: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let client = unsafe { Pointer::slice(client, length) }?.to_vec();
            server.bindings.insert(address, binding.binding(client)?);
            Ok(())
        })())
    }

    /// Removes the binding of `address`, if any.
    pub unsafe extern "C" fn umilib_protocol_dhcp_v4_dhcpv4_server_remove_binding(server: *mut DHCPv4Server, address: IPv4Address) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(server) }?.bindings.remove(&address);
            Ok(())
        })())
    }
}

/// The functions of this module, in declaration order.
pub const FUNCTIONS: &[Function] =
    &Function::concat::<{ MESSAGE.len() + CLIENT.len() + SERVER.len() }>(&[MESSAGE, CLIENT, SERVER]);

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v4",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_dhcp_v4_DHCPv4Message",
            documentation: " The header of a DHCPv4 message (RFC 2131 §2), its fields as they are; the options are beside it.",
            fields: &[
                Parameter { name: "op", value: <u8 as Value>::TYPE },
                Parameter { name: "hardware_type", value: <u8 as Value>::TYPE },
                Parameter { name: "hardware_length", value: <u8 as Value>::TYPE },
                Parameter { name: "hops", value: <u8 as Value>::TYPE },
                Parameter { name: "xid", value: <u32 as Value>::TYPE },
                Parameter { name: "secs", value: <u16 as Value>::TYPE },
                Parameter { name: "flags", value: <u16 as Value>::TYPE },
                Parameter { name: "ciaddr", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "yiaddr", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "siaddr", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "giaddr", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "chaddr", value: <[u8; 16] as Value>::TYPE },
                Parameter { name: "sname", value: <[u8; 64] as Value>::TYPE },
                Parameter { name: "file", value: <[u8; 128] as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v4_DHCPv4Route",
            documentation: " A route of the classless static route option (RFC 3442 §2).",
            fields: &[
                Parameter { name: "destination", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "prefix", value: <u8 as Value>::TYPE },
                Parameter { name: "router", value: <IPv4Address as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v4_DHCPv4ClientConfig",
            documentation: " How a DHCPv4 client asks, but its client identifier, host name and option codes.",
            fields: &[
                Parameter { name: "hardware", value: <MACAddress as Value>::TYPE },
                Parameter { name: "broadcast", value: <bool as Value>::TYPE },
                Parameter { name: "ipv6_only", value: <bool as Value>::TYPE },
                Parameter { name: "maximum_message_size", value: <u16 as Value>::TYPE },
                Parameter { name: "retransmissions", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v4_DHCPv4Lease",
            documentation: " An address leased: durations in milliseconds (UINT64_MAX for infinity), acquired in nanoseconds.",
            fields: &[
                Parameter { name: "address", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "server", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "lease", value: <u64 as Value>::TYPE },
                Parameter { name: "renewal", value: <u64 as Value>::TYPE },
                Parameter { name: "rebinding", value: <u64 as Value>::TYPE },
                Parameter { name: "acquired", value: <u64 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v4_DHCPv4ClientEvent",
            documentation: " What a DHCPv4 client tells: kind 0 Bound (with its lease), 1 Refused, 2 Expired, 3 Unanswered,\n \
                            4 IPv6Only (for wait milliseconds).",
            fields: &[
                Parameter { name: "kind", value: <u8 as Value>::TYPE },
                Parameter { name: "lease", value: <FFIDHCPv4Lease as Value>::TYPE },
                Parameter { name: "wait", value: <u64 as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_dhcp_v4_DHCPv4Client",
            documentation: " A DHCPv4 client without I/O (RFC 2131 §4.4).",
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v4_DHCPv4ServerConfig",
            documentation: " What a DHCPv4 server leases, but its reservations and options: durations in milliseconds,\n \
                            a lease of UINT64_MAX for ever.",
            fields: &[
                Parameter { name: "address", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "first", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "last", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "authoritative", value: <bool as Value>::TYPE },
                Parameter { name: "lease", value: <u64 as Value>::TYPE },
                Parameter { name: "offer_time", value: <u64 as Value>::TYPE },
                Parameter { name: "decline_time", value: <u64 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v4_DHCPv4Reply",
            documentation: " Where a DHCPv4 server's reply goes: to link without ARP if has_link (RFC 2131 §4.1).",
            fields: &[
                Parameter { name: "destination", value: <IPv4Address as Value>::TYPE },
                Parameter { name: "port", value: <u16 as Value>::TYPE },
                Parameter { name: "link", value: <MACAddress as Value>::TYPE },
                Parameter { name: "has_link", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dhcp_v4_DHCPv4Binding",
            documentation: " An address a DHCPv4 server gave: state 0 Offered, 1 Bound, 2 Declined; until expires\n \
                            (nanoseconds, UINT64_MAX for never).",
            fields: &[
                Parameter { name: "state", value: <u8 as Value>::TYPE },
                Parameter { name: "expires", value: <u64 as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_dhcp_v4_DHCPv4Server",
            documentation: " A DHCPv4 server without I/O (RFC 2131 §4.3) and its bindings.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
