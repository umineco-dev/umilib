//! The C ABI of [`crate::protocol::dns`].
//!
//! Names and records cross as their presentation format (RFC 1035 §5.1),
//! records one a line as a zone file has them. A message, an authoritative
//! server and a resolver are handles; a header, an EDNS, a configuration
//! and a resolver's transmission and event are structures. A transport is
//! a number: 0 UDP, 1 TCP, 2 TLS, 3 HTTPS, 4 QUIC. Times are nanoseconds
//! of the caller's monotonic clock (`now`) and, for cookies, seconds since
//! 1970 (`time`). A function that needs randomness takes a generator of
//! `crypto::random` (a handle and the C name of its type, `random_type`),
//! as the functions that generate keys take it.

#[cfg(umilib_feature = "protocol-dns-dnssec")]
pub mod dnssec;
#[cfg(umilib_feature = "protocol-dns-https")]
pub mod https;
#[cfg(umilib_feature = "protocol-dns-quic")]
pub mod quic;
#[cfg(umilib_feature = "protocol-dns-tcp")]
pub mod tcp;
#[cfg(umilib_feature = "protocol-dns-tls")]
pub mod tls;
#[cfg(umilib_feature = "protocol-dns-udp")]
pub mod udp;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::fmt::Write;
use core::time::Duration;

use crate::ffi::crypto::random::RandomSource;
use crate::ffi::protocol::ip::{FFIIPEndpoint, FFIIPEndpointPattern};
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::dns::{
    DNSAuthority, DNSAuthorityConfig, DNSCacheConfig, DNSClass, DNSEDNS, DNSError, DNSHeader, DNSMessage, DNSName,
    DNSOpcode, DNSOption, DNSOptionCode, DNSPeer, DNSQuestion, DNSRecord, DNSResolver, DNSResolverConfig,
    DNSResolverEvent, DNSResponseCode, DNSTransport, DNSType, DNSUpstream, DNSZone, DNSZoneFile,
};
use crate::runtime::Instant;

/// The statuses of this module, one per variant of [`DNSError`].
pub struct DNSStatus;

impl DNSStatus {
    pub const MALFORMED: Status = Status::new(c"protocol.dns", c"Malformed", c"not a DNS message, record or name");
    pub const SYNTAX: Status = Status::new(c"protocol.dns", c"Syntax", c"not of the presentation format of DNS");
    pub const TOO_LARGE: Status = Status::new(c"protocol.dns", c"TooLarge", c"a DNS message or name too large");
    pub const STATE: Status = Status::new(c"protocol.dns", c"State", c"not possible in this state");
    pub const CONFIG: Status = Status::new(c"protocol.dns", c"Config", c"a DNS configuration that cannot work");
    pub const BOGUS: Status = Status::new(c"protocol.dns", c"Bogus", c"a response that cannot be trusted");
    pub const TIMEOUT: Status = Status::new(c"protocol.dns", c"Timeout", c"no DNS server answered in time");
    /// The transport of its number.
    pub fn transport(number: u8) -> Result<DNSTransport, &'static Status> {
        Ok(match number {
            0 => DNSTransport::UDP,
            1 => DNSTransport::TCP,
            2 => DNSTransport::TLS,
            3 => DNSTransport::HTTPS,
            4 => DNSTransport::QUIC,
            _ => return Err(&Status::INVALID_ARGUMENT),
        })
    }

    pub fn transport_number(transport: DNSTransport) -> u8 {
        match transport {
            DNSTransport::UDP => 0,
            DNSTransport::TCP => 1,
            DNSTransport::TLS => 2,
            DNSTransport::HTTPS => 3,
            DNSTransport::QUIC => 4,
        }
    }

    /// The name of the `length` bytes of text at `text`.
    ///
    /// # Safety
    /// As [`Pointer::text`].
    pub unsafe fn name(text: *const u8, length: usize) -> Result<DNSName, &'static Status> {
        // SAFETY: the caller's promise.
        let text = unsafe { Pointer::text(text, length) }?;
        DNSName::parse(text, None).map_err(|error| error.to_status())
    }

    /// The records of the zone-file text `text`, of no origin and the TTL 0 for those without one.
    pub fn records(text: &str) -> Result<Vec<DNSRecord>, &'static Status> {
        DNSZoneFile { origin: None, default_ttl: Some(0) }.parse(text).map_err(|error| error.error.to_status())
    }

    /// The records one a line.
    pub fn lines(records: &[DNSRecord]) -> String {
        let mut text = String::new();
        for record in records {
            let _ = writeln!(text, "{record}");
        }
        text
    }
}

impl ToStatus for DNSError {
    fn to_status(&self) -> &'static Status {
        match self {
            DNSError::Malformed(_) => &DNSStatus::MALFORMED,
            DNSError::Syntax(_) => &DNSStatus::SYNTAX,
            DNSError::TooLarge(_) => &DNSStatus::TOO_LARGE,
            DNSError::State => &DNSStatus::STATE,
            DNSError::Config => &DNSStatus::CONFIG,
            DNSError::Bogus { .. } => &DNSStatus::BOGUS,
            DNSError::Timeout => &DNSStatus::TIMEOUT,
        }
    }
}

/// A [`DNSHeader`], the response code whole (with its EDNS bits).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDNSHeader {
    pub id: u16,
    pub response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authentic_data: bool,
    pub checking_disabled: bool,
    pub rcode: u16,
}

impl FFIDNSHeader {
    pub fn of(message: &DNSMessage) -> FFIDNSHeader {
        let header = &message.header;
        FFIDNSHeader {
            id: header.id,
            response: header.response,
            opcode: header.opcode.0,
            authoritative: header.authoritative,
            truncated: header.truncated,
            recursion_desired: header.recursion_desired,
            recursion_available: header.recursion_available,
            authentic_data: header.authentic_data,
            checking_disabled: header.checking_disabled,
            rcode: message.rcode().0,
        }
    }

    /// Sets the header of `message`; a response code above 15 adds EDNS.
    pub fn apply(&self, message: &mut DNSMessage) {
        message.header = DNSHeader {
            id: self.id,
            response: self.response,
            opcode: DNSOpcode(self.opcode),
            authoritative: self.authoritative,
            truncated: self.truncated,
            recursion_desired: self.recursion_desired,
            recursion_available: self.recursion_available,
            authentic_data: self.authentic_data,
            checking_disabled: self.checking_disabled,
            ..message.header
        };
        message.set_rcode(DNSResponseCode(self.rcode));
    }
}

/// The EDNS of a message (RFC 6891 §6.1), if `present`; its options are reached by code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDNSEDNS {
    pub present: bool,
    pub udp_size: u16,
    pub version: u8,
    pub dnssec_ok: bool,
}

/// A [`DNSAuthorityConfig`], its durations in milliseconds (0: none).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDNSAuthorityConfig {
    pub minimal: bool,
    pub udp_size: u16,
    pub maximum_chain: u32,
    pub padding: u32,
    pub transfer_size: u32,
    pub keepalive: u32,
}

impl FFIDNSAuthorityConfig {
    pub fn of(config: &DNSAuthorityConfig) -> FFIDNSAuthorityConfig {
        FFIDNSAuthorityConfig {
            minimal: config.minimal,
            udp_size: config.udp_size,
            maximum_chain: config.maximum_chain as u32,
            padding: config.padding as u32,
            transfer_size: config.transfer_size as u32,
            keepalive: config.keepalive.map_or(0, |keepalive| keepalive.as_millis() as u32),
        }
    }

    pub fn config(&self) -> DNSAuthorityConfig {
        DNSAuthorityConfig {
            minimal: self.minimal,
            udp_size: self.udp_size,
            maximum_chain: self.maximum_chain as usize,
            padding: self.padding as usize,
            transfer_size: self.transfer_size as usize,
            keepalive: (self.keepalive != 0).then(|| Duration::from_millis(u64::from(self.keepalive))),
            ..DNSAuthorityConfig::default()
        }
    }
}

/// A [`DNSResolverConfig`] but its servers, its durations in milliseconds
/// and the cache's TTLs in seconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDNSResolverConfig {
    pub timeout: u32,
    pub maximum_timeout: u32,
    pub rounds: u32,
    pub edns: bool,
    pub udp_size: u16,
    pub recursion_desired: bool,
    pub dnssec_ok: bool,
    pub checking_disabled: bool,
    pub cookies: bool,
    pub padding: u32,
    pub maximum_queries: u32,
    pub cache_entries: u32,
    pub cache_maximum_ttl: u32,
    pub cache_minimum_ttl: u32,
    pub cache_maximum_negative_ttl: u32,
    pub cache_failure_ttl: u32,
}

impl FFIDNSResolverConfig {
    pub fn of(config: &DNSResolverConfig) -> FFIDNSResolverConfig {
        let cache = &config.cache;
        FFIDNSResolverConfig {
            timeout: config.timeout.as_millis() as u32,
            maximum_timeout: config.maximum_timeout.as_millis() as u32,
            rounds: config.rounds as u32,
            edns: config.edns,
            udp_size: config.udp_size,
            recursion_desired: config.recursion_desired,
            dnssec_ok: config.dnssec_ok,
            checking_disabled: config.checking_disabled,
            cookies: config.cookies,
            padding: config.padding as u32,
            maximum_queries: config.maximum_queries as u32,
            cache_entries: cache.maximum_entries as u32,
            cache_maximum_ttl: cache.maximum_ttl.as_secs() as u32,
            cache_minimum_ttl: cache.minimum_ttl.as_secs() as u32,
            cache_maximum_negative_ttl: cache.maximum_negative_ttl.as_secs() as u32,
            cache_failure_ttl: cache.failure_ttl.as_secs() as u32,
        }
    }

    /// The configuration of these values and `upstreams`.
    pub fn config(&self, upstreams: Vec<DNSUpstream>) -> DNSResolverConfig {
        let seconds = |value: u32| Duration::from_secs(u64::from(value));
        DNSResolverConfig {
            upstreams,
            timeout: Duration::from_millis(u64::from(self.timeout)),
            maximum_timeout: Duration::from_millis(u64::from(self.maximum_timeout)),
            rounds: self.rounds as usize,
            edns: self.edns,
            udp_size: self.udp_size,
            recursion_desired: self.recursion_desired,
            dnssec_ok: self.dnssec_ok,
            checking_disabled: self.checking_disabled,
            cookies: self.cookies,
            padding: self.padding as usize,
            cache: DNSCacheConfig {
                maximum_entries: self.cache_entries as usize,
                maximum_ttl: seconds(self.cache_maximum_ttl),
                minimum_ttl: seconds(self.cache_minimum_ttl),
                maximum_negative_ttl: seconds(self.cache_maximum_negative_ttl),
                failure_ttl: seconds(self.cache_failure_ttl),
            },
            maximum_queries: self.maximum_queries as usize,
        }
    }
}

/// A server of a resolver: its endpoint and transport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDNSUpstream {
    pub endpoint: FFIIPEndpoint,
    pub transport: u8,
}

impl FFIDNSUpstream {
    /// The servers of the `count` structures at `upstreams`.
    ///
    /// # Safety
    /// As [`Pointer::slice_of`].
    pub unsafe fn list(upstreams: *const FFIDNSUpstream, count: usize) -> Result<Vec<DNSUpstream>, &'static Status> {
        // SAFETY: the caller's promise.
        let upstreams = unsafe { Pointer::slice_of(upstreams, count) }?;
        upstreams
            .iter()
            .map(|upstream| {
                Ok(DNSUpstream {
                    endpoint: upstream.endpoint.endpoint()?,
                    transport: DNSStatus::transport(upstream.transport)?,
                    name: None,
                })
            })
            .collect()
    }
}

/// A query a resolver sends: of which query, to which server, over which transport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDNSTransmission {
    pub query: u64,
    pub upstream: u32,
    pub transport: u8,
}

impl Value for FFIDNSHeader {
    const TYPE: Type = Type::Named("umilib_protocol_dns_DNSHeader");
}

impl Value for FFIDNSEDNS {
    const TYPE: Type = Type::Named("umilib_protocol_dns_DNSEDNS");
}

impl Value for FFIDNSAuthorityConfig {
    const TYPE: Type = Type::Named("umilib_protocol_dns_DNSAuthorityConfig");
}

impl Value for FFIDNSResolverConfig {
    const TYPE: Type = Type::Named("umilib_protocol_dns_DNSResolverConfig");
}

impl Value for FFIDNSUpstream {
    const TYPE: Type = Type::Named("umilib_protocol_dns_DNSUpstream");
}

impl Value for FFIDNSTransmission {
    const TYPE: Type = Type::Named("umilib_protocol_dns_DNSTransmission");
}

impl Value for DNSMessage {
    const TYPE: Type = Type::Named("umilib_protocol_dns_DNSMessage");
}

impl Value for DNSAuthority {
    const TYPE: Type = Type::Named("umilib_protocol_dns_DNSAuthority");
}

impl Value for DNSResolver {
    const TYPE: Type = Type::Named("umilib_protocol_dns_DNSResolver");
}

crate::ffi_functions! {
    /// Writes a query of `id` for the name of the `length` bytes of text at `name`, of the type
    /// `kind` and the class `record_class`, with recursion desired, into `out`; fails with Syntax for a
    /// name that is not one.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_query(name: *const u8, length: usize, kind: u16, record_class: u16, id: u16, out: *mut *mut DNSMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let name = unsafe { DNSStatus::name(name, length) }?;
            let question = DNSQuestion { name, kind: DNSType(kind), class: DNSClass(record_class) };
            unsafe { Pointer::write_handle(out, DNSMessage::query(id, question)) }
        })())
    }

    /// Reads the message of the `length` bytes at `bytes` into `out`; fails with Malformed.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_decode(bytes: *const u8, length: usize, out: *mut *mut DNSMessage) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let message = DNSMessage::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, message) }
        })())
    }

    /// Releases a message. Does nothing if `message` is null.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_free(message: *mut DNSMessage) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(message) }
    }

    /// Writes the message in at most `limit` bytes, whole RRsets left out from the end (RFC 2181
    /// §9), into `out`; fails with TooLarge if not even the question fits.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_encode(message: *const DNSMessage, limit: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            let bytes = message.encode(limit).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// Writes the header into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_header(message: *const DNSMessage, out: *mut FFIDNSHeader) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            unsafe { Pointer::write(out, FFIDNSHeader::of(message)) }
        })())
    }

    /// Sets the header to `header`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_set_header(message: *mut DNSMessage, header: FFIDNSHeader) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let message = unsafe { Pointer::reference_mut(message) }?;
            header.apply(message);
            Ok(())
        })())
    }

    /// Writes the EDNS into `out`, `present` false without one.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_edns(message: *const DNSMessage, out: *mut FFIDNSEDNS) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            let edns = message.edns.as_ref().map_or_else(FFIDNSEDNS::default, |edns| FFIDNSEDNS {
                present: true,
                udp_size: edns.udp_size,
                version: edns.version,
                dnssec_ok: edns.dnssec_ok,
            });
            unsafe { Pointer::write(out, edns) }
        })())
    }

    /// Sets the EDNS to `edns` (its options kept), or removes it if not `present`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_set_edns(message: *mut DNSMessage, edns: FFIDNSEDNS) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let message = unsafe { Pointer::reference_mut(message) }?;
            if !edns.present {
                message.edns = None;
                return Ok(());
            }
            let current = message.edns.get_or_insert_with(DNSEDNS::default);
            current.udp_size = edns.udp_size;
            current.version = edns.version;
            current.dnssec_ok = edns.dnssec_ok;
            Ok(())
        })())
    }

    /// Writes whether the EDNS has an option of `code` into `out_found`, and its data into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_option(message: *const DNSMessage, code: u16, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let message = unsafe { Pointer::reference(message) }?;
            Pointer::check_range(out, 1)?;
            let data = message.edns.as_ref().and_then(|edns| edns.option(DNSOptionCode(code)));
            unsafe { Pointer::write(out_found, data.is_some()) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(data.unwrap_or_default().to_vec())) }
        })())
    }

    /// Sets the option of `code` to the `length` bytes at `data`, the only one of it; adds EDNS if there is none.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_set_option(message: *mut DNSMessage, code: u16, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let message = unsafe { Pointer::reference_mut(message) }?;
            let data = unsafe { Pointer::slice(data, length) }?.to_vec();
            message.edns.get_or_insert_with(DNSEDNS::default).set_option(DNSOption { code: DNSOptionCode(code), data });
            Ok(())
        })())
    }

    /// Writes whether the message has a question into `out_found`, its name (text) into
    /// `out_name`, its type into `out_kind` and its class into `out_class`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_question(message: *const DNSMessage, out_found: *mut bool, out_name: *mut Buffer, out_kind: *mut u16, out_class: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[Pointer::range(out_found, 1), Pointer::range(out_kind, 1), Pointer::range(out_class, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let message = unsafe { Pointer::reference(message) }?;
            Pointer::check_range(out_name, 1)?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out_class, 1)?;
            let question = message.question();
            unsafe { Pointer::write(out_found, question.is_some()) }?;
            unsafe { Pointer::write_text(out_name, question.map(|question| question.name.to_string()).unwrap_or_default()) }?;
            unsafe { Pointer::write(out_kind, question.map_or(0, |question| question.kind.0)) }?;
            unsafe { Pointer::write(out_class, question.map_or(0, |question| question.class.0)) }
        })())
    }

    /// Writes the records of `section` (0 answer, 1 authority, 2 additional), one a line, into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_records(message: *const DNSMessage, section: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let message = unsafe { Pointer::reference(message) }?;
            let records = match section {
                0 => &message.answers,
                1 => &message.authorities,
                2 => &message.additionals,
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            unsafe { Pointer::write_text(out, DNSStatus::lines(records)) }
        })())
    }

    /// Adds the records of the zone-file text of the `length` bytes at `text` (absolute names, TTL 0
    /// where none is given) to `section` (0 answer, 1 authority, 2 additional); fails with Syntax.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_message_add_records(message: *mut DNSMessage, section: u8, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let message = unsafe { Pointer::reference_mut(message) }?;
            let records = DNSStatus::records(unsafe { Pointer::text(text, length) }?)?;
            let target = match section {
                0 => &mut message.answers,
                1 => &mut message.authorities,
                2 => &mut message.additionals,
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            target.extend(records);
            Ok(())
        })())
    }

    /// Writes the records of the zone file of the `length` bytes at `text`, of the origin of the
    /// `origin_length` bytes at `origin` (none if 0) and the default TTL `ttl` (none if `has_ttl` is
    /// false), one a line with absolute names, into `out`; on Syntax, the line into `out_line`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_zone_file_parse(text: *const u8, length: usize, origin: *const u8, origin_length: usize, has_ttl: bool, ttl: u32, out_line: *mut usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(text, length), Pointer::range(origin, origin_length)],
                &[Pointer::range(out_line, 1)],
            )?;
            // SAFETY: the caller passes readable text and writable pointers.
            let text = unsafe { Pointer::text(text, length) }?;
            Pointer::check_range(out_line, 1)?;
            Pointer::check_range(out, 1)?;
            let origin = match origin_length {
                0 => None,
                _ => Some(unsafe { DNSStatus::name(origin, origin_length) }?),
            };
            let mut file = DNSZoneFile { origin, default_ttl: has_ttl.then_some(ttl) };
            match file.parse(text) {
                Ok(records) => {
                    unsafe { Pointer::write(out_line, 0) }?;
                    unsafe { Pointer::write_text(out, DNSStatus::lines(&records)) }
                }
                Err(error) => {
                    unsafe { Pointer::write(out_line, error.line) }?;
                    Err(error.error.to_status())
                }
            }
        })())
    }

    /// Writes the default configuration of an authoritative server into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_authority_config_default(out: *mut FFIDNSAuthorityConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFIDNSAuthorityConfig::of(&DNSAuthorityConfig::default())) })
    }

    /// Writes an authoritative server of `config` and no zone into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_authority_new(config: FFIDNSAuthorityConfig, out: *mut *mut DNSAuthority) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, DNSAuthority::new(Vec::new(), config.config())) })
    }

    /// Releases a server. Does nothing if `authority` is null.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_authority_free(authority: *mut DNSAuthority) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(authority) }
    }

    /// Adds the zone of the origin of the `origin_length` bytes at `origin` and the records of the
    /// zone-file text of the `length` bytes at `text` (relative names of that origin, the default TTL
    /// the SOA's); fails with Syntax, or Config for a zone without its one SOA at the origin.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_authority_add_zone(authority: *mut DNSAuthority, origin: *const u8, origin_length: usize, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let authority = unsafe { Pointer::reference_mut(authority) }?;
            let origin = unsafe { DNSStatus::name(origin, origin_length) }?;
            let text = unsafe { Pointer::text(text, length) }?;
            let records = DNSZoneFile::new(Some(origin.clone())).parse(text).map_err(|error| error.error.to_status())?;
            let zone = DNSZone::new(origin, records).map_err(|error| error.to_status())?;
            authority.zones.push(zone);
            Ok(())
        })())
    }

    /// Sets the secrets of server cookies (RFC 9018 §5) to the `length` bytes at `secrets`, 16 a
    /// secret, the first the current one; none ignores cookies. Fails with InvalidArgument for a
    /// length that is not a multiple of 16.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_authority_set_cookie_secrets(authority: *mut DNSAuthority, secrets: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable secrets.
            let authority = unsafe { Pointer::reference_mut(authority) }?;
            let (secrets, rest) = unsafe { Pointer::slice(secrets, length) }?.as_chunks::<16>();
            if !rest.is_empty() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            authority.config.cookie_secrets = secrets.to_vec();
            Ok(())
        })())
    }

    /// Sets the clients that may transfer zones (RFC 5936) to the `count` patterns at `patterns`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_authority_set_transfers(authority: *mut DNSAuthority, patterns: *const FFIIPEndpointPattern, count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable patterns.
            let authority = unsafe { Pointer::reference_mut(authority) }?;
            let patterns = unsafe { Pointer::slice_of(patterns, count) }?;
            authority.config.transfers = patterns.iter().map(FFIIPEndpointPattern::pattern).collect::<Result<_, _>>()?;
            Ok(())
        })())
    }

    /// Writes the responses to the query of the `length` bytes at `query` from `peer` over
    /// `transport` at `time` into `out`, each after its length in two bytes (none for a message that
    /// is not answered, several for a zone transfer).
    pub unsafe extern "C" fn umilib_protocol_dns_dns_authority_respond(authority: *const DNSAuthority, query: *const u8, length: usize, peer: FFIIPEndpoint, transport: u8, time: u32, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let authority = unsafe { Pointer::reference(authority) }?;
            let query = unsafe { Pointer::slice(query, length) }?;
            let peer = DNSPeer { endpoint: peer.endpoint()?, transport: DNSStatus::transport(transport)? };
            let mut framed = Vec::new();
            for response in authority.respond(query, &peer, time) {
                framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
                framed.extend_from_slice(&response);
            }
            unsafe { Pointer::write(out, Buffer::from_vec(framed)) }
        })())
    }

    /// Writes the default configuration of a resolver into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_resolver_config_default(out: *mut FFIDNSResolverConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFIDNSResolverConfig::of(&DNSResolverConfig::default())) })
    }

    /// Writes a resolver of `config` and the `count` servers at `upstreams`, its cookie secret
    /// drawn from `random`, into `out`; fails with Config without servers.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_resolver_new(config: FFIDNSResolverConfig, upstreams: *const FFIDNSUpstream, count: usize, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut DNSResolver) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable servers, a live generator and a writable pointer.
            let upstreams = unsafe { FFIDNSUpstream::list(upstreams, count) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let resolver = DNSResolver::new(config.config(upstreams), &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, resolver) }
        })())
    }

    /// Releases a resolver. Does nothing if `resolver` is null.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_resolver_free(resolver: *mut DNSResolver) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(resolver) }
    }

    /// Starts resolving the name of the `length` bytes of text at `name`, of `kind` and
    /// `record_class`, at `now`, its ID drawn from `random`, and writes the query's handle into
    /// `out`; fails with State at the limit of queries.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_resolver_resolve(resolver: *mut DNSResolver, name: *const u8, length: usize, kind: u16, record_class: u16, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(name, length), Pointer::range(random_type, random_type_length)],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes a valid handle, readable text and a writable pointer.
            let resolver = unsafe { Pointer::reference_mut(resolver) }?;
            let name = unsafe { DNSStatus::name(name, length) }?;
            let question = DNSQuestion { name, kind: DNSType(kind), class: DNSClass(record_class) };
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let query = resolver.resolve(question, Instant::from_nanos(now), &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, query) }
        })())
    }

    /// Writes whether a query is to be sent into `out_found`, where into `out`, and its bytes into `out_message`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_resolver_transmit(resolver: *mut DNSResolver, out_found: *mut bool, out: *mut FFIDNSTransmission, out_message: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let resolver = unsafe { Pointer::reference_mut(resolver) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_message, 1)?;
            let transmission = resolver.transmit();
            unsafe { Pointer::write(out_found, transmission.is_some()) }?;
            let (structure, bytes) = transmission.map_or((FFIDNSTransmission::default(), Vec::new()), |transmission| {
                let structure = FFIDNSTransmission {
                    query: transmission.query,
                    upstream: transmission.upstream as u32,
                    transport: DNSStatus::transport_number(transmission.transport),
                };
                (structure, transmission.message)
            });
            unsafe { Pointer::write(out, structure) }?;
            unsafe { Pointer::write(out_message, Buffer::from_vec(bytes)) }
        })())
    }

    /// Takes the response of the `length` bytes at `bytes` from the server `upstream` over
    /// `transport` to the query `query`, at `now`, a query sent again drawing its ID from `random`;
    /// one that does not match its query is ignored.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_resolver_receive(resolver: *mut DNSResolver, query: u64, upstream: u32, transport: u8, bytes: *const u8, length: usize, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let resolver = unsafe { Pointer::reference_mut(resolver) }?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let transport = DNSStatus::transport(transport)?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            resolver.receive(query, upstream as usize, transport, bytes, Instant::from_nanos(now), &mut random);
            Ok(())
        })())
    }

    /// Writes whether a timer is set into `out_found` and when it fires (nanoseconds) into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_resolver_poll_timeout(resolver: *const DNSResolver, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let resolver = unsafe { Pointer::reference(resolver) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let timeout = resolver.poll_timeout();
            unsafe { Pointer::write(out_found, timeout.is_some()) }?;
            unsafe { Pointer::write(out, timeout.map_or(0, Instant::as_nanos)) }
        })())
    }

    /// Sends again, to their next servers, the queries unanswered at `now`, their IDs drawn from `random`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_resolver_expire(resolver: *mut DNSResolver, now: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let resolver = unsafe { Pointer::reference_mut(resolver) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            resolver.expire(Instant::from_nanos(now), &mut random);
            Ok(())
        })())
    }

    /// Stops resolving the query `query`; it is not told.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_resolver_cancel(resolver: *mut DNSResolver, query: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let resolver = unsafe { Pointer::reference_mut(resolver) }?;
            resolver.cancel(query);
            Ok(())
        })())
    }

    /// Writes whether a query is resolved into `out_found`, its handle into `out_query`, the status of
    /// its failure (null for a response) into `out_error`, and the response into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dns_resolver_poll_event(resolver: *mut DNSResolver, out_found: *mut bool, out_query: *mut u64, out_error: *mut *const Status, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[Pointer::range(out_found, 1), Pointer::range(out_query, 1), Pointer::range(out_error, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let resolver = unsafe { Pointer::reference_mut(resolver) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_query, 1)?;
            Pointer::check_range(out_error, 1)?;
            Pointer::check_range(out, 1)?;
            let event = resolver.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let (query, error, bytes) = match event {
                Some(DNSResolverEvent::Resolved { query, result: Ok(response), .. }) => {
                    (query, core::ptr::null(), response.encode(DNSMessage::MAXIMUM_SIZE).unwrap_or_default())
                }
                Some(DNSResolverEvent::Resolved { query, result: Err(error), .. }) => (query, error.to_status() as *const Status, Vec::new()),
                None => (0, core::ptr::null(), Vec::new()),
            };
            unsafe { Pointer::write(out_query, query) }?;
            unsafe { Pointer::write(out_error, error) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "dns",
    definitions: &[
        Definition::Opaque {
            name: "umilib_protocol_dns_DNSMessage", documentation: " A DNS message (RFC 1035 §4.1)."
        },
        Definition::Opaque {
            name: "umilib_protocol_dns_DNSAuthority",
            documentation: " An authoritative name server and its zones.",
        },
        Definition::Opaque { name: "umilib_protocol_dns_DNSResolver", documentation: " A stub resolver." },
        Definition::Structure {
            name: "umilib_protocol_dns_DNSHeader",
            documentation: " The header of a message, the response code whole.",
            fields: &[
                Parameter { name: "id", value: <u16 as Value>::TYPE },
                Parameter { name: "response", value: <bool as Value>::TYPE },
                Parameter { name: "opcode", value: <u8 as Value>::TYPE },
                Parameter { name: "authoritative", value: <bool as Value>::TYPE },
                Parameter { name: "truncated", value: <bool as Value>::TYPE },
                Parameter { name: "recursion_desired", value: <bool as Value>::TYPE },
                Parameter { name: "recursion_available", value: <bool as Value>::TYPE },
                Parameter { name: "authentic_data", value: <bool as Value>::TYPE },
                Parameter { name: "checking_disabled", value: <bool as Value>::TYPE },
                Parameter { name: "rcode", value: <u16 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dns_DNSEDNS",
            documentation: " The EDNS of a message, if present.",
            fields: &[
                Parameter { name: "present", value: <bool as Value>::TYPE },
                Parameter { name: "udp_size", value: <u16 as Value>::TYPE },
                Parameter { name: "version", value: <u8 as Value>::TYPE },
                Parameter { name: "dnssec_ok", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dns_DNSAuthorityConfig",
            documentation: " The configuration of an authoritative server, durations in milliseconds (0: none).",
            fields: &[
                Parameter { name: "minimal", value: <bool as Value>::TYPE },
                Parameter { name: "udp_size", value: <u16 as Value>::TYPE },
                Parameter { name: "maximum_chain", value: <u32 as Value>::TYPE },
                Parameter { name: "padding", value: <u32 as Value>::TYPE },
                Parameter { name: "transfer_size", value: <u32 as Value>::TYPE },
                Parameter { name: "keepalive", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dns_DNSResolverConfig",
            documentation: " The configuration of a resolver but its servers, durations in milliseconds and TTLs in seconds.",
            fields: &[
                Parameter { name: "timeout", value: <u32 as Value>::TYPE },
                Parameter { name: "maximum_timeout", value: <u32 as Value>::TYPE },
                Parameter { name: "rounds", value: <u32 as Value>::TYPE },
                Parameter { name: "edns", value: <bool as Value>::TYPE },
                Parameter { name: "udp_size", value: <u16 as Value>::TYPE },
                Parameter { name: "recursion_desired", value: <bool as Value>::TYPE },
                Parameter { name: "dnssec_ok", value: <bool as Value>::TYPE },
                Parameter { name: "checking_disabled", value: <bool as Value>::TYPE },
                Parameter { name: "cookies", value: <bool as Value>::TYPE },
                Parameter { name: "padding", value: <u32 as Value>::TYPE },
                Parameter { name: "maximum_queries", value: <u32 as Value>::TYPE },
                Parameter { name: "cache_entries", value: <u32 as Value>::TYPE },
                Parameter { name: "cache_maximum_ttl", value: <u32 as Value>::TYPE },
                Parameter { name: "cache_minimum_ttl", value: <u32 as Value>::TYPE },
                Parameter { name: "cache_maximum_negative_ttl", value: <u32 as Value>::TYPE },
                Parameter { name: "cache_failure_ttl", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dns_DNSUpstream",
            documentation: " A server of a resolver: its endpoint and transport.",
            fields: &[
                Parameter { name: "endpoint", value: <FFIIPEndpoint as Value>::TYPE },
                Parameter { name: "transport", value: <u8 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dns_DNSTransmission",
            documentation: " A query to send: of which query, to which server, over which transport.",
            fields: &[
                Parameter { name: "query", value: <u64 as Value>::TYPE },
                Parameter { name: "upstream", value: <u32 as Value>::TYPE },
                Parameter { name: "transport", value: <u8 as Value>::TYPE },
            ],
        },
    ],
    functions: FUNCTIONS,
    modules: &[
        #[cfg(umilib_feature = "protocol-dns-dnssec")]
        dnssec::MODULE,
        #[cfg(umilib_feature = "protocol-dns-https")]
        https::MODULE,
        #[cfg(umilib_feature = "protocol-dns-quic")]
        quic::MODULE,
        #[cfg(umilib_feature = "protocol-dns-tcp")]
        tcp::MODULE,
        #[cfg(umilib_feature = "protocol-dns-tls")]
        tls::MODULE,
        #[cfg(umilib_feature = "protocol-dns-udp")]
        udp::MODULE,
    ],
};
