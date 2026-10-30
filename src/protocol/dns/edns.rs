use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::hash::siphash::SipHash;
use crate::protocol::ip::IPAddress;

use super::{DNSClass, DNSError, DNSMessage, DNSName, DNSRecord, DNSType};

/// The code of an EDNS option (RFC 6891 §6.1.2, IANA's registry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DNSOptionCode(pub u16);

impl DNSOptionCode {
    pub const NSID: DNSOptionCode = DNSOptionCode(3);
    pub const CLIENT_SUBNET: DNSOptionCode = DNSOptionCode(8);
    /// RFC 7873 §4.
    pub const COOKIE: DNSOptionCode = DNSOptionCode(10);
    /// RFC 7828 §3.1.
    pub const TCP_KEEPALIVE: DNSOptionCode = DNSOptionCode(11);
    /// RFC 7830 §3.
    pub const PADDING: DNSOptionCode = DNSOptionCode(12);
    /// RFC 8914 §2.
    pub const EXTENDED_ERROR: DNSOptionCode = DNSOptionCode(15);
    /// RFC 9567 §6.1.
    pub const REPORT_CHANNEL: DNSOptionCode = DNSOptionCode(18);
}

/// An EDNS option: its code and data.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSOption {
    pub code: DNSOptionCode,
    pub data: Vec<u8>,
}

/// A DNS cookie (RFC 7873 §4): the client's 8 bytes, and the server's 8
/// to 32 when it has sent one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSCookie {
    pub client: [u8; 8],
    pub server: Option<Vec<u8>>,
}

impl DNSCookie {
    /// The cookie of an option's data; a length other than 8 or 16 to 40
    /// is FORMERR (RFC 7873 §5.2.2).
    pub fn decode(data: &[u8]) -> Result<DNSCookie, DNSError> {
        let client: [u8; 8] = data
            .get(..8)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(DNSError::Malformed("a cookie of a wrong length"))?;
        match data.len() {
            8 => Ok(DNSCookie { client, server: None }),
            16..=40 => Ok(DNSCookie { client, server: Some(data[8..].to_vec()) }),
            _ => Err(DNSError::Malformed("a cookie of a wrong length")),
        }
    }

    pub fn encode(&self) -> DNSOption {
        let mut data = self.client.to_vec();
        data.extend_from_slice(self.server.as_deref().unwrap_or_default());
        DNSOption { code: DNSOptionCode::COOKIE, data }
    }

    /// The version of the server cookie of RFC 9018 §4.
    pub const SERVER_VERSION: u8 = 1;
    /// How long a server cookie is valid after its timestamp, and before
    /// it (RFC 9018 §4.3), in seconds.
    pub const SERVER_LIFETIME: u32 = 3600;
    pub const SERVER_SKEW: u32 = 300;
    /// The age after which a server sends a new cookie (RFC 9018 §4.3).
    pub const SERVER_RENEWAL: u32 = 1800;

    /// The server cookie of RFC 9018 §4 for `client` at `address`, made at
    /// `timestamp` (seconds since 1970, modulo 2^32) with `secret`: version
    /// 1, three reserved zeros, the timestamp, and the hash of
    /// [`DNSCookie::server_hash`].
    pub fn server_cookie(secret: &[u8; 16], client: &[u8; 8], address: &IPAddress, timestamp: u32) -> [u8; 16] {
        let mut cookie = [0u8; 16];
        cookie[0] = DNSCookie::SERVER_VERSION;
        cookie[4..8].copy_from_slice(&timestamp.to_be_bytes());
        let header: [u8; 8] = cookie[..8].try_into().unwrap_or_default();
        cookie[8..].copy_from_slice(&DNSCookie::server_hash(secret, client, &header, address));
        cookie
    }

    /// The hash of a server cookie (RFC 9018 §4.4): SipHash-2-4, keyed by
    /// `secret`, of the client cookie, the server cookie's version,
    /// reserved bytes and timestamp (`header`), and the client's address.
    pub fn server_hash(secret: &[u8; 16], client: &[u8; 8], header: &[u8; 8], address: &IPAddress) -> [u8; 8] {
        let mut input = Vec::with_capacity(32);
        input.extend_from_slice(client);
        input.extend_from_slice(header);
        match address {
            IPAddress::V4(address) => input.extend_from_slice(&address.0),
            IPAddress::V6(address) => input.extend_from_slice(&address.0),
        }
        SipHash::<2, 4>::hash(secret, &input)
    }

    /// The timestamp of the cookie's server cookie and the index of the one
    /// of `secrets` that made it for `address` (RFC 9018 §5 keeps old
    /// secrets valid for a while), if `now` is at most an hour after the
    /// timestamp and five minutes before it in serial arithmetic (RFC 9018
    /// §4.3). Only a server cookie of 16 bytes, of version 1, is checked
    /// (§4.4); its reserved bytes are hashed as they are.
    pub fn check_server(&self, secrets: &[[u8; 16]], address: &IPAddress, now: u32) -> Option<(u32, usize)> {
        let server: &[u8; 16] = self.server.as_deref()?.try_into().ok()?;
        let (header, hash) = server.split_at(8);
        let header: &[u8; 8] = header.try_into().ok()?;
        if header[0] != DNSCookie::SERVER_VERSION {
            return None;
        }
        let timestamp = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let age = now.wrapping_sub(timestamp) as i32;
        if age > DNSCookie::SERVER_LIFETIME as i32 || age < -(DNSCookie::SERVER_SKEW as i32) {
            return None;
        }
        let index = secrets.iter().position(|secret| {
            let expected = DNSCookie::server_hash(secret, &self.client, header, address);
            crate::secret::ConstantTimeEq::ct_eq(&expected[..], hash).into_bool()
        })?;
        Some((timestamp, index))
    }
}

/// An Extended DNS Error (RFC 8914 §2): its INFO-CODE and text.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSExtendedError {
    pub info_code: u16,
    pub text: String,
}

impl DNSExtendedError {
    pub const OTHER: u16 = 0;
    pub const UNSUPPORTED_DNSKEY_ALGORITHM: u16 = 1;
    pub const UNSUPPORTED_DS_DIGEST_TYPE: u16 = 2;
    pub const STALE_ANSWER: u16 = 3;
    pub const FORGED_ANSWER: u16 = 4;
    pub const DNSSEC_INDETERMINATE: u16 = 5;
    pub const DNSSEC_BOGUS: u16 = 6;
    pub const SIGNATURE_EXPIRED: u16 = 7;
    pub const SIGNATURE_NOT_YET_VALID: u16 = 8;
    pub const DNSKEY_MISSING: u16 = 9;
    pub const RRSIGS_MISSING: u16 = 10;
    pub const NO_ZONE_KEY_BIT_SET: u16 = 11;
    pub const NSEC_MISSING: u16 = 12;
    pub const CACHED_ERROR: u16 = 13;
    pub const NOT_READY: u16 = 14;
    pub const BLOCKED: u16 = 15;
    pub const CENSORED: u16 = 16;
    pub const FILTERED: u16 = 17;
    pub const PROHIBITED: u16 = 18;
    pub const STALE_NXDOMAIN_ANSWER: u16 = 19;
    pub const NOT_AUTHORITATIVE: u16 = 20;
    pub const NOT_SUPPORTED: u16 = 21;
    pub const NO_REACHABLE_AUTHORITY: u16 = 22;
    pub const NETWORK_ERROR: u16 = 23;
    pub const INVALID_DATA: u16 = 24;
    pub const SIGNATURE_EXPIRED_BEFORE_VALID: u16 = 25;
    pub const TOO_EARLY: u16 = 26;
    pub const UNSUPPORTED_NSEC3_ITERATIONS: u16 = 27;
    pub const UNABLE_TO_CONFORM_TO_POLICY: u16 = 28;
    pub const SYNTHESIZED: u16 = 29;
    pub const INVALID_QUERY_TYPE: u16 = 30;

    /// The error of an option's data: two bytes of code, then UTF-8 text
    /// (RFC 8914 §2); text that is not UTF-8 is replaced.
    pub fn decode(data: &[u8]) -> Result<DNSExtendedError, DNSError> {
        let [high, low, text @ ..] = data else { return Err(DNSError::Malformed("an extended error cut short")) };
        Ok(DNSExtendedError {
            info_code: u16::from_be_bytes([*high, *low]),
            text: String::from_utf8_lossy(text).into_owned(),
        })
    }

    pub fn encode(&self) -> DNSOption {
        let mut data = self.info_code.to_be_bytes().to_vec();
        data.extend_from_slice(self.text.as_bytes());
        DNSOption { code: DNSOptionCode::EXTENDED_ERROR, data }
    }
}

/// The EDNS(0) of a message, its OPT pseudo-record (RFC 6891 §6.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSEDNS {
    /// The largest UDP payload the sender takes (the OPT's class); below 512 is taken as 512.
    pub udp_size: u16,
    /// The upper 8 bits of the response code.
    pub extended_rcode: u8,
    pub version: u8,
    /// DO: the sender takes DNSSEC records (RFC 3225).
    pub dnssec_ok: bool,
    /// The other 15 flag bits, which must be zero: kept as received.
    pub z: u16,
    pub options: Vec<DNSOption>,
}

impl Default for DNSEDNS {
    fn default() -> DNSEDNS {
        DNSEDNS {
            udp_size: DNSEDNS::DEFAULT_UDP_SIZE,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: Vec::new(),
        }
    }
}

impl DNSEDNS {
    /// The size that avoids IP fragmentation on common paths (RFC 9715 §3.2,
    /// the value of DNS Flag Day 2020).
    pub const DEFAULT_UDP_SIZE: u16 = 1232;

    /// The EDNS of an OPT record; its owner must be the root (RFC 6891 §6.1.1).
    pub fn from_record(record: &DNSRecord, rdata: &[u8]) -> Result<DNSEDNS, DNSError> {
        if !record.name.is_root() {
            return Err(DNSError::Malformed("an OPT not owned by the root"));
        }
        let mut options = Vec::new();
        let mut rest = rdata;
        while !rest.is_empty() {
            let [high, low, length_high, length_low, tail @ ..] = rest else {
                return Err(DNSError::Malformed("an EDNS option cut short"));
            };
            let length = usize::from(u16::from_be_bytes([*length_high, *length_low]));
            let data = tail.get(..length).ok_or(DNSError::Malformed("an EDNS option cut short"))?;
            options.push(DNSOption { code: DNSOptionCode(u16::from_be_bytes([*high, *low])), data: data.to_vec() });
            rest = &tail[length..];
        }
        let ttl = record.ttl;
        Ok(DNSEDNS {
            udp_size: record.class.0,
            extended_rcode: (ttl >> 24) as u8,
            version: (ttl >> 16) as u8,
            dnssec_ok: ttl & 0x8000 != 0,
            z: (ttl & 0x7FFF) as u16,
            options,
        })
    }

    /// Appends the OPT record.
    pub fn encode(&self, out: &mut Vec<u8>) {
        DNSName::root().encode(out, None);
        out.extend_from_slice(&DNSType::OPT.0.to_be_bytes());
        out.extend_from_slice(&DNSClass(self.udp_size).0.to_be_bytes());
        let ttl = u32::from(self.extended_rcode) << 24
            | u32::from(self.version) << 16
            | if self.dnssec_ok { 0x8000 } else { 0 }
            | u32::from(self.z & 0x7FFF);
        out.extend_from_slice(&ttl.to_be_bytes());
        let length: usize = self.options.iter().map(|option| 4 + option.data.len()).sum();
        out.extend_from_slice(&(length as u16).to_be_bytes());
        for option in &self.options {
            out.extend_from_slice(&option.code.0.to_be_bytes());
            out.extend_from_slice(&(option.data.len() as u16).to_be_bytes());
            out.extend_from_slice(&option.data);
        }
    }

    /// The length of the OPT record [`DNSEDNS::encode`] writes.
    pub fn encoded_length(&self) -> usize {
        11 + self.options.iter().map(|option| 4 + option.data.len()).sum::<usize>()
    }

    pub fn option(&self, code: DNSOptionCode) -> Option<&[u8]> {
        self.options.iter().find(|option| option.code == code).map(|option| option.data.as_slice())
    }

    /// Sets the option of `option`'s code, the only one of it.
    pub fn set_option(&mut self, option: DNSOption) {
        self.options.retain(|found| found.code != option.code);
        self.options.push(option);
    }

    pub fn cookie(&self) -> Option<Result<DNSCookie, DNSError>> {
        self.option(DNSOptionCode::COOKIE).map(DNSCookie::decode)
    }

    /// The extended errors of the message (RFC 8914 §2: there may be several).
    pub fn extended_errors(&self) -> Vec<DNSExtendedError> {
        self.options
            .iter()
            .filter(|option| option.code == DNSOptionCode::EXTENDED_ERROR)
            .filter_map(|option| DNSExtendedError::decode(&option.data).ok())
            .collect()
    }

    /// The largest UDP payload the sender takes: at least 512 (RFC 6891 §6.2.3).
    pub fn payload_size(&self) -> usize {
        usize::from(self.udp_size.max(512))
    }
}

/// The timeout of the edns-tcp-keepalive option (RFC 7828 §3.1): in units of 100 milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DNSKeepalive;

impl DNSKeepalive {
    /// The option of a query: no timeout (§3.1).
    pub fn query() -> DNSOption {
        DNSOption { code: DNSOptionCode::TCP_KEEPALIVE, data: Vec::new() }
    }

    /// The option of a response, giving `timeout` (rounded down to 100 ms, at most 6553.5 s).
    pub fn response(timeout: Duration) -> DNSOption {
        let units = (timeout.as_millis() / 100).min(u128::from(u16::MAX)) as u16;
        DNSOption { code: DNSOptionCode::TCP_KEEPALIVE, data: units.to_be_bytes().to_vec() }
    }

    /// The timeout of a response's option: None without one (§3.2.1, a
    /// length of 2), an error for another length.
    pub fn timeout(message: &DNSMessage) -> Result<Option<Duration>, DNSError> {
        let Some(data) = message.edns.as_ref().and_then(|edns| edns.option(DNSOptionCode::TCP_KEEPALIVE)) else {
            return Ok(None);
        };
        match data {
            [high, low] => Ok(Some(Duration::from_millis(u64::from(u16::from_be_bytes([*high, *low])) * 100))),
            [] => Ok(None),
            _ => Err(DNSError::Malformed("an edns-tcp-keepalive of a wrong length")),
        }
    }
}
