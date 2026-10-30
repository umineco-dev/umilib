use alloc::vec::Vec;
use core::time::Duration;

use crate::protocol::ip::IPv4Address;

use super::super::DHCPError;

/// The code of a DHCPv4 option (RFC 2132, IANA's BOOTP and DHCP parameters).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DHCPv4OptionCode(pub u8);

impl DHCPv4OptionCode {
    pub const PAD: DHCPv4OptionCode = DHCPv4OptionCode(0);
    pub const SUBNET_MASK: DHCPv4OptionCode = DHCPv4OptionCode(1);
    pub const ROUTER: DHCPv4OptionCode = DHCPv4OptionCode(3);
    pub const DOMAIN_NAME_SERVER: DHCPv4OptionCode = DHCPv4OptionCode(6);
    pub const HOST_NAME: DHCPv4OptionCode = DHCPv4OptionCode(12);
    pub const DOMAIN_NAME: DHCPv4OptionCode = DHCPv4OptionCode(15);
    pub const INTERFACE_MTU: DHCPv4OptionCode = DHCPv4OptionCode(26);
    pub const BROADCAST_ADDRESS: DHCPv4OptionCode = DHCPv4OptionCode(28);
    pub const NTP_SERVERS: DHCPv4OptionCode = DHCPv4OptionCode(42);
    pub const VENDOR_SPECIFIC: DHCPv4OptionCode = DHCPv4OptionCode(43);
    pub const REQUESTED_ADDRESS: DHCPv4OptionCode = DHCPv4OptionCode(50);
    pub const LEASE_TIME: DHCPv4OptionCode = DHCPv4OptionCode(51);
    pub const OVERLOAD: DHCPv4OptionCode = DHCPv4OptionCode(52);
    pub const MESSAGE_TYPE: DHCPv4OptionCode = DHCPv4OptionCode(53);
    pub const SERVER_IDENTIFIER: DHCPv4OptionCode = DHCPv4OptionCode(54);
    pub const PARAMETER_REQUEST_LIST: DHCPv4OptionCode = DHCPv4OptionCode(55);
    pub const MESSAGE: DHCPv4OptionCode = DHCPv4OptionCode(56);
    pub const MAXIMUM_MESSAGE_SIZE: DHCPv4OptionCode = DHCPv4OptionCode(57);
    pub const RENEWAL_TIME: DHCPv4OptionCode = DHCPv4OptionCode(58);
    pub const REBINDING_TIME: DHCPv4OptionCode = DHCPv4OptionCode(59);
    pub const VENDOR_CLASS_IDENTIFIER: DHCPv4OptionCode = DHCPv4OptionCode(60);
    pub const CLIENT_IDENTIFIER: DHCPv4OptionCode = DHCPv4OptionCode(61);
    /// RFC 4039 §4.
    pub const RAPID_COMMIT: DHCPv4OptionCode = DHCPv4OptionCode(80);
    /// RFC 3046 §2.
    pub const RELAY_AGENT_INFORMATION: DHCPv4OptionCode = DHCPv4OptionCode(82);
    /// RFC 8925 §3.1.
    pub const IPV6_ONLY_PREFERRED: DHCPv4OptionCode = DHCPv4OptionCode(108);
    /// RFC 8910 §2.1.
    pub const CAPTIVE_PORTAL: DHCPv4OptionCode = DHCPv4OptionCode(114);
    /// RFC 3397 §2.
    pub const DOMAIN_SEARCH: DHCPv4OptionCode = DHCPv4OptionCode(119);
    /// RFC 3442 §2.
    pub const CLASSLESS_STATIC_ROUTE: DHCPv4OptionCode = DHCPv4OptionCode(121);
    pub const END: DHCPv4OptionCode = DHCPv4OptionCode(255);
}

/// The type of a DHCPv4 message (RFC 2132 §9.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DHCPv4MessageType(pub u8);

impl DHCPv4MessageType {
    pub const DISCOVER: DHCPv4MessageType = DHCPv4MessageType(1);
    pub const OFFER: DHCPv4MessageType = DHCPv4MessageType(2);
    pub const REQUEST: DHCPv4MessageType = DHCPv4MessageType(3);
    pub const DECLINE: DHCPv4MessageType = DHCPv4MessageType(4);
    pub const ACK: DHCPv4MessageType = DHCPv4MessageType(5);
    pub const NAK: DHCPv4MessageType = DHCPv4MessageType(6);
    pub const RELEASE: DHCPv4MessageType = DHCPv4MessageType(7);
    pub const INFORM: DHCPv4MessageType = DHCPv4MessageType(8);
}

/// A route of the classless static route option (RFC 3442 §2): the
/// destination and its prefix length, and the router.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv4Route {
    pub destination: IPv4Address,
    pub prefix: u8,
    pub router: IPv4Address,
}

/// The options of a DHCPv4 message, each code once, in the order first
/// seen; an option given in several parts is their concatenation (RFC 3396 §7).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DHCPv4Options {
    pub entries: Vec<(DHCPv4OptionCode, Vec<u8>)>,
}

impl DHCPv4Options {
    pub fn new() -> DHCPv4Options {
        DHCPv4Options { entries: Vec::new() }
    }

    /// Adds the options of `area` (RFC 2132 §2): PAD alone, END ends it,
    /// any other a code, a length and the data. Fails for an option cut short.
    pub fn decode_area(&mut self, area: &[u8]) -> Result<(), DHCPError> {
        let mut index = 0;
        while index < area.len() {
            let code = DHCPv4OptionCode(area[index]);
            match code {
                DHCPv4OptionCode::PAD => index += 1,
                DHCPv4OptionCode::END => return Ok(()),
                _ => {
                    let length =
                        usize::from(*area.get(index + 1).ok_or(DHCPError::Malformed("an option without its length"))?);
                    let data =
                        area.get(index + 2..index + 2 + length).ok_or(DHCPError::Malformed("an option cut short"))?;
                    self.append(code, data);
                    index += 2 + length;
                }
            }
        }
        Ok(())
    }

    /// Appends `data` to the option `code` (RFC 3396 §7).
    pub fn append(&mut self, code: DHCPv4OptionCode, data: &[u8]) {
        match self.entries.iter_mut().find(|(found, _)| *found == code) {
            Some((_, existing)) => existing.extend_from_slice(data),
            None => self.entries.push((code, data.to_vec())),
        }
    }

    /// Writes the options, each of more than 255 bytes in parts of at most
    /// 255 (RFC 3396 §6), and END.
    pub fn encode(&self, out: &mut Vec<u8>) {
        for (code, data) in &self.entries {
            if data.is_empty() {
                out.extend_from_slice(&[code.0, 0]);
            }
            for part in data.chunks(255) {
                out.push(code.0);
                out.push(part.len() as u8);
                out.extend_from_slice(part);
            }
        }
        out.push(DHCPv4OptionCode::END.0);
    }

    pub fn get(&self, code: DHCPv4OptionCode) -> Option<&[u8]> {
        self.entries.iter().find(|(found, _)| *found == code).map(|(_, data)| data.as_slice())
    }

    /// Sets the option `code`, replacing it if there is one.
    pub fn set(&mut self, code: DHCPv4OptionCode, data: Vec<u8>) {
        match self.entries.iter_mut().find(|(found, _)| *found == code) {
            Some((_, existing)) => *existing = data,
            None => self.entries.push((code, data)),
        }
    }

    pub fn remove(&mut self, code: DHCPv4OptionCode) {
        self.entries.retain(|(found, _)| *found != code);
    }

    pub fn message_type(&self) -> Option<DHCPv4MessageType> {
        match self.get(DHCPv4OptionCode::MESSAGE_TYPE)? {
            [kind] => Some(DHCPv4MessageType(*kind)),
            _ => None,
        }
    }

    /// The address of a 4-byte option.
    pub fn address(&self, code: DHCPv4OptionCode) -> Option<IPv4Address> {
        let data: [u8; 4] = self.get(code)?.try_into().ok()?;
        Some(IPv4Address(data))
    }

    /// The addresses of an option of a list of them (RFC 2132 §3.5, §3.8).
    pub fn addresses(&self, code: DHCPv4OptionCode) -> Vec<IPv4Address> {
        let data = self.get(code).unwrap_or_default();
        if !data.len().is_multiple_of(4) {
            return Vec::new();
        }
        data.as_chunks::<4>().0.iter().map(|chunk| IPv4Address(*chunk)).collect()
    }

    pub fn set_address(&mut self, code: DHCPv4OptionCode, address: IPv4Address) {
        self.set(code, address.0.to_vec());
    }

    pub fn set_addresses(&mut self, code: DHCPv4OptionCode, addresses: &[IPv4Address]) {
        self.set(code, addresses.iter().flat_map(|address| address.0).collect());
    }

    /// A time of seconds (RFC 2132 §9.2, §9.11, §9.12; RFC 8925 §3.1):
    /// None for 0xFFFFFFFF, infinity.
    pub fn time(&self, code: DHCPv4OptionCode) -> Option<Option<Duration>> {
        let data: [u8; 4] = self.get(code)?.try_into().ok()?;
        Some(match u32::from_be_bytes(data) {
            u32::MAX => None,
            seconds => Some(Duration::from_secs(u64::from(seconds))),
        })
    }

    /// Sets a time of seconds; None for infinity.
    pub fn set_time(&mut self, code: DHCPv4OptionCode, time: Option<Duration>) {
        let seconds = time.map_or(u32::MAX, |time| time.as_secs().min(u64::from(u32::MAX - 1)) as u32);
        self.set(code, seconds.to_be_bytes().to_vec());
    }

    /// The largest message the sender takes (RFC 2132 §9.10): at least 576.
    pub fn maximum_message_size(&self) -> Option<u16> {
        let data: [u8; 2] = self.get(DHCPv4OptionCode::MAXIMUM_MESSAGE_SIZE)?.try_into().ok()?;
        Some(u16::from_be_bytes(data)).filter(|size| *size >= 576)
    }

    /// The routes of the classless static route option (RFC 3442 §2): each
    /// a prefix length, the significant bytes of the destination (its bits
    /// beyond the prefix zeroed), and the router. A client given this
    /// option ignores the Router option (§2).
    pub fn routes(&self) -> Result<Vec<DHCPv4Route>, DHCPError> {
        let mut data = self.get(DHCPv4OptionCode::CLASSLESS_STATIC_ROUTE).unwrap_or_default();
        let malformed = DHCPError::Malformed("a classless static route cut short");
        let mut routes = Vec::new();
        while let [prefix, rest @ ..] = data {
            if *prefix > 32 {
                return Err(DHCPError::Malformed("a route of a prefix longer than 32"));
            }
            let significant = usize::from(prefix.div_ceil(8));
            let (destination, rest) = rest.split_at_checked(significant).ok_or(malformed)?;
            let (router, rest) = rest.split_at_checked(4).ok_or(malformed)?;
            let mut address = [0u8; 4];
            address[..significant].copy_from_slice(destination);
            // The bits beyond the prefix are zeroed (§2).
            let mask = u32::MAX.checked_shl(32 - u32::from(*prefix)).unwrap_or(0);
            let address = (u32::from_be_bytes(address) & mask).to_be_bytes();
            routes.push(DHCPv4Route {
                destination: IPv4Address(address),
                prefix: *prefix,
                router: IPv4Address(router.try_into().map_err(|_| malformed)?),
            });
            data = rest;
        }
        Ok(routes)
    }

    pub fn set_routes(&mut self, routes: &[DHCPv4Route]) {
        let mut data = Vec::new();
        for route in routes {
            let significant = usize::from(route.prefix.min(32).div_ceil(8));
            data.push(route.prefix.min(32));
            data.extend_from_slice(&route.destination.0[..significant]);
            data.extend_from_slice(&route.router.0);
        }
        self.set(DHCPv4OptionCode::CLASSLESS_STATIC_ROUTE, data);
    }
}
