use alloc::string::String;
use alloc::vec::Vec;

use crate::protocol::ip::IPv6Address;

use super::super::{DHCPDUID, DHCPError};

/// The code of a DHCPv6 option (RFC 9915 §24, IANA's DHCPv6 parameters).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DHCPv6OptionCode(pub u16);

impl DHCPv6OptionCode {
    pub const CLIENT_ID: DHCPv6OptionCode = DHCPv6OptionCode(1);
    pub const SERVER_ID: DHCPv6OptionCode = DHCPv6OptionCode(2);
    pub const IA_NA: DHCPv6OptionCode = DHCPv6OptionCode(3);
    /// Obsolete (RFC 9915 §21.5): ignored.
    pub const IA_TA: DHCPv6OptionCode = DHCPv6OptionCode(4);
    pub const IAADDR: DHCPv6OptionCode = DHCPv6OptionCode(5);
    pub const ORO: DHCPv6OptionCode = DHCPv6OptionCode(6);
    pub const PREFERENCE: DHCPv6OptionCode = DHCPv6OptionCode(7);
    pub const ELAPSED_TIME: DHCPv6OptionCode = DHCPv6OptionCode(8);
    pub const RELAY_MSG: DHCPv6OptionCode = DHCPv6OptionCode(9);
    pub const AUTH: DHCPv6OptionCode = DHCPv6OptionCode(11);
    /// Obsolete (RFC 9915 §21.12): ignored.
    pub const UNICAST: DHCPv6OptionCode = DHCPv6OptionCode(12);
    pub const STATUS_CODE: DHCPv6OptionCode = DHCPv6OptionCode(13);
    pub const RAPID_COMMIT: DHCPv6OptionCode = DHCPv6OptionCode(14);
    pub const USER_CLASS: DHCPv6OptionCode = DHCPv6OptionCode(15);
    pub const VENDOR_CLASS: DHCPv6OptionCode = DHCPv6OptionCode(16);
    pub const VENDOR_OPTS: DHCPv6OptionCode = DHCPv6OptionCode(17);
    pub const INTERFACE_ID: DHCPv6OptionCode = DHCPv6OptionCode(18);
    pub const RECONF_MSG: DHCPv6OptionCode = DHCPv6OptionCode(19);
    pub const RECONF_ACCEPT: DHCPv6OptionCode = DHCPv6OptionCode(20);
    /// RFC 3646 §3.
    pub const DNS_SERVERS: DHCPv6OptionCode = DHCPv6OptionCode(23);
    /// RFC 3646 §4.
    pub const DOMAIN_LIST: DHCPv6OptionCode = DHCPv6OptionCode(24);
    pub const IA_PD: DHCPv6OptionCode = DHCPv6OptionCode(25);
    pub const IAPREFIX: DHCPv6OptionCode = DHCPv6OptionCode(26);
    pub const INFORMATION_REFRESH_TIME: DHCPv6OptionCode = DHCPv6OptionCode(32);
    pub const SOL_MAX_RT: DHCPv6OptionCode = DHCPv6OptionCode(82);
    pub const INF_MAX_RT: DHCPv6OptionCode = DHCPv6OptionCode(83);
}

/// An option: its code and data (RFC 9915 §21.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv6Option {
    pub code: DHCPv6OptionCode,
    pub data: Vec<u8>,
}

/// The options of a message or of an option, in order; a code may repeat
/// (several IA_NA, several IAADDR in one).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DHCPv6Options {
    pub entries: Vec<DHCPv6Option>,
}

impl DHCPv6Options {
    pub fn new() -> DHCPv6Options {
        DHCPv6Options { entries: Vec::new() }
    }

    /// The options of `bytes`: each a code, a length and the data (§21.1).
    pub fn decode(mut bytes: &[u8]) -> Result<DHCPv6Options, DHCPError> {
        let mut entries = Vec::new();
        while !bytes.is_empty() {
            let [high, low, length_high, length_low, rest @ ..] = bytes else {
                return Err(DHCPError::Malformed("an option cut short"));
            };
            let length = usize::from(u16::from_be_bytes([*length_high, *length_low]));
            let data = rest.get(..length).ok_or(DHCPError::Malformed("an option cut short"))?;
            entries
                .push(DHCPv6Option { code: DHCPv6OptionCode(u16::from_be_bytes([*high, *low])), data: data.to_vec() });
            bytes = &rest[length..];
        }
        Ok(DHCPv6Options { entries })
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), DHCPError> {
        for option in &self.entries {
            let length = u16::try_from(option.data.len()).map_err(|_| DHCPError::TooLarge)?;
            out.extend_from_slice(&option.code.0.to_be_bytes());
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(&option.data);
        }
        Ok(())
    }

    pub fn get(&self, code: DHCPv6OptionCode) -> Option<&[u8]> {
        self.entries.iter().find(|option| option.code == code).map(|option| option.data.as_slice())
    }

    pub fn all(&self, code: DHCPv6OptionCode) -> impl Iterator<Item = &[u8]> {
        self.entries.iter().filter(move |option| option.code == code).map(|option| option.data.as_slice())
    }

    pub fn contains(&self, code: DHCPv6OptionCode) -> bool {
        self.get(code).is_some()
    }

    /// Adds the option `code`.
    pub fn push(&mut self, code: DHCPv6OptionCode, data: Vec<u8>) {
        self.entries.push(DHCPv6Option { code, data });
    }

    /// Sets the one option `code`, replacing those there are.
    pub fn set(&mut self, code: DHCPv6OptionCode, data: Vec<u8>) {
        self.remove(code);
        self.push(code, data);
    }

    pub fn remove(&mut self, code: DHCPv6OptionCode) {
        self.entries.retain(|option| option.code != code);
    }

    /// The DUID of the client or server identifier option `code`.
    pub fn duid(&self, code: DHCPv6OptionCode) -> Option<DHCPDUID> {
        DHCPDUID::decode(self.get(code)?).ok()
    }

    /// The status of the message or option (§21.13); success without one.
    pub fn status(&self) -> Result<DHCPv6StatusCode, DHCPError> {
        match self.get(DHCPv6OptionCode::STATUS_CODE) {
            Some(data) => DHCPv6StatusCode::decode(data),
            None => Ok(DHCPv6StatusCode::new(DHCPv6StatusCode::SUCCESS, "")),
        }
    }

    /// The IAs of type `code` (IA_NA or IA_PD) that can be read.
    pub fn ias(&self, code: DHCPv6OptionCode) -> Vec<DHCPv6IA> {
        self.all(code).filter_map(|data| DHCPv6IA::decode(code, data).ok()).collect()
    }

    /// The addresses of an option of a list of them (RFC 3646 §3).
    pub fn addresses(&self, code: DHCPv6OptionCode) -> Vec<IPv6Address> {
        let data = self.get(code).unwrap_or_default();
        if !data.len().is_multiple_of(16) {
            return Vec::new();
        }
        data.as_chunks::<16>().0.iter().map(|chunk| IPv6Address(*chunk)).collect()
    }

    /// The option codes of the Option Request option (§21.7).
    pub fn requested(&self) -> Vec<DHCPv6OptionCode> {
        let data = self.get(DHCPv6OptionCode::ORO).unwrap_or_default();
        data.as_chunks::<2>().0.iter().map(|pair| DHCPv6OptionCode(u16::from_be_bytes(*pair))).collect()
    }
}

/// The Status Code option (RFC 9915 §21.13).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv6StatusCode {
    pub code: u16,
    pub message: String,
}

impl DHCPv6StatusCode {
    pub const SUCCESS: u16 = 0;
    pub const UNSPEC_FAIL: u16 = 1;
    pub const NO_ADDRS_AVAIL: u16 = 2;
    pub const NO_BINDING: u16 = 3;
    pub const NOT_ON_LINK: u16 = 4;
    /// Obsolete (RFC 9915 §21.13).
    pub const USE_MULTICAST: u16 = 5;
    pub const NO_PREFIX_AVAIL: u16 = 6;

    pub fn new(code: u16, message: &str) -> DHCPv6StatusCode {
        DHCPv6StatusCode { code, message: String::from(message) }
    }

    /// Two bytes of code, then UTF-8 text; text that is not UTF-8 is replaced.
    pub fn decode(data: &[u8]) -> Result<DHCPv6StatusCode, DHCPError> {
        let [high, low, text @ ..] = data else { return Err(DHCPError::Malformed("a status code cut short")) };
        Ok(DHCPv6StatusCode {
            code: u16::from_be_bytes([*high, *low]),
            message: String::from_utf8_lossy(text).into_owned(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        [&self.code.to_be_bytes()[..], self.message.as_bytes()].concat()
    }
}

/// An Identity Association of addresses (IA_NA, §21.4) or prefixes (IA_PD, §21.21).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv6IA {
    pub kind: DHCPv6OptionCode,
    pub iaid: u32,
    /// T1 and T2 in seconds: 0 lets the client choose; 0xFFFFFFFF is infinity (§7.7).
    pub t1: u32,
    pub t2: u32,
    pub options: DHCPv6Options,
}

impl DHCPv6IA {
    /// The time value of infinity (§7.7).
    pub const INFINITY: u32 = u32::MAX;

    pub fn new(kind: DHCPv6OptionCode, iaid: u32) -> DHCPv6IA {
        DHCPv6IA { kind, iaid, t1: 0, t2: 0, options: DHCPv6Options::new() }
    }

    pub fn decode(kind: DHCPv6OptionCode, data: &[u8]) -> Result<DHCPv6IA, DHCPError> {
        if data.len() < 12 {
            return Err(DHCPError::Malformed("an IA cut short"));
        }
        let word = |at: usize| u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
        Ok(DHCPv6IA { kind, iaid: word(0), t1: word(4), t2: word(8), options: DHCPv6Options::decode(&data[12..])? })
    }

    pub fn encode(&self) -> Result<DHCPv6Option, DHCPError> {
        let mut data = Vec::with_capacity(12);
        for word in [self.iaid, self.t1, self.t2] {
            data.extend_from_slice(&word.to_be_bytes());
        }
        self.options.encode(&mut data)?;
        Ok(DHCPv6Option { code: self.kind, data })
    }

    pub fn addresses(&self) -> Vec<DHCPv6IAAddress> {
        self.options.all(DHCPv6OptionCode::IAADDR).filter_map(|data| DHCPv6IAAddress::decode(data).ok()).collect()
    }

    pub fn prefixes(&self) -> Vec<DHCPv6IAPrefix> {
        self.options.all(DHCPv6OptionCode::IAPREFIX).filter_map(|data| DHCPv6IAPrefix::decode(data).ok()).collect()
    }

    /// The IA as a client keeps it (§18.2.10.1): none if its T1 is above a
    /// nonzero T2 (§21.4, §21.21) or if it holds nothing usable; else
    /// without the addresses and prefixes of a preferred lifetime above
    /// their valid one (§21.6, §21.22) or of a valid lifetime of 0.
    pub fn usable(&self) -> Option<DHCPv6IA> {
        if self.t2 != 0 && self.t1 > self.t2 {
            return None;
        }
        let mut ia = self.clone();
        ia.options.entries.retain(|option| {
            let lifetimes = match option.code {
                DHCPv6OptionCode::IAADDR => {
                    DHCPv6IAAddress::decode(&option.data).map(|held| (held.preferred, held.valid))
                }
                DHCPv6OptionCode::IAPREFIX => {
                    DHCPv6IAPrefix::decode(&option.data).map(|held| (held.preferred, held.valid))
                }
                _ => return true,
            };
            lifetimes.is_ok_and(|(preferred, valid)| valid > 0 && preferred <= valid)
        });
        (!ia.lifetimes().is_empty()).then_some(ia)
    }

    /// The IA `seconds` later: its T1, T2 and lifetimes less them, infinity kept (§7.7).
    pub fn aged(&self, seconds: u32) -> DHCPv6IA {
        let less = |value: u32| if value == DHCPv6IA::INFINITY { value } else { value.saturating_sub(seconds) };
        let mut ia = DHCPv6IA { t1: less(self.t1), t2: less(self.t2), ..self.clone() };
        for option in &mut ia.options.entries {
            let aged = match option.code {
                DHCPv6OptionCode::IAADDR => DHCPv6IAAddress::decode(&option.data).and_then(|held| {
                    DHCPv6IAAddress { preferred: less(held.preferred), valid: less(held.valid), ..held }.encode()
                }),
                DHCPv6OptionCode::IAPREFIX => DHCPv6IAPrefix::decode(&option.data).and_then(|held| {
                    DHCPv6IAPrefix { preferred: less(held.preferred), valid: less(held.valid), ..held }.encode()
                }),
                _ => continue,
            };
            if let Ok(data) = aged {
                option.data = data;
            }
        }
        ia
    }

    /// The lifetimes of what the IA holds, preferred and valid: of its addresses or prefixes.
    pub fn lifetimes(&self) -> Vec<(u32, u32)> {
        let addresses = self.addresses().into_iter().map(|address| (address.preferred, address.valid));
        let prefixes = self.prefixes().into_iter().map(|prefix| (prefix.preferred, prefix.valid));
        addresses.chain(prefixes).collect()
    }
}

/// An IA Address option (§21.6).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv6IAAddress {
    pub address: IPv6Address,
    pub preferred: u32,
    pub valid: u32,
    pub options: DHCPv6Options,
}

impl DHCPv6IAAddress {
    pub fn decode(data: &[u8]) -> Result<DHCPv6IAAddress, DHCPError> {
        if data.len() < 24 {
            return Err(DHCPError::Malformed("an IA address cut short"));
        }
        let word = |at: usize| u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
        Ok(DHCPv6IAAddress {
            address: IPv6Address(data[..16].try_into().unwrap_or_default()),
            preferred: word(16),
            valid: word(20),
            options: DHCPv6Options::decode(&data[24..])?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, DHCPError> {
        let mut data = self.address.0.to_vec();
        data.extend_from_slice(&self.preferred.to_be_bytes());
        data.extend_from_slice(&self.valid.to_be_bytes());
        self.options.encode(&mut data)?;
        Ok(data)
    }
}

/// An IA Prefix option (§21.22).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv6IAPrefix {
    pub preferred: u32,
    pub valid: u32,
    pub length: u8,
    pub prefix: IPv6Address,
    pub options: DHCPv6Options,
}

impl DHCPv6IAPrefix {
    pub fn decode(data: &[u8]) -> Result<DHCPv6IAPrefix, DHCPError> {
        if data.len() < 25 {
            return Err(DHCPError::Malformed("an IA prefix cut short"));
        }
        let word = |at: usize| u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
        if data[8] > 128 {
            return Err(DHCPError::Malformed("a prefix longer than 128 bits"));
        }
        Ok(DHCPv6IAPrefix {
            preferred: word(0),
            valid: word(4),
            length: data[8],
            prefix: IPv6Address(data[9..25].try_into().unwrap_or_default()),
            options: DHCPv6Options::decode(&data[25..])?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, DHCPError> {
        if self.length > 128 {
            return Err(DHCPError::Malformed("a prefix longer than 128 bits"));
        }
        let mut data = Vec::with_capacity(25);
        data.extend_from_slice(&self.preferred.to_be_bytes());
        data.extend_from_slice(&self.valid.to_be_bytes());
        data.push(self.length);
        data.extend_from_slice(&self.prefix.0);
        self.options.encode(&mut data)?;
        Ok(data)
    }
}
