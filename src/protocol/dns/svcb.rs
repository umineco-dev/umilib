use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::protocol::ip::{IPv4Address, IPv6Address};

use super::{DNSError, DNSName, DNSToken};

/// The key of a service parameter (RFC 9460 §14.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DNSServiceKey(pub u16);

impl DNSServiceKey {
    pub const MANDATORY: DNSServiceKey = DNSServiceKey(0);
    pub const ALPN: DNSServiceKey = DNSServiceKey(1);
    pub const NO_DEFAULT_ALPN: DNSServiceKey = DNSServiceKey(2);
    pub const PORT: DNSServiceKey = DNSServiceKey(3);
    pub const IPV4HINT: DNSServiceKey = DNSServiceKey(4);
    /// The ECHConfigList of the service (RFC 9848 §2).
    pub const ECH: DNSServiceKey = DNSServiceKey(5);
    pub const IPV6HINT: DNSServiceKey = DNSServiceKey(6);
    /// The URI template of DNS over HTTPS (RFC 9461 §5).
    pub const DOHPATH: DNSServiceKey = DNSServiceKey(7);
    /// Oblivious HTTP (RFC 9540 §4).
    pub const OHTTP: DNSServiceKey = DNSServiceKey(8);
    /// The key reserved as invalid (RFC 9460 §14.3.2).
    pub const INVALID: DNSServiceKey = DNSServiceKey(65535);

    pub const NAMES: [(DNSServiceKey, &'static str); 9] = [
        (DNSServiceKey::MANDATORY, "mandatory"),
        (DNSServiceKey::ALPN, "alpn"),
        (DNSServiceKey::NO_DEFAULT_ALPN, "no-default-alpn"),
        (DNSServiceKey::PORT, "port"),
        (DNSServiceKey::IPV4HINT, "ipv4hint"),
        (DNSServiceKey::ECH, "ech"),
        (DNSServiceKey::IPV6HINT, "ipv6hint"),
        (DNSServiceKey::DOHPATH, "dohpath"),
        (DNSServiceKey::OHTTP, "ohttp"),
    ];

    /// The key of its name, or of "keyNNNNN" (RFC 9460 §2.1).
    pub fn parse(text: &str) -> Result<DNSServiceKey, DNSError> {
        if let Some((key, _)) = DNSServiceKey::NAMES.iter().find(|(_, name)| *name == text) {
            return Ok(*key);
        }
        let digits = text.strip_prefix("key").ok_or(DNSError::Syntax("not a service parameter key"))?;
        if digits.is_empty() || digits.len() > 5 || digits.starts_with('0') && digits.len() > 1 {
            return Err(DNSError::Syntax("not a service parameter key"));
        }
        let key = DNSServiceKey(digits.parse().map_err(|_| DNSError::Syntax("not a service parameter key"))?);
        if key == DNSServiceKey::INVALID {
            return Err(DNSError::Syntax("the invalid key"));
        }
        Ok(key)
    }
}

impl fmt::Display for DNSServiceKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match DNSServiceKey::NAMES.iter().find(|(key, _)| key == self) {
            Some((_, name)) => formatter.write_str(name),
            None => write!(formatter, "key{}", self.0),
        }
    }
}

/// The data of an SVCB or HTTPS record (RFC 9460 §2.2): its priority (0
/// for AliasMode), its target, and its parameters by increasing key, each
/// valid for its key. The typed accessors read them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSServiceBinding {
    pub priority: u16,
    pub target: DNSName,
    pub params: Vec<(DNSServiceKey, Vec<u8>)>,
}

impl DNSServiceBinding {
    /// A binding of `priority` and `target`, without parameters.
    pub fn new(priority: u16, target: DNSName) -> DNSServiceBinding {
        DNSServiceBinding { priority, target, params: Vec::new() }
    }

    pub fn is_alias(&self) -> bool {
        self.priority == 0
    }

    /// The binding of `bytes`, the parameters of the RDATA, checked (RFC 9460 §2.2).
    pub fn decode_params(priority: u16, target: DNSName, bytes: &[u8]) -> Result<DNSServiceBinding, DNSError> {
        let mut params = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let [high, low, length_high, length_low, tail @ ..] = rest else {
                return Err(DNSError::Malformed("a service parameter cut short"));
            };
            let length = usize::from(u16::from_be_bytes([*length_high, *length_low]));
            let value = tail.get(..length).ok_or(DNSError::Malformed("a service parameter cut short"))?;
            params.push((DNSServiceKey(u16::from_be_bytes([*high, *low])), value.to_vec()));
            rest = &tail[length..];
        }
        let binding = DNSServiceBinding { priority, target, params };
        binding.check().map_err(|_| DNSError::Malformed("invalid service parameters"))?;
        Ok(binding)
    }

    /// Checks the rules of the parameters (RFC 9460 §2.2, §7, §8): keys
    /// strictly increasing, never the invalid one, each value of its key's
    /// form, and the keys of "mandatory" present and not "mandatory" itself.
    pub fn check(&self) -> Result<(), DNSError> {
        let invalid = DNSError::Syntax;
        for pair in self.params.windows(2) {
            if pair[0].0 >= pair[1].0 {
                return Err(invalid("service parameter keys not in increasing order"));
            }
        }
        for (key, value) in &self.params {
            let valid = match *key {
                DNSServiceKey::INVALID => false,
                DNSServiceKey::MANDATORY => {
                    value.len() >= 2
                        && value.len() % 2 == 0
                        && DNSServiceBinding::keys_of(value).windows(2).all(|pair| pair[0] < pair[1])
                }
                DNSServiceKey::ALPN => DNSServiceBinding::strings_of(value).is_some_and(|ids| !ids.is_empty()),
                DNSServiceKey::NO_DEFAULT_ALPN => value.is_empty(),
                DNSServiceKey::PORT => value.len() == 2,
                DNSServiceKey::IPV4HINT => !value.is_empty() && value.len() % 4 == 0,
                DNSServiceKey::IPV6HINT => !value.is_empty() && value.len() % 16 == 0,
                DNSServiceKey::ECH => !value.is_empty(),
                DNSServiceKey::OHTTP => value.is_empty(),
                _ => true,
            };
            if !valid {
                return Err(invalid("a service parameter of the wrong form for its key"));
            }
        }
        if let Some(mandatory) = self.value(DNSServiceKey::MANDATORY) {
            for key in DNSServiceBinding::keys_of(mandatory) {
                if key == DNSServiceKey::MANDATORY || self.value(key).is_none() {
                    return Err(invalid("a mandatory key missing, or mandatory itself"));
                }
            }
        }
        // no-default-alpn needs alpn (RFC 9460 §7.1.1).
        if self.value(DNSServiceKey::NO_DEFAULT_ALPN).is_some() && self.value(DNSServiceKey::ALPN).is_none() {
            return Err(invalid("no-default-alpn without alpn"));
        }
        Ok(())
    }

    /// Appends the RDATA.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.priority.to_be_bytes());
        self.target.encode(out, None);
        for (key, value) in &self.params {
            out.extend_from_slice(&key.0.to_be_bytes());
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
        }
    }

    /// The value of `key`, if present.
    pub fn value(&self, key: DNSServiceKey) -> Option<&[u8]> {
        self.params.iter().find(|(found, _)| *found == key).map(|(_, value)| value.as_slice())
    }

    /// Sets `key` to `value`, keeping the keys in order.
    pub fn set(&mut self, key: DNSServiceKey, value: &[u8]) {
        match self.params.binary_search_by_key(&key, |(found, _)| *found) {
            Ok(index) => self.params[index].1 = value.to_vec(),
            Err(index) => self.params.insert(index, (key, value.to_vec())),
        }
    }

    /// The protocols of "alpn", which are those of the service with the
    /// default one unless "no-default-alpn" (RFC 9460 §7.1).
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        self.value(DNSServiceKey::ALPN).and_then(DNSServiceBinding::strings_of).unwrap_or_default()
    }

    /// The port of "port"; `None` without one, or with a value not of 2 bytes (RFC 9460 §7.2).
    pub fn port(&self) -> Option<u16> {
        self.value(DNSServiceKey::PORT).and_then(|value| value.try_into().ok()).map(u16::from_be_bytes)
    }

    pub fn ipv4_hints(&self) -> Vec<IPv4Address> {
        let value = self.value(DNSServiceKey::IPV4HINT).unwrap_or_default();
        value.as_chunks::<4>().0.iter().map(|chunk| IPv4Address(*chunk)).collect()
    }

    pub fn ipv6_hints(&self) -> Vec<IPv6Address> {
        let value = self.value(DNSServiceKey::IPV6HINT).unwrap_or_default();
        value.as_chunks::<16>().0.iter().map(|chunk| IPv6Address(*chunk)).collect()
    }

    /// The ECHConfigList of the service, for TLS's ECH (RFC 9848 §2).
    pub fn ech(&self) -> Option<&[u8]> {
        self.value(DNSServiceKey::ECH)
    }

    /// The keys of a "mandatory" value.
    pub fn keys_of(value: &[u8]) -> Vec<DNSServiceKey> {
        value.as_chunks::<2>().0.iter().map(|pair| DNSServiceKey(u16::from_be_bytes(*pair))).collect()
    }

    /// The length-prefixed strings of an "alpn" value, none empty; `None` if they do not fill it.
    pub fn strings_of(value: &[u8]) -> Option<Vec<Vec<u8>>> {
        let mut strings = Vec::new();
        let mut rest = value;
        while let [length, tail @ ..] = rest {
            let length = *length as usize;
            if length == 0 || tail.len() < length {
                return None;
            }
            strings.push(tail[..length].to_vec());
            rest = &tail[length..];
        }
        Some(strings)
    }

    /// The parameters of the presentation format's `tokens` (RFC 9460 §2.1,
    /// Appendix A): `key=value`, the value possibly quoted, lists split by
    /// commas that are not escaped.
    pub fn parse_params(priority: u16, target: DNSName, tokens: &[DNSToken]) -> Result<DNSServiceBinding, DNSError> {
        let syntax = DNSError::Syntax;
        let mut binding = DNSServiceBinding::new(priority, target);
        let mut index = 0;
        while index < tokens.len() {
            let token = &tokens[index];
            index += 1;
            let text = token.text.clone();
            let (key, raw) = match text.iter().position(|byte| *byte == b'=') {
                Some(equals) => {
                    let key = core::str::from_utf8(&text[..equals]).map_err(|_| syntax("not a key"))?;
                    let mut value = DNSToken { text: text[equals + 1..].to_vec(), quoted: false };
                    // `key="value"`: the value came as the next token, quoted.
                    if value.text.is_empty() && tokens.get(index).is_some_and(|next| next.quoted) {
                        value = tokens[index].clone();
                        index += 1;
                    }
                    (DNSServiceKey::parse(key)?, Some(value))
                }
                None => (DNSServiceKey::parse(token.as_str()?)?, None),
            };
            if binding.value(key).is_some() {
                return Err(syntax("a service parameter key repeated"));
            }
            let value = match (key, raw) {
                (DNSServiceKey::NO_DEFAULT_ALPN | DNSServiceKey::OHTTP, None) => Vec::new(),
                (_, None) => return Err(syntax("a service parameter without its value")),
                (DNSServiceKey::NO_DEFAULT_ALPN | DNSServiceKey::OHTTP, Some(_)) => {
                    return Err(syntax("a value for a key that takes none"));
                }
                (key, Some(raw)) => DNSServiceBinding::parse_value(key, &raw)?,
            };
            binding.set(key, &value);
        }
        binding.check()?;
        Ok(binding)
    }

    /// The wire form of the presentation value `raw` of `key`.
    pub fn parse_value(key: DNSServiceKey, raw: &DNSToken) -> Result<Vec<u8>, DNSError> {
        let syntax = DNSError::Syntax;
        let unescaped = raw.unescaped()?;
        let items = || DNSServiceBinding::split_list(&unescaped);
        let value = match key {
            DNSServiceKey::MANDATORY => {
                let mut keys = Vec::new();
                for item in items()? {
                    keys.push(DNSServiceKey::parse(core::str::from_utf8(&item).map_err(|_| syntax("not a key"))?)?);
                }
                keys.sort();
                keys.dedup();
                keys.iter().flat_map(|key| key.0.to_be_bytes()).collect()
            }
            DNSServiceKey::ALPN => {
                let mut out = Vec::new();
                for item in items()? {
                    if item.is_empty() || item.len() > 255 {
                        return Err(syntax("an empty or long alpn"));
                    }
                    out.push(item.len() as u8);
                    out.extend_from_slice(&item);
                }
                out
            }
            DNSServiceKey::PORT => {
                let text = core::str::from_utf8(&unescaped).map_err(|_| syntax("not a port"))?;
                text.parse::<u16>().map_err(|_| syntax("not a port"))?.to_be_bytes().to_vec()
            }
            DNSServiceKey::IPV4HINT => {
                let mut out = Vec::new();
                for item in items()? {
                    let text = core::str::from_utf8(&item).map_err(|_| syntax("not an address"))?;
                    out.extend_from_slice(&text.parse::<IPv4Address>().map_err(|_| syntax("not an IPv4 address"))?.0);
                }
                out
            }
            DNSServiceKey::IPV6HINT => {
                let mut out = Vec::new();
                for item in items()? {
                    let text = core::str::from_utf8(&item).map_err(|_| syntax("not an address"))?;
                    out.extend_from_slice(&text.parse::<IPv6Address>().map_err(|_| syntax("not an IPv6 address"))?.0);
                }
                out
            }
            DNSServiceKey::ECH => DNSToken::base64(&unescaped)?,
            _ => unescaped,
        };
        Ok(value)
    }

    /// The items of a comma-separated list (RFC 9460 Appendix A.1), from a
    /// value whose character-string escapes were already replaced: a
    /// backslash escapes the next byte (a comma or a backslash of an item).
    pub fn split_list(value: &[u8]) -> Result<Vec<Vec<u8>>, DNSError> {
        let mut items = Vec::new();
        let mut item = Vec::new();
        let mut index = 0;
        while index < value.len() {
            match value[index] {
                b',' => items.push(core::mem::take(&mut item)),
                b'\\' => {
                    index += 1;
                    item.push(*value.get(index).ok_or(DNSError::Syntax("an escape at the end of a list"))?);
                }
                byte => item.push(byte),
            }
            index += 1;
        }
        items.push(item);
        Ok(items)
    }

    /// The items as a list: each comma and backslash of an item escaped
    /// (RFC 9460 Appendix A.1), then quoted as a character-string.
    pub fn join_list(items: &[Vec<u8>]) -> String {
        let mut listed = Vec::new();
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                listed.push(b',');
            }
            for &byte in item {
                if byte == b',' || byte == b'\\' {
                    listed.push(b'\\');
                }
                listed.push(byte);
            }
        }
        DNSToken::quote(&listed)
    }
}

/// The presentation format: priority, target, then each parameter.
impl fmt::Display for DNSServiceBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.priority, self.target)?;
        for (key, value) in &self.params {
            match *key {
                DNSServiceKey::NO_DEFAULT_ALPN | DNSServiceKey::OHTTP if value.is_empty() => write!(f, " {key}")?,
                DNSServiceKey::MANDATORY => {
                    let keys: Vec<String> =
                        DNSServiceBinding::keys_of(value).iter().map(|key| alloc::format!("{key}")).collect();
                    write!(f, " {key}={}", keys.join(","))?;
                }
                DNSServiceKey::ALPN => {
                    let ids = DNSServiceBinding::strings_of(value).unwrap_or_default();
                    write!(f, " {key}={}", DNSServiceBinding::join_list(&ids))?;
                }
                DNSServiceKey::PORT if value.len() == 2 => {
                    write!(f, " {key}={}", u16::from_be_bytes([value[0], value[1]]))?
                }
                DNSServiceKey::IPV4HINT => {
                    let hints: Vec<String> = self.ipv4_hints().iter().map(|hint| alloc::format!("{hint}")).collect();
                    write!(f, " {key}={}", hints.join(","))?;
                }
                DNSServiceKey::IPV6HINT => {
                    let hints: Vec<String> = self.ipv6_hints().iter().map(|hint| alloc::format!("{hint}")).collect();
                    write!(f, " {key}={}", hints.join(","))?;
                }
                DNSServiceKey::ECH => write!(f, " {key}={}", Base64::STANDARD.encode(value))?,
                _ => write!(f, " {key}={}", DNSToken::quote(value))?,
            }
        }
        Ok(())
    }
}
