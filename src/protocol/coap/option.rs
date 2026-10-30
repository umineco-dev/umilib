use alloc::string::String;
use alloc::vec::Vec;

use super::{CoAPContentFormat, CoAPError};

/// The number of an option (RFC 7252 §5.4, §12.2, IANA's registry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoAPOptionNumber(pub u16);

/// The format of an option's value (RFC 7252 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoAPOptionFormat {
    Empty,
    Opaque,
    Uint,
    String,
}

impl CoAPOptionNumber {
    pub const IF_MATCH: CoAPOptionNumber = CoAPOptionNumber(1);
    pub const URI_HOST: CoAPOptionNumber = CoAPOptionNumber(3);
    pub const ETAG: CoAPOptionNumber = CoAPOptionNumber(4);
    pub const IF_NONE_MATCH: CoAPOptionNumber = CoAPOptionNumber(5);
    /// RFC 7641 §2.
    pub const OBSERVE: CoAPOptionNumber = CoAPOptionNumber(6);
    pub const URI_PORT: CoAPOptionNumber = CoAPOptionNumber(7);
    pub const LOCATION_PATH: CoAPOptionNumber = CoAPOptionNumber(8);
    pub const URI_PATH: CoAPOptionNumber = CoAPOptionNumber(11);
    pub const CONTENT_FORMAT: CoAPOptionNumber = CoAPOptionNumber(12);
    pub const MAX_AGE: CoAPOptionNumber = CoAPOptionNumber(14);
    pub const URI_QUERY: CoAPOptionNumber = CoAPOptionNumber(15);
    pub const ACCEPT: CoAPOptionNumber = CoAPOptionNumber(17);
    pub const LOCATION_QUERY: CoAPOptionNumber = CoAPOptionNumber(20);
    /// RFC 7959 §2.1.
    pub const BLOCK2: CoAPOptionNumber = CoAPOptionNumber(23);
    pub const BLOCK1: CoAPOptionNumber = CoAPOptionNumber(27);
    pub const SIZE2: CoAPOptionNumber = CoAPOptionNumber(28);
    pub const PROXY_URI: CoAPOptionNumber = CoAPOptionNumber(35);
    pub const PROXY_SCHEME: CoAPOptionNumber = CoAPOptionNumber(39);
    pub const SIZE1: CoAPOptionNumber = CoAPOptionNumber(60);

    /// Critical: an endpoint that does not know it cannot ignore it (§5.4.1).
    pub fn is_critical(&self) -> bool {
        self.0 & 1 != 0
    }

    /// Unsafe to forward by a proxy that does not know it (§5.4.2).
    pub fn is_unsafe(&self) -> bool {
        self.0 & 2 != 0
    }

    /// Not part of the cache key (§5.4.2, §5.4.6).
    pub fn is_no_cache_key(&self) -> bool {
        self.0 & 0x1e == 0x1c
    }

    /// The definition of a known option: its format, least and greatest
    /// length, and whether it may repeat (RFC 7252 table 4, RFC 7641 §2,
    /// RFC 7959 table 1 and table 2).
    pub fn definition(&self) -> Option<(CoAPOptionFormat, usize, usize, bool)> {
        use CoAPOptionFormat::{Empty, Opaque, String, Uint};
        Some(match *self {
            CoAPOptionNumber::IF_MATCH => (Opaque, 0, 8, true),
            CoAPOptionNumber::URI_HOST => (String, 1, 255, false),
            CoAPOptionNumber::ETAG => (Opaque, 1, 8, true),
            CoAPOptionNumber::IF_NONE_MATCH => (Empty, 0, 0, false),
            CoAPOptionNumber::OBSERVE => (Uint, 0, 3, false),
            CoAPOptionNumber::URI_PORT => (Uint, 0, 2, false),
            CoAPOptionNumber::LOCATION_PATH => (String, 0, 255, true),
            CoAPOptionNumber::URI_PATH => (String, 0, 255, true),
            CoAPOptionNumber::CONTENT_FORMAT => (Uint, 0, 2, false),
            CoAPOptionNumber::MAX_AGE => (Uint, 0, 4, false),
            CoAPOptionNumber::URI_QUERY => (String, 0, 255, true),
            CoAPOptionNumber::ACCEPT => (Uint, 0, 2, false),
            CoAPOptionNumber::LOCATION_QUERY => (String, 0, 255, true),
            CoAPOptionNumber::BLOCK2 | CoAPOptionNumber::BLOCK1 => (Uint, 0, 3, false),
            CoAPOptionNumber::SIZE2 | CoAPOptionNumber::SIZE1 => (Uint, 0, 4, false),
            CoAPOptionNumber::PROXY_URI => (String, 1, 1034, false),
            CoAPOptionNumber::PROXY_SCHEME => (String, 1, 255, false),
            _ => return None,
        })
    }
}

/// The options of a message, in the order of their numbers, repeated ones
/// in the order given (RFC 7252 §3.1, §5.4.5).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CoAPOptions {
    pub entries: Vec<(CoAPOptionNumber, Vec<u8>)>,
}

impl CoAPOptions {
    pub fn new() -> CoAPOptions {
        CoAPOptions { entries: Vec::new() }
    }

    /// Adds an option after those of its number and before greater ones.
    pub fn push(&mut self, number: CoAPOptionNumber, value: Vec<u8>) {
        let at = self.entries.iter().position(|(found, _)| *found > number).unwrap_or(self.entries.len());
        self.entries.insert(at, (number, value));
    }

    /// Sets the one option `number`, replacing those there are.
    pub fn set(&mut self, number: CoAPOptionNumber, value: Vec<u8>) {
        self.remove(number);
        self.push(number, value);
    }

    pub fn remove(&mut self, number: CoAPOptionNumber) {
        self.entries.retain(|(found, _)| *found != number);
    }

    pub fn get(&self, number: CoAPOptionNumber) -> Option<&[u8]> {
        self.entries.iter().find(|(found, _)| *found == number).map(|(_, value)| value.as_slice())
    }

    pub fn all(&self, number: CoAPOptionNumber) -> impl Iterator<Item = &[u8]> {
        self.entries.iter().filter(move |(found, _)| *found == number).map(|(_, value)| value.as_slice())
    }

    pub fn contains(&self, number: CoAPOptionNumber) -> bool {
        self.get(number).is_some()
    }

    /// The bytes of the uint `value`, without leading zeros (§3.2).
    pub fn uint_bytes(value: u32) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
        bytes[zeros..].to_vec()
    }

    /// The uint of `bytes`, of at most 4 (§3.2).
    pub fn uint_of(bytes: &[u8]) -> Option<u32> {
        (bytes.len() <= 4).then(|| bytes.iter().fold(0u32, |value, byte| value << 8 | u32::from(*byte)))
    }

    pub fn uint(&self, number: CoAPOptionNumber) -> Option<u32> {
        CoAPOptions::uint_of(self.get(number)?)
    }

    pub fn set_uint(&mut self, number: CoAPOptionNumber, value: u32) {
        self.set(number, CoAPOptions::uint_bytes(value));
    }

    /// The first option that makes the message one to reject (§5.4.1,
    /// §5.4.3, §5.4.5): a critical option unknown, of a value its
    /// definition does not allow, or repeated though it may not be.
    /// Elective ones so are ignored ([`CoAPOptions::usable`]).
    pub fn check(&self) -> Result<(), CoAPOptionNumber> {
        for (index, (number, value)) in self.entries.iter().enumerate() {
            if !number.is_critical() {
                continue;
            }
            let Some((format, least, greatest, repeatable)) = number.definition() else { return Err(*number) };
            let repeated = index > 0 && self.entries[index - 1].0 == *number;
            if value.len() < least || value.len() > greatest || (repeated && !repeatable) {
                return Err(*number);
            }
            if format == CoAPOptionFormat::String && core::str::from_utf8(value).is_err() {
                return Err(*number);
            }
        }
        Ok(())
    }

    /// The options without the elective ones to ignore: unknown, of a value
    /// out of their definition, or repeated beyond the first (§5.4.1, §5.4.5).
    pub fn usable(&self) -> CoAPOptions {
        let mut usable = CoAPOptions::new();
        for (index, (number, value)) in self.entries.iter().enumerate() {
            if !number.is_critical() {
                let Some((_, least, greatest, repeatable)) = number.definition() else { continue };
                let repeated = index > 0 && self.entries[index - 1].0 == *number;
                if value.len() < least || value.len() > greatest || (repeated && !repeatable) {
                    continue;
                }
            }
            usable.entries.push((*number, value.clone()));
        }
        usable
    }

    /// The path of Uri-Path options (§6.5), each segment as given.
    pub fn path(&self) -> Vec<String> {
        self.all(CoAPOptionNumber::URI_PATH).map(|segment| String::from_utf8_lossy(segment).into_owned()).collect()
    }

    pub fn queries(&self) -> Vec<String> {
        self.all(CoAPOptionNumber::URI_QUERY).map(|query| String::from_utf8_lossy(query).into_owned()).collect()
    }

    /// Sets the Uri-Path options of `path` ("/a/b"), and the Uri-Query
    /// options of `query` ("x=1&y"), as §6.4 splits a URI.
    pub fn set_uri(&mut self, path: &str, query: Option<&str>) {
        self.remove(CoAPOptionNumber::URI_PATH);
        self.remove(CoAPOptionNumber::URI_QUERY);
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            self.push(CoAPOptionNumber::URI_PATH, segment.as_bytes().to_vec());
        }
        for part in query.unwrap_or_default().split('&').filter(|part| !part.is_empty()) {
            self.push(CoAPOptionNumber::URI_QUERY, part.as_bytes().to_vec());
        }
    }

    pub fn content_format(&self) -> Option<CoAPContentFormat> {
        self.uint(CoAPOptionNumber::CONTENT_FORMAT).map(|value| CoAPContentFormat(value as u16))
    }

    /// The Max-Age in seconds: 60 without the option (§5.10.5).
    pub fn max_age(&self) -> u32 {
        self.uint(CoAPOptionNumber::MAX_AGE).unwrap_or(60)
    }

    /// The Observe value (RFC 7641 §2): of 24 bits.
    pub fn observe(&self) -> Option<u32> {
        self.uint(CoAPOptionNumber::OBSERVE).map(|value| value & 0xFF_FFFF)
    }

    pub fn block(&self, number: CoAPOptionNumber) -> Option<Result<CoAPBlock, CoAPError>> {
        self.get(number).map(CoAPBlock::decode)
    }
}

/// A Block1 or Block2 option (RFC 7959 §2.2): the block's number, whether
/// more follow, and its size as SZX, 2^(SZX + 4) bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CoAPBlock {
    pub number: u32,
    pub more: bool,
    pub exponent: u8,
}

impl CoAPBlock {
    /// The largest block number: of 20 bits (§2.2).
    pub const MAXIMUM_NUMBER: u32 = (1 << 20) - 1;

    /// The block of a size in bytes, 16 to 1024 in powers of 2.
    pub fn new(number: u32, more: bool, size: usize) -> Result<CoAPBlock, CoAPError> {
        let exponent = match size {
            16 => 0,
            32 => 1,
            64 => 2,
            128 => 3,
            256 => 4,
            512 => 5,
            1024 => 6,
            _ => return Err(CoAPError::Option("a block size not of 16 to 1024 in powers of 2")),
        };
        if number > CoAPBlock::MAXIMUM_NUMBER {
            return Err(CoAPError::Option("a block number of more than 20 bits"));
        }
        Ok(CoAPBlock { number, more, exponent })
    }

    /// The option's value; SZX 7 is reserved and an error (§2.2).
    pub fn decode(value: &[u8]) -> Result<CoAPBlock, CoAPError> {
        let raw = CoAPOptions::uint_of(value)
            .filter(|_| value.len() <= 3)
            .ok_or(CoAPError::Option("a block option longer than 3 bytes"))?;
        let exponent = (raw & 7) as u8;
        if exponent == 7 {
            return Err(CoAPError::Option("a block size of the reserved SZX 7"));
        }
        Ok(CoAPBlock { number: raw >> 4, more: raw & 8 != 0, exponent })
    }

    pub fn encode(&self) -> Vec<u8> {
        CoAPOptions::uint_bytes(self.number << 4 | u32::from(self.more) << 3 | u32::from(self.exponent))
    }

    pub fn size(&self) -> usize {
        1 << (usize::from(self.exponent) + 4)
    }

    /// The offset of the block in the whole body (§2.2).
    pub fn offset(&self) -> usize {
        self.number as usize * self.size()
    }

    /// The block of `body` at this block's number and size, and whether more follow (§2.4).
    pub fn slice<'a>(&self, body: &'a [u8]) -> Option<(&'a [u8], bool)> {
        let start = self.offset();
        if start > body.len() || (start == body.len() && start != 0) {
            return None;
        }
        let end = (start + self.size()).min(body.len());
        Some((&body[start..end], end < body.len()))
    }
}
