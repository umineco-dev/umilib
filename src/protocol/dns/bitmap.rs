use alloc::vec::Vec;
use core::fmt;

use super::{DNSError, DNSType};

/// The types of an NSEC or NSEC3 record: its type bitmap (RFC 4034 §4.1.2),
/// kept sorted and without repeats.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DNSTypeBitmap {
    pub types: Vec<DNSType>,
}

impl DNSTypeBitmap {
    pub fn new(types: &[DNSType]) -> DNSTypeBitmap {
        let mut types = types.to_vec();
        types.sort();
        types.dedup();
        DNSTypeBitmap { types }
    }

    pub fn contains(&self, kind: DNSType) -> bool {
        self.types.binary_search(&kind).is_ok()
    }

    /// The bitmap of `bytes`: windows in increasing order, each of 1 to 32
    /// bytes, its last byte not zero (RFC 4034 §4.1.2).
    pub fn decode(bytes: &[u8]) -> Result<DNSTypeBitmap, DNSError> {
        let malformed = DNSError::Malformed;
        let mut types = Vec::new();
        let mut rest = bytes;
        let mut previous: Option<u8> = None;
        while let [window, length, tail @ ..] = rest {
            let length = *length as usize;
            if previous.is_some_and(|previous| *window <= previous) {
                return Err(malformed("type bitmap windows out of order"));
            }
            if !(1..=32).contains(&length) || tail.len() < length || tail[length - 1] == 0 {
                return Err(malformed("a type bitmap window of a wrong length"));
            }
            for (index, byte) in tail[..length].iter().enumerate() {
                for bit in 0..8 {
                    if byte & (0x80 >> bit) != 0 {
                        types.push(DNSType(u16::from(*window) << 8 | (index * 8 + bit) as u16));
                    }
                }
            }
            previous = Some(*window);
            rest = &tail[length..];
        }
        if !rest.is_empty() {
            return Err(malformed("a type bitmap cut short"));
        }
        Ok(DNSTypeBitmap { types })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut index = 0;
        while index < self.types.len() {
            let window = (self.types[index].0 >> 8) as u8;
            let mut bits = [0u8; 32];
            let mut length = 0;
            while index < self.types.len() && (self.types[index].0 >> 8) as u8 == window {
                let low = (self.types[index].0 & 0xFF) as usize;
                bits[low / 8] |= 0x80 >> (low % 8);
                length = low / 8 + 1;
                index += 1;
            }
            out.extend_from_slice(&[window, length as u8]);
            out.extend_from_slice(&bits[..length]);
        }
    }
}

/// The types, each after a space.
impl fmt::Display for DNSTypeBitmap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for kind in &self.types {
            write!(formatter, " {kind}")?;
        }
        Ok(())
    }
}
