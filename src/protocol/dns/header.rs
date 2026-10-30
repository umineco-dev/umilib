use super::{DNSError, DNSOpcode};

/// The header of a message (RFC 1035 §4.1.1, RFC 2535 §6.1 for AD and CD)
/// without its counts, which the message's sections give.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DNSHeader {
    pub id: u16,
    /// Whether it is a response.
    pub response: bool,
    pub opcode: DNSOpcode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    /// The Z bit, which must be zero (RFC 1035 §4.1.1): kept as received.
    pub z: bool,
    /// AD: the answer was validated by DNSSEC (RFC 4035 §3.2.3, RFC 6840 §5.7).
    pub authentic_data: bool,
    /// CD: the client validates itself (RFC 4035 §3.2.2).
    pub checking_disabled: bool,
    /// The low 4 bits of the response code; EDNS carries the rest.
    pub rcode: u8,
}

impl Default for DNSOpcode {
    fn default() -> DNSOpcode {
        DNSOpcode::QUERY
    }
}

impl DNSHeader {
    pub const LENGTH: usize = 12;

    /// The header and the four counts at the start of `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<(DNSHeader, [u16; 4]), DNSError> {
        let bytes: &[u8; 12] =
            bytes.get(..12).and_then(|bytes| bytes.try_into().ok()).ok_or(DNSError::Malformed("a header cut short"))?;
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let header = DNSHeader {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            response: flags & 0x8000 != 0,
            opcode: DNSOpcode((flags >> 11 & 0xF) as u8),
            authoritative: flags & 0x0400 != 0,
            truncated: flags & 0x0200 != 0,
            recursion_desired: flags & 0x0100 != 0,
            recursion_available: flags & 0x0080 != 0,
            z: flags & 0x0040 != 0,
            authentic_data: flags & 0x0020 != 0,
            checking_disabled: flags & 0x0010 != 0,
            rcode: (flags & 0xF) as u8,
        };
        let count = |index: usize| u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        Ok((header, [count(4), count(6), count(8), count(10)]))
    }

    /// Appends the header with `counts` (questions, answers, authorities, additionals).
    pub fn encode(&self, counts: [u16; 4], out: &mut alloc::vec::Vec<u8>) {
        let mut flags = u16::from(self.opcode.0 & 0xF) << 11 | u16::from(self.rcode & 0xF);
        for (bit, set) in [
            (0x8000, self.response),
            (0x0400, self.authoritative),
            (0x0200, self.truncated),
            (0x0100, self.recursion_desired),
            (0x0080, self.recursion_available),
            (0x0040, self.z),
            (0x0020, self.authentic_data),
            (0x0010, self.checking_disabled),
        ] {
            if set {
                flags |= bit;
            }
        }
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        for count in counts {
            out.extend_from_slice(&count.to_be_bytes());
        }
    }
}
