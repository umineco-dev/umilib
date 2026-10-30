use alloc::vec::Vec;

use super::{CoAPCode, CoAPError, CoAPOptionNumber, CoAPOptions, CoAPType};

/// A CoAP message (RFC 7252 §3): its type, code, Message ID, token (of up
/// to 65804 bytes, RFC 8974 §2.1), options and payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoAPMessage {
    pub kind: CoAPType,
    pub code: CoAPCode,
    pub id: u16,
    pub token: Vec<u8>,
    pub options: CoAPOptions,
    pub payload: Vec<u8>,
}

impl CoAPMessage {
    pub const VERSION: u8 = 1;
    /// The default port of CoAP over UDP (RFC 7252 §6.1).
    pub const PORT: u16 = 5683;
    /// The largest token (RFC 8974 §2.1).
    pub const MAXIMUM_TOKEN: usize = 65804;

    pub fn new(kind: CoAPType, code: CoAPCode, id: u16) -> CoAPMessage {
        CoAPMessage { kind, code, id, token: Vec::new(), options: CoAPOptions::new(), payload: Vec::new() }
    }

    /// An empty message of `kind` and `id`: an ACK or a RST (§4.1, §4.2).
    pub fn empty(kind: CoAPType, id: u16) -> CoAPMessage {
        CoAPMessage::new(kind, CoAPCode::EMPTY, id)
    }

    /// The message of `bytes` (§3): a message format error for another
    /// version, a token length of 15, an option of delta or length 15 but
    /// the payload marker, a marker without payload, or an empty message
    /// with a token, options or payload (§4.1).
    pub fn decode(bytes: &[u8]) -> Result<CoAPMessage, CoAPError> {
        let [first, code, high, low, rest @ ..] = bytes else {
            return Err(CoAPError::Malformed("a message shorter than its header"));
        };
        if first >> 6 != CoAPMessage::VERSION {
            return Err(CoAPError::Malformed("a version other than 1"));
        }
        let kind = CoAPType::from_bits(first >> 4);
        let (length, mut rest) = match first & 15 {
            length @ 0..=12 => (usize::from(length), rest),
            13 => {
                let [extended, rest @ ..] = rest else { return Err(CoAPError::Malformed("a token length cut short")) };
                (usize::from(*extended) + 13, rest)
            }
            14 => {
                let [high, low, rest @ ..] = rest else { return Err(CoAPError::Malformed("a token length cut short")) };
                (usize::from(u16::from_be_bytes([*high, *low])) + 269, rest)
            }
            _ => return Err(CoAPError::Malformed("the reserved token length 15")),
        };
        let token = rest.get(..length).ok_or(CoAPError::Malformed("a token cut short"))?.to_vec();
        rest = &rest[length..];
        let mut options = CoAPOptions::new();
        let mut number: u32 = 0;
        let mut payload = Vec::new();
        while let [header, tail @ ..] = rest {
            if *header == 0xFF {
                if tail.is_empty() {
                    return Err(CoAPError::Malformed("a payload marker without payload"));
                }
                payload = tail.to_vec();
                break;
            }
            let (delta, tail) = CoAPMessage::extended(header >> 4, tail)?;
            let (length, tail) = CoAPMessage::extended(header & 15, tail)?;
            number += delta;
            let number = u16::try_from(number).map_err(|_| CoAPError::Malformed("an option number above 65535"))?;
            let value = tail.get(..length as usize).ok_or(CoAPError::Malformed("an option cut short"))?;
            options.entries.push((CoAPOptionNumber(number), value.to_vec()));
            rest = &tail[length as usize..];
        }
        let code = CoAPCode(*code);
        if code.is_empty() && (length != 0 || !options.entries.is_empty() || !payload.is_empty() || bytes.len() != 4) {
            return Err(CoAPError::Malformed("an empty message that is not empty"));
        }
        Ok(CoAPMessage { kind, code, id: u16::from_be_bytes([*high, *low]), token, options, payload })
    }

    /// An option's delta or length of `nibble` and its extension (§3.1): 13
    /// and 14 extend by one and two bytes; 15 is an error.
    pub fn extended(nibble: u8, bytes: &[u8]) -> Result<(u32, &[u8]), CoAPError> {
        match nibble {
            0..=12 => Ok((u32::from(nibble), bytes)),
            13 => match bytes {
                [extended, rest @ ..] => Ok((u32::from(*extended) + 13, rest)),
                [] => Err(CoAPError::Malformed("an option header cut short")),
            },
            14 => match bytes {
                [high, low, rest @ ..] => Ok((u32::from(u16::from_be_bytes([*high, *low])) + 269, rest)),
                _ => Err(CoAPError::Malformed("an option header cut short")),
            },
            _ => Err(CoAPError::Malformed("an option delta or length of 15")),
        }
    }

    /// The nibble and extension of a delta or length (§3.1).
    pub fn nibble(value: usize, extension: &mut Vec<u8>) -> u8 {
        match value {
            0..=12 => value as u8,
            13..=268 => {
                extension.push((value - 13) as u8);
                13
            }
            _ => {
                extension.extend_from_slice(&((value - 269) as u16).to_be_bytes());
                14
            }
        }
    }

    /// The message (§3); fails for a token or an option value above its largest length.
    pub fn encode(&self) -> Result<Vec<u8>, CoAPError> {
        if self.token.len() > CoAPMessage::MAXIMUM_TOKEN {
            return Err(CoAPError::TooLarge);
        }
        let mut extension = Vec::new();
        let token_nibble = CoAPMessage::nibble(self.token.len(), &mut extension);
        let mut out = Vec::with_capacity(4 + self.token.len() + self.payload.len() + 16);
        out.push(CoAPMessage::VERSION << 6 | self.kind.bits() << 4 | token_nibble);
        out.push(self.code.0);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&extension);
        out.extend_from_slice(&self.token);
        let mut options = self.options.entries.clone();
        options.sort_by_key(|(number, _)| *number);
        let mut previous = 0usize;
        for (number, value) in &options {
            if value.len() > 65_535 + 269 {
                return Err(CoAPError::TooLarge);
            }
            let mut extensions = Vec::new();
            let delta = CoAPMessage::nibble(usize::from(number.0) - previous, &mut extensions);
            let mut lengths = Vec::new();
            let length = CoAPMessage::nibble(value.len(), &mut lengths);
            out.push(delta << 4 | length);
            out.extend_from_slice(&extensions);
            out.extend_from_slice(&lengths);
            out.extend_from_slice(value);
            previous = usize::from(number.0);
        }
        if !self.payload.is_empty() {
            out.push(0xFF);
            out.extend_from_slice(&self.payload);
        }
        Ok(out)
    }

    /// The header fields of `bytes`, if it has a header: its type and ID,
    /// to reject (RST) a message that cannot be read otherwise (§4.2, §4.3).
    pub fn header(bytes: &[u8]) -> Option<(CoAPType, u16)> {
        let [first, _, high, low, ..] = bytes else { return None };
        (first >> 6 == CoAPMessage::VERSION)
            .then(|| (CoAPType::from_bits(first >> 4), u16::from_be_bytes([*high, *low])))
    }
}
