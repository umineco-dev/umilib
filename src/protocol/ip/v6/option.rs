use crate::bytes::Writer;

use super::super::IPProtocol;
use super::IPv6Error;

/// The Option Type of an option of a Hop-by-Hop or Destination Options
/// header (RFC 8200 §4.2), from the IANA registry "Destination Options and
/// Hop-by-Hop Options".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct IPv6OptionKind(pub u8);

impl IPv6OptionKind {
    pub const PAD1: IPv6OptionKind = IPv6OptionKind(0x00);
    pub const PADN: IPv6OptionKind = IPv6OptionKind(0x01);
    /// RFC 2473.
    pub const TUNNEL_ENCAPSULATION_LIMIT: IPv6OptionKind = IPv6OptionKind(0x04);
    /// RFC 2711.
    pub const ROUTER_ALERT: IPv6OptionKind = IPv6OptionKind(0x05);
    /// RFC 2675.
    pub const JUMBO_PAYLOAD: IPv6OptionKind = IPv6OptionKind(0xC2);
    /// RFC 6275.
    pub const HOME_ADDRESS: IPv6OptionKind = IPv6OptionKind(0xC9);

    /// What a node that does not recognize the option does (the highest
    /// two bits): 0 skips it, 1 discards the packet, 2 discards it and sends
    /// an ICMP Parameter Problem, 3 does so only if the destination is not multicast.
    pub const fn action(&self) -> u8 {
        self.0 >> 6
    }

    /// Whether the Option Data may change en route (the third-highest bit).
    pub const fn may_change(&self) -> bool {
        self.0 & 0x20 != 0
    }
}

/// One option: its type and its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPv6Option<'a> {
    pub kind: IPv6OptionKind,
    pub data: &'a [u8],
    /// The offset of its type in its header, which an ICMP Parameter Problem points to.
    pub offset: usize,
}

impl IPv6Option<'_> {
    /// Writes an option of `kind` with `data` (at most 255 bytes; none for Pad1).
    pub fn encode(kind: IPv6OptionKind, data: &[u8], out: &mut impl Writer) -> Result<(), IPv6Error> {
        if kind == IPv6OptionKind::PAD1 {
            if !data.is_empty() {
                return Err(IPv6Error::Option);
            }
            return Ok(out.write_u8(IPv6OptionKind::PAD1.0)?);
        }
        let length = u8::try_from(data.len()).map_err(|_| IPv6Error::Option)?;
        out.write(&[kind.0, length])?;
        Ok(out.write(data)?)
    }

    /// Writes `length` bytes of padding (at most 257): Pad1 for one, PadN otherwise.
    pub fn encode_padding(length: usize, out: &mut impl Writer) -> Result<(), IPv6Error> {
        match length {
            0 => Ok(()),
            1 => IPv6Option::encode(IPv6OptionKind::PAD1, &[], out),
            _ => {
                let zeros = [0u8; 255];
                let data = zeros.get(..length - 2).ok_or(IPv6Error::Option)?;
                IPv6Option::encode(IPv6OptionKind::PADN, data, out)
            }
        }
    }
}

/// A Hop-by-Hop Options header (RFC 8200 §4.3) or a Destination Options
/// header (§4.6): the Next Header value and the options area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPv6OptionsHeader<'a> {
    pub next_header: IPProtocol,
    /// The options, padding included: the bytes after the first two.
    pub options: &'a [u8],
}

impl<'a> IPv6OptionsHeader<'a> {
    /// The header that `bytes` is (the bytes of an [`super::IPv6ExtensionHeader`]),
    /// whose options must follow the format of RFC 8200 §4.2.
    pub fn decode(bytes: &'a [u8]) -> Result<IPv6OptionsHeader<'a>, IPv6Error> {
        if bytes.len() < 8 || !bytes.len().is_multiple_of(8) || (bytes[1] as usize + 1) * 8 != bytes.len() {
            return Err(IPv6Error::Length);
        }
        let header = IPv6OptionsHeader { next_header: IPProtocol(bytes[0]), options: &bytes[2..] };
        for option in header.iter() {
            option?;
        }
        Ok(header)
    }

    /// The options in order, without padding.
    pub fn iter(&self) -> IPv6OptionIterator<'a> {
        IPv6OptionIterator { bytes: self.options, offset: 2 }
    }

    /// The length of a header whose options take `length` bytes: padded to a multiple of 8.
    pub fn encoded_length(length: usize) -> usize {
        (length + 2).div_ceil(8) * 8
    }

    /// Writes the header: its options (encoded, as by [`IPv6Option::encode`]),
    /// padded to a multiple of 8 bytes.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), IPv6Error> {
        let length = IPv6OptionsHeader::encoded_length(self.options.len());
        let units = u8::try_from(length / 8 - 1).map_err(|_| IPv6Error::Length)?;
        out.write(&[self.next_header.0, units])?;
        out.write(self.options)?;
        IPv6Option::encode_padding(length - 2 - self.options.len(), out)
    }
}

/// The options of [`IPv6OptionsHeader::iter`]; an error ends it.
#[derive(Clone, Debug)]
pub struct IPv6OptionIterator<'a> {
    pub bytes: &'a [u8],
    /// The offset of `bytes` in the header.
    pub offset: usize,
}

impl<'a> Iterator for IPv6OptionIterator<'a> {
    type Item = Result<IPv6Option<'a>, IPv6Error>;

    fn next(&mut self) -> Option<Result<IPv6Option<'a>, IPv6Error>> {
        loop {
            let (&kind, rest) = self.bytes.split_first()?;
            let kind = IPv6OptionKind(kind);
            if kind == IPv6OptionKind::PAD1 {
                self.bytes = rest;
                self.offset += 1;
                continue;
            }
            let Some(length) =
                rest.first().map(|&length| length as usize + 2).filter(|&length| length <= self.bytes.len())
            else {
                self.bytes = &[];
                return Some(Err(IPv6Error::Option));
            };
            let option = IPv6Option { kind, data: &self.bytes[2..length], offset: self.offset };
            self.bytes = &self.bytes[length..];
            self.offset += length;
            if kind == IPv6OptionKind::PADN {
                continue;
            }
            return Some(Ok(option));
        }
    }
}
