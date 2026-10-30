use crate::bytes::Writer;

use super::super::IPProtocol;
use super::{IPv6Error, IPv6ExtensionHeaders, IPv6FragmentHeader, IPv6Header};

/// One packet of [`IPv6Fragmenter`]: the IPv6 header, the per-fragment
/// extension headers, the Fragment header (none for a packet that fits
/// unfragmented) and the data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPv6Fragment<'a> {
    pub header: IPv6Header,
    pub per_fragment: &'a [u8],
    /// The offset in `per_fragment` of the Next Header field to set to the
    /// Fragment header's number, or `None` if it is that of `header`.
    pub next_header_offset: Option<usize>,
    pub fragment: Option<IPv6FragmentHeader>,
    pub data: &'a [u8],
}

impl IPv6Fragment<'_> {
    /// The length of the packet.
    pub fn length(&self) -> usize {
        IPv6Header::LENGTH + self.header.payload_length as usize
    }

    /// Writes the packet.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), IPv6Error> {
        self.header.encode(out)?;
        match (self.fragment, self.next_header_offset) {
            (Some(_), Some(offset)) => {
                out.write(&self.per_fragment[..offset])?;
                out.write_u8(IPProtocol::IPV6_FRAGMENT.0)?;
                out.write(&self.per_fragment[offset + 1..])?;
            }
            _ => out.write(self.per_fragment)?,
        }
        if let Some(fragment) = &self.fragment {
            fragment.encode(out)?;
        }
        Ok(out.write(self.data)?)
    }
}

/// The fragments of a packet that fit an MTU, made by its source (RFC 8200
/// §4.5): the per-fragment headers (the extension headers up to the last
/// Routing header, or else a Hop-by-Hop Options header) repeat in every
/// fragment, the fragmentable part is cut into parts of multiples of 8
/// bytes but the last, and the first part holds the rest of the header
/// chain (RFC 7112). A packet that fits is one packet without a Fragment header.
#[derive(Clone, Debug)]
pub struct IPv6Fragmenter<'a> {
    pub header: IPv6Header,
    pub per_fragment: &'a [u8],
    pub next_header_offset: Option<usize>,
    /// The Next Header value of the first header of the fragmentable part.
    pub next_header: IPProtocol,
    pub fragmentable: &'a [u8],
    pub identification: u32,
    pub mtu: usize,
    pub position: usize,
    pub done: bool,
}

impl<'a> IPv6Fragmenter<'a> {
    /// The fragments of `payload` after `header` for `mtu`, identified by
    /// `identification` (RFC 7739: unpredictable). Fails with
    /// [`IPv6Error::Fragment`] if a fragment could not carry 8 bytes,
    /// with [`IPv6Error::HeaderChain`] if the first could not carry the
    /// header chain, and with [`IPv6Error::ExtensionHeader`] if the packet
    /// already has a Fragment header: only its source fragments a packet,
    /// once (RFC 8200 §4.5).
    pub fn new(
        header: IPv6Header,
        payload: &'a [u8],
        identification: u32,
        mtu: usize,
    ) -> Result<IPv6Fragmenter<'a>, IPv6Error> {
        let payload = payload.get(..header.payload_length as usize).ok_or(IPv6Error::Length)?;
        let (mut split, mut next_header_offset, mut next_header) = (0, None, header.next_header);
        let mut headers = IPv6ExtensionHeaders::new(header.next_header, payload);
        let mut start = 0;
        while let Some(extension) = headers.next() {
            let extension = extension?;
            if extension.kind == IPProtocol::IPV6_FRAGMENT {
                return Err(IPv6Error::ExtensionHeader);
            }
            if matches!(extension.kind, IPProtocol::HOP_BY_HOP_OPTIONS | IPProtocol::IPV6_ROUTING) {
                (split, next_header_offset, next_header) = (headers.offset, Some(start), extension.next_header);
            }
            start = headers.offset;
        }
        let chain_end = headers.offset;
        let fragmenter = IPv6Fragmenter {
            header,
            per_fragment: &payload[..split],
            next_header_offset,
            next_header,
            fragmentable: &payload[split..],
            identification,
            mtu,
            position: 0,
            done: false,
        };
        if IPv6Header::LENGTH + payload.len() > mtu {
            let room = fragmenter.room();
            if room < IPv6FragmentHeader::FRAGMENT_UNIT {
                return Err(IPv6Error::Fragment);
            }
            if chain_end - split > room {
                return Err(IPv6Error::HeaderChain);
            }
        }
        Ok(fragmenter)
    }

    /// The data that a fragment but the last carries: a multiple of 8 bytes.
    pub fn room(&self) -> usize {
        let fixed = IPv6Header::LENGTH + self.per_fragment.len() + IPv6FragmentHeader::LENGTH;
        self.mtu.saturating_sub(fixed) / IPv6FragmentHeader::FRAGMENT_UNIT * IPv6FragmentHeader::FRAGMENT_UNIT
    }
}

impl<'a> Iterator for IPv6Fragmenter<'a> {
    type Item = IPv6Fragment<'a>;

    fn next(&mut self) -> Option<IPv6Fragment<'a>> {
        if self.done {
            return None;
        }
        self.done = true;
        if IPv6Header::LENGTH + self.per_fragment.len() + self.fragmentable.len() <= self.mtu {
            return Some(IPv6Fragment {
                header: self.header,
                per_fragment: self.per_fragment,
                next_header_offset: None,
                fragment: None,
                data: self.fragmentable,
            });
        }
        let remaining = self.fragmentable.len() - self.position;
        let fixed = IPv6Header::LENGTH + self.per_fragment.len() + IPv6FragmentHeader::LENGTH;
        let length = if fixed + remaining <= self.mtu { remaining } else { self.room() };
        let last = length == remaining;
        let fragment = IPv6FragmentHeader {
            next_header: self.next_header,
            fragment_offset: (self.position / IPv6FragmentHeader::FRAGMENT_UNIT) as u16,
            more_fragments: !last,
            identification: self.identification,
        };
        let mut header = self.header;
        // The fragment is shorter than the packet, whose payload length fits.
        header.payload_length = (self.per_fragment.len() + IPv6FragmentHeader::LENGTH + length) as u16;
        if self.next_header_offset.is_none() {
            header.next_header = IPProtocol::IPV6_FRAGMENT;
        }
        let data = &self.fragmentable[self.position..self.position + length];
        self.position += length;
        self.done = last;
        Some(IPv6Fragment {
            header,
            per_fragment: self.per_fragment,
            next_header_offset: self.next_header_offset,
            fragment: Some(fragment),
            data,
        })
    }
}
