use alloc::vec::Vec;
use core::time::Duration;

use super::super::{
    IPError, IPFirstFragment, IPFragmentBuffer, IPProtocol, IPReassembly, IPReassemblyTable, IPv6Address,
};
use super::{IPv6Error, IPv6ExtensionHeaders, IPv6FragmentHeader, IPv6Header};
use crate::runtime::Instant;

/// The limits of an [`IPv6Reassembler`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPv6ReassemblyConfig {
    /// How long a packet may take from its first-arriving fragment (RFC 8200 §4.5: 60 seconds).
    pub timeout: Duration,
    /// The largest payload, per-fragment headers included, that is
    /// reassembled (at most 65,535; RFC 8200 §5: at least 1,500 − 40).
    pub maximum_length: usize,
    /// The most packets being reassembled at once.
    pub maximum_datagrams: usize,
    /// The most bytes held by all the packets being reassembled.
    pub maximum_buffered: usize,
}

impl Default for IPv6ReassemblyConfig {
    fn default() -> IPv6ReassemblyConfig {
        IPv6ReassemblyConfig {
            timeout: Duration::from_secs(60),
            maximum_length: IPv6Header::MAXIMUM_PAYLOAD_LENGTH,
            maximum_datagrams: 64,
            maximum_buffered: 4 << 20,
        }
    }
}

/// What identifies the fragments of one packet (RFC 8200 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct IPv6ReassemblyKey {
    pub source: IPv6Address,
    pub destination: IPv6Address,
    pub identification: u32,
}

impl IPv6ReassemblyKey {
    pub fn of(header: &IPv6Header, fragment: &IPv6FragmentHeader) -> IPv6ReassemblyKey {
        IPv6ReassemblyKey {
            source: header.source,
            destination: header.destination,
            identification: fragment.identification,
        }
    }
}

/// The parts of a fragment packet: the per-fragment headers, the Fragment
/// header and the fragment's data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPv6FragmentParts<'a> {
    pub per_fragment: &'a [u8],
    /// The offset in `per_fragment` of the Next Header field that names
    /// the Fragment header, or `None` if it is that of the IPv6 header.
    pub next_header_offset: Option<usize>,
    pub fragment: IPv6FragmentHeader,
    pub data: &'a [u8],
}

impl<'a> IPv6FragmentParts<'a> {
    /// The parts of `payload` after `header`; `None` if it has no Fragment header.
    pub fn of(header: &IPv6Header, payload: &'a [u8]) -> Result<Option<IPv6FragmentParts<'a>>, IPv6Error> {
        let mut headers = IPv6ExtensionHeaders::new(header.next_header, payload);
        let mut next_header_offset = None;
        let mut start = 0;
        while let Some(extension) = headers.next() {
            let extension = extension?;
            if extension.kind == IPProtocol::IPV6_FRAGMENT {
                return Ok(Some(IPv6FragmentParts {
                    per_fragment: &payload[..start],
                    next_header_offset,
                    fragment: IPv6FragmentHeader::decode(extension.bytes)?,
                    data: &payload[headers.offset..],
                }));
            }
            next_header_offset = Some(start);
            start = headers.offset;
        }
        Ok(None)
    }

    /// The header and the payload of the packet these parts make whole
    /// when `data` is all of the fragmentable part: the Fragment header
    /// removed and its Next Header value put in its place.
    pub fn reassemble(&self, header: &IPv6Header, data: &[u8]) -> Result<(IPv6Header, Vec<u8>), IPv6Error> {
        let mut header = *header;
        let mut payload = Vec::with_capacity(self.per_fragment.len() + data.len());
        payload.extend_from_slice(self.per_fragment);
        match self.next_header_offset {
            Some(offset) => payload[offset] = self.fragment.next_header.0,
            None => header.next_header = self.fragment.next_header,
        }
        payload.extend_from_slice(data);
        header.payload_length = u16::try_from(payload.len()).map_err(|_| IPv6Error::Reassembly(IPError::Length))?;
        Ok((header, payload))
    }
}

/// The headers of the fragment at offset zero of a packet, which the
/// reassembled packet keeps (RFC 8200 §4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IPv6FirstFragment {
    pub header: IPv6Header,
    pub per_fragment: Vec<u8>,
    /// As [`IPv6FragmentParts::next_header_offset`].
    pub next_header_offset: Option<usize>,
    pub fragment: IPv6FragmentHeader,
}

impl IPFirstFragment for IPv6FirstFragment {
    fn memory(&self) -> usize {
        self.per_fragment.len()
    }
}

/// One IPv6 packet being reassembled; its first fragment is its headers.
pub type IPv6Reassembly = IPReassembly<IPv6FirstFragment>;

/// The reassembly of IPv6 packets from their fragments (RFC 8200 §4.5),
/// without I/O. An atomic fragment is a whole packet (RFC 6946); a first
/// fragment without the whole header chain fails (RFC 7112); fragments that
/// overlap abandon their packet (RFC 5722). A packet not complete by its
/// deadline is given back by [`IPv6Reassembler::expire`], so that an ICMPv6
/// Time Exceeded message can be sent if its first fragment arrived. When a
/// limit is reached, the packets with the earliest deadlines are dropped to
/// make room (see [`IPReassemblyTable::make_room`]).
#[derive(Clone, Debug, Default)]
pub struct IPv6Reassembler {
    pub config: IPv6ReassemblyConfig,
    pub table: IPReassemblyTable<IPv6ReassemblyKey, IPv6FirstFragment>,
}

impl IPv6Reassembler {
    pub fn new(config: IPv6ReassemblyConfig) -> IPv6Reassembler {
        IPv6Reassembler { config, table: IPReassemblyTable::new() }
    }

    /// Adds a packet received at `now`: its header and its payload. Returns
    /// the packet it completes, without a Fragment header. A packet without
    /// a Fragment header is complete. A fragment that overlaps another
    /// abandons its packet; other failures drop only the fragment, as does a
    /// fragment of a packet whose deadline is past ([`IPv6Error::Expired`]:
    /// call [`IPv6Reassembler::expire`] before receiving).
    pub fn receive(
        &mut self,
        header: &IPv6Header,
        payload: &[u8],
        now: Instant,
    ) -> Result<Option<(IPv6Header, Vec<u8>)>, IPv6Error> {
        let payload = payload.get(..header.payload_length as usize).ok_or(IPv6Error::Length)?;
        let Some(parts) = IPv6FragmentParts::of(header, payload)? else {
            return Ok(Some((*header, payload.to_vec())));
        };
        let fragment = parts.fragment;
        // A Hop-by-Hop Options header comes only right after the IPv6 header (RFC 8200 §4.1).
        if fragment.next_header == IPProtocol::HOP_BY_HOP_OPTIONS {
            return Err(IPv6Error::ExtensionHeader);
        }
        if fragment.more_fragments && !parts.data.len().is_multiple_of(IPv6FragmentHeader::FRAGMENT_UNIT) {
            return Err(IPv6Error::Length);
        }
        let offset = fragment.fragment_offset as usize * IPv6FragmentHeader::FRAGMENT_UNIT;
        if offset == 0 {
            match IPv6ExtensionHeaders::upper_layer(fragment.next_header, parts.data) {
                Err(IPv6Error::Length) => return Err(IPv6Error::HeaderChain),
                result => result?,
            };
        }
        if fragment.is_atomic() {
            return parts.reassemble(header, parts.data).map(Some);
        }
        let maximum = self.config.maximum_length.min(IPv6Header::MAXIMUM_PAYLOAD_LENGTH);
        if parts.per_fragment.len() + offset + parts.data.len() > maximum {
            return Err(IPv6Error::Reassembly(IPError::Length));
        }
        let key = IPv6ReassemblyKey::of(header, &fragment);
        let last = !fragment.more_fragments;
        let (growth, first) = match self.table.entries.get(&key) {
            Some(reassembly) if reassembly.deadline <= now => return Err(IPv6Error::Expired),
            Some(reassembly) if reassembly.abandoned => return Err(IPv6Error::Reassembly(IPError::Overlap)),
            Some(reassembly) => {
                (reassembly.buffer.check(offset, parts.data, last, maximum), reassembly.first.is_none())
            }
            None => (IPFragmentBuffer::new().check(offset, parts.data, last, maximum), true),
        };
        let growth = match growth {
            Ok(growth) => growth,
            Err(IPError::Overlap) => {
                self.table.abandon(&key);
                return Err(IPv6Error::Reassembly(IPError::Overlap));
            }
            Err(error) => return Err(error.into()),
        };
        let first = first && offset == 0;
        let growth = growth + if first { parts.per_fragment.len() } else { 0 };
        if !self.table.make_room(&key, growth, self.config.maximum_datagrams, self.config.maximum_buffered) {
            return Err(IPv6Error::Limit);
        }
        self.table.open(key, now.saturating_add(self.config.timeout));
        let inserted = self.table.modify(&key, |reassembly| {
            let complete = reassembly.buffer.insert(offset, parts.data, last, maximum)?;
            if first {
                reassembly.first = Some(IPv6FirstFragment {
                    header: *header,
                    per_fragment: parts.per_fragment.to_vec(),
                    next_header_offset: parts.next_header_offset,
                    fragment,
                });
            }
            Ok::<bool, IPError>(complete)
        });
        if !inserted.ok_or(IPv6Error::Limit)?? {
            return Ok(None);
        }
        let reassembly = self.table.discard(&key).ok_or(IPv6Error::Limit)?;
        let first = reassembly.first.ok_or(IPv6Error::Reassembly(IPError::Length))?;
        if first.per_fragment.len() + reassembly.buffer.data.len() > maximum {
            return Err(IPv6Error::Reassembly(IPError::Length));
        }
        let parts = IPv6FragmentParts {
            per_fragment: &first.per_fragment,
            next_header_offset: first.next_header_offset,
            fragment: first.fragment,
            data: &[],
        };
        parts.reassemble(&first.header, &reassembly.buffer.data).map(Some)
    }

    /// The earliest deadline of the packets being reassembled.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.table.poll_timeout()
    }

    /// Removes a packet whose deadline is at or before `now` and returns it
    /// (an abandoned one has no first fragment to answer).
    pub fn expire(&mut self, now: Instant) -> Option<(IPv6ReassemblyKey, IPv6Reassembly)> {
        self.table.expire(now)
    }
}
