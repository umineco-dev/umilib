use alloc::vec::Vec;
use core::time::Duration;

use super::super::{
    IPError, IPFirstFragment, IPFragmentBuffer, IPProtocol, IPReassembly, IPReassemblyTable, IPv4Address,
};
use super::{IPv4Error, IPv4Header};
use crate::runtime::Instant;

/// The limits of an [`IPv4Reassembler`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPv4ReassemblyConfig {
    /// How long a datagram may take from its first-arriving fragment
    /// (RFC 1122 §3.3.2 recommends 60 to 120 seconds).
    pub timeout: Duration,
    /// The largest datagram, header included, that is reassembled (EMTU_R;
    /// RFC 1122 §3.3.2: at least 576).
    pub maximum_length: usize,
    /// The most datagrams being reassembled at once.
    pub maximum_datagrams: usize,
    /// The most bytes held by all the datagrams being reassembled.
    pub maximum_buffered: usize,
}

impl Default for IPv4ReassemblyConfig {
    fn default() -> IPv4ReassemblyConfig {
        IPv4ReassemblyConfig {
            timeout: Duration::from_secs(60),
            maximum_length: IPv4Header::MAXIMUM_TOTAL_LENGTH,
            maximum_datagrams: 64,
            maximum_buffered: 4 << 20,
        }
    }
}

/// What identifies the fragments of one datagram (RFC 791 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct IPv4ReassemblyKey {
    pub source: IPv4Address,
    pub destination: IPv4Address,
    pub protocol: IPProtocol,
    pub identification: u16,
}

impl IPv4ReassemblyKey {
    pub fn of(header: &IPv4Header) -> IPv4ReassemblyKey {
        IPv4ReassemblyKey {
            source: header.source,
            destination: header.destination,
            protocol: header.protocol,
            identification: header.identification,
        }
    }
}

impl IPFirstFragment for IPv4Header {
    fn memory(&self) -> usize {
        0
    }
}

/// One IPv4 datagram being reassembled; its first fragment is its header.
pub type IPv4Reassembly = IPReassembly<IPv4Header>;

/// The reassembly of IPv4 datagrams from their fragments (RFC 791 §3.2,
/// RFC 815, RFC 1122 §3.3.2), without I/O. Fragments that overlap abandon
/// their datagram (RFC 1858, RFC 5722); a datagram not complete by its
/// deadline is given back by [`IPv4Reassembler::expire`], so that an ICMP
/// Time Exceeded message can be sent if its first fragment arrived. When a
/// limit is reached, the datagrams with the earliest deadlines are dropped
/// to make room (see [`IPReassemblyTable::make_room`]).
#[derive(Clone, Debug, Default)]
pub struct IPv4Reassembler {
    pub config: IPv4ReassemblyConfig,
    pub table: IPReassemblyTable<IPv4ReassemblyKey, IPv4Header>,
}

impl IPv4Reassembler {
    pub fn new(config: IPv4ReassemblyConfig) -> IPv4Reassembler {
        IPv4Reassembler { config, table: IPReassemblyTable::new() }
    }

    /// Adds a fragment received at `now`: its header and its data. Returns
    /// the datagram it completes: the header of its first fragment,
    /// unfragmented, and its data. A packet that is not a fragment is a
    /// complete datagram. A fragment that overlaps another abandons its
    /// datagram; other failures drop only the fragment, as does a fragment
    /// of a datagram whose deadline is past ([`IPv4Error::Expired`]: call
    /// [`IPv4Reassembler::expire`] before receiving).
    pub fn receive(
        &mut self,
        header: &IPv4Header,
        payload: &[u8],
        now: Instant,
    ) -> Result<Option<(IPv4Header, Vec<u8>)>, IPv4Error> {
        if !header.is_fragment() {
            return Ok(Some((*header, payload.to_vec())));
        }
        if header.more_fragments && !payload.len().is_multiple_of(IPv4Header::FRAGMENT_UNIT) {
            return Err(IPv4Error::Length);
        }
        let key = IPv4ReassemblyKey::of(header);
        let offset = header.fragment_offset as usize * IPv4Header::FRAGMENT_UNIT;
        let last = !header.more_fragments;
        // The data may fill the datagram up to its limit after the smallest header.
        let maximum =
            self.config.maximum_length.min(IPv4Header::MAXIMUM_TOTAL_LENGTH).saturating_sub(IPv4Header::MINIMUM_LENGTH);
        let growth = match self.table.entries.get(&key) {
            Some(reassembly) if reassembly.deadline <= now => return Err(IPv4Error::Expired),
            Some(reassembly) if reassembly.abandoned => return Err(IPv4Error::Reassembly(IPError::Overlap)),
            Some(reassembly) => reassembly.buffer.check(offset, payload, last, maximum),
            None => IPFragmentBuffer::new().check(offset, payload, last, maximum),
        };
        let growth = match growth {
            Ok(growth) => growth,
            Err(IPError::Overlap) => {
                self.table.abandon(&key);
                return Err(IPv4Error::Reassembly(IPError::Overlap));
            }
            Err(error) => return Err(error.into()),
        };
        if !self.table.make_room(&key, growth, self.config.maximum_datagrams, self.config.maximum_buffered) {
            return Err(IPv4Error::Limit);
        }
        self.table.open(key, now.saturating_add(self.config.timeout));
        let inserted = self.table.modify(&key, |reassembly| {
            let complete = reassembly.buffer.insert(offset, payload, last, maximum)?;
            if offset == 0 && reassembly.first.is_none() {
                reassembly.first = Some(*header);
            }
            Ok::<bool, IPError>(complete)
        });
        if !inserted.ok_or(IPv4Error::Limit)?? {
            return Ok(None);
        }
        let reassembly = self.table.discard(&key).ok_or(IPv4Error::Limit)?;
        let mut datagram = reassembly.first.ok_or(IPv4Error::Reassembly(IPError::Length))?;
        let data = reassembly.buffer.data;
        if datagram.header_length() + data.len() > self.config.maximum_length {
            return Err(IPv4Error::Reassembly(IPError::Length));
        }
        datagram.more_fragments = false;
        datagram.fragment_offset = 0;
        datagram.set_payload_length(data.len())?;
        Ok(Some((datagram, data)))
    }

    /// The earliest deadline of the datagrams being reassembled.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.table.poll_timeout()
    }

    /// Removes a datagram whose deadline is at or before `now` and returns
    /// it (an abandoned one has no first fragment to answer).
    pub fn expire(&mut self, now: Instant) -> Option<(IPv4ReassemblyKey, IPv4Reassembly)> {
        self.table.expire(now)
    }
}
