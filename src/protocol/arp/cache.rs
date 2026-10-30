use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::time::Duration;

use super::{ARPAddress, ARPError, ARPHardwareType, ARPOperation, ARPPacket};
use crate::protocol::ethernet::{EtherType, MACAddress};
use crate::protocol::ip::IPv4Address;
use crate::runtime::Instant;

/// The parameters of an [`ARPCache`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ARPConfig {
    /// The hardware type and the protocol the cache resolves (RFC 826:
    /// packets of others are ignored).
    pub hardware_type: ARPHardwareType,
    pub protocol_type: EtherType,
    /// How long a learned address is used before it is resolved again
    /// (RFC 1122 §2.3.2.1: on the order of a minute, configurable).
    pub timeout: Duration,
    /// The time between requests for one address (RFC 1122 §2.3.2.1: at
    /// most one per second).
    pub retransmission_interval: Duration,
    /// The requests sent for an address before it is unreachable.
    pub maximum_requests: u32,
    /// The most addresses resolved and being resolved.
    pub maximum_entries: usize,
    /// The most packets kept for an address being resolved, the latest ones
    /// (RFC 1122 §2.3.2.2: at least one).
    pub maximum_queued: usize,
}

impl Default for ARPConfig {
    fn default() -> ARPConfig {
        ARPConfig {
            hardware_type: ARPHardwareType::ETHERNET,
            protocol_type: EtherType::IPV4,
            timeout: Duration::from_secs(60),
            retransmission_interval: Duration::from_secs(1),
            maximum_requests: 3,
            maximum_entries: 512,
            maximum_queued: 1,
        }
    }
}

/// What the cache knows of one protocol address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ARPEntry<H> {
    /// Requests are sent: `requests` so far, the next at `next_request`;
    /// the packets waiting for the address are kept.
    Incomplete { requests: u32, next_request: Instant, queue: VecDeque<Vec<u8>> },
    /// The address is known until `expires`.
    Reachable { hardware: H, expires: Instant },
    /// The address is set by the application and never expires.
    Static { hardware: H },
}

/// The answer of [`ARPCache::resolve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ARPResolution<H> {
    /// The hardware address: the packet can be sent.
    Resolved(H),
    /// The address is unknown: the packet is kept and a request is to be sent now.
    Request,
    /// The address is being resolved: the packet is kept.
    Pending,
}

/// What [`ARPCache::receive`] makes of a packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ARPReception<H: ARPAddress = MACAddress, P: ARPAddress = IPv4Address> {
    /// The reply to send to the sender's hardware address.
    pub reply: Option<ARPPacket<H, P>>,
    /// The packets kept for the sender's protocol address, now resolved, to send.
    pub resolved: Vec<Vec<u8>>,
    /// Whether the packet claims a local protocol address from another
    /// hardware address: an address conflict (RFC 5227 §2.4).
    pub conflict: bool,
}

/// What [`ARPCache::poll`] reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ARPEvent<P> {
    /// A request for the address is to be sent again.
    Request(P),
    /// The address did not answer: the packets kept for it are dropped
    /// (an ICMP Destination Unreachable may be sent for them).
    Unreachable(P, VecDeque<Vec<u8>>),
}

/// The translation table of ARP (RFC 826) from protocol addresses `P` to
/// hardware addresses `H`, without I/O: it answers requests for local
/// addresses, learns from packets as RFC 826 does, keeps packets for
/// addresses being resolved (RFC 1122 §2.3.2.2), limits requests to one per
/// interval (RFC 1122 §2.3.2.1) and forgets addresses after a timeout.
#[derive(Clone, Debug)]
pub struct ARPCache<H: ARPAddress = MACAddress, P: ARPAddress + Ord = IPv4Address> {
    pub config: ARPConfig,
    pub entries: BTreeMap<P, ARPEntry<H>>,
}

impl<H: ARPAddress, P: ARPAddress + Ord> ARPCache<H, P> {
    pub fn new(config: ARPConfig) -> ARPCache<H, P> {
        ARPCache { config, entries: BTreeMap::new() }
    }

    /// The hardware address of `address` at `now`, or the start or wait of
    /// its resolution; `packet`, if any, is kept until it ends.
    pub fn resolve(&mut self, address: P, packet: Option<Vec<u8>>, now: Instant) -> Result<ARPResolution<H>, ARPError> {
        let full = self.entries.len() >= self.config.maximum_entries;
        match self.entries.get_mut(&address) {
            Some(ARPEntry::Static { hardware }) => return Ok(ARPResolution::Resolved(*hardware)),
            Some(ARPEntry::Reachable { hardware, expires }) if *expires > now => {
                return Ok(ARPResolution::Resolved(*hardware));
            }
            Some(ARPEntry::Incomplete { queue, .. }) => {
                ARPCache::<H, P>::enqueue(queue, packet, self.config.maximum_queued);
                return Ok(ARPResolution::Pending);
            }
            Some(ARPEntry::Reachable { .. }) => {}
            None if full => self.make_room(&address)?,
            None => {}
        }
        let mut queue = VecDeque::new();
        ARPCache::<H, P>::enqueue(&mut queue, packet, self.config.maximum_queued);
        let next_request = now.saturating_add(self.config.retransmission_interval);
        self.entries.insert(address, ARPEntry::Incomplete { requests: 1, next_request, queue });
        Ok(ARPResolution::Request)
    }

    /// Forgets the entries due soonest (those that expire first or whose
    /// next request is the earliest), static entries excepted, until one
    /// more than `address` fits `maximum_entries`, which static entries
    /// count against; fails with [`ARPError::Limit`] if it cannot.
    pub fn make_room(&mut self, address: &P) -> Result<(), ARPError> {
        let due = |entry: &ARPEntry<H>| match entry {
            ARPEntry::Incomplete { next_request, .. } => Some(*next_request),
            ARPEntry::Reachable { expires, .. } => Some(*expires),
            ARPEntry::Static { .. } => None,
        };
        while self.entries.len() >= self.config.maximum_entries {
            let candidates = self.entries.iter().filter(|(other, _)| *other != address);
            let soonest = candidates.filter_map(|(other, entry)| Some((due(entry)?, *other))).min();
            let (_, other) = soonest.ok_or(ARPError::Limit)?;
            self.entries.remove(&other);
        }
        Ok(())
    }

    /// Keeps `packet` in `queue`, dropping the oldest beyond `maximum`.
    pub fn enqueue(queue: &mut VecDeque<Vec<u8>>, packet: Option<Vec<u8>>, maximum: usize) {
        if let Some(packet) = packet {
            queue.push_back(packet);
        }
        while queue.len() > maximum {
            queue.pop_front();
        }
    }

    /// The hardware address of `address`, if it is known at `now`.
    pub fn lookup(&self, address: &P, now: Instant) -> Option<H> {
        match self.entries.get(address)? {
            ARPEntry::Static { hardware } => Some(*hardware),
            ARPEntry::Reachable { hardware, expires } if *expires > now => Some(*hardware),
            _ => None,
        }
    }

    /// Sets the hardware address of `address` until it is removed.
    pub fn insert_static(&mut self, address: P, hardware: H) {
        self.entries.insert(address, ARPEntry::Static { hardware });
    }

    pub fn remove(&mut self, address: &P) -> Option<ARPEntry<H>> {
        self.entries.remove(address)
    }

    /// Processes a packet received at `now` on an interface of the hardware
    /// address `hardware` and the protocol addresses `local` (RFC 826
    /// "Packet Reception"): the sender is learned if it is already known or
    /// the packet is for a local address, and a request for a local address
    /// is answered. A probe's sender is not learned, but the probe is
    /// answered (RFC 5227 §2.5); a packet that claims a local address from
    /// another hardware address is a conflict (§2.4), neither learned nor
    /// answered; a sender with a group hardware address is not learned.
    pub fn receive(&mut self, packet: &ARPPacket<H, P>, hardware: H, local: &[P], now: Instant) -> ARPReception<H, P> {
        let mut reception = ARPReception { reply: None, resolved: Vec::new(), conflict: false };
        if packet.hardware_type != self.config.hardware_type || packet.protocol_type != self.config.protocol_type {
            return reception;
        }
        reception.conflict = local.contains(&packet.sender_protocol) && packet.sender_hardware != hardware;
        let for_us = local.contains(&packet.target_protocol);
        let sender = packet.sender_protocol;
        if !sender.is_unspecified() && !reception.conflict && !packet.sender_hardware.is_multicast() {
            let known = self.entries.contains_key(&sender);
            let room = self.entries.len() < self.config.maximum_entries;
            if known || (for_us && room) {
                let expires = now.saturating_add(self.config.timeout);
                let learned = ARPEntry::Reachable { hardware: packet.sender_hardware, expires };
                match self.entries.insert(sender, learned) {
                    Some(ARPEntry::Incomplete { queue, .. }) => reception.resolved = queue.into(),
                    Some(ARPEntry::Static { hardware }) => {
                        self.entries.insert(sender, ARPEntry::Static { hardware });
                    }
                    _ => {}
                }
            }
        }
        if for_us && packet.operation == ARPOperation::REQUEST && !reception.conflict {
            reception.reply = Some(packet.reply(hardware));
        }
        reception
    }

    /// The earliest time at which [`ARPCache::poll`] has something to do.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.entries
            .values()
            .filter_map(|entry| match entry {
                ARPEntry::Incomplete { next_request, .. } => Some(*next_request),
                ARPEntry::Reachable { expires, .. } => Some(*expires),
                ARPEntry::Static { .. } => None,
            })
            .min()
    }

    /// Advances the cache to `now`: forgets expired addresses and returns
    /// the next request to send again or the next address that did not
    /// answer; `None` once nothing is due.
    pub fn poll(&mut self, now: Instant) -> Option<ARPEvent<P>> {
        self.entries.retain(|_, entry| !matches!(entry, ARPEntry::Reachable { expires, .. } if *expires <= now));
        let (address, entry) = self
            .entries
            .iter_mut()
            .find(|(_, entry)| matches!(entry, ARPEntry::Incomplete { next_request, .. } if *next_request <= now))?;
        let address = *address;
        let ARPEntry::Incomplete { requests, next_request, .. } = entry else { return None };
        if *requests < self.config.maximum_requests {
            *requests += 1;
            *next_request = now.saturating_add(self.config.retransmission_interval);
            return Some(ARPEvent::Request(address));
        }
        match self.entries.remove(&address) {
            Some(ARPEntry::Incomplete { queue, .. }) => Some(ARPEvent::Unreachable(address, queue)),
            _ => None,
        }
    }
}
