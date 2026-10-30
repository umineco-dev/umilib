use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::time::Duration;

use crate::protocol::icmp::ICMPError;
use crate::protocol::ip::IPv6Address;
use crate::runtime::Instant;

use super::NDPNeighborAdvertisement;

/// A link-layer address that Neighbor Discovery carries in its Source and
/// Target Link-Layer Address options (RFC 4861 §4.6.1): the first
/// [`NDPLinkAddress::LENGTH`] bytes of the option's data, the rest padding.
pub trait NDPLinkAddress: Copy + Eq {
    const LENGTH: usize;

    /// The address at the start of `data`, the data of an option; `None` if
    /// it is shorter, or longer than the address and its padding to 8 bytes.
    fn from_option(data: &[u8]) -> Option<Self>;

    fn as_bytes(&self) -> &[u8];
}

impl<const N: usize> NDPLinkAddress for [u8; N] {
    const LENGTH: usize = N;

    fn from_option(data: &[u8]) -> Option<[u8; N]> {
        if data.len() != (N + 2).div_ceil(8) * 8 - 2 {
            return None;
        }
        data[..N].try_into().ok()
    }

    fn as_bytes(&self) -> &[u8] {
        self
    }
}

/// The parameters of a [`NeighborCache`] (RFC 4861 §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborConfig {
    /// How long a neighbor stays REACHABLE after a confirmation: the
    /// ReachableTime of RFC 4861 §6.3.2, which the caller draws between 0.5
    /// and 1.5 times the BaseReachableTime (by default 30 seconds) and draws
    /// again at least every few hours.
    pub reachable_time: Duration,
    /// The time between solicitations: RetransTimer (1 second).
    pub retransmission_timer: Duration,
    /// How long a neighbor stays DELAY before probing: DELAY_FIRST_PROBE_TIME (5 seconds).
    pub delay_first_probe_time: Duration,
    /// The multicast solicitations of address resolution: MAX_MULTICAST_SOLICIT (3).
    pub maximum_multicast_solicitations: u32,
    /// The unicast probes of unreachability detection: MAX_UNICAST_SOLICIT (3).
    pub maximum_unicast_solicitations: u32,
    /// The most neighbors known and being resolved.
    pub maximum_entries: usize,
    /// The most packets kept for a neighbor being resolved, the latest ones.
    pub maximum_queued: usize,
}

impl Default for NeighborConfig {
    fn default() -> NeighborConfig {
        NeighborConfig {
            reachable_time: Duration::from_secs(30),
            retransmission_timer: Duration::from_secs(1),
            delay_first_probe_time: Duration::from_secs(5),
            maximum_multicast_solicitations: 3,
            maximum_unicast_solicitations: 3,
            maximum_entries: 512,
            maximum_queued: 1,
        }
    }
}

/// The reachability state of a neighbor (RFC 4861 §7.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeighborState<L> {
    /// Address resolution is in progress: `solicitations` sent, the next at `next`.
    Incomplete { solicitations: u32, next: Instant },
    /// The neighbor was confirmed reachable; it is until `expires`.
    Reachable { link: L, expires: Instant },
    /// The neighbor is not known to be reachable; nothing is done until a packet is sent.
    Stale { link: L },
    /// A packet was sent to a STALE neighbor; it is probed at `until` unless confirmed before.
    Delay { link: L, until: Instant },
    /// Unicast probes are sent: `solicitations` sent, the next at `next`.
    Probe { link: L, solicitations: u32, next: Instant },
}

impl<L: Copy> NeighborState<L> {
    /// The link-layer address, once resolved.
    pub fn link(&self) -> Option<L> {
        match self {
            NeighborState::Incomplete { .. } => None,
            NeighborState::Reachable { link, .. }
            | NeighborState::Stale { link }
            | NeighborState::Delay { link, .. }
            | NeighborState::Probe { link, .. } => Some(*link),
        }
    }

    /// When the state changes by itself; never for STALE.
    pub fn deadline(&self) -> Option<Instant> {
        match self {
            NeighborState::Incomplete { next, .. } | NeighborState::Probe { next, .. } => Some(*next),
            NeighborState::Reachable { expires, .. } => Some(*expires),
            NeighborState::Delay { until, .. } => Some(*until),
            NeighborState::Stale { .. } => None,
        }
    }
}

/// What the cache knows of one neighbor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborEntry<L> {
    pub state: NeighborState<L>,
    /// The neighbor is a router (RFC 4861 Appendix D).
    pub is_router: bool,
    /// The packets waiting for the neighbor's address.
    pub queue: VecDeque<Vec<u8>>,
    /// When a message, a confirmation or a packet resolved last refreshed the
    /// entry (not a timer), which orders the entries to forget.
    pub updated: Instant,
}

/// What a received message did to one neighbor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NeighborReception {
    /// The packets kept for the neighbor, now resolved: send them.
    pub packets: VecDeque<Vec<u8>>,
    /// The neighbor was a router and no longer is: remove it from the
    /// Default Router List (RFC 4861 §7.2.5).
    pub no_longer_router: bool,
}

/// The answer of [`NeighborCache::resolve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeighborResolution<L> {
    /// The link-layer address: the packet can be sent.
    Resolved(L),
    /// The address is unknown: the packet is kept, and a multicast Neighbor
    /// Solicitation to its solicited-node address is to be sent now.
    Solicit,
    /// The address is being resolved: the packet is kept.
    Pending,
}

/// What [`NeighborCache::poll`] reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NeighborEvent<L> {
    /// A Neighbor Solicitation for `target` is to be sent: to its
    /// solicited-node multicast address if `link` is `None`, or else
    /// unicast to `link` (a probe of unreachability detection).
    Solicit { target: IPv6Address, link: Option<L> },
    /// The neighbor did not answer, or was forgotten to make room while being
    /// resolved: its entry is gone and the packets kept for it are dropped.
    /// An ICMPv6 Destination Unreachable, code 3 (Address Unreachable), is
    /// to be sent for each (RFC 4861 §7.2.2).
    Unreachable { target: IPv6Address, packets: VecDeque<Vec<u8>> },
}

/// The Neighbor Cache of RFC 4861 §5.1 and its reachability state machine
/// (§7.3, Appendix C), without I/O: address resolution, Neighbor
/// Unreachability Detection, and what Neighbor Discovery messages teach.
/// The caller sends the solicitations it asks for and gives it what it
/// receives; `L` is the link-layer address.
#[derive(Clone, Debug)]
pub struct NeighborCache<L: NDPLinkAddress = [u8; 6]> {
    pub config: NeighborConfig,
    pub entries: BTreeMap<IPv6Address, NeighborEntry<L>>,
    /// The neighbors forgotten to make room while being resolved, with the
    /// packets kept for them, which [`NeighborCache::poll`] reports as
    /// unreachable; at most `maximum_entries`, the oldest dropped beyond.
    pub abandoned: VecDeque<(IPv6Address, VecDeque<Vec<u8>>)>,
}

impl<L: NDPLinkAddress> NeighborCache<L> {
    pub fn new(config: NeighborConfig) -> NeighborCache<L> {
        NeighborCache { config, entries: BTreeMap::new(), abandoned: VecDeque::new() }
    }

    /// The link-layer address to send a packet to `address` at `now`, or the
    /// start or wait of its resolution; `packet`, if any, is kept until it
    /// ends. Sending to a STALE neighbor starts unreachability detection
    /// (DELAY). A full cache makes room as [`NeighborCache::make_room`] says.
    pub fn resolve(
        &mut self,
        address: IPv6Address,
        packet: Option<Vec<u8>>,
        now: Instant,
    ) -> Result<NeighborResolution<L>, ICMPError> {
        if !self.entries.contains_key(&address) {
            self.make_room(&address)?;
            let next = now.saturating_add(self.config.retransmission_timer);
            let mut entry = NeighborEntry {
                state: NeighborState::Incomplete { solicitations: 1, next },
                is_router: false,
                queue: VecDeque::new(),
                updated: now,
            };
            NeighborCache::<L>::enqueue(&mut entry.queue, packet, self.config.maximum_queued);
            self.entries.insert(address, entry);
            return Ok(NeighborResolution::Solicit);
        }
        let delay = now.saturating_add(self.config.delay_first_probe_time);
        let maximum = self.config.maximum_queued;
        let entry = self.entries.get_mut(&address).ok_or(ICMPError::Limit)?;
        match entry.state {
            NeighborState::Incomplete { .. } => {
                NeighborCache::<L>::enqueue(&mut entry.queue, packet, maximum);
                Ok(NeighborResolution::Pending)
            }
            NeighborState::Reachable { link, expires } if expires > now => {
                entry.updated = now;
                Ok(NeighborResolution::Resolved(link))
            }
            NeighborState::Reachable { link, .. } | NeighborState::Stale { link } => {
                entry.state = NeighborState::Delay { link, until: delay };
                entry.updated = now;
                Ok(NeighborResolution::Resolved(link))
            }
            NeighborState::Delay { link, .. } | NeighborState::Probe { link, .. } => {
                entry.updated = now;
                Ok(NeighborResolution::Resolved(link))
            }
        }
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

    /// Forgets entries other than that of `address` until one more fits
    /// `maximum_entries`, and fails with [`ICMPError::Limit`] if it cannot.
    /// Entries being resolved go first, so that resolutions nobody answers
    /// do not push out the neighbors in use (RFC 6583 §7.1); their packets
    /// are kept in `abandoned`. Then the entries refreshed longest ago go ([`NeighborEntry::updated`]).
    pub fn make_room(&mut self, address: &IPv6Address) -> Result<(), ICMPError> {
        while self.entries.len() >= self.config.maximum_entries {
            let oldest = self
                .entries
                .iter()
                .filter(|(other, _)| *other != address)
                .min_by_key(|(_, entry)| (!matches!(entry.state, NeighborState::Incomplete { .. }), entry.updated))
                .map(|(other, _)| *other)
                .ok_or(ICMPError::Limit)?;
            let entry = self.entries.remove(&oldest).ok_or(ICMPError::Limit)?;
            if matches!(entry.state, NeighborState::Incomplete { .. }) {
                self.abandoned.push_back((oldest, entry.queue));
                while self.abandoned.len() > self.config.maximum_entries {
                    self.abandoned.pop_front();
                }
            }
        }
        Ok(())
    }

    /// The link-layer address of `address` and its state, if it is resolved.
    pub fn lookup(&self, address: &IPv6Address) -> Option<(L, NeighborState<L>)> {
        let entry = self.entries.get(address)?;
        Some((entry.state.link()?, entry.state))
    }

    /// A confirmation from an upper layer that `address` is reachable at
    /// `now` (RFC 4861 §7.3.1), such as an acknowledgment of new TCP data.
    pub fn confirm(&mut self, address: &IPv6Address, now: Instant) {
        let expires = now.saturating_add(self.config.reachable_time);
        if let Some(entry) = self.entries.get_mut(address)
            && let Some(link) = entry.state.link()
        {
            entry.state = NeighborState::Reachable { link, expires };
            entry.updated = now;
        }
    }

    /// Processes a valid Neighbor Advertisement received at `now` (RFC 4861
    /// §7.2.5). An advertisement for a target without an entry is ignored,
    /// as is one without a link-layer address for a target being resolved.
    pub fn receive_advertisement(
        &mut self,
        advertisement: &NDPNeighborAdvertisement,
        now: Instant,
    ) -> NeighborReception {
        let reachable = now.saturating_add(self.config.reachable_time);
        let Some(entry) = self.entries.get_mut(&advertisement.target) else { return NeighborReception::default() };
        // A malformed option is as good as none.
        let supplied = advertisement.target_link_address().and_then(L::from_option);
        let was_router = entry.is_router;
        let packets = match entry.state.link() {
            None => {
                let Some(link) = supplied else { return NeighborReception::default() };
                entry.state = if advertisement.solicited_flag {
                    NeighborState::Reachable { link, expires: reachable }
                } else {
                    NeighborState::Stale { link }
                };
                core::mem::take(&mut entry.queue)
            }
            Some(cached) => {
                let different = supplied.is_some_and(|link| link != cached);
                if !advertisement.override_flag && different {
                    // Only a REACHABLE entry changes, to STALE, and in no other way.
                    if matches!(entry.state, NeighborState::Reachable { .. }) {
                        entry.state = NeighborState::Stale { link: cached };
                        entry.updated = now;
                    }
                    return NeighborReception::default();
                }
                let link = supplied.unwrap_or(cached);
                if advertisement.solicited_flag {
                    entry.state = NeighborState::Reachable { link, expires: reachable };
                } else if different {
                    entry.state = NeighborState::Stale { link };
                }
                VecDeque::new()
            }
        };
        entry.is_router = advertisement.router_flag;
        entry.updated = now;
        NeighborReception { packets, no_longer_router: was_router && !entry.is_router }
    }

    /// Learns what a Neighbor Solicitation, Router Solicitation, Router
    /// Advertisement or Redirect received at `now` says of `address` (RFC
    /// 4861 §7.2.3, §6.2.6, §6.3.4, §8.3, Appendix C): its link-layer address
    /// `link`, if the message has one, and whether it is a router: `router`
    /// is `Some(true)` for a Router Advertisement or the target of a
    /// Redirect to a router, `Some(false)` for a Router Solicitation, and
    /// `None` for no indication. A different link-layer address makes the
    /// entry STALE; a new entry is made, STALE, unless the cache is full.
    pub fn learn(
        &mut self,
        address: IPv6Address,
        link: Option<L>,
        router: Option<bool>,
        now: Instant,
    ) -> NeighborReception {
        let Some(entry) = self.entries.get_mut(&address) else {
            if let Some(link) = link
                && self.entries.len() < self.config.maximum_entries
            {
                let entry = NeighborEntry {
                    state: NeighborState::Stale { link },
                    is_router: router.unwrap_or(false),
                    queue: VecDeque::new(),
                    updated: now,
                };
                self.entries.insert(address, entry);
            }
            return NeighborReception::default();
        };
        let was_router = entry.is_router;
        if let Some(router) = router {
            entry.is_router = router;
        }
        let mut packets = VecDeque::new();
        if let Some(link) = link
            && entry.state.link() != Some(link)
        {
            entry.state = NeighborState::Stale { link };
            entry.updated = now;
            packets = core::mem::take(&mut entry.queue);
        }
        NeighborReception { packets, no_longer_router: was_router && !entry.is_router }
    }

    pub fn remove(&mut self, address: &IPv6Address) -> Option<NeighborEntry<L>> {
        self.entries.remove(address)
    }

    /// The earliest time at which [`NeighborCache::poll`] has something to
    /// do: [`Instant::ZERO`], at once, while an abandoned neighbor is to be reported.
    pub fn poll_timeout(&self) -> Option<Instant> {
        if !self.abandoned.is_empty() {
            return Some(Instant::ZERO);
        }
        self.entries.values().filter_map(|entry| entry.state.deadline()).min()
    }

    /// Advances the cache to `now` and returns the next solicitation to send
    /// or neighbor that did not answer; `None` once nothing is due.
    pub fn poll(&mut self, now: Instant) -> Option<NeighborEvent<L>> {
        if let Some((target, packets)) = self.abandoned.pop_front() {
            return Some(NeighborEvent::Unreachable { target, packets });
        }
        let retransmission = now.saturating_add(self.config.retransmission_timer);
        let multicast = self.config.maximum_multicast_solicitations;
        let unicast = self.config.maximum_unicast_solicitations;
        // REACHABLE entries past their time become STALE, which reports nothing.
        for entry in self.entries.values_mut() {
            if let NeighborState::Reachable { link, expires } = entry.state
                && expires <= now
            {
                entry.state = NeighborState::Stale { link };
            }
        }
        let (target, entry) = self
            .entries
            .iter_mut()
            .find(|(_, entry)| entry.state.deadline().is_some_and(|deadline| deadline <= now))?;
        let target = *target;
        match entry.state {
            NeighborState::Delay { link, .. } => {
                entry.state = NeighborState::Probe { link, solicitations: 1, next: retransmission };
                Some(NeighborEvent::Solicit { target, link: Some(link) })
            }
            NeighborState::Incomplete { solicitations, .. } if solicitations < multicast => {
                entry.state = NeighborState::Incomplete { solicitations: solicitations + 1, next: retransmission };
                Some(NeighborEvent::Solicit { target, link: None })
            }
            NeighborState::Probe { link, solicitations, .. } if solicitations < unicast => {
                entry.state = NeighborState::Probe { link, solicitations: solicitations + 1, next: retransmission };
                Some(NeighborEvent::Solicit { target, link: Some(link) })
            }
            NeighborState::Incomplete { .. } | NeighborState::Probe { .. } => {
                let entry = self.entries.remove(&target)?;
                Some(NeighborEvent::Unreachable { target, packets: entry.queue })
            }
            NeighborState::Reachable { .. } | NeighborState::Stale { .. } => None,
        }
    }
}
