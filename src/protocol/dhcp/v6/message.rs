use alloc::vec::Vec;
use core::time::Duration;

use crate::crypto::random::Random;
use crate::protocol::ip::IPv6Address;
use crate::runtime::Instant;

use super::super::DHCPError;
use super::{DHCPv6OptionCode, DHCPv6Options};

/// The type of a DHCPv6 message (RFC 9915 §7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DHCPv6MessageType(pub u8);

impl DHCPv6MessageType {
    pub const SOLICIT: DHCPv6MessageType = DHCPv6MessageType(1);
    pub const ADVERTISE: DHCPv6MessageType = DHCPv6MessageType(2);
    pub const REQUEST: DHCPv6MessageType = DHCPv6MessageType(3);
    pub const CONFIRM: DHCPv6MessageType = DHCPv6MessageType(4);
    pub const RENEW: DHCPv6MessageType = DHCPv6MessageType(5);
    pub const REBIND: DHCPv6MessageType = DHCPv6MessageType(6);
    pub const REPLY: DHCPv6MessageType = DHCPv6MessageType(7);
    pub const RELEASE: DHCPv6MessageType = DHCPv6MessageType(8);
    pub const DECLINE: DHCPv6MessageType = DHCPv6MessageType(9);
    pub const RECONFIGURE: DHCPv6MessageType = DHCPv6MessageType(10);
    pub const INFORMATION_REQUEST: DHCPv6MessageType = DHCPv6MessageType(11);
    pub const RELAY_FORW: DHCPv6MessageType = DHCPv6MessageType(12);
    pub const RELAY_REPL: DHCPv6MessageType = DHCPv6MessageType(13);

    pub fn is_relay(&self) -> bool {
        *self == DHCPv6MessageType::RELAY_FORW || *self == DHCPv6MessageType::RELAY_REPL
    }
}

/// A message between a client and a server (RFC 9915 §8): its type, its
/// transaction ID of 24 bits, and its options.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv6Message {
    pub kind: DHCPv6MessageType,
    pub transaction: u32,
    pub options: DHCPv6Options,
}

impl DHCPv6Message {
    pub const CLIENT_PORT: u16 = 546;
    pub const SERVER_PORT: u16 = 547;
    /// All_DHCP_Relay_Agents_and_Servers, ff02::1:2 (§7.1).
    pub const ALL_RELAY_AGENTS_AND_SERVERS: IPv6Address =
        IPv6Address([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2]);

    pub fn new(kind: DHCPv6MessageType, transaction: u32) -> DHCPv6Message {
        DHCPv6Message { kind, transaction: transaction & 0xFF_FFFF, options: DHCPv6Options::new() }
    }

    pub fn decode(bytes: &[u8]) -> Result<DHCPv6Message, DHCPError> {
        let [kind, a, b, c, rest @ ..] = bytes else {
            return Err(DHCPError::Malformed("a message shorter than its header"));
        };
        let kind = DHCPv6MessageType(*kind);
        if kind.is_relay() {
            return Err(DHCPError::Malformed("a relay agent's message"));
        }
        Ok(DHCPv6Message {
            kind,
            transaction: u32::from_be_bytes([0, *a, *b, *c]),
            options: DHCPv6Options::decode(rest)?,
        })
    }

    /// Its bytes; fails for a relay agent's type or a transaction ID of more than 24 bits.
    pub fn encode(&self) -> Result<Vec<u8>, DHCPError> {
        if self.kind.is_relay() {
            return Err(DHCPError::Malformed("a relay agent's message"));
        }
        if self.transaction > 0xFF_FFFF {
            return Err(DHCPError::Malformed("a transaction ID of more than 24 bits"));
        }
        let mut out = alloc::vec![self.kind.0];
        out.extend_from_slice(&self.transaction.to_be_bytes()[1..]);
        self.options.encode(&mut out)?;
        Ok(out)
    }
}

/// A message of relay agents (RFC 9915 §9): its type, hop count, link and
/// peer addresses, and options, one of which carries the relayed message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv6RelayMessage {
    pub kind: DHCPv6MessageType,
    pub hops: u8,
    pub link: IPv6Address,
    pub peer: IPv6Address,
    pub options: DHCPv6Options,
}

impl DHCPv6RelayMessage {
    /// The most hops a Relay-forward may have made (§7.6: HOP_COUNT_LIMIT).
    pub const HOP_COUNT_LIMIT: u8 = 8;

    pub fn decode(bytes: &[u8]) -> Result<DHCPv6RelayMessage, DHCPError> {
        if bytes.len() < 34 {
            return Err(DHCPError::Malformed("a relay message shorter than its header"));
        }
        let kind = DHCPv6MessageType(bytes[0]);
        if !kind.is_relay() {
            return Err(DHCPError::Malformed("not a relay agent's message"));
        }
        Ok(DHCPv6RelayMessage {
            kind,
            hops: bytes[1],
            link: IPv6Address(bytes[2..18].try_into().unwrap_or_default()),
            peer: IPv6Address(bytes[18..34].try_into().unwrap_or_default()),
            options: DHCPv6Options::decode(&bytes[34..])?,
        })
    }

    /// Its bytes; fails for a type that is not a relay agent's.
    pub fn encode(&self) -> Result<Vec<u8>, DHCPError> {
        if !self.kind.is_relay() {
            return Err(DHCPError::Malformed("not a relay agent's message"));
        }
        let mut out = alloc::vec![self.kind.0, self.hops];
        out.extend_from_slice(&self.link.0);
        out.extend_from_slice(&self.peer.0);
        self.options.encode(&mut out)?;
        Ok(out)
    }

    /// The message relayed (the Relay Message option, §21.10).
    pub fn relayed(&self) -> Option<&[u8]> {
        self.options.get(DHCPv6OptionCode::RELAY_MSG)
    }
}

/// The parameters of a client's retransmissions (RFC 9915 §15, table 1):
/// the first timeout, the largest, the most transmissions and the longest
/// time (none of either: no limit), and whether the first timeout's random
/// part is positive (Solicit, §18.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv6Retransmission {
    pub initial: Duration,
    pub maximum: Option<Duration>,
    pub count: Option<usize>,
    pub duration: Option<Duration>,
    pub positive: bool,
}

impl DHCPv6Retransmission {
    pub const SOLICIT: DHCPv6Retransmission = DHCPv6Retransmission::new(1, Some(3600), None, None, true);
    pub const REQUEST: DHCPv6Retransmission = DHCPv6Retransmission::new(1, Some(30), Some(10), None, false);
    pub const CONFIRM: DHCPv6Retransmission = DHCPv6Retransmission::new(1, Some(4), None, Some(10), false);
    pub const RENEW: DHCPv6Retransmission = DHCPv6Retransmission::new(10, Some(600), None, None, false);
    pub const REBIND: DHCPv6Retransmission = DHCPv6Retransmission::new(10, Some(600), None, None, false);
    pub const INFORMATION_REQUEST: DHCPv6Retransmission = DHCPv6Retransmission::new(1, Some(3600), None, None, false);
    pub const RELEASE: DHCPv6Retransmission = DHCPv6Retransmission::new(1, None, Some(4), None, false);
    pub const DECLINE: DHCPv6Retransmission = DHCPv6Retransmission::new(1, None, Some(4), None, false);

    pub const fn new(
        initial: u64,
        maximum: Option<u64>,
        count: Option<usize>,
        duration: Option<u64>,
        positive: bool,
    ) -> DHCPv6Retransmission {
        DHCPv6Retransmission {
            initial: Duration::from_secs(initial),
            maximum: match maximum {
                Some(seconds) => Some(Duration::from_secs(seconds)),
                None => None,
            },
            count,
            duration: match duration {
                Some(seconds) => Some(Duration::from_secs(seconds)),
                None => None,
            },
            positive,
        }
    }

    /// RAND of §15: a number from -0.1 to 0.1 (above 0 if `positive`), in thousandths.
    pub fn random<R: Random>(positive: bool, random: &mut R) -> i64 {
        let value = i64::from(random.next_u32().unwrap_or(0) % 101);
        if positive { value.max(1) } else { value * 2 - 100 }
    }

    /// `duration` times `thousandths` / 1000.
    pub fn scale(duration: Duration, thousandths: i64) -> Duration {
        let millis = duration.as_millis().min(u128::from(u32::MAX)) as i64;
        Duration::from_millis((millis * thousandths / 1000).max(0) as u64)
    }

    /// The first timeout (§15): IRT + RAND × IRT.
    pub fn first<R: Random>(&self, random: &mut R) -> Duration {
        DHCPv6Retransmission::scale(self.initial, 1000 + DHCPv6Retransmission::random(self.positive, random))
    }

    /// The timeout after `previous` (§15): 2 × RTprev + RAND × RTprev, and
    /// above MRT, MRT + RAND × MRT.
    pub fn next<R: Random>(&self, previous: Duration, random: &mut R) -> Duration {
        let timeout = DHCPv6Retransmission::scale(previous, 2000 + DHCPv6Retransmission::random(false, random));
        match self.maximum {
            Some(maximum) if timeout > maximum => {
                DHCPv6Retransmission::scale(maximum, 1000 + DHCPv6Retransmission::random(false, random))
            }
            _ => timeout,
        }
    }

    /// Whether the exchange that began at `started` ends after `sent`
    /// transmissions at `now` (§15: MRC and MRD).
    pub fn is_over(&self, sent: usize, started: Instant, now: Instant) -> bool {
        self.count.is_some_and(|count| sent >= count)
            || self.duration.is_some_and(|duration| now.saturating_duration_since(started) >= duration)
    }

    /// The Elapsed Time option's value (§21.9): hundredths of a second
    /// since the exchange began, at most 0xFFFF.
    pub fn elapsed(started: Instant, now: Instant) -> u16 {
        (now.saturating_duration_since(started).as_millis() / 10).min(0xFFFF) as u16
    }
}
