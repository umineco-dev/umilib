use alloc::vec::Vec;
use core::ops::RangeInclusive;
use core::time::Duration;

use crate::runtime::Instant;

use super::{QUICECNCounts, QUICPacketNumberSpace, QUICRangeSet};

/// The ECN codepoint of a datagram's IP header (RFC 3168 §5, RFC 9000 §13.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum QUICECN {
    #[default]
    NotECT,
    ECT1,
    ECT0,
    CE,
}

/// What an endpoint received in one packet number space and owes
/// acknowledgments for (RFC 9000 §13.2): the packet numbers, when the
/// largest arrived, the ECN counts, and when an ACK frame is due.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QUICReceivedPackets {
    pub received: QUICRangeSet,
    /// The numbers below which every packet counts as a duplicate: their
    /// ranges were dropped (RFC 9000 §13.2.3).
    pub floor: u64,
    /// The largest packet number received and when.
    pub largest: Option<(u64, Instant)>,
    /// Ack-eliciting packets received since the last ACK frame sent.
    pub unacknowledged: u32,
    /// When an ACK frame must go at the latest, if one is owed.
    pub due: Option<Instant>,
    /// Whether one must go now.
    pub immediate: bool,
    pub ecn: QUICECNCounts,
    /// Whether any packet came with an ECN codepoint, which makes ACK
    /// frames report the counts (RFC 9000 §13.4.1).
    pub ecn_seen: bool,
}

impl QUICReceivedPackets {
    /// Ack-eliciting packets after which an ACK goes at once (RFC 9000 §13.2.2: SHOULD after two).
    pub const ACK_ELICITING_THRESHOLD: u32 = 2;

    pub fn new() -> QUICReceivedPackets {
        QUICReceivedPackets::default()
    }

    /// Whether `number` was received already, or is too old to tell.
    pub fn is_duplicate(&self, number: u64) -> bool {
        number < self.floor || self.received.contains(number)
    }

    /// Records packet `number` of `space`, received at `now` with `ecn`
    /// (RFC 9000 §13.2.1, §13.2.2): Initial and Handshake packets that elicit
    /// acknowledgments are acknowledged at once, application packets within
    /// `max_ack_delay`, at once after two, out of order, or marked CE.
    /// At most `limit` ranges are kept: the oldest are forgotten.
    #[allow(clippy::too_many_arguments)]
    pub fn receive(
        &mut self,
        space: QUICPacketNumberSpace,
        number: u64,
        ack_eliciting: bool,
        ecn: QUICECN,
        max_ack_delay: Duration,
        limit: usize,
        now: Instant,
    ) {
        let in_order = self.largest.is_none_or(|(largest, _)| number == largest + 1);
        self.received.insert(number..=number);
        if self.received.len() > limit {
            self.received.truncate(limit);
            self.floor = self.floor.max(self.received.smallest().unwrap_or(0));
        }
        if self.largest.is_none_or(|(largest, _)| number > largest) {
            self.largest = Some((number, now));
        }
        match ecn {
            QUICECN::NotECT => {}
            QUICECN::ECT0 => self.ecn.ect0 += 1,
            QUICECN::ECT1 => self.ecn.ect1 += 1,
            QUICECN::CE => self.ecn.ce += 1,
        }
        self.ecn_seen |= ecn != QUICECN::NotECT;
        if !ack_eliciting {
            return;
        }
        self.unacknowledged += 1;
        let immediate = space != QUICPacketNumberSpace::ApplicationData
            || self.unacknowledged >= QUICReceivedPackets::ACK_ELICITING_THRESHOLD
            || !in_order
            || ecn == QUICECN::CE;
        self.immediate |= immediate;
        let due = now + max_ack_delay;
        self.due = Some(self.due.map_or(due, |earlier| earlier.min(due)));
    }

    /// Whether an ACK frame should go now.
    pub fn wants_ack(&self, now: Instant) -> bool {
        self.immediate || self.due.is_some_and(|due| due <= now)
    }

    /// The ranges to acknowledge, largest first, at most `limit` of them,
    /// and the delay since the largest arrived, encoded with
    /// `exponent` (RFC 9000 §19.3).
    pub fn ack(&self, exponent: u64, limit: usize, now: Instant) -> Option<(Vec<RangeInclusive<u64>>, u64)> {
        let (_, time) = self.largest?;
        let ranges: Vec<RangeInclusive<u64>> = self.received.iter().rev().take(limit).collect();
        let delay = now.saturating_duration_since(time).as_micros() as u64 >> exponent.min(20);
        Some((ranges, delay))
    }

    /// An ACK frame was sent: none is owed until more packets arrive.
    pub fn acknowledged(&mut self) {
        self.unacknowledged = 0;
        self.due = None;
        self.immediate = false;
    }

    /// An ACK frame whose largest was `largest` was acknowledged: the
    /// packets up to it need not be acknowledged again (RFC 9000 §13.2.4).
    pub fn stop_acknowledging(&mut self, largest: u64) {
        // The largest itself stays, for the next frame's Largest Acknowledged.
        self.received.remove_below(largest);
        self.floor = self.floor.max(largest);
    }
}
