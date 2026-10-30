use alloc::vec::Vec;

use crate::runtime::Instant;

use super::{
    QUICError, QUICHeaderProtection, QUICPacketKey, QUICReceiveBuffer, QUICReceivedPackets, QUICSecret, QUICSendBuffer,
    QUICVersionProfile,
};

/// The keys of one direction at one encryption level: the packet key and
/// the header protection key (RFC 9001 §5).
#[derive(Debug)]
pub struct QUICKeys {
    pub packet: QUICPacketKey,
    pub header: QUICHeaderProtection,
}

impl QUICKeys {
    pub fn new(profile: &QUICVersionProfile, secret: &QUICSecret) -> Result<QUICKeys, QUICError> {
        Ok(QUICKeys { packet: secret.packet_key(profile)?, header: secret.header_protection(profile)? })
    }
}

/// A packet number space of a connection (RFC 9000 §12.3): what it
/// received and owes acknowledgments for, its CRYPTO streams, its keys
/// (the Initial and Handshake spaces; 1-RTT keys are [`QUICOneRTT`]), and
/// the next packet number.
#[derive(Debug, Default)]
pub struct QUICSpace {
    pub received: QUICReceivedPackets,
    pub crypto_send: QUICSendBuffer,
    pub crypto_receive: QUICReceiveBuffer,
    pub read: Option<QUICKeys>,
    pub write: Option<QUICKeys>,
    pub next_number: u64,
    /// Whether the keys were discarded (RFC 9001 §4.9): nothing more is
    /// sent or read in this space.
    pub discarded: bool,
    /// Ack-eliciting packets owed as probes after a probe timeout (RFC 9002 §6.2.4).
    pub probes: u8,
    /// Whether a packet received since the last ACK frame sent may be
    /// acknowledged with what goes next.
    pub unacknowledged: bool,
}

impl QUICSpace {
    /// Forgets the keys and what is left to send (RFC 9001 §4.9).
    pub fn discard(&mut self) {
        self.read = None;
        self.write = None;
        self.discarded = true;
        self.crypto_send = QUICSendBuffer::new();
        self.probes = 0;
        self.unacknowledged = false;
        self.received.acknowledged();
    }
}

/// The 1-RTT keys and their key phases (RFC 9001 §6): the current keys of
/// each direction, the next read key computed ahead (§6.3), the previous
/// read key for delayed packets (§6.5), and what governs the next update.
#[derive(Debug)]
pub struct QUICOneRTT {
    pub phase: bool,
    pub read_secret: QUICSecret,
    pub write_secret: QUICSecret,
    pub read: QUICPacketKey,
    pub write: QUICPacketKey,
    pub read_header: QUICHeaderProtection,
    pub write_header: QUICHeaderProtection,
    pub next_read: QUICPacketKey,
    /// The read key of the previous phase, until it is discarded.
    pub previous_read: Option<(QUICPacketKey, Instant)>,
    /// The first packet number sent in the current phase: an update waits
    /// for its acknowledgment (RFC 9001 §6.1).
    pub first_sent: Option<u64>,
    /// The smallest packet number received in the current phase, which
    /// tells delayed packets of the previous phase from those of the next (§6.5).
    pub first_received: Option<u64>,
    /// Whether a packet of the current phase was acknowledged.
    pub acknowledged: bool,
    /// The packets protected with the current write key (§6.6).
    pub written: u64,
}

impl QUICOneRTT {
    pub fn new(
        profile: &QUICVersionProfile,
        read_secret: QUICSecret,
        write_secret: QUICSecret,
    ) -> Result<QUICOneRTT, QUICError> {
        let next_read = read_secret.next(profile)?.packet_key(profile)?;
        Ok(QUICOneRTT {
            phase: false,
            read: read_secret.packet_key(profile)?,
            write: write_secret.packet_key(profile)?,
            read_header: read_secret.header_protection(profile)?,
            write_header: write_secret.header_protection(profile)?,
            read_secret,
            write_secret,
            next_read,
            previous_read: None,
            first_sent: None,
            first_received: None,
            acknowledged: false,
            written: 0,
        })
    }

    /// Moves both directions to the next phase (RFC 9001 §6.1, §6.2): the
    /// current read key becomes the previous one until `discard_at`.
    pub fn update(&mut self, profile: &QUICVersionProfile, discard_at: Instant) -> Result<(), QUICError> {
        self.read_secret = self.read_secret.next(profile)?;
        self.write_secret = self.write_secret.next(profile)?;
        let next_read = self.read_secret.next(profile)?.packet_key(profile)?;
        let read = core::mem::replace(&mut self.next_read, next_read);
        let previous = core::mem::replace(&mut self.read, read);
        self.previous_read = Some((previous, discard_at));
        self.write = self.write_secret.packet_key(profile)?;
        self.phase = !self.phase;
        self.first_sent = None;
        self.first_received = None;
        self.acknowledged = false;
        self.written = 0;
        Ok(())
    }
}

/// Packets that could not be read when they arrived, because their keys
/// were not there yet (RFC 9001 §4.1.4, §5.7): kept, up to a limit, to be
/// read when the keys come.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QUICBufferedPackets {
    pub packets: Vec<(Vec<u8>, super::QUICECN)>,
}
