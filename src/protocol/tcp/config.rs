use core::time::Duration;

use super::{TCPCongestionKind, TCPError};

/// Whether a connection uses Explicit Congestion Notification (RFC 3168,
/// RFC 9293 SHLD-8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TCPECNMode {
    /// Never.
    Off = 0,
    /// When the peer asks for it in its SYN, as Linux does by default.
    #[default]
    Accept = 1,
    /// Asked for in the SYN of an active open, and accepted when asked.
    Request = 2,
}

/// The parameters of a connection. Every limit and time of RFC 9293 and the
/// RFCs it relies on can be changed; the defaults follow them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TCPConfig {
    /// The MTU of the path, from which the MSS this end advertises and the
    /// largest segment it sends follow (RFC 9293 MUST-16, MUST-67).
    pub mtu: u16,
    /// The bytes the send buffer holds: unacknowledged and unsent data.
    pub send_buffer: usize,
    /// The bytes the receive buffer holds: unread and out-of-order data. The
    /// window advertised is the room left.
    pub receive_buffer: usize,
    /// Window scaling (RFC 7323 §2).
    pub window_scale: bool,
    /// Timestamps: RTT measurement and PAWS (RFC 7323 §3–§5).
    pub timestamps: bool,
    /// Selective acknowledgments (RFC 2018, RFC 6675).
    pub sack: bool,
    pub ecn: TCPECNMode,
    /// The Nagle algorithm (RFC 9293 §3.7.4, SHLD-7); it can be turned off
    /// for a connection (MUST-17).
    pub nagle: bool,
    /// How long an acknowledgment may wait for more data: under 0.5 seconds
    /// (MUST-40). One is sent at least for every second full-sized segment
    /// (SHLD-19).
    pub delayed_ack: Duration,
    /// The RTO before any sample (RFC 6298 (2.1)).
    pub initial_rto: Duration,
    /// The lower bound of the RTO (RFC 6298 (2.4)).
    pub minimum_rto: Duration,
    /// The upper bound of the RTO, at least 60 seconds (RFC 6298 (2.5)).
    pub maximum_rto: Duration,
    /// G, the granularity of the RTO's clock (RFC 6298 §2).
    pub clock_granularity: Duration,
    pub congestion: TCPCongestionKind,
    /// The initial window in bytes; that of RFC 5681 §3.1 if `None`.
    pub initial_window: Option<u32>,
    /// R1: the retransmissions of a segment after which the application is
    /// told of the trouble (RFC 9293 MUST-20, SHLD-9, SHLD-10).
    pub retries: u32,
    /// R2: how long a data segment is retransmitted before the connection
    /// is given up (SHLD-11, MUST-21).
    pub user_timeout: Duration,
    /// R2 for a SYN: at least 3 minutes (MUST-23).
    pub connect_timeout: Duration,
    /// Keep-alives, off by default (MAY-5, MUST-24, MUST-25).
    pub keepalive: bool,
    /// The idleness before the first keep-alive: at least two hours by default (MUST-27, MUST-28).
    pub keepalive_idle: Duration,
    /// The time between keep-alives.
    pub keepalive_interval: Duration,
    /// The keep-alives that go unanswered before the connection is given
    /// up, at least 1. One would give up after a single unanswered probe,
    /// which MUST-29 forbids; the default is 9.
    pub keepalive_probes: u32,
    /// TIME-WAIT: twice the Maximum Segment Lifetime of 2 minutes (MUST-13).
    pub time_wait: Duration,
    /// The challenge ACKs sent each second at most (RFC 5961 §7).
    pub challenge_acks: u32,
    /// Whether an ICMP hard error (RFC 9293 §3.9.2.2) aborts a synchronized
    /// connection, as SHLD-26 says. Off by default: it is reported as
    /// trouble, as RFC 5927 §4.2 advises, because an attacker who guesses a
    /// sequence number in flight could otherwise end the connection. A
    /// connection not yet synchronized is always aborted.
    pub hard_error_abort: bool,
}

impl Default for TCPConfig {
    fn default() -> TCPConfig {
        TCPConfig {
            mtu: 1500,
            send_buffer: 256 * 1024,
            receive_buffer: 256 * 1024,
            window_scale: true,
            timestamps: true,
            sack: true,
            ecn: TCPECNMode::Accept,
            nagle: true,
            delayed_ack: Duration::from_millis(40),
            initial_rto: Duration::from_secs(1),
            minimum_rto: Duration::from_secs(1),
            maximum_rto: Duration::from_secs(60),
            clock_granularity: Duration::from_millis(1),
            congestion: TCPCongestionKind::CUBIC,
            initial_window: None,
            retries: 3,
            user_timeout: Duration::from_secs(100),
            connect_timeout: Duration::from_secs(180),
            keepalive: false,
            keepalive_idle: Duration::from_secs(2 * 60 * 60),
            keepalive_interval: Duration::from_secs(75),
            keepalive_probes: 9,
            time_wait: Duration::from_secs(240),
            challenge_acks: 1000,
            hard_error_abort: false,
        }
    }
}

impl TCPConfig {
    /// The smallest MTU: that of IPv4 (RFC 791).
    pub const MINIMUM_MTU: u16 = 68;
    /// The largest buffer: the largest window, 65535 << 14 bytes (RFC 7323
    /// §2.3). Sequence numbers compare modulo 2^32 only within 2^31.
    pub const MAXIMUM_BUFFER: usize = (u16::MAX as usize) << 14;

    /// Checks that the configuration can work, and fails with
    /// [`TCPError::Config`] if it cannot: an MTU below 68, an empty buffer
    /// or one above [`TCPConfig::MAXIMUM_BUFFER`], no keep-alive probe, a
    /// minimum RTO of zero, an RTO whose bounds are reversed or exclude its
    /// initial value, a clock granularity of zero, or an initial window of
    /// zero. Values that
    /// differ from what the RFCs ask but still work, such as a minimum RTO
    /// of 200 ms, are the user's choice.
    pub fn check(&self) -> Result<(), TCPError> {
        let working = self.mtu >= TCPConfig::MINIMUM_MTU
            && (1..=TCPConfig::MAXIMUM_BUFFER).contains(&self.send_buffer)
            && (1..=TCPConfig::MAXIMUM_BUFFER).contains(&self.receive_buffer)
            && self.keepalive_probes > 0
            && !self.minimum_rto.is_zero()
            && self.minimum_rto <= self.maximum_rto
            && (self.minimum_rto..=self.maximum_rto).contains(&self.initial_rto)
            && !self.clock_granularity.is_zero()
            && self.initial_window.is_none_or(|window| window > 0);
        if working { Ok(()) } else { Err(TCPError::Config) }
    }
}
