use alloc::collections::VecDeque;
use core::time::Duration;

use crate::bytes::{Buffer, Writer};
use crate::protocol::ip::{IPAddress, IPEndpoint, IPEndpoints};
use crate::runtime::Instant;

use super::{
    TCPCloseReason, TCPConfig, TCPCongestion, TCPCongestionControl, TCPECNMode, TCPError, TCPEvent, TCPFlags,
    TCPOptionSet, TCPReceiveBuffer, TCPRetransmissionTimer, TCPScoreboard, TCPSegment, TCPSendBuffer, TCPSequence,
    TCPState, TCPTimestamps,
};

/// What [`TCPConnection::transmit`] wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TCPTransmission {
    /// The bytes of the segment written.
    pub length: usize,
    /// Whether its IP header is to carry ECT(0): a segment of new data on a
    /// connection that uses ECN (RFC 3168 §6.1.1, §6.1.4, §6.1.5).
    pub ect: bool,
}

/// An ICMP error about a segment a connection sent (RFC 9293 §3.9.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TCPICMPError {
    /// Destination Unreachable codes 0, 1 and 5, Time Exceeded, Parameter
    /// Problem: the connection goes on (MUST-56).
    Soft,
    /// Destination Unreachable codes 2 to 4: a connection not yet
    /// synchronized is aborted; a synchronized one is aborted if
    /// [`TCPConfig::hard_error_abort`] says so (SHLD-26), and is told of the
    /// trouble otherwise (RFC 5927 §4.2).
    Hard,
    /// Fragmentation Needed or Packet Too Big, with the MTU of the next hop.
    PacketTooBig(u16),
}

/// The loss recovery in progress: NewReno's (RFC 6582) or SACK's (RFC 6675).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TCPRecovery {
    /// The recovery ends when it is acknowledged: `recover` (RFC 6582) or RecoveryPoint (RFC 6675).
    pub point: TCPSequence,
    /// HighRxt + 1: the end of what was retransmitted (RFC 6675).
    pub retransmitted: TCPSequence,
    /// RescueRxt: the RecoveryPoint of the rescue retransmission, once sent
    /// (RFC 6675 NextSeg (4)).
    pub rescue: Option<TCPSequence>,
    /// Whether the recovery is that of RFC 6675.
    pub sack: bool,
}

/// A TCP connection (RFC 9293) without I/O: it is given the segments that
/// arrive, the time and the application's data, and writes the segments to
/// send. The caller demultiplexes segments to it, builds the IP headers
/// around what it writes, and calls [`TCPConnection::transmit`] until it
/// writes nothing after each input and at [`TCPConnection::poll_timeout`].
/// Giving it every segment that arrived before transmitting aggregates the
/// acknowledgments (MUST-58, MUST-59). `C` is the congestion control.
#[derive(Clone, Debug)]
pub struct TCPConnection<C: TCPCongestionControl = TCPCongestion> {
    pub config: TCPConfig,
    pub local: IPEndpoint,
    pub remote: IPEndpoint,
    pub state: TCPState,
    /// Whether the connection was opened passively (MUST-11).
    pub passive: bool,
    /// ISS.
    pub iss: TCPSequence,
    /// SND.UNA.
    pub send_unacknowledged: TCPSequence,
    /// SND.NXT.
    pub send_next: TCPSequence,
    /// The end of the highest data sent.
    pub send_maximum: TCPSequence,
    /// SND.WND, scaled.
    pub send_window: u32,
    /// SND.WL1 and SND.WL2.
    pub send_window_sequence: TCPSequence,
    pub send_window_acknowledgment: TCPSequence,
    /// MAX.SND.WND (RFC 5961 §5.2).
    pub maximum_send_window: u32,
    /// SND.UP: the end of the urgent data sent.
    pub send_urgent: Option<TCPSequence>,
    pub send: TCPSendBuffer,
    /// The application closed: a FIN follows the data.
    pub closing: bool,
    pub fin_sent: bool,
    /// IRS.
    pub irs: TCPSequence,
    pub receive: TCPReceiveBuffer,
    pub fin_received: bool,
    /// The right edge of the window last advertised: RCV.NXT + RCV.WND.
    pub receive_advertised: TCPSequence,
    /// RCV.UP: the end of the urgent data received.
    pub receive_urgent: Option<TCPSequence>,
    pub peer_mss: u16,
    /// The MTU of the path that Packet Too Big reported (RFC 1191, RFC
    /// 8201), if any; [`TCPConnection::mtu`] is the smaller of it and the
    /// configuration's.
    pub path_mtu: Option<u16>,
    /// Whether both SYNs carried Window Scale (RFC 7323 §2.2).
    pub window_scaling: bool,
    pub send_scale: u8,
    pub receive_scale: u8,
    pub sack: bool,
    pub timestamps: bool,
    pub ecn: bool,
    /// TS.Recent and when it was taken (RFC 7323 §4.3, §5.5).
    pub timestamp_recent: u32,
    pub timestamp_recent_at: Instant,
    /// Last.ACK.sent (RFC 7323 §4.3).
    pub last_ack_sent: TCPSequence,
    /// What is added to the clock in milliseconds for TSval (RFC 7323 §5.4).
    pub timestamp_offset: u32,
    pub timer: TCPRetransmissionTimer,
    pub retransmit_at: Option<Instant>,
    /// Expiries of the retransmission timer for SND.UNA, and when the first came (R1, R2).
    pub retransmissions: u32,
    pub first_retransmission: Option<Instant>,
    /// The segment timed for an RTT sample without timestamps: its end and when it was sent.
    pub rtt_sample: Option<(TCPSequence, Instant)>,
    pub persist_at: Option<Instant>,
    pub persist_backoff: u32,
    pub ack_at: Option<Instant>,
    pub ack_now: bool,
    /// Bytes received since the last acknowledgment.
    pub unacknowledged: u32,
    pub keepalive_at: Option<Instant>,
    pub keepalives: u32,
    pub time_wait_at: Option<Instant>,
    /// The time after which data held back by the sender's SWS avoidance is sent (RFC 9293 §3.8.6.2.1).
    pub override_at: Option<Instant>,
    pub override_due: bool,
    pub last_received: Instant,
    /// When data or a SYN or FIN was last sent: the idle period of RFC 5681 §4.1 counts from it.
    pub last_data_sent: Instant,
    /// The smallest data segment sent since nothing was in flight: honest
    /// SACK blocks are at most one per segment in flight (RFC 6675 §5).
    pub smallest_segment: u32,
    pub syn_due: bool,
    pub probe_due: bool,
    pub keepalive_due: bool,
    /// A fast retransmission of the segment at this sequence number (RFC 5681 §3.2, RFC 6582).
    pub retransmit_due: Option<TCPSequence>,
    /// A reset to send: its sequence number, and its acknowledgment number if any.
    pub reset_due: Option<(TCPSequence, Option<TCPSequence>)>,
    pub congestion: C,
    pub recovery: Option<TCPRecovery>,
    /// `recover` (RFC 6582) and RecoveryPoint after a timeout (RFC 6675
    /// §5.1): no new recovery begins before SND.UNA reaches it.
    pub recover: TCPSequence,
    /// DupAcks: the duplicate acknowledgments, as RFC 5681 §2 counts them,
    /// or with SACK those that SACK new data (RFC 6675 §2).
    pub duplicate_acks: u32,
    /// The segments of new data that Limited Transmit lets past cwnd without
    /// SACK, and the bytes Limited Transmit sent, left out of FlightSize at
    /// the next reduction (RFC 5681 §3.2 (1), (2), RFC 3042, RFC 6675 (4.2)).
    pub limited_transmit: u32,
    pub limited_bytes: u32,
    pub scoreboard: TCPScoreboard,
    /// The receiver echoes CE with ECE until a CWR arrives (RFC 3168 §6.1.3).
    pub ecn_echo: bool,
    /// The sender sets CWR on its next new data after a reduction (RFC 3168 §6.1.2).
    pub ecn_cwr_due: bool,
    /// No second reduction, for loss or ECE, before this is acknowledged:
    /// one per window of data (RFC 3168 §6.1.2).
    pub reduced_until: Option<TCPSequence>,
    /// With cwnd at one segment, an ECE holds new data until the RTO has
    /// passed (RFC 3168 §6.1.2).
    pub ecn_hold: Option<Instant>,
    /// The challenge ACKs of the current second: when it began and how many (RFC 5961 §7).
    pub challenges: (Instant, u32),
    pub events: VecDeque<TCPEvent>,
}

impl TCPConnection<TCPCongestion> {
    /// An active open from `local` to `remote` with the initial sequence
    /// number `iss` (from [`TCPISNGenerator`](super::TCPISNGenerator)), and
    /// the congestion control of `config`.
    pub fn connect(
        config: TCPConfig,
        local: IPEndpoint,
        remote: IPEndpoint,
        iss: TCPSequence,
        now: Instant,
    ) -> Result<TCPConnection<TCPCongestion>, TCPError> {
        let congestion =
            TCPCongestion::new(config.congestion, TCPConnection::<TCPCongestion>::initial_window(&config, local));
        TCPConnection::connect_with(config, local, remote, iss, congestion, now)
    }

    /// A passive open from the SYN `syn`, which came from `remote` to
    /// `local`, with the initial sequence number `iss`: the connection is in
    /// SYN-RECEIVED and its SYN-ACK is due.
    pub fn accept(
        config: TCPConfig,
        local: IPEndpoint,
        remote: IPEndpoint,
        syn: &TCPSegment,
        iss: TCPSequence,
        now: Instant,
    ) -> Result<TCPConnection<TCPCongestion>, TCPError> {
        let congestion =
            TCPCongestion::new(config.congestion, TCPConnection::<TCPCongestion>::initial_window(&config, local));
        TCPConnection::accept_with(config, local, remote, syn, iss, congestion, now)
    }

    /// The initial window of RFC 5681 §3.1 for the MSS this end sends, or that of `config`.
    pub fn initial_window(config: &TCPConfig, local: IPEndpoint) -> u32 {
        let mss = TCPConnection::<TCPCongestion>::advertised_mss(config, local) as u32;
        config.initial_window.unwrap_or(TCPCongestion::initial_window(mss))
    }
}

impl<C: TCPCongestionControl> TCPConnection<C> {
    /// The MSS assumed without an MSS option: 536 for IPv4, 1220 for IPv6 (MUST-15).
    pub const DEFAULT_MSS_V4: u16 = 536;
    pub const DEFAULT_MSS_V6: u16 = 1220;
    /// The time after which the sender's SWS avoidance sends what it held (RFC 9293 §3.8.6.2.1: 0.1 to 1 second).
    pub const OVERRIDE: Duration = Duration::from_millis(200);
    /// How long TS.Recent stays valid without being updated (RFC 7323 §5.5).
    pub const TIMESTAMP_LIFETIME: Duration = Duration::from_secs(24 * 24 * 60 * 60);

    /// [`TCPConnection::connect`] with the congestion control `congestion`.
    pub fn connect_with(
        config: TCPConfig,
        local: IPEndpoint,
        remote: IPEndpoint,
        iss: TCPSequence,
        congestion: C,
        now: Instant,
    ) -> Result<TCPConnection<C>, TCPError> {
        // An OPEN to an address that names no single host is refused (MUST-46).
        if !TCPConnection::<C>::is_host(remote.address) || remote.port == 0 {
            return Err(TCPError::Address);
        }
        let mut connection = TCPConnection::new(config, local, remote, iss, congestion, now)?;
        connection.state = TCPState::SynSent;
        connection.ecn = config.ecn == TCPECNMode::Request;
        connection.syn_due = true;
        Ok(connection)
    }

    /// [`TCPConnection::accept`] with the congestion control `congestion`.
    pub fn accept_with(
        config: TCPConfig,
        local: IPEndpoint,
        remote: IPEndpoint,
        syn: &TCPSegment,
        iss: TCPSequence,
        congestion: C,
        now: Instant,
    ) -> Result<TCPConnection<C>, TCPError> {
        if !syn.flags.contains(TCPFlags::SYN) || syn.flags.intersects(TCPFlags::ACK.union(TCPFlags::RST)) {
            return Err(TCPError::State);
        }
        // A SYN from or to an address that names no single host is ignored (MUST-57, MUST-63).
        if !TCPConnection::<C>::is_host(remote.address) || !TCPConnection::<C>::is_host(local.address) {
            return Err(TCPError::Address);
        }
        let mut connection = TCPConnection::new(config, local, remote, iss, congestion, now)?;
        connection.passive = true;
        connection.state = TCPState::SynReceived;
        connection.synchronize(syn, now)?;
        // ECN: a SYN with ECE and CWR asks for it (RFC 3168 §6.1.1).
        connection.ecn = config.ecn != TCPECNMode::Off && syn.flags.contains(TCPFlags::ECE.union(TCPFlags::CWR));
        connection.syn_due = true;
        Ok(connection)
    }

    pub fn new(
        config: TCPConfig,
        local: IPEndpoint,
        remote: IPEndpoint,
        iss: TCPSequence,
        congestion: C,
        now: Instant,
    ) -> Result<TCPConnection<C>, TCPError> {
        if local.address.version() != remote.address.version() {
            return Err(TCPError::Family);
        }
        config.check()?;
        let receive_scale = if config.window_scale { TCPConnection::<C>::scale_for(config.receive_buffer) } else { 0 };
        let peer_mss =
            if matches!(remote.address, IPAddress::V4(_)) { Self::DEFAULT_MSS_V4 } else { Self::DEFAULT_MSS_V6 };
        Ok(TCPConnection {
            config,
            local,
            remote,
            state: TCPState::Closed,
            passive: false,
            iss,
            send_unacknowledged: iss,
            send_next: iss,
            send_maximum: iss,
            send_window: 0,
            send_window_sequence: TCPSequence(0),
            send_window_acknowledgment: iss,
            maximum_send_window: 0,
            send_urgent: None,
            send: TCPSendBuffer::new(iss.add(1), config.send_buffer),
            closing: false,
            fin_sent: false,
            irs: TCPSequence(0),
            receive: TCPReceiveBuffer::new(TCPSequence(0), config.receive_buffer),
            fin_received: false,
            receive_advertised: TCPSequence(0),
            receive_urgent: None,
            peer_mss,
            path_mtu: None,
            window_scaling: false,
            send_scale: 0,
            receive_scale,
            sack: false,
            timestamps: false,
            ecn: false,
            timestamp_recent: 0,
            timestamp_recent_at: now,
            last_ack_sent: TCPSequence(0),
            timestamp_offset: iss.0,
            timer: TCPRetransmissionTimer::new(
                config.initial_rto,
                config.minimum_rto,
                config.maximum_rto,
                config.clock_granularity,
            ),
            retransmit_at: None,
            retransmissions: 0,
            first_retransmission: None,
            rtt_sample: None,
            persist_at: None,
            persist_backoff: 0,
            ack_at: None,
            ack_now: false,
            unacknowledged: 0,
            keepalive_at: None,
            keepalives: 0,
            time_wait_at: None,
            override_at: None,
            override_due: false,
            last_received: now,
            last_data_sent: now,
            smallest_segment: u32::MAX,
            syn_due: false,
            probe_due: false,
            keepalive_due: false,
            retransmit_due: None,
            reset_due: None,
            congestion,
            recovery: None,
            recover: iss,
            duplicate_acks: 0,
            limited_transmit: 0,
            limited_bytes: 0,
            scoreboard: TCPScoreboard::default(),
            ecn_echo: false,
            ecn_cwr_due: false,
            reduced_until: None,
            ecn_hold: None,
            challenges: (now, 0),
            events: VecDeque::new(),
        })
    }

    /// Whether `address` names a single host: not unspecified, multicast or the IPv4 broadcast.
    pub fn is_host(address: IPAddress) -> bool {
        let broadcast = matches!(address, IPAddress::V4(address) if address.is_broadcast());
        !(address.is_unspecified() || address.is_multicast() || broadcast)
    }

    /// The smallest window scale that lets `buffer` bytes be advertised (RFC 7323 §2.3).
    pub fn scale_for(buffer: usize) -> u8 {
        let mut scale = 0;
        while scale < TCPOptionSet::MAXIMUM_WINDOW_SCALE && (buffer >> scale) > u16::MAX as usize {
            scale += 1;
        }
        scale
    }

    /// The length of the IP header of the connection's packets, options aside.
    pub fn ip_header_length(address: IPAddress) -> u32 {
        match address {
            IPAddress::V4(_) => 20,
            IPAddress::V6(_) => 40,
        }
    }

    /// The MSS this end advertises: the MTU less the IP and TCP headers (MUST-67).
    pub fn advertised_mss(config: &TCPConfig, local: IPEndpoint) -> u16 {
        (config.mtu as u32)
            .saturating_sub(TCPConnection::<C>::ip_header_length(local.address) + 20)
            .clamp(1, u16::MAX as u32) as u16
    }

    /// The largest data of a segment with `options` bytes of options: the
    /// smaller of the peer's MSS and what the MTU allows, less the options
    /// (the effective send MSS, MUST-16).
    pub fn segment_size(&self, options: usize) -> u32 {
        let ip = TCPConnection::<C>::ip_header_length(self.local.address);
        let limit = (self.peer_mss as u32 + 20).min((self.mtu() as u32).saturating_sub(ip));
        limit.saturating_sub(20 + options as u32).max(1)
    }

    /// The MTU the segments are sized for: the configuration's, or the
    /// path's if Packet Too Big reported a smaller one.
    pub fn mtu(&self) -> u16 {
        self.path_mtu.map_or(self.config.mtu, |path| path.min(self.config.mtu))
    }

    /// Replaces the configuration, for example to turn Nagle off (MUST-17)
    /// or keep-alives on (MUST-24). The buffers take the new sizes; their
    /// data is kept, and the right edge of the window already advertised
    /// never moves left (SHLD-14). The RTO's bounds and granularity apply
    /// from the next RTO computed; the RTT measured is kept. What the
    /// connection chose when it was made stays as it was, and reads back
    /// so: the options of the handshake (`window_scale`, `timestamps`,
    /// `sack`, `ecn`) and the congestion control. Fails with
    /// [`TCPError::Config`] for a configuration that cannot work.
    pub fn set_config(&mut self, config: TCPConfig, now: Instant) -> Result<(), TCPError> {
        config.check()?;
        self.config = TCPConfig {
            window_scale: self.config.window_scale,
            timestamps: self.config.timestamps,
            sack: self.config.sack,
            ecn: self.config.ecn,
            congestion: self.config.congestion,
            ..config
        };
        self.send.capacity = config.send_buffer;
        self.receive.capacity = config.receive_buffer;
        self.timer.minimum = config.minimum_rto;
        self.timer.maximum = config.maximum_rto;
        self.timer.granularity = config.clock_granularity;
        self.timer.timeout = self.timer.timeout.clamp(config.minimum_rto, config.maximum_rto);
        self.schedule_keepalive(now);
        Ok(())
    }

    /// RCV.WND: from RCV.NXT to the right edge last advertised, 0 once
    /// RCV.NXT reached it.
    pub fn receive_window(&self) -> u32 {
        let next = self.receive_next();
        if self.receive_advertised.is_after(next) {
            self.receive_advertised.distance(next).min(i32::MAX as u32)
        } else {
            0
        }
    }

    /// Queues `event` for the application. Readable, Writable, Urgent and
    /// Trouble say that something is so, not how often: one of each waits
    /// at most.
    pub fn notify(&mut self, event: TCPEvent) {
        let repeatable =
            matches!(event, TCPEvent::Readable | TCPEvent::Writable | TCPEvent::Urgent | TCPEvent::Trouble);
        if !(repeatable && self.events.contains(&event)) {
            self.events.push_back(event);
        }
    }

    /// The SMSS of congestion control: the segment size with the options every segment carries.
    pub fn mss(&self) -> u32 {
        self.segment_size(if self.timestamps { 12 } else { 0 })
    }

    /// RCV.NXT: after the data in order, and after the FIN once it arrived.
    pub fn receive_next(&self) -> TCPSequence {
        self.receive.next.add(self.fin_received as u32)
    }

    /// The data sent and not yet acknowledged (FlightSize, RFC 5681 §2).
    pub fn flight(&self) -> u32 {
        self.send_maximum.distance(self.send_unacknowledged)
    }

    /// The data in the buffer not yet sent from SND.NXT.
    pub fn unsent(&self) -> u32 {
        let end = self.send.end();
        if self.send_next.is_before(end) { end.distance(self.send_next) } else { 0 }
    }

    /// The sequence number of the FIN, once the application closed.
    pub fn fin_sequence(&self) -> Option<TCPSequence> {
        self.closing.then(|| self.send.end())
    }

    /// TSval at `now`: milliseconds, offset for the connection (RFC 7323 §5.4).
    pub fn timestamp(&self, now: Instant) -> u32 {
        ((now.as_nanos() / 1_000_000) as u32).wrapping_add(self.timestamp_offset)
    }

    /// The bytes that can be read.
    pub fn readable(&self) -> usize {
        self.receive.data.len()
    }

    /// The room for data to send.
    pub fn writable(&self) -> usize {
        if self.state.can_send() && !self.closing { self.send.space() } else { 0 }
    }

    /// The urgent bytes not yet read (MUST-33).
    pub fn urgent_remaining(&self) -> u32 {
        match self.receive_urgent {
            Some(urgent) if urgent.is_after(self.receive.read_position()) => {
                urgent.distance(self.receive.read_position())
            }
            _ => 0,
        }
    }

    pub fn poll_event(&mut self) -> Option<TCPEvent> {
        self.events.pop_front()
    }

    /// Takes as much of `data` as fits in the send buffer; fails with
    /// [`TCPError::State`] once the application closed or the connection did.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, TCPError> {
        if !self.state.can_send() || self.closing {
            return Err(TCPError::State);
        }
        Ok(self.send.append(data))
    }

    /// [`TCPConnection::send`], the data being urgent (RFC 9293 §3.8.5, MUST-30, MUST-31).
    pub fn send_urgent(&mut self, data: &[u8]) -> Result<usize, TCPError> {
        let taken = self.send(data)?;
        if taken > 0 {
            self.send_urgent = Some(self.send.end());
        }
        Ok(taken)
    }

    /// Reads into `out` and returns how many bytes; the window may open.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let count = self.receive.read(out);
        // An urgent pointer that was read past is forgotten, so it never wraps (MUST-32, MUST-33).
        if self.receive_urgent.is_some_and(|urgent| urgent.is_at_or_before(self.receive.read_position())) {
            self.receive_urgent = None;
        }
        if count > 0 && self.window_update_due() {
            self.ack_now = true;
        }
        count
    }

    /// Closes the sending half: a FIN follows the data (RFC 9293 §3.10.4).
    /// Fails with [`TCPError::State`] once the connection closed ("connection
    /// does not exist") or the application already closed.
    pub fn close(&mut self) -> Result<(), TCPError> {
        match self.state {
            TCPState::SynSent | TCPState::Listen => {
                self.finish(TCPCloseReason::Aborted);
                Ok(())
            }
            TCPState::SynReceived | TCPState::Established | TCPState::CloseWait if self.closing => Err(TCPError::State),
            TCPState::SynReceived | TCPState::Established | TCPState::CloseWait => {
                self.closing = true;
                Ok(())
            }
            _ => Err(TCPError::State),
        }
    }

    /// Aborts the connection: a reset is sent unless it was not synchronized
    /// or is closing (RFC 9293 §3.10.5). Fails with [`TCPError::State`] once
    /// it closed ("connection does not exist").
    pub fn abort(&mut self) -> Result<(), TCPError> {
        if self.state == TCPState::Closed {
            return Err(TCPError::State);
        }
        if matches!(
            self.state,
            TCPState::SynReceived
                | TCPState::Established
                | TCPState::FinWait1
                | TCPState::FinWait2
                | TCPState::CloseWait
        ) {
            self.reset_due = Some((self.send_next, None));
        }
        self.finish(TCPCloseReason::Aborted);
        Ok(())
    }

    /// Closes the connection for `reason` and tells the application, once.
    pub fn finish(&mut self, reason: TCPCloseReason) {
        if self.state == TCPState::Closed {
            return;
        }
        self.state = TCPState::Closed;
        self.retransmit_at = None;
        self.persist_at = None;
        self.ack_at = None;
        self.keepalive_at = None;
        self.time_wait_at = None;
        self.override_at = None;
        self.ecn_hold = None;
        self.syn_due = false;
        self.ack_now = false;
        self.events.push_back(TCPEvent::Closed(reason));
    }

    /// The earliest timer: a retransmission, a probe, a delayed ACK, a
    /// keep-alive, the end of TIME-WAIT, the SWS override or the end of an
    /// ECN hold. What an input
    /// makes due (a segment, the application's data, a close, an abort, an
    /// ICMP error, a new configuration) is written by the
    /// [`TCPConnection::transmit`] calls that follow that input.
    pub fn poll_timeout(&self) -> Option<Instant> {
        [
            self.retransmit_at,
            self.persist_at,
            self.ack_at,
            self.keepalive_at,
            self.time_wait_at,
            self.override_at,
            self.ecn_hold,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Whether the SYN `syn`, for the endpoints of this connection in
    /// TIME-WAIT, may open a new incarnation (RFC 6191 §2, RFC 9293
    /// SHLD-4): its timestamp is newer than TS.Recent, or equal with a
    /// sequence number past RCV.NXT, or, without timestamps on the old
    /// incarnation, its sequence number is past RCV.NXT or the new one uses
    /// timestamps. If so, the caller forgets this connection and gives the
    /// SYN to its listener.
    pub fn accepts_syn(&self, syn: &TCPSegment) -> bool {
        if self.state != TCPState::TimeWait
            || !syn.flags.contains(TCPFlags::SYN)
            || syn.flags.intersects(TCPFlags::ACK.union(TCPFlags::RST))
        {
            return false;
        }
        let stamps = syn.option_set().ok().and_then(|options| options.timestamps).filter(|_| self.config.timestamps);
        let after = syn.sequence.is_at_or_after(self.receive_next());
        match (self.timestamps, stamps) {
            (true, Some(stamps)) => {
                let value = TCPSequence(stamps.value);
                let recent = TCPSequence(self.timestamp_recent);
                value.is_after(recent) || (value == recent && after)
            }
            (true, None) => after,
            (false, Some(_)) => true,
            (false, None) => after,
        }
    }

    /// An ICMP error about the segment of `sequence` the connection sent
    /// (MUST-54). It is acted on only if `sequence` is in [SND.UNA, SND.NXT)
    /// (RFC 5927 §4.1).
    pub fn receive_error(&mut self, error: TCPICMPError, sequence: TCPSequence, _now: Instant) {
        if self.state == TCPState::Closed
            || !sequence.is_in(self.send_unacknowledged, self.send_maximum.max(self.send_next))
        {
            return;
        }
        match error {
            TCPICMPError::Soft => self.notify(TCPEvent::Trouble),
            TCPICMPError::Hard => {
                if self.state.is_synchronized() && !self.config.hard_error_abort {
                    // Reported, not fatal, unless the configuration says so (RFC 5927 §4.2, SHLD-26).
                    self.notify(TCPEvent::Trouble);
                } else {
                    self.finish(TCPCloseReason::Unreachable);
                }
            }
            TCPICMPError::PacketTooBig(mtu) => {
                let ip = TCPConnection::<C>::ip_header_length(self.local.address);
                let minimum = if ip == 20 { 68 } else { 1280 };
                let mtu = mtu.max(minimum);
                if mtu < self.mtu() {
                    self.path_mtu = Some(mtu);
                    if !self.state.is_synchronized() {
                        // The SYN fits any MTU; the handshake goes on.
                        return;
                    }
                    // Resend what no longer fits (RFC 1191 §6.1, RFC 8201 §5.4).
                    self.send_next = self.send_unacknowledged;
                    self.rtt_sample = None;
                    if self.fin_sent && self.fin_sequence().is_some_and(|fin| self.send_next.is_at_or_before(fin)) {
                        self.fin_sent = false;
                    }
                }
            }
        }
    }

    /// Records what the SYN `syn` of the peer says: IRS, RCV.NXT, the
    /// window, and the options (RFC 9293 §3.10.7.3, RFC 7323, RFC 2018).
    pub fn synchronize(&mut self, syn: &TCPSegment, now: Instant) -> Result<(), TCPError> {
        let options = syn.option_set()?;
        self.irs = syn.sequence;
        self.receive = TCPReceiveBuffer::new(syn.sequence.add(1), self.config.receive_buffer);
        self.receive_advertised = self.receive.next;
        if let Some(mss) = options.mss {
            self.peer_mss = mss.max(1);
        }
        // Window scaling needs Window Scale in both SYNs; a peer sends it in a
        // SYN-ACK only if the SYN had it (RFC 7323 §2.2).
        self.window_scaling = self.config.window_scale && options.window_scale.is_some();
        if self.window_scaling {
            self.send_scale = options.window_scale.unwrap_or(0);
        } else {
            self.send_scale = 0;
            self.receive_scale = 0;
        }
        self.sack = self.config.sack && options.sack_permitted;
        self.timestamps = self.config.timestamps && options.timestamps.is_some();
        if let Some(stamps) = options.timestamps.filter(|_| self.timestamps) {
            self.timestamp_recent = stamps.value;
            self.timestamp_recent_at = now;
        }
        // The window of a SYN is not scaled (RFC 7323 §2.2).
        self.send_window = syn.window as u32;
        self.maximum_send_window = self.send_window;
        self.send_window_sequence = syn.sequence;
        self.send_window_acknowledgment = syn.acknowledgment;
        Ok(())
    }

    /// Processes a segment that arrived for the connection at `now`; `ce`
    /// is whether its IP header carried Congestion Experienced (RFC 3168
    /// §6.1.3). The segment is processed as RFC 9293 §3.10.7 describes.
    pub fn receive(&mut self, segment: &TCPSegment, ce: bool, now: Instant) {
        match self.state {
            TCPState::Closed | TCPState::Listen => {}
            TCPState::SynSent => self.receive_syn_sent(segment, now),
            _ => self.receive_synchronized(segment, ce, now),
        }
    }

    /// RFC 9293 §3.10.7.3.
    pub fn receive_syn_sent(&mut self, segment: &TCPSegment, now: Instant) {
        let flags = segment.flags;
        let acknowledged = flags.contains(TCPFlags::ACK);
        if acknowledged
            && (segment.acknowledgment.is_at_or_before(self.iss) || segment.acknowledgment.is_after(self.send_next))
        {
            if !flags.contains(TCPFlags::RST) {
                self.reset_due = Some((segment.acknowledgment, None));
            }
            return;
        }
        if flags.contains(TCPFlags::RST) {
            // Only a reset that acknowledges the SYN is believed (RFC 5961 §3.2).
            if acknowledged {
                self.finish(TCPCloseReason::Refused);
            }
            return;
        }
        if !flags.contains(TCPFlags::SYN) {
            return;
        }
        if self.synchronize(segment, now).is_err() {
            self.reset_due = Some((if acknowledged { segment.acknowledgment } else { TCPSequence(0) }, None));
            self.finish(TCPCloseReason::Reset);
            return;
        }
        // ECN: a SYN-ACK with ECE and without CWR agrees to it (RFC 3168 §6.1.1).
        self.ecn = self.ecn && flags.contains(TCPFlags::ECE) && !flags.contains(TCPFlags::CWR);
        self.last_received = now;
        if acknowledged {
            self.acknowledge_syn(segment.acknowledgment, segment.option_set().ok(), now);
            self.state = TCPState::Established;
            self.notify(TCPEvent::Connected);
            self.ack_now = true;
            self.schedule_keepalive(now);
            self.receive_text(segment, false, now);
        } else {
            // A simultaneous open: the SYN-ACK is due (RFC 9293 §3.5).
            self.state = TCPState::SynReceived;
            self.syn_due = true;
        }
    }

    /// The acknowledgment of the SYN: SND.UNA moves past ISS.
    pub fn acknowledge_syn(&mut self, acknowledgment: TCPSequence, options: Option<TCPOptionSet>, now: Instant) {
        self.send_unacknowledged = acknowledgment;
        if self.send_maximum.is_before(acknowledgment) {
            self.send_maximum = acknowledgment;
        }
        if self.send_next.is_before(acknowledgment) {
            self.send_next = acknowledgment;
        }
        let rtt = options
            .and_then(|options| options.timestamps)
            .filter(|_| self.timestamps)
            .and_then(|stamps| (stamps.echo_reply != 0).then(|| self.timestamp(now).wrapping_sub(stamps.echo_reply)));
        match (rtt, self.retransmissions) {
            (Some(milliseconds), _) if milliseconds < 60_000 => {
                self.timer.sample(Duration::from_millis(milliseconds as u64))
            }
            (None, 0) => {
                if let Some((_, sent)) = self.rtt_sample {
                    self.timer.sample(now.saturating_duration_since(sent));
                }
            }
            _ => {}
        }
        let lost = self.retransmissions > 0;
        if lost {
            self.timer.restore_after_syn_loss();
        }
        self.rtt_sample = None;
        self.retransmissions = 0;
        self.first_retransmission = None;
        self.retransmit_at = None;
        self.syn_due = false;
        // The initial window of the SMSS now known, one segment if the SYN was lost (RFC 5681 §3.1).
        let mss = self.mss();
        let window = if lost { mss } else { self.config.initial_window.unwrap_or(TCPCongestion::initial_window(mss)) };
        self.congestion.set_window(window);
    }

    /// Whether a segment of `length` from `sequence` is acceptable (RFC 9293 §3.10.7.4, first).
    pub fn acceptable(&self, sequence: TCPSequence, length: u32) -> bool {
        let next = self.receive_next();
        let window = self.receive_window();
        let end = next.add(window);
        match (length, window) {
            (0, 0) => sequence == next,
            (0, _) => sequence.is_in(next, end),
            (_, 0) => false,
            _ => sequence.is_in(next, end) || sequence.add(length - 1).is_in(next, end),
        }
    }

    /// Asks for a challenge ACK, within the limit of RFC 5961 §7.
    pub fn challenge(&mut self, now: Instant) {
        if now.saturating_duration_since(self.challenges.0) >= Duration::from_secs(1) {
            self.challenges = (now, 0);
        }
        if self.challenges.1 < self.config.challenge_acks {
            self.challenges.1 += 1;
            self.ack_now = true;
        }
    }

    /// RFC 9293 §3.10.7.4 for every state from SYN-RECEIVED on.
    pub fn receive_synchronized(&mut self, segment: &TCPSegment, ce: bool, now: Instant) {
        // A window probe's byte is not taken, but its CE is echoed (RFC 3168 §6.1.6).
        let carries_data = !segment.payload.is_empty();
        let mut trimmed = *segment;
        if self.state == TCPState::SynReceived && segment.flags.contains(TCPFlags::SYN) && segment.sequence == self.irs
        {
            if !segment.flags.contains(TCPFlags::ACK) {
                // The SYN again: the SYN-ACK was lost.
                self.syn_due = true;
                return;
            }
            if !self.passive {
                // The SYN-ACK of a simultaneous open (Figure 7): its SYN is
                // trimmed as lying before the window, and what follows is new.
                trimmed.sequence = segment.sequence.add(1);
                trimmed.flags = segment.flags.difference(TCPFlags::SYN);
            }
        }
        let flags = trimmed.flags;
        let Ok(options) = trimmed.option_set() else {
            // An illegal option length resets the connection (MUST-7).
            if !flags.contains(TCPFlags::RST) {
                self.reset_due = Some((self.send_next, None));
                self.finish(TCPCloseReason::Reset);
            }
            return;
        };
        // Timestamps: a segment without one is dropped once they are in use,
        // and PAWS drops old ones (RFC 7323 §3.2, §5.3).
        if self.timestamps && !flags.contains(TCPFlags::RST) {
            let Some(stamps) = options.timestamps else { return };
            let fresh = now.saturating_duration_since(self.timestamp_recent_at) < Self::TIMESTAMP_LIFETIME;
            if fresh && TCPSequence(stamps.value).is_before(TCPSequence(self.timestamp_recent)) {
                self.ack_now = true;
                return;
            }
        }
        let length = trimmed.sequence_length();
        if !self.acceptable(trimmed.sequence, length) {
            if self.receive_window() == 0 && trimmed.sequence == self.receive_next() {
                // A zero window takes no text, but the ACK, URG and RST of a
                // segment at RCV.NXT are still processed (RFC 9293 §3.10.7.4).
                trimmed.payload = &[];
                trimmed.flags = flags.difference(TCPFlags::FIN);
                if !flags.contains(TCPFlags::RST) {
                    self.ack_now = true;
                }
            } else {
                if !flags.contains(TCPFlags::RST) {
                    self.ack_now = true;
                }
                if self.state == TCPState::TimeWait
                    && flags.contains(TCPFlags::FIN)
                    && trimmed.sequence.add(length) == self.receive_next()
                {
                    // The remote FIN again: acknowledge it and restart the 2 MSL timeout (RFC 9293 §3.10.7.4).
                    self.time_wait_at = Some(now.saturating_add(self.config.time_wait));
                }
                return;
            }
        }
        let segment = &trimmed;
        let flags = segment.flags;
        // TS.Recent follows the segments at the left edge (RFC 7323 §4.3).
        if let Some(stamps) = options.timestamps.filter(|_| self.timestamps)
            && segment.sequence.is_at_or_before(self.last_ack_sent)
            && TCPSequence(stamps.value).is_at_or_after(TCPSequence(self.timestamp_recent))
        {
            self.timestamp_recent = stamps.value;
            self.timestamp_recent_at = now;
        }
        if flags.contains(TCPFlags::RST) {
            // Only a reset at RCV.NXT is believed; another in the window asks for a challenge (RFC 5961 §3.2).
            if segment.sequence != self.receive_next() {
                self.challenge(now);
                return;
            }
            let reason = match self.state {
                TCPState::SynReceived if !self.passive => TCPCloseReason::Refused,
                TCPState::Closing | TCPState::LastAck | TCPState::TimeWait => TCPCloseReason::Normal,
                _ => TCPCloseReason::Reset,
            };
            self.finish(reason);
            return;
        }
        if flags.contains(TCPFlags::SYN) {
            if self.state == TCPState::SynReceived && self.passive {
                // A passive open returns to LISTEN (RFC 9293 §3.10.7.4, fourth): the
                // half-open connection ends, and its listener forgets it.
                self.finish(TCPCloseReason::Reset);
                return;
            }
            // A SYN in a synchronized state asks for a challenge (RFC 5961 §4.2).
            self.challenge(now);
            return;
        }
        if !flags.contains(TCPFlags::ACK) {
            return;
        }
        self.last_received = now;
        self.keepalives = 0;
        self.schedule_keepalive(now);
        // The acceptable ACKs (RFC 5961 §5.2): SND.UNA - MAX.SND.WND <= SEG.ACK <= SND.NXT.
        let acknowledgment = segment.acknowledgment;
        let lowest = self.send_unacknowledged.sub(self.maximum_send_window);
        let highest = self.send_next.max(self.send_maximum);
        if acknowledgment.is_before(lowest) || acknowledgment.is_after(highest) {
            self.challenge(now);
            return;
        }
        if self.state == TCPState::SynReceived {
            if acknowledgment.is_after(self.send_unacknowledged) {
                self.acknowledge_syn(acknowledgment, Some(options), now);
                self.state = TCPState::Established;
                self.notify(TCPEvent::Connected);
                self.update_window(segment);
                self.schedule_keepalive(now);
            } else {
                self.reset_due = Some((acknowledgment, None));
                return;
            }
        } else {
            self.receive_acknowledgment(segment, &options, now);
        }
        if self.state == TCPState::Closed {
            return;
        }
        // The urgent pointer (RFC 9293 §3.10.7.4, sixth, MUST-62).
        if flags.contains(TCPFlags::URG) && self.state.can_receive() {
            let urgent = segment.sequence.add(segment.urgent_pointer as u32);
            if self.receive_urgent.is_none_or(|previous| urgent.is_after(previous)) {
                self.receive_urgent = Some(urgent);
                self.notify(TCPEvent::Urgent);
            }
        }
        // CWR ends the echo, and CE on the same segment starts it again (RFC 3168 §6.1.3).
        if flags.contains(TCPFlags::CWR) {
            self.ecn_echo = false;
        }
        if ce && self.ecn && carries_data {
            self.ecn_echo = true;
        }
        self.receive_text(segment, ce, now);
    }

    /// The ACK field of a segment in a synchronized state (RFC 9293 §3.10.7.4, fifth).
    pub fn receive_acknowledgment(&mut self, segment: &TCPSegment, options: &TCPOptionSet, now: Instant) {
        let acknowledgment = segment.acknowledgment;
        let mss = self.mss();
        let flight = self.flight();
        let sacked = self.scoreboard.sacked();
        if self.sack {
            let limit = TCPScoreboard::limit(flight, self.smallest_segment.min(mss));
            self.scoreboard.update(options.sack(), self.send_unacknowledged, self.send_maximum, limit);
        }
        let new_sack = self.scoreboard.sacked() > sacked;
        let ece = self.ecn && segment.flags.contains(TCPFlags::ECE);
        // A duplicate: with SACK, an ACK that SACKs new data (RFC 6675 §2);
        // without, one that changes nothing (RFC 5681 §2).
        // A closed window is not a loss: the answers to window probes are not duplicates (RFC 9293 §3.8.6.1).
        let duplicate = flight > 0
            && self.send_window > 0
            && if self.sack {
                new_sack
            } else {
                acknowledgment == self.send_unacknowledged
                    && segment.payload.is_empty()
                    && !segment.flags.intersects(TCPFlags::SYN.union(TCPFlags::FIN))
                    && (segment.window as u32) << self.send_scale == self.send_window
            };
        if acknowledgment.is_after(self.send_unacknowledged) {
            let acknowledged = acknowledgment.distance(self.send_unacknowledged);
            self.take_rtt_sample(acknowledgment, options.timestamps, now);
            // The FIN is acknowledged by any ACK past it, even one that comes after a timeout
            // made it due again: an ACK beyond SND.MAX was refused above, so the FIN was sent.
            let fin_was = self.fin_sequence();
            self.send.acknowledge(acknowledgment);
            self.send_unacknowledged = acknowledgment;
            if self.send_next.is_before(acknowledgment) {
                self.send_next = acknowledgment;
            }
            if self.recover.is_before(acknowledgment) {
                // Kept near SND.UNA, so that it compares right modulo 2^32.
                self.recover = acknowledgment;
            }
            if self.reduced_until.is_some_and(|until| acknowledgment.is_at_or_after(until)) {
                // The window of the last reduction is acknowledged; forgotten, so it never wraps.
                self.reduced_until = None;
            }
            if acknowledgment == self.send_maximum {
                self.smallest_segment = u32::MAX;
            }
            self.scoreboard.acknowledge(acknowledgment);
            self.retransmissions = 0;
            self.first_retransmission = None;
            self.persist_backoff = 0;
            if let Some(urgent) = self.send_urgent
                && urgent.is_at_or_before(acknowledgment)
            {
                self.send_urgent = None;
            }
            self.acknowledged_in_recovery(acknowledgment, acknowledged, flight, mss, ece, now);
            // The retransmission timer restarts, or stops when nothing is outstanding (RFC 6298 (5.2), (5.3)).
            self.retransmit_at = if self.flight() > 0 || self.send_next.is_before(self.send_maximum) {
                Some(now.saturating_add(self.timer.current()))
            } else {
                None
            };
            if self.send.space() > 0 && self.state.can_send() && !self.closing {
                self.notify(TCPEvent::Writable);
            }
            if let Some(fin) = fin_was
                && acknowledgment.is_after(fin)
            {
                self.fin_sent = true;
                self.fin_acknowledged(now);
            }
        }
        if ece {
            self.echo_received(flight, mss, now);
        }
        if duplicate {
            self.duplicate_acknowledgment(flight, mss, now);
        }
        self.update_window(segment);
    }

    /// An ECN-Echo: cwnd is reduced once per window of data, as for a loss,
    /// and with cwnd at one segment new data waits for the RTO (RFC 3168 §6.1.2).
    pub fn echo_received(&mut self, flight: u32, mss: u32, now: Instant) {
        if self.reduced_until.is_some_and(|until| self.send_unacknowledged.is_before(until)) {
            return;
        }
        if self.congestion.window() <= mss {
            self.ecn_hold = Some(now.saturating_add(self.timer.current()));
            if self.flight() > 0 {
                self.retransmit_at = Some(now.saturating_add(self.timer.current()));
            }
        }
        self.congestion.congestion(flight, mss, true, now);
        self.reduced_until = Some(self.send_maximum);
        self.ecn_cwr_due = true;
    }

    /// Takes an RTT sample from the timestamps, or from the timed segment
    /// unless it was retransmitted (Karn's algorithm, MUST-18).
    pub fn take_rtt_sample(&mut self, acknowledgment: TCPSequence, stamps: Option<TCPTimestamps>, now: Instant) {
        if let Some(stamps) = stamps.filter(|stamps| self.timestamps && stamps.echo_reply != 0) {
            let milliseconds = self.timestamp(now).wrapping_sub(stamps.echo_reply);
            if milliseconds < 60_000 {
                self.timer.sample(Duration::from_millis(milliseconds as u64));
            }
            return;
        }
        if let Some((end, sent)) = self.rtt_sample
            && acknowledgment.is_at_or_after(end)
        {
            self.timer.sample(now.saturating_duration_since(sent));
            self.rtt_sample = None;
        }
    }

    /// New data acknowledged: congestion control and loss recovery (RFC 5681, RFC 6582, RFC 6675).
    pub fn acknowledged_in_recovery(
        &mut self,
        acknowledgment: TCPSequence,
        acknowledged: u32,
        flight: u32,
        mss: u32,
        ece: bool,
        now: Instant,
    ) {
        let rtt = self.timer.smoothed.unwrap_or(self.timer.timeout);
        match self.recovery {
            None => {
                self.duplicate_acks = 0;
                self.limited_transmit = 0;
                self.limited_bytes = 0;
                // No growth for an ACK that echoes congestion (RFC 3168 §6.1.2).
                if !ece {
                    let limited = flight < self.congestion.window().saturating_sub(mss);
                    self.congestion.acknowledge(acknowledged, mss, rtt, limited, now);
                }
            }
            Some(recovery) if acknowledgment.is_at_or_after(recovery.point) => {
                // A full acknowledgment ends the recovery (RFC 6582 §3.2 (3), RFC 6675 §5).
                self.recovery = None;
                self.duplicate_acks = 0;
                let threshold = self.congestion.threshold();
                let window = if recovery.sack { threshold } else { threshold.min(self.flight().max(mss) + mss) };
                self.congestion.set_window(window);
            }
            Some(recovery) if !recovery.sack => {
                // A partial acknowledgment: retransmit the next hole and deflate (RFC 6582 §3.2 (5)).
                self.duplicate_acks = 0;
                self.retransmit_due = Some(acknowledgment);
                let window = self.congestion.window().saturating_sub(acknowledged);
                let window = if acknowledged >= mss { window.saturating_add(mss) } else { window };
                self.congestion.set_window(window.max(mss));
            }
            Some(_) => {}
        }
    }

    /// A duplicate acknowledgment (RFC 5681 §3.2, RFC 6582 §3.2, RFC 6675 §5).
    pub fn duplicate_acknowledgment(&mut self, flight: u32, mss: u32, now: Instant) {
        match self.recovery {
            Some(recovery) if !recovery.sack => {
                // Each further duplicate inflates cwnd by a segment (RFC 6582 §3.2 (4)).
                self.congestion.set_window(self.congestion.window().saturating_add(mss));
            }
            // In SACK recovery the scoreboard drives what is sent (RFC 6675 (B), (C)).
            Some(_) => {}
            None => {
                self.duplicate_acks += 1;
                // Limited Transmit: without SACK, a segment of new data for each of
                // the first two duplicates (RFC 5681 §3.2 (1)); with SACK, pipe
                // decides (RFC 6675 (3)).
                if !self.sack && self.duplicate_acks <= 2 {
                    self.limited_transmit = self.duplicate_acks;
                }
                let lost = self.sack
                    && self.scoreboard.is_lost(
                        self.send_unacknowledged,
                        self.send_unacknowledged,
                        self.send_maximum,
                        mss,
                    );
                // No new recovery before SND.UNA reaches `recover` (RFC 6582 §3.2 (1), RFC 6675 §5.1).
                let allowed = self.send_unacknowledged.is_at_or_after(self.recover);
                if allowed && (self.duplicate_acks >= TCPScoreboard::DUPLICATE_THRESHOLD || lost) {
                    self.enter_recovery(flight, mss, now);
                }
            }
        }
    }

    /// Loss found: fast retransmit and recovery (RFC 5681 §3.2, RFC 6582 §3.2 (2), RFC 6675 (4)).
    pub fn enter_recovery(&mut self, flight: u32, mss: u32, now: Instant) {
        // One reduction per window, ECE included (RFC 3168 §6.1.2); what Limited
        // Transmit sent is not part of FlightSize here (RFC 5681 §3.2 (2)).
        if self.reduced_until.is_none_or(|until| self.send_unacknowledged.is_at_or_after(until)) {
            self.congestion.congestion(flight.saturating_sub(self.limited_bytes), mss, false, now);
        }
        self.limited_transmit = 0;
        self.limited_bytes = 0;
        self.recovery = Some(TCPRecovery {
            point: self.send_maximum,
            retransmitted: self.send_unacknowledged,
            rescue: None,
            sack: self.sack,
        });
        self.recover = self.send_maximum;
        self.reduced_until = Some(self.send_maximum);
        if !self.sack {
            // cwnd = ssthresh + 3 SMSS (RFC 6582 §3.2 (2)).
            self.congestion.set_window(self.congestion.threshold().saturating_add(3 * mss));
        }
        // The segment at SND.UNA is sent again at once (RFC 5681 §3.2 (2), RFC 6675 (4.3)).
        self.retransmit_due = Some(self.send_unacknowledged);
        self.rtt_sample = None;
    }

    /// The window fields of a segment (RFC 9293 §3.10.7.4, fifth).
    pub fn update_window(&mut self, segment: &TCPSegment) {
        // Only an ACK in [SND.UNA, SND.NXT] updates the window (RFC 9293 §3.10.7.4, fifth).
        let highest = self.send_next.max(self.send_maximum);
        if segment.acknowledgment.is_before(self.send_unacknowledged) || segment.acknowledgment.is_after(highest) {
            return;
        }
        let newer = self.send_window_sequence.is_before(segment.sequence)
            || (self.send_window_sequence == segment.sequence
                && self.send_window_acknowledgment.is_at_or_before(segment.acknowledgment));
        if !newer {
            return;
        }
        let window = (segment.window as u32) << self.send_scale;
        self.send_window = window;
        self.maximum_send_window = self.maximum_send_window.max(window);
        self.send_window_sequence = segment.sequence;
        self.send_window_acknowledgment = segment.acknowledgment;
        if window > 0 {
            self.persist_at = None;
            self.persist_backoff = 0;
        }
    }

    /// The FIN this end sent was acknowledged.
    pub fn fin_acknowledged(&mut self, now: Instant) {
        match self.state {
            TCPState::FinWait1 => self.state = TCPState::FinWait2,
            TCPState::Closing => self.enter_time_wait(now),
            TCPState::LastAck => self.finish(TCPCloseReason::Normal),
            _ => {}
        }
    }

    pub fn enter_time_wait(&mut self, now: Instant) {
        self.state = TCPState::TimeWait;
        self.retransmit_at = None;
        self.persist_at = None;
        self.keepalive_at = None;
        self.time_wait_at = Some(now.saturating_add(self.config.time_wait));
    }

    /// The data and the FIN of a segment (RFC 9293 §3.10.7.4, seventh and eighth).
    pub fn receive_text(&mut self, segment: &TCPSegment, ce: bool, now: Instant) {
        let data_start = if segment.flags.contains(TCPFlags::SYN) { segment.sequence.add(1) } else { segment.sequence };
        if !segment.payload.is_empty() {
            if self.state.can_receive() {
                let limit = self.receive_advertised;
                let before = self.receive.next;
                let in_order = self.receive.insert(data_start, segment.payload, limit);
                if in_order > 0 {
                    self.notify(TCPEvent::Readable);
                    self.unacknowledged = self.unacknowledged.saturating_add(in_order as u32);
                    // An ACK for every second full-sized segment (SHLD-19), at once when a hole is filled.
                    let filled = !self.receive.pending.is_empty()
                        || self.receive.next.distance(before) as usize > segment.payload.len();
                    // RMSS: the MSS this end advertised, less the options every segment carries.
                    let options = if self.timestamps { 12 } else { 0 };
                    let rmss =
                        (TCPConnection::<C>::advertised_mss(&self.config, self.local) as u32).saturating_sub(options);
                    if self.unacknowledged >= 2 * rmss || filled || ce {
                        self.ack_now = true;
                    } else if self.ack_at.is_none() {
                        self.ack_at = Some(now.saturating_add(self.config.delayed_ack));
                    }
                } else {
                    // Out of order or a duplicate: an ACK at once (RFC 5681 §4.2).
                    self.ack_now = true;
                }
            } else {
                self.ack_now = true;
            }
        }
        if segment.flags.contains(TCPFlags::FIN) {
            let fin = data_start.add(segment.payload.len() as u32);
            // The FIN counts only within the window (RFC 9293 §3.10.7.4: segments are trimmed to it).
            let in_window = fin.is_before(self.receive_advertised);
            if fin == self.receive.next && in_window && !self.fin_received && self.state.can_receive() {
                self.fin_received = true;
                self.ack_now = true;
                self.notify(TCPEvent::PeerClosed);
                let fin_acknowledged =
                    self.fin_sent && self.fin_sequence().is_some_and(|fin| self.send_unacknowledged.is_after(fin));
                match self.state {
                    TCPState::SynReceived | TCPState::Established => self.state = TCPState::CloseWait,
                    TCPState::FinWait1 if fin_acknowledged => self.enter_time_wait(now),
                    TCPState::FinWait1 => self.state = TCPState::Closing,
                    TCPState::FinWait2 => self.enter_time_wait(now),
                    _ => {}
                }
            } else {
                // A FIN that cannot be taken yet is acknowledged, so the peer sends it again.
                self.ack_now = true;
            }
        }
    }

    pub fn schedule_keepalive(&mut self, now: Instant) {
        self.keepalive_at = (self.config.keepalive
            && matches!(self.state, TCPState::Established | TCPState::CloseWait))
        .then(|| now.saturating_add(self.config.keepalive_idle));
    }

    /// Whether reading opened the window enough to say so (RFC 9293 §3.8.6.2.2).
    pub fn window_update_due(&self) -> bool {
        let edge = self.receive.next.add(self.receive.space() as u32);
        let threshold = (self.config.receive_buffer / 2)
            .min(TCPConnection::<C>::advertised_mss(&self.config, self.local) as usize) as u32;
        edge.is_after(self.receive_advertised) && edge.distance(self.receive_advertised) >= threshold
    }

    /// The timers due at `now` (RFC 6298 §5, RFC 9293 §3.8.6.1, §3.8.4, §3.6).
    pub fn expire(&mut self, now: Instant) {
        if self.time_wait_at.is_some_and(|at| at <= now) {
            self.time_wait_at = None;
            self.finish(TCPCloseReason::Normal);
            return;
        }
        if self.retransmit_at.is_some_and(|at| at <= now) {
            self.retransmit_at = None;
            self.retransmission_timeout(now);
            if self.state == TCPState::Closed {
                return;
            }
        }
        if self.persist_at.is_some_and(|at| at <= now) {
            self.persist_at = None;
            self.probe_due = true;
        }
        if self.ack_at.is_some_and(|at| at <= now) {
            self.ack_at = None;
            self.ack_now = true;
        }
        if self.override_at.is_some_and(|at| at <= now) {
            self.override_at = None;
            self.override_due = true;
        }
        if self.ecn_hold.is_some_and(|at| at <= now) {
            self.ecn_hold = None;
        }
        if self.keepalive_at.is_some_and(|at| at <= now) {
            if self.flight() == 0 {
                if self.keepalives >= self.config.keepalive_probes {
                    self.finish(TCPCloseReason::Timeout);
                    return;
                }
                self.keepalives += 1;
                self.keepalive_due = true;
            }
            self.keepalive_at = Some(now.saturating_add(self.config.keepalive_interval));
        }
    }

    /// The retransmission timer expired (RFC 6298 (5.4)–(5.6), RFC 9293 MUST-20).
    pub fn retransmission_timeout(&mut self, now: Instant) {
        let first = *self.first_retransmission.get_or_insert(now);
        let limit = if self.state.is_synchronized() { self.config.user_timeout } else { self.config.connect_timeout };
        if now.saturating_duration_since(first) >= limit {
            self.finish(TCPCloseReason::Timeout);
            return;
        }
        self.retransmissions += 1;
        if self.retransmissions == self.config.retries {
            self.notify(TCPEvent::Trouble);
        }
        self.timer.expire();
        self.rtt_sample = None;
        match self.state {
            TCPState::SynSent | TCPState::SynReceived => self.syn_due = true,
            _ => {
                let mss = self.mss();
                self.congestion.timeout(self.flight(), mss, now);
                self.recovery = None;
                // No fast recovery for what was sent before the timeout (RFC 6582 §3.2 (4), RFC 6675 §5.1).
                self.recover = self.send_maximum;
                self.reduced_until = Some(self.send_maximum);
                self.duplicate_acks = 0;
                self.limited_transmit = 0;
                self.limited_bytes = 0;
                self.scoreboard.clear();
                // Go back to SND.UNA (RFC 9293 §3.8.1).
                self.send_next = self.send_unacknowledged;
                if self.fin_sent && self.fin_sequence().is_some_and(|fin| self.send_next.is_at_or_before(fin)) {
                    self.fin_sent = false;
                }
            }
        }
        self.retransmit_at = Some(now.saturating_add(self.timer.current()));
    }

    /// Writes the next segment due at `now` into `out`, if any. Call it until it returns `None`.
    pub fn transmit(&mut self, now: Instant, out: &mut impl Writer) -> Result<Option<TCPTransmission>, TCPError> {
        self.expire(now);
        if let Some((sequence, acknowledgment)) = self.reset_due.take() {
            let flags = if acknowledgment.is_some() { TCPFlags::RST.union(TCPFlags::ACK) } else { TCPFlags::RST };
            return self.write(sequence, flags, &[], 0, false, now, out).map(Some);
        }
        match self.state {
            TCPState::Closed | TCPState::Listen => return Ok(None),
            TCPState::SynSent if self.syn_due => return self.write_syn(false, now, out).map(Some),
            TCPState::SynReceived if self.syn_due => return self.write_syn(true, now, out).map(Some),
            TCPState::SynSent | TCPState::SynReceived => {
                return if self.ack_now { self.write_ack(now, out).map(Some) } else { Ok(None) };
            }
            _ => {}
        }
        if let Some(transmission) = self.write_data(now, out)? {
            return Ok(Some(transmission));
        }
        if self.keepalive_due {
            self.keepalive_due = false;
            // A probe one before SND.NXT, without data (RFC 9293 §3.8.4, SHLD-12).
            let sequence = self.send_next.sub(1);
            return self.write(sequence, TCPFlags::ACK, &[], 0, false, now, out).map(Some);
        }
        if self.ack_now {
            return self.write_ack(now, out).map(Some);
        }
        Ok(None)
    }

    /// The SYN, or the SYN-ACK of `acknowledge`, with this end's options.
    pub fn write_syn(
        &mut self,
        acknowledge: bool,
        now: Instant,
        out: &mut impl Writer,
    ) -> Result<TCPTransmission, TCPError> {
        self.syn_due = false;
        let mut options = TCPOptionSet {
            mss: Some(TCPConnection::<C>::advertised_mss(&self.config, self.local)),
            ..TCPOptionSet::default()
        };
        if acknowledge {
            options.window_scale = self.window_scaling.then_some(self.receive_scale);
            options.sack_permitted = self.sack;
            options.timestamps = self
                .timestamps
                .then(|| TCPTimestamps { value: self.timestamp(now), echo_reply: self.timestamp_recent });
        } else {
            options.window_scale = self.config.window_scale.then_some(self.receive_scale);
            options.sack_permitted = self.config.sack;
            options.timestamps =
                self.config.timestamps.then(|| TCPTimestamps { value: self.timestamp(now), echo_reply: 0 });
        }
        let mut bytes = Buffer::new();
        options.encode(&mut bytes)?;
        let mut flags = TCPFlags::SYN;
        if acknowledge {
            flags = flags.union(TCPFlags::ACK);
            if self.ecn {
                flags = flags.union(TCPFlags::ECE);
            }
        } else if self.ecn {
            flags = flags.union(TCPFlags::ECE).union(TCPFlags::CWR);
        }
        let window = (self.receive.space().min(u16::MAX as usize)) as u16;
        let segment = TCPSegment {
            source_port: self.local.port,
            destination_port: self.remote.port,
            sequence: self.iss,
            acknowledgment: if acknowledge { self.receive_next() } else { TCPSequence(0) },
            flags,
            window,
            urgent_pointer: 0,
            options: bytes.as_slice(),
            payload: &[],
        };
        segment.encode(self.local.address, self.remote.address, out)?;
        if acknowledge {
            self.receive_advertised = self.receive.next.add(window as u32);
            self.last_ack_sent = self.receive_next();
        }
        self.send_next = self.iss.add(1);
        if self.send_maximum.is_before(self.send_next) {
            self.send_maximum = self.send_next;
        }
        if self.retransmissions == 0 && self.rtt_sample.is_none() {
            self.rtt_sample = Some((self.iss.add(1), now));
        }
        if self.retransmit_at.is_none() {
            self.retransmit_at = Some(now.saturating_add(self.timer.current()));
        }
        self.last_data_sent = now;
        Ok(TCPTransmission { length: segment.length(), ect: false })
    }

    /// Writes a pure acknowledgment.
    pub fn write_ack(&mut self, now: Instant, out: &mut impl Writer) -> Result<TCPTransmission, TCPError> {
        self.write(self.send_next, TCPFlags::ACK, &[], 0, false, now, out)
    }

    /// Writes the data or FIN that the windows and the rules of sending allow, if any.
    pub fn write_data(&mut self, now: Instant, out: &mut impl Writer) -> Result<Option<TCPTransmission>, TCPError> {
        if !matches!(
            self.state,
            TCPState::Established | TCPState::CloseWait | TCPState::FinWait1 | TCPState::Closing | TCPState::LastAck
        ) {
            return Ok(None);
        }
        let options_length = self.data_options_length();
        let size = self.segment_size(options_length);
        // A fast retransmission (RFC 5681 §3.2, RFC 6582 §3.2, RFC 6675 (4.3)).
        if let Some(sequence) = self.retransmit_due.take()
            && sequence.is_before(self.send_maximum)
        {
            let mut length = (self.send_maximum.distance(sequence)).min(size);
            // With SACK, the segment presumed dropped ends where the SACKed data starts (RFC 6675 (4.3)).
            if self.sack
                && let Some((start, hole)) =
                    self.scoreboard.next_unsacked(sequence, self.send_unacknowledged, self.send_maximum)
                && start == sequence
            {
                length = length.min(hole);
            }
            if let Some(recovery) = self.recovery.as_mut().filter(|recovery| recovery.sack) {
                if sequence.add(length).is_after(recovery.retransmitted) {
                    recovery.retransmitted = sequence.add(length);
                }
                // HighRxt and RescueRxt both move past the segment at entry (RFC 6675 (4.3)), so
                // that the rescue does not repeat it.
                recovery.rescue.get_or_insert(sequence.add(length));
            }
            return self.write_range(sequence, length, false, now, out).map(Some);
        }
        if self.recovery.is_some_and(|recovery| recovery.sack) {
            return self.write_sack_recovery(size, now, out);
        }
        // Zero-window probes (RFC 9293 §3.8.6.1, MUST-36): one byte past the window.
        let pending = self.unsent() as usize + (self.closing && !self.fin_sent) as usize;
        if self.probe_due {
            self.probe_due = false;
            if pending > 0 && self.send_window == 0 {
                // Probes that go unanswered for R2 give the connection up (RFC 9293 §3.8.6.1, MUST-37).
                if self.persist_backoff > 0
                    && now.saturating_duration_since(self.last_received) >= self.config.user_timeout
                {
                    self.finish(TCPCloseReason::Timeout);
                    return Ok(None);
                }
                self.persist_backoff = self.persist_backoff.saturating_add(1);
                let sequence = self.send_next;
                let data = self.unsent() > 0;
                // Not new data: no ECT and no CWR on a probe (RFC 3168 §6.1.6).
                let probe = self.write_range(sequence, 1, false, now, out)?;
                if data {
                    // The byte is sent again when the window opens, unless the probe's ACK covers it.
                    self.send_next = sequence;
                }
                self.retransmit_at = None;
                self.schedule_persist(now);
                return Ok(Some(probe));
            }
        }
        if pending == 0 || self.ecn_hold.is_some() {
            return Ok(None);
        }
        // Before a SACK recovery, Limited Transmit sends while cwnd - pipe >= 1 SMSS (RFC 6675 (3)).
        let limited = self.sack && self.duplicate_acks > 0;
        let in_flight = if limited {
            self.scoreboard.pipe(self.send_unacknowledged, self.send_maximum, self.send_unacknowledged, self.mss())
        } else {
            self.send_next.distance(self.send_unacknowledged)
        };
        let window = self.send_window.min(self.congestion_window(size));
        let usable = window.saturating_sub(in_flight);
        if self.send_window == 0 || usable == 0 || (limited && usable < self.mss()) {
            if self.send_window == 0 && self.flight() == 0 && self.persist_at.is_none() {
                self.schedule_persist(now);
            }
            return Ok(None);
        }
        // After an idle period cwnd restarts (RFC 5681 §4.1).
        if self.flight() == 0 && now.saturating_duration_since(self.last_data_sent) > self.timer.current() {
            let restart = self.config.initial_window.unwrap_or(TCPCongestion::initial_window(self.mss()));
            self.congestion.restart(restart, now);
        }
        let window = self.send_window.min(self.congestion_window(size));
        let usable = window.saturating_sub(in_flight);
        // The receiver's window counts from SND.UNA whatever pipe says.
        let room = self.send_window.saturating_sub(self.send_next.distance(self.send_unacknowledged));
        let data = self.unsent();
        let length = data.min(usable).min(room).min(size);
        let fin_now = self.closing && !self.fin_sent && length == data && usable > data && room > data;
        // The sender's SWS avoidance and Nagle (RFC 9293 §3.8.6.2.1, §3.7.4).
        let full = length >= size;
        let all = length == data;
        let nagle = !self.config.nagle || in_flight == 0 || fin_now;
        let half_window = length >= self.maximum_send_window / 2 && length > 0;
        let overridden = core::mem::take(&mut self.override_due) && length > 0;
        if !(full || (all && nagle) || half_window || overridden || (length == 0 && fin_now)) {
            if !all && self.override_at.is_none() {
                self.override_at = Some(now.saturating_add(Self::OVERRIDE));
            }
            return Ok(None);
        }
        self.override_at = None;
        let new_data = !self.send_next.is_before(self.send_maximum);
        self.write_range(self.send_next, length + fin_now as u32, new_data, now, out).map(Some)
    }

    /// The SACK recovery of RFC 6675 (C): while cwnd - pipe >= 1 SMSS, the
    /// segment NextSeg () names: (1) a lost one above HighRxt, (2) new data,
    /// (3) an unSACKed one above HighRxt, (4) once per recovery, the rescue
    /// retransmission of the highest unSACKed data.
    pub fn write_sack_recovery(
        &mut self,
        size: u32,
        now: Instant,
        out: &mut impl Writer,
    ) -> Result<Option<TCPTransmission>, TCPError> {
        let Some(recovery) = self.recovery else { return Ok(None) };
        let (una, max, mss) = (self.send_unacknowledged, self.send_maximum, self.mss());
        let pipe = self.scoreboard.pipe(una, max, recovery.retransmitted, mss);
        if self.congestion.window().saturating_sub(pipe) < mss {
            return Ok(None);
        }
        let from = recovery.retransmitted.max(una);
        if let Some((start, length)) = self.scoreboard.next_lost(from, una, max, mss) {
            return self.write_recovery_range(start, length.min(size), true, now, out).map(Some);
        }
        // (2) New data, as the receiver's window allows.
        let room = self.send_window.saturating_sub(self.send_next.distance(una));
        let data = self.unsent();
        if data > 0 && room > 0 && self.send_next == max && self.ecn_hold.is_none() {
            let length = data.min(room).min(size);
            let fin = self.closing && !self.fin_sent && length == data && room > data;
            return self.write_range(self.send_next, length + fin as u32, true, now, out).map(Some);
        }
        if let Some((start, length)) = self.scoreboard.next_unsacked(from, una, max) {
            return self.write_recovery_range(start, length.min(size), true, now, out).map(Some);
        }
        // (4) The rescue retransmission, which does not move HighRxt.
        if recovery.rescue.is_none_or(|rescue| una.is_after(rescue))
            && let Some((start, end)) = self.scoreboard.highest_unsacked(una, max)
        {
            let length = end.distance(start).min(size);
            if let Some(recovery) = self.recovery.as_mut() {
                recovery.rescue = Some(recovery.point);
            }
            return self.write_recovery_range(end.sub(length), length, false, now, out).map(Some);
        }
        Ok(None)
    }

    /// Retransmits `length` from `start` in a SACK recovery, moving HighRxt
    /// past it if `high` (RFC 6675 (C.2)).
    pub fn write_recovery_range(
        &mut self,
        start: TCPSequence,
        length: u32,
        high: bool,
        now: Instant,
        out: &mut impl Writer,
    ) -> Result<TCPTransmission, TCPError> {
        if high && let Some(recovery) = self.recovery.as_mut() {
            recovery.retransmitted = start.add(length);
        }
        self.write_range(start, length, false, now, out)
    }

    /// cwnd, and the segments of new data Limited Transmit lets past it.
    pub fn congestion_window(&self, size: u32) -> u32 {
        let extra = if self.recovery.is_none() && self.send_next == self.send_maximum {
            self.limited_transmit * size
        } else {
            0
        };
        self.congestion.window().saturating_add(extra)
    }

    pub fn schedule_persist(&mut self, now: Instant) {
        let factor = 1u32.checked_shl(self.persist_backoff.min(16)).unwrap_or(u32::MAX);
        let delay = self.timer.current().saturating_mul(factor).min(self.config.maximum_rto);
        self.persist_at = Some(now.saturating_add(delay));
    }

    /// The bytes of options a data segment carries: Timestamps, and the SACK blocks to report.
    pub fn data_options_length(&self) -> usize {
        let timestamps = if self.timestamps { 12 } else { 0 };
        let sack = if self.sack && !self.receive.pending.is_empty() {
            let blocks = self.receive.pending.len().min(if self.timestamps { 3 } else { 4 });
            4 + 8 * blocks
        } else {
            0
        };
        timestamps + sack
    }

    /// Writes the sequence space from `sequence`, `length` long: data, and
    /// the FIN if it is the last of it. Only `new_data`, neither a
    /// retransmission nor a window probe, carries ECT(0) and CWR (RFC 3168
    /// §6.1.5, §6.1.6) and is timed for an RTT sample (MUST-18).
    pub fn write_range(
        &mut self,
        sequence: TCPSequence,
        length: u32,
        new_data: bool,
        now: Instant,
        out: &mut impl Writer,
    ) -> Result<TCPTransmission, TCPError> {
        let data_end = self.send.end();
        let available = data_end.distance(sequence).min(i32::MAX as u32);
        let data_length = length.min(if sequence.is_before(data_end) { available } else { 0 });
        let fin = self.closing && sequence.add(data_length) == data_end && length > data_length;
        let mut flags = TCPFlags::ACK;
        if data_length > 0 && sequence.add(data_length) == data_end {
            // The last of the data buffered is pushed (MUST-61).
            flags = flags.union(TCPFlags::PSH);
        }
        if fin {
            flags = flags.union(TCPFlags::FIN);
        }
        let mut urgent_pointer = 0;
        if let Some(urgent) = self.send_urgent
            && urgent.is_after(sequence)
        {
            flags = flags.union(TCPFlags::URG);
            urgent_pointer = urgent.distance(sequence).min(u16::MAX as u32) as u16;
        }
        let fresh = new_data && data_length > 0;
        if fresh && self.ecn_cwr_due {
            flags = flags.union(TCPFlags::CWR);
            self.ecn_cwr_due = false;
        }
        let payload = self.send.slice(sequence, data_length as usize).to_vec();
        let ect = self.ecn && fresh;
        let transmission = self.write(sequence, flags, &payload, urgent_pointer, ect, now, out)?;
        let end = sequence.add(data_length + fin as u32);
        if data_length + fin as u32 > 0 {
            self.last_data_sent = now;
        }
        if data_length > 0 {
            self.smallest_segment = self.smallest_segment.min(data_length);
        }
        if fin {
            self.fin_sent = true;
            match self.state {
                TCPState::Established => self.state = TCPState::FinWait1,
                TCPState::CloseWait => self.state = TCPState::LastAck,
                _ => {}
            }
        }
        if end.is_after(self.send_next) {
            self.send_next = end;
        }
        if end.is_after(self.send_maximum) {
            // Of the data in flight, what lies past cwnd was sent by Limited Transmit.
            let flight = end.distance(self.send_unacknowledged);
            if self.recovery.is_none() && self.duplicate_acks > 0 {
                self.limited_bytes = self.limited_bytes.max(flight.saturating_sub(self.congestion.window()));
            }
            if self.rtt_sample.is_none() && new_data && !self.timestamps {
                self.rtt_sample = Some((end, now));
            }
            self.send_maximum = end;
        }
        if !new_data && data_length > 0 {
            // Karn's algorithm: no sample while something is sent twice.
            self.rtt_sample = None;
        }
        if self.retransmit_at.is_none() && data_length + fin as u32 > 0 {
            self.retransmit_at = Some(now.saturating_add(self.timer.current()));
        }
        Ok(transmission)
    }

    /// Writes a segment from `sequence` with `flags`, `payload` and the
    /// connection's acknowledgment, window and options.
    #[allow(clippy::too_many_arguments)]
    pub fn write(
        &mut self,
        sequence: TCPSequence,
        flags: TCPFlags,
        payload: &[u8],
        urgent_pointer: u16,
        ect: bool,
        now: Instant,
        out: &mut impl Writer,
    ) -> Result<TCPTransmission, TCPError> {
        let reset = flags.contains(TCPFlags::RST);
        let mut options = TCPOptionSet::default();
        if self.timestamps && !reset {
            options.timestamps = Some(TCPTimestamps { value: self.timestamp(now), echo_reply: self.timestamp_recent });
        }
        if self.sack && !reset {
            let (blocks, count) = self.receive.sack_blocks(if self.timestamps { 3 } else { 4 });
            options = options.with_sack(&blocks[..count]);
        }
        let mut bytes = Buffer::new();
        options.encode(&mut bytes)?;
        let mut flags = flags;
        if self.ecn && self.ecn_echo && flags.contains(TCPFlags::ACK) && !reset {
            flags = flags.union(TCPFlags::ECE);
        }
        // The window: the room in the buffer, never moving the right edge left (SHLD-14), and
        // moving it right only by a useful amount (the receiver's SWS avoidance, MUST-39).
        let next = self.receive_next();
        let edge = self.receive.next.add(self.receive.space() as u32);
        let threshold = (self.config.receive_buffer / 2)
            .min(TCPConnection::<C>::advertised_mss(&self.config, self.local) as usize) as u32;
        if edge.is_after(self.receive_advertised)
            && (edge.distance(self.receive_advertised) >= threshold || self.receive_advertised.is_before(next))
        {
            self.receive_advertised = edge;
        }
        if self.receive_advertised.is_before(next) {
            self.receive_advertised = next;
        }
        let window = (self.receive_advertised.distance(next) >> self.receive_scale).min(u16::MAX as u32) as u16;
        let acknowledge = flags.contains(TCPFlags::ACK);
        let segment = TCPSegment {
            source_port: self.local.port,
            destination_port: self.remote.port,
            sequence,
            acknowledgment: if acknowledge { next } else { TCPSequence(0) },
            flags,
            window: if reset { 0 } else { window },
            urgent_pointer,
            options: bytes.as_slice(),
            payload,
        };
        segment.encode(self.local.address, self.remote.address, out)?;
        if acknowledge && !reset {
            self.last_ack_sent = next;
            self.ack_now = false;
            self.ack_at = None;
            self.unacknowledged = 0;
        }
        Ok(TCPTransmission { length: segment.length(), ect })
    }
}

impl<C: TCPCongestionControl> IPEndpoints for TCPConnection<C> {
    fn local(&self) -> IPEndpoint {
        self.local
    }

    fn remote(&self) -> IPEndpoint {
        self.remote
    }
}
