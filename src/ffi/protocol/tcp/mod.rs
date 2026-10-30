//! The C ABI of [`crate::protocol::tcp`].
//!
//! A segment is an [`FFITCPSegment`] of its fields, with its options and data
//! passed beside it; decoding gives their offsets in the bytes. The addresses
//! that carry a segment are their octets (4 or 16) and their number. A
//! connection, a listener, a congestion control and an ISN generator are
//! handles; the configuration, the retransmission timer, options, headers and
//! rules are structures. Instants and durations are nanoseconds. A state, an
//! event, a close reason, a congestion control and an ECN mode cross as the
//! numbers of their Rust enums.

use alloc::vec::Vec;
use core::time::Duration;

use crate::bytes::Buffer as Bytes;
use crate::ffi::protocol::ip::{FFIIPEndpoint, FFIIPEndpointPattern, IPStatus};
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::ip::IPAddress;
use crate::protocol::tcp::{
    TCPCloseReason, TCPConfig, TCPCongestion, TCPCongestionControl, TCPCongestionKind, TCPConnection, TCPECNMode,
    TCPError, TCPEvent, TCPFlags, TCPHeader, TCPICMPError, TCPISNGenerator, TCPListener, TCPOptionKind, TCPOptionSet,
    TCPOptions, TCPRetransmissionTimer, TCPRule, TCPSACKBlock, TCPSegment, TCPSequence, TCPTimestamps,
};
use crate::runtime::Instant;
use crate::service::Rule;

/// The statuses of this module, one per variant of [`TCPError`] that is not
/// another module's.
pub struct TCPStatus;

impl TCPStatus {
    pub const LENGTH: Status = Status::new(c"protocol.tcp", c"Length", c"the TCP segment's length is wrong");
    pub const CHECKSUM: Status = Status::new(c"protocol.tcp", c"Checksum", c"the TCP checksum is wrong");
    pub const OPTION: Status =
        Status::new(c"protocol.tcp", c"Option", c"a TCP option is malformed or the options do not fit");
    pub const FAMILY: Status = Status::new(c"protocol.tcp", c"Family", c"the addresses are of different IP versions");
    pub const ADDRESS: Status = Status::new(c"protocol.tcp", c"Address", c"the address names no single host");
    pub const STATE: Status = Status::new(c"protocol.tcp", c"State", c"the connection's state does not allow it");
    pub const CONFIG: Status = Status::new(c"protocol.tcp", c"Config", c"the TCP configuration cannot work");

    /// The addresses of the `source_length` octets at `source` and the
    /// `destination_length` octets at `destination`.
    ///
    /// # Safety
    /// As [`Pointer::slice`].
    pub unsafe fn addresses(
        source: *const u8,
        source_length: usize,
        destination: *const u8,
        destination_length: usize,
    ) -> Result<(IPAddress, IPAddress), &'static Status> {
        // SAFETY: the caller's promise.
        let source = unsafe { IPStatus::address(source, source_length) }?;
        let destination = unsafe { IPStatus::address(destination, destination_length) }?;
        Ok((source, destination))
    }

    /// Writes what `write` writes into a new buffer at `out`.
    ///
    /// # Safety
    /// As [`Pointer::write`].
    pub unsafe fn write_bytes(
        out: *mut Buffer,
        write: impl FnOnce(&mut Bytes) -> Result<(), TCPError>,
    ) -> Result<(), &'static Status> {
        Pointer::check_range(out, 1)?;
        let mut bytes = Bytes::new();
        write(&mut bytes).map_err(|error| error.to_status())?;
        // SAFETY: the caller's promise.
        unsafe { Pointer::write(out, Buffer::from_vec(bytes.into_vec())) }
    }
}

impl ToStatus for TCPError {
    fn to_status(&self) -> &'static Status {
        match self {
            TCPError::Length => &TCPStatus::LENGTH,
            TCPError::Checksum => &TCPStatus::CHECKSUM,
            TCPError::Option => &TCPStatus::OPTION,
            TCPError::Family => &TCPStatus::FAMILY,
            TCPError::Address => &TCPStatus::ADDRESS,
            TCPError::State => &TCPStatus::STATE,
            TCPError::Config => &TCPStatus::CONFIG,
            TCPError::Write(error) => error.to_status(),
        }
    }
}

/// The fields of a [`TCPSegment`] but its options and data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFITCPSegment {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: TCPSequence,
    pub acknowledgment: TCPSequence,
    pub flags: TCPFlags,
    pub window: u16,
    pub urgent_pointer: u16,
}

impl FFITCPSegment {
    pub fn with<'a>(&self, options: &'a [u8], payload: &'a [u8]) -> TCPSegment<'a> {
        TCPSegment {
            source_port: self.source_port,
            destination_port: self.destination_port,
            sequence: self.sequence,
            acknowledgment: self.acknowledgment,
            flags: self.flags,
            window: self.window,
            urgent_pointer: self.urgent_pointer,
            options,
            payload,
        }
    }

    pub fn of(segment: &TCPSegment) -> FFITCPSegment {
        FFITCPSegment {
            source_port: segment.source_port,
            destination_port: segment.destination_port,
            sequence: segment.sequence,
            acknowledgment: segment.acknowledgment,
            flags: segment.flags,
            window: segment.window,
            urgent_pointer: segment.urgent_pointer,
        }
    }

    /// The segment of `segment` with the `options_length` bytes at `options`
    /// and the `payload_length` bytes at `payload`.
    ///
    /// # Safety
    /// As [`Pointer::slice`] and [`Pointer::reference`].
    pub unsafe fn read<'a>(
        segment: *const FFITCPSegment,
        options: *const u8,
        options_length: usize,
        payload: *const u8,
        payload_length: usize,
    ) -> Result<TCPSegment<'a>, &'static Status> {
        // SAFETY: the caller's promise.
        let segment = unsafe { Pointer::reference(segment) }?;
        let options = unsafe { Pointer::slice(options, options_length) }?;
        let payload = unsafe { Pointer::slice(payload, payload_length) }?;
        Ok(segment.with(options, payload))
    }
}

/// A [`TCPOptionSet`]: each optional option with whether it is present.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFITCPOptionSet {
    pub has_mss: bool,
    pub mss: u16,
    pub has_window_scale: bool,
    pub window_scale: u8,
    pub sack_permitted: bool,
    pub has_timestamps: bool,
    pub timestamps: TCPTimestamps,
    pub sack_blocks: [TCPSACKBlock; 4],
    pub sack_count: u8,
}

impl From<FFITCPOptionSet> for TCPOptionSet {
    fn from(set: FFITCPOptionSet) -> TCPOptionSet {
        TCPOptionSet {
            mss: set.has_mss.then_some(set.mss),
            window_scale: set.has_window_scale.then_some(set.window_scale),
            sack_permitted: set.sack_permitted,
            timestamps: set.has_timestamps.then_some(set.timestamps),
            sack_blocks: set.sack_blocks,
            sack_count: set.sack_count.min(TCPOptionSet::MAXIMUM_SACK_BLOCKS as u8),
        }
    }
}

impl From<TCPOptionSet> for FFITCPOptionSet {
    fn from(set: TCPOptionSet) -> FFITCPOptionSet {
        FFITCPOptionSet {
            has_mss: set.mss.is_some(),
            mss: set.mss.unwrap_or(0),
            has_window_scale: set.window_scale.is_some(),
            window_scale: set.window_scale.unwrap_or(0),
            sack_permitted: set.sack_permitted,
            has_timestamps: set.timestamps.is_some(),
            timestamps: set.timestamps.unwrap_or_default(),
            sack_blocks: set.sack_blocks,
            sack_count: set.sack_count,
        }
    }
}

/// A [`TCPRetransmissionTimer`], durations in nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFITCPRetransmissionTimer {
    pub has_smoothed: bool,
    pub smoothed: u64,
    pub variation: u64,
    pub timeout: u64,
    pub backoff: u32,
    pub minimum: u64,
    pub maximum: u64,
    pub granularity: u64,
}

impl FFITCPRetransmissionTimer {
    pub fn nanoseconds(duration: Duration) -> u64 {
        u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
    }
}

impl From<FFITCPRetransmissionTimer> for TCPRetransmissionTimer {
    fn from(timer: FFITCPRetransmissionTimer) -> TCPRetransmissionTimer {
        TCPRetransmissionTimer {
            smoothed: timer.has_smoothed.then(|| Duration::from_nanos(timer.smoothed)),
            variation: Duration::from_nanos(timer.variation),
            timeout: Duration::from_nanos(timer.timeout),
            backoff: timer.backoff,
            minimum: Duration::from_nanos(timer.minimum),
            maximum: Duration::from_nanos(timer.maximum),
            granularity: Duration::from_nanos(timer.granularity),
        }
    }
}

impl From<TCPRetransmissionTimer> for FFITCPRetransmissionTimer {
    fn from(timer: TCPRetransmissionTimer) -> FFITCPRetransmissionTimer {
        let nanoseconds = FFITCPRetransmissionTimer::nanoseconds;
        FFITCPRetransmissionTimer {
            has_smoothed: timer.smoothed.is_some(),
            smoothed: timer.smoothed.map_or(0, nanoseconds),
            variation: nanoseconds(timer.variation),
            timeout: nanoseconds(timer.timeout),
            backoff: timer.backoff,
            minimum: nanoseconds(timer.minimum),
            maximum: nanoseconds(timer.maximum),
            granularity: nanoseconds(timer.granularity),
        }
    }
}

/// A [`TCPConfig`], durations in nanoseconds; the ECN mode and the
/// congestion control as their numbers; no initial window if `has_initial_window` is false.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFITCPConfig {
    pub mtu: u16,
    pub send_buffer: usize,
    pub receive_buffer: usize,
    pub window_scale: bool,
    pub timestamps: bool,
    pub sack: bool,
    pub ecn: u8,
    pub nagle: bool,
    pub delayed_ack: u64,
    pub initial_rto: u64,
    pub minimum_rto: u64,
    pub maximum_rto: u64,
    pub clock_granularity: u64,
    pub congestion: u8,
    pub has_initial_window: bool,
    pub initial_window: u32,
    pub retries: u32,
    pub user_timeout: u64,
    pub connect_timeout: u64,
    pub keepalive: bool,
    pub keepalive_idle: u64,
    pub keepalive_interval: u64,
    pub keepalive_probes: u32,
    pub time_wait: u64,
    pub challenge_acks: u32,
    pub hard_error_abort: bool,
}

impl FFITCPConfig {
    /// The configuration; fails with InvalidArgument for an unknown ECN mode or congestion control.
    pub fn config(&self) -> Result<TCPConfig, &'static Status> {
        let ecn = match self.ecn {
            0 => TCPECNMode::Off,
            1 => TCPECNMode::Accept,
            2 => TCPECNMode::Request,
            _ => return Err(&Status::INVALID_ARGUMENT),
        };
        let congestion = FFITCPConfig::congestion(self.congestion)?;
        Ok(TCPConfig {
            mtu: self.mtu,
            send_buffer: self.send_buffer,
            receive_buffer: self.receive_buffer,
            window_scale: self.window_scale,
            timestamps: self.timestamps,
            sack: self.sack,
            ecn,
            nagle: self.nagle,
            delayed_ack: Duration::from_nanos(self.delayed_ack),
            initial_rto: Duration::from_nanos(self.initial_rto),
            minimum_rto: Duration::from_nanos(self.minimum_rto),
            maximum_rto: Duration::from_nanos(self.maximum_rto),
            clock_granularity: Duration::from_nanos(self.clock_granularity),
            congestion,
            initial_window: self.has_initial_window.then_some(self.initial_window),
            retries: self.retries,
            user_timeout: Duration::from_nanos(self.user_timeout),
            connect_timeout: Duration::from_nanos(self.connect_timeout),
            keepalive: self.keepalive,
            keepalive_idle: Duration::from_nanos(self.keepalive_idle),
            keepalive_interval: Duration::from_nanos(self.keepalive_interval),
            keepalive_probes: self.keepalive_probes,
            time_wait: Duration::from_nanos(self.time_wait),
            challenge_acks: self.challenge_acks,
            hard_error_abort: self.hard_error_abort,
        })
    }

    /// The congestion control of `kind`; fails with InvalidArgument for an unknown one.
    pub fn congestion(kind: u8) -> Result<TCPCongestionKind, &'static Status> {
        match kind {
            0 => Ok(TCPCongestionKind::NewReno),
            1 => Ok(TCPCongestionKind::CUBIC),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

impl From<TCPConfig> for FFITCPConfig {
    fn from(config: TCPConfig) -> FFITCPConfig {
        let nanoseconds = FFITCPRetransmissionTimer::nanoseconds;
        FFITCPConfig {
            mtu: config.mtu,
            send_buffer: config.send_buffer,
            receive_buffer: config.receive_buffer,
            window_scale: config.window_scale,
            timestamps: config.timestamps,
            sack: config.sack,
            ecn: config.ecn as u8,
            nagle: config.nagle,
            delayed_ack: nanoseconds(config.delayed_ack),
            initial_rto: nanoseconds(config.initial_rto),
            minimum_rto: nanoseconds(config.minimum_rto),
            maximum_rto: nanoseconds(config.maximum_rto),
            clock_granularity: nanoseconds(config.clock_granularity),
            congestion: config.congestion as u8,
            has_initial_window: config.initial_window.is_some(),
            initial_window: config.initial_window.unwrap_or(0),
            retries: config.retries,
            user_timeout: nanoseconds(config.user_timeout),
            connect_timeout: nanoseconds(config.connect_timeout),
            keepalive: config.keepalive,
            keepalive_idle: nanoseconds(config.keepalive_idle),
            keepalive_interval: nanoseconds(config.keepalive_interval),
            keepalive_probes: config.keepalive_probes,
            time_wait: nanoseconds(config.time_wait),
            challenge_acks: config.challenge_acks,
            hard_error_abort: config.hard_error_abort,
        }
    }
}

/// What a connection's state machine holds that an application may read,
/// for the bindings that cannot reach the fields of the Rust structure.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFITCPConnectionInfo {
    pub state: u8,
    pub passive: bool,
    pub iss: TCPSequence,
    pub send_unacknowledged: TCPSequence,
    pub send_next: TCPSequence,
    pub send_maximum: TCPSequence,
    pub send_window: u32,
    pub maximum_send_window: u32,
    pub irs: TCPSequence,
    pub receive_next: TCPSequence,
    pub peer_mss: u16,
    /// The MTU the segments are sized for ([`TCPConnection::mtu`]).
    pub mtu: u16,
    pub window_scaling: bool,
    pub send_scale: u8,
    pub receive_scale: u8,
    pub sack: bool,
    pub timestamps: bool,
    pub ecn: bool,
    pub congestion_window: u32,
    pub congestion_threshold: u32,
    pub in_recovery: bool,
    pub timer: FFITCPRetransmissionTimer,
}

/// The endpoints a [`TCPRule`] is matched against from C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FFITCPEndpoints {
    pub local: crate::protocol::ip::IPEndpoint,
    pub remote: crate::protocol::ip::IPEndpoint,
}

impl crate::protocol::ip::IPEndpoints for FFITCPEndpoints {
    fn local(&self) -> crate::protocol::ip::IPEndpoint {
        self.local
    }

    fn remote(&self) -> crate::protocol::ip::IPEndpoint {
        self.remote
    }
}

/// A [`TCPRule`]: the patterns of the local and the remote endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFITCPRule {
    pub local: FFIIPEndpointPattern,
    pub remote: FFIIPEndpointPattern,
}

impl Value for TCPSequence {
    const TYPE: Type = Type::U32;
}

impl Value for TCPFlags {
    const TYPE: Type = Type::U8;
}

impl Value for TCPHeader {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPHeader");
}

impl Value for FFITCPSegment {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPSegment");
}

impl Value for TCPSACKBlock {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPSACKBlock");
}

impl Value for TCPTimestamps {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPTimestamps");
}

impl Value for FFITCPOptionSet {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPOptionSet");
}

impl Value for FFITCPRetransmissionTimer {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPRetransmissionTimer");
}

impl Value for FFITCPConfig {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPConfig");
}

impl Value for FFITCPConnectionInfo {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPConnectionInfo");
}

impl Value for FFITCPRule {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPRule");
}

impl Value for TCPISNGenerator {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPISNGenerator");
}

impl Value for TCPCongestion {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPCongestion");
}

impl Value for TCPConnection {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPConnection");
}

impl Value for TCPListener {
    const TYPE: Type = Type::Named("umilib_protocol_tcp_TCPListener");
}

impl FFITCPConnectionInfo {
    pub fn of(connection: &TCPConnection) -> FFITCPConnectionInfo {
        FFITCPConnectionInfo {
            state: connection.state as u8,
            passive: connection.passive,
            iss: connection.iss,
            send_unacknowledged: connection.send_unacknowledged,
            send_next: connection.send_next,
            send_maximum: connection.send_maximum,
            send_window: connection.send_window,
            maximum_send_window: connection.maximum_send_window,
            irs: connection.irs,
            receive_next: connection.receive_next(),
            peer_mss: connection.peer_mss,
            mtu: connection.mtu(),
            window_scaling: connection.window_scaling,
            send_scale: connection.send_scale,
            receive_scale: connection.receive_scale,
            sack: connection.sack,
            timestamps: connection.timestamps,
            ecn: connection.ecn,
            congestion_window: connection.congestion.window(),
            congestion_threshold: connection.congestion.threshold(),
            in_recovery: connection.recovery.is_some(),
            timer: connection.timer.into(),
        }
    }
}

/// The numbers of [`TCPEvent`]: the kind, and the close reason of `Closed`.
pub struct FFITCPEvent;

impl FFITCPEvent {
    pub fn of(event: TCPEvent) -> (u8, u8) {
        match event {
            TCPEvent::Connected => (0, 0),
            TCPEvent::Readable => (1, 0),
            TCPEvent::Writable => (2, 0),
            TCPEvent::Urgent => (3, 0),
            TCPEvent::PeerClosed => (4, 0),
            TCPEvent::Trouble => (5, 0),
            TCPEvent::Closed(reason) => (6, reason as u8),
        }
    }

    /// The reason of `number`.
    pub fn reason(number: u8) -> Option<TCPCloseReason> {
        [
            TCPCloseReason::Normal,
            TCPCloseReason::Reset,
            TCPCloseReason::Refused,
            TCPCloseReason::Timeout,
            TCPCloseReason::Aborted,
            TCPCloseReason::Unreachable,
        ]
        .into_iter()
        .find(|reason| *reason as u8 == number)
    }
}

crate::ffi_functions! {
    /// Whether `a` is before `b` modulo 2^32 (RFC 9293 §3.4).
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_sequence_is_before(a: TCPSequence, b: TCPSequence) -> bool {
        a.is_before(b)
    }

    /// How far `later` is after `earlier`, modulo 2^32.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_sequence_distance(later: TCPSequence, earlier: TCPSequence) -> u32 {
        later.distance(earlier)
    }

    /// Reads the header at the start of the `length` bytes at `bytes` into `out`; fails with Length.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_header_decode(bytes: *const u8, length: usize, out: *mut TCPHeader) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(bytes, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let header = TCPHeader::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, header) }
        })())
    }

    /// Writes the 20 bytes of `header` into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_header_encode(header: TCPHeader, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable buffer.
        Status::from_result(unsafe { Pointer::write(out, Buffer::from_vec(header.to_bytes().to_vec())) })
    }

    /// Reads the segment of the `length` bytes at `bytes`, carried from the address at `source` to that
    /// at `destination`, into `out`, with the offsets and lengths of its options and its data in the
    /// bytes. Fails with Length, Checksum, Option or Family, and with the ip module's Length for an
    /// address of other than 4 or 16 octets.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_segment_decode(bytes: *const u8, length: usize, source: *const u8, source_length: usize, destination: *const u8, destination_length: usize, out: *mut FFITCPSegment, out_options_offset: *mut usize, out_options_length: *mut usize, out_payload_offset: *mut usize, out_payload_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[
                    Pointer::range(bytes, length),
                    Pointer::range(source, source_length),
                    Pointer::range(destination, destination_length),
                ],
                &[
                    Pointer::range(out, 1),
                    Pointer::range(out_options_offset, 1),
                    Pointer::range(out_options_length, 1),
                    Pointer::range(out_payload_offset, 1),
                    Pointer::range(out_payload_length, 1),
                ],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let (source, destination) = unsafe { TCPStatus::addresses(source, source_length, destination, destination_length) }?;
            for pointer in [out_options_offset, out_options_length, out_payload_offset, out_payload_length] {
                Pointer::check_range(pointer, 1)?;
            }
            Pointer::check_range(out, 1)?;
            let segment = TCPSegment::decode(bytes, source, destination).map_err(|error| error.to_status())?;
            let offset = |part: &[u8]| part.as_ptr() as usize - bytes.as_ptr() as usize;
            let values = (FFITCPSegment::of(&segment), offset(segment.options), segment.options.len(), offset(segment.payload), segment.payload.len());
            unsafe { Pointer::write(out, values.0) }?;
            unsafe { Pointer::write(out_options_offset, values.1) }?;
            unsafe { Pointer::write(out_options_length, values.2) }?;
            unsafe { Pointer::write(out_payload_offset, values.3) }?;
            unsafe { Pointer::write(out_payload_length, values.4) }
        })())
    }

    /// Writes the segment of `segment`, the `options_length` bytes of options at `options` and the
    /// `payload_length` bytes of data at `payload`, from the address at `source` to that at
    /// `destination`, with its data offset and checksum, into `out`; fails with Option, Length or Family.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_segment_encode(segment: *const FFITCPSegment, options: *const u8, options_length: usize, payload: *const u8, payload_length: usize, source: *const u8, source_length: usize, destination: *const u8, destination_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure, readable bytes and a writable buffer.
            let segment = unsafe { FFITCPSegment::read(segment, options, options_length, payload, payload_length) }?;
            let (source, destination) = unsafe { TCPStatus::addresses(source, source_length, destination, destination_length) }?;
            unsafe { TCPStatus::write_bytes(out, |bytes| segment.encode(source, destination, bytes)) }
        })())
    }

    /// Writes whether a reset answers the segment `segment` (with its options and data) when no
    /// connection exists (RFC 9293 §3.10.7.1) into `out_found` and the reset into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_segment_reset_reply(segment: *const FFITCPSegment, options: *const u8, options_length: usize, payload: *const u8, payload_length: usize, out_found: *mut bool, out: *mut FFITCPSegment) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[
                    Pointer::range(segment, 1),
                    Pointer::range(options, options_length),
                    Pointer::range(payload, payload_length),
                ],
                &[Pointer::range(out_found, 1), Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes a valid structure, readable bytes and writable pointers.
            let segment = unsafe { FFITCPSegment::read(segment, options, options_length, payload, payload_length) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let reply = segment.reset_reply();
            unsafe { Pointer::write(out_found, reply.is_some()) }?;
            unsafe { Pointer::write(out, reply.map_or_else(FFITCPSegment::default, |reply| FFITCPSegment::of(&reply))) }
        })())
    }

    /// Writes the options of the `length` bytes at `options` that this crate understands into `out`;
    /// fails with Option for an illegal length.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_option_set_decode(options: *const u8, length: usize, out: *mut FFITCPOptionSet) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(options, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let options = unsafe { Pointer::slice(options, length) }?;
            let set = TCPOptionSet::decode(options).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, set.into()) }
        })())
    }

    /// Writes the options of `set` as Linux lays them out into `out`; fails with Option if they do not fit.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_option_set_encode(set: *const FFITCPOptionSet, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure and a writable buffer.
            let set: TCPOptionSet = (*unsafe { Pointer::reference(set) }?).into();
            unsafe { TCPStatus::write_bytes(out, |bytes| set.encode(bytes)) }
        })())
    }

    /// Writes whether the options of the `length` bytes at `options` have one at `index` (No-Operation
    /// included) into `out_found`, its kind into `out_kind` and its data into `out`; fails with Option.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_options_get(options: *const u8, length: usize, index: usize, out_found: *mut bool, out_kind: *mut u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(options, length)],
                &[Pointer::range(out_found, 1), Pointer::range(out_kind, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let options = unsafe { Pointer::slice(options, length) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out, 1)?;
            let option = TCPOptions::new(options).nth(index).transpose().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_found, option.is_some()) }?;
            unsafe { Pointer::write(out_kind, option.map_or(0, |option| option.kind.0)) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(option.map_or_else(Vec::new, |option| option.data.to_vec()))) }
        })())
    }

    /// Writes the option of `kind` and the `length` bytes of data at `data` into `out`; fails with Option.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_option_encode(kind: u8, data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            unsafe { TCPStatus::write_bytes(out, |bytes| crate::protocol::tcp::TCPOption::encode(TCPOptionKind(kind), data, bytes)) }
        })())
    }

    /// Writes a generator of initial sequence numbers under the 16 bytes of key at `key` into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_isn_generator_new(key: *const u8, out: *mut *mut TCPISNGenerator) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes 16 readable bytes and a writable pointer.
            let key: [u8; 16] = unsafe { Pointer::slice(key, 16) }?.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, TCPISNGenerator::new(key)) }
        })())
    }

    /// Releases a generator. Does nothing if `generator` is null.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_isn_generator_free(generator: *mut TCPISNGenerator) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(generator) }
    }

    /// Writes the initial sequence number of a connection between `local` and `remote` opened at `now` into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_isn_generator_generate(generator: *const TCPISNGenerator, local: *const FFIIPEndpoint, remote: *const FFIIPEndpoint, now: u64, out: *mut TCPSequence) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and structures and a writable pointer.
            let generator = unsafe { Pointer::reference(generator) }?;
            let local = unsafe { Pointer::reference(local) }?.endpoint()?;
            let remote = unsafe { Pointer::reference(remote) }?.endpoint()?;
            unsafe { Pointer::write(out, generator.generate(local, remote, Instant::from_nanos(now))) }
        })())
    }

    /// Writes a retransmission timer of RTO `initial`, bounded by `minimum` and `maximum`, with the
    /// clock granularity `granularity`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_retransmission_timer_new(initial: u64, minimum: u64, maximum: u64, granularity: u64, out: *mut FFITCPRetransmissionTimer) -> *const Status {
        let timer = TCPRetransmissionTimer::new(Duration::from_nanos(initial), Duration::from_nanos(minimum), Duration::from_nanos(maximum), Duration::from_nanos(granularity));
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, timer.into()) })
    }

    /// Takes the RTT sample `rtt` into the timer at `timer` (RFC 6298 (2.2), (2.3)).
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_retransmission_timer_sample(timer: *mut FFITCPRetransmissionTimer, rtt: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure.
            let slot = unsafe { Pointer::reference_mut(timer) }?;
            let mut value: TCPRetransmissionTimer = (*slot).into();
            value.sample(Duration::from_nanos(rtt));
            *slot = value.into();
            Ok(())
        })())
    }

    /// Records an expiry of the timer at `timer`: the RTO doubles (RFC 6298 (5.5)).
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_retransmission_timer_expire(timer: *mut FFITCPRetransmissionTimer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure.
            let slot = unsafe { Pointer::reference_mut(timer) }?;
            let mut value: TCPRetransmissionTimer = (*slot).into();
            value.expire();
            *slot = value.into();
            Ok(())
        })())
    }

    /// Restores the timer at `timer` after a lost SYN (RFC 6298 (5.7)).
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_retransmission_timer_restore_after_syn_loss(timer: *mut FFITCPRetransmissionTimer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure.
            let slot = unsafe { Pointer::reference_mut(timer) }?;
            let mut value: TCPRetransmissionTimer = (*slot).into();
            value.restore_after_syn_loss();
            *slot = value.into();
            Ok(())
        })())
    }

    /// The current RTO of `timer`, backoff included.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_retransmission_timer_current(timer: FFITCPRetransmissionTimer) -> u64 {
        FFITCPRetransmissionTimer::nanoseconds(TCPRetransmissionTimer::from(timer).current())
    }

    /// Writes the congestion control of `kind` (0 NewReno, 1 CUBIC) with the window `window` into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_congestion_new(kind: u8, window: u32, out: *mut *mut TCPCongestion) -> *const Status {
        Status::from_result((|| {
            let kind = FFITCPConfig::congestion(kind)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, TCPCongestion::new(kind, window)) }
        })())
    }

    /// Releases a congestion control. Does nothing if `congestion` is null.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_congestion_free(congestion: *mut TCPCongestion) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(congestion) }
    }

    /// The initial window of RFC 5681 §3.1 for `mss`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_congestion_initial_window(mss: u32) -> u32 {
        TCPCongestion::initial_window(mss)
    }

    /// Writes cwnd and ssthresh of the control at `congestion` into `out_window` and `out_threshold`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_congestion_window(congestion: *const TCPCongestion, out_window: *mut u32, out_threshold: *mut u32) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_window, 1), Pointer::range(out_threshold, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let congestion = unsafe { Pointer::reference(congestion) }?;
            Pointer::check_range(out_threshold, 1)?;
            unsafe { Pointer::write(out_window, congestion.window()) }?;
            unsafe { Pointer::write(out_threshold, congestion.threshold()) }
        })())
    }

    /// Sets cwnd of the control at `congestion` to `window`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_congestion_set_window(congestion: *mut TCPCongestion, window: u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(congestion) }?.set_window(window);
            Ok(())
        })())
    }

    /// Tells the control at `congestion` that `acknowledged` bytes were acknowledged at `now`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_congestion_acknowledge(congestion: *mut TCPCongestion, acknowledged: u32, mss: u32, rtt: u64, limited: bool, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(congestion) }?.acknowledge(acknowledged, mss, Duration::from_nanos(rtt), limited, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Tells the control at `congestion` of a congestion event at `now`, an ECN-Echo if `ecn`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_congestion_congestion(congestion: *mut TCPCongestion, in_flight: u32, mss: u32, ecn: bool, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(congestion) }?.congestion(in_flight, mss, ecn, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Tells the control at `congestion` that the retransmission timer expired at `now`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_congestion_timeout(congestion: *mut TCPCongestion, in_flight: u32, mss: u32, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(congestion) }?.timeout(in_flight, mss, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Restarts the control at `congestion` after idleness at `restart` bytes (RFC 5681 §4.1).
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_congestion_restart(congestion: *mut TCPCongestion, restart: u32, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(congestion) }?.restart(restart, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes the default configuration (RFC 9293 and the RFCs it relies on) into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_config_default(out: *mut FFITCPConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, TCPConfig::default().into()) })
    }

    /// Writes a connection actively opened from `local` to `remote` with `iss` at `now` into `out`;
    /// fails with Address (MUST-46), Family, or InvalidArgument for a bad configuration.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_connect(config: *const FFITCPConfig, local: *const FFIIPEndpoint, remote: *const FFIIPEndpoint, iss: TCPSequence, now: u64, out: *mut *mut TCPConnection) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid structures and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?.config()?;
            let local = unsafe { Pointer::reference(local) }?.endpoint()?;
            let remote = unsafe { Pointer::reference(remote) }?.endpoint()?;
            Pointer::check_range(out, 1)?;
            let connection = TCPConnection::connect(config, local, remote, iss, Instant::from_nanos(now)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, connection) }
        })())
    }

    /// Writes a connection passively opened from the SYN `syn` (with its options and data) that came
    /// from `remote` to `local`, with `iss` at `now`, into `out`; fails with State, Address or Family.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_accept(config: *const FFITCPConfig, local: *const FFIIPEndpoint, remote: *const FFIIPEndpoint, syn: *const FFITCPSegment, options: *const u8, options_length: usize, payload: *const u8, payload_length: usize, iss: TCPSequence, now: u64, out: *mut *mut TCPConnection) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid structures, readable bytes and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?.config()?;
            let local = unsafe { Pointer::reference(local) }?.endpoint()?;
            let remote = unsafe { Pointer::reference(remote) }?.endpoint()?;
            let syn = unsafe { FFITCPSegment::read(syn, options, options_length, payload, payload_length) }?;
            Pointer::check_range(out, 1)?;
            let connection = TCPConnection::accept(config, local, remote, &syn, iss, Instant::from_nanos(now)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, connection) }
        })())
    }

    /// Releases a connection. Does nothing if `connection` is null.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_free(connection: *mut TCPConnection) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(connection) }
    }

    /// Gives the connection a segment that arrived at `now`, with Congestion Experienced if `ce`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_receive(connection: *mut TCPConnection, segment: *const FFITCPSegment, options: *const u8, options_length: usize, payload: *const u8, payload_length: usize, ce: bool, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and structure and readable bytes.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let segment = unsafe { FFITCPSegment::read(segment, options, options_length, payload, payload_length) }?;
            connection.receive(&segment, ce, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the connection has a segment to send at `now` into `out_found`, the segment into
    /// `out`, and whether its IP header carries ECT(0) into `out_ect`. Call it until it finds none.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_transmit(connection: *mut TCPConnection, now: u64, out_found: *mut bool, out: *mut Buffer, out_ect: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out_ect, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_ect, 1)?;
            let mut bytes = Bytes::new();
            let transmission = connection.transmit(Instant::from_nanos(now), &mut bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_found, transmission.is_some()) }?;
            unsafe { Pointer::write(out_ect, transmission.is_some_and(|transmission| transmission.ect)) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes.into_vec())) }
        })())
    }

    /// Writes whether the connection has a timer into `out_found` and the earliest into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_poll_timeout(connection: *const TCPConnection, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference(connection) }?;
            Pointer::check_range(out, 1)?;
            let deadline = connection.poll_timeout();
            unsafe { Pointer::write(out_found, deadline.is_some()) }?;
            unsafe { Pointer::write(out, deadline.map_or(0, Instant::as_nanos)) }
        })())
    }

    /// Writes whether an event is waiting into `out_found`, its kind (0 Connected, 1 Readable, 2
    /// Writable, 3 Urgent, 4 PeerClosed, 5 Trouble, 6 Closed) into `out_kind` and the close reason of
    /// Closed into `out_reason`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_poll_event(connection: *mut TCPConnection, out_found: *mut bool, out_kind: *mut u8, out_reason: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[Pointer::range(out_found, 1), Pointer::range(out_kind, 1), Pointer::range(out_reason, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out_reason, 1)?;
            let event = connection.poll_event();
            let (kind, reason) = event.map_or((0, 0), FFITCPEvent::of);
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            unsafe { Pointer::write(out_kind, kind) }?;
            unsafe { Pointer::write(out_reason, reason) }
        })())
    }

    /// Takes as much of the `length` bytes at `data` as fits, urgent if `urgent`, and writes how
    /// many into `out`; fails with State once the application or the connection closed.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_send(connection: *mut TCPConnection, data: *const u8, length: usize, urgent: bool, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            let taken = if urgent { connection.send_urgent(data) } else { connection.send(data) }.map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, taken) }
        })())
    }

    /// Reads into the `length` bytes at `out` and writes how many into `out_count`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_read(connection: *mut TCPConnection, out: *mut u8, length: usize, out_count: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out, length), Pointer::range(out_count, 1)])?;
            // SAFETY: the caller passes a valid handle and writable bytes and pointer.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            Pointer::check_range(out_count, 1)?;
            let count = connection.read(out);
            unsafe { Pointer::write(out_count, count) }
        })())
    }

    /// Writes the bytes that can be read, the room to send and the urgent bytes not yet read into
    /// `out_readable`, `out_writable` and `out_urgent`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_sizes(connection: *const TCPConnection, out_readable: *mut usize, out_writable: *mut usize, out_urgent: *mut u32) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[Pointer::range(out_readable, 1), Pointer::range(out_writable, 1), Pointer::range(out_urgent, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference(connection) }?;
            Pointer::check_range(out_readable, 1)?;
            Pointer::check_range(out_writable, 1)?;
            Pointer::check_range(out_urgent, 1)?;
            unsafe { Pointer::write(out_readable, connection.readable()) }?;
            unsafe { Pointer::write(out_writable, connection.writable()) }?;
            unsafe { Pointer::write(out_urgent, connection.urgent_remaining()) }
        })())
    }

    /// Closes the sending half: a FIN follows the data; fails with State.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_close(connection: *mut TCPConnection) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(connection) }?.close().map_err(|error| error.to_status())
        })())
    }

    /// Aborts the connection: a reset is sent if it was synchronized; fails with State once it closed.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_abort(connection: *mut TCPConnection) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(connection) }?.abort().map_err(|error| error.to_status())
        })())
    }

    /// Gives the connection an ICMP error about the segment of `sequence`: `kind` 0 soft, 1 hard, 2
    /// Packet Too Big with the MTU `mtu`; fails with InvalidArgument for another kind.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_receive_error(connection: *mut TCPConnection, kind: u8, mtu: u16, sequence: TCPSequence, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let error = match kind {
                0 => TCPICMPError::Soft,
                1 => TCPICMPError::Hard,
                2 => TCPICMPError::PacketTooBig(mtu),
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            connection.receive_error(error, sequence, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the SYN `syn` (with its options and data) may open a new incarnation of the
    /// connection in TIME-WAIT (RFC 6191 §2) into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_accepts_syn(connection: *const TCPConnection, syn: *const FFITCPSegment, options: *const u8, options_length: usize, payload: *const u8, payload_length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[
                    Pointer::range(syn, 1),
                    Pointer::range(options, options_length),
                    Pointer::range(payload, payload_length),
                ],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and structure, readable bytes and a writable pointer.
            let connection = unsafe { Pointer::reference(connection) }?;
            let syn = unsafe { FFITCPSegment::read(syn, options, options_length, payload, payload_length) }?;
            unsafe { Pointer::write(out, connection.accepts_syn(&syn)) }
        })())
    }

    /// Writes what the connection's state machine holds into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_info(connection: *const TCPConnection, out: *mut FFITCPConnectionInfo) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write(out, FFITCPConnectionInfo::of(connection)) }
        })())
    }

    /// Writes the configuration of the connection into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_config(connection: *const TCPConnection, out: *mut FFITCPConfig) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write(out, connection.config.into()) }
        })())
    }

    /// Changes the configuration of the connection to `config`, such as Nagle (MUST-17) or
    /// keep-alives (MUST-24); fails with InvalidArgument for an unknown ECN mode or congestion
    /// control, and with Config for a configuration that cannot work.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_set_config(connection: *mut TCPConnection, config: *const FFITCPConfig, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and structure.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let config = unsafe { Pointer::reference(config) }?.config()?;
            connection.set_config(config, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Writes the local and remote endpoints of the connection into `out_local` and `out_remote`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_connection_endpoints(connection: *const TCPConnection, out_local: *mut FFIIPEndpoint, out_remote: *mut FFIIPEndpoint) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_local, 1), Pointer::range(out_remote, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference(connection) }?;
            Pointer::check_range(out_remote, 1)?;
            unsafe { Pointer::write(out_local, FFIIPEndpoint::of(&connection.local)) }?;
            unsafe { Pointer::write(out_remote, FFIIPEndpoint::of(&connection.remote)) }
        })())
    }

    /// Writes a listener for the local endpoints of `local`, of `backlog` connections, with initial
    /// sequence numbers under the 16 bytes of key at `key`, into `out`; fails with Config for a
    /// configuration that cannot work.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_listener_new(config: *const FFITCPConfig, local: *const FFIIPEndpointPattern, backlog: usize, key: *const u8, out: *mut *mut TCPListener) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid structures, 16 readable bytes and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?.config()?;
            let local = unsafe { Pointer::reference(local) }?.pattern()?;
            let key: [u8; 16] = unsafe { Pointer::slice(key, 16) }?.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            Pointer::check_range(out, 1)?;
            let listener = TCPListener::new(config, local, backlog, TCPISNGenerator::new(key)).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, listener) }
        })())
    }

    /// Releases a listener. Does nothing if `listener` is null.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_listener_free(listener: *mut TCPListener) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(listener) }
    }

    /// Gives the listener a segment from `remote` to `local` that no connection took.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_listener_receive(listener: *mut TCPListener, segment: *const FFITCPSegment, options: *const u8, options_length: usize, payload: *const u8, payload_length: usize, local: *const FFIIPEndpoint, remote: *const FFIIPEndpoint, ce: bool, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and structures and readable bytes.
            let listener = unsafe { Pointer::reference_mut(listener) }?;
            let segment = unsafe { FFITCPSegment::read(segment, options, options_length, payload, payload_length) }?;
            let local = unsafe { Pointer::reference(local) }?.endpoint()?;
            let remote = unsafe { Pointer::reference(remote) }?.endpoint()?;
            listener.receive(&segment, local, remote, ce, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the listener has a segment to send at `now` into `out_found`, its endpoints into
    /// `out_local` and `out_remote`, the segment into `out` and ECT(0) into `out_ect`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_listener_transmit(listener: *mut TCPListener, now: u64, out_found: *mut bool, out_local: *mut FFIIPEndpoint, out_remote: *mut FFIIPEndpoint, out: *mut Buffer, out_ect: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[
                    Pointer::range(out_found, 1),
                    Pointer::range(out_local, 1),
                    Pointer::range(out_remote, 1),
                    Pointer::range(out_ect, 1),
                ],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let listener = unsafe { Pointer::reference_mut(listener) }?;
            for pointer in [out_found, out_ect] {
                Pointer::check_range(pointer, 1)?;
            }
            Pointer::check_range(out_local, 1)?;
            Pointer::check_range(out_remote, 1)?;
            Pointer::check_range(out, 1)?;
            let mut bytes = Bytes::new();
            let written = listener.transmit(Instant::from_nanos(now), &mut bytes).map_err(|error| error.to_status())?;
            let (local, remote, ect) = written.map_or((FFIIPEndpoint::default(), FFIIPEndpoint::default(), false), |(local, remote, transmission)| (FFIIPEndpoint::of(&local), FFIIPEndpoint::of(&remote), transmission.ect));
            unsafe { Pointer::write(out_found, written.is_some()) }?;
            unsafe { Pointer::write(out_local, local) }?;
            unsafe { Pointer::write(out_remote, remote) }?;
            unsafe { Pointer::write(out_ect, ect) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes.into_vec())) }
        })())
    }

    /// Writes whether a connection is established and waiting into `out_found`, and its handle into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_listener_accept(listener: *mut TCPListener, out_found: *mut bool, out: *mut *mut TCPConnection) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let listener = unsafe { Pointer::reference_mut(listener) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let connection = listener.accept();
            unsafe { Pointer::write(out_found, connection.is_some()) }?;
            match connection {
                Some(connection) => unsafe { Pointer::write_handle(out, connection) },
                None => Ok(()),
            }
        })())
    }

    /// Writes whether the listener has a timer into `out_found` and the earliest into `out`, and the
    /// connections being set up and waiting into `out_pending` and `out_ready`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_listener_poll_timeout(listener: *const TCPListener, out_found: *mut bool, out: *mut u64, out_pending: *mut usize, out_ready: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[
                    Pointer::range(out_found, 1),
                    Pointer::range(out, 1),
                    Pointer::range(out_pending, 1),
                    Pointer::range(out_ready, 1),
                ],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let listener = unsafe { Pointer::reference(listener) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_pending, 1)?;
            Pointer::check_range(out_ready, 1)?;
            let deadline = listener.poll_timeout();
            unsafe { Pointer::write(out_found, deadline.is_some()) }?;
            unsafe { Pointer::write(out, deadline.map_or(0, Instant::as_nanos)) }?;
            unsafe { Pointer::write(out_pending, listener.pending()) }?;
            unsafe { Pointer::write(out_ready, listener.ready.len()) }
        })())
    }

    /// Writes whether the local endpoint `local` is one of the listener's into `out`.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_listener_matches(listener: *const TCPListener, local: *const FFIIPEndpoint, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(local, 1)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and structure and a writable pointer.
            let listener = unsafe { Pointer::reference(listener) }?;
            let local = unsafe { Pointer::reference(local) }?.endpoint()?;
            unsafe { Pointer::write(out, listener.matches(local)) }
        })())
    }

    /// Writes whether the rule at `rule` matches a connection to `local` from `remote` into `out`;
    /// fails with the ip module's Length for a bad address length.
    pub unsafe extern "C" fn umilib_protocol_tcp_tcp_rule_matches(rule: *const FFITCPRule, local: *const FFIIPEndpoint, remote: *const FFIIPEndpoint, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(rule, 1), Pointer::range(local, 1), Pointer::range(remote, 1)],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes valid structures and a writable pointer.
            let rule = unsafe { Pointer::reference(rule) }?;
            let rule = TCPRule { local: rule.local.pattern()?, remote: rule.remote.pattern()? };
            let local = unsafe { Pointer::reference(local) }?.endpoint()?;
            let remote = unsafe { Pointer::reference(remote) }?.endpoint()?;
            unsafe { Pointer::write(out, rule.matches(&FFITCPEndpoints { local, remote })) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "tcp",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_tcp_TCPHeader",
            documentation: " The fixed 20 bytes of a TCP header (RFC 9293 §3.1), its fields as they are.",
            fields: &[
                Parameter { name: "source_port", value: <u16 as Value>::TYPE },
                Parameter { name: "destination_port", value: <u16 as Value>::TYPE },
                Parameter { name: "sequence", value: <u32 as Value>::TYPE },
                Parameter { name: "acknowledgment", value: <u32 as Value>::TYPE },
                Parameter { name: "data_offset", value: <u8 as Value>::TYPE },
                Parameter { name: "reserved", value: <u8 as Value>::TYPE },
                Parameter { name: "flags", value: <u8 as Value>::TYPE },
                Parameter { name: "window", value: <u16 as Value>::TYPE },
                Parameter { name: "checksum", value: <u16 as Value>::TYPE },
                Parameter { name: "urgent_pointer", value: <u16 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_tcp_TCPSegment",
            documentation: " The fields of a TCP segment but its options and data.",
            fields: &[
                Parameter { name: "source_port", value: <u16 as Value>::TYPE },
                Parameter { name: "destination_port", value: <u16 as Value>::TYPE },
                Parameter { name: "sequence", value: <u32 as Value>::TYPE },
                Parameter { name: "acknowledgment", value: <u32 as Value>::TYPE },
                Parameter { name: "flags", value: <u8 as Value>::TYPE },
                Parameter { name: "window", value: <u16 as Value>::TYPE },
                Parameter { name: "urgent_pointer", value: <u16 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_tcp_TCPSACKBlock",
            documentation: " A block of a SACK option (RFC 2018 §3): from `left` up to `right`.",
            fields: &[
                Parameter { name: "left", value: <u32 as Value>::TYPE },
                Parameter { name: "right", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_tcp_TCPTimestamps",
            documentation: " The values of a Timestamps option (RFC 7323 §3.2).",
            fields: &[
                Parameter { name: "value", value: <u32 as Value>::TYPE },
                Parameter { name: "echo_reply", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_tcp_TCPOptionSet",
            documentation: " The options this crate understands, each optional one with whether it is present.",
            fields: &[
                Parameter { name: "has_mss", value: <bool as Value>::TYPE },
                Parameter { name: "mss", value: <u16 as Value>::TYPE },
                Parameter { name: "has_window_scale", value: <bool as Value>::TYPE },
                Parameter { name: "window_scale", value: <u8 as Value>::TYPE },
                Parameter { name: "sack_permitted", value: <bool as Value>::TYPE },
                Parameter { name: "has_timestamps", value: <bool as Value>::TYPE },
                Parameter { name: "timestamps", value: <TCPTimestamps as Value>::TYPE },
                Parameter { name: "sack_blocks", value: <[TCPSACKBlock; 4] as Value>::TYPE },
                Parameter { name: "sack_count", value: <u8 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_tcp_TCPRetransmissionTimer",
            documentation: " The retransmission timer of RFC 6298, durations in nanoseconds.",
            fields: &[
                Parameter { name: "has_smoothed", value: <bool as Value>::TYPE },
                Parameter { name: "smoothed", value: <u64 as Value>::TYPE },
                Parameter { name: "variation", value: <u64 as Value>::TYPE },
                Parameter { name: "timeout", value: <u64 as Value>::TYPE },
                Parameter { name: "backoff", value: <u32 as Value>::TYPE },
                Parameter { name: "minimum", value: <u64 as Value>::TYPE },
                Parameter { name: "maximum", value: <u64 as Value>::TYPE },
                Parameter { name: "granularity", value: <u64 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_tcp_TCPConfig",
            documentation: " The parameters of a connection, durations in nanoseconds.",
            fields: &[
                Parameter { name: "mtu", value: <u16 as Value>::TYPE },
                Parameter { name: "send_buffer", value: <usize as Value>::TYPE },
                Parameter { name: "receive_buffer", value: <usize as Value>::TYPE },
                Parameter { name: "window_scale", value: <bool as Value>::TYPE },
                Parameter { name: "timestamps", value: <bool as Value>::TYPE },
                Parameter { name: "sack", value: <bool as Value>::TYPE },
                Parameter { name: "ecn", value: <u8 as Value>::TYPE },
                Parameter { name: "nagle", value: <bool as Value>::TYPE },
                Parameter { name: "delayed_ack", value: <u64 as Value>::TYPE },
                Parameter { name: "initial_rto", value: <u64 as Value>::TYPE },
                Parameter { name: "minimum_rto", value: <u64 as Value>::TYPE },
                Parameter { name: "maximum_rto", value: <u64 as Value>::TYPE },
                Parameter { name: "clock_granularity", value: <u64 as Value>::TYPE },
                Parameter { name: "congestion", value: <u8 as Value>::TYPE },
                Parameter { name: "has_initial_window", value: <bool as Value>::TYPE },
                Parameter { name: "initial_window", value: <u32 as Value>::TYPE },
                Parameter { name: "retries", value: <u32 as Value>::TYPE },
                Parameter { name: "user_timeout", value: <u64 as Value>::TYPE },
                Parameter { name: "connect_timeout", value: <u64 as Value>::TYPE },
                Parameter { name: "keepalive", value: <bool as Value>::TYPE },
                Parameter { name: "keepalive_idle", value: <u64 as Value>::TYPE },
                Parameter { name: "keepalive_interval", value: <u64 as Value>::TYPE },
                Parameter { name: "keepalive_probes", value: <u32 as Value>::TYPE },
                Parameter { name: "time_wait", value: <u64 as Value>::TYPE },
                Parameter { name: "challenge_acks", value: <u32 as Value>::TYPE },
                Parameter { name: "hard_error_abort", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_tcp_TCPConnectionInfo",
            documentation: " What a connection's state machine holds that an application may read.",
            fields: &[
                Parameter { name: "state", value: <u8 as Value>::TYPE },
                Parameter { name: "passive", value: <bool as Value>::TYPE },
                Parameter { name: "iss", value: <u32 as Value>::TYPE },
                Parameter { name: "send_unacknowledged", value: <u32 as Value>::TYPE },
                Parameter { name: "send_next", value: <u32 as Value>::TYPE },
                Parameter { name: "send_maximum", value: <u32 as Value>::TYPE },
                Parameter { name: "send_window", value: <u32 as Value>::TYPE },
                Parameter { name: "maximum_send_window", value: <u32 as Value>::TYPE },
                Parameter { name: "irs", value: <u32 as Value>::TYPE },
                Parameter { name: "receive_next", value: <u32 as Value>::TYPE },
                Parameter { name: "peer_mss", value: <u16 as Value>::TYPE },
                Parameter { name: "mtu", value: <u16 as Value>::TYPE },
                Parameter { name: "window_scaling", value: <bool as Value>::TYPE },
                Parameter { name: "send_scale", value: <u8 as Value>::TYPE },
                Parameter { name: "receive_scale", value: <u8 as Value>::TYPE },
                Parameter { name: "sack", value: <bool as Value>::TYPE },
                Parameter { name: "timestamps", value: <bool as Value>::TYPE },
                Parameter { name: "ecn", value: <bool as Value>::TYPE },
                Parameter { name: "congestion_window", value: <u32 as Value>::TYPE },
                Parameter { name: "congestion_threshold", value: <u32 as Value>::TYPE },
                Parameter { name: "in_recovery", value: <bool as Value>::TYPE },
                Parameter { name: "timer", value: <FFITCPRetransmissionTimer as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_tcp_TCPRule",
            documentation: " A rule that routes connections by their local and remote endpoints.",
            fields: &[
                Parameter { name: "local", value: <FFIIPEndpointPattern as Value>::TYPE },
                Parameter { name: "remote", value: <FFIIPEndpointPattern as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_tcp_TCPISNGenerator",
            documentation: " The generator of initial sequence numbers of RFC 6528.",
        },
        Definition::Opaque {
            name: "umilib_protocol_tcp_TCPCongestion",
            documentation: " A congestion control: NewReno or CUBIC.",
        },
        Definition::Opaque {
            name: "umilib_protocol_tcp_TCPConnection",
            documentation: " A TCP connection without I/O.",
        },
        Definition::Opaque {
            name: "umilib_protocol_tcp_TCPListener",
            documentation: " A passive OPEN and its connections being set up.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
