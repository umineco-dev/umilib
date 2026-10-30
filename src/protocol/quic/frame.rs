use core::ops::RangeInclusive;

use crate::bytes::{ByteCounter, Reader, Writer};

use super::{QUICConnectionID, QUICError, QUICErrorCode, QUICPacketType, QUICStreamID, QUICVarint};

/// A frame type (RFC 9000 §12.4, §19, RFC 9221 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct QUICFrameType(pub u64);

impl QUICFrameType {
    pub const PADDING: QUICFrameType = QUICFrameType(0x00);
    pub const PING: QUICFrameType = QUICFrameType(0x01);
    pub const ACK: QUICFrameType = QUICFrameType(0x02);
    pub const ACK_ECN: QUICFrameType = QUICFrameType(0x03);
    pub const RESET_STREAM: QUICFrameType = QUICFrameType(0x04);
    pub const STOP_SENDING: QUICFrameType = QUICFrameType(0x05);
    pub const CRYPTO: QUICFrameType = QUICFrameType(0x06);
    pub const NEW_TOKEN: QUICFrameType = QUICFrameType(0x07);
    /// STREAM: 0x08 to 0x0f, with the OFF (0x04), LEN (0x02) and FIN (0x01) bits.
    pub const STREAM: QUICFrameType = QUICFrameType(0x08);
    pub const MAX_DATA: QUICFrameType = QUICFrameType(0x10);
    pub const MAX_STREAM_DATA: QUICFrameType = QUICFrameType(0x11);
    pub const MAX_STREAMS_BIDI: QUICFrameType = QUICFrameType(0x12);
    pub const MAX_STREAMS_UNI: QUICFrameType = QUICFrameType(0x13);
    pub const DATA_BLOCKED: QUICFrameType = QUICFrameType(0x14);
    pub const STREAM_DATA_BLOCKED: QUICFrameType = QUICFrameType(0x15);
    pub const STREAMS_BLOCKED_BIDI: QUICFrameType = QUICFrameType(0x16);
    pub const STREAMS_BLOCKED_UNI: QUICFrameType = QUICFrameType(0x17);
    pub const NEW_CONNECTION_ID: QUICFrameType = QUICFrameType(0x18);
    pub const RETIRE_CONNECTION_ID: QUICFrameType = QUICFrameType(0x19);
    pub const PATH_CHALLENGE: QUICFrameType = QUICFrameType(0x1A);
    pub const PATH_RESPONSE: QUICFrameType = QUICFrameType(0x1B);
    /// CONNECTION_CLOSE of the transport (RFC 9000 §19.19).
    pub const CONNECTION_CLOSE: QUICFrameType = QUICFrameType(0x1C);
    /// CONNECTION_CLOSE of the application.
    pub const APPLICATION_CLOSE: QUICFrameType = QUICFrameType(0x1D);
    pub const HANDSHAKE_DONE: QUICFrameType = QUICFrameType(0x1E);
    /// DATAGRAM without and with a Length field (RFC 9221 §4).
    pub const DATAGRAM: QUICFrameType = QUICFrameType(0x30);
    pub const DATAGRAM_WITH_LENGTH: QUICFrameType = QUICFrameType(0x31);

    pub const fn is_stream(self) -> bool {
        self.0 >= 0x08 && self.0 <= 0x0F
    }

    pub const fn is_known(self) -> bool {
        self.0 <= 0x1E || self.0 == 0x30 || self.0 == 0x31
    }

    /// Whether a packet of `packet_type` may carry frames of this type: the
    /// "Pkts" column of RFC 9000 §12.4 Table 3 and RFC 9221 §4. 0-RTT
    /// packets carry neither RETIRE_CONNECTION_ID, which only answers what
    /// the server sent (RFC 9000 §12.5), nor what Table 3 forbids there.
    pub const fn permits(self, packet_type: QUICPacketType) -> bool {
        let (initial, handshake, zero, one) = match self.0 {
            0x00 | 0x01 => (true, true, true, true),
            0x02 | 0x03 | 0x06 => (true, true, false, true),
            0x07 | 0x1B | 0x1E => (false, false, false, true),
            0x19 => (false, false, false, true),
            0x04 | 0x05 | 0x08..=0x18 | 0x1A | 0x1D | 0x30 | 0x31 => (false, false, true, true),
            0x1C => (true, true, true, true),
            _ => (false, false, false, false),
        };
        match packet_type {
            QUICPacketType::Initial => initial,
            QUICPacketType::Handshake => handshake,
            QUICPacketType::ZeroRTT => zero,
            QUICPacketType::OneRTT => one,
            QUICPacketType::Retry => false,
        }
    }

    /// Whether a packet with this frame must be acknowledged: all but
    /// PADDING, ACK and CONNECTION_CLOSE (RFC 9002 §2, RFC 9000 Table 3 "N").
    pub const fn is_ack_eliciting(self) -> bool {
        !matches!(self.0, 0x00 | 0x02 | 0x03 | 0x1C | 0x1D)
    }

    /// Whether this is a probing frame: one that a packet sent to validate
    /// a path may carry without migrating (RFC 9000 §9.1, Table 3 "P").
    pub const fn is_probing(self) -> bool {
        matches!(self.0, 0x00 | 0x18 | 0x1A | 0x1B)
    }

    /// Whether a packet with only frames like this one does not count as
    /// bytes in flight: ACK alone (RFC 9000 Table 3 "C", RFC 9002 §2).
    pub const fn is_congestion_exempt(self) -> bool {
        matches!(self.0, 0x02 | 0x03)
    }
}

/// The ECN counts of an ACK frame of type 0x03 (RFC 9000 §19.3.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct QUICECNCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}

/// An ACK frame (RFC 9000 §19.3), its ranges as they are on the wire: they
/// were checked when decoded, and [`QUICACKFrame::ranges`] reads them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QUICACKFrame<'a> {
    pub largest: u64,
    /// The ACK Delay field, before scaling by the sender's `ack_delay_exponent`.
    pub delay: u64,
    pub first_range: u64,
    pub range_count: u64,
    /// The Gap and ACK Range Length fields after the first range.
    pub ranges_field: &'a [u8],
    pub ecn: Option<QUICECNCounts>,
}

impl<'a> QUICACKFrame<'a> {
    /// The packet numbers acknowledged, as inclusive ranges from the
    /// largest down (RFC 9000 §19.3.1).
    pub fn ranges(&self) -> QUICACKRanges<'a> {
        QUICACKRanges {
            reader: Reader::new(self.ranges_field),
            next: self.largest.checked_sub(self.first_range).map(|smallest| smallest..=self.largest),
        }
    }

    /// The smallest packet number acknowledged.
    pub fn smallest(&self) -> u64 {
        self.ranges().last().map_or(self.largest, |range| *range.start())
    }

    /// Writes an ACK frame of `ranges`, disjoint, non-adjacent and from the
    /// largest down, with the encoded `delay` and, if any, ECN counts.
    pub fn encode_ranges(
        ranges: &[RangeInclusive<u64>],
        delay: u64,
        ecn: Option<QUICECNCounts>,
        out: &mut impl Writer,
    ) -> Result<(), QUICError> {
        let [first, rest @ ..] = ranges else { return Err(QUICError::Config) };
        let frame_type = if ecn.is_some() { QUICFrameType::ACK_ECN } else { QUICFrameType::ACK };
        QUICVarint::write(out, frame_type.0)?;
        QUICVarint::write(out, *first.end())?;
        QUICVarint::write(out, delay)?;
        QUICVarint::write(out, rest.len() as u64)?;
        QUICVarint::write(out, first.end().checked_sub(*first.start()).ok_or(QUICError::Config)?)?;
        let mut smallest = *first.start();
        for range in rest {
            // largest = previous_smallest - gap - 2 (RFC 9000 §19.3.1).
            let gap = smallest.checked_sub(*range.end()).and_then(|gap| gap.checked_sub(2)).ok_or(QUICError::Config)?;
            QUICVarint::write(out, gap)?;
            QUICVarint::write(out, range.end().checked_sub(*range.start()).ok_or(QUICError::Config)?)?;
            smallest = *range.start();
        }
        if let Some(counts) = ecn {
            QUICVarint::write(out, counts.ect0)?;
            QUICVarint::write(out, counts.ect1)?;
            QUICVarint::write(out, counts.ce)?;
        }
        Ok(())
    }
}

/// The ranges of an [`QUICACKFrame`], largest first.
#[derive(Clone, Debug)]
pub struct QUICACKRanges<'a> {
    reader: Reader<'a>,
    next: Option<RangeInclusive<u64>>,
}

impl Iterator for QUICACKRanges<'_> {
    type Item = RangeInclusive<u64>;

    fn next(&mut self) -> Option<RangeInclusive<u64>> {
        let current = self.next.take()?;
        if !self.reader.is_empty() {
            // Decoded frames were checked; a frame made otherwise ends at its first impossible range.
            let gap = QUICVarint::read(&mut self.reader).ok()?;
            let length = QUICVarint::read(&mut self.reader).ok()?;
            self.next = current
                .start()
                .checked_sub(gap)
                .and_then(|end| end.checked_sub(2))
                .and_then(|largest| largest.checked_sub(length).map(|smallest| smallest..=largest));
        }
        Some(current)
    }
}

/// A frame (RFC 9000 §19, RFC 9221 §4), its data borrowed from the packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QUICFrame<'a> {
    /// A run of PADDING frames, `length` bytes.
    Padding {
        length: usize,
    },
    Ping,
    ACK(QUICACKFrame<'a>),
    ResetStream {
        stream: QUICStreamID,
        error: u64,
        final_size: u64,
    },
    StopSending {
        stream: QUICStreamID,
        error: u64,
    },
    Crypto {
        offset: u64,
        data: &'a [u8],
    },
    NewToken {
        token: &'a [u8],
    },
    Stream {
        stream: QUICStreamID,
        offset: u64,
        data: &'a [u8],
        fin: bool,
    },
    MaxData {
        maximum: u64,
    },
    MaxStreamData {
        stream: QUICStreamID,
        maximum: u64,
    },
    MaxStreams {
        bidirectional: bool,
        maximum: u64,
    },
    DataBlocked {
        maximum: u64,
    },
    StreamDataBlocked {
        stream: QUICStreamID,
        maximum: u64,
    },
    StreamsBlocked {
        bidirectional: bool,
        maximum: u64,
    },
    NewConnectionID {
        sequence: u64,
        retire_prior_to: u64,
        id: QUICConnectionID,
        reset_token: [u8; 16],
    },
    RetireConnectionID {
        sequence: u64,
    },
    PathChallenge {
        data: [u8; 8],
    },
    PathResponse {
        data: [u8; 8],
    },
    /// CONNECTION_CLOSE of type 0x1c: a transport error, and the type of
    /// the frame that caused it.
    ConnectionClose {
        error: QUICErrorCode,
        frame_type: QUICFrameType,
        reason: &'a [u8],
    },
    /// CONNECTION_CLOSE of type 0x1d: an error of the application.
    ApplicationClose {
        error: u64,
        reason: &'a [u8],
    },
    HandshakeDone,
    Datagram {
        data: &'a [u8],
    },
}

impl<'a> QUICFrame<'a> {
    /// The type the frame is encoded with: the one [`QUICFrame::encode`]
    /// writes, LEN set where it can be absent.
    pub fn frame_type(&self) -> QUICFrameType {
        match self {
            QUICFrame::Padding { .. } => QUICFrameType::PADDING,
            QUICFrame::Ping => QUICFrameType::PING,
            QUICFrame::ACK(frame) if frame.ecn.is_some() => QUICFrameType::ACK_ECN,
            QUICFrame::ACK(_) => QUICFrameType::ACK,
            QUICFrame::ResetStream { .. } => QUICFrameType::RESET_STREAM,
            QUICFrame::StopSending { .. } => QUICFrameType::STOP_SENDING,
            QUICFrame::Crypto { .. } => QUICFrameType::CRYPTO,
            QUICFrame::NewToken { .. } => QUICFrameType::NEW_TOKEN,
            QUICFrame::Stream { offset, fin, .. } => {
                QUICFrameType(0x08 | if *offset > 0 { 0x04 } else { 0 } | 0x02 | u64::from(*fin))
            }
            QUICFrame::MaxData { .. } => QUICFrameType::MAX_DATA,
            QUICFrame::MaxStreamData { .. } => QUICFrameType::MAX_STREAM_DATA,
            QUICFrame::MaxStreams { bidirectional: true, .. } => QUICFrameType::MAX_STREAMS_BIDI,
            QUICFrame::MaxStreams { bidirectional: false, .. } => QUICFrameType::MAX_STREAMS_UNI,
            QUICFrame::DataBlocked { .. } => QUICFrameType::DATA_BLOCKED,
            QUICFrame::StreamDataBlocked { .. } => QUICFrameType::STREAM_DATA_BLOCKED,
            QUICFrame::StreamsBlocked { bidirectional: true, .. } => QUICFrameType::STREAMS_BLOCKED_BIDI,
            QUICFrame::StreamsBlocked { bidirectional: false, .. } => QUICFrameType::STREAMS_BLOCKED_UNI,
            QUICFrame::NewConnectionID { .. } => QUICFrameType::NEW_CONNECTION_ID,
            QUICFrame::RetireConnectionID { .. } => QUICFrameType::RETIRE_CONNECTION_ID,
            QUICFrame::PathChallenge { .. } => QUICFrameType::PATH_CHALLENGE,
            QUICFrame::PathResponse { .. } => QUICFrameType::PATH_RESPONSE,
            QUICFrame::ConnectionClose { .. } => QUICFrameType::CONNECTION_CLOSE,
            QUICFrame::ApplicationClose { .. } => QUICFrameType::APPLICATION_CLOSE,
            QUICFrame::HandshakeDone => QUICFrameType::HANDSHAKE_DONE,
            QUICFrame::Datagram { .. } => QUICFrameType::DATAGRAM_WITH_LENGTH,
        }
    }

    /// Reads the next frame of a packet's payload. Fails with
    /// FRAME_ENCODING_ERROR for a frame cut short, of an unknown type, or
    /// with a field out of range, and PROTOCOL_VIOLATION for a type not in
    /// its shortest encoding (RFC 9000 §12.4: MAY; it costs nothing to the
    /// peers that follow the rule).
    pub fn decode(reader: &mut Reader<'a>) -> Result<QUICFrame<'a>, QUICError> {
        let unknown = QUICFrameType::PADDING;
        let (raw, length) = QUICVarint::read_with_length(reader)
            .map_err(|_| QUICError::frame_encoding(unknown, "frame type cut short"))?;
        let frame_type = QUICFrameType(raw);
        if QUICVarint::length(raw) != Some(length) {
            return Err(QUICError::violation(frame_type, "frame type not in its shortest encoding"));
        }
        let mut fields = QUICFrameReader { reader, frame_type };
        let frame = match raw {
            0x00 => {
                let mut length = 1;
                while fields.reader.peek(1).is_ok_and(|byte| byte[0] == 0) {
                    fields.reader.skip(1).map_err(|_| fields.error("PADDING"))?;
                    length += 1;
                }
                QUICFrame::Padding { length }
            }
            0x01 => QUICFrame::Ping,
            0x02 | 0x03 => QUICFrame::ACK(fields.ack()?),
            0x04 => QUICFrame::ResetStream {
                stream: QUICStreamID(fields.integer()?),
                error: fields.integer()?,
                final_size: fields.integer()?,
            },
            0x05 => QUICFrame::StopSending { stream: QUICStreamID(fields.integer()?), error: fields.integer()? },
            0x06 => {
                let offset = fields.integer()?;
                let data = fields.data()?;
                fields.end_within_stream(offset, data.len())?;
                QUICFrame::Crypto { offset, data }
            }
            0x07 => {
                let token = fields.data()?;
                if token.is_empty() {
                    return Err(fields.error("empty NEW_TOKEN"));
                }
                QUICFrame::NewToken { token }
            }
            0x08..=0x0F => {
                let stream = QUICStreamID(fields.integer()?);
                let offset = if raw & 0x04 != 0 { fields.integer()? } else { 0 };
                let data = if raw & 0x02 != 0 { fields.data()? } else { fields.reader.read_rest() };
                fields.end_within_stream(offset, data.len())?;
                QUICFrame::Stream { stream, offset, data, fin: raw & 0x01 != 0 }
            }
            0x10 => QUICFrame::MaxData { maximum: fields.integer()? },
            0x11 => QUICFrame::MaxStreamData { stream: QUICStreamID(fields.integer()?), maximum: fields.integer()? },
            0x12 | 0x13 => QUICFrame::MaxStreams { bidirectional: raw == 0x12, maximum: fields.stream_count()? },
            0x14 => QUICFrame::DataBlocked { maximum: fields.integer()? },
            0x15 => {
                QUICFrame::StreamDataBlocked { stream: QUICStreamID(fields.integer()?), maximum: fields.integer()? }
            }
            0x16 | 0x17 => QUICFrame::StreamsBlocked { bidirectional: raw == 0x16, maximum: fields.stream_count()? },
            0x18 => {
                let sequence = fields.integer()?;
                let retire_prior_to = fields.integer()?;
                let length = fields.reader.read_u8().map_err(|_| fields.error("NEW_CONNECTION_ID"))? as usize;
                if !(1..=QUICConnectionID::MAXIMUM_LENGTH).contains(&length) {
                    return Err(fields.error("connection ID of NEW_CONNECTION_ID not of 1 to 20 bytes"));
                }
                if retire_prior_to > sequence {
                    return Err(fields.error("Retire Prior To above the Sequence Number"));
                }
                let id = fields.reader.read_slice(length).map_err(|_| fields.error("NEW_CONNECTION_ID"))?;
                let reset_token = fields.reader.read_array().map_err(|_| fields.error("NEW_CONNECTION_ID"))?;
                let id = QUICConnectionID::new(id).ok_or(fields.error("NEW_CONNECTION_ID"))?;
                QUICFrame::NewConnectionID { sequence, retire_prior_to, id, reset_token }
            }
            0x19 => QUICFrame::RetireConnectionID { sequence: fields.integer()? },
            0x1A => QUICFrame::PathChallenge { data: fields.reader.read_array().map_err(|_| fields.error("PATH"))? },
            0x1B => QUICFrame::PathResponse { data: fields.reader.read_array().map_err(|_| fields.error("PATH"))? },
            0x1C => {
                let error = QUICErrorCode(fields.integer()?);
                let frame_type = QUICFrameType(fields.integer()?);
                QUICFrame::ConnectionClose { error, frame_type, reason: fields.data()? }
            }
            0x1D => QUICFrame::ApplicationClose { error: fields.integer()?, reason: fields.data()? },
            0x1E => QUICFrame::HandshakeDone,
            0x30 => QUICFrame::Datagram { data: fields.reader.read_rest() },
            0x31 => QUICFrame::Datagram { data: fields.data()? },
            _ => return Err(fields.error("unknown frame type")),
        };
        Ok(frame)
    }

    /// Writes the frame. STREAM and DATAGRAM frames carry their length; see
    /// [`QUICFrame::encode_last`] for the last frame of a packet.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), QUICError> {
        self.encode_with(true, out)
    }

    /// Writes the frame as the last of its packet: STREAM and DATAGRAM
    /// frames without a Length field, their data running to the packet's end.
    pub fn encode_last(&self, out: &mut impl Writer) -> Result<(), QUICError> {
        self.encode_with(false, out)
    }

    /// The bytes [`QUICFrame::encode`] writes.
    pub fn encoded_length(&self) -> usize {
        let mut counter = ByteCounter::default();
        // Counting does not fail for a frame that can be written.
        let _ = self.encode(&mut counter);
        counter.count
    }

    fn encode_with(&self, length: bool, out: &mut impl Writer) -> Result<(), QUICError> {
        let frame_type = self.frame_type().0;
        match self {
            QUICFrame::Padding { length } => {
                for _ in 0..*length {
                    out.write_u8(0)?;
                }
            }
            QUICFrame::Ping | QUICFrame::HandshakeDone => QUICVarint::write_all(out, &[frame_type])?,
            QUICFrame::ACK(frame) => {
                QUICVarint::write_all(
                    out,
                    &[frame_type, frame.largest, frame.delay, frame.range_count, frame.first_range],
                )?;
                out.write(frame.ranges_field)?;
                if let Some(counts) = frame.ecn {
                    QUICVarint::write_all(out, &[counts.ect0, counts.ect1, counts.ce])?;
                }
            }
            QUICFrame::ResetStream { stream, error, final_size } => {
                QUICVarint::write_all(out, &[frame_type, stream.0, *error, *final_size])?
            }
            QUICFrame::StopSending { stream, error } => QUICVarint::write_all(out, &[frame_type, stream.0, *error])?,
            QUICFrame::Crypto { offset, data } => {
                QUICVarint::write_all(out, &[frame_type, *offset, data.len() as u64])?;
                out.write(data)?;
            }
            QUICFrame::NewToken { token } => {
                QUICVarint::write_all(out, &[frame_type, token.len() as u64])?;
                out.write(token)?;
            }
            QUICFrame::Stream { stream, offset, data, .. } => {
                let frame_type = if length { frame_type } else { frame_type & !0x02 };
                QUICVarint::write_all(out, &[frame_type, stream.0])?;
                if *offset > 0 {
                    QUICVarint::write(out, *offset)?;
                }
                if length {
                    QUICVarint::write(out, data.len() as u64)?;
                }
                out.write(data)?;
            }
            QUICFrame::MaxData { maximum }
            | QUICFrame::DataBlocked { maximum }
            | QUICFrame::MaxStreams { maximum, .. }
            | QUICFrame::StreamsBlocked { maximum, .. } => QUICVarint::write_all(out, &[frame_type, *maximum])?,
            QUICFrame::MaxStreamData { stream, maximum } | QUICFrame::StreamDataBlocked { stream, maximum } => {
                QUICVarint::write_all(out, &[frame_type, stream.0, *maximum])?
            }
            QUICFrame::NewConnectionID { sequence, retire_prior_to, id, reset_token } => {
                QUICVarint::write_all(out, &[frame_type, *sequence, *retire_prior_to])?;
                out.write_u8(id.len() as u8)?;
                out.write(id.as_slice())?;
                out.write(reset_token)?;
            }
            QUICFrame::RetireConnectionID { sequence } => QUICVarint::write_all(out, &[frame_type, *sequence])?,
            QUICFrame::PathChallenge { data } | QUICFrame::PathResponse { data } => {
                QUICVarint::write(out, frame_type)?;
                out.write(data)?;
            }
            QUICFrame::ConnectionClose { error, frame_type: cause, reason } => {
                QUICVarint::write_all(out, &[frame_type, error.0, cause.0, reason.len() as u64])?;
                out.write(reason)?;
            }
            QUICFrame::ApplicationClose { error, reason } => {
                QUICVarint::write_all(out, &[frame_type, *error, reason.len() as u64])?;
                out.write(reason)?;
            }
            QUICFrame::Datagram { data } => {
                if length {
                    QUICVarint::write_all(out, &[QUICFrameType::DATAGRAM_WITH_LENGTH.0, data.len() as u64])?;
                } else {
                    QUICVarint::write(out, QUICFrameType::DATAGRAM.0)?;
                }
                out.write(data)?;
            }
        }
        Ok(())
    }
}

/// The frames of a packet's payload, in order.
#[derive(Clone, Debug)]
pub struct QUICFrames<'a> {
    pub reader: Reader<'a>,
}

impl<'a> QUICFrames<'a> {
    pub fn new(payload: &'a [u8]) -> QUICFrames<'a> {
        QUICFrames { reader: Reader::new(payload) }
    }
}

impl<'a> Iterator for QUICFrames<'a> {
    type Item = Result<QUICFrame<'a>, QUICError>;

    fn next(&mut self) -> Option<Result<QUICFrame<'a>, QUICError>> {
        if self.reader.is_empty() {
            return None;
        }
        let frame = QUICFrame::decode(&mut self.reader);
        if frame.is_err() {
            self.reader.read_rest();
        }
        Some(frame)
    }
}

/// The reader of one frame's fields: each read fails with the
/// FRAME_ENCODING_ERROR of the frame's type (RFC 9000 §12.4), as frames of
/// extensions need too.
#[derive(Debug)]
pub struct QUICFrameReader<'r, 'a> {
    pub reader: &'r mut Reader<'a>,
    pub frame_type: QUICFrameType,
}

impl<'a> QUICFrameReader<'_, 'a> {
    pub fn error(&self, reason: &'static str) -> QUICError {
        QUICError::frame_encoding(self.frame_type, reason)
    }

    pub fn integer(&mut self) -> Result<u64, QUICError> {
        QUICVarint::read(self.reader).map_err(|_| self.error("frame cut short"))
    }

    /// A Length field and the bytes it counts.
    pub fn data(&mut self) -> Result<&'a [u8], QUICError> {
        let length = self.integer()?;
        let length = usize::try_from(length).map_err(|_| self.error("length past the packet"))?;
        self.reader.read_slice(length).map_err(|_| self.error("length past the packet"))
    }

    /// A stream count of MAX_STREAMS or STREAMS_BLOCKED: at most 2^60
    /// (RFC 9000 §19.11, §19.14).
    pub fn stream_count(&mut self) -> Result<u64, QUICError> {
        let count = self.integer()?;
        if count > QUICStreamID::MAXIMUM_COUNT {
            return Err(self.error("more than 2^60 streams"));
        }
        Ok(count)
    }

    /// The end of data at `offset` must not pass 2^62 - 1 (RFC 9000 §19.6, §19.8).
    pub fn end_within_stream(&self, offset: u64, length: usize) -> Result<(), QUICError> {
        match offset.checked_add(length as u64) {
            Some(end) if end <= QUICVarint::MAXIMUM => Ok(()),
            _ => Err(self.error("data past 2^62 - 1")),
        }
    }

    /// An ACK frame, every range checked to stay at or above zero (RFC 9000 §19.3.1).
    pub fn ack(&mut self) -> Result<QUICACKFrame<'a>, QUICError> {
        let largest = self.integer()?;
        let delay = self.integer()?;
        let range_count = self.integer()?;
        let first_range = self.integer()?;
        let mut smallest = largest.checked_sub(first_range).ok_or(self.error("negative packet number"))?;
        let start = *self.reader;
        for _ in 0..range_count {
            let gap = self.integer()?;
            let length = self.integer()?;
            smallest = smallest
                .checked_sub(gap)
                .and_then(|value| value.checked_sub(2))
                .and_then(|largest| largest.checked_sub(length))
                .ok_or(self.error("negative packet number"))?;
        }
        let consumed = self.reader.position() - start.position();
        let ranges_field = start.peek(consumed).map_err(|_| self.error("ACK"))?;
        let ecn = if self.frame_type == QUICFrameType::ACK_ECN {
            Some(QUICECNCounts { ect0: self.integer()?, ect1: self.integer()?, ce: self.integer()? })
        } else {
            None
        };
        Ok(QUICACKFrame { largest, delay, first_range, range_count, ranges_field, ecn })
    }
}
