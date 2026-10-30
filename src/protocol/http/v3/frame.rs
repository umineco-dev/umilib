use alloc::vec::Vec;

use crate::bytes::Reader;
use crate::protocol::quic::QUICVarint;

use super::{H3Error, H3ErrorCode};

/// A frame type (RFC 9114 §7.2, RFC 9218 §7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct H3FrameType(pub u64);

impl H3FrameType {
    pub const DATA: H3FrameType = H3FrameType(0x00);
    pub const HEADERS: H3FrameType = H3FrameType(0x01);
    pub const CANCEL_PUSH: H3FrameType = H3FrameType(0x03);
    pub const SETTINGS: H3FrameType = H3FrameType(0x04);
    pub const PUSH_PROMISE: H3FrameType = H3FrameType(0x05);
    pub const GOAWAY: H3FrameType = H3FrameType(0x07);
    pub const MAX_PUSH_ID: H3FrameType = H3FrameType(0x0D);
    pub const PRIORITY_UPDATE_REQUEST: H3FrameType = H3FrameType(0xF0700);
    pub const PRIORITY_UPDATE_PUSH: H3FrameType = H3FrameType(0xF0701);

    /// Whether this is a type of HTTP/2 that HTTP/3 reserves, an error to
    /// receive (RFC 9114 §7.2.8): PRIORITY, PING, WINDOW_UPDATE, CONTINUATION.
    pub const fn is_http2(self) -> bool {
        matches!(self.0, 0x02 | 0x06 | 0x08 | 0x09)
    }

    /// Whether this end knows nothing of the type: neither a frame of
    /// RFC 9114 or RFC 9218 nor one of HTTP/2's types it reserves (§7.2.8).
    pub const fn is_unknown(self) -> bool {
        !matches!(
            self,
            H3FrameType::DATA
                | H3FrameType::HEADERS
                | H3FrameType::CANCEL_PUSH
                | H3FrameType::SETTINGS
                | H3FrameType::PUSH_PROMISE
                | H3FrameType::GOAWAY
                | H3FrameType::MAX_PUSH_ID
                | H3FrameType::PRIORITY_UPDATE_REQUEST
                | H3FrameType::PRIORITY_UPDATE_PUSH
        ) && !self.is_http2()
    }

    /// The reserved type 0x1f × `n` + 0x21, which means nothing (RFC 9114 §7.2.8).
    pub const fn reserved(n: u64) -> H3FrameType {
        H3FrameType(0x1F * n + 0x21)
    }
}

/// The type of a unidirectional stream (RFC 9114 §6.2, RFC 9204 §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct H3StreamType(pub u64);

impl H3StreamType {
    pub const CONTROL: H3StreamType = H3StreamType(0x00);
    pub const PUSH: H3StreamType = H3StreamType(0x01);
    pub const ENCODER: H3StreamType = H3StreamType(0x02);
    pub const DECODER: H3StreamType = H3StreamType(0x03);
}

/// The header of a frame: its type and the length of its payload (RFC 9114 §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H3FrameHeader {
    pub frame_type: H3FrameType,
    pub length: u64,
}

impl H3FrameHeader {
    /// The header at the start of `bytes` and its length; `None` while not whole.
    pub fn decode(bytes: &[u8]) -> Option<(H3FrameHeader, usize)> {
        let mut reader = Reader::new(bytes);
        let frame_type = QUICVarint::read(&mut reader).ok()?;
        let length = QUICVarint::read(&mut reader).ok()?;
        Some((H3FrameHeader { frame_type: H3FrameType(frame_type), length }, reader.position()))
    }

    /// Appends a frame of `frame_type` around `payload`.
    pub fn write(frame_type: H3FrameType, payload: &[u8], out: &mut Vec<u8>) {
        H3FrameHeader::write_header(frame_type, payload.len() as u64, out);
        out.extend_from_slice(payload);
    }

    /// Appends the header of a frame of `frame_type` and `length`.
    pub fn write_header(frame_type: H3FrameType, length: u64, out: &mut Vec<u8>) {
        // Types and lengths of this crate fit varints.
        let _ = QUICVarint::write(out, frame_type.0);
        let _ = QUICVarint::write(out, length);
    }

    /// The single varint payload of GOAWAY, MAX_PUSH_ID and CANCEL_PUSH (RFC 9114 §7.2).
    pub fn integer(payload: &[u8]) -> Result<u64, H3Error> {
        let mut reader = Reader::new(payload);
        let value = QUICVarint::read(&mut reader)
            .map_err(|_| H3Error::connection(H3ErrorCode::FRAME_ERROR, "a frame cut short"))?;
        if !reader.is_empty() {
            return Err(H3Error::connection(H3ErrorCode::FRAME_ERROR, "a frame longer than its content"));
        }
        Ok(value)
    }
}
