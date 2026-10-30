use alloc::vec::Vec;

use super::{H2Error, H2ErrorCode, H2SettingID};

/// A frame type (RFC 9113 §6, RFC 9218 §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct H2FrameType(pub u8);

impl H2FrameType {
    pub const DATA: H2FrameType = H2FrameType(0x0);
    pub const HEADERS: H2FrameType = H2FrameType(0x1);
    pub const PRIORITY: H2FrameType = H2FrameType(0x2);
    pub const RST_STREAM: H2FrameType = H2FrameType(0x3);
    pub const SETTINGS: H2FrameType = H2FrameType(0x4);
    pub const PUSH_PROMISE: H2FrameType = H2FrameType(0x5);
    pub const PING: H2FrameType = H2FrameType(0x6);
    pub const GOAWAY: H2FrameType = H2FrameType(0x7);
    pub const WINDOW_UPDATE: H2FrameType = H2FrameType(0x8);
    pub const CONTINUATION: H2FrameType = H2FrameType(0x9);
    pub const PRIORITY_UPDATE: H2FrameType = H2FrameType(0x10);
}

/// The flags of frames (RFC 9113 §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H2Flags;

impl H2Flags {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

/// The 9 bytes before each frame's payload (RFC 9113 §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H2FrameHeader {
    pub length: u32,
    pub frame_type: H2FrameType,
    pub flags: u8,
    /// The stream identifier, its reserved bit ignored.
    pub stream: u32,
}

impl H2FrameHeader {
    pub const LENGTH: usize = 9;

    /// The header at the start of `bytes`, if it has 9 bytes.
    pub fn decode(bytes: &[u8]) -> Option<H2FrameHeader> {
        let header: &[u8; 9] = bytes.get(..H2FrameHeader::LENGTH)?.try_into().ok()?;
        Some(H2FrameHeader {
            length: u32::from_be_bytes([0, header[0], header[1], header[2]]),
            frame_type: H2FrameType(header[3]),
            flags: header[4],
            stream: u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7FFF_FFFF,
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.length.to_be_bytes()[1..]);
        out.push(self.frame_type.0);
        out.push(self.flags);
        out.extend_from_slice(&(self.stream & 0x7FFF_FFFF).to_be_bytes());
    }
}

/// The priority fields of HEADERS and PRIORITY frames, which RFC 9113
/// deprecates (§5.3.2): checked and otherwise ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H2PriorityField {
    pub exclusive: bool,
    pub dependency: u32,
    pub weight: u8,
}

impl H2PriorityField {
    pub fn decode(bytes: &[u8]) -> H2PriorityField {
        let dependency = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        H2PriorityField {
            exclusive: dependency & 0x8000_0000 != 0,
            dependency: dependency & 0x7FFF_FFFF,
            weight: bytes[4],
        }
    }
}

/// A frame (RFC 9113 §6, RFC 9218 §7.1), borrowing its payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum H2Frame<'a> {
    /// `length` is the whole payload, padding included, as flow control counts it.
    Data {
        stream: u32,
        data: &'a [u8],
        end_stream: bool,
        length: u32,
    },
    Headers {
        stream: u32,
        block: &'a [u8],
        end_stream: bool,
        end_headers: bool,
        priority: Option<H2PriorityField>,
    },
    Priority {
        stream: u32,
        priority: H2PriorityField,
    },
    ResetStream {
        stream: u32,
        code: H2ErrorCode,
    },
    Settings {
        ack: bool,
        settings: Vec<(H2SettingID, u32)>,
    },
    PushPromise {
        stream: u32,
        promised: u32,
        block: &'a [u8],
        end_headers: bool,
    },
    Ping {
        ack: bool,
        data: [u8; 8],
    },
    GoAway {
        last: u32,
        code: H2ErrorCode,
        debug: &'a [u8],
    },
    WindowUpdate {
        stream: u32,
        increment: u32,
    },
    Continuation {
        stream: u32,
        block: &'a [u8],
        end_headers: bool,
    },
    /// PRIORITY_UPDATE of a request stream (RFC 9218 §7.1).
    PriorityUpdate {
        prioritized: u32,
        value: &'a [u8],
    },
    /// A frame of a type this crate does not know, which is ignored (RFC 9113 §5.5).
    Unknown {
        frame_type: H2FrameType,
    },
}

impl<'a> H2Frame<'a> {
    /// The frame of `header` and its whole `payload`. Fails with the errors
    /// of RFC 9113 §6: lengths a frame cannot have, padding as long as the
    /// payload, frames on the wrong stream, a window increment of 0.
    pub fn decode(header: &H2FrameHeader, payload: &'a [u8]) -> Result<H2Frame<'a>, H2Error> {
        let stream = header.stream;
        let on_stream = |frame: &'static str| {
            if stream == 0 { Err(H2Error::protocol(frame)) } else { Ok(()) }
        };
        let on_connection = |frame: &'static str| {
            if stream != 0 { Err(H2Error::protocol(frame)) } else { Ok(()) }
        };
        match header.frame_type {
            H2FrameType::DATA => {
                on_stream("DATA on stream 0")?;
                let data = H2Frame::unpad(header, payload)?;
                Ok(H2Frame::Data {
                    stream,
                    data,
                    end_stream: header.flags & H2Flags::END_STREAM != 0,
                    length: header.length,
                })
            }
            H2FrameType::HEADERS => {
                on_stream("HEADERS on stream 0")?;
                let mut block = H2Frame::unpad(header, payload)?;
                let priority = if header.flags & H2Flags::PRIORITY != 0 {
                    if block.len() < 5 {
                        return Err(H2Error::frame_size("HEADERS too short for its priority"));
                    }
                    // A stream that depends on itself is an error of the
                    // connection's reader, after its block is decoded (RFC
                    // 9113 §4.3, §5.3.1): HPACK must stay in step.
                    let priority = H2PriorityField::decode(block);
                    block = &block[5..];
                    Some(priority)
                } else {
                    None
                };
                Ok(H2Frame::Headers {
                    stream,
                    block,
                    end_stream: header.flags & H2Flags::END_STREAM != 0,
                    end_headers: header.flags & H2Flags::END_HEADERS != 0,
                    priority,
                })
            }
            H2FrameType::PRIORITY => {
                on_stream("PRIORITY on stream 0")?;
                if payload.len() != 5 {
                    return Err(H2Error::stream(stream, H2ErrorCode::FRAME_SIZE_ERROR, "PRIORITY not of 5 bytes"));
                }
                let priority = H2PriorityField::decode(payload);
                if priority.dependency == stream {
                    return Err(H2Error::stream(
                        stream,
                        H2ErrorCode::PROTOCOL_ERROR,
                        "a stream that depends on itself",
                    ));
                }
                Ok(H2Frame::Priority { stream, priority })
            }
            H2FrameType::RST_STREAM => {
                on_stream("RST_STREAM on stream 0")?;
                let code: [u8; 4] = payload.try_into().map_err(|_| H2Error::frame_size("RST_STREAM not of 4 bytes"))?;
                Ok(H2Frame::ResetStream { stream, code: H2ErrorCode(u32::from_be_bytes(code)) })
            }
            H2FrameType::SETTINGS => {
                on_connection("SETTINGS on a stream")?;
                let ack = header.flags & H2Flags::ACK != 0;
                if ack && !payload.is_empty() {
                    return Err(H2Error::frame_size("a SETTINGS acknowledgment with a payload"));
                }
                let (pairs, rest) = payload.as_chunks::<6>();
                if !rest.is_empty() {
                    return Err(H2Error::frame_size("SETTINGS not of a multiple of 6 bytes"));
                }
                let settings = pairs
                    .iter()
                    .map(|pair| {
                        (
                            H2SettingID(u16::from_be_bytes([pair[0], pair[1]])),
                            u32::from_be_bytes([pair[2], pair[3], pair[4], pair[5]]),
                        )
                    })
                    .collect();
                Ok(H2Frame::Settings { ack, settings })
            }
            H2FrameType::PUSH_PROMISE => {
                on_stream("PUSH_PROMISE on stream 0")?;
                let block = H2Frame::unpad(header, payload)?;
                if block.len() < 4 {
                    return Err(H2Error::frame_size("PUSH_PROMISE too short"));
                }
                let promised = u32::from_be_bytes([block[0], block[1], block[2], block[3]]) & 0x7FFF_FFFF;
                Ok(H2Frame::PushPromise {
                    stream,
                    promised,
                    block: &block[4..],
                    end_headers: header.flags & H2Flags::END_HEADERS != 0,
                })
            }
            H2FrameType::PING => {
                on_connection("PING on a stream")?;
                let data = payload.try_into().map_err(|_| H2Error::frame_size("PING not of 8 bytes"))?;
                Ok(H2Frame::Ping { ack: header.flags & H2Flags::ACK != 0, data })
            }
            H2FrameType::GOAWAY => {
                on_connection("GOAWAY on a stream")?;
                if payload.len() < 8 {
                    return Err(H2Error::frame_size("GOAWAY shorter than 8 bytes"));
                }
                let last = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7FFF_FFFF;
                let code = H2ErrorCode(u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]));
                Ok(H2Frame::GoAway { last, code, debug: &payload[8..] })
            }
            H2FrameType::WINDOW_UPDATE => {
                let increment: [u8; 4] =
                    payload.try_into().map_err(|_| H2Error::frame_size("WINDOW_UPDATE not of 4 bytes"))?;
                let increment = u32::from_be_bytes(increment) & 0x7FFF_FFFF;
                if increment == 0 {
                    return Err(match stream {
                        0 => H2Error::protocol("a window increment of 0"),
                        stream => H2Error::stream(stream, H2ErrorCode::PROTOCOL_ERROR, "a window increment of 0"),
                    });
                }
                Ok(H2Frame::WindowUpdate { stream, increment })
            }
            H2FrameType::CONTINUATION => {
                on_stream("CONTINUATION on stream 0")?;
                Ok(H2Frame::Continuation {
                    stream,
                    block: payload,
                    end_headers: header.flags & H2Flags::END_HEADERS != 0,
                })
            }
            H2FrameType::PRIORITY_UPDATE => {
                on_connection("PRIORITY_UPDATE on a stream")?;
                if payload.len() < 4 {
                    return Err(H2Error::frame_size("PRIORITY_UPDATE shorter than 4 bytes"));
                }
                let prioritized = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7FFF_FFFF;
                Ok(H2Frame::PriorityUpdate { prioritized, value: &payload[4..] })
            }
            frame_type => Ok(H2Frame::Unknown { frame_type }),
        }
    }

    /// The payload of a padded frame without its padding (RFC 9113 §6.1).
    pub fn unpad(header: &H2FrameHeader, payload: &'a [u8]) -> Result<&'a [u8], H2Error> {
        if header.flags & H2Flags::PADDED == 0 {
            return Ok(payload);
        }
        let (&padding, rest) =
            payload.split_first().ok_or(H2Error::frame_size("a padded frame without its padding length"))?;
        let end =
            rest.len().checked_sub(padding as usize).ok_or(H2Error::protocol("padding as long as the payload"))?;
        Ok(&rest[..end])
    }

    /// Appends a frame of `frame_type` with `flags` on `stream` around `payload`.
    pub fn write(frame_type: H2FrameType, flags: u8, stream: u32, payload: &[u8], out: &mut Vec<u8>) {
        H2FrameHeader { length: payload.len() as u32, frame_type, flags, stream }.encode(out);
        out.extend_from_slice(payload);
    }

    /// Appends the frame.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            H2Frame::Data { stream, data, end_stream, .. } => {
                H2Frame::write(H2FrameType::DATA, if *end_stream { H2Flags::END_STREAM } else { 0 }, *stream, data, out)
            }
            H2Frame::Headers { stream, block, end_stream, end_headers, priority } => {
                let mut flags = 0;
                if *end_stream {
                    flags |= H2Flags::END_STREAM;
                }
                if *end_headers {
                    flags |= H2Flags::END_HEADERS;
                }
                let mut payload = Vec::with_capacity(block.len() + 5);
                if let Some(priority) = priority {
                    flags |= H2Flags::PRIORITY;
                    payload.extend_from_slice(
                        &(priority.dependency | if priority.exclusive { 0x8000_0000 } else { 0 }).to_be_bytes(),
                    );
                    payload.push(priority.weight);
                }
                payload.extend_from_slice(block);
                H2Frame::write(H2FrameType::HEADERS, flags, *stream, &payload, out);
            }
            H2Frame::Priority { stream, priority } => {
                let mut payload =
                    (priority.dependency | if priority.exclusive { 0x8000_0000 } else { 0 }).to_be_bytes().to_vec();
                payload.push(priority.weight);
                H2Frame::write(H2FrameType::PRIORITY, 0, *stream, &payload, out);
            }
            H2Frame::ResetStream { stream, code } => {
                H2Frame::write(H2FrameType::RST_STREAM, 0, *stream, &code.0.to_be_bytes(), out)
            }
            H2Frame::Settings { ack, settings } => {
                let mut payload = Vec::with_capacity(6 * settings.len());
                for (id, value) in settings {
                    payload.extend_from_slice(&id.0.to_be_bytes());
                    payload.extend_from_slice(&value.to_be_bytes());
                }
                H2Frame::write(H2FrameType::SETTINGS, if *ack { H2Flags::ACK } else { 0 }, 0, &payload, out);
            }
            H2Frame::PushPromise { stream, promised, block, end_headers } => {
                let mut payload = promised.to_be_bytes().to_vec();
                payload.extend_from_slice(block);
                H2Frame::write(
                    H2FrameType::PUSH_PROMISE,
                    if *end_headers { H2Flags::END_HEADERS } else { 0 },
                    *stream,
                    &payload,
                    out,
                );
            }
            H2Frame::Ping { ack, data } => {
                H2Frame::write(H2FrameType::PING, if *ack { H2Flags::ACK } else { 0 }, 0, data, out)
            }
            H2Frame::GoAway { last, code, debug } => {
                let mut payload = last.to_be_bytes().to_vec();
                payload.extend_from_slice(&code.0.to_be_bytes());
                payload.extend_from_slice(debug);
                H2Frame::write(H2FrameType::GOAWAY, 0, 0, &payload, out);
            }
            H2Frame::WindowUpdate { stream, increment } => {
                H2Frame::write(H2FrameType::WINDOW_UPDATE, 0, *stream, &increment.to_be_bytes(), out)
            }
            H2Frame::Continuation { stream, block, end_headers } => H2Frame::write(
                H2FrameType::CONTINUATION,
                if *end_headers { H2Flags::END_HEADERS } else { 0 },
                *stream,
                block,
                out,
            ),
            H2Frame::PriorityUpdate { prioritized, value } => {
                let mut payload = prioritized.to_be_bytes().to_vec();
                payload.extend_from_slice(value);
                H2Frame::write(H2FrameType::PRIORITY_UPDATE, 0, 0, &payload, out);
            }
            H2Frame::Unknown { .. } => {}
        }
    }
}
