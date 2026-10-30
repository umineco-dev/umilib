use alloc::vec::Vec;

/// An opcode (RFC 6455 §5.2, §11.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WebSocketOpcode(pub u8);

impl WebSocketOpcode {
    pub const CONTINUATION: WebSocketOpcode = WebSocketOpcode(0x0);
    pub const TEXT: WebSocketOpcode = WebSocketOpcode(0x1);
    pub const BINARY: WebSocketOpcode = WebSocketOpcode(0x2);
    pub const CLOSE: WebSocketOpcode = WebSocketOpcode(0x8);
    pub const PING: WebSocketOpcode = WebSocketOpcode(0x9);
    pub const PONG: WebSocketOpcode = WebSocketOpcode(0xA);

    /// Whether this is a control opcode (RFC 6455 §5.5): those from 0x8.
    pub const fn is_control(self) -> bool {
        self.0 & 0x8 != 0
    }

    /// Whether RFC 6455 defines it; the others are reserved (§5.2).
    pub const fn is_defined(self) -> bool {
        matches!(self.0, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xA)
    }
}

/// The header of a frame (RFC 6455 §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WebSocketFrameHeader {
    pub fin: bool,
    /// The RSV1, RSV2 and RSV3 bits, which only extensions use (RSV1 is
    /// permessage-deflate's, RFC 7692 §6).
    pub rsv1: bool,
    pub rsv2: bool,
    pub rsv3: bool,
    pub opcode: WebSocketOpcode,
    pub mask: Option<[u8; 4]>,
    pub length: u64,
}

impl WebSocketFrameHeader {
    /// The longest payload of a control frame (RFC 6455 §5.5).
    pub const MAXIMUM_CONTROL_LENGTH: u64 = 125;

    /// The header at the start of `bytes` and its length; `None` while it is
    /// not whole, `Err` for a 64-bit length with its top bit set or a length
    /// not in the fewest bytes, which §5.2 requires of every sender.
    pub fn decode(bytes: &[u8]) -> Result<Option<(WebSocketFrameHeader, usize)>, &'static str> {
        let [first, second, ..] = *bytes else { return Ok(None) };
        let masked = second & 0x80 != 0;
        let (length, mut position) = match second & 0x7F {
            126 => match bytes.get(2..4) {
                Some(length) => match u16::from_be_bytes([length[0], length[1]]) {
                    0..=125 => return Err("a 16-bit length of fewer than 126 bytes"),
                    length => (u64::from(length), 4),
                },
                None => return Ok(None),
            },
            127 => match bytes.get(2..10) {
                Some(length) => {
                    let length = u64::from_be_bytes(length.try_into().unwrap_or([0; 8]));
                    if length >> 63 != 0 {
                        return Err("a 64-bit length with its top bit set");
                    }
                    if length <= u64::from(u16::MAX) {
                        return Err("a 64-bit length of fewer than 65536 bytes");
                    }
                    (length, 10)
                }
                None => return Ok(None),
            },
            length => (u64::from(length), 2),
        };
        let mask = if masked {
            let Some(key) = bytes.get(position..position + 4) else { return Ok(None) };
            position += 4;
            Some([key[0], key[1], key[2], key[3]])
        } else {
            None
        };
        Ok(Some((
            WebSocketFrameHeader {
                fin: first & 0x80 != 0,
                rsv1: first & 0x40 != 0,
                rsv2: first & 0x20 != 0,
                rsv3: first & 0x10 != 0,
                opcode: WebSocketOpcode(first & 0x0F),
                mask,
                length,
            },
            position,
        )))
    }

    /// Appends the header, its length in the fewest bytes (§5.2).
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut first = self.opcode.0 & 0x0F;
        for (bit, set) in [(0x80, self.fin), (0x40, self.rsv1), (0x20, self.rsv2), (0x10, self.rsv3)] {
            if set {
                first |= bit;
            }
        }
        out.push(first);
        let masked = if self.mask.is_some() { 0x80 } else { 0 };
        match self.length {
            0..=125 => out.push(masked | self.length as u8),
            126..=0xFFFF => {
                out.push(masked | 126);
                out.extend_from_slice(&(self.length as u16).to_be_bytes());
            }
            _ => {
                out.push(masked | 127);
                out.extend_from_slice(&self.length.to_be_bytes());
            }
        }
        if let Some(mask) = self.mask {
            out.extend_from_slice(&mask);
        }
    }

    /// Masks or unmasks `data` with `mask`, the byte at `offset` of the
    /// payload first (RFC 6455 §5.3).
    pub fn apply_mask(mask: [u8; 4], offset: u64, data: &mut [u8]) {
        for (index, byte) in data.iter_mut().enumerate() {
            *byte ^= mask[((offset + index as u64) % 4) as usize];
        }
    }
}

/// The status codes of a Close frame (RFC 6455 §7.4, §11.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WebSocketCloseCode(pub u16);

impl WebSocketCloseCode {
    pub const NORMAL: WebSocketCloseCode = WebSocketCloseCode(1000);
    pub const GOING_AWAY: WebSocketCloseCode = WebSocketCloseCode(1001);
    pub const PROTOCOL_ERROR: WebSocketCloseCode = WebSocketCloseCode(1002);
    pub const UNSUPPORTED_DATA: WebSocketCloseCode = WebSocketCloseCode(1003);
    /// No status code was given; never sent (§7.4.1).
    pub const NO_STATUS: WebSocketCloseCode = WebSocketCloseCode(1005);
    /// The connection ended without a Close frame; never sent (§7.4.1).
    pub const ABNORMAL: WebSocketCloseCode = WebSocketCloseCode(1006);
    pub const INVALID_PAYLOAD: WebSocketCloseCode = WebSocketCloseCode(1007);
    pub const POLICY_VIOLATION: WebSocketCloseCode = WebSocketCloseCode(1008);
    pub const MESSAGE_TOO_BIG: WebSocketCloseCode = WebSocketCloseCode(1009);
    pub const MANDATORY_EXTENSION: WebSocketCloseCode = WebSocketCloseCode(1010);
    pub const INTERNAL_ERROR: WebSocketCloseCode = WebSocketCloseCode(1011);

    /// Whether a Close frame may carry the code (§7.4.1, §7.4.2, §11.7):
    /// those of the registry for use in frames, and 3000 to 4999.
    pub const fn is_valid(self) -> bool {
        matches!(self.0, 1000..=1003 | 1007..=1014 | 3000..=4999)
    }
}
