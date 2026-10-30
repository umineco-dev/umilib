//! QUIC version 2 (RFC 9369): version 1 with another Version field, other
//! long header packet types, salt, labels and Retry key, so that middleboxes
//! do not ossify on version 1.

use super::{QUICPacketType, QUICVersion, QUICVersionProfile};

/// QUIC version 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICv2;

impl QUICv2 {
    pub const PROFILE: QUICVersionProfile = QUICVersionProfile {
        version: QUICVersion::V2,
        // RFC 9369 §3.2: Retry 0b00, Initial 0b01, 0-RTT 0b10, Handshake 0b11.
        long_types: [
            QUICPacketType::Retry,
            QUICPacketType::Initial,
            QUICPacketType::ZeroRTT,
            QUICPacketType::Handshake,
        ],
        // RFC 9369 §3.3.1.
        initial_salt: [
            0x0D, 0xED, 0xE3, 0xDE, 0xF7, 0x00, 0xA6, 0xDB, 0x81, 0x93, 0x81, 0xBE, 0x6E, 0x26, 0x9D, 0xCB, 0xF9, 0xBD,
            0x2E, 0xD9,
        ],
        // RFC 9369 §3.3.2.
        key_label: b"quicv2 key",
        iv_label: b"quicv2 iv",
        hp_label: b"quicv2 hp",
        ku_label: b"quicv2 ku",
        // RFC 9369 §3.3.3.
        retry_key: [0x8F, 0xB4, 0xB0, 0x1B, 0x56, 0xAC, 0x48, 0xE2, 0x60, 0xFB, 0xCB, 0xCE, 0xAD, 0x7C, 0xCC, 0x92],
        retry_nonce: [0xD8, 0x69, 0x69, 0xBC, 0x2D, 0x7C, 0x6D, 0x99, 0x90, 0xEF, 0xB0, 0x4A],
    };
}
