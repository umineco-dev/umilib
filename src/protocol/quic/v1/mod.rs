//! QUIC version 1 (RFC 9000, RFC 9001): the constants that make the
//! transport of the root module version 1.

use super::{QUICPacketType, QUICVersion, QUICVersionProfile};

/// QUIC version 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICv1;

impl QUICv1 {
    pub const PROFILE: QUICVersionProfile = QUICVersionProfile {
        version: QUICVersion::V1,
        // RFC 9000 §17.2, Table 5.
        long_types: [
            QUICPacketType::Initial,
            QUICPacketType::ZeroRTT,
            QUICPacketType::Handshake,
            QUICPacketType::Retry,
        ],
        // RFC 9001 §5.2.
        initial_salt: [
            0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3, 0x4D, 0x17, 0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD, 0xCC, 0xBB,
            0x7F, 0x0A,
        ],
        // RFC 9001 §5.1, §6.1.
        key_label: b"quic key",
        iv_label: b"quic iv",
        hp_label: b"quic hp",
        ku_label: b"quic ku",
        // RFC 9001 §5.8.
        retry_key: [0xBE, 0x0C, 0x69, 0x0B, 0x9F, 0x66, 0x57, 0x5A, 0x1D, 0x76, 0x6B, 0x54, 0xE3, 0x68, 0xC8, 0x4E],
        retry_nonce: [0x46, 0x15, 0x99, 0xD3, 0x5D, 0x63, 0x2B, 0xF2, 0x23, 0x98, 0x25, 0xBB],
    };
}
