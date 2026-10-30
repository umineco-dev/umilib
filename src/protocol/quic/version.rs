use super::QUICPacketType;

/// A QUIC version (RFC 8999 §5.1, RFC 9000 §15): the 32 bits of the
/// Version field of long headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct QUICVersion(pub u32);

impl QUICVersion {
    /// The Version field of Version Negotiation packets (RFC 8999 §6).
    pub const NEGOTIATION: QUICVersion = QUICVersion(0);
    /// QUIC version 1 (RFC 9000).
    pub const V1: QUICVersion = QUICVersion(0x0000_0001);
    /// QUIC version 2 (RFC 9369 §3.1).
    pub const V2: QUICVersion = QUICVersion(0x6B33_43CF);

    /// Whether this version is reserved to exercise version negotiation:
    /// one of the pattern 0x?a?a?a?a (RFC 9000 §15), which is never chosen.
    pub const fn is_reserved(self) -> bool {
        self.0 & 0x0F0F_0F0F == 0x0A0A_0A0A
    }

    /// The rules of this version, when this crate implements it.
    pub fn profile(self) -> Option<&'static QUICVersionProfile> {
        QUICVersionProfile::ALL.iter().copied().find(|profile| profile.version == self)
    }

    /// Whether this crate implements this version.
    pub fn is_supported(self) -> bool {
        self.profile().is_some()
    }
}

/// What differs between the versions of QUIC that share the transport of
/// RFC 9000: the Version field, the long header packet types, the salt of
/// the Initial secrets, the labels of key derivation, and the key of Retry
/// integrity (RFC 9369 §3). The `v1` and `v2` modules define one each; a
/// version that differs in more than these needs code of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICVersionProfile {
    pub version: QUICVersion,
    /// The packet type of each value of the two Long Packet Type bits.
    pub long_types: [QUICPacketType; 4],
    /// The salt of HKDF-Extract for the Initial secrets (RFC 9001 §5.2).
    pub initial_salt: [u8; 20],
    /// The labels of HKDF-Expand-Label for the packet protection key, IV,
    /// header protection key and key update (RFC 9001 §5.1, §6.1).
    pub key_label: &'static [u8],
    pub iv_label: &'static [u8],
    pub hp_label: &'static [u8],
    pub ku_label: &'static [u8],
    /// The AEAD_AES_128_GCM key and nonce of the Retry Integrity Tag (RFC 9001 §5.8).
    pub retry_key: [u8; 16],
    pub retry_nonce: [u8; 12],
}

impl QUICVersionProfile {
    /// The versions this crate implements, those of the features compiled in.
    pub const ALL: &'static [&'static QUICVersionProfile] = &[
        #[cfg(umilib_feature = "protocol-quic-v1")]
        &super::v1::QUICv1::PROFILE,
        #[cfg(umilib_feature = "protocol-quic-v2")]
        &super::v2::QUICv2::PROFILE,
    ];

    /// The packet type of the Long Packet Type bits of `first`, the first byte.
    pub const fn long_type(&self, first: u8) -> QUICPacketType {
        self.long_types[((first >> 4) & 0x03) as usize]
    }

    /// The Long Packet Type bits of `packet_type`, or `None` for a type that
    /// has no long header (1-RTT).
    pub fn long_type_bits(&self, packet_type: QUICPacketType) -> Option<u8> {
        self.long_types.iter().position(|kind| *kind == packet_type).map(|bits| bits as u8)
    }
}
