use super::TLSVersion;

/// A group of key exchange: `NamedGroup` (RFC 9846 §4.3.7, RFC 7919,
/// RFC 10024, and the IANA "TLS Supported Groups" registry). Unknown values
/// are kept as they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TLSNamedGroup(pub u16);

impl TLSNamedGroup {
    pub const SECP256R1: TLSNamedGroup = TLSNamedGroup(0x0017);
    pub const SECP384R1: TLSNamedGroup = TLSNamedGroup(0x0018);
    pub const SECP521R1: TLSNamedGroup = TLSNamedGroup(0x0019);
    pub const X25519: TLSNamedGroup = TLSNamedGroup(0x001D);
    pub const X448: TLSNamedGroup = TLSNamedGroup(0x001E);
    pub const FFDHE2048: TLSNamedGroup = TLSNamedGroup(0x0100);
    pub const FFDHE3072: TLSNamedGroup = TLSNamedGroup(0x0101);
    pub const FFDHE4096: TLSNamedGroup = TLSNamedGroup(0x0102);
    pub const FFDHE6144: TLSNamedGroup = TLSNamedGroup(0x0103);
    pub const FFDHE8192: TLSNamedGroup = TLSNamedGroup(0x0104);
    /// The post-quantum/traditional hybrids of RFC 10024 §7.
    pub const SECP256R1_MLKEM768: TLSNamedGroup = TLSNamedGroup(0x11EB);
    pub const X25519_MLKEM768: TLSNamedGroup = TLSNamedGroup(0x11EC);
    pub const SECP384R1_MLKEM1024: TLSNamedGroup = TLSNamedGroup(0x11ED);

    /// The kind of key exchange of the group, if this crate knows it.
    pub fn kind(self) -> Option<TLSGroupKind> {
        match self.0 {
            0x0017..=0x0019 | 0x001D | 0x001E => Some(TLSGroupKind::ECDHE),
            0x0100..=0x0104 => Some(TLSGroupKind::FFDHE),
            0x11EB..=0x11ED => Some(TLSGroupKind::Hybrid),
            _ => None,
        }
    }

    /// Whether the group can be used with `version`: the hybrids are KEMs,
    /// which TLS 1.2's ServerKeyExchange cannot carry (RFC 10024 §1).
    pub fn usable_with(self, version: TLSVersion) -> bool {
        match self.kind() {
            Some(TLSGroupKind::Hybrid) => version == TLSVersion::TLS1_3,
            Some(TLSGroupKind::ECDHE) => true,
            Some(TLSGroupKind::FFDHE) => version == TLSVersion::TLS1_3,
            None => false,
        }
    }

    /// Whether the value is a GREASE value (RFC 8701 §2).
    pub fn is_grease(self) -> bool {
        TLSVersion::grease(self.0)
    }
}

/// How a group exchanges keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLSGroupKind {
    /// Elliptic curve Diffie-Hellman (RFC 9846 §4.3.8.2).
    ECDHE,
    /// Finite field Diffie-Hellman (RFC 9846 §4.3.8.1, RFC 7919).
    FFDHE,
    /// A KEM that combines ML-KEM with ECDHE (RFC 10024).
    Hybrid,
}
