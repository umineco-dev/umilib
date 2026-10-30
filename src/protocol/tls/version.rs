/// A protocol version: `ProtocolVersion` (RFC 9846 §4.2.2). Only TLS 1.2
/// and TLS 1.3 are negotiated; earlier versions are refused (RFC 8996).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct TLSVersion(pub u16);

impl TLSVersion {
    /// TLS 1.0 and 1.1: deprecated (RFC 8996); never negotiated.
    pub const TLS1_0: TLSVersion = TLSVersion(0x0301);
    pub const TLS1_1: TLSVersion = TLSVersion(0x0302);
    pub const TLS1_2: TLSVersion = TLSVersion(0x0303);
    pub const TLS1_3: TLSVersion = TLSVersion(0x0304);

    /// Whether the version is one this crate can negotiate when its module is compiled.
    pub fn is_supported(self) -> bool {
        (self == TLSVersion::TLS1_3 && cfg!(umilib_feature = "protocol-tls-v1_3"))
            || (self == TLSVersion::TLS1_2 && cfg!(umilib_feature = "protocol-tls-v1_2"))
    }

    /// Whether the value is a GREASE value: 0x?A?A with both bytes equal (RFC 8701 §2).
    pub fn is_grease(self) -> bool {
        TLSVersion::grease(self.0)
    }

    /// Whether `value` is one of the GREASE values of RFC 8701 §2, shared by
    /// versions, cipher suites, groups, signature schemes and extensions.
    pub fn grease(value: u16) -> bool {
        let [high, low] = value.to_be_bytes();
        high == low && high & 0x0F == 0x0A
    }
}
