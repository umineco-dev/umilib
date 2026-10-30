use super::TLSVersion;

/// A signature scheme: `SignatureScheme` (RFC 9846 §4.3.3 and the IANA
/// "TLS SignatureScheme" registry). In TLS 1.2 the same two bytes are the
/// `SignatureAndHashAlgorithm` of RFC 5246 §7.4.1.4.1. Unknown values are
/// kept as they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TLSSignatureScheme(pub u16);

impl TLSSignatureScheme {
    pub const RSA_PKCS1_SHA256: TLSSignatureScheme = TLSSignatureScheme(0x0401);
    pub const RSA_PKCS1_SHA384: TLSSignatureScheme = TLSSignatureScheme(0x0501);
    pub const RSA_PKCS1_SHA512: TLSSignatureScheme = TLSSignatureScheme(0x0601);
    pub const ECDSA_SECP256R1_SHA256: TLSSignatureScheme = TLSSignatureScheme(0x0403);
    pub const ECDSA_SECP384R1_SHA384: TLSSignatureScheme = TLSSignatureScheme(0x0503);
    pub const ECDSA_SECP521R1_SHA512: TLSSignatureScheme = TLSSignatureScheme(0x0603);
    pub const RSA_PSS_RSAE_SHA256: TLSSignatureScheme = TLSSignatureScheme(0x0804);
    pub const RSA_PSS_RSAE_SHA384: TLSSignatureScheme = TLSSignatureScheme(0x0805);
    pub const RSA_PSS_RSAE_SHA512: TLSSignatureScheme = TLSSignatureScheme(0x0806);
    pub const ED25519: TLSSignatureScheme = TLSSignatureScheme(0x0807);
    pub const ED448: TLSSignatureScheme = TLSSignatureScheme(0x0808);
    pub const RSA_PSS_PSS_SHA256: TLSSignatureScheme = TLSSignatureScheme(0x0809);
    pub const RSA_PSS_PSS_SHA384: TLSSignatureScheme = TLSSignatureScheme(0x080A);
    pub const RSA_PSS_PSS_SHA512: TLSSignatureScheme = TLSSignatureScheme(0x080B);
    /// Legacy: only in certificates, never in handshake signatures of TLS 1.3.
    pub const RSA_PKCS1_SHA1: TLSSignatureScheme = TLSSignatureScheme(0x0201);
    pub const ECDSA_SHA1: TLSSignatureScheme = TLSSignatureScheme(0x0203);

    /// Whether the scheme may sign a handshake (CertificateVerify, or
    /// ServerKeyExchange in TLS 1.2) of `version`. TLS 1.3 forbids
    /// RSASSA-PKCS1-v1_5 there (RFC 9846 §4.3.3). SHA-1 is refused in both
    /// versions (RFC 9846 §4.3.3, RFC 9155).
    pub fn signs_handshakes_of(self, version: TLSVersion) -> bool {
        match self {
            TLSSignatureScheme::RSA_PKCS1_SHA1 | TLSSignatureScheme::ECDSA_SHA1 => false,
            TLSSignatureScheme::RSA_PKCS1_SHA256
            | TLSSignatureScheme::RSA_PKCS1_SHA384
            | TLSSignatureScheme::RSA_PKCS1_SHA512 => version == TLSVersion::TLS1_2,
            _ => true,
        }
    }

    /// Whether the value is a GREASE value (RFC 8701 §2).
    pub fn is_grease(self) -> bool {
        TLSVersion::grease(self.0)
    }
}
