use super::TLSVersion;

/// The AEAD algorithm of a cipher suite (RFC 5116, RFC 8439, RFC 6655).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLSAEADAlgorithm {
    AES128GCM,
    AES256GCM,
    ChaCha20Poly1305,
    AES128CCM,
    /// AES-128-CCM with a tag of 8 bytes (RFC 6655).
    AES128CCM8,
}

impl TLSAEADAlgorithm {
    pub fn key_length(self) -> usize {
        match self {
            TLSAEADAlgorithm::AES256GCM | TLSAEADAlgorithm::ChaCha20Poly1305 => 32,
            _ => 16,
        }
    }

    /// The length of the nonce: 12 bytes for every AEAD of TLS (RFC 9846 §5.3).
    pub fn nonce_length(self) -> usize {
        12
    }

    pub fn tag_length(self) -> usize {
        match self {
            TLSAEADAlgorithm::AES128CCM8 => 8,
            _ => 16,
        }
    }
}

/// The hash function of a cipher suite: of HKDF and the transcript in TLS
/// 1.3, of the PRF in TLS 1.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLSHashAlgorithm {
    SHA256,
    SHA384,
}

impl TLSHashAlgorithm {
    pub fn length(self) -> usize {
        match self {
            TLSHashAlgorithm::SHA256 => 32,
            TLSHashAlgorithm::SHA384 => 48,
        }
    }
}

/// How the server authenticates in a TLS 1.2 cipher suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLSAuthentication {
    RSA,
    ECDSA,
}

/// A cipher suite (RFC 9846 §4.2.2, Appendix B.4, and the IANA "TLS
/// Cipher Suites" registry). The suites of TLS 1.3 name only the AEAD and
/// the hash; those of TLS 1.2 name the key exchange and the authentication
/// as well, and only the ECDHE ones with an AEAD are implemented. Unknown
/// values are kept as they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TLSCipherSuite(pub u16);

impl TLSCipherSuite {
    pub const TLS_AES_128_GCM_SHA256: TLSCipherSuite = TLSCipherSuite(0x1301);
    pub const TLS_AES_256_GCM_SHA384: TLSCipherSuite = TLSCipherSuite(0x1302);
    pub const TLS_CHACHA20_POLY1305_SHA256: TLSCipherSuite = TLSCipherSuite(0x1303);
    pub const TLS_AES_128_CCM_SHA256: TLSCipherSuite = TLSCipherSuite(0x1304);
    pub const TLS_AES_128_CCM_8_SHA256: TLSCipherSuite = TLSCipherSuite(0x1305);
    /// TLS 1.2 (RFC 5289).
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: TLSCipherSuite = TLSCipherSuite(0xC02B);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: TLSCipherSuite = TLSCipherSuite(0xC02C);
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: TLSCipherSuite = TLSCipherSuite(0xC02F);
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: TLSCipherSuite = TLSCipherSuite(0xC030);
    /// TLS 1.2 (RFC 7905).
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: TLSCipherSuite = TLSCipherSuite(0xCCA8);
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: TLSCipherSuite = TLSCipherSuite(0xCCA9);
    /// The signaling value of a client that falls back to an older version (RFC 7507).
    pub const TLS_FALLBACK_SCSV: TLSCipherSuite = TLSCipherSuite(0x5600);
    /// The signaling value of secure renegotiation (RFC 5746 §3.3).
    pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: TLSCipherSuite = TLSCipherSuite(0x00FF);

    /// The suites this crate implements, in their default order of preference.
    pub const ALL: [TLSCipherSuite; 11] = [
        TLSCipherSuite::TLS_AES_128_GCM_SHA256,
        TLSCipherSuite::TLS_AES_256_GCM_SHA384,
        TLSCipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        TLSCipherSuite::TLS_AES_128_CCM_SHA256,
        TLSCipherSuite::TLS_AES_128_CCM_8_SHA256,
        // RFC 9325 §4.2.1: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 first among TLS 1.2's.
        TLSCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLSCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLSCipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    /// The version the suite is defined for, if this crate knows it.
    pub fn version(self) -> Option<TLSVersion> {
        match self.0 {
            0x1301..=0x1305 => Some(TLSVersion::TLS1_3),
            0xC02B | 0xC02C | 0xC02F | 0xC030 | 0xCCA8 | 0xCCA9 => Some(TLSVersion::TLS1_2),
            _ => None,
        }
    }

    pub fn aead(self) -> Option<TLSAEADAlgorithm> {
        Some(match self {
            TLSCipherSuite::TLS_AES_128_GCM_SHA256
            | TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | TLSCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => TLSAEADAlgorithm::AES128GCM,
            TLSCipherSuite::TLS_AES_256_GCM_SHA384
            | TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | TLSCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => TLSAEADAlgorithm::AES256GCM,
            TLSCipherSuite::TLS_CHACHA20_POLY1305_SHA256
            | TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | TLSCipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => TLSAEADAlgorithm::ChaCha20Poly1305,
            TLSCipherSuite::TLS_AES_128_CCM_SHA256 => TLSAEADAlgorithm::AES128CCM,
            TLSCipherSuite::TLS_AES_128_CCM_8_SHA256 => TLSAEADAlgorithm::AES128CCM8,
            _ => return None,
        })
    }

    pub fn hash(self) -> Option<TLSHashAlgorithm> {
        Some(match self {
            TLSCipherSuite::TLS_AES_256_GCM_SHA384
            | TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | TLSCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => TLSHashAlgorithm::SHA384,
            suite if suite.version().is_some() => TLSHashAlgorithm::SHA256,
            _ => return None,
        })
    }

    /// How the server authenticates, for a TLS 1.2 suite.
    pub fn authentication(self) -> Option<TLSAuthentication> {
        match self.0 {
            0xC02B | 0xC02C | 0xCCA9 => Some(TLSAuthentication::ECDSA),
            0xC02F | 0xC030 | 0xCCA8 => Some(TLSAuthentication::RSA),
            _ => None,
        }
    }

    /// Whether the value is a GREASE value (RFC 8701 §2).
    pub fn is_grease(self) -> bool {
        TLSVersion::grease(self.0)
    }
}
