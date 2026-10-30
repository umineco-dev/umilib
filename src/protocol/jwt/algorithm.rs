use crate::auth::cert::key::{HashAlgorithm, MLDSAParameterSet};

/// A JWS algorithm (`alg`, RFC 7518 §3, RFC 8812, RFC 9864, RFC 9964).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JWSAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    ES512,
    /// ECDSA over secp256k1 with SHA-256 (RFC 8812 §3.2).
    ES256K,
    /// EdDSA with the curve of the key, Ed25519 or Ed448 (RFC 8037 §3.1);
    /// deprecated for the fully specified [`JWSAlgorithm::Ed25519`] and
    /// [`JWSAlgorithm::Ed448`] (RFC 9864 §2.2).
    EdDSA,
    Ed25519,
    Ed448,
    MLDSA44,
    MLDSA65,
    MLDSA87,
    /// No signature: an Unsecured JWS (RFC 7518 §3.6), which only the
    /// functions of unsecured objects accept.
    None,
}

impl JWSAlgorithm {
    pub const ALL: [JWSAlgorithm; 20] = [
        JWSAlgorithm::HS256,
        JWSAlgorithm::HS384,
        JWSAlgorithm::HS512,
        JWSAlgorithm::RS256,
        JWSAlgorithm::RS384,
        JWSAlgorithm::RS512,
        JWSAlgorithm::PS256,
        JWSAlgorithm::PS384,
        JWSAlgorithm::PS512,
        JWSAlgorithm::ES256,
        JWSAlgorithm::ES384,
        JWSAlgorithm::ES512,
        JWSAlgorithm::ES256K,
        JWSAlgorithm::EdDSA,
        JWSAlgorithm::Ed25519,
        JWSAlgorithm::Ed448,
        JWSAlgorithm::MLDSA44,
        JWSAlgorithm::MLDSA65,
        JWSAlgorithm::MLDSA87,
        JWSAlgorithm::None,
    ];

    /// The name of the algorithm in the IANA registry, the value of `alg`.
    pub const fn name(self) -> &'static str {
        match self {
            JWSAlgorithm::HS256 => "HS256",
            JWSAlgorithm::HS384 => "HS384",
            JWSAlgorithm::HS512 => "HS512",
            JWSAlgorithm::RS256 => "RS256",
            JWSAlgorithm::RS384 => "RS384",
            JWSAlgorithm::RS512 => "RS512",
            JWSAlgorithm::PS256 => "PS256",
            JWSAlgorithm::PS384 => "PS384",
            JWSAlgorithm::PS512 => "PS512",
            JWSAlgorithm::ES256 => "ES256",
            JWSAlgorithm::ES384 => "ES384",
            JWSAlgorithm::ES512 => "ES512",
            JWSAlgorithm::ES256K => "ES256K",
            JWSAlgorithm::EdDSA => "EdDSA",
            JWSAlgorithm::Ed25519 => "Ed25519",
            JWSAlgorithm::Ed448 => "Ed448",
            JWSAlgorithm::MLDSA44 => "ML-DSA-44",
            JWSAlgorithm::MLDSA65 => "ML-DSA-65",
            JWSAlgorithm::MLDSA87 => "ML-DSA-87",
            JWSAlgorithm::None => "none",
        }
    }

    /// The algorithm named `name` (names are case-sensitive, RFC 7515 §4.1.1).
    pub fn from_name(name: &str) -> Option<JWSAlgorithm> {
        JWSAlgorithm::ALL.into_iter().find(|algorithm| algorithm.name() == name)
    }

    /// The hash function of the HMAC, RSA and ECDSA algorithms.
    pub const fn hash(self) -> Option<HashAlgorithm> {
        match self {
            JWSAlgorithm::HS256
            | JWSAlgorithm::RS256
            | JWSAlgorithm::PS256
            | JWSAlgorithm::ES256
            | JWSAlgorithm::ES256K => Some(HashAlgorithm::SHA256),
            JWSAlgorithm::HS384 | JWSAlgorithm::RS384 | JWSAlgorithm::PS384 | JWSAlgorithm::ES384 => {
                Some(HashAlgorithm::SHA384)
            }
            JWSAlgorithm::HS512 | JWSAlgorithm::RS512 | JWSAlgorithm::PS512 | JWSAlgorithm::ES512 => {
                Some(HashAlgorithm::SHA512)
            }
            _ => None,
        }
    }

    /// The parameter set of the ML-DSA algorithms.
    pub const fn mldsa(self) -> Option<MLDSAParameterSet> {
        match self {
            JWSAlgorithm::MLDSA44 => Some(MLDSAParameterSet::MLDSA44),
            JWSAlgorithm::MLDSA65 => Some(MLDSAParameterSet::MLDSA65),
            JWSAlgorithm::MLDSA87 => Some(MLDSAParameterSet::MLDSA87),
            _ => None,
        }
    }
}

/// A JWE key management algorithm (`alg`, RFC 7518 §4, and the RSA-OAEP
/// variants of the W3C Web Cryptography API). RSA1_5 is not implemented:
/// its padding oracle (RFC 8725 §2.1) makes it unsafe to decrypt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JWEAlgorithm {
    /// RSAES-OAEP with SHA-1 and MGF1 with SHA-1.
    RSAOAEP,
    RSAOAEP256,
    RSAOAEP384,
    RSAOAEP512,
    A128KW,
    A192KW,
    A256KW,
    /// The shared symmetric key is the content encryption key.
    Dir,
    /// The content encryption key is derived by ECDH-ES and Concat KDF.
    ECDHES,
    ECDHESA128KW,
    ECDHESA192KW,
    ECDHESA256KW,
    A128GCMKW,
    A192GCMKW,
    A256GCMKW,
    PBES2HS256A128KW,
    PBES2HS384A192KW,
    PBES2HS512A256KW,
}

impl JWEAlgorithm {
    pub const ALL: [JWEAlgorithm; 18] = [
        JWEAlgorithm::RSAOAEP,
        JWEAlgorithm::RSAOAEP256,
        JWEAlgorithm::RSAOAEP384,
        JWEAlgorithm::RSAOAEP512,
        JWEAlgorithm::A128KW,
        JWEAlgorithm::A192KW,
        JWEAlgorithm::A256KW,
        JWEAlgorithm::Dir,
        JWEAlgorithm::ECDHES,
        JWEAlgorithm::ECDHESA128KW,
        JWEAlgorithm::ECDHESA192KW,
        JWEAlgorithm::ECDHESA256KW,
        JWEAlgorithm::A128GCMKW,
        JWEAlgorithm::A192GCMKW,
        JWEAlgorithm::A256GCMKW,
        JWEAlgorithm::PBES2HS256A128KW,
        JWEAlgorithm::PBES2HS384A192KW,
        JWEAlgorithm::PBES2HS512A256KW,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            JWEAlgorithm::RSAOAEP => "RSA-OAEP",
            JWEAlgorithm::RSAOAEP256 => "RSA-OAEP-256",
            JWEAlgorithm::RSAOAEP384 => "RSA-OAEP-384",
            JWEAlgorithm::RSAOAEP512 => "RSA-OAEP-512",
            JWEAlgorithm::A128KW => "A128KW",
            JWEAlgorithm::A192KW => "A192KW",
            JWEAlgorithm::A256KW => "A256KW",
            JWEAlgorithm::Dir => "dir",
            JWEAlgorithm::ECDHES => "ECDH-ES",
            JWEAlgorithm::ECDHESA128KW => "ECDH-ES+A128KW",
            JWEAlgorithm::ECDHESA192KW => "ECDH-ES+A192KW",
            JWEAlgorithm::ECDHESA256KW => "ECDH-ES+A256KW",
            JWEAlgorithm::A128GCMKW => "A128GCMKW",
            JWEAlgorithm::A192GCMKW => "A192GCMKW",
            JWEAlgorithm::A256GCMKW => "A256GCMKW",
            JWEAlgorithm::PBES2HS256A128KW => "PBES2-HS256+A128KW",
            JWEAlgorithm::PBES2HS384A192KW => "PBES2-HS384+A192KW",
            JWEAlgorithm::PBES2HS512A256KW => "PBES2-HS512+A256KW",
        }
    }

    pub fn from_name(name: &str) -> Option<JWEAlgorithm> {
        JWEAlgorithm::ALL.into_iter().find(|algorithm| algorithm.name() == name)
    }

    /// The bytes of the AES key that wraps the content encryption key, for
    /// the algorithms that wrap with AES (KW, ECDH-ES+KW, GCMKW, PBES2).
    pub const fn wrapping_key_size(self) -> Option<usize> {
        match self {
            JWEAlgorithm::A128KW
            | JWEAlgorithm::ECDHESA128KW
            | JWEAlgorithm::A128GCMKW
            | JWEAlgorithm::PBES2HS256A128KW => Some(16),
            JWEAlgorithm::A192KW
            | JWEAlgorithm::ECDHESA192KW
            | JWEAlgorithm::A192GCMKW
            | JWEAlgorithm::PBES2HS384A192KW => Some(24),
            JWEAlgorithm::A256KW
            | JWEAlgorithm::ECDHESA256KW
            | JWEAlgorithm::A256GCMKW
            | JWEAlgorithm::PBES2HS512A256KW => Some(32),
            _ => None,
        }
    }

    /// Whether the algorithm determines the content encryption key itself
    /// (direct encryption and direct key agreement), so that a JWE using it
    /// has one recipient and an empty encrypted key (RFC 7516 §4.6, §5.1).
    pub const fn is_direct(self) -> bool {
        matches!(self, JWEAlgorithm::Dir | JWEAlgorithm::ECDHES)
    }
}

/// A JWE content encryption algorithm (`enc`, RFC 7518 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JWEEncryption {
    A128CBCHS256,
    A192CBCHS384,
    A256CBCHS512,
    A128GCM,
    A192GCM,
    A256GCM,
}

impl JWEEncryption {
    pub const ALL: [JWEEncryption; 6] = [
        JWEEncryption::A128CBCHS256,
        JWEEncryption::A192CBCHS384,
        JWEEncryption::A256CBCHS512,
        JWEEncryption::A128GCM,
        JWEEncryption::A192GCM,
        JWEEncryption::A256GCM,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            JWEEncryption::A128CBCHS256 => "A128CBC-HS256",
            JWEEncryption::A192CBCHS384 => "A192CBC-HS384",
            JWEEncryption::A256CBCHS512 => "A256CBC-HS512",
            JWEEncryption::A128GCM => "A128GCM",
            JWEEncryption::A192GCM => "A192GCM",
            JWEEncryption::A256GCM => "A256GCM",
        }
    }

    pub fn from_name(name: &str) -> Option<JWEEncryption> {
        JWEEncryption::ALL.into_iter().find(|encryption| encryption.name() == name)
    }

    /// The bytes of the content encryption key: for AES-CBC with HMAC the
    /// MAC key and the encryption key together (RFC 7518 §5.2.2.1).
    pub const fn key_size(self) -> usize {
        match self {
            JWEEncryption::A128CBCHS256 => 32,
            JWEEncryption::A192CBCHS384 => 48,
            JWEEncryption::A256CBCHS512 => 64,
            JWEEncryption::A128GCM => 16,
            JWEEncryption::A192GCM => 24,
            JWEEncryption::A256GCM => 32,
        }
    }

    /// The bytes of the initialization vector: 128 bits for CBC, 96 for GCM.
    pub const fn iv_size(self) -> usize {
        match self {
            JWEEncryption::A128CBCHS256 | JWEEncryption::A192CBCHS384 | JWEEncryption::A256CBCHS512 => 16,
            _ => 12,
        }
    }

    /// The bytes of the authentication tag: half the MAC key for AES-CBC
    /// with HMAC (RFC 7518 §5.2.3 to §5.2.5), 128 bits for GCM.
    pub const fn tag_size(self) -> usize {
        match self {
            JWEEncryption::A128CBCHS256 => 16,
            JWEEncryption::A192CBCHS384 => 24,
            JWEEncryption::A256CBCHS512 => 32,
            _ => 16,
        }
    }
}
