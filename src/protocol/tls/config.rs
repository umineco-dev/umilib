use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::{
    TLSAEAD, TLSAntiReplay, TLSCertificateVerifier, TLSCertifiedKey, TLSCipherSuite, TLSECHConfig, TLSECHKey, TLSError,
    TLSKeyShareSecret, TLSNamedGroup, TLSPSKMode, TLSSessionStore, TLSSignatureScheme, TLSTicketer, TLSVersion,
};

/// What both ends configure: the versions, algorithms and limits they
/// accept, in their order of preference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TLSConfig {
    /// The versions offered or accepted: TLS 1.3 and TLS 1.2 by default,
    /// those compiled in.
    pub versions: Vec<TLSVersion>,
    pub cipher_suites: Vec<TLSCipherSuite>,
    /// The groups of key exchange (`supported_groups`).
    pub groups: Vec<TLSNamedGroup>,
    /// The signature schemes accepted from the peer and used to sign
    /// (`signature_algorithms`).
    pub signature_schemes: Vec<TLSSignatureScheme>,
    /// The application protocols (ALPN, RFC 7301), most preferred first;
    /// none if empty.
    pub protocols: Vec<Vec<u8>>,
    /// The largest handshake message accepted: certificate chains are the
    /// largest. 64 KiB by default.
    pub maximum_handshake_message: usize,
    /// The largest plaintext of a record this end accepts, advertised with
    /// `record_size_limit` (RFC 8449) if it is below 2^14.
    pub record_size_limit: u16,
    /// The largest application data buffered for reading before records
    /// are refused: the application must read.
    pub maximum_buffered_data: usize,
    /// How many KeyUpdate messages the peer may send in a row without
    /// application data between them (RFC 9846 §4.7.3 asks for a limit).
    pub maximum_key_updates: u32,
    /// Whether TLS 1.2 requires the extended main secret (RFC 7627): a
    /// peer without it fails with `handshake_failure`. On by default, as
    /// RFC 9325 §3.5 and the triple handshake attack call for.
    pub require_extended_main_secret: bool,
    /// How many records that change nothing (warning alerts, ChangeCipherSpecs,
    /// HelloRequests) are dropped in a row, without application data
    /// between, before the connection fails with `unexpected_message`: 32
    /// by default.
    pub maximum_ignored_records: u32,
    /// The key exchange modes of resumption, in order of preference: with
    /// (EC)DHE by default, for forward secrecy (RFC 9846 §4.3.9).
    pub psk_modes: Vec<TLSPSKMode>,
}

impl Default for TLSConfig {
    fn default() -> TLSConfig {
        let versions =
            [TLSVersion::TLS1_3, TLSVersion::TLS1_2].into_iter().filter(|version| version.is_supported()).collect();
        let cipher_suites = TLSCipherSuite::ALL
            .into_iter()
            .filter(|suite| suite.version().is_some_and(TLSVersion::is_supported))
            .filter(|suite| suite.aead().is_some_and(TLSAEAD::supports))
            // CCM_8 has a short tag; it is for constrained devices and only if asked for (RFC 9846 §B.4).
            .filter(|suite| *suite != TLSCipherSuite::TLS_AES_128_CCM_8_SHA256)
            .collect();
        let groups =
            TLSConfig::DEFAULT_GROUPS.into_iter().filter(|group| TLSKeyShareSecret::supports(*group)).collect();
        TLSConfig {
            versions,
            cipher_suites,
            groups,
            signature_schemes: TLSConfig::DEFAULT_SIGNATURE_SCHEMES.to_vec(),
            protocols: Vec::new(),
            maximum_handshake_message: 1 << 16,
            record_size_limit: 1 << 14,
            maximum_buffered_data: 1 << 20,
            maximum_key_updates: 32,
            require_extended_main_secret: true,
            maximum_ignored_records: 32,
            psk_modes: vec![TLSPSKMode::PSK_DHE_KE],
        }
    }
}

impl TLSConfig {
    /// The groups by default, those compiled in: the hybrid of RFC 10024
    /// that is recommended, then X25519 and the NIST curves (RFC 9846 §9.1).
    pub const DEFAULT_GROUPS: [TLSNamedGroup; 6] = [
        TLSNamedGroup::X25519_MLKEM768,
        TLSNamedGroup::X25519,
        TLSNamedGroup::SECP256R1,
        TLSNamedGroup::SECP384R1,
        TLSNamedGroup::SECP521R1,
        TLSNamedGroup::X448,
    ];
    /// The signature schemes by default: those of RFC 9846 §9.1 first.
    pub const DEFAULT_SIGNATURE_SCHEMES: [TLSSignatureScheme; 13] = [
        TLSSignatureScheme::ECDSA_SECP256R1_SHA256,
        TLSSignatureScheme::RSA_PSS_RSAE_SHA256,
        TLSSignatureScheme::RSA_PKCS1_SHA256,
        TLSSignatureScheme::ED25519,
        TLSSignatureScheme::ECDSA_SECP384R1_SHA384,
        TLSSignatureScheme::RSA_PSS_RSAE_SHA384,
        TLSSignatureScheme::RSA_PKCS1_SHA384,
        TLSSignatureScheme::ECDSA_SECP521R1_SHA512,
        TLSSignatureScheme::RSA_PSS_RSAE_SHA512,
        TLSSignatureScheme::RSA_PKCS1_SHA512,
        TLSSignatureScheme::ED448,
        TLSSignatureScheme::RSA_PSS_PSS_SHA256,
        TLSSignatureScheme::RSA_PSS_PSS_SHA384,
    ];

    /// Fails with [`TLSError::Config`] if the configuration cannot work: no
    /// version this crate supports, no cipher suite, group or signature
    /// scheme it implements, an ALPN name of 0 or more than 255 bytes, a
    /// record size limit below 64 or above 2^14, or a limit of handshake
    /// messages below 2^14.
    pub fn check(&self) -> Result<(), TLSError> {
        let working = self.versions.iter().any(|version| version.is_supported())
            && self.cipher_suites.iter().any(|suite| suite.aead().is_some_and(TLSAEAD::supports))
            && self.groups.iter().any(|group| TLSKeyShareSecret::supports(*group))
            && self.signature_schemes.iter().any(|scheme| scheme.algorithm().is_some())
            && self.protocols.iter().all(|protocol| (1..=255).contains(&protocol.len()))
            && (64..=1 << 14).contains(&self.record_size_limit)
            && self.maximum_handshake_message >= 1 << 14;
        if working { Ok(()) } else { Err(TLSError::Config) }
    }
}

/// How a client offers TLS 1.3's middlebox compatibility mode (RFC 9846
/// Appendix E.4): a session ID and ChangeCipherSpec records that look like
/// TLS 1.2 resumption to middleboxes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLSMiddleboxCompatibility {
    Off,
    On,
}

/// The configuration of clients.
#[derive(Clone)]
pub struct TLSClientConfig {
    pub config: TLSConfig,
    /// The groups the first ClientHello sends key shares for; the server
    /// asks for another with a HelloRetryRequest. By default the first two
    /// of `config.groups` when the first is a hybrid (a classical share
    /// alongside), otherwise the first.
    pub key_share_groups: Vec<TLSNamedGroup>,
    /// What checks the server's certificate chain.
    pub verifier: Arc<dyn TLSCertificateVerifier>,
    /// The certificate sent when the server asks for one.
    pub certificate: Option<Arc<TLSCertifiedKey>>,
    pub middlebox_compatibility: TLSMiddleboxCompatibility,
    /// Whether to send `server_name` (RFC 6066) when connecting to a name.
    pub send_server_name: bool,
    /// Whether to ask the server to staple an OCSP response to its
    /// certificate (`status_request`, RFC 6066 §8), which the verifier is
    /// given. Off by default.
    pub request_certificate_status: bool,
    /// Whether to offer post-handshake authentication (`post_handshake_auth`,
    /// RFC 9846 §4.6.2): the server may then ask for `certificate` at any
    /// time. Off by default.
    pub post_handshake_authentication: bool,
    /// Where the tickets of servers are kept to resume their sessions (RFC
    /// 9846 §4.6.1); no resumption without one.
    pub sessions: Option<Arc<dyn TLSSessionStore>>,
    /// Whether to send early data (0-RTT) when a ticket allows it. Off by
    /// default: early data can be replayed (RFC 9846 §8).
    pub early_data: bool,
    /// The server's ECH configurations (RFC 9849 §4), from its DNS records
    /// or a retry: the first this crate can use encrypts the ClientHello,
    /// with TLS 1.3 offered and `crypto-hpke` compiled in.
    pub ech_configs: Vec<TLSECHConfig>,
    /// Whether to send a GREASE `encrypted_client_hello` when no
    /// configuration is used (RFC 9849 §6.2). Off by default.
    pub ech_grease: bool,
}

impl TLSClientConfig {
    /// The defaults with `verifier`.
    pub fn new(verifier: Arc<dyn TLSCertificateVerifier>) -> TLSClientConfig {
        let config = TLSConfig::default();
        let key_share_groups = TLSClientConfig::default_key_shares(&config.groups);
        TLSClientConfig {
            config,
            key_share_groups,
            verifier,
            certificate: None,
            middlebox_compatibility: TLSMiddleboxCompatibility::On,
            send_server_name: true,
            request_certificate_status: false,
            post_handshake_authentication: false,
            sessions: None,
            early_data: false,
            ech_configs: Vec::new(),
            ech_grease: false,
        }
    }

    pub fn default_key_shares(groups: &[TLSNamedGroup]) -> Vec<TLSNamedGroup> {
        match groups {
            [first, second, ..] if first.kind() == Some(super::TLSGroupKind::Hybrid) => vec![*first, *second],
            [first, ..] => vec![*first],
            [] => Vec::new(),
        }
    }

    /// [`TLSConfig::check`], and every key share group must be one of the groups.
    pub fn check(&self) -> Result<(), TLSError> {
        self.config.check()?;
        let shares = self.key_share_groups.iter().all(|group| self.config.groups.contains(group));
        if shares { Ok(()) } else { Err(TLSError::Config) }
    }
}

/// Whether a server asks clients for a certificate (RFC 9846 §4.4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLSClientAuthentication {
    Off,
    /// Asked for; the handshake goes on without one.
    Optional,
    /// Asked for; the handshake fails without one (`certificate_required`).
    Required,
}

/// The configuration of servers.
#[derive(Clone)]
pub struct TLSServerConfig {
    pub config: TLSConfig,
    /// The certificates to present, chosen by the name the client asks for
    /// (`server_name`) and the signature schemes it accepts; the first that
    /// fits, or the first if none names the server.
    pub certificates: Vec<Arc<TLSCertifiedKey>>,
    pub client_authentication: TLSClientAuthentication,
    /// What checks the client's certificate chain when one is asked for.
    pub client_verifier: Option<Arc<dyn TLSCertificateVerifier>>,
    /// Whether the server chooses the cipher suite by its own preference
    /// rather than the client's.
    pub prefer_own_cipher_suites: bool,
    /// What makes and opens session tickets (RFC 9846 §4.6.1); no
    /// resumption without one.
    pub tickets: Option<Arc<dyn TLSTicketer>>,
    /// How many tickets are sent after each handshake: 2 by default, so a
    /// client can open two connections.
    pub ticket_count: usize,
    /// The lifetime of tickets in seconds, at most seven days: two hours by default.
    pub ticket_lifetime: u32,
    /// The most early data (0-RTT) accepted with a ticket; 0, the default,
    /// accepts none. Accepting it needs `anti_replay` (RFC 9846 §8).
    pub maximum_early_data: u32,
    /// What refuses replayed early data.
    pub anti_replay: Option<Arc<dyn TLSAntiReplay>>,
    /// How far, in seconds, a ClientHello with early data may arrive from
    /// when its ticket's age says it should (RFC 9846 §8.3): 10 by default.
    pub freshness_window: i64,
    /// The keys of the server's ECH configurations (RFC 9849 §7.1), with
    /// which it decrypts ClientHelloInners; those marked `retry` are sent
    /// to clients whose ECH was rejected.
    pub ech_keys: Vec<TLSECHKey>,
}

impl TLSServerConfig {
    /// Seven days (RFC 9846 §4.6.1).
    pub const MAXIMUM_TICKET_LIFETIME: u32 = 604_800;

    pub fn new(certificates: Vec<Arc<TLSCertifiedKey>>) -> TLSServerConfig {
        TLSServerConfig {
            config: TLSConfig::default(),
            certificates,
            client_authentication: TLSClientAuthentication::Off,
            client_verifier: None,
            prefer_own_cipher_suites: true,
            tickets: None,
            ticket_count: 2,
            ticket_lifetime: 7200,
            maximum_early_data: 0,
            anti_replay: None,
            freshness_window: 10,
            ech_keys: Vec::new(),
        }
    }

    /// [`TLSConfig::check`], at least one certificate and none with an empty
    /// chain, a verifier when clients are asked for certificates, a ticket
    /// lifetime of at most seven days, tickets and anti-replay when early
    /// data is accepted, and an ECH key marked `retry` when there are ECH
    /// keys (RFC 9849 §7.1: a rejection must carry retry configurations).
    pub fn check(&self) -> Result<(), TLSError> {
        self.config.check()?;
        let working = !self.certificates.is_empty()
            && self.certificates.iter().all(|key| !key.chain.is_empty())
            && (self.ech_keys.is_empty() || self.ech_keys.iter().any(|key| key.retry))
            && (self.client_authentication == TLSClientAuthentication::Off || self.client_verifier.is_some())
            && self.ticket_lifetime <= TLSServerConfig::MAXIMUM_TICKET_LIFETIME
            && (self.maximum_early_data == 0 || (self.tickets.is_some() && self.anti_replay.is_some()));
        if working { Ok(()) } else { Err(TLSError::Config) }
    }
}
