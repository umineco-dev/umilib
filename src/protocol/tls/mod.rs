//! Transport Layer Security: TLS 1.3 (RFC 9846) and TLS 1.2 (RFC 5246,
//! with only the ECDHE key exchanges and AEAD ciphers that RFC 9325
//! recommends), without I/O.
//!
//! This root module holds what both versions share: the record layer
//! ([`TLSRecord`]), alerts ([`TLSAlert`]), the registries of versions,
//! cipher suites, groups, signature schemes and extensions, the vectors of
//! the presentation language ([`TLSVector`]), the handshake framing
//! ([`TLSHandshake`], [`TLSHandshakeReassembler`]), the extensions
//! ([`TLSExtension`] and the types of their content), and the hellos
//! ([`TLSClientHello`], [`TLSServerHello`]). Each version is a module of
//! its own: `v1_3` (feature `protocol-tls-v1_3`) and `v1_2`
//! (`protocol-tls-v1_2`).

mod alert;
mod certificate;
mod client;
mod codec;
mod config;
mod connection;
mod ech;
mod error;
mod extension;
mod group;
mod handshake;
mod hello;
mod key_exchange;
mod layer;
mod message;
mod protection;
mod quic;
mod record;
mod resumption;
mod rule;
mod server;
mod signature;
mod suite;
mod transcript;
mod version;

#[cfg(umilib_feature = "protocol-tls-v1_2")]
pub mod v1_2;
#[cfg(umilib_feature = "protocol-tls-v1_3")]
pub mod v1_3;

pub use alert::{TLSAlert, TLSAlertDescription, TLSAlertLevel};
pub use certificate::{TLSCertificateVerifier, TLSCertifiedKey, TLSPathVerifier};
pub use client::TLSClientStart;
pub use codec::TLSVector;
pub use config::{TLSClientAuthentication, TLSClientConfig, TLSConfig, TLSMiddleboxCompatibility, TLSServerConfig};
pub use connection::{
    TLSConnection, TLSConnectionState, TLSContext, TLSEarlyData, TLSEvent, TLSHandshakeProtocol, TLSRole, TLSSession,
};
#[cfg(umilib_feature = "crypto-hpke")]
pub use ech::TLSECHCipher;
pub use ech::{
    TLSECH, TLSECHAcceptance, TLSECHCipherSuite, TLSECHClientHello, TLSECHConfig, TLSECHConfigExtension, TLSECHKey,
    TLSECHOffer, TLSECHOpener, TLSECHSealer, TLSECHStatus,
};
pub use error::TLSError;
pub use extension::{
    TLSCertificateAuthorities, TLSCertificateStatus, TLSEarlyDataIndication, TLSExtension, TLSExtensionContext,
    TLSExtensionType, TLSKeyShare, TLSKeyShareEntry, TLSOpaqueExtension, TLSPSKIdentity, TLSPSKMode, TLSPointFormats,
    TLSPreSharedKey, TLSProtocolNames, TLSRecordSizeLimit, TLSServerNames, TLSSignatureSchemes, TLSSupportedGroups,
    TLSSupportedVersions,
};
pub use group::{TLSGroupKind, TLSNamedGroup};
pub use handshake::{TLSHandshake, TLSHandshakeReassembler, TLSHandshakeType};
pub use hello::{TLSClientHello, TLSServerHello};
#[cfg(umilib_feature = "crypto-dh")]
pub use key_exchange::TLSFiniteFieldSecret;
#[cfg(umilib_feature = "crypto-hybrid")]
pub use key_exchange::TLSHybridSecret;
pub use key_exchange::TLSKeyShareSecret;
pub use layer::{TLSRecordLayer, TLSRecordProtector};
pub use message::{TLSCertificateVerify, TLSFinished};
pub use protection::TLSAEAD;
pub use quic::{TLSDirection, TLSEncryptionLevel, TLSQUIC, TLSTrafficSecret};
pub use record::{TLSContentType, TLSRecord, TLSRecordHeader};
pub use resumption::{
    TLSAntiReplay, TLSReplayCache, TLSSessionCache, TLSSessionState, TLSSessionStore, TLSSessionTicket, TLSTicketKey,
    TLSTicketKeys, TLSTicketer,
};
pub use rule::{TLSNamePattern, TLSRoute, TLSRule};
pub use server::TLSServerStart;
pub use signature::TLSSignatureScheme;
pub use suite::{TLSAEADAlgorithm, TLSAuthentication, TLSCipherSuite, TLSHashAlgorithm};
pub use transcript::{TLSTranscript, TLSTranscriptState};
pub use version::TLSVersion;
