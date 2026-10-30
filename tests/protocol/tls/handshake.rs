//! TLS 1.3 handshakes between this crate's client and server, with the
//! certificates OpenSSL made (`certificates/make.sh`): every group, cipher
//! suite and kind of key, HelloRetryRequest, ALPN, the server's name,
//! client authentication, KeyUpdate, exporters and closing; and the alerts
//! of RFC 9846 §6.2 for what must fail.

use std::sync::Arc;

use umilib::auth::cert::key::{KeyLimits, PrivateKey};
use umilib::auth::cert::path::TrustAnchor;
use umilib::auth::cert::x509::Certificate;
use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;
use umilib::protocol::tls::{
    TLSAlertDescription, TLSCertifiedKey, TLSCipherSuite, TLSClientAuthentication, TLSClientConfig, TLSConnection,
    TLSError, TLSEvent, TLSNamedGroup, TLSPathVerifier, TLSServerConfig, TLSSignatureScheme, TLSVersion,
};

use crate::Vectors;

/// 2027-01-01, inside the validity of the certificates.
pub const TIME: i64 = 1_798_761_600;

pub struct Fixture;

impl Fixture {
    pub fn certificate(name: &str) -> Vec<u8> {
        Vectors::bytes(&format!("protocol/tls/certificates/{name}.der"))
    }

    pub fn key(name: &str) -> PrivateKey {
        PrivateKey::from_pem(&Vectors::read(&format!("protocol/tls/certificates/{name}.key"))).unwrap()
    }

    /// The chain of `name`, issued by the root (not included), and its key.
    pub fn certified(name: &str) -> Arc<TLSCertifiedKey> {
        Arc::new(TLSCertifiedKey { chain: vec![Fixture::certificate(name)], key: Fixture::key(name), ocsp: None })
    }

    pub fn anchor(name: &str) -> TrustAnchor {
        let certificate = Certificate::from_der(&Fixture::certificate(name)).unwrap().into_owned();
        TrustAnchor::from_certificate(certificate, &KeyLimits::default()).unwrap()
    }

    pub fn random(seed: u8) -> Box<HMACDRBG<SHA256>> {
        Box::new(HMACDRBG::new(&[seed; 32], &[seed; 16], b"tls tests").unwrap())
    }

    pub fn client_config() -> TLSClientConfig {
        TLSClientConfig::new(Arc::new(TLSPathVerifier::servers(vec![Fixture::anchor("root")])))
    }

    pub fn server_config(name: &str) -> TLSServerConfig {
        TLSServerConfig::new(vec![Fixture::certified(name)])
    }
}

/// A client and a server joined by a perfect transport.
pub struct Pair {
    pub client: TLSConnection,
    pub server: TLSConnection,
}

impl Pair {
    pub fn new(client: TLSClientConfig, server: TLSServerConfig, name: Option<&str>) -> Pair {
        let client = TLSConnection::client(Arc::new(client), name, Fixture::random(1), TIME).unwrap();
        let server = TLSConnection::server(Arc::new(server), Fixture::random(2), TIME).unwrap();
        Pair { client, server }
    }

    /// Moves bytes both ways until neither side has more; the first error, if any.
    pub fn run(&mut self) -> Result<(), (bool, TLSError)> {
        loop {
            let mut moved = false;
            let mut bytes = Vec::new();
            self.client.transmit(&mut bytes).unwrap();
            if !bytes.is_empty() {
                moved = true;
                self.server.receive(&bytes).map_err(|error| (false, error))?;
            }
            let mut bytes = Vec::new();
            self.server.transmit(&mut bytes).unwrap();
            if !bytes.is_empty() {
                moved = true;
                self.client.receive(&bytes).map_err(|error| (true, error))?;
            }
            if !moved {
                return Ok(());
            }
        }
    }

    pub fn events(connection: &mut TLSConnection) -> Vec<TLSEvent> {
        std::iter::from_fn(|| connection.poll_event()).collect()
    }

    /// Sends `data` from the client to the server and back, and checks it.
    pub fn echo(&mut self, data: &[u8]) {
        self.client.send(data).unwrap();
        self.run().unwrap();
        let mut received = vec![0; data.len()];
        assert_eq!(self.server.read(&mut received), data.len());
        assert_eq!(received, data);
        self.server.send(&received).unwrap();
        self.run().unwrap();
        let mut back = vec![0; data.len()];
        assert_eq!(self.client.read(&mut back), data.len());
        assert_eq!(back, data);
    }
}

#[test]
fn a_full_handshake_and_data() {
    // RFC 9846 §2: a 1-RTT handshake authenticated by the server's certificate.
    let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some("server.example"));
    pair.run().unwrap();
    assert!(!pair.client.is_handshaking() && !pair.server.is_handshaking());
    assert_eq!(Pair::events(&mut pair.client), [TLSEvent::Connected]);
    assert_eq!(Pair::events(&mut pair.server), [TLSEvent::Connected]);
    for connection in [&pair.client, &pair.server] {
        assert_eq!(connection.session.version, Some(TLSVersion::TLS1_3));
        assert_eq!(connection.session.cipher_suite, Some(TLSCipherSuite::TLS_AES_128_GCM_SHA256));
    }
    assert_eq!(pair.client.session.peer_signature_scheme, Some(TLSSignatureScheme::ECDSA_SECP256R1_SHA256));
    assert_eq!(pair.client.session.peer_certificates, [Fixture::certificate("server-p256")]);
    assert_eq!(pair.server.session.server_name.as_deref(), Some("server.example"));
    pair.echo(b"hello, tls");
    // Larger than a record: split and joined again (RFC 9846 §5.1).
    pair.echo(&(0..100_000u32).map(|index| index as u8).collect::<Vec<_>>());
    // Both ends export the same keying material (RFC 9846 §7.5).
    let (mut client, mut server) = ([0u8; 32], [0u8; 32]);
    pair.client.export(b"EXPORTER-test", Some(b"context"), &mut client).unwrap();
    pair.server.export(b"EXPORTER-test", Some(b"context"), &mut server).unwrap();
    assert_eq!(client, server);
    let mut empty = [0u8; 32];
    pair.client.export(b"EXPORTER-test", None, &mut empty).unwrap();
    let mut same = [0u8; 32];
    pair.client.export(b"EXPORTER-test", Some(b""), &mut same).unwrap();
    assert_eq!(empty, same, "no context is an empty context in TLS 1.3");
    assert_ne!(empty, client);
}

#[test]
fn every_group_and_cipher_suite() {
    for group in [
        TLSNamedGroup::X25519,
        TLSNamedGroup::X448,
        TLSNamedGroup::SECP256R1,
        TLSNamedGroup::SECP384R1,
        TLSNamedGroup::SECP521R1,
        TLSNamedGroup::FFDHE2048,
        TLSNamedGroup::X25519_MLKEM768,
        TLSNamedGroup::SECP256R1_MLKEM768,
        TLSNamedGroup::SECP384R1_MLKEM1024,
    ]
    .into_iter()
    // FFDHE and the hybrids are in builds with `crypto-dh` and `crypto-hybrid`.
    .filter(|group| umilib::protocol::tls::TLSKeyShareSecret::supports(*group))
    {
        let mut client = Fixture::client_config();
        client.config.groups = vec![group];
        client.key_share_groups = vec![group];
        let mut server = Fixture::server_config("server-p256");
        server.config.groups = vec![group];
        let mut pair = Pair::new(client, server, Some("server.example"));
        pair.run().unwrap_or_else(|error| panic!("{group:?}: {error:?}"));
        assert_eq!(pair.client.session.group, Some(group));
        pair.echo(b"group");
    }
    for suite in [
        TLSCipherSuite::TLS_AES_128_GCM_SHA256,
        TLSCipherSuite::TLS_AES_256_GCM_SHA384,
        TLSCipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        TLSCipherSuite::TLS_AES_128_CCM_SHA256,
        TLSCipherSuite::TLS_AES_128_CCM_8_SHA256,
    ]
    .into_iter()
    // CCM is in builds with `crypto-mode-ccm`.
    .filter(|suite| suite.aead().is_some_and(umilib::protocol::tls::TLSAEAD::supports))
    {
        let mut client = Fixture::client_config();
        client.config.cipher_suites = vec![suite];
        let mut server = Fixture::server_config("server-p256");
        server.config.cipher_suites.push(TLSCipherSuite::TLS_AES_128_CCM_8_SHA256);
        let mut pair = Pair::new(client, server, Some("server.example"));
        pair.run().unwrap_or_else(|error| panic!("{suite:?}: {error:?}"));
        assert_eq!(pair.server.session.cipher_suite, Some(suite));
        pair.echo(&[7; 40_000]);
    }
}

#[test]
fn every_kind_of_key() {
    for (name, scheme) in [
        ("server-p256", TLSSignatureScheme::ECDSA_SECP256R1_SHA256),
        ("server-p384", TLSSignatureScheme::ECDSA_SECP384R1_SHA384),
        ("server-p521", TLSSignatureScheme::ECDSA_SECP521R1_SHA512),
        ("server-rsa", TLSSignatureScheme::RSA_PSS_RSAE_SHA256),
        ("server-pss", TLSSignatureScheme::RSA_PSS_PSS_SHA256),
        ("server-ed25519", TLSSignatureScheme::ED25519),
        ("server-ed448", TLSSignatureScheme::ED448),
    ] {
        let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config(name), Some("server.example"));
        pair.run().unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(pair.client.session.peer_signature_scheme, Some(scheme), "{name}");
    }
}

#[test]
fn hello_retry_requests() {
    // RFC 9846 §4.2.4: the client's share is of a group the server does not
    // take; the server asks for one it does, and the handshake completes.
    let mut client = Fixture::client_config();
    client.config.groups = vec![TLSNamedGroup::X25519, TLSNamedGroup::SECP384R1];
    client.key_share_groups = vec![TLSNamedGroup::X25519];
    let mut server = Fixture::server_config("server-p256");
    server.config.groups = vec![TLSNamedGroup::SECP384R1];
    let mut pair = Pair::new(client, server, Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.client.session.group, Some(TLSNamedGroup::SECP384R1));
    pair.echo(b"after a retry");
    // Without a group in common: handshake_failure.
    let mut client = Fixture::client_config();
    client.config.groups = vec![TLSNamedGroup::X25519];
    client.key_share_groups = vec![TLSNamedGroup::X25519];
    let mut server = Fixture::server_config("server-p256");
    server.config.groups = vec![TLSNamedGroup::SECP384R1];
    let mut pair = Pair::new(client, server, Some("server.example"));
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE))));
}

#[test]
fn application_protocols() {
    // RFC 7301: the server's preference among the client's protocols.
    let mut client = Fixture::client_config();
    client.config.protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    let mut server = Fixture::server_config("server-p256");
    server.config.protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut pair = Pair::new(client.clone(), server, Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.client.session.protocol.as_deref(), Some(b"h2".as_slice()));
    assert_eq!(pair.server.session.protocol.as_deref(), Some(b"h2".as_slice()));
    // None in common: no_application_protocol (RFC 7301 §3.2).
    let mut server = Fixture::server_config("server-p256");
    server.config.protocols = vec![b"smtp".to_vec()];
    let mut pair = Pair::new(client, server, Some("server.example"));
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::NO_APPLICATION_PROTOCOL))));
    assert_eq!(
        pair.client.receive(&take(&mut pair.server)),
        Err(TLSError::Alert(TLSAlertDescription::NO_APPLICATION_PROTOCOL))
    );
}

/// The bytes `connection` has to send.
pub fn take(connection: &mut TLSConnection) -> Vec<u8> {
    let mut bytes = Vec::new();
    connection.transmit(&mut bytes).unwrap();
    bytes
}

#[test]
fn certificates_are_checked() {
    // RFC 9846 §4.5.1.3, RFC 9525: the chain must reach a trust anchor, be
    // valid now and name the server.
    for (certificate, name, alert) in [
        ("server-p256", "other.example", TLSAlertDescription::BAD_CERTIFICATE),
        ("stranger", "server.example", TLSAlertDescription::UNKNOWN_CA),
        ("expired", "server.example", TLSAlertDescription::CERTIFICATE_EXPIRED),
    ] {
        let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config(certificate), Some(name));
        assert_eq!(pair.run(), Err((true, TLSError::Protocol(alert))), "{certificate} for {name}");
        // The server learns why.
        assert_eq!(pair.server.receive(&take(&mut pair.client)), Err(TLSError::Alert(alert)));
    }
    // Names: a wildcard, and addresses, which are not sent as server_name (RFC 6066 §3).
    for name in ["host.wild.example", "127.0.0.1", "::1"] {
        let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some(name));
        pair.run().unwrap_or_else(|error| panic!("{name}: {error:?}"));
        let sent = pair.server.session.server_name.clone();
        assert_eq!(sent.is_some(), name.contains("example"), "{name}");
    }
}

#[test]
fn certificates_are_chosen_by_name() {
    // RFC 6066 §3: the certificate that names the server asked for, and the
    // empty server_name acknowledges it.
    let server = TLSServerConfig::new(vec![Fixture::certified("stranger"), Fixture::certified("server-ed25519")]);
    let mut pair = Pair::new(Fixture::client_config(), server, Some("server.example"));
    pair.run().unwrap_err();
    // The stranger is also named server.example; the first that names it wins, and it is not trusted.
    let server = TLSServerConfig::new(vec![Fixture::certified("server-ed25519"), Fixture::certified("stranger")]);
    let mut pair = Pair::new(Fixture::client_config(), server, Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.client.session.peer_signature_scheme, Some(TLSSignatureScheme::ED25519));
}

#[test]
fn clients_authenticate_when_asked() {
    // RFC 9846 §4.4.2, §4.5.1.3: a CertificateRequest, then the client's
    // Certificate and CertificateVerify, checked by the server.
    let mut server = Fixture::server_config("server-p256");
    server.client_authentication = TLSClientAuthentication::Required;
    server.client_verifier = Some(Arc::new(TLSPathVerifier::clients(vec![Fixture::anchor("root")])));
    let mut client = Fixture::client_config();
    client.certificate = Some(Fixture::certified("client"));
    let mut pair = Pair::new(client, server.clone(), Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.server.session.peer_certificates, [Fixture::certificate("client")]);
    assert_eq!(pair.server.session.peer_signature_scheme, Some(TLSSignatureScheme::ECDSA_SECP256R1_SHA256));
    pair.echo(b"authenticated");
    // Without a certificate: certificate_required, sent under the
    // application keys after the client's Finished (RFC 9846 §4.5.3).
    let mut pair = Pair::new(Fixture::client_config(), server.clone(), Some("server.example"));
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::CERTIFICATE_REQUIRED))));
    assert_eq!(
        pair.client.receive(&take(&mut pair.server)),
        Err(TLSError::Alert(TLSAlertDescription::CERTIFICATE_REQUIRED))
    );
    // Optional: the handshake completes without one.
    server.client_authentication = TLSClientAuthentication::Optional;
    let mut pair = Pair::new(Fixture::client_config(), server, Some("server.example"));
    pair.run().unwrap();
    assert!(pair.server.session.peer_certificates.is_empty());
}

#[test]
fn key_updates_and_closing() {
    // RFC 9846 §4.7.3: a KeyUpdate replaces the sender's keys; with
    // update_requested the peer replaces its own.
    let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some("server.example"));
    pair.run().unwrap();
    pair.client.update_keys(true).unwrap();
    pair.echo(b"after an update");
    pair.server.update_keys(false).unwrap();
    pair.echo(b"after another");
    // A peer that only updates keys is cut off.
    for _ in 0..40 {
        pair.client.update_keys(false).unwrap();
    }
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::UNEXPECTED_MESSAGE))));
    // RFC 9846 §6.1: close_notify closes one half; data before it arrives.
    let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some("server.example"));
    pair.run().unwrap();
    Pair::events(&mut pair.server);
    Pair::events(&mut pair.client);
    pair.client.send(b"last words").unwrap();
    pair.client.close().unwrap();
    assert_eq!(pair.client.send(b"more"), Err(TLSError::State));
    pair.run().unwrap();
    assert_eq!(Pair::events(&mut pair.server), [TLSEvent::Readable, TLSEvent::PeerClosed]);
    let mut words = [0u8; 10];
    assert_eq!(pair.server.read(&mut words), 10);
    pair.server.send(b"reply").unwrap();
    pair.server.close().unwrap();
    pair.run().unwrap();
    assert_eq!(Pair::events(&mut pair.client), [TLSEvent::Readable, TLSEvent::PeerClosed]);
}

#[test]
fn tampered_records_are_refused() {
    // RFC 9846 §5.2: a record that does not authenticate is bad_record_mac.
    let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some("server.example"));
    pair.run().unwrap();
    pair.client.send(b"integrity").unwrap();
    let mut bytes = take(&mut pair.client);
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(pair.server.receive(&bytes), Err(TLSError::Protocol(TLSAlertDescription::BAD_RECORD_MAC)));
    assert!(pair.server.send(b"x").is_err());
    // Application data before the handshake completes: unexpected_message.
    let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some("server.example"));
    assert_eq!(pair.client.send(b"early"), Err(TLSError::State));
    let record = [23, 3, 3, 0, 1, 0];
    assert_eq!(pair.server.receive(&record), Err(TLSError::Protocol(TLSAlertDescription::UNEXPECTED_MESSAGE)));
}

#[test]
fn versions_are_negotiated() {
    // RFC 9846 §4.2.1: the highest version both support, and protocol_version without one.
    let mut client = Fixture::client_config();
    client.config.versions = vec![TLSVersion::TLS1_2];
    let mut server = Fixture::server_config("server-p256");
    server.config.versions = vec![TLSVersion::TLS1_3];
    let mut pair = Pair::new(client.clone(), server.clone(), Some("server.example"));
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::PROTOCOL_VERSION))));
    let mut pair = Pair::new(Fixture::client_config(), server, Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.server.session.version, Some(TLSVersion::TLS1_3));
    let mut pair = Pair::new(client, Fixture::server_config("server-p256"), Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.server.session.version, Some(TLSVersion::TLS1_2));
    // RFC 8996: no TLS 1.0 or 1.1, and a configuration with none supported fails.
    let mut client = Fixture::client_config();
    client.config.versions = vec![TLSVersion::TLS1_1, TLSVersion::TLS1_0];
    assert_eq!(
        TLSConnection::client(Arc::new(client), Some("server.example"), Fixture::random(1), TIME).err(),
        Some(TLSError::Config)
    );
}

#[test]
fn post_handshake_authentication() {
    // RFC 9846 §4.6.2: a client that offers post_handshake_auth answers a
    // CertificateRequest at any time with Certificate, CertificateVerify and
    // Finished.
    let verifier = Arc::new(TLSPathVerifier::clients(vec![Fixture::anchor("root")]));
    let mut server = Fixture::server_config("server-p256");
    server.client_verifier = Some(verifier);
    let mut client = Fixture::client_config();
    client.post_handshake_authentication = true;
    client.certificate = Some(Fixture::certified("client"));
    let mut pair = Pair::new(client.clone(), server.clone(), Some("server.example"));
    pair.run().unwrap();
    Pair::events(&mut pair.server);
    assert!(pair.server.session.peer_certificates.is_empty());
    for _ in 0..2 {
        pair.server.request_certificate().unwrap();
        // One request at a time.
        assert_eq!(pair.server.request_certificate(), Err(TLSError::State));
        pair.run().unwrap();
        assert_eq!(Pair::events(&mut pair.server), [TLSEvent::Authenticated]);
        assert_eq!(pair.server.session.peer_certificates, [Fixture::certificate("client")]);
        assert_eq!(pair.server.session.peer_signature_scheme, Some(TLSSignatureScheme::ECDSA_SECP256R1_SHA256));
        pair.echo(b"authenticated later");
        Pair::events(&mut pair.server);
    }
    // A client without a certificate declines with an empty Certificate.
    let mut declining = client.clone();
    declining.certificate = None;
    let mut pair = Pair::new(declining, server.clone(), Some("server.example"));
    pair.run().unwrap();
    Pair::events(&mut pair.server);
    pair.server.request_certificate().unwrap();
    pair.run().unwrap();
    assert_eq!(Pair::events(&mut pair.server), [TLSEvent::Authenticated]);
    assert!(pair.server.session.peer_certificates.is_empty());
    // A certificate the server does not trust.
    let mut stranger = client.clone();
    stranger.certificate = Some(Fixture::certified("stranger"));
    let mut pair = Pair::new(stranger, server.clone(), Some("server.example"));
    pair.run().unwrap();
    pair.server.request_certificate().unwrap();
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::UNKNOWN_CA))));
    // Not offered: the server cannot ask, and a request is unexpected_message.
    let mut pair = Pair::new(Fixture::client_config(), server.clone(), Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.server.request_certificate(), Err(TLSError::State));
    let request = [0x0D, 0, 0, 11, 1, 7, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3];
    pair.server.layer.write(umilib::protocol::tls::TLSContentType::HANDSHAKE, &request).unwrap();
    assert_eq!(pair.run(), Err((true, TLSError::Protocol(TLSAlertDescription::UNEXPECTED_MESSAGE))));
    // A server without a verifier of clients cannot ask either.
    let mut pair = Pair::new(client, Fixture::server_config("server-p256"), Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.server.request_certificate(), Err(TLSError::State));
}
