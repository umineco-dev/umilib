//! TLS 1.2 handshakes between this crate's client and server (RFC 5246
//! with the ECDHE suites of RFC 8422, RFC 5289 and RFC 7905), and the
//! rules every TLS 1.2 peer of this crate must keep: secure renegotiation
//! signalled and renegotiation refused (RFC 5746), the extended main secret
//! (RFC 7627, RFC 9325 §3.5), the fallback signal (RFC 7507), the point
//! formats (RFC 8422 §5.1.2) and the downgrade protection of RFC 9846 §4.2.3.

use std::sync::Arc;

use umilib::protocol::tls::{
    TLSAlertDescription, TLSCipherSuite, TLSClientAuthentication, TLSClientConfig, TLSClientHello, TLSConnection,
    TLSError, TLSEvent, TLSExtension, TLSExtensionType, TLSHandshake, TLSHandshakeType, TLSNamedGroup, TLSPathVerifier,
    TLSServerConfig, TLSServerHello, TLSSignatureScheme, TLSVersion,
};

use super::handshake::{Fixture, Pair, TIME, take};

pub struct TLS12;

impl TLS12 {
    pub fn client() -> TLSClientConfig {
        let mut config = Fixture::client_config();
        config.config.versions = vec![TLSVersion::TLS1_2];
        config
    }

    pub fn server(name: &str) -> TLSServerConfig {
        let mut config = Fixture::server_config(name);
        config.config.versions = vec![TLSVersion::TLS1_2];
        config
    }

    /// The extensions of a well-formed ClientHello of TLS 1.2, but for those
    /// of `without`.
    pub fn extensions(without: &[TLSExtensionType]) -> Vec<TLSExtension> {
        [
            TLSExtension::new(TLSExtensionType::EXTENDED_MAIN_SECRET, vec![]),
            TLSExtension::new(TLSExtensionType::RENEGOTIATION_INFO, vec![0]),
            TLSExtension::new(TLSExtensionType::EC_POINT_FORMATS, vec![1, 0]),
            TLSExtension::new(TLSExtensionType::SUPPORTED_GROUPS, vec![0, 4, 0, 0x1D, 0, 0x17]),
            TLSExtension::new(TLSExtensionType::SIGNATURE_ALGORITHMS, vec![0, 4, 4, 3, 8, 4]),
        ]
        .into_iter()
        .filter(|extension| !without.contains(&extension.kind))
        .collect()
    }

    pub fn hello(extensions: Vec<TLSExtension>) -> TLSClientHello {
        TLSClientHello {
            legacy_version: TLSVersion::TLS1_2,
            random: [9; 32],
            legacy_session_id: Vec::new(),
            cipher_suites: vec![
                TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLSCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            legacy_compression_methods: vec![0],
            extensions,
        }
    }

    /// The ClientHello as a record.
    pub fn record(hello: &TLSClientHello) -> Vec<u8> {
        let message = TLSHandshake::new(TLSHandshakeType::CLIENT_HELLO, hello.to_bytes().unwrap()).to_bytes().unwrap();
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        record
    }

    /// What a server of `config` answers to `hello`: the error, or its ServerHello.
    pub fn answer(config: TLSServerConfig, hello: &TLSClientHello) -> Result<TLSServerHello, TLSError> {
        let mut server = TLSConnection::server(Arc::new(config), Fixture::random(2), TIME).unwrap();
        server.receive(&TLS12::record(hello))?;
        let bytes = take(&mut server);
        assert_eq!(bytes[0], 22, "a handshake record");
        assert_eq!(bytes[5], TLSHandshakeType::SERVER_HELLO.0);
        let length = u32::from_be_bytes([0, bytes[6], bytes[7], bytes[8]]) as usize;
        Ok(TLSServerHello::decode(&bytes[9..9 + length]).unwrap())
    }

    /// A ServerHello of TLS 1.2 that answers the ClientHello of a client
    /// of `config`, as a record, with `extensions`.
    pub fn server_hello(
        config: TLSClientConfig,
        suite: TLSCipherSuite,
        compression: u8,
        extensions: Vec<TLSExtension>,
    ) -> Result<(), TLSError> {
        let mut client =
            TLSConnection::client(Arc::new(config), Some("server.example"), Fixture::random(1), TIME).unwrap();
        take(&mut client);
        let hello = TLSServerHello {
            legacy_version: TLSVersion::TLS1_2,
            random: [5; 32],
            legacy_session_id_echo: Vec::new(),
            cipher_suite: suite,
            legacy_compression_method: compression,
            extensions,
        };
        let message = TLSHandshake::new(TLSHandshakeType::SERVER_HELLO, hello.to_bytes().unwrap()).to_bytes().unwrap();
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        client.receive(&record)
    }
}

#[test]
fn a_full_handshake_and_data() {
    let mut pair = Pair::new(TLS12::client(), TLS12::server("server-p256"), Some("server.example"));
    pair.run().unwrap();
    assert_eq!(Pair::events(&mut pair.client), [TLSEvent::Connected]);
    assert_eq!(Pair::events(&mut pair.server), [TLSEvent::Connected]);
    for connection in [&pair.client, &pair.server] {
        assert_eq!(connection.session.version, Some(TLSVersion::TLS1_2));
        assert_eq!(connection.session.cipher_suite, Some(TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));
        assert_eq!(connection.session.group, Some(TLSNamedGroup::X25519), "the hybrids are not for TLS 1.2");
    }
    assert_eq!(pair.client.session.peer_signature_scheme, Some(TLSSignatureScheme::ECDSA_SECP256R1_SHA256));
    assert_eq!(pair.client.session.peer_certificates, [Fixture::certificate("server-p256")]);
    assert_eq!(pair.server.session.server_name.as_deref(), Some("server.example"));
    pair.echo(b"hello, tls 1.2");
    pair.echo(&(0..100_000u32).map(|index| index as u8).collect::<Vec<_>>());
    // RFC 5705 §4: both ends export the same; no context differs from an empty one.
    let (mut client, mut server) = ([0u8; 32], [0u8; 32]);
    pair.client.export(b"EXPORTER-test", Some(b"context"), &mut client).unwrap();
    pair.server.export(b"EXPORTER-test", Some(b"context"), &mut server).unwrap();
    assert_eq!(client, server);
    let (mut none, mut empty) = ([0u8; 32], [0u8; 32]);
    pair.client.export(b"EXPORTER-test", None, &mut none).unwrap();
    pair.client.export(b"EXPORTER-test", Some(b""), &mut empty).unwrap();
    assert_ne!(none, empty);
    // TLS 1.2 has no KeyUpdate.
    assert_eq!(pair.client.update_keys(false), Err(TLSError::State));
    pair.client.send(b"last").unwrap();
    pair.client.close().unwrap();
    pair.run().unwrap();
    assert_eq!(Pair::events(&mut pair.server), [TLSEvent::Readable, TLSEvent::PeerClosed]);
}

#[test]
fn every_group_suite_and_key() {
    for group in [
        TLSNamedGroup::X25519,
        TLSNamedGroup::X448,
        TLSNamedGroup::SECP256R1,
        TLSNamedGroup::SECP384R1,
        TLSNamedGroup::SECP521R1,
    ] {
        let mut client = TLS12::client();
        client.config.groups = vec![group, TLSNamedGroup::SECP256R1];
        client.key_share_groups = TLSClientConfig::default_key_shares(&client.config.groups);
        let mut server = TLS12::server("server-p256");
        server.config.groups = vec![group];
        let mut pair = Pair::new(client, server, Some("server.example"));
        pair.run().unwrap_or_else(|error| panic!("{group:?}: {error:?}"));
        assert_eq!(pair.client.session.group, Some(group));
        pair.echo(b"group");
    }
    for (suite, certificate) in [
        (TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "server-p256"),
        (TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "server-p256"),
        (TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "server-p256"),
        (TLSCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "server-rsa"),
        (TLSCipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "server-rsa"),
        (TLSCipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "server-rsa"),
    ] {
        let mut client = TLS12::client();
        client.config.cipher_suites = vec![suite];
        let mut pair = Pair::new(client, TLS12::server(certificate), Some("server.example"));
        pair.run().unwrap_or_else(|error| panic!("{suite:?}: {error:?}"));
        assert_eq!(pair.server.session.cipher_suite, Some(suite));
        pair.echo(&[7; 40_000]);
    }
    // In TLS 1.2 an ECDSA scheme names only its hash (RFC 8422 §5.1.3);
    // EdDSA keys authenticate the ECDSA suites (RFC 8422 §3).
    for (name, scheme) in [
        ("server-p256", TLSSignatureScheme::ECDSA_SECP256R1_SHA256),
        ("server-p384", TLSSignatureScheme::ECDSA_SECP256R1_SHA256),
        ("server-p521", TLSSignatureScheme::ECDSA_SECP256R1_SHA256),
        ("server-rsa", TLSSignatureScheme::RSA_PSS_RSAE_SHA256),
        ("server-pss", TLSSignatureScheme::RSA_PSS_PSS_SHA256),
        ("server-ed25519", TLSSignatureScheme::ED25519),
        ("server-ed448", TLSSignatureScheme::ED448),
    ] {
        let mut pair = Pair::new(TLS12::client(), TLS12::server(name), Some("server.example"));
        pair.run().unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(pair.client.session.peer_signature_scheme, Some(scheme), "{name}");
    }
    // RSASSA-PKCS1-v1_5 still signs in TLS 1.2 (RFC 5246 §7.4.1.4.1).
    let mut client = TLS12::client();
    client.config.signature_schemes = vec![TLSSignatureScheme::RSA_PKCS1_SHA384];
    let mut pair = Pair::new(client, TLS12::server("server-rsa"), Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.client.session.peer_signature_scheme, Some(TLSSignatureScheme::RSA_PKCS1_SHA384));
}

#[test]
fn certificates_must_fit_the_suite_and_curves() {
    // An RSA certificate cannot serve the ECDSA suites: handshake_failure.
    let mut client = TLS12::client();
    client.config.cipher_suites = vec![TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let mut pair = Pair::new(client, TLS12::server("server-rsa"), Some("server.example"));
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE))));
    // An ECDSA certificate on a curve the client does not list (RFC 8422 §5.1.1).
    let mut client = TLS12::client();
    client.config.groups = vec![TLSNamedGroup::X25519, TLSNamedGroup::SECP256R1];
    client.key_share_groups = TLSClientConfig::default_key_shares(&client.config.groups);
    let mut pair = Pair::new(client, TLS12::server("server-p384"), Some("server.example"));
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE))));
    // The server chooses the certificate that fits among several.
    let mut server = TLS12::server("server-p384");
    server.certificates.push(Fixture::certified("server-rsa"));
    let mut client = TLS12::client();
    client.config.groups = vec![TLSNamedGroup::X25519];
    client.key_share_groups = TLSClientConfig::default_key_shares(&client.config.groups);
    let mut pair = Pair::new(client, server, Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.client.session.peer_certificates, [Fixture::certificate("server-rsa")]);
}

#[test]
fn the_server_checks_the_client_hello() {
    let failure = Some(TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE));
    // A well-formed one: renegotiation_info and the extended main secret
    // acknowledged, the point formats answered, and the random of a server
    // that also supports TLS 1.3 marked (RFC 9846 §4.2.3).
    let hello = TLS12::answer(Fixture::server_config("server-p256"), &TLS12::hello(TLS12::extensions(&[]))).unwrap();
    assert_eq!(hello.legacy_version, TLSVersion::TLS1_2);
    assert_eq!(hello.random[24..], TLSServerHello::DOWNGRADE_TLS1_2);
    assert_eq!(hello.extension(TLSExtensionType::RENEGOTIATION_INFO), Some([0].as_slice()));
    assert_eq!(hello.extension(TLSExtensionType::EXTENDED_MAIN_SECRET), Some([].as_slice()));
    assert!(hello.extension(TLSExtensionType::EC_POINT_FORMATS).is_some_and(|formats| formats.contains(&0)));
    assert_eq!(hello.cipher_suite, TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    // A server of TLS 1.2 only does not mark it.
    let hello = TLS12::answer(TLS12::server("server-p256"), &TLS12::hello(TLS12::extensions(&[]))).unwrap();
    assert_ne!(hello.random[24..], TLSServerHello::DOWNGRADE_TLS1_2);
    // RFC 5746 §3.6: the signalling suite stands for an empty renegotiation_info.
    let mut scsv = TLS12::hello(TLS12::extensions(&[TLSExtensionType::RENEGOTIATION_INFO]));
    scsv.cipher_suites.push(TLSCipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    let hello = TLS12::answer(TLS12::server("server-p256"), &scsv).unwrap();
    assert_eq!(hello.extension(TLSExtensionType::RENEGOTIATION_INFO), Some([0].as_slice()));
    // Neither: no secure renegotiation (RFC 9325 §3.5).
    let none = TLS12::hello(TLS12::extensions(&[TLSExtensionType::RENEGOTIATION_INFO]));
    assert_eq!(TLS12::answer(TLS12::server("server-p256"), &none).err(), failure);
    // A renegotiation_info that is not empty in an initial handshake (RFC 5746 §3.6).
    let mut renegotiating = TLS12::hello(TLS12::extensions(&[TLSExtensionType::RENEGOTIATION_INFO]));
    renegotiating.extensions.push(TLSExtension::new(TLSExtensionType::RENEGOTIATION_INFO, vec![12; 13]));
    assert_eq!(TLS12::answer(TLS12::server("server-p256"), &renegotiating).err(), failure);
    // RFC 7627 §5.3: without the extended main secret, refused by default…
    let plain = TLS12::hello(TLS12::extensions(&[TLSExtensionType::EXTENDED_MAIN_SECRET]));
    assert_eq!(TLS12::answer(TLS12::server("server-p256"), &plain).err(), failure);
    // …and served without it if configured so.
    let mut lenient = TLS12::server("server-p256");
    lenient.config.require_extended_main_secret = false;
    let hello = TLS12::answer(lenient, &plain).unwrap();
    assert_eq!(hello.extension(TLSExtensionType::EXTENDED_MAIN_SECRET), None);
    // RFC 7507 §3: a fallback to a server that could have served TLS 1.3.
    let mut fallback = TLS12::hello(TLS12::extensions(&[]));
    fallback.cipher_suites.push(TLSCipherSuite::TLS_FALLBACK_SCSV);
    assert_eq!(
        TLS12::answer(Fixture::server_config("server-p256"), &fallback).err(),
        Some(TLSError::Protocol(TLSAlertDescription::INAPPROPRIATE_FALLBACK))
    );
    assert!(TLS12::answer(TLS12::server("server-p256"), &fallback).is_ok(), "the highest version this server has");
    // RFC 5246 §7.4.1.2: null compression must be offered.
    let mut compressed = TLS12::hello(TLS12::extensions(&[]));
    compressed.legacy_compression_methods = vec![1];
    assert_eq!(
        TLS12::answer(TLS12::server("server-p256"), &compressed).err(),
        Some(TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER))
    );
    // RFC 8422 §5.1.2: the uncompressed point format must be listed.
    let mut formats = TLS12::hello(TLS12::extensions(&[TLSExtensionType::EC_POINT_FORMATS]));
    formats.extensions.push(TLSExtension::new(TLSExtensionType::EC_POINT_FORMATS, vec![1, 1]));
    assert_eq!(
        TLS12::answer(TLS12::server("server-p256"), &formats).err(),
        Some(TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER))
    );
    // Without signature_algorithms the client accepts only SHA-1 (RFC 5246
    // §7.4.1.4.1), which is refused (RFC 9155).
    let sha1 = TLS12::hello(TLS12::extensions(&[TLSExtensionType::SIGNATURE_ALGORITHMS]));
    assert_eq!(TLS12::answer(TLS12::server("server-p256"), &sha1).err(), failure);
    // Without supported_groups, secp256r1 (RFC 8422 §4).
    let groups = TLS12::hello(TLS12::extensions(&[TLSExtensionType::SUPPORTED_GROUPS]));
    assert!(TLS12::answer(TLS12::server("server-p256"), &groups).is_ok());
    // A legacy_version below TLS 1.2 without supported_versions (RFC 8996).
    let mut old = TLS12::hello(TLS12::extensions(&[]));
    old.legacy_version = TLSVersion::TLS1_1;
    assert_eq!(
        TLS12::answer(TLS12::server("server-p256"), &old).err(),
        Some(TLSError::Protocol(TLSAlertDescription::PROTOCOL_VERSION))
    );
    // No suite in common.
    let mut suites = TLS12::hello(TLS12::extensions(&[]));
    suites.cipher_suites = vec![TLSCipherSuite(0x009C)];
    assert_eq!(TLS12::answer(TLS12::server("server-p256"), &suites).err(), failure);
}

#[test]
fn the_client_checks_the_server_hello() {
    let suite = TLSCipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let renegotiation = TLSExtension::new(TLSExtensionType::RENEGOTIATION_INFO, vec![0]);
    let extended = TLSExtension::new(TLSExtensionType::EXTENDED_MAIN_SECRET, vec![]);
    let alert = |description| Err(TLSError::Protocol(description));
    // Well-formed: the client waits for the Certificate.
    assert_eq!(TLS12::server_hello(TLS12::client(), suite, 0, vec![renegotiation.clone(), extended.clone()]), Ok(()));
    // RFC 5746 §3.4: no renegotiation_info.
    assert_eq!(
        TLS12::server_hello(TLS12::client(), suite, 0, vec![extended.clone()]),
        alert(TLSAlertDescription::HANDSHAKE_FAILURE)
    );
    // RFC 7627 §5.2: no extended main secret.
    assert_eq!(
        TLS12::server_hello(TLS12::client(), suite, 0, vec![renegotiation.clone()]),
        alert(TLSAlertDescription::HANDSHAKE_FAILURE)
    );
    let mut lenient = TLS12::client();
    lenient.config.require_extended_main_secret = false;
    assert_eq!(TLS12::server_hello(lenient, suite, 0, vec![renegotiation.clone()]), Ok(()));
    // A suite, a compression or an extension the client did not offer.
    assert_eq!(
        TLS12::server_hello(TLS12::client(), TLSCipherSuite(0x009C), 0, vec![renegotiation.clone(), extended.clone()]),
        alert(TLSAlertDescription::ILLEGAL_PARAMETER)
    );
    assert_eq!(
        TLS12::server_hello(
            TLS12::client(),
            TLSCipherSuite::TLS_AES_128_GCM_SHA256,
            0,
            vec![renegotiation.clone(), extended.clone()]
        ),
        alert(TLSAlertDescription::ILLEGAL_PARAMETER)
    );
    assert_eq!(
        TLS12::server_hello(TLS12::client(), suite, 1, vec![renegotiation.clone(), extended.clone()]),
        alert(TLSAlertDescription::ILLEGAL_PARAMETER)
    );
    let ticket = TLSExtension::new(TLSExtensionType::SESSION_TICKET, vec![]);
    assert_eq!(
        TLS12::server_hello(TLS12::client(), suite, 0, vec![renegotiation.clone(), extended.clone(), ticket]),
        alert(TLSAlertDescription::UNSUPPORTED_EXTENSION)
    );
    // RFC 8422 §5.2: the server's point formats list the uncompressed one.
    let formats = TLSExtension::new(TLSExtensionType::EC_POINT_FORMATS, vec![1, 1]);
    assert_eq!(
        TLS12::server_hello(TLS12::client(), suite, 0, vec![renegotiation.clone(), extended.clone(), formats]),
        alert(TLSAlertDescription::ILLEGAL_PARAMETER)
    );
    let formats = TLSExtension::new(TLSExtensionType::EC_POINT_FORMATS, vec![3, 0, 1, 2]);
    assert_eq!(TLS12::server_hello(TLS12::client(), suite, 0, vec![renegotiation, extended, formats]), Ok(()));
}

#[test]
fn downgrades_are_detected() {
    // RFC 9846 §4.2.3: a server that supports TLS 1.3 and negotiates TLS 1.2
    // with a client that offered TLS 1.3 is an attack to that client.
    let mut server = Fixture::server_config("server-p256");
    server.config.versions = vec![TLSVersion::TLS1_2, TLSVersion::TLS1_3];
    let mut pair = Pair::new(Fixture::client_config(), server.clone(), Some("server.example"));
    assert_eq!(pair.run(), Err((true, TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER))));
    // A client of TLS 1.2 only expects that mark.
    let mut pair = Pair::new(TLS12::client(), server, Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.client.session.version, Some(TLSVersion::TLS1_2));
    // Both versions on both ends: TLS 1.3.
    let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.client.session.version, Some(TLSVersion::TLS1_3));
}

#[test]
fn renegotiation_is_refused() {
    // RFC 5746 §4.2, §4.4, RFC 5246 §7.2.2: a HelloRequest or a ClientHello
    // after the handshake is answered with the warning no_renegotiation,
    // which the peer may ignore; the connection goes on.
    let mut pair = Pair::new(TLS12::client(), TLS12::server("server-p256"), Some("server.example"));
    pair.run().unwrap();
    pair.server.layer.write_handshake(&TLSHandshake::new(TLSHandshakeType::HELLO_REQUEST, vec![])).unwrap();
    let request = take(&mut pair.server);
    pair.client.receive(&request).unwrap();
    let warning = take(&mut pair.client);
    assert_eq!(warning.len(), 5 + 8 + 2 + 16, "one protected alert record");
    pair.server.receive(&warning).unwrap();
    pair.echo(b"still open");
    let hello = TLS12::hello(TLS12::extensions(&[])).to_bytes().unwrap();
    pair.client.layer.write_handshake(&TLSHandshake::new(TLSHandshakeType::CLIENT_HELLO, hello)).unwrap();
    pair.run().unwrap();
    pair.echo(b"still open");
}

#[test]
fn clients_authenticate_when_asked() {
    // RFC 5246 §7.4.4, §7.4.6, §7.4.8: CertificateRequest, the client's
    // Certificate and its CertificateVerify over the messages so far.
    let mut server = TLS12::server("server-p256");
    server.client_authentication = TLSClientAuthentication::Required;
    server.client_verifier = Some(Arc::new(TLSPathVerifier::clients(vec![Fixture::anchor("root")])));
    let mut client = TLS12::client();
    client.certificate = Some(Fixture::certified("client"));
    let mut pair = Pair::new(client, server.clone(), Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.server.session.peer_certificates, [Fixture::certificate("client")]);
    assert_eq!(pair.server.session.peer_signature_scheme, Some(TLSSignatureScheme::ECDSA_SECP256R1_SHA256));
    pair.echo(b"authenticated");
    // Without a certificate: handshake_failure (RFC 5246 §7.4.6).
    let mut pair = Pair::new(TLS12::client(), server.clone(), Some("server.example"));
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE))));
    // A certificate the server does not trust.
    let mut client = TLS12::client();
    client.certificate = Some(Fixture::certified("stranger"));
    let mut pair = Pair::new(client, server.clone(), Some("server.example"));
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::UNKNOWN_CA))));
    // Optional: the handshake completes without one.
    server.client_authentication = TLSClientAuthentication::Optional;
    let mut pair = Pair::new(TLS12::client(), server, Some("server.example"));
    pair.run().unwrap();
    assert!(pair.server.session.peer_certificates.is_empty());
}

#[test]
fn application_protocols() {
    let mut client = TLS12::client();
    client.config.protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    let mut server = TLS12::server("server-p256");
    server.config.protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut pair = Pair::new(client.clone(), server, Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.client.session.protocol.as_deref(), Some(b"h2".as_slice()));
    assert_eq!(pair.server.session.protocol.as_deref(), Some(b"h2".as_slice()));
    let mut server = TLS12::server("server-p256");
    server.config.protocols = vec![b"smtp".to_vec()];
    let mut pair = Pair::new(client, server, Some("server.example"));
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::NO_APPLICATION_PROTOCOL))));
}

#[test]
fn messages_out_of_order_are_refused() {
    // A ChangeCipherSpec before the ClientKeyExchange (RFC 5246 §7.1, §7.3).
    let mut pair = Pair::new(TLS12::client(), TLS12::server("server-p256"), Some("server.example"));
    pair.server.receive(&take(&mut pair.client)).unwrap();
    assert_eq!(
        pair.server.receive(&[20, 3, 3, 0, 1, 1]),
        Err(TLSError::Protocol(TLSAlertDescription::UNEXPECTED_MESSAGE))
    );
    // A Finished that does not verify: decrypt_error (RFC 5246 §7.4.9).
    let mut pair = Pair::new(TLS12::client(), TLS12::server("server-p256"), Some("server.example"));
    pair.server.receive(&take(&mut pair.client)).unwrap();
    pair.client.receive(&take(&mut pair.server)).unwrap();
    let flight = take(&mut pair.client);
    let mut tampered = flight.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(pair.server.receive(&tampered), Err(TLSError::Protocol(TLSAlertDescription::BAD_RECORD_MAC)));
    // The records of TLS 1.2 refuse tampering as well.
    let mut pair = Pair::new(TLS12::client(), TLS12::server("server-p256"), Some("server.example"));
    pair.run().unwrap();
    pair.client.send(b"integrity").unwrap();
    let mut bytes = take(&mut pair.client);
    bytes[5] ^= 1;
    assert_eq!(pair.server.receive(&bytes), Err(TLSError::Protocol(TLSAlertDescription::BAD_RECORD_MAC)));
}

#[test]
fn hello_requests_during_the_handshake_are_ignored() {
    // RFC 5246 §7.4.1.1: ignored while negotiating, and not hashed.
    let mut pair = Pair::new(TLS12::client(), TLS12::server("server-p256"), Some("server.example"));
    pair.server.receive(&take(&mut pair.client)).unwrap();
    let flight = take(&mut pair.server);
    let first = 5 + u16::from_be_bytes([flight[3], flight[4]]) as usize;
    let mut bytes = flight[..first].to_vec();
    bytes.extend_from_slice(&[22, 3, 3, 0, 4, 0, 0, 0, 0]);
    bytes.extend_from_slice(&flight[first..]);
    pair.client.receive(&bytes).unwrap();
    pair.run().unwrap();
    pair.echo(b"negotiated");
}

#[test]
fn messages_of_tls_1_2() {
    use umilib::auth::cert::key::{KeyAlgorithm, NamedCurve};
    use umilib::protocol::tls::v1_2::{TLS12CertificateRequest, TLS12ServerKeyExchange};
    // RFC 8422 §5.4: only named curves; explicit curves are illegal_parameter.
    let mut body = vec![TLS12ServerKeyExchange::NAMED_CURVE, 0, 0x1D, 32];
    body.extend_from_slice(&[9; 32]);
    body.extend_from_slice(&[4, 3, 0, 2, 1, 2]);
    let exchange = TLS12ServerKeyExchange::decode(&body).unwrap();
    assert_eq!(exchange.group, TLSNamedGroup::X25519);
    assert_eq!(exchange.signature.algorithm, TLSSignatureScheme::ECDSA_SECP256R1_SHA256);
    let mut encoded = Vec::new();
    exchange.encode(&mut encoded).unwrap();
    assert_eq!(encoded, body);
    body[0] = 1;
    assert_eq!(TLS12ServerKeyExchange::decode(&body), Err(TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER)));
    // RFC 5246 §7.4.6: the client's certificate is of a type asked for.
    let request = TLS12CertificateRequest {
        types: vec![TLS12CertificateRequest::RSA_SIGN],
        schemes: vec![TLSSignatureScheme::RSA_PSS_RSAE_SHA256],
        authorities: vec![],
    };
    assert!(request.accepts(&KeyAlgorithm::RSA));
    assert!(!request.accepts(&KeyAlgorithm::EC(NamedCurve::P256)));
    let mut encoded = Vec::new();
    request.encode(&mut encoded).unwrap();
    assert_eq!(encoded, [1, 1, 0, 2, 8, 4, 0, 0]);
    assert_eq!(TLS12CertificateRequest::decode(&encoded).unwrap(), request);
}
