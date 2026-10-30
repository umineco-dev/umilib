//! The extensions both versions negotiate: `record_size_limit` (RFC 8449)
//! and `status_request`, OCSP stapling (RFC 6066 §8, RFC 9846 §4.5.1.1).

use std::sync::Arc;

use umilib::protocol::tls::{
    TLSAlertDescription, TLSCertifiedKey, TLSClientConfig, TLSConnection, TLSError, TLSExtension, TLSExtensionType,
    TLSRecordHeader, TLSServerConfig, TLSVersion,
};

use super::handshake::{Fixture, Pair, TIME, take};
use super::v1_2::TLS12;

pub struct Records;

impl Records {
    /// The content type and length of each record of `bytes`.
    pub fn of(bytes: &[u8]) -> Vec<(u8, usize)> {
        let mut records = Vec::new();
        let mut rest = bytes;
        while rest.len() >= 5 {
            let length = u16::from_be_bytes([rest[3], rest[4]]) as usize;
            records.push((rest[0], length));
            rest = &rest[5 + length..];
        }
        assert!(rest.is_empty(), "whole records");
        records
    }

    /// Sends `length` bytes from `from` and returns the length of the
    /// largest record written for them.
    pub fn largest(from: &mut TLSConnection, length: usize) -> usize {
        from.send(&vec![1; length]).unwrap();
        Records::of(&take(from)).into_iter().map(|(_, length)| length).max().unwrap()
    }

    pub fn configs(version: TLSVersion) -> (TLSClientConfig, TLSServerConfig) {
        let (mut client, mut server) = (Fixture::client_config(), Fixture::server_config("server-p256"));
        client.config.versions = vec![version];
        server.config.versions = vec![version];
        (client, server)
    }
}

#[test]
fn record_size_limits() {
    // RFC 8449 §4: each end writes protected records within the peer's
    // limit; TLS 1.3 counts the content type in the value, TLS 1.2 does
    // not. The ciphertext adds the tag (16), and in TLS 1.3 the content
    // type (1), in TLS 1.2 with AES-GCM the explicit nonce (8).
    for (version, overhead) in [(TLSVersion::TLS1_3, 1 + 16), (TLSVersion::TLS1_2, 8 + 16)] {
        let (mut client, mut server) = Records::configs(version);
        client.config.record_size_limit = 64;
        server.config.record_size_limit = 512;
        let mut pair = Pair::new(client, server, Some("server.example"));
        pair.run().unwrap();
        assert_eq!(Records::largest(&mut pair.server, 1000), 64 + overhead, "{version:?}");
        assert_eq!(Records::largest(&mut pair.client, 5000), 512 + overhead, "{version:?}");
        assert_eq!(pair.client.layer.own_limit, 64);
        assert_eq!(pair.server.layer.own_limit, 512);
        // Without limits below the maximum, records of 2^14 bytes.
        let mut pair = Pair::new(Records::configs(version).0, Records::configs(version).1, Some("server.example"));
        pair.run().unwrap();
        assert_eq!(Records::largest(&mut pair.server, 20_000), TLSRecordHeader::MAXIMUM_PLAINTEXT + overhead);
    }
}

#[test]
fn record_size_limits_need_the_peer() {
    // A limit holds only once the peer has seen it (RFC 8449 §4): a client
    // without the extension may send records of 2^14 bytes.
    let mut server = TLS12::server("server-p256");
    server.config.record_size_limit = 64;
    let mut connection = TLSConnection::server(Arc::new(server.clone()), Fixture::random(2), TIME).unwrap();
    connection.receive(&TLS12::record(&TLS12::hello(TLS12::extensions(&[])))).unwrap();
    assert_eq!(connection.layer.own_limit, TLSRecordHeader::MAXIMUM_PLAINTEXT);
    // A value below 64 is illegal_parameter.
    let mut hello = TLS12::hello(TLS12::extensions(&[]));
    hello.extensions.push(TLSExtension::new(TLSExtensionType::RECORD_SIZE_LIMIT, vec![0, 63]));
    assert_eq!(
        TLS12::answer(server.clone(), &hello).err(),
        Some(TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER))
    );
    // With it, the server answers with its own.
    let mut hello = TLS12::hello(TLS12::extensions(&[]));
    hello.extensions.push(TLSExtension::new(TLSExtensionType::RECORD_SIZE_LIMIT, vec![0x40, 0]));
    let answer = TLS12::answer(server, &hello).unwrap();
    assert_eq!(answer.extension(TLSExtensionType::RECORD_SIZE_LIMIT), Some([0, 64].as_slice()));
}

/// A server of server-p256 that staples `response`.
pub fn stapling(version: TLSVersion, response: Option<&str>) -> (TLSClientConfig, TLSServerConfig) {
    let (mut client, _) = Records::configs(version);
    client.request_certificate_status = true;
    let key = TLSCertifiedKey {
        chain: vec![Fixture::certificate("server-p256")],
        key: Fixture::key("server-p256"),
        ocsp: response.map(Fixture::certificate),
    };
    let mut server = TLSServerConfig::new(vec![Arc::new(key)]);
    server.config.versions = vec![version];
    (client, server)
}

#[test]
fn ocsp_stapling() {
    for version in [TLSVersion::TLS1_3, TLSVersion::TLS1_2] {
        // The response reaches the client, which the verifier checks.
        let (client, server) = stapling(version, Some("ocsp-good"));
        let mut pair = Pair::new(client.clone(), server.clone(), Some("server.example"));
        pair.run().unwrap_or_else(|error| panic!("{version:?}: {error:?}"));
        assert_eq!(pair.client.session.certificate_status, Some(Fixture::certificate("ocsp-good")), "{version:?}");
        pair.echo(b"stapled");
        // Not asked for: not sent.
        let mut quiet = client.clone();
        quiet.request_certificate_status = false;
        let mut pair = Pair::new(quiet, server, Some("server.example"));
        pair.run().unwrap();
        assert_eq!(pair.client.session.certificate_status, None);
        // Asked for, but the server has none: the handshake goes on (RFC 6066 §8).
        let (client, server) = stapling(version, None);
        let mut pair = Pair::new(client, server, Some("server.example"));
        pair.run().unwrap();
        assert_eq!(pair.client.session.certificate_status, None);
    }
}

#[cfg(feature = "auth-cert-ocsp")]
#[test]
fn stapled_responses_are_checked() {
    for version in [TLSVersion::TLS1_3, TLSVersion::TLS1_2] {
        for (response, alert) in [
            ("ocsp-revoked", TLSAlertDescription::CERTIFICATE_REVOKED),
            ("ocsp-other", TLSAlertDescription::BAD_CERTIFICATE_STATUS_RESPONSE),
            ("root", TLSAlertDescription::BAD_CERTIFICATE_STATUS_RESPONSE),
        ] {
            let (client, server) = stapling(version, Some(response));
            let mut pair = Pair::new(client, server, Some("server.example"));
            assert_eq!(pair.run(), Err((true, TLSError::Protocol(alert))), "{version:?} {response}");
        }
    }
}

#[test]
fn rules_route_by_name_and_protocol() {
    use umilib::protocol::tls::{TLSNamePattern, TLSRule};
    use umilib::service::Rule;
    // Before the handshake, the ClientHello's server_name and offered protocols.
    let mut config = Fixture::client_config();
    config.config.protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut client =
        TLSConnection::client(Arc::new(config), Some("Api.Example.COM."), Fixture::random(1), TIME).unwrap();
    let record = take(&mut client);
    let message = umilib::protocol::tls::TLSHandshake::decode(&record[5..], 1 << 16).unwrap().unwrap().0;
    let hello = umilib::protocol::tls::TLSClientHello::decode(&message.body).unwrap();
    assert!(TLSRule::new(TLSNamePattern::parse("api.example.com")).matches(&hello));
    assert!(TLSRule::new(TLSNamePattern::parse("*.example.com")).matches(&hello));
    assert!(TLSRule::new(TLSNamePattern::parse("*.example.com")).with_protocol(b"h2").matches(&hello));
    assert!(!TLSRule::new(TLSNamePattern::parse("*.example.com")).with_protocol(b"h3").matches(&hello));
    assert!(!TLSRule::new(TLSNamePattern::parse("*.com")).matches(&hello), "one label only");
    assert!(!TLSRule::new(TLSNamePattern::parse("example.com")).matches(&hello));
    assert!(!TLSRule::new(TLSNamePattern::None).matches(&hello));
    assert!(TLSRule::new(TLSNamePattern::parse("*")).matches(&hello));
    // After it, the session's name and negotiated protocol.
    let mut client = Fixture::client_config();
    client.config.protocols = vec![b"h2".to_vec()];
    let mut server = Fixture::server_config("server-p256");
    server.config.protocols = vec![b"h2".to_vec()];
    let mut pair = Pair::new(client, server, Some("server.example"));
    pair.run().unwrap();
    assert!(TLSRule::new(TLSNamePattern::parse("server.example")).with_protocol(b"h2").matches(&pair.server.session));
    assert!(!TLSRule::new(TLSNamePattern::parse("server.example")).with_protocol(b"h3").matches(&pair.server.session));
    // A client of an address sends no name.
    let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some("127.0.0.1"));
    pair.run().unwrap();
    assert!(TLSRule::new(TLSNamePattern::None).matches(&pair.server.session));
    assert!(!TLSRule::new(TLSNamePattern::parse("server.example")).matches(&pair.server.session));
}
