//! The rules of RFC 9846 §5, §6.1 and Appendix E.3, RFC 5246 §6.2.1 and
//! RFC 9849 §6.1.6 at the edges of a connection: records that share
//! messages, records after closing, protected ChangeCipherSpecs, records
//! that change nothing, early data around HelloRetryRequests and record
//! limits, and what a session shows before the server is authenticated.

use std::sync::Arc;

use umilib::protocol::tls::{
    TLSAlert, TLSAlertDescription, TLSAlertLevel, TLSContentType, TLSEarlyData, TLSError, TLSNamedGroup,
    TLSSessionCache, TLSSignatureScheme, TLSVersion,
};

use super::handshake::{Fixture, Pair, TIME, take};
use super::resumption::Resumption;
use super::v1_2::TLS12;

/// The records of `bytes`: content type and fragment.
fn records(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut found = Vec::new();
    let mut rest = bytes;
    while rest.len() >= 5 {
        let length = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        found.push((rest[0], rest[5..5 + length].to_vec()));
        rest = &rest[5 + length..];
    }
    found
}

fn record(content_type: u8, fragment: &[u8]) -> Vec<u8> {
    let mut record = vec![content_type, 3, 3];
    record.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
    record.extend_from_slice(fragment);
    record
}

#[test]
fn a_tls_1_2_flight_in_one_record() {
    // RFC 5246 §6.2.1: messages of one type may share a record. The flight of
    // a TLS 1.2 server in one record reads as in four.
    let mut pair = Pair::new(TLS12::client(), TLS12::server("server-p256"), Some("server.example"));
    pair.server.receive(&take(&mut pair.client)).unwrap();
    let flight = records(&take(&mut pair.server));
    assert!(flight.len() >= 4 && flight.iter().all(|(content_type, _)| *content_type == 22));
    let joined: Vec<u8> = flight.iter().flat_map(|(_, fragment)| fragment.clone()).collect();
    pair.client.receive(&record(22, &joined)).unwrap();
    pair.run().unwrap();
    pair.echo(b"one record");
    // In TLS 1.3 the ServerHello ends its record (RFC 9846 §5.1).
    let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some("server.example"));
    pair.server.receive(&take(&mut pair.client)).unwrap();
    let flight = records(&take(&mut pair.server));
    let mut joined = flight[0].1.clone();
    joined.extend_from_slice(&[0x08, 0, 0, 2, 0, 0]);
    assert_eq!(
        pair.client.receive(&record(22, &joined)),
        Err(TLSError::Protocol(TLSAlertDescription::UNEXPECTED_MESSAGE))
    );
}

#[test]
fn closing() {
    // RFC 9846 §6.1: what follows close_notify is ignored, and nothing
    // follows one's own close_notify: neither a KeyUpdate nor an alert.
    let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some("server.example"));
    pair.run().unwrap();
    pair.client.close().unwrap();
    pair.server.update_keys(true).unwrap();
    let request = take(&mut pair.server);
    pair.server.receive(&take(&mut pair.client)).unwrap();
    pair.server.receive(&[23, 3, 3, 0, 5, 1, 2, 3, 4, 5]).unwrap();
    pair.client.receive(&request).unwrap();
    assert!(take(&mut pair.client).is_empty(), "no KeyUpdate after close_notify");
    assert!(pair.client.receive(&[23, 3, 3, 0, 5, 1, 2, 3, 4, 5]).is_err());
    assert!(take(&mut pair.client).is_empty(), "no alert after close_notify");
}

#[test]
fn protected_change_cipher_specs_are_refused() {
    // RFC 9846 §5: a ChangeCipherSpec under protection is unexpected_message.
    let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some("server.example"));
    pair.run().unwrap();
    let mut bytes = Vec::new();
    pair.server.layer.writer.as_mut().unwrap().seal(TLSContentType::CHANGE_CIPHER_SPEC, &[1], &mut bytes).unwrap();
    assert_eq!(pair.client.receive(&bytes), Err(TLSError::Protocol(TLSAlertDescription::UNEXPECTED_MESSAGE)));
}

#[test]
fn records_that_change_nothing_are_counted() {
    // Warning alerts are dropped (RFC 9846 §6.1), but not without end: more
    // than maximum_ignored_records in a row, without data, fail.
    let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some("server.example"));
    pair.run().unwrap();
    let mut alert = Vec::new();
    TLSAlert { level: TLSAlertLevel::WARNING, description: TLSAlertDescription::USER_CANCELED }
        .encode(&mut alert)
        .unwrap();
    for _ in 0..20 {
        pair.server.layer.write(TLSContentType::ALERT, &alert).unwrap();
    }
    pair.run().unwrap();
    pair.echo(b"data resets the count");
    for _ in 0..20 {
        pair.server.layer.write(TLSContentType::ALERT, &alert).unwrap();
    }
    pair.run().unwrap();
    for _ in 0..20 {
        pair.server.layer.write(TLSContentType::ALERT, &alert).unwrap();
    }
    assert_eq!(pair.run(), Err((true, TLSError::Protocol(TLSAlertDescription::UNEXPECTED_MESSAGE))));
}

#[test]
fn early_data_and_tls_1_2() {
    // RFC 9846 Appendix E.3: a client that sent early data fails when the
    // server chooses TLS 1.2.
    let cache = Arc::new(TLSSessionCache::new(8));
    let (client, server) = Resumption::early(&cache);
    Resumption::first(&client, &server);
    let mut older = server.clone();
    older.config.versions = vec![TLSVersion::TLS1_2];
    let mut pair = Resumption::pair(&client, &older, "server.example", 2, TIME);
    pair.client.send(b"early").unwrap();
    // The ClientHello alone: a server of TLS 1.2 would fail on the early data.
    let flight = take(&mut pair.client);
    let hello = 5 + u16::from_be_bytes([flight[3], flight[4]]) as usize;
    pair.server.receive(&flight[..hello]).unwrap();
    assert_eq!(
        pair.client.receive(&take(&mut pair.server)),
        Err(TLSError::Protocol(TLSAlertDescription::PROTOCOL_VERSION))
    );
}

#[test]
fn large_early_data() {
    // Early data in records of 2^14 bytes, refused after a HelloRetryRequest,
    // or accepted by a server whose record_size_limit the client has not seen
    // (RFC 9846 §4.2.10, RFC 8449 §4).
    let cache = Arc::new(TLSSessionCache::new(8));
    let (mut client, mut server) = Resumption::early(&cache);
    server.maximum_early_data = 1 << 15;
    client.config.groups = vec![TLSNamedGroup::X25519, TLSNamedGroup::SECP384R1];
    client.key_share_groups = vec![TLSNamedGroup::X25519];
    Resumption::first(&client, &server);
    let mut retrying = server.clone();
    retrying.config.groups = vec![TLSNamedGroup::SECP384R1];
    let mut pair = Resumption::pair(&client, &retrying, "server.example", 2, TIME);
    pair.client.send(&[7; 1 << 14]).unwrap();
    pair.run().unwrap();
    assert_eq!(pair.client.session.early_data, TLSEarlyData::Rejected);
    pair.echo(b"after the retry");
    let mut limited = server.clone();
    limited.config.record_size_limit = 512;
    let mut pair = Resumption::pair(&client, &limited, "server.example", 3, TIME);
    pair.client.send(&[7; 1 << 14]).unwrap();
    pair.run().unwrap();
    assert_eq!(pair.server.session.early_data, TLSEarlyData::Accepted);
    assert_eq!(pair.server.readable(), 1 << 14);
    assert_eq!(pair.server.layer.own_limit, 512, "the limit holds after the early data");
    // The ticket's allowance holds though the server now allows less (RFC 9846 §4.6.1).
    let mut stricter = server.clone();
    stricter.maximum_early_data = 1024;
    let mut pair = Resumption::pair(&client, &stricter, "server.example", 4, TIME);
    pair.client.send(&[7; 4096]).unwrap();
    pair.run().unwrap();
    assert_eq!(pair.server.readable(), 4096);
}

#[cfg(feature = "crypto-hpke")]
#[test]
fn ech_rejection_shows_once_authenticated() {
    // RFC 9849 §6.1.6: retry configurations are used only when the server
    // proved it holds the public name; before, the session shows nothing.
    use umilib::protocol::tls::{TLSECHCipher, TLSECHCipherSuite, TLSECHConfig, TLSECHStatus};
    let key = |seed: u8| {
        let template = TLSECHConfig {
            config_id: 1,
            kem_id: TLSECHConfig::DHKEM_X25519,
            public_key: Vec::new(),
            cipher_suites: vec![TLSECHCipherSuite::MANDATORY],
            maximum_name_length: 0,
            public_name: b"public.wild.example".to_vec(),
            extensions: Vec::new(),
        };
        TLSECHCipher::generate(template, true, &mut *Fixture::random(seed)).unwrap()
    };
    let mut client = Fixture::client_config();
    client.ech_configs = vec![key(1).config];
    let mut server = umilib::protocol::tls::TLSServerConfig::new(vec![Fixture::certified("stranger")]);
    server.ech_keys = vec![key(2)];
    let mut pair = Pair::new(client, server.clone(), Some("server.example"));
    assert!(pair.run().is_err());
    assert_eq!(pair.client.session.ech, TLSECHStatus::Offered);
    // ECH keys none of which is for retries cannot work (RFC 9849 §7.1).
    server.ech_keys[0].retry = false;
    assert_eq!(server.check(), Err(TLSError::Config));
}

#[test]
fn servers_sign_with_their_own_schemes() {
    // A server signs only with a scheme of its configuration: with none
    // that its key can use, it has no certificate to offer.
    let mut server = Fixture::server_config("server-p256");
    server.config.signature_schemes = vec![TLSSignatureScheme::ED25519];
    let mut pair = Pair::new(Fixture::client_config(), server, Some("server.example"));
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::HANDSHAKE_FAILURE))));
    // An empty chain cannot work.
    let mut server = Fixture::server_config("server-p256");
    Arc::get_mut(&mut server.certificates[0]).unwrap().chain.clear();
    assert_eq!(server.check(), Err(TLSError::Config));
}

#[test]
fn the_name_asked_for_is_recorded() {
    // The session holds the name the client asked for, though no
    // certificate names it (the certificate is then not acknowledged).
    let mut pair = Pair::new(Fixture::client_config(), Fixture::server_config("server-p256"), Some("unknown.test"));
    assert!(pair.run().is_err());
    assert_eq!(pair.server.session.server_name.as_deref(), Some("unknown.test"));
}

#[test]
fn exporters_refuse_long_contexts() {
    // RFC 5705 §4: the context is <0..2^16-1>.
    let mut pair = Pair::new(TLS12::client(), TLS12::server("server-p256"), Some("server.example"));
    pair.run().unwrap();
    let mut out = [0u8; 16];
    assert!(pair.client.export(b"label", Some(&vec![0; 1 << 16]), &mut out).is_err());
    assert!(pair.client.export(b"label", Some(&vec![0; (1 << 16) - 1]), &mut out).is_ok());
}
