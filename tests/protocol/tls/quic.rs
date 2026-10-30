//! TLS when QUIC carries it (RFC 9001 §4, §8): handshake bytes by
//! encryption level, the secrets handed to QUIC, and the adjustments of the
//! handshake: TLS 1.3 only, ALPN and transport parameters required, no
//! middlebox compatibility mode, no EndOfEarlyData, no KeyUpdate, no
//! post-handshake authentication, and 0-RTT tickets of 0xffffffff.

use std::sync::Arc;

use umilib::protocol::tls::v1_3::{TLS13CertificateRequest, TLS13EncryptedExtensions, TLS13NewSessionTicket};
use umilib::protocol::tls::{
    TLSAlertDescription, TLSClientConfig, TLSClientHello, TLSConnection, TLSContentType, TLSDirection, TLSEarlyData,
    TLSEarlyDataIndication, TLSEncryptionLevel, TLSError, TLSEvent, TLSExtension, TLSExtensionType, TLSHandshake,
    TLSHandshakeType, TLSNamedGroup, TLSServerConfig, TLSSessionCache, TLSSessionStore, TLSTrafficSecret, TLSVersion,
};

use super::handshake::{Fixture, Pair, TIME};
use super::resumption::Resumption;

/// A client and a server whose handshake a perfect QUIC carries.
struct QUICPair {
    client: TLSConnection,
    server: TLSConnection,
    /// Each run of handshake bytes moved: whether the client sent it, and its level.
    flights: Vec<(bool, TLSEncryptionLevel)>,
    client_secrets: Vec<TLSTrafficSecret>,
    server_secrets: Vec<TLSTrafficSecret>,
}

impl QUICPair {
    fn configs() -> (TLSClientConfig, TLSServerConfig) {
        let mut client = Fixture::client_config();
        client.config.protocols = vec![b"h3".to_vec()];
        let mut server = Fixture::server_config("server-p256");
        server.config.protocols = vec![b"doq".to_vec(), b"h3".to_vec()];
        (client, server)
    }

    fn new(client: &TLSClientConfig, server: &TLSServerConfig, seed: u8) -> QUICPair {
        let client = TLSConnection::quic_client(
            Arc::new(client.clone()),
            Some("server.example"),
            b"client parameters".to_vec(),
            Fixture::random(seed),
            TIME,
        )
        .unwrap();
        let server = TLSConnection::quic_server(
            Arc::new(server.clone()),
            b"server parameters".to_vec(),
            Fixture::random(seed + 100),
            TIME,
        )
        .unwrap();
        QUICPair { client, server, flights: Vec::new(), client_secrets: Vec::new(), server_secrets: Vec::new() }
    }

    /// Moves handshake bytes and secrets until neither side has more; the
    /// first error and whether the client met it.
    fn run(&mut self) -> Result<(), (bool, TLSError)> {
        loop {
            self.client_secrets.extend(std::iter::from_fn(|| self.client.take_secret()));
            self.server_secrets.extend(std::iter::from_fn(|| self.server.take_secret()));
            if let Some((level, bytes)) = self.client.take_handshake() {
                self.flights.push((true, level));
                self.server.receive_handshake(level, &bytes).map_err(|error| (false, error))?;
                continue;
            }
            if let Some((level, bytes)) = self.server.take_handshake() {
                self.flights.push((false, level));
                self.client.receive_handshake(level, &bytes).map_err(|error| (true, error))?;
                continue;
            }
            return Ok(());
        }
    }

    fn secret(secrets: &[TLSTrafficSecret], level: TLSEncryptionLevel, direction: TLSDirection) -> &[u8] {
        let found = secrets.iter().find(|secret| secret.level == level && secret.direction == direction);
        found.unwrap_or_else(|| panic!("no {level:?} {direction:?}")).secret.expose()
    }
}

fn hello_of(connection: &mut TLSConnection) -> (Vec<u8>, TLSClientHello) {
    let (level, bytes) = connection.take_handshake().unwrap();
    assert_eq!(level, TLSEncryptionLevel::Initial);
    let hello = TLSClientHello::decode(&bytes[4..]).unwrap();
    (bytes, hello)
}

#[test]
fn a_handshake_by_levels() {
    // RFC 9001 §4.1.5, Figure 5.
    let (client, server) = QUICPair::configs();
    let mut pair = QUICPair::new(&client, &server, 1);
    pair.run().unwrap();
    use TLSEncryptionLevel::{Application, Handshake, Initial};
    assert_eq!(pair.flights, [(true, Initial), (false, Initial), (false, Handshake), (true, Handshake)]);
    assert!(!pair.client.is_handshaking() && !pair.server.is_handshaking());
    assert!(Pair::events(&mut pair.client).contains(&TLSEvent::Connected));
    // Each end's write secret is the other's read secret, at both levels.
    for level in [Handshake, Application] {
        assert_eq!(
            QUICPair::secret(&pair.client_secrets, level, TLSDirection::Writing),
            QUICPair::secret(&pair.server_secrets, level, TLSDirection::Reading),
        );
        assert_eq!(
            QUICPair::secret(&pair.server_secrets, level, TLSDirection::Writing),
            QUICPair::secret(&pair.client_secrets, level, TLSDirection::Reading),
        );
    }
    assert_eq!(pair.client_secrets.len(), 4);
    // The transport parameters of each end reach the other (RFC 9001 §8.2).
    assert_eq!(pair.server.session.transport_parameters.as_deref(), Some(&b"client parameters"[..]));
    assert_eq!(pair.client.session.transport_parameters.as_deref(), Some(&b"server parameters"[..]));
    assert_eq!(pair.client.session.protocol.as_deref(), Some(&b"h3"[..]));
    assert_eq!(pair.client.reading_level(), Some(Application));
    // The exporters agree; nothing is sent as records.
    let (mut one, mut two) = ([0u8; 32], [0u8; 32]);
    pair.client.export(b"label", None, &mut one).unwrap();
    pair.server.export(b"label", None, &mut two).unwrap();
    assert_eq!(one, two);
    assert!(!pair.client.wants_transmit() && !pair.server.wants_transmit());
    // QUIC carries application data and closes the connection (RFC 9001 §4.1.3, §4.8).
    assert_eq!(pair.client.send(b"data"), Err(TLSError::State));
    assert_eq!(pair.client.close(), Err(TLSError::State));
}

#[test]
fn the_client_hello() {
    // RFC 9001 §4.2, §8.2, §8.4: TLS 1.3 only, the transport parameters, an
    // empty session ID; and neither record_size_limit nor post_handshake_auth.
    let (mut client, server) = QUICPair::configs();
    client.post_handshake_authentication = true;
    let mut pair = QUICPair::new(&client, &server, 1);
    let (_, hello) = hello_of(&mut pair.client);
    assert!(hello.legacy_session_id.is_empty());
    assert_eq!(hello.extension(TLSExtensionType::QUIC_TRANSPORT_PARAMETERS), Some(&b"client parameters"[..]));
    assert!(hello.extension(TLSExtensionType::RECORD_SIZE_LIMIT).is_none());
    assert!(hello.extension(TLSExtensionType::POST_HANDSHAKE_AUTH).is_none());
    assert!(hello.cipher_suites.iter().all(|suite| suite.version() == Some(TLSVersion::TLS1_3)));
    let versions = hello.extension(TLSExtensionType::SUPPORTED_VERSIONS).unwrap();
    assert_eq!(versions, [2, 0x03, 0x04]);
}

#[test]
fn configurations_that_cannot_carry_quic() {
    // RFC 9001 §8.1: ALPN; §4.2: TLS 1.3; §5.3: no TLS_AES_128_CCM_8_SHA256.
    let (client, server) = QUICPair::configs();
    let mut none = client.clone();
    none.config.protocols.clear();
    let quic = |config: TLSClientConfig| {
        TLSConnection::quic_client(Arc::new(config), Some("server.example"), Vec::new(), Fixture::random(1), TIME)
    };
    assert_eq!(quic(none).err(), Some(TLSError::Config));
    let mut old = client.clone();
    old.config.versions = vec![TLSVersion::TLS1_2];
    assert_eq!(quic(old).err(), Some(TLSError::Config));
    let mut ccm8 = server.clone();
    ccm8.config.cipher_suites.push(umilib::protocol::tls::TLSCipherSuite::TLS_AES_128_CCM_8_SHA256);
    let made = TLSConnection::quic_server(Arc::new(ccm8), Vec::new(), Fixture::random(2), TIME);
    assert_eq!(made.err(), Some(TLSError::Config));
}

#[test]
fn no_protocol_in_common() {
    // RFC 9001 §8.1: no_application_protocol, QUIC error 0x0178.
    let (mut client, server) = QUICPair::configs();
    client.config.protocols = vec![b"other".to_vec()];
    let mut pair = QUICPair::new(&client, &server, 1);
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::NO_APPLICATION_PROTOCOL))));
    // Nothing is written for the alert: QUIC sends it as CRYPTO_ERROR (RFC 9001 §4.8).
    assert!(pair.server.take_handshake().is_none());
    assert_eq!(pair.server.error, Some(TLSError::Protocol(TLSAlertDescription::NO_APPLICATION_PROTOCOL)));
}

#[test]
fn the_server_requires_transport_parameters_and_no_session_id() {
    let (client, server) = QUICPair::configs();
    // A ClientHello without transport parameters: missing_extension (RFC 9001 §8.2).
    let mut pair = QUICPair::new(&client, &server, 1);
    let (_, mut hello) = hello_of(&mut pair.client);
    hello.extensions.retain(|extension| extension.kind != TLSExtensionType::QUIC_TRANSPORT_PARAMETERS);
    let bytes = TLSHandshake::new(TLSHandshakeType::CLIENT_HELLO, hello.to_bytes().unwrap()).to_bytes().unwrap();
    assert_eq!(
        pair.server.receive_handshake(TLSEncryptionLevel::Initial, &bytes),
        Err(TLSError::Protocol(TLSAlertDescription::MISSING_EXTENSION))
    );
    // A session ID: PROTOCOL_VIOLATION (RFC 9001 §8.4).
    let mut pair = QUICPair::new(&client, &server, 1);
    let (_, mut hello) = hello_of(&mut pair.client);
    hello.legacy_session_id = vec![7; 32];
    let bytes = TLSHandshake::new(TLSHandshakeType::CLIENT_HELLO, hello.to_bytes().unwrap()).to_bytes().unwrap();
    assert_eq!(pair.server.receive_handshake(TLSEncryptionLevel::Initial, &bytes), Err(TLSError::Transport));
    // Over records, the transport parameters are unsupported_extension (RFC 9001 §8.2).
    let mut pair = QUICPair::new(&client, &server, 1);
    let (bytes, _) = hello_of(&mut pair.client);
    let mut tcp = TLSConnection::server(Arc::new(server.clone()), Fixture::random(3), TIME).unwrap();
    let mut record = vec![TLSContentType::HANDSHAKE.0, 3, 1];
    record.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    record.extend_from_slice(&bytes);
    assert_eq!(tcp.receive(&record), Err(TLSError::Protocol(TLSAlertDescription::UNSUPPORTED_EXTENSION)));
}

#[test]
fn the_client_requires_transport_parameters() {
    // EncryptedExtensions without transport parameters: missing_extension
    // (RFC 9001 §8.2). QUIC protects the handshake, so its bytes are plain here.
    let (client, server) = QUICPair::configs();
    let mut pair = QUICPair::new(&client, &server, 1);
    let (bytes, _) = hello_of(&mut pair.client);
    pair.server.receive_handshake(TLSEncryptionLevel::Initial, &bytes).unwrap();
    let (_, hello) = pair.server.take_handshake().unwrap();
    pair.client.receive_handshake(TLSEncryptionLevel::Initial, &hello).unwrap();
    let (level, flight) = pair.server.take_handshake().unwrap();
    assert_eq!((level, flight[0]), (TLSEncryptionLevel::Handshake, TLSHandshakeType::ENCRYPTED_EXTENSIONS.0));
    let length = 4 + u32::from_be_bytes([0, flight[1], flight[2], flight[3]]) as usize;
    let mut extensions = TLS13EncryptedExtensions::decode(&flight[4..length]).unwrap();
    extensions.extensions.retain(|extension| extension.kind != TLSExtensionType::QUIC_TRANSPORT_PARAMETERS);
    let mut changed = TLSHandshake::with(TLSHandshakeType::ENCRYPTED_EXTENSIONS, |body| extensions.encode(body))
        .unwrap()
        .to_bytes()
        .unwrap();
    changed.extend_from_slice(&flight[length..]);
    assert_eq!(
        pair.client.receive_handshake(TLSEncryptionLevel::Handshake, &changed),
        Err(TLSError::Protocol(TLSAlertDescription::MISSING_EXTENSION))
    );
}

#[test]
fn levels_are_checked() {
    // Data at a level TLS does not read is the transport's error (RFC 9001 §4.1.3).
    let (client, server) = QUICPair::configs();
    let mut pair = QUICPair::new(&client, &server, 1);
    let (bytes, _) = hello_of(&mut pair.client);
    assert_eq!(pair.server.receive_handshake(TLSEncryptionLevel::Handshake, &bytes), Err(TLSError::Transport));
    // More bytes at the Initial level than the ClientHello cannot wait for the next level.
    let mut pair = QUICPair::new(&client, &server, 1);
    let (bytes, _) = hello_of(&mut pair.client);
    pair.server.receive_handshake(TLSEncryptionLevel::Initial, &bytes).unwrap();
    let (level, flight) = pair.server.take_handshake().unwrap();
    assert_eq!(level, TLSEncryptionLevel::Initial);
    let mut extra = flight.clone();
    extra.extend_from_slice(&[0x08, 0, 0]);
    assert_eq!(pair.client.receive_handshake(TLSEncryptionLevel::Initial, &extra), Err(TLSError::Transport));
}

#[test]
fn no_key_update_and_no_post_handshake_authentication() {
    let (client, server) = QUICPair::configs();
    let mut pair = QUICPair::new(&client, &server, 1);
    pair.run().unwrap();
    // RFC 9001 §6: no KeyUpdate is sent; one received is 0x010a, unexpected_message.
    assert_eq!(pair.client.update_keys(true), Err(TLSError::State));
    assert_eq!(
        pair.client.receive_handshake(TLSEncryptionLevel::Application, &[24, 0, 0, 1, 0]),
        Err(TLSError::Protocol(TLSAlertDescription::UNEXPECTED_MESSAGE))
    );
    // RFC 9001 §4.4: a post-handshake CertificateRequest is PROTOCOL_VIOLATION.
    let mut pair = QUICPair::new(&client, &server, 1);
    pair.run().unwrap();
    assert_eq!(pair.server.request_certificate(), Err(TLSError::State));
    let schemes = umilib::protocol::tls::TLSSignatureSchemes {
        schemes: vec![umilib::protocol::tls::TLSSignatureScheme::ED25519],
    };
    let request = TLS13CertificateRequest {
        context: vec![1; 8],
        extensions: vec![
            TLSExtension::with(TLSExtensionType::SIGNATURE_ALGORITHMS, |data| schemes.encode(data)).unwrap(),
        ],
    };
    let message = TLSHandshake::with(TLSHandshakeType::CERTIFICATE_REQUEST, |body| request.encode(body)).unwrap();
    assert_eq!(
        pair.client.receive_handshake(TLSEncryptionLevel::Application, &message.to_bytes().unwrap()),
        Err(TLSError::Transport)
    );
}

#[test]
fn zero_rtt() {
    // RFC 9001 §4.6: tickets say 0xffffffff, the client gets the 0-RTT
    // write secret after its ClientHello, the server the read secret, and
    // no EndOfEarlyData is sent (§8.3).
    let cache = Arc::new(TLSSessionCache::new(8));
    let (mut client, mut server) = Resumption::early(&cache);
    let (quic_client, quic_server) = QUICPair::configs();
    client.config.protocols = quic_client.config.protocols;
    server.config.protocols = quic_server.config.protocols;
    let mut first = QUICPair::new(&client, &server, 1);
    first.server.session.application = b"server state".to_vec();
    first.client.session.application = b"remembered".to_vec();
    first.run().unwrap();
    let ticket = cache.take("server.example").unwrap();
    assert_eq!(ticket.state.maximum_early_data, 0xFFFF_FFFF);
    assert_eq!(ticket.state.application, b"remembered");
    cache.put("server.example", ticket);
    let mut second = QUICPair::new(&client, &server, 2);
    // The client finds what it kept with the ticket.
    assert_eq!(second.client.session.application, b"remembered");
    assert_eq!(second.client.session.early_data, TLSEarlyData::Offered);
    second.server.session.application = b"server state".to_vec();
    second.run().unwrap();
    assert_eq!(second.server.session.early_data, TLSEarlyData::Accepted);
    assert_eq!(second.client.session.early_data, TLSEarlyData::Accepted);
    assert_eq!(
        QUICPair::secret(&second.client_secrets, TLSEncryptionLevel::EarlyData, TLSDirection::Writing),
        QUICPair::secret(&second.server_secrets, TLSEncryptionLevel::EarlyData, TLSDirection::Reading),
    );
    assert!(!second.client.is_handshaking() && !second.server.is_handshaking());
    // A server whose state changed refuses 0-RTT (RFC 9001 §4.6.3) but resumes.
    let mut third = QUICPair::new(&client, &server, 3);
    third.server.session.application = b"other state".to_vec();
    third.run().unwrap();
    assert!(third.server.session.resumed);
    assert_eq!(third.client.session.early_data, TLSEarlyData::Rejected);
}

#[test]
fn tickets_of_other_early_data_sizes() {
    // RFC 9001 §4.6.1: a NewSessionTicket whose early_data is not
    // 0xffffffff is PROTOCOL_VIOLATION.
    let cache = Arc::new(TLSSessionCache::new(8));
    let (mut client, _) = Resumption::configs(&cache);
    client.config.protocols = vec![b"h3".to_vec()];
    let (_, server) = QUICPair::configs();
    let mut pair = QUICPair::new(&client, &server, 1);
    pair.run().unwrap();
    let indication = TLSEarlyDataIndication(1024);
    let ticket = TLS13NewSessionTicket {
        lifetime: 60,
        age_add: 0,
        nonce: vec![0],
        ticket: vec![1, 2, 3],
        extensions: vec![TLSExtension::with(TLSExtensionType::EARLY_DATA, |data| indication.encode(data)).unwrap()],
    };
    let message = TLSHandshake::with(TLSHandshakeType::NEW_SESSION_TICKET, |body| ticket.encode(body)).unwrap();
    assert_eq!(
        pair.client.receive_handshake(TLSEncryptionLevel::Application, &message.to_bytes().unwrap()),
        Err(TLSError::Transport)
    );
}

#[test]
fn tickets_with_no_early_data_size() {
    // RFC 9001 §4.6.1: an early_data extension of any value but
    // 0xffffffff, 0 included, is PROTOCOL_VIOLATION; none at all is fine.
    let cache = Arc::new(TLSSessionCache::new(8));
    let (mut client, _) = Resumption::configs(&cache);
    client.config.protocols = vec![b"h3".to_vec()];
    let (_, server) = QUICPair::configs();
    let ticket = |extensions: Vec<TLSExtension>| {
        let ticket =
            TLS13NewSessionTicket { lifetime: 60, age_add: 0, nonce: vec![0], ticket: vec![1, 2, 3], extensions };
        TLSHandshake::with(TLSHandshakeType::NEW_SESSION_TICKET, |body| ticket.encode(body))
            .unwrap()
            .to_bytes()
            .unwrap()
    };
    let mut pair = QUICPair::new(&client, &server, 1);
    pair.run().unwrap();
    let zero = TLSExtension::with(TLSExtensionType::EARLY_DATA, |data| TLSEarlyDataIndication(0).encode(data)).unwrap();
    assert_eq!(
        pair.client.receive_handshake(TLSEncryptionLevel::Application, &ticket(vec![zero])),
        Err(TLSError::Transport)
    );
    let mut pair = QUICPair::new(&client, &server, 1);
    pair.run().unwrap();
    pair.client.receive_handshake(TLSEncryptionLevel::Application, &ticket(Vec::new())).unwrap();
}

#[test]
fn a_second_client_hello_keeps_the_transport_parameters() {
    // RFC 9846 §4.1.2: the ClientHello after a HelloRetryRequest changes
    // only what it lists, which quic_transport_parameters is not.
    let (mut client, mut server) = QUICPair::configs();
    client.config.groups = vec![TLSNamedGroup::X25519, TLSNamedGroup::SECP384R1];
    client.key_share_groups = vec![TLSNamedGroup::X25519];
    server.config.groups = vec![TLSNamedGroup::SECP384R1];
    let retried = |change: bool| {
        let mut pair = QUICPair::new(&client, &server, 1);
        let (bytes, _) = hello_of(&mut pair.client);
        pair.server.receive_handshake(TLSEncryptionLevel::Initial, &bytes).unwrap();
        let (_, retry) = pair.server.take_handshake().unwrap();
        pair.client.receive_handshake(TLSEncryptionLevel::Initial, &retry).unwrap();
        let (bytes, mut hello) = hello_of(&mut pair.client);
        let bytes = if change {
            for extension in &mut hello.extensions {
                if extension.kind == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS {
                    extension.data = b"other parameters".to_vec();
                }
            }
            TLSHandshake::new(TLSHandshakeType::CLIENT_HELLO, hello.to_bytes().unwrap()).to_bytes().unwrap()
        } else {
            bytes
        };
        pair.server.receive_handshake(TLSEncryptionLevel::Initial, &bytes)
    };
    assert_eq!(retried(false), Ok(()));
    assert_eq!(retried(true), Err(TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER)));
}

#[test]
fn no_records_and_no_hello_request() {
    // RFC 9001 §4.1.3: QUIC carries no TLS records; §4.2: TLS 1.3 only, so
    // a HelloRequest is unexpected_message, not a TLS 1.2 request to ignore.
    let (client, server) = QUICPair::configs();
    let mut pair = QUICPair::new(&client, &server, 1);
    assert_eq!(pair.server.receive(&[22, 3, 3, 0, 0]), Err(TLSError::State));
    let (bytes, _) = hello_of(&mut pair.client);
    pair.server.receive_handshake(TLSEncryptionLevel::Initial, &bytes).unwrap();
    let request = TLSHandshake::new(TLSHandshakeType::HELLO_REQUEST, Vec::new()).to_bytes().unwrap();
    assert_eq!(
        pair.client.receive_handshake(TLSEncryptionLevel::Initial, &request),
        Err(TLSError::Protocol(TLSAlertDescription::UNEXPECTED_MESSAGE))
    );
}
