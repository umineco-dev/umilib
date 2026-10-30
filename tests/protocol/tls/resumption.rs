//! Resumption with tickets and early data in TLS 1.3 (RFC 9846 §2.2, §2.3,
//! §4.2.10, §4.2.11, §4.6.1, §8) between this crate's client and server.

use std::sync::Arc;

use umilib::protocol::tls::{
    TLSAlertDescription, TLSAntiReplay, TLSClientConfig, TLSClientHello, TLSConnection, TLSEarlyData, TLSError,
    TLSEvent, TLSExtensionType, TLSHandshake, TLSHandshakeType, TLSNamedGroup, TLSPSKMode, TLSReplayCache,
    TLSServerConfig, TLSSessionCache, TLSSessionState, TLSSessionStore, TLSSessionTicket, TLSTicketKey, TLSTicketKeys,
    TLSTicketer, TLSVersion,
};
use umilib::secret::Secret;

use super::handshake::{Fixture, Pair, TIME, take};

pub struct Resumption;

impl Resumption {
    pub fn keys(name: u8) -> Arc<TLSTicketKeys> {
        Arc::new(TLSTicketKeys::new(vec![TLSTicketKey::new([name; 16], &[name; 32]).unwrap()]))
    }

    /// A client that keeps tickets in `cache`, and a server that makes them.
    pub fn configs(cache: &Arc<TLSSessionCache>) -> (TLSClientConfig, TLSServerConfig) {
        let mut client = Fixture::client_config();
        client.sessions = Some(cache.clone());
        let mut server = Fixture::server_config("server-p256");
        server.tickets = Some(Resumption::keys(1));
        (client, server)
    }

    /// The configurations of 0-RTT: early data sent, and accepted up to 1024 bytes.
    pub fn early(cache: &Arc<TLSSessionCache>) -> (TLSClientConfig, TLSServerConfig) {
        let (mut client, mut server) = Resumption::configs(cache);
        client.early_data = true;
        server.maximum_early_data = 1024;
        server.anti_replay = Some(Arc::new(TLSReplayCache::new(10, 64)));
        (client, server)
    }

    /// A pair whose randomness is seeded by `seed`, at `time`.
    pub fn pair(client: &TLSClientConfig, server: &TLSServerConfig, name: &str, seed: u8, time: i64) -> Pair {
        let client = TLSConnection::client(Arc::new(client.clone()), Some(name), Fixture::random(seed), time).unwrap();
        let server = TLSConnection::server(Arc::new(server.clone()), Fixture::random(seed + 100), time).unwrap();
        Pair { client, server }
    }

    /// A handshake that leaves its tickets in the cache.
    pub fn first(client: &TLSClientConfig, server: &TLSServerConfig) {
        let mut pair = Resumption::pair(client, server, "server.example", 1, TIME);
        pair.run().unwrap();
    }
}

#[test]
fn tickets_resume_sessions() {
    let cache = Arc::new(TLSSessionCache::new(8));
    let (client, server) = Resumption::configs(&cache);
    Resumption::first(&client, &server);
    // Two tickets by default, each of its own PSK (RFC 9846 §4.6.1).
    assert_eq!(cache.tickets.lock().len(), 2);
    let mut pair = Resumption::pair(&client, &server, "server.example", 2, TIME + 60);
    pair.run().unwrap();
    for connection in [&pair.client, &pair.server] {
        assert!(connection.session.resumed);
        assert_eq!(connection.session.version, Some(TLSVersion::TLS1_3));
        // psk_dhe_ke by default: forward secrecy (RFC 9846 §4.3.9).
        assert!(connection.session.group.is_some());
    }
    // No certificates were sent; the session keeps the server's.
    assert_eq!(pair.client.session.peer_certificates, [Fixture::certificate("server-p256")]);
    pair.echo(b"resumed");
    let (mut client_key, mut server_key) = ([0u8; 16], [0u8; 16]);
    pair.client.export(b"EXPORTER-test", None, &mut client_key).unwrap();
    pair.server.export(b"EXPORTER-test", None, &mut server_key).unwrap();
    assert_eq!(client_key, server_key);
    // One ticket was used and two more came.
    assert_eq!(cache.tickets.lock().len(), 3);
}

#[test]
fn psk_only_key_exchange() {
    // psk_ke: no key share at all (RFC 9846 §4.2.9).
    let cache = Arc::new(TLSSessionCache::new(8));
    let (mut client, mut server) = Resumption::configs(&cache);
    client.config.psk_modes = vec![TLSPSKMode::PSK_KE];
    server.config.psk_modes = vec![TLSPSKMode::PSK_KE];
    Resumption::first(&client, &server);
    let mut pair = Resumption::pair(&client, &server, "server.example", 2, TIME);
    pair.run().unwrap();
    assert!(pair.client.session.resumed && pair.server.session.resumed);
    assert_eq!((pair.client.session.group, pair.server.session.group), (None, None));
    pair.echo(b"without a key share");
    // A server that allows only psk_dhe_ke does a full handshake instead.
    let mut strict = server.clone();
    strict.config.psk_modes = vec![TLSPSKMode::PSK_DHE_KE];
    let mut pair = Resumption::pair(&client, &strict, "server.example", 3, TIME);
    pair.run().unwrap();
    assert!(!pair.client.session.resumed);
}

#[test]
fn early_data_is_accepted_once() {
    let cache = Arc::new(TLSSessionCache::new(8));
    let (client, server) = Resumption::early(&cache);
    Resumption::first(&client, &server);
    let mut pair = Resumption::pair(&client, &server, "server.example", 2, TIME + 5);
    assert_eq!(pair.client.session.early_data, TLSEarlyData::Offered);
    pair.client.send(b"early").unwrap();
    // No more than the ticket allows.
    assert_eq!(pair.client.send(&[0; 1020]), Err(TLSError::State));
    let flight = take(&mut pair.client);
    pair.server.receive(&flight).unwrap();
    assert_eq!(pair.server.session.early_data, TLSEarlyData::Accepted);
    // The server reads the early data before the handshake completes.
    let mut read = [0u8; 5];
    assert_eq!(pair.server.read(&mut read), 5);
    assert_eq!(&read, b"early");
    pair.run().unwrap();
    assert_eq!(pair.client.session.early_data, TLSEarlyData::Accepted);
    assert!(Pair::events(&mut pair.client).contains(&TLSEvent::Connected));
    Pair::events(&mut pair.server);
    pair.echo(b"after 0-RTT");
    // The same flight to another server of the same anti-replay: the early
    // data is refused and skipped; the handshake goes on (RFC 9846 §8).
    let mut replayed = TLSConnection::server(Arc::new(server.clone()), Fixture::random(9), TIME + 5).unwrap();
    replayed.receive(&flight).unwrap();
    assert!(replayed.session.resumed);
    assert_eq!(replayed.session.early_data, TLSEarlyData::Rejected);
    assert_eq!(replayed.readable(), 0);
}

#[test]
fn early_data_can_be_refused() {
    let cache = Arc::new(TLSSessionCache::new(8));
    let (client, server) = Resumption::early(&cache);
    Resumption::first(&client, &server);
    // A server that no longer takes early data resumes without it; the
    // client learns it must send the data again (RFC 9846 §4.2.10).
    let mut refusing = server.clone();
    refusing.maximum_early_data = 1024;
    refusing.anti_replay = Some(Arc::new(Refusing));
    let mut pair = Resumption::pair(&client, &refusing, "server.example", 2, TIME);
    pair.client.send(b"early, refused").unwrap();
    pair.run().unwrap();
    assert!(pair.client.session.resumed);
    assert_eq!(pair.client.session.early_data, TLSEarlyData::Rejected);
    assert_eq!(pair.server.session.early_data, TLSEarlyData::Rejected);
    assert_eq!(pair.server.readable(), 0);
    pair.echo(b"sent again");
    // A ticket used too late for its age: not fresh, so no early data (RFC 9846 §8.3).
    Resumption::first(&client, &server);
    let mut pair = Resumption::pair(&client, &server, "server.example", 3, TIME);
    let flight = {
        pair.client.send(b"late").unwrap();
        take(&mut pair.client)
    };
    let mut late = TLSConnection::server(Arc::new(server.clone()), Fixture::random(8), TIME + 60).unwrap();
    late.receive(&flight).unwrap();
    assert!(late.session.resumed);
    assert_eq!(late.session.early_data, TLSEarlyData::Rejected);
    assert_eq!(late.readable(), 0);
}

/// An anti-replay that accepts nothing.
struct Refusing;

impl TLSAntiReplay for Refusing {
    fn accept(&self, _binder: &[u8], _time: i64) -> bool {
        false
    }
}

#[test]
fn hello_retry_requests_and_resumption() {
    // After a HelloRetryRequest the PSK is offered again with a new binder,
    // and early data is given up (RFC 9846 §4.1.2, §4.2.10).
    let cache = Arc::new(TLSSessionCache::new(8));
    let (mut client, mut server) = Resumption::early(&cache);
    client.config.groups = vec![TLSNamedGroup::X25519, TLSNamedGroup::SECP384R1];
    client.key_share_groups = vec![TLSNamedGroup::X25519];
    server.config.groups = vec![TLSNamedGroup::SECP384R1];
    Resumption::first(&client, &server);
    let mut pair = Resumption::pair(&client, &server, "server.example", 2, TIME);
    pair.client.send(b"early, then retried").unwrap();
    pair.run().unwrap();
    assert!(pair.client.session.resumed && pair.server.session.resumed);
    assert_eq!(pair.client.session.group, Some(TLSNamedGroup::SECP384R1));
    assert_eq!(pair.client.session.early_data, TLSEarlyData::Rejected);
    assert_eq!(pair.server.readable(), 0);
    pair.echo(b"after the retry");
}

#[test]
fn tickets_that_do_not_resume() {
    let cache = Arc::new(TLSSessionCache::new(8));
    let (client, server) = Resumption::configs(&cache);
    // Expired (RFC 9846 §4.6.1): not offered.
    Resumption::first(&client, &server);
    let mut pair = Resumption::pair(&client, &server, "server.example", 2, TIME + 7200);
    pair.run().unwrap();
    assert!(!pair.client.session.resumed);
    // Of another server's keys: a full handshake.
    let mut other = server.clone();
    other.tickets = Some(Resumption::keys(2));
    let mut pair = Resumption::pair(&client, &other, "server.example", 3, TIME);
    pair.run().unwrap();
    assert!(!pair.client.session.resumed && !pair.server.session.resumed);
    // For another name: a full handshake.
    let ticket = cache.take("server.example").unwrap();
    cache.put("host.wild.example", ticket);
    let mut pair = Resumption::pair(&client, &server, "host.wild.example", 4, TIME);
    pair.run().unwrap();
    assert!(!pair.server.session.resumed);
    // A server without tickets: none sent, none kept.
    let empty = Arc::new(TLSSessionCache::new(8));
    let (client, mut server) = Resumption::configs(&empty);
    server.tickets = None;
    Resumption::first(&client, &server);
    assert_eq!(empty.tickets.lock().len(), 0);
    // TLS 1.2 has no tickets here.
    let (mut client, mut server) = Resumption::configs(&empty);
    client.config.versions = vec![TLSVersion::TLS1_2];
    server.config.versions = vec![TLSVersion::TLS1_2];
    Resumption::first(&client, &server);
    assert_eq!(empty.tickets.lock().len(), 0);
}

#[test]
fn binders_are_checked() {
    let cache = Arc::new(TLSSessionCache::new(8));
    let (client, server) = Resumption::configs(&cache);
    Resumption::first(&client, &server);
    let mut pair = Resumption::pair(&client, &server, "server.example", 2, TIME);
    let mut hello = take(&mut pair.client);
    // The binder ends the ClientHello (RFC 9846 §4.3.11): decrypt_error.
    let last = hello.len() - 1;
    hello[last] ^= 1;
    assert_eq!(pair.server.receive(&hello), Err(TLSError::Protocol(TLSAlertDescription::DECRYPT_ERROR)));
    // A PSK without psk_key_exchange_modes: missing_extension (RFC 9846 §4.2.9).
    hello[last] ^= 1;
    let message = TLSHandshake::decode(&hello[5..], 1 << 16).unwrap().unwrap().0;
    let mut decoded = TLSClientHello::decode(&message.body).unwrap();
    decoded.extensions.retain(|extension| extension.kind != TLSExtensionType::PSK_KEY_EXCHANGE_MODES);
    let message = TLSHandshake::new(TLSHandshakeType::CLIENT_HELLO, decoded.to_bytes().unwrap()).to_bytes().unwrap();
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(message.len() as u16).to_be_bytes());
    record.extend_from_slice(&message);
    let mut server = TLSConnection::server(Arc::new(server), Fixture::random(5), TIME).unwrap();
    assert_eq!(server.receive(&record), Err(TLSError::Protocol(TLSAlertDescription::MISSING_EXTENSION)));
}

#[test]
fn client_certificates_are_resumed() {
    let cache = Arc::new(TLSSessionCache::new(8));
    let (mut client, mut server) = Resumption::configs(&cache);
    client.certificate = Some(Fixture::certified("client"));
    server.client_authentication = umilib::protocol::tls::TLSClientAuthentication::Required;
    server.client_verifier =
        Some(Arc::new(umilib::protocol::tls::TLSPathVerifier::clients(vec![Fixture::anchor("root")])));
    Resumption::first(&client, &server);
    let mut pair = Resumption::pair(&client, &server, "server.example", 2, TIME);
    pair.run().unwrap();
    assert!(pair.server.session.resumed);
    assert_eq!(pair.server.session.peer_certificates, [Fixture::certificate("client")]);
}

#[test]
fn session_states_and_tickets() {
    let state = TLSSessionState {
        version: TLSVersion::TLS1_3,
        cipher_suite: umilib::protocol::tls::TLSCipherSuite::TLS_AES_256_GCM_SHA384,
        psk: Secret::new(vec![7; 48]),
        time: TIME,
        lifetime: 3600,
        age_add: 0xFFFF_FF00,
        maximum_early_data: 1024,
        protocol: Some(b"h2".to_vec()),
        server_name: Some("server.example".into()),
        peer_certificates: vec![vec![1, 2, 3]],
        application: b"settings".to_vec(),
    };
    let mut bytes = Vec::new();
    state.encode(&mut bytes).unwrap();
    let decoded = TLSSessionState::decode(&bytes).unwrap();
    assert_eq!(decoded.psk.expose(), state.psk.expose());
    assert_eq!(
        (decoded.cipher_suite, decoded.time, decoded.lifetime, decoded.age_add, decoded.maximum_early_data),
        (state.cipher_suite, state.time, state.lifetime, state.age_add, state.maximum_early_data)
    );
    assert_eq!((&decoded.protocol, &decoded.server_name), (&state.protocol, &state.server_name));
    assert_eq!(decoded.application, state.application);
    assert_eq!(decoded.peer_certificates, state.peer_certificates);
    // RFC 9846 §4.6.1: current for its lifetime; the age is obfuscated by age_add modulo 2^32.
    assert!(state.is_current(TIME) && state.is_current(TIME + 3599) && !state.is_current(TIME + 3600));
    assert!(!state.is_current(TIME - 1));
    assert_eq!(state.obfuscated_age(TIME + 2), 0xFFFF_FF00u32.wrapping_add(2000));
    assert!(state.is_fresh(state.obfuscated_age(TIME + 2), TIME + 2, 0));
    assert!(state.is_fresh(state.obfuscated_age(TIME + 2), TIME + 12, 10));
    assert!(!state.is_fresh(state.obfuscated_age(TIME + 2), TIME + 13, 10));
    // Sealed tickets open only with their key, and not once altered; a
    // rotation keeps the old key to open.
    let mut random = Fixture::random(3);
    let old = Resumption::keys(1);
    let ticket = old.seal(&bytes, &mut *random).unwrap();
    assert_eq!(old.open(&ticket).unwrap(), bytes);
    assert_eq!(Resumption::keys(2).open(&ticket), None);
    let mut altered = ticket.clone();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    assert_eq!(old.open(&altered), None);
    let rotated = TLSTicketKeys::new(vec![
        TLSTicketKey::new([2; 16], &[2; 32]).unwrap(),
        TLSTicketKey::new([1; 16], &[1; 32]).unwrap(),
    ]);
    assert_eq!(rotated.open(&ticket).unwrap(), bytes);
    assert_eq!(&rotated.seal(&bytes, &mut *random).unwrap()[..16], &[2; 16]);
}

#[test]
fn replay_caches() {
    // ClientHello recording (RFC 9846 §8.2): each binder once while a replay
    // could still be fresh (§8.3). A ClientHello up to `window` seconds early
    // stays fresh until `window` seconds late, so the record covers twice the
    // window, and a second for whole seconds.
    let cache = TLSReplayCache::new(10, 2);
    assert!(cache.accept(b"first", TIME));
    assert!(!cache.accept(b"first", TIME + 5));
    assert!(!cache.accept(b"first", TIME + 22));
    assert!(cache.accept(b"second", TIME + 5));
    // Full: refused, which is always safe.
    assert!(!cache.accept(b"third", TIME + 5));
    // Past the record the binders are forgotten.
    assert!(cache.accept(b"third", TIME + 23));
    assert!(cache.accept(b"first", TIME + 28));
    // The session cache: the newest ticket of a name, once; the oldest of
    // all goes when it is full.
    let sessions = TLSSessionCache::new(2);
    let ticket = |byte: u8| TLSSessionTicket {
        ticket: vec![byte],
        state: TLSSessionState {
            version: TLSVersion::TLS1_3,
            cipher_suite: umilib::protocol::tls::TLSCipherSuite::TLS_AES_128_GCM_SHA256,
            psk: Secret::new(vec![byte; 32]),
            time: TIME,
            lifetime: 60,
            age_add: 0,
            maximum_early_data: 0,
            protocol: None,
            server_name: None,
            peer_certificates: Vec::new(),
            application: Vec::new(),
        },
    };
    sessions.put("a.example", ticket(1));
    sessions.put("a.example", ticket(2));
    sessions.put("b.example", ticket(3));
    assert_eq!(sessions.take("a.example").map(|ticket| ticket.ticket), Some(vec![2]));
    assert!(sessions.take("a.example").is_none(), "ticket 1 was dropped when the cache was full");
    assert_eq!(sessions.take("b.example").map(|ticket| ticket.ticket), Some(vec![3]));
}

#[test]
fn resumption_needs_what_the_server_requires() {
    // A ticket of a session without a client certificate does not resume
    // with a server that now requires one: the full handshake asks for it.
    let cache = Arc::new(TLSSessionCache::new(8));
    let (client, mut server) = Resumption::configs(&cache);
    server.client_verifier =
        Some(Arc::new(umilib::protocol::tls::TLSPathVerifier::clients(vec![Fixture::anchor("root")])));
    server.client_authentication = umilib::protocol::tls::TLSClientAuthentication::Optional;
    Resumption::first(&client, &server);
    server.client_authentication = umilib::protocol::tls::TLSClientAuthentication::Required;
    let mut pair = Resumption::pair(&client, &server, "server.example", 2, TIME);
    assert_eq!(pair.run(), Err((false, TLSError::Protocol(TLSAlertDescription::CERTIFICATE_REQUIRED))));
    assert!(!pair.server.session.resumed);
}

#[test]
fn a_psk_needs_no_key_share() {
    // RFC 9846 §9.2: a ClientHello with a PSK of psk_ke needs neither
    // supported_groups, key_share nor signature_algorithms.
    use umilib::protocol::tls::v1_3::TLS13Resumption;
    use umilib::protocol::tls::{
        TLSCipherSuite, TLSExtension, TLSServerHello, TLSServerNames, TLSSupportedVersions, TLSTranscript,
    };
    let cache = Arc::new(TLSSessionCache::new(8));
    let (client, mut server) = Resumption::configs(&cache);
    server.config.psk_modes = vec![TLSPSKMode::PSK_KE];
    Resumption::first(&client, &server);
    let ticket = cache.take("server.example").unwrap();
    let names = TLSServerNames { host_names: vec![b"server.example".to_vec()] };
    let mut extensions = vec![
        TLSExtension::with(TLSExtensionType::SERVER_NAME, |data| names.encode(data)).unwrap(),
        TLSExtension::with(TLSExtensionType::SUPPORTED_VERSIONS, |data| {
            TLSSupportedVersions::Offered(vec![TLSVersion::TLS1_3]).encode(data)
        })
        .unwrap(),
        TLSExtension::with(TLSExtensionType::PSK_KEY_EXCHANGE_MODES, |data| {
            TLSPSKMode::encode_list(&[TLSPSKMode::PSK_KE], data)
        })
        .unwrap(),
    ];
    let record = |extensions: Vec<TLSExtension>, bind: bool| {
        let hello = TLSClientHello {
            legacy_version: TLSVersion::TLS1_2,
            random: [3; 32],
            legacy_session_id: Vec::new(),
            cipher_suites: vec![TLSCipherSuite::TLS_AES_128_GCM_SHA256],
            legacy_compression_methods: vec![0],
            extensions,
        };
        let mut message =
            TLSHandshake::new(TLSHandshakeType::CLIENT_HELLO, hello.to_bytes().unwrap()).to_bytes().unwrap();
        if bind {
            TLS13Resumption::bind(&mut message, &ticket.state, &TLSTranscript::new()).unwrap();
        }
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        record
    };
    // Without a PSK: missing_extension.
    let mut connection = TLSConnection::server(Arc::new(server.clone()), Fixture::random(6), TIME).unwrap();
    assert_eq!(
        connection.receive(&record(extensions.clone(), false)),
        Err(TLSError::Protocol(TLSAlertDescription::MISSING_EXTENSION))
    );
    extensions.push(TLS13Resumption::offer(&ticket, TIME).unwrap());
    let mut connection = TLSConnection::server(Arc::new(server), Fixture::random(6), TIME).unwrap();
    connection.receive(&record(extensions, true)).unwrap();
    assert!(connection.session.resumed);
    let bytes = take(&mut connection);
    let length = u32::from_be_bytes([0, bytes[6], bytes[7], bytes[8]]) as usize;
    let hello = TLSServerHello::decode(&bytes[9..9 + length]).unwrap();
    assert!(hello.extension(TLSExtensionType::PRE_SHARED_KEY).is_some());
    assert!(hello.extension(TLSExtensionType::KEY_SHARE).is_none());
}
