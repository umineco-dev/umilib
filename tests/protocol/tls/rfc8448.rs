//! TLS 1.3 against the traces of RFC 8448: every secret, key and IV the
//! traces derive, and the client of section 3 driven by the server's
//! records, whose answers must be the trace's records byte for byte.

use std::sync::Arc;

use umilib::auth::cert::path::ServiceIdentity;
use umilib::crypto::KeyAgreement;
use umilib::crypto::ecdh::X25519;
use umilib::protocol::tls::v1_3::{TLS13KeySchedule, TLS13Resumption};
use umilib::protocol::tls::{
    TLSAlertDescription, TLSCertificateVerifier, TLSCipherSuite, TLSClientConfig, TLSClientHello, TLSClientStart,
    TLSConnection, TLSEarlyData, TLSError, TLSEvent, TLSExtensionContext, TLSExtensionType, TLSHandshake,
    TLSHashAlgorithm, TLSKeyShareSecret, TLSMiddleboxCompatibility, TLSPreSharedKey, TLSReplayCache, TLSRole,
    TLSSessionCache, TLSSessionStore, TLSSessionTicket, TLSTicketer, TLSTranscript,
};

use super::Trace;
use super::handshake::Fixture;

/// The steps of the traces: the items of one `{client}`/`{server}` step, in order.
fn steps() -> Vec<Vec<super::TraceItem>> {
    let mut steps: Vec<Vec<super::TraceItem>> = Vec::new();
    for item in Trace::items() {
        match steps.last_mut() {
            Some(step) if step[0].section == item.section && step[0].step == item.step => step.push(item),
            _ => steps.push(vec![item]),
        }
    }
    steps
}

fn get<'a>(step: &'a [super::TraceItem], label: &str) -> Option<&'a [u8]> {
    step.iter().find(|item| item.label == label).map(|item| item.bytes.as_slice())
}

/// The label and context of an HkdfLabel (RFC 9846 §7.1), as RFC 8448 shows it in "info".
fn label_of(info: &[u8]) -> (&[u8], &[u8]) {
    let label = &info[3..3 + info[2] as usize];
    let context = &info[4 + info[2] as usize..];
    (label.strip_prefix(b"tls13 ").expect("a label of TLS 1.3"), context)
}

#[test]
fn the_key_schedule_of_every_trace() {
    // RFC 9846 §7.1: HKDF-Extract, HKDF-Expand-Label and Derive-Secret; §7.3: traffic keys.
    let schedule = TLS13KeySchedule::new(TLSHashAlgorithm::SHA256);
    let (mut extracted, mut expanded, mut keyed) = (0, 0, 0);
    for step in steps() {
        let name = format!("{} {}", step[0].section, step[0].step);
        if step[0].step.contains("extract secret") {
            let salt = get(&step, "salt").unwrap_or(&[]);
            let secret = schedule.extract(salt, get(&step, "IKM").unwrap());
            assert_eq!(secret.expose().as_slice(), get(&step, "secret").unwrap(), "{name}");
            extracted += 1;
        } else if let (Some(prk), Some(info), Some(output)) =
            (get(&step, "PRK"), get(&step, "info"), get(&step, "expanded"))
        {
            let (label, context) = label_of(info);
            let value = schedule.expand_label(prk, label, context, output.len()).unwrap();
            assert_eq!(value.expose().as_slice(), output, "{name}");
            if let Some(hash) = get(&step, "hash") {
                assert_eq!(hash, context, "{name}: the context is the transcript hash");
            }
            expanded += 1;
        } else if let (Some(prk), Some(key), Some(iv)) =
            (get(&step, "PRK"), get(&step, "key expanded"), get(&step, "iv expanded"))
        {
            let keys = schedule.traffic_keys(prk, key.len()).unwrap();
            assert_eq!((keys.key.expose().as_slice(), keys.iv.expose().as_slice()), (key, iv), "{name}");
            keyed += 1;
        }
    }
    assert!(extracted >= 15 && expanded >= 59 && keyed >= 21, "{extracted} {expanded} {keyed}");
}

/// Accepts the certificate of RFC 8448 §2, the only one the traces send.
struct Pinned(Vec<u8>);

impl TLSCertificateVerifier for Pinned {
    fn verify(
        &self,
        chain: &[Vec<u8>],
        _identity: Option<&ServiceIdentity>,
        _ocsp: Option<&[u8]>,
        _time: i64,
    ) -> Result<(), TLSAlertDescription> {
        if chain.first() == Some(&self.0) { Ok(()) } else { Err(TLSAlertDescription::BAD_CERTIFICATE) }
    }
}

/// The client of `section`, built from the trace's ClientHello and x25519
/// key, and the section's records: (step, bytes).
fn client_of(section: &str, compatibility: TLSMiddleboxCompatibility) -> (TLSConnection, Vec<(String, Vec<u8>)>) {
    client_with(section, compatibility, Fixture::random(1), |_| {})
}

/// [`client_of`] with the random source `random`.
fn client_with(
    section: &str,
    compatibility: TLSMiddleboxCompatibility,
    random: Box<dyn umilib::crypto::random::Random + Send>,
    configure: impl FnOnce(&mut TLSClientConfig),
) -> (TLSConnection, Vec<(String, Vec<u8>)>) {
    let (start, records) = start_of(section, compatibility, configure);
    let mut client = TLSConnection::new(TLSRole::Client, &start.config.config, random, super::handshake::TIME);
    client.engine = Some(Box::new(start));
    (client, records)
}

/// The client of `section` before its connection: built from the trace's
/// ClientHello and x25519 key, with the section's records: (step, bytes).
fn start_of(
    section: &str,
    compatibility: TLSMiddleboxCompatibility,
    configure: impl FnOnce(&mut TLSClientConfig),
) -> (TLSClientStart, Vec<(String, Vec<u8>)>) {
    let items = Trace::items();
    let records: Vec<(String, Vec<u8>)> = items
        .iter()
        .filter(|item| item.section.starts_with(section) && item.label == "complete record")
        .map(|item| (item.step.clone(), item.bytes.clone()))
        .collect();
    // The payload of the first record: section 4's "ClientHello" is truncated before its binders.
    let hello_bytes = Trace::find(&items, section, "client}  send handshake record", "payload");
    let hello = TLSClientHello::decode(&TLSHandshake::decode(hello_bytes, 1 << 16).unwrap().unwrap().0.body).unwrap();
    let private =
        X25519::private_key_from_bytes(Trace::find(&items, section, "client}  create an ephemeral", "private key"))
            .unwrap();
    // The certificate of RFC 8448 §2: the first entry of section 3's Certificate message.
    let message = Trace::find(&items, "3.", "construct a Certificate", "Certificate");
    let length = u32::from_be_bytes([0, message[8], message[9], message[10]]) as usize;
    let certificate = message[11..11 + length].to_vec();
    let mut config = TLSClientConfig::new(Arc::new(Pinned(certificate)));
    config.middlebox_compatibility = compatibility;
    configure(&mut config);
    let mut transcript = TLSTranscript::new();
    transcript.update(hello_bytes);
    let start = TLSClientStart {
        config: Arc::new(config),
        server_name: Some("server".into()),
        identity: None,
        hello,
        transcript,
        shares: vec![TLSKeyShareSecret::X25519(private)],
        retry: None,
        sent_change_cipher_spec: false,
        name: Some("server".into()),
        resumption: None,
        early_data: 0,
        ech: None,
        ech_rejected: false,
        ech_retry_configs: None,
    };
    (start, records)
}

fn records_of<'a>(records: &'a [(String, Vec<u8>)], prefix: &str) -> Vec<&'a [u8]> {
    records.iter().filter(|(step, _)| step.starts_with(prefix)).map(|(_, bytes)| bytes.as_slice()).collect()
}

#[test]
fn the_client_of_section_3() {
    // The server's records in, the client's out, byte for byte: its
    // Finished, application data and close_notify.
    let items = Trace::items();
    let (mut client, records) = client_of("3.", TLSMiddleboxCompatibility::Off);
    let server = records_of(&records, "server}  send handshake record");
    // The ServerHello, the encrypted flight, and later the NewSessionTicket.
    assert_eq!(server.len(), 3);
    client.receive(server[0]).unwrap();
    client.receive(server[1]).unwrap();
    assert_eq!(client.poll_event(), Some(TLSEvent::Connected));
    let ours = records_of(&records, "client}  send");
    let mut out = Vec::new();
    client.transmit(&mut out).unwrap();
    assert_eq!(out.as_slice(), ours[1], "the client's Finished record");
    // A client that does not resume ignores the NewSessionTicket (RFC 9846 §4.7.1).
    client.receive(server[2]).unwrap();
    let client_data = Trace::find(&items, "3.", "client}  send application_data record", "payload");
    client.send(client_data).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out).unwrap();
    assert_eq!(out.as_slice(), ours[2], "the client's application data record");
    let server_data = Trace::find(&items, "3.", "server}  send application_data record", "payload");
    client.receive(records_of(&records, "server}  send application_data record")[0]).unwrap();
    let mut read = vec![0; server_data.len()];
    assert_eq!(client.read(&mut read), server_data.len());
    assert_eq!(read, server_data);
    client.close().unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out).unwrap();
    assert_eq!(out.as_slice(), ours[3], "the client's close_notify");
    client.receive(records_of(&records, "server}  send alert record")[0]).unwrap();
    assert!(std::iter::from_fn(|| client.poll_event()).any(|event| event == TLSEvent::PeerClosed));
}

#[test]
fn the_client_of_section_7() {
    // Middlebox compatibility mode (RFC 9846 Appendix E.4): the server's
    // dummy ChangeCipherSpec is dropped, and the client sends its own
    // before its Finished.
    let (mut client, records) = client_of("7.", TLSMiddleboxCompatibility::On);
    let server_handshake = records_of(&records, "server}  send handshake record");
    client.receive(server_handshake[0]).unwrap();
    client.receive(records_of(&records, "server}  send change_cipher_spec record")[0]).unwrap();
    client.receive(server_handshake[1]).unwrap();
    assert_eq!(client.poll_event(), Some(TLSEvent::Connected));
    let mut out = Vec::new();
    client.transmit(&mut out).unwrap();
    let expected: Vec<u8> = [
        records_of(&records, "client}  send change_cipher_spec record")[0],
        records_of(&records, "client}  send handshake record")[1],
    ]
    .concat();
    assert_eq!(out, expected, "the client's ChangeCipherSpec and Finished");
    client.close().unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out).unwrap();
    assert_eq!(out.as_slice(), records_of(&records, "client}  send alert record")[0]);
}

/// A random source that gives the bytes it holds, in order.
struct Scripted(std::collections::VecDeque<u8>);

impl umilib::crypto::random::Random for Scripted {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), umilib::crypto::random::RandomError> {
        for byte in out {
            *byte = self.0.pop_front().expect("a scripted byte");
        }
        Ok(())
    }
}

impl Scripted {
    /// The bytes that make the scalar `value` (big-endian): the field
    /// elements of `math::ec` read 32-bit little-endian words, the most
    /// significant first.
    fn scalar(value: &[u8]) -> Scripted {
        Scripted(value.chunks(4).flat_map(|word| word.iter().rev().copied()).collect())
    }
}

#[test]
fn the_client_of_section_5() {
    // RFC 9846 §4.2.2, §4.2.4: after the HelloRetryRequest for P-256 with a
    // cookie, the second ClientHello is the first with the key share
    // replaced by one of P-256 and the cookie added. Where the cookie goes
    // and whether `padding` is added are the client's choice (the trace
    // adds 175 bytes of padding), so the extensions are compared, not the
    // bytes; and since the server's Finished covers the trace's second
    // ClientHello, the handshake cannot go on from the trace.
    let items = Trace::items();
    let private = Trace::find(&items, "5.", "client}  create an ephemeral P-256", "private key").to_vec();
    let random = Box::new(Scripted::scalar(&private));
    let (mut client, records) = client_with("5.", TLSMiddleboxCompatibility::Off, random, |_| {});
    let server = records_of(&records, "server}  send handshake record");
    let ours = records_of(&records, "client}  send handshake record");
    client.receive(server[0]).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out).unwrap();
    let hello = |record: &[u8]| {
        TLSClientHello::decode(&TLSHandshake::decode(&record[5..], 1 << 16).unwrap().unwrap().0.body).unwrap()
    };
    let (sent, expected) = (hello(&out), hello(ours[1]));
    assert_eq!((sent.random, &sent.cipher_suites), (expected.random, &expected.cipher_suites));
    let padding = umilib::protocol::tls::TLSExtensionType::PADDING;
    let mut kinds: Vec<_> = sent.extensions.iter().map(|extension| extension.kind).collect();
    let mut expected_kinds: Vec<_> =
        expected.extensions.iter().map(|extension| extension.kind).filter(|kind| *kind != padding).collect();
    kinds.sort();
    expected_kinds.sort();
    assert_eq!(kinds, expected_kinds);
    for extension in &sent.extensions {
        assert_eq!(Some(extension.data.as_slice()), expected.extension(extension.kind), "{:?}", extension.kind);
    }
}

/// The ticket the client of section 3 keeps from the server's
/// NewSessionTicket (RFC 9846 §4.6.1): its PSK is the IKM of the early
/// secret of section 4, which resumes with it.
fn ticket_of_section_3() -> TLSSessionTicket {
    let cache = Arc::new(TLSSessionCache::new(4));
    let store = cache.clone();
    let (mut client, records) =
        client_with("3.", TLSMiddleboxCompatibility::Off, Fixture::random(1), |config| config.sessions = Some(store));
    for record in records_of(&records, "server}  send handshake record") {
        client.receive(record).unwrap();
    }
    cache.take("server").expect("the ticket is kept")
}

#[test]
fn the_ticket_of_section_3() {
    let items = Trace::items();
    let ticket = ticket_of_section_3();
    let psk = Trace::find(&items, "4.", "client}  extract secret \"early\"", "IKM");
    assert_eq!(ticket.state.psk.expose().as_slice(), psk);
    // The NewSessionTicket: lifetime 30 s, age_add, early_data of 1024 bytes.
    assert_eq!((ticket.state.lifetime, ticket.state.age_add), (30, 0xFAD6_AAC5));
    assert_eq!(ticket.state.maximum_early_data, 1024);
    assert_eq!(ticket.state.cipher_suite, TLSCipherSuite::TLS_AES_128_GCM_SHA256);
    let hello = Trace::find(&items, "4.", "client}  send handshake record", "payload");
    let hello = TLSClientHello::decode(&hello[4..]).unwrap();
    let offered = hello.extension(TLSExtensionType::PRE_SHARED_KEY).unwrap();
    let TLSPreSharedKey::Offered { identities, .. } =
        TLSPreSharedKey::decode(offered, TLSExtensionContext::ClientHello).unwrap()
    else {
        panic!("offered");
    };
    assert_eq!(identities[0].identity, ticket.ticket);
}

#[test]
fn the_binder_of_section_4() {
    // RFC 9846 §4.3.11.2: the binder over the ClientHello truncated before
    // its binders, keyed by the binder key of the PSK.
    let items = Trace::items();
    let ticket = ticket_of_section_3();
    let complete = Trace::find(&items, "4.", "client}  send handshake record", "payload");
    let mut message = complete.to_vec();
    let length = message.len();
    message[length - 32..].fill(0);
    TLS13Resumption::bind(&mut message, &ticket.state, &TLSTranscript::new()).unwrap();
    assert_eq!(message, complete);
    let binder_hash = Trace::find(&items, "4.", "client}  calculate PSK binder", "binder hash");
    let hash = TLS13Resumption::binder_hash(&ticket.state, &TLSTranscript::new(), complete, 35).unwrap();
    assert_eq!(hash, binder_hash);
}

#[test]
fn the_client_of_section_4() {
    // A resumption with 0-RTT: the early data under the keys of early data,
    // EndOfEarlyData under them too, then the Finished, byte for byte.
    let items = Trace::items();
    let (mut start, records) = start_of("4.", TLSMiddleboxCompatibility::Off, |_| {});
    start.resumption = Some(ticket_of_section_3());
    let mut client =
        TLSConnection::new(TLSRole::Client, &start.config.config, Fixture::random(1), super::handshake::TIME);
    start.offer_early_data(&mut client.context()).unwrap();
    client.engine = Some(Box::new(start));
    assert_eq!(client.session.early_data, TLSEarlyData::Offered);
    let early = Trace::find(&items, "4.", "client}  send application_data record", "payload");
    client.send(early).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out).unwrap();
    assert_eq!(out.as_slice(), records_of(&records, "client}  send application_data record")[0], "the early data");
    // No more than the ticket allows (1024 bytes in all).
    assert_eq!(client.send(&[0; 1024]), Err(TLSError::State));
    let server = records_of(&records, "server}  send handshake record");
    client.receive(server[0]).unwrap();
    client.receive(server[1]).unwrap();
    assert_eq!(client.poll_event(), Some(TLSEvent::Connected));
    assert_eq!(client.session.early_data, TLSEarlyData::Accepted);
    assert!(client.session.resumed);
    let mut out = Vec::new();
    client.transmit(&mut out).unwrap();
    let ours = records_of(&records, "client}  send handshake record");
    assert_eq!(out, [ours[1], ours[2]].concat(), "EndOfEarlyData and Finished");
    let payloads: Vec<&[u8]> = items
        .iter()
        .filter(|item| {
            item.section.starts_with("4.")
                && item.step.contains("client}  send application_data record")
                && item.label == "payload"
        })
        .map(|item| item.bytes.as_slice())
        .collect();
    client.send(payloads[1]).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out).unwrap();
    assert_eq!(out.as_slice(), records_of(&records, "client}  send application_data record")[1]);
    client.close().unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out).unwrap();
    assert_eq!(out.as_slice(), records_of(&records, "client}  send alert record")[0]);
}

/// The ticket of section 3 as the trace's server would open it.
struct TraceTickets(TLSSessionTicket);

impl TLSTicketer for TraceTickets {
    fn seal(&self, _state: &[u8], _random: &mut dyn umilib::crypto::random::Random) -> Option<Vec<u8>> {
        None
    }

    fn open(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        let mut state = Vec::new();
        (ticket == self.0.ticket).then(|| self.0.state.encode(&mut state).unwrap())?;
        Some(state)
    }
}

/// A server of section 4: it opens the ticket of section 3, issued
/// `age` before now as the ClientHello's obfuscated age says, and accepts
/// early data, with `anti_replay`.
fn server_of_section_4(anti_replay: Arc<TLSReplayCache>) -> TLSConnection {
    let items = Trace::items();
    let mut ticket = ticket_of_section_3();
    let hello = Trace::find(&items, "4.", "client}  send handshake record", "payload");
    let hello = TLSClientHello::decode(&hello[4..]).unwrap();
    let TLSPreSharedKey::Offered { identities, .. } = TLSPreSharedKey::decode(
        hello.extension(TLSExtensionType::PRE_SHARED_KEY).unwrap(),
        TLSExtensionContext::ClientHello,
    )
    .unwrap() else {
        panic!("offered")
    };
    let age = identities[0].obfuscated_ticket_age.wrapping_sub(ticket.state.age_add);
    ticket.state.time = super::handshake::TIME - i64::from(age / 1000);
    // The trace's client asked for "server" (built from its ClientHello, its session did not record it).
    ticket.state.server_name = Some("server".into());
    let mut config = Fixture::server_config("server-p256");
    config.tickets = Some(Arc::new(TraceTickets(ticket)));
    config.maximum_early_data = 1024;
    config.anti_replay = Some(anti_replay);
    TLSConnection::server(Arc::new(config), Fixture::random(2), super::handshake::TIME).unwrap()
}

#[test]
fn the_server_of_section_4() {
    // The server checks the binder, accepts the PSK and the early data, and
    // reads it with the keys of early data until EndOfEarlyData; its own
    // flight differs from the trace (its randomness), so the client's
    // Finished cannot follow.
    let items = Trace::items();
    let (_, records) = start_of("4.", TLSMiddleboxCompatibility::Off, |_| {});
    let client = records_of(&records, "client}  send handshake record");
    let early = records_of(&records, "client}  send application_data record")[0];
    let anti_replay = Arc::new(TLSReplayCache::new(10, 16));
    let mut server = server_of_section_4(anti_replay.clone());
    server.receive(client[0]).unwrap();
    assert!(server.session.resumed);
    assert_eq!(server.session.early_data, TLSEarlyData::Accepted);
    server.receive(early).unwrap();
    let payload = Trace::find(&items, "4.", "client}  send application_data record", "payload");
    let mut read = vec![0; payload.len()];
    assert_eq!(server.read(&mut read), payload.len());
    assert_eq!(read, payload);
    server.receive(client[1]).unwrap();
    // The same ClientHello again is a replay (RFC 9846 §8): its early data
    // is refused, and skipped as it does not decrypt.
    let mut replayed = server_of_section_4(anti_replay);
    replayed.receive(client[0]).unwrap();
    assert!(replayed.session.resumed);
    assert_eq!(replayed.session.early_data, TLSEarlyData::Rejected);
    replayed.receive(early).unwrap();
    assert_eq!(replayed.readable(), 0);
}
