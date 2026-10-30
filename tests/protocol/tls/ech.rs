//! Encrypted ClientHello (RFC 9849) between this crate's client and server:
//! acceptance, rejection with retry configurations, HelloRetryRequest,
//! GREASE, resumption and early data, and the rules of decoding.

use std::sync::Arc;

use umilib::protocol::tls::{
    TLSAlertDescription, TLSClientConfig, TLSClientHello, TLSConnection, TLSECH, TLSECHCipher, TLSECHCipherSuite,
    TLSECHClientHello, TLSECHConfig, TLSECHConfigExtension, TLSECHKey, TLSECHStatus, TLSEarlyData, TLSError,
    TLSExtension, TLSExtensionType, TLSHandshake, TLSHandshakeType, TLSNamedGroup, TLSReplayCache, TLSServerConfig,
    TLSServerNames, TLSSessionCache, TLSVersion,
};

use super::handshake::{Fixture, Pair, TIME, take};

pub struct ECH;

impl ECH {
    /// A key of the configuration `config_id` for public.wild.example, which
    /// the servers' certificate names.
    pub fn key(config_id: u8, seed: u8) -> TLSECHKey {
        let template = TLSECHConfig {
            config_id,
            kem_id: TLSECHConfig::DHKEM_X25519,
            public_key: Vec::new(),
            cipher_suites: vec![
                TLSECHCipherSuite::MANDATORY,
                TLSECHCipherSuite {
                    kdf_id: TLSECHCipherSuite::HKDF_SHA256,
                    aead_id: TLSECHCipherSuite::CHACHA20_POLY1305,
                },
            ],
            maximum_name_length: 32,
            public_name: b"public.wild.example".to_vec(),
            extensions: Vec::new(),
        };
        TLSECHCipher::generate(template, true, &mut *Fixture::random(seed)).unwrap()
    }

    pub fn configs(client_key: &TLSECHKey, server_key: Option<TLSECHKey>) -> (TLSClientConfig, TLSServerConfig) {
        let mut client = Fixture::client_config();
        client.ech_configs = vec![client_key.config.clone()];
        let mut server = Fixture::server_config("server-p256");
        server.ech_keys = server_key.into_iter().collect();
        (client, server)
    }

    /// The ClientHello of a record.
    pub fn hello(record: &[u8]) -> TLSClientHello {
        let message = TLSHandshake::decode(&record[5..], 1 << 16).unwrap().unwrap().0;
        TLSClientHello::decode(&message.body).unwrap()
    }

    pub fn record(hello: &TLSClientHello) -> Vec<u8> {
        let message = TLSHandshake::new(TLSHandshakeType::CLIENT_HELLO, hello.to_bytes().unwrap()).to_bytes().unwrap();
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        record
    }

    pub fn host(hello: &TLSClientHello) -> Vec<u8> {
        TLSServerNames::decode(hello.extension(TLSExtensionType::SERVER_NAME).unwrap())
            .unwrap()
            .host_name()
            .unwrap()
            .to_vec()
    }
}

#[test]
fn ech_is_accepted() {
    let key = ECH::key(7, 1);
    let (client, server) = ECH::configs(&key, Some(key.clone()));
    let mut pair = Pair::new(client, server, Some("server.example"));
    // The ClientHelloOuter names the public name; the name asked for is
    // only in the encrypted ClientHelloInner (RFC 9849 §6.1).
    let flight = take(&mut pair.client);
    let outer = ECH::hello(&flight);
    assert_eq!(ECH::host(&outer), b"public.wild.example");
    assert!(!flight.windows(14).any(|window| window == b"server.example"));
    let Some(TLSECHClientHello::Outer { config_id, cipher_suite, .. }) = TLSECH::of(&outer).unwrap() else {
        panic!("an outer encrypted_client_hello")
    };
    assert_eq!((config_id, cipher_suite), (7, TLSECHCipherSuite::MANDATORY));
    pair.server.receive(&flight).unwrap();
    pair.run().unwrap();
    for connection in [&pair.client, &pair.server] {
        assert_eq!(connection.session.ech, TLSECHStatus::Accepted);
        assert_eq!(connection.session.version, Some(TLSVersion::TLS1_3));
    }
    assert_eq!(pair.server.session.server_name.as_deref(), Some("server.example"));
    pair.echo(b"encrypted hello");
}

#[test]
fn ech_rejected_gives_retry_configurations() {
    // A server that cannot open the ClientHelloInner completes the
    // handshake for the public name with its retry configurations; the
    // client then fails with ech_required (RFC 9849 §6.1.6, §7.1).
    let stale = ECH::key(7, 1);
    let current = ECH::key(7, 2);
    let (client, server) = ECH::configs(&stale, Some(current.clone()));
    let mut pair = Pair::new(client.clone(), server, Some("server.example"));
    assert_eq!(pair.run(), Err((true, TLSError::Protocol(TLSAlertDescription::ECH_REQUIRED))));
    let TLSECHStatus::Rejected { retry_configs: Some(list) } = pair.client.session.ech.clone() else {
        panic!("retry configurations: {:?}", pair.client.session.ech)
    };
    assert_eq!(TLSECHConfig::decode_list(&list).unwrap(), std::slice::from_ref(&current.config));
    assert_eq!(pair.client.session.server_name.as_deref(), Some("public.wild.example"));
    assert_eq!(pair.server.receive(&take(&mut pair.client)), Err(TLSError::Alert(TLSAlertDescription::ECH_REQUIRED)));
    // The retry with them is accepted.
    let mut retried = client.clone();
    retried.ech_configs = TLSECHConfig::decode_list(&list).unwrap();
    let (_, server) = ECH::configs(&current, Some(current.clone()));
    let mut pair = Pair::new(retried, server, Some("server.example"));
    pair.run().unwrap();
    assert_eq!(pair.client.session.ech, TLSECHStatus::Accepted);
    // A server without ECH: no retry configurations.
    let (client, server) = ECH::configs(&stale, None);
    let mut pair = Pair::new(client, server, Some("server.example"));
    assert_eq!(pair.run(), Err((true, TLSError::Protocol(TLSAlertDescription::ECH_REQUIRED))));
    assert_eq!(pair.client.session.ech, TLSECHStatus::Rejected { retry_configs: None });
    // The certificate must name the public name (RFC 9849 §6.1.7).
    let (client, _) = ECH::configs(&stale, None);
    let mut pair =
        Pair::new(client, TLSServerConfig::new(vec![Fixture::certified("stranger")]), Some("server.example"));
    assert!(matches!(pair.run(), Err((true, TLSError::Protocol(alert))) if alert != TLSAlertDescription::ECH_REQUIRED));
}

#[test]
fn ech_and_hello_retry_requests() {
    // RFC 9849 §6.1.5, §7.1.1, §7.2.1: the HelloRetryRequest confirms ECH,
    // and the second ClientHelloOuter carries the second inner one under
    // the same HPKE context.
    for (server_key, accepted) in [(ECH::key(7, 1), true), (ECH::key(7, 2), false)] {
        let (mut client, mut server) = ECH::configs(&ECH::key(7, 1), Some(server_key));
        client.config.groups = vec![TLSNamedGroup::X25519, TLSNamedGroup::SECP384R1];
        client.key_share_groups = vec![TLSNamedGroup::X25519];
        server.config.groups = vec![TLSNamedGroup::SECP384R1];
        let mut pair = Pair::new(client, server, Some("server.example"));
        if accepted {
            pair.run().unwrap();
            assert_eq!(pair.client.session.ech, TLSECHStatus::Accepted);
            assert_eq!(pair.server.session.ech, TLSECHStatus::Accepted);
            assert_eq!(pair.client.session.group, Some(TLSNamedGroup::SECP384R1));
            pair.echo(b"after a retry");
        } else {
            assert_eq!(pair.run(), Err((true, TLSError::Protocol(TLSAlertDescription::ECH_REQUIRED))));
        }
    }
}

#[test]
fn ech_rejected_by_tls_1_2() {
    // A server of TLS 1.2 uses the ClientHelloOuter: ECH is rejected (RFC 9849 §6.1.4).
    let key = ECH::key(7, 1);
    let (client, mut server) = ECH::configs(&key, Some(key.clone()));
    server.config.versions = vec![TLSVersion::TLS1_2];
    let mut pair = Pair::new(client, server, Some("server.example"));
    assert_eq!(pair.run(), Err((true, TLSError::Protocol(TLSAlertDescription::ECH_REQUIRED))));
    assert_eq!(pair.client.session.version, Some(TLSVersion::TLS1_2));
}

#[test]
fn grease_ech() {
    // RFC 9849 §6.2: a client without a configuration sends GREASE, which
    // servers ignore; retry configurations are not kept.
    let mut client = Fixture::client_config();
    client.ech_grease = true;
    let mut server = Fixture::server_config("server-p256");
    server.ech_keys = vec![ECH::key(7, 1)];
    let mut pair = Pair::new(client.clone(), server, Some("server.example"));
    let flight = take(&mut pair.client);
    assert!(matches!(TLSECH::of(&ECH::hello(&flight)).unwrap(), Some(TLSECHClientHello::Outer { .. })));
    pair.server.receive(&flight).unwrap();
    pair.run().unwrap();
    assert_eq!(pair.client.session.ech, TLSECHStatus::Grease);
    assert!(matches!(pair.server.session.ech, TLSECHStatus::Rejected { .. }));
    pair.echo(b"greased");
    let mut pair = Pair::new(client, Fixture::server_config("server-p256"), Some("server.example"));
    pair.run().unwrap();
}

#[test]
fn ech_with_resumption_and_early_data() {
    // The PSK and early data are in the ClientHelloInner; the outer one has
    // a GREASE pre_shared_key and early_data (RFC 9849 §6.1, §6.1.2).
    let key = ECH::key(7, 1);
    let cache = Arc::new(TLSSessionCache::new(8));
    let (mut client, mut server) = ECH::configs(&key, Some(key.clone()));
    client.sessions = Some(cache.clone());
    client.early_data = true;
    server.tickets = Some(super::resumption::Resumption::keys(1));
    server.maximum_early_data = 1024;
    server.anti_replay = Some(Arc::new(TLSReplayCache::new(10, 16)));
    super::resumption::Resumption::first(&client, &server);
    let mut pair = super::resumption::Resumption::pair(&client, &server, "server.example", 2, TIME);
    pair.client.send(b"early, encrypted").unwrap();
    let flight = take(&mut pair.client);
    let outer = ECH::hello(&flight);
    assert!(outer.extension(TLSExtensionType::PRE_SHARED_KEY).is_some());
    assert!(outer.extension(TLSExtensionType::EARLY_DATA).is_some());
    pair.server.receive(&flight).unwrap();
    pair.run().unwrap();
    for connection in [&pair.client, &pair.server] {
        assert_eq!(connection.session.ech, TLSECHStatus::Accepted);
        assert!(connection.session.resumed);
        assert_eq!(connection.session.early_data, TLSEarlyData::Accepted);
    }
    let mut read = [0u8; 16];
    assert_eq!(pair.server.read(&mut read), 16);
    assert_eq!(&read, b"early, encrypted");
}

#[test]
fn the_outer_hello_is_authenticated() {
    // RFC 9849 §5.2: the ClientHelloOuter is the associated data; a change
    // to it leaves the inner one closed, and the server rejects ECH.
    let key = ECH::key(7, 1);
    let (client, server) = ECH::configs(&key, Some(key.clone()));
    let mut pair = Pair::new(client, server.clone(), Some("server.example"));
    let mut outer = ECH::hello(&take(&mut pair.client));
    outer.random[0] ^= 1;
    let mut connection = TLSConnection::server(Arc::new(server.clone()), Fixture::random(4), TIME).unwrap();
    connection.receive(&ECH::record(&outer)).unwrap();
    assert_eq!(connection.session.ech, TLSECHStatus::Rejected { retry_configs: None });
    // An inner encrypted_client_hello from the network: illegal_parameter (RFC 9849 §7).
    outer.extensions.retain(|extension| extension.kind != TLSExtensionType::ENCRYPTED_CLIENT_HELLO);
    outer.extensions.insert(0, TLSECHClientHello::Inner.extension().unwrap());
    let mut connection = TLSConnection::server(Arc::new(server), Fixture::random(4), TIME).unwrap();
    assert_eq!(
        connection.receive(&ECH::record(&outer)),
        Err(TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER))
    );
}

#[test]
fn configurations() {
    // RFC 9849 §4: a list of configurations; other versions are skipped.
    let key = ECH::key(9, 3);
    let mut list = Vec::new();
    TLSECHConfig::encode_list(std::slice::from_ref(&key.config), &mut list).unwrap();
    assert_eq!(TLSECHConfig::decode_list(&list).unwrap(), std::slice::from_ref(&key.config));
    let mut other = vec![0xFE, 0x0C, 0, 2, 1, 2];
    other.extend_from_slice(&list[2..]);
    let mut mixed = (other.len() as u16).to_be_bytes().to_vec();
    mixed.extend_from_slice(&other);
    assert_eq!(TLSECHConfig::decode_list(&mixed).unwrap(), std::slice::from_ref(&key.config));
    assert!(TLSECHConfig::decode_list(&[0, 0]).is_err(), "at least 4 bytes");
    // The info of HPKE: "tls ech", 0, the ECHConfig.
    assert_eq!(&key.config.info().unwrap()[..8], b"tls ech\0");
    assert_eq!(key.config.info().unwrap()[8..], list[2..]);
    // Usable: a supported KEM and suite, no unknown mandatory extension, a host name.
    assert_eq!(key.config.usable_suite(), Some(TLSECHCipherSuite::MANDATORY));
    let mut mandatory = key.config.clone();
    mandatory.extensions.push(TLSECHConfigExtension { kind: 0x8001, data: vec![] });
    assert_eq!(mandatory.usable_suite(), None);
    let mut optional = key.config.clone();
    optional.extensions.push(TLSECHConfigExtension { kind: 0x0001, data: vec![] });
    assert!(optional.usable_suite().is_some());
    let mut unknown_kem = key.config.clone();
    unknown_kem.kem_id = 0x0041;
    assert_eq!(unknown_kem.usable_suite(), None);
    // RFC 9849 §6.1.7: LDH labels of at most 63 octets, and no IPv4 literal.
    for (name, valid) in [
        ("example.com", true),
        ("a-b.example", true),
        ("1.2.3.4", false),
        ("example.0x1f", false),
        ("example.0X", false),
        ("example.123", false),
        ("a..b", false),
        (".example", false),
        ("-a.example", false),
        ("a_b.example", false),
    ] {
        assert_eq!(TLSECHConfig::is_public_name(name.as_bytes()), valid, "{name}");
    }
    let long = format!("{}.example", "a".repeat(64));
    assert!(!TLSECHConfig::is_public_name(long.as_bytes()));
    // An unknown ECHClientHello type: illegal_parameter (RFC 9849 §7).
    assert_eq!(TLSECHClientHello::decode(&[2]), Err(TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER)));
}

#[test]
fn encoded_client_hello_inner() {
    let name = |host: &str| {
        let names = TLSServerNames { host_names: vec![host.as_bytes().to_vec()] };
        TLSExtension::with(TLSExtensionType::SERVER_NAME, |data| names.encode(data)).unwrap()
    };
    let inner = TLSClientHello {
        legacy_version: TLSVersion::TLS1_2,
        random: [1; 32],
        legacy_session_id: vec![5; 32],
        cipher_suites: vec![umilib::protocol::tls::TLSCipherSuite::TLS_AES_128_GCM_SHA256],
        legacy_compression_methods: vec![0],
        extensions: vec![
            name("a.example"),
            TLSExtension::new(TLSExtensionType::SUPPORTED_GROUPS, vec![0, 2, 0, 0x1D]),
            TLSExtension::new(TLSExtensionType::KEY_SHARE, vec![0, 4, 0, 0x1D, 0, 0]),
            TLSECHClientHello::Inner.extension().unwrap(),
        ],
    };
    // RFC 9849 §5.1, §6.1.3: no session ID, the name padded to the
    // maximum, and the whole to a multiple of 32.
    let encoded = TLSECH::encode_inner(&inner, 32).unwrap();
    let mut unpadded = inner.clone();
    unpadded.legacy_session_id.clear();
    let length = unpadded.to_bytes().unwrap().len();
    assert_eq!(encoded.len() % 32, 0);
    assert!(encoded.len() >= length + (32 - 9));
    assert_eq!(&encoded[..length], unpadded.to_bytes().unwrap());
    let mut outer = inner.clone();
    outer.random = [2; 32];
    outer.extensions[0] = name("public.example");
    assert_eq!(TLSECH::decode_inner(&encoded, &outer).unwrap(), inner);
    // Padding must be zeros.
    let mut bad = encoded.clone();
    let last = bad.len() - 1;
    bad[last] = 1;
    assert_eq!(TLSECH::decode_inner(&bad, &outer), Err(TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER)));
    // ech_outer_extensions: the outer extensions referred to, in order.
    let compressed = |kinds: &[u16]| {
        let mut hello = unpadded.clone();
        let mut data = vec![(kinds.len() * 2) as u8];
        for kind in kinds {
            data.extend_from_slice(&kind.to_be_bytes());
        }
        hello.extensions.splice(1..3, [TLSExtension::new(TLSExtensionType::ECH_OUTER_EXTENSIONS, data)]);
        hello.to_bytes().unwrap()
    };
    let groups = TLSExtensionType::SUPPORTED_GROUPS.0;
    let share = TLSExtensionType::KEY_SHARE.0;
    assert_eq!(TLSECH::decode_inner(&compressed(&[groups, share]), &outer).unwrap(), inner);
    let illegal = Err(TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER));
    // Out of order, repeated, missing from the outer one, or ECH itself.
    assert_eq!(TLSECH::decode_inner(&compressed(&[share, groups]), &outer), illegal);
    assert_eq!(TLSECH::decode_inner(&compressed(&[groups, groups]), &outer), illegal);
    assert_eq!(TLSECH::decode_inner(&compressed(&[groups, 0x1234]), &outer), illegal);
    assert_eq!(TLSECH::decode_inner(&compressed(&[TLSExtensionType::ENCRYPTED_CLIENT_HELLO.0]), &outer), illegal);
    // The ClientHelloInner must carry ECH of type inner and offer only TLS 1.3.
    assert_eq!(
        TLSECH::check_inner(&inner),
        Err(TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER)),
        "no supported_versions"
    );
}
