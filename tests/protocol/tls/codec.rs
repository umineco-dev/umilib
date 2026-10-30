//! The codec: every message and record of RFC 8448 reads and writes back
//! byte for byte, and the rules of RFC 9846 §4 and §5 on malformed input.

use umilib::bytes::{Buffer, Reader};
use umilib::protocol::tls::v1_3::{
    TLS13Certificate, TLS13CertificateRequest, TLS13EncryptedExtensions, TLS13KeyUpdate, TLS13NewSessionTicket,
};
use umilib::protocol::tls::{
    TLSAlert, TLSAlertDescription, TLSAlertLevel, TLSCertificateVerify, TLSCipherSuite, TLSClientHello, TLSContentType,
    TLSError, TLSExtension, TLSExtensionContext, TLSExtensionType, TLSFinished, TLSHandshake, TLSHandshakeReassembler,
    TLSHandshakeType, TLSKeyShare, TLSNamedGroup, TLSPSKMode, TLSPreSharedKey, TLSRecord, TLSRecordHeader,
    TLSRecordSizeLimit, TLSServerHello, TLSServerNames, TLSSignatureScheme, TLSSignatureSchemes, TLSSupportedGroups,
    TLSSupportedVersions, TLSVersion,
};

use super::Trace;

fn decode_error() -> TLSError {
    TLSError::Protocol(TLSAlertDescription::DECODE_ERROR)
}

fn illegal() -> TLSError {
    TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER)
}

/// Reads the body of `message` as its type says, checks the extension
/// rules of RFC 9846 §4.3, and writes it back.
fn round_trip(message: &TLSHandshake) -> Vec<u8> {
    let mut body = Buffer::new();
    match message.kind {
        TLSHandshakeType::CLIENT_HELLO => {
            let hello = TLSClientHello::decode(&message.body).unwrap();
            TLSExtension::check(&hello.extensions, TLSExtensionContext::ClientHello).unwrap();
            hello.encode(&mut body).unwrap();
        }
        TLSHandshakeType::SERVER_HELLO => {
            let hello = TLSServerHello::decode(&message.body).unwrap();
            let context = if hello.is_retry() {
                TLSExtensionContext::HelloRetryRequest
            } else {
                TLSExtensionContext::ServerHello
            };
            TLSExtension::check(&hello.extensions, context).unwrap();
            hello.encode(&mut body).unwrap();
        }
        TLSHandshakeType::ENCRYPTED_EXTENSIONS => {
            let extensions = TLS13EncryptedExtensions::decode(&message.body).unwrap();
            TLSExtension::check(&extensions.extensions, TLSExtensionContext::EncryptedExtensions).unwrap();
            extensions.encode(&mut body).unwrap();
        }
        TLSHandshakeType::CERTIFICATE => {
            let certificate = TLS13Certificate::decode(&message.body).unwrap();
            for entry in &certificate.entries {
                TLSExtension::check(&entry.extensions, TLSExtensionContext::Certificate).unwrap();
            }
            certificate.encode(&mut body).unwrap();
        }
        TLSHandshakeType::CERTIFICATE_REQUEST => {
            let request = TLS13CertificateRequest::decode(&message.body).unwrap();
            TLSExtension::check(&request.extensions, TLSExtensionContext::CertificateRequest).unwrap();
            request.encode(&mut body).unwrap();
        }
        TLSHandshakeType::CERTIFICATE_VERIFY => {
            TLSCertificateVerify::decode_body(&message.body).unwrap().encode(&mut body).unwrap();
        }
        TLSHandshakeType::FINISHED => {
            TLSFinished::decode(&message.body, message.body.len()).unwrap().encode(&mut body).unwrap();
        }
        TLSHandshakeType::NEW_SESSION_TICKET => {
            let ticket = TLS13NewSessionTicket::decode(&message.body).unwrap();
            TLSExtension::check(&ticket.extensions, TLSExtensionContext::NewSessionTicket).unwrap();
            ticket.encode(&mut body).unwrap();
        }
        TLSHandshakeType::END_OF_EARLY_DATA => assert!(message.body.is_empty()),
        kind => panic!("unexpected message {kind:?}"),
    }
    body.into_vec()
}

#[test]
fn messages_of_rfc_8448_read_and_write_back() {
    let names = [
        "ClientHello",
        "ServerHello",
        "EncryptedExtensions",
        "Certificate",
        "CertificateRequest",
        "CertificateVerify",
        "Finished",
        "NewSessionTicket",
        "EndOfEarlyData",
    ];
    let mut seen = 0;
    let items = Trace::items();
    for item in items.iter().filter(|item| names.contains(&item.label.as_str())) {
        if TLSHandshake::decode(&item.bytes, 1 << 24).unwrap().is_none() {
            // Section 4 shows the ClientHello before its binders: the
            // truncated ClientHello the binders authenticate (RFC 9846
            // §4.3.11.2), a prefix of the one sent.
            let sent = items
                .iter()
                .find(|other| other.section == item.section && other.label == "payload" && other.bytes[0] == 1)
                .unwrap();
            assert!(sent.bytes.starts_with(&item.bytes) && sent.bytes.len() > item.bytes.len());
            continue;
        }
        let (message, length) = TLSHandshake::decode(&item.bytes, TLSHandshake::MAXIMUM_LENGTH).unwrap().unwrap();
        assert_eq!(length, item.bytes.len(), "{} {}", item.section, item.label);
        if message.kind != TLSHandshakeType::END_OF_EARLY_DATA {
            assert_eq!(round_trip(&message), message.body, "{} {}", item.section, item.label);
        }
        assert_eq!(message.to_bytes().unwrap(), item.bytes);
        seen += 1;
    }
    // 40 labelled messages, one of them the truncated ClientHello.
    assert_eq!(seen, 39, "every whole message of the traces");
}

#[test]
fn records_of_rfc_8448_read_and_write_back() {
    // RFC 9846 §5.1: a record holds its type, legacy_record_version and length.
    let records: Vec<_> = Trace::items().into_iter().filter(|item| item.label == "complete record").collect();
    assert_eq!(records.len(), 41);
    for item in &records {
        let (record, length) =
            TLSRecord::decode(&item.bytes, TLSRecordHeader::MAXIMUM_CIPHERTEXT).unwrap().expect("a whole record");
        assert_eq!(length, item.bytes.len());
        assert!(
            [
                TLSContentType::HANDSHAKE,
                TLSContentType::APPLICATION_DATA,
                TLSContentType::ALERT,
                TLSContentType::CHANGE_CIPHER_SPEC
            ]
            .contains(&record.header.content_type)
        );
        // The first ClientHello may say 0x0301; every other record says 0x0303 (RFC 9846 §5.1).
        assert!([TLSVersion::TLS1_0, TLSVersion::TLS1_2].contains(&record.header.version));
        let mut out = Buffer::new();
        record.encode(&mut out).unwrap();
        assert_eq!(out.as_slice(), item.bytes.as_slice());
        // A record cut short is not yet whole.
        assert_eq!(
            TLSRecord::decode(&item.bytes[..item.bytes.len() - 1], TLSRecordHeader::MAXIMUM_CIPHERTEXT).unwrap(),
            None
        );
    }
}

#[test]
fn the_client_hello_of_rfc_8448_section_3() {
    let items = Trace::items();
    let item = items.iter().find(|item| item.label == "ClientHello").unwrap();
    let public = &items.iter().find(|item| item.label == "public key").unwrap().bytes;
    let (message, _) = TLSHandshake::decode(&item.bytes, TLSHandshake::MAXIMUM_LENGTH).unwrap().unwrap();
    let hello = TLSClientHello::decode(&message.body).unwrap();
    assert_eq!(hello.legacy_version, TLSVersion::TLS1_2);
    assert_eq!(
        hello.cipher_suites,
        [
            TLSCipherSuite::TLS_AES_128_GCM_SHA256,
            TLSCipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            TLSCipherSuite::TLS_AES_256_GCM_SHA384
        ]
    );
    assert_eq!(hello.legacy_compression_methods, [0]);
    let names = TLSServerNames::decode(hello.extension(TLSExtensionType::SERVER_NAME).unwrap()).unwrap();
    assert_eq!(names.host_name(), Some(b"server".as_slice()));
    let groups = TLSSupportedGroups::decode(hello.extension(TLSExtensionType::SUPPORTED_GROUPS).unwrap()).unwrap();
    assert_eq!(groups.groups[..2], [TLSNamedGroup::X25519, TLSNamedGroup::SECP256R1]);
    let TLSKeyShare::Client(shares) =
        TLSKeyShare::decode(hello.extension(TLSExtensionType::KEY_SHARE).unwrap(), TLSExtensionContext::ClientHello)
            .unwrap()
    else {
        panic!("a client's key shares")
    };
    assert_eq!((shares.len(), shares[0].group, &shares[0].key_exchange), (1, TLSNamedGroup::X25519, public));
    let versions = TLSSupportedVersions::decode(
        hello.extension(TLSExtensionType::SUPPORTED_VERSIONS).unwrap(),
        TLSExtensionContext::ClientHello,
    )
    .unwrap();
    assert_eq!(versions, TLSSupportedVersions::Offered(vec![TLSVersion::TLS1_3]));
    let schemes =
        TLSSignatureSchemes::decode(hello.extension(TLSExtensionType::SIGNATURE_ALGORITHMS).unwrap()).unwrap();
    assert_eq!(schemes.schemes[0], TLSSignatureScheme::ECDSA_SECP256R1_SHA256);
    let modes = TLSPSKMode::decode_list(hello.extension(TLSExtensionType::PSK_KEY_EXCHANGE_MODES).unwrap()).unwrap();
    assert_eq!(modes, [TLSPSKMode::PSK_DHE_KE]);
    let limit = TLSRecordSizeLimit::decode(hello.extension(TLSExtensionType::RECORD_SIZE_LIMIT).unwrap()).unwrap();
    assert_eq!(limit, TLSRecordSizeLimit(0x4001));
}

#[test]
fn hello_retry_requests_and_pre_shared_keys_of_rfc_8448() {
    // RFC 9846 §4.2.4: a HelloRetryRequest is a ServerHello with the special random; it names a group.
    let items = Trace::items();
    let retries: Vec<_> = items
        .iter()
        .filter(|item| item.label == "ServerHello")
        .map(|item| {
            TLSServerHello::decode(&TLSHandshake::decode(&item.bytes, 1 << 24).unwrap().unwrap().0.body).unwrap()
        })
        .filter(TLSServerHello::is_retry)
        .collect();
    assert_eq!(retries.len(), 1);
    let share = TLSKeyShare::decode(
        retries[0].extension(TLSExtensionType::KEY_SHARE).unwrap(),
        TLSExtensionContext::HelloRetryRequest,
    )
    .unwrap();
    assert_eq!(share, TLSKeyShare::Retry(TLSNamedGroup::SECP256R1));
    assert!(retries[0].extension(TLSExtensionType::COOKIE).is_some());
    // §4.3.11: the resumed ClientHello of section 4 offers one PSK and its binder, last.
    let resumed = items
        .iter()
        .filter(|item| item.label == "payload" && item.section.starts_with("4.") && item.bytes[0] == 1)
        .map(|item| {
            TLSClientHello::decode(&TLSHandshake::decode(&item.bytes, 1 << 24).unwrap().unwrap().0.body).unwrap()
        })
        .next()
        .unwrap();
    assert_eq!(resumed.extensions.last().unwrap().kind, TLSExtensionType::PRE_SHARED_KEY);
    let TLSPreSharedKey::Offered { identities, binders } = TLSPreSharedKey::decode(
        resumed.extension(TLSExtensionType::PRE_SHARED_KEY).unwrap(),
        TLSExtensionContext::ClientHello,
    )
    .unwrap() else {
        panic!("offered keys")
    };
    assert_eq!((identities.len(), binders.len(), binders[0].len()), (1, 1, 32));
    let ticket = items.iter().find(|item| item.label == "NewSessionTicket").unwrap();
    let ticket =
        TLS13NewSessionTicket::decode(&TLSHandshake::decode(&ticket.bytes, 1 << 24).unwrap().unwrap().0.body).unwrap();
    assert_eq!(identities[0].identity, ticket.ticket);
    assert_eq!(
        TLSPreSharedKey::binders_length(&binders),
        2 + 33,
        "the binders list: its length, then each binder with its own"
    );
}

#[test]
fn extension_blocks_follow_rfc_9846_section_4_3() {
    let block = |extensions: &[(u16, &[u8])]| {
        let mut bytes = Buffer::new();
        let list: Vec<TLSExtension> =
            extensions.iter().map(|(kind, data)| TLSExtension::new(TLSExtensionType(*kind), data.to_vec())).collect();
        TLSExtension::encode_list(&list, &mut bytes).unwrap();
        bytes.into_vec()
    };
    // Two extensions of one type: illegal_parameter.
    let twice = block(&[(10, &[0, 2, 0, 0x1D]), (10, &[0, 2, 0, 0x17])]);
    assert_eq!(TLSExtension::decode_list(&mut Reader::new(&twice), 0), Err(illegal()));
    // An extension in a message that may not carry it: illegal_parameter.
    let list = vec![TLSExtension::new(TLSExtensionType::SUPPORTED_GROUPS, vec![])];
    assert_eq!(TLSExtension::check(&list, TLSExtensionContext::ServerHello), Err(illegal()));
    assert_eq!(TLSExtension::check(&list, TLSExtensionContext::EncryptedExtensions), Ok(()));
    // Unknown extensions are ignored wherever they are.
    let unknown = vec![TLSExtension::new(TLSExtensionType(0x1234), vec![1])];
    assert_eq!(TLSExtension::check(&unknown, TLSExtensionContext::ServerHello), Ok(()));
    // pre_shared_key must be the last extension of a ClientHello, and may be anywhere in a ServerHello.
    let early = vec![
        TLSExtension::new(TLSExtensionType::PRE_SHARED_KEY, vec![]),
        TLSExtension::new(TLSExtensionType::KEY_SHARE, vec![]),
    ];
    assert_eq!(TLSExtension::check(&early, TLSExtensionContext::ClientHello), Err(illegal()));
    assert_eq!(TLSExtension::check(&early, TLSExtensionContext::ServerHello), Ok(()));
    // A block whose length runs past the message: decode_error.
    assert_eq!(TLSExtension::decode_list(&mut Reader::new(&[0, 5, 0, 10, 0]), 0), Err(decode_error()));
}

#[test]
fn extension_contents_follow_their_rfcs() {
    // Trailing data after a structure: decode_error (RFC 9846 §4.3).
    assert_eq!(TLSSupportedGroups::decode(&[0, 2, 0, 0x1D, 0]), Err(decode_error()));
    // A list of 16-bit values of odd length, or shorter than its minimum: decode_error.
    assert_eq!(TLSSupportedGroups::decode(&[0, 3, 0, 0x1D, 0]), Err(decode_error()));
    assert_eq!(TLSSupportedGroups::decode(&[0, 0]), Err(decode_error()));
    assert_eq!(TLSSignatureSchemes::decode(&[0, 0]), Err(decode_error()));
    // Two key shares of one group: illegal_parameter (RFC 9846 §4.3.8).
    let shares = [0, 10, 0, 0x1D, 0, 1, 9, 0, 0x1D, 0, 1, 8];
    assert_eq!(TLSKeyShare::decode(&shares, TLSExtensionContext::ClientHello), Err(illegal()));
    // An empty key_exchange: decode_error (<1..2^16-1>).
    assert_eq!(TLSKeyShare::decode(&[0, 4, 0, 0x1D, 0, 0], TLSExtensionContext::ClientHello), Err(decode_error()));
    // supported_versions of a ClientHello: <2..254>.
    assert_eq!(TLSSupportedVersions::decode(&[0], TLSExtensionContext::ClientHello), Err(decode_error()));
    assert_eq!(
        TLSSupportedVersions::decode(&[0x03, 0x04], TLSExtensionContext::ServerHello),
        Ok(TLSSupportedVersions::Selected(TLSVersion::TLS1_3))
    );
    // record_size_limit below 64: illegal_parameter (RFC 8449 §4).
    assert_eq!(TLSRecordSizeLimit::decode(&[0, 63]), Err(illegal()));
    assert_eq!(TLSRecordSizeLimit::decode(&[0, 64]), Ok(TLSRecordSizeLimit(64)));
    // server_name: only host_name, at most one (RFC 6066 §3).
    assert_eq!(TLSServerNames::decode(&[0, 4, 1, 0, 1, b'a']), Err(decode_error()));
    assert_eq!(TLSServerNames::decode(&[0, 8, 0, 0, 1, b'a', 0, 0, 1, b'b']), Err(illegal()));
    // pre_shared_key: as many binders as identities, binders of 32..255 bytes.
    let mut offered = Buffer::new();
    TLSPreSharedKey::Offered {
        identities: vec![umilib::protocol::tls::TLSPSKIdentity { identity: vec![1], obfuscated_ticket_age: 7 }; 2],
        binders: vec![vec![0; 32]],
    }
    .encode(&mut offered)
    .unwrap();
    assert_eq!(TLSPreSharedKey::decode(offered.as_slice(), TLSExtensionContext::ClientHello), Err(illegal()));
}

#[test]
fn hellos_refuse_malformed_fields() {
    let items = Trace::items();
    let item = items.iter().find(|item| item.label == "ClientHello").unwrap();
    let body = TLSHandshake::decode(&item.bytes, 1 << 24).unwrap().unwrap().0.body;
    // A legacy_session_id longer than 32 bytes: decode_error.
    let mut long = body.clone();
    long[34] = 33;
    assert_eq!(TLSClientHello::decode(&long), Err(decode_error()));
    // Data after the extensions: decode_error.
    let mut trailing = body.clone();
    trailing.push(0);
    assert_eq!(TLSClientHello::decode(&trailing), Err(decode_error()));
    // A ClientHello of TLS 1.2 may have no extension block at all (RFC 5246 §7.4.1.2).
    let mut legacy = Buffer::new();
    let hello = TLSClientHello { extensions: vec![], ..TLSClientHello::decode(&body).unwrap() };
    hello.encode(&mut legacy).unwrap();
    let without = &legacy.as_slice()[..legacy.len() - 2];
    assert_eq!(TLSClientHello::decode(without).unwrap(), hello);
}

#[test]
fn records_and_handshake_framing() {
    // RFC 9846 §5.1: a fragment above 2^14 bytes is a record_overflow.
    let header =
        TLSRecordHeader { content_type: TLSContentType::HANDSHAKE, version: TLSVersion::TLS1_2, length: (1 << 14) + 1 };
    assert_eq!(
        TLSRecord::decode(&header.to_bytes(), TLSRecordHeader::MAXIMUM_PLAINTEXT),
        Err(TLSError::Protocol(TLSAlertDescription::RECORD_OVERFLOW))
    );
    assert_eq!(TLSRecord::decode(&header.to_bytes(), TLSRecordHeader::MAXIMUM_CIPHERTEXT), Ok(None));
    // Messages span records and records hold several messages.
    let first = TLSHandshake::new(TLSHandshakeType::FINISHED, vec![7; 40]).to_bytes().unwrap();
    let second = TLSHandshake::new(TLSHandshakeType::KEY_UPDATE, vec![1]).to_bytes().unwrap();
    let stream: Vec<u8> = first.iter().chain(&second).copied().collect();
    let mut reassembler = TLSHandshakeReassembler::new(1 << 16);
    reassembler.push(&stream[..3]).unwrap();
    assert_eq!(reassembler.pop(), Ok(None));
    assert!(!reassembler.is_empty(), "a partial message is held");
    reassembler.push(&stream[3..]).unwrap();
    assert_eq!(reassembler.pop().unwrap().unwrap().body, vec![7; 40]);
    assert_eq!(reassembler.pop().unwrap().unwrap().kind, TLSHandshakeType::KEY_UPDATE);
    assert!(reassembler.pop().unwrap().is_none() && reassembler.is_empty());
    // Zero-length handshake fragments are refused (RFC 9846 §5.1).
    assert_eq!(reassembler.push(&[]), Err(TLSError::Protocol(TLSAlertDescription::UNEXPECTED_MESSAGE)));
    // A message longer than the limit is refused as soon as its header is whole.
    let mut small = TLSHandshakeReassembler::new(100);
    assert_eq!(small.push(&[1, 0, 1, 0]), Err(decode_error()));
}

#[test]
fn alerts_and_small_messages() {
    // RFC 9846 §6: close_notify and user_canceled are warnings, the others fatal.
    assert_eq!(TLSAlert::new(TLSAlertDescription::CLOSE_NOTIFY).level, TLSAlertLevel::WARNING);
    assert_eq!(TLSAlert::new(TLSAlertDescription::USER_CANCELED).level, TLSAlertLevel::WARNING);
    assert_eq!(TLSAlert::new(TLSAlertDescription::DECODE_ERROR).level, TLSAlertLevel::FATAL);
    assert_eq!(TLSAlert::decode(&[2, 40]).unwrap(), TLSAlert::new(TLSAlertDescription::HANDSHAKE_FAILURE));
    assert_eq!(TLSAlert::decode(&[2]), Err(decode_error()));
    assert_eq!(TLSAlert::decode(&[2, 40, 0]), Err(decode_error()), "one alert per record");
    // KeyUpdate: 0 or 1, else illegal_parameter (RFC 9846 §4.7.3).
    assert_eq!(TLS13KeyUpdate::decode(&[1]), Ok(TLS13KeyUpdate { request_update: true }));
    assert_eq!(TLS13KeyUpdate::decode(&[2]), Err(illegal()));
    assert_eq!(TLS13KeyUpdate::decode(&[0, 0]), Err(decode_error()));
    // NewSessionTicket: a lifetime above seven days is illegal (RFC 9846 §4.7.1).
    let ticket =
        TLS13NewSessionTicket { lifetime: 604_801, age_add: 0, nonce: vec![], ticket: vec![1], extensions: vec![] };
    let mut bytes = Buffer::new();
    ticket.encode(&mut bytes).unwrap();
    assert_eq!(TLS13NewSessionTicket::decode(bytes.as_slice()), Err(illegal()));
    // Finished: exactly the length of the hash.
    assert_eq!(TLSFinished::decode(&[0; 31], 32), Err(decode_error()));
}

#[test]
fn registries_and_grease() {
    // RFC 8701 §2: 0x?A?A with equal bytes, in every registry.
    for value in [0x0A0A, 0x1A1A, 0xFAFA] {
        assert!(TLSVersion(value).is_grease() && TLSCipherSuite(value).is_grease());
        assert!(TLSNamedGroup(value).is_grease() && TLSExtensionType(value).is_grease());
    }
    assert!(!TLSVersion(0x0A1A).is_grease() && !TLSVersion(0x0B0B).is_grease());
    // RFC 9846 §4.3.3: no RSASSA-PKCS1-v1_5 in TLS 1.3 handshakes; no SHA-1 in either version.
    assert!(!TLSSignatureScheme::RSA_PKCS1_SHA256.signs_handshakes_of(TLSVersion::TLS1_3));
    assert!(TLSSignatureScheme::RSA_PKCS1_SHA256.signs_handshakes_of(TLSVersion::TLS1_2));
    assert!(!TLSSignatureScheme::ECDSA_SHA1.signs_handshakes_of(TLSVersion::TLS1_2));
    // RFC 10024: the hybrids are TLS 1.3 groups.
    assert!(TLSNamedGroup::X25519_MLKEM768.usable_with(TLSVersion::TLS1_3));
    assert!(!TLSNamedGroup::X25519_MLKEM768.usable_with(TLSVersion::TLS1_2));
    // Cipher suites name their version, AEAD and hash.
    assert_eq!(TLSCipherSuite::TLS_AES_256_GCM_SHA384.hash().unwrap().length(), 48);
    assert_eq!(TLSCipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.version(), Some(TLSVersion::TLS1_2));
    assert_eq!(TLSCipherSuite::TLS_AES_128_CCM_8_SHA256.aead().unwrap().tag_length(), 8);
}
