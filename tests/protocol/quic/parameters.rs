//! Transport parameters (RFC 9000 §7.4, §18; RFC 9221 §3; RFC 9287 §3;
//! RFC 9368 §3, §4).

use umilib::protocol::ip::{IPv4Address, IPv6Address};
use umilib::protocol::quic::{
    QUICConnectionID, QUICError, QUICErrorCode, QUICPreferredAddress, QUICRole, QUICTransportParameterID,
    QUICTransportParameters, QUICVarint, QUICVersion, QUICVersionInformation,
};

use super::QUICVectors;
use crate::Vectors;

fn error(bytes: &[u8], sender: QUICRole) -> QUICErrorCode {
    match QUICTransportParameters::decode(bytes, sender) {
        Err(QUICError::Transport(error)) => error.code,
        other => panic!("{bytes:02x?}: {other:?}"),
    }
}

fn parameter(id: u64, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    QUICVarint::write_all(&mut out, &[id, value.len() as u64]).unwrap();
    out.extend_from_slice(value);
    out
}

#[test]
fn the_client_hello_of_rfc_9001() {
    // The quic_transport_parameters extension (0x39) in the ClientHello of
    // RFC 9001 Appendix A.2.
    let crypto = QUICVectors::block(9001, "frames to make a 1162-byte payload:");
    let start = crypto.windows(4).position(|window| window == [0x00, 0x39, 0x00, 0x32]).unwrap() + 4;
    let parameters = QUICTransportParameters::decode(&crypto[start..start + 0x32], QUICRole::Client).unwrap();
    assert_eq!(parameters.initial_max_data, QUICVarint::MAXIMUM);
    assert_eq!(parameters.initial_max_stream_data_bidi_local, 0xFFFF);
    assert_eq!(parameters.initial_max_stream_data_bidi_remote, 0xFFFF);
    assert_eq!(parameters.initial_max_stream_data_uni, 0xFFFF);
    assert_eq!(parameters.initial_max_streams_bidi, 16);
    assert_eq!(parameters.initial_max_streams_uni, 16);
    assert_eq!(parameters.max_idle_timeout, 30_000);
    assert_eq!(parameters.initial_source_connection_id.unwrap().as_slice(), Vectors::hex("8394c8f03e515708"));
    // What it leaves out has its default (RFC 9000 §18.2).
    assert_eq!(parameters.max_udp_payload_size, 65_527);
    assert_eq!((parameters.ack_delay_exponent, parameters.max_ack_delay), (3, 25));
    assert_eq!(parameters.active_connection_id_limit, 2);
    assert!(!parameters.disable_active_migration && parameters.preferred_address.is_none());
}

#[test]
fn defaults_are_not_written() {
    let mut out = Vec::new();
    QUICTransportParameters::default().encode(&[], &mut out).unwrap();
    assert!(out.is_empty());
    assert_eq!(QUICTransportParameters::decode(&[], QUICRole::Server).unwrap(), QUICTransportParameters::default());
}

#[test]
fn every_parameter_round_trips() {
    let id = |byte: u8| QUICConnectionID::new(&[byte; 8]).unwrap();
    let parameters = QUICTransportParameters {
        original_destination_connection_id: Some(id(1)),
        max_idle_timeout: 30_000,
        stateless_reset_token: Some([7; 16]),
        max_udp_payload_size: 1452,
        initial_max_data: 1 << 20,
        initial_max_stream_data_bidi_local: 1 << 16,
        initial_max_stream_data_bidi_remote: 1 << 17,
        initial_max_stream_data_uni: 1 << 18,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 1 << 60,
        ack_delay_exponent: 20,
        max_ack_delay: (1 << 14) - 1,
        disable_active_migration: true,
        preferred_address: Some(QUICPreferredAddress {
            ipv4: IPv4Address::new(192, 0, 2, 1),
            ipv4_port: 443,
            ipv6: IPv6Address::LOOPBACK,
            ipv6_port: 8443,
            connection_id: id(3),
            reset_token: [4; 16],
        }),
        active_connection_id_limit: 8,
        initial_source_connection_id: Some(QUICConnectionID::EMPTY),
        retry_source_connection_id: Some(id(5)),
        version_information: Some(QUICVersionInformation {
            chosen: QUICVersion::V1,
            available: vec![QUICVersion::V2, QUICVersion::V1],
        }),
        max_datagram_frame_size: 65_535,
        grease_quic_bit: true,
    };
    let reserved = QUICTransportParameterID::reserved(3).unwrap();
    let mut out = Vec::new();
    parameters.encode(&[(reserved, b"ignored")], &mut out).unwrap();
    assert_eq!(QUICTransportParameters::decode(&out, QUICRole::Server).unwrap(), parameters);
    // Only reserved identifiers may be added (RFC 9000 §18.1: 31 × N + 27).
    assert_eq!(reserved, QUICTransportParameterID(31 * 3 + 27));
    assert!(parameters.encode(&[(QUICTransportParameterID(0x99), b"")], &mut Vec::new()).is_err());
}

#[test]
fn unknown_parameters_are_ignored() {
    // RFC 9000 §7.4.2, §18.1.
    let mut bytes = parameter(27, b"anything");
    bytes.extend(parameter(0x7F_FF00, &[]));
    bytes.extend(parameter(0x04, &[0x10]));
    let parameters = QUICTransportParameters::decode(&bytes, QUICRole::Client).unwrap();
    assert_eq!(parameters.initial_max_data, 16);
}

#[test]
fn invalid_parameters() {
    let invalid = QUICErrorCode::TRANSPORT_PARAMETER_ERROR;
    // Server-only parameters from a client (RFC 9000 §18.2).
    for id in [0x00, 0x02, 0x0D, 0x10] {
        let value = if id == 0x02 { vec![0; 16] } else { vec![1; 8] };
        assert_eq!(error(&parameter(id, &value), QUICRole::Client), invalid, "{id:#x}");
    }
    // Values out of range (RFC 9000 §18.2, §4.6).
    let cases: [(u64, u64); 6] =
        [(0x03, 1199), (0x0A, 21), (0x0B, 1 << 14), (0x0E, 1), (0x08, (1 << 60) + 1), (0x09, (1 << 60) + 1)];
    for (id, value) in cases {
        let mut encoded = Vec::new();
        QUICVarint::write(&mut encoded, value).unwrap();
        assert_eq!(error(&parameter(id, &encoded), QUICRole::Server), invalid, "{id:#x} = {value}");
    }
    for (id, value) in [(0x03u64, 1200u64), (0x0A, 20), (0x0B, (1 << 14) - 1), (0x0E, 2), (0x08, 1 << 60)] {
        let mut encoded = Vec::new();
        QUICVarint::write(&mut encoded, value).unwrap();
        assert!(QUICTransportParameters::decode(&parameter(id, &encoded), QUICRole::Server).is_ok(), "{id:#x}");
    }
    // An integer whose length is not its encoding's.
    assert_eq!(error(&parameter(0x04, &[0x10, 0]), QUICRole::Server), invalid);
    assert_eq!(error(&parameter(0x04, &[0x40]), QUICRole::Server), invalid);
    assert_eq!(error(&parameter(0x04, &[]), QUICRole::Server), invalid);
    // A stateless reset token not of 16 bytes; a connection ID above 20.
    assert_eq!(error(&parameter(0x02, &[0; 15]), QUICRole::Server), invalid);
    assert_eq!(error(&parameter(0x0F, &[0; 21]), QUICRole::Server), invalid);
    // Flags with a value (RFC 9000 §18.2, RFC 9287 §3).
    assert_eq!(error(&parameter(0x0C, &[0]), QUICRole::Server), invalid);
    assert_eq!(error(&parameter(0x2AB2, &[0]), QUICRole::Server), invalid);
    // A preferred address with an empty connection ID (RFC 9000 §18.2).
    let mut address = vec![0; 4 + 2 + 16 + 2];
    address.push(0);
    address.extend_from_slice(&[0; 16]);
    assert_eq!(error(&parameter(0x0D, &address), QUICRole::Server), invalid);
    // A parameter repeated (RFC 9000 §7.4).
    let mut bytes = parameter(0x04, &[1]);
    bytes.extend(parameter(0x05, &[1]));
    bytes.extend(parameter(0x04, &[1]));
    assert_eq!(error(&bytes, QUICRole::Server), invalid);
    // Cut short.
    assert_eq!(error(&[0x04, 2, 1], QUICRole::Server), invalid);
    assert_eq!(error(&[0x40], QUICRole::Server), invalid);
}

#[test]
fn version_information() {
    // RFC 9368 §4: too short, not a multiple of 4, a zero version, or a
    // client's Chosen Version not among its Available Versions.
    let invalid = QUICErrorCode::TRANSPORT_PARAMETER_ERROR;
    let words = |versions: &[u32]| versions.iter().flat_map(|version| version.to_be_bytes()).collect::<Vec<u8>>();
    for value in
        [vec![], vec![0, 0, 1], words(&[1, 2]).into_iter().chain([0]).collect(), words(&[0, 1]), words(&[1, 0, 1])]
    {
        assert_eq!(error(&parameter(0x11, &value), QUICRole::Server), invalid, "{value:02x?}");
    }
    assert_eq!(error(&parameter(0x11, &words(&[1, 0x6B33_43CF])), QUICRole::Client), invalid);
    // A server's Available Versions may leave out its Chosen Version, or be empty (RFC 9368 §3).
    let parameters = QUICTransportParameters::decode(&parameter(0x11, &words(&[1])), QUICRole::Server).unwrap();
    let information = parameters.version_information.unwrap();
    assert_eq!((information.chosen, information.available), (QUICVersion::V1, vec![]));
    let parameters =
        QUICTransportParameters::decode(&parameter(0x11, &words(&[1, 0x6B33_43CF, 1])), QUICRole::Client).unwrap();
    assert_eq!(parameters.version_information.unwrap().available, [QUICVersion::V2, QUICVersion::V1]);
}

#[test]
fn reserved_identifiers() {
    // RFC 9000 §18.1: 31 × N + 27.
    for n in [0u64, 1, 2, 1000] {
        let id = QUICTransportParameterID::reserved(n).unwrap();
        assert_eq!(id.0, 31 * n + 27);
        assert!(id.is_reserved());
    }
    assert!(!QUICTransportParameterID::MAX_IDLE_TIMEOUT.is_reserved());
    assert!(QUICTransportParameterID::reserved(u64::MAX / 31).is_none());
}

#[test]
fn values_the_peer_would_refuse_are_not_written() {
    // RFC 9000 §18.2: what decoding refuses, encoding refuses too.
    let invalid = [
        QUICTransportParameters { max_udp_payload_size: 1199, ..QUICTransportParameters::default() },
        QUICTransportParameters { ack_delay_exponent: 21, ..QUICTransportParameters::default() },
        QUICTransportParameters { max_ack_delay: 1 << 14, ..QUICTransportParameters::default() },
        QUICTransportParameters { active_connection_id_limit: 1, ..QUICTransportParameters::default() },
        QUICTransportParameters { initial_max_streams_bidi: (1 << 60) + 1, ..QUICTransportParameters::default() },
        QUICTransportParameters { initial_max_streams_uni: (1 << 60) + 1, ..QUICTransportParameters::default() },
        QUICTransportParameters {
            preferred_address: Some(QUICPreferredAddress {
                ipv4: IPv4Address::new(192, 0, 2, 1),
                ipv4_port: 443,
                ipv6: IPv6Address([0; 16]),
                ipv6_port: 0,
                connection_id: QUICConnectionID::EMPTY,
                reset_token: [0; 16],
            }),
            ..QUICTransportParameters::default()
        },
        QUICTransportParameters {
            version_information: Some(QUICVersionInformation { chosen: QUICVersion(0), available: Vec::new() }),
            ..QUICTransportParameters::default()
        },
    ];
    for parameters in invalid {
        assert!(matches!(parameters.encode(&[], &mut Vec::new()), Err(QUICError::Config)), "{parameters:?}");
    }
}
