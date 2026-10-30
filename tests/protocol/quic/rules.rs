//! The rules each frame is checked by once a connection is established
//! (RFC 9000 §2–§5, §10, §13, §19; RFC 9221 §3): a client sends a frame
//! that breaks one, and the server closes with the error the RFC names,
//! which the client receives in a CONNECTION_CLOSE.

use umilib::protocol::quic::{
    QUICCloseReason, QUICConfig, QUICConnectionID, QUICConnectionState, QUICErrorCode, QUICEvent, QUICFrame,
    QUICFrameType, QUICStreamID, QUICVarint,
};

use super::connection::Network;

/// A connection that sent `frames`, encoded, and what each end ended with.
fn send(frames: &[Vec<u8>]) -> Network {
    let mut network = Network::new(QUICConfig::default());
    network.run();
    for frame in frames {
        // Once the server closed, nothing more goes.
        if network.client.send_extension_frame(frame.clone()).is_err() {
            break;
        }
        network.run();
    }
    network.run();
    network
}

fn encoded(frame: QUICFrame<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    frame.encode(&mut out).unwrap();
    out
}

/// The error the server closed with, which the client was told.
fn closed_with(frames: &[Vec<u8>]) -> QUICErrorCode {
    let mut network = send(frames);
    let server = network.server();
    assert_eq!(server.state, QUICConnectionState::Closing, "the server did not close");
    let error = Network::events(server)
        .into_iter()
        .find_map(|event| match event {
            QUICEvent::Closed { reason: QUICCloseReason::Local { error, .. } } => Some(error),
            _ => None,
        })
        .unwrap();
    let told = Network::events(&mut network.client).into_iter().find_map(|event| match event {
        QUICEvent::Closed { reason: QUICCloseReason::Peer { error, .. } } => Some(error),
        _ => None,
    });
    assert_eq!(told, Some(error), "the client was told the error");
    assert_eq!(network.client.state, QUICConnectionState::Draining);
    error
}

fn stream(stream: u64, offset: u64, data: &[u8], fin: bool) -> Vec<u8> {
    encoded(QUICFrame::Stream { stream: QUICStreamID(stream), offset, data, fin })
}

#[test]
fn streams_never_opened_or_without_the_half() {
    // RFC 9000 §19.8: STREAM for a locally initiated stream not yet created,
    // or for a send-only stream: STREAM_STATE_ERROR. Here the server's own
    // streams 1 (bidirectional) and 3 (unidirectional).
    assert_eq!(closed_with(&[stream(1, 0, b"x", false)]), QUICErrorCode::STREAM_STATE_ERROR);
    assert_eq!(closed_with(&[stream(3, 0, b"x", false)]), QUICErrorCode::STREAM_STATE_ERROR);
    // RFC 9000 §19.10, §19.5: MAX_STREAM_DATA and STOP_SENDING for the
    // client's unidirectional stream 2, which the server only receives.
    let open = stream(2, 0, b"x", false);
    let maximum = encoded(QUICFrame::MaxStreamData { stream: QUICStreamID(2), maximum: 100 });
    assert_eq!(closed_with(&[open.clone(), maximum]), QUICErrorCode::STREAM_STATE_ERROR);
    let stop = encoded(QUICFrame::StopSending { stream: QUICStreamID(2), error: 0 });
    assert_eq!(closed_with(&[open, stop]), QUICErrorCode::STREAM_STATE_ERROR);
    // RFC 9000 §19.4: RESET_STREAM for a send-only stream (the server's 3).
    let reset = encoded(QUICFrame::ResetStream { stream: QUICStreamID(3), error: 0, final_size: 0 });
    assert_eq!(closed_with(&[reset]), QUICErrorCode::STREAM_STATE_ERROR);
}

#[test]
fn streams_past_the_limit() {
    // RFC 9000 §4.6: opening the 101st bidirectional stream when 100 are allowed.
    let limit = QUICConfig::default().initial_max_streams_bidi;
    assert_eq!(closed_with(&[stream(4 * limit, 0, b"x", false)]), QUICErrorCode::STREAM_LIMIT_ERROR);
    // The last one allowed opens, with all those before it (RFC 9000 §3.2).
    let mut network = send(&[stream(4 * (limit - 1), 0, b"x", false)]);
    assert_eq!(network.server().state, QUICConnectionState::Established);
    let opened = Network::events(network.server())
        .into_iter()
        .filter(|event| matches!(event, QUICEvent::StreamOpened { .. }))
        .count();
    assert_eq!(opened as u64, limit);
}

#[test]
fn flow_control() {
    // RFC 9000 §4.1: data past the stream's limit, or the connection's.
    let window = QUICConfig::default().initial_max_stream_data_bidi_remote;
    assert_eq!(closed_with(&[stream(0, window, b"x", false)]), QUICErrorCode::FLOW_CONTROL_ERROR);
    assert!(send(&[stream(0, window - 1, b"x", false)]).server().state == QUICConnectionState::Established);
    // Many streams together past the connection's limit (1 MiB, 256 KiB each).
    let frames: Vec<Vec<u8>> = (0..5).map(|index| stream(4 * index, window - 1, b"x", false)).collect();
    assert_eq!(closed_with(&frames), QUICErrorCode::FLOW_CONTROL_ERROR);
}

#[test]
fn final_sizes() {
    // RFC 9000 §4.5: a final size that changes, data past it, or a reset below what was received.
    assert_eq!(
        closed_with(&[stream(0, 0, b"0123456789", true), stream(0, 0, b"0123456789ab", true)]),
        QUICErrorCode::FINAL_SIZE_ERROR
    );
    assert_eq!(closed_with(&[stream(0, 0, b"0123", true), stream(0, 4, b"x", false)]), QUICErrorCode::FINAL_SIZE_ERROR);
    assert_eq!(closed_with(&[stream(0, 10, b"x", false), stream(0, 0, b"abc", true)]), QUICErrorCode::FINAL_SIZE_ERROR);
    let reset = encoded(QUICFrame::ResetStream { stream: QUICStreamID(0), error: 7, final_size: 5 });
    assert_eq!(closed_with(&[stream(0, 0, b"0123456789", false), reset]), QUICErrorCode::FINAL_SIZE_ERROR);
    // The same final size again is fine, and a reset tells the application (RFC 9000 §3.2).
    let reset = encoded(QUICFrame::ResetStream { stream: QUICStreamID(0), error: 7, final_size: 10 });
    let mut network = send(&[stream(0, 0, b"0123456789", true), stream(0, 0, b"0123456789", true), reset]);
    assert_eq!(network.server().state, QUICConnectionState::Established);
}

#[test]
fn frames_a_client_never_sends() {
    // RFC 9000 §19.7, §19.20: NEW_TOKEN and HANDSHAKE_DONE from a client.
    assert_eq!(closed_with(&[encoded(QUICFrame::NewToken { token: b"t" })]), QUICErrorCode::PROTOCOL_VIOLATION);
    assert_eq!(closed_with(&[encoded(QUICFrame::HandshakeDone)]), QUICErrorCode::PROTOCOL_VIOLATION);
}

#[test]
fn connection_ids() {
    // RFC 9000 §19.16: retiring a sequence number never issued.
    let retire = encoded(QUICFrame::RetireConnectionID { sequence: 100 });
    assert_eq!(closed_with(&[retire]), QUICErrorCode::PROTOCOL_VIOLATION);
    // RFC 9000 §5.1.1: more active IDs than the server's
    // active_connection_id_limit (4): the client issued 4 already.
    let id = QUICConnectionID::new(&[7; 8]).unwrap();
    let extra = encoded(QUICFrame::NewConnectionID { sequence: 100, retire_prior_to: 0, id, reset_token: [7; 16] });
    assert_eq!(closed_with(&[extra]), QUICErrorCode::CONNECTION_ID_LIMIT_ERROR);
    // The same frame twice is no error (RFC 9000 §19.15); an ID reused under
    // another number, or a number reused for another ID, is.
    let mut network = Network::new(QUICConfig::default());
    network.run();
    let issued = network.client.local_ids.ids[&1];
    let again = encoded(QUICFrame::NewConnectionID {
        sequence: 1,
        retire_prior_to: 0,
        id: issued.id,
        reset_token: issued.reset_token.unwrap(),
    });
    network.client.send_extension_frame(again).unwrap();
    network.run();
    assert_eq!(network.server().state, QUICConnectionState::Established);
    let reused = encoded(QUICFrame::NewConnectionID { sequence: 1, retire_prior_to: 0, id, reset_token: [1; 16] });
    network.client.send_extension_frame(reused).unwrap();
    network.run();
    assert_eq!(network.server().state, QUICConnectionState::Closing);
}

#[test]
fn acknowledgments_of_packets_never_sent() {
    // RFC 9000 §13.1: an ACK of a packet number never sent.
    let ack = {
        let mut out = Vec::new();
        let ranges = [1_000_000..=1_000_001, 10..=20];
        umilib::protocol::quic::QUICACKFrame::encode_ranges(&ranges, 0, None, &mut out).unwrap();
        out
    };
    assert_eq!(closed_with(&[ack]), QUICErrorCode::PROTOCOL_VIOLATION);
}

#[test]
fn datagrams_not_advertised() {
    // RFC 9221 §3: a DATAGRAM frame to an end that did not advertise them.
    assert_eq!(closed_with(&[encoded(QUICFrame::Datagram { data: b"x" })]), QUICErrorCode::PROTOCOL_VIOLATION);
}

#[test]
fn malformed_and_unknown_frames() {
    // RFC 9000 §12.4: an unknown type is FRAME_ENCODING_ERROR, as is a frame cut short.
    assert_eq!(closed_with(&[vec![0x21]]), QUICErrorCode::FRAME_ENCODING_ERROR);
    let mut streams = vec![QUICFrameType::MAX_STREAMS_BIDI.0 as u8];
    QUICVarint::write(&mut streams, (1 << 60) + 1).unwrap();
    assert_eq!(closed_with(&[streams]), QUICErrorCode::FRAME_ENCODING_ERROR);
    assert_eq!(closed_with(&[vec![0x04, 0]]), QUICErrorCode::FRAME_ENCODING_ERROR);
}

#[test]
fn crypto_data_too_far_ahead() {
    // RFC 9000 §7.5: more CRYPTO data held than this end buffers.
    let crypto = encoded(QUICFrame::Crypto { offset: 1 << 20, data: b"x" });
    assert_eq!(closed_with(&[crypto]), QUICErrorCode::CRYPTO_BUFFER_EXCEEDED);
}

#[test]
fn the_amplification_limit() {
    // RFC 9000 §8.1: before the client's address is validated, the server
    // sends at most three times what it received.
    let mut network = Network::new(QUICConfig::default());
    // The client's second datagram and later ones are lost: the server only
    // ever has the first.
    network.drop = Box::new(|_, from_client, _| from_client);
    let mut first = Vec::new();
    network.client.transmit(network.now, &mut first).unwrap();
    network.deliver(true, &first);
    for _ in 0..20 {
        network.run();
        network.tick();
    }
    let sent: usize =
        network.delivered.iter().filter(|(from_client, _)| !from_client).map(|(_, datagram)| datagram.len()).sum();
    assert!(sent > 0 && sent <= 3 * first.len(), "{sent} bytes for {}", first.len());
}

#[test]
fn retirements_waiting_for_acknowledgment() {
    // RFC 9000 §5.1.2: an end allows at least twice its
    // active_connection_id_limit (4 here) of RETIRE_CONNECTION_ID frames not
    // yet acknowledged, and may close with CONNECTION_ID_LIMIT_ERROR past it.
    // Each NEW_CONNECTION_ID here retires one more, all in one packet.
    let retiring = |count: u64| {
        let mut frames = Vec::new();
        for sequence in 4..4 + count {
            let id = QUICConnectionID::new(&[sequence as u8; 8]).unwrap();
            frames.extend(encoded(QUICFrame::NewConnectionID {
                sequence,
                retire_prior_to: sequence - 3,
                id,
                reset_token: [sequence as u8; 16],
            }));
        }
        frames
    };
    let network = send(&[retiring(8)]);
    assert_eq!(network.server.as_ref().unwrap().state, QUICConnectionState::Established);
    // The IDs are made up, so the client cannot read the CONNECTION_CLOSE
    // sent to them: only the server's error is checked.
    let mut network = send(&[retiring(9)]);
    let error = Network::events(network.server()).into_iter().find_map(|event| match event {
        QUICEvent::Closed { reason: QUICCloseReason::Local { error, .. } } => Some(error),
        _ => None,
    });
    assert_eq!(error, Some(QUICErrorCode::CONNECTION_ID_LIMIT_ERROR));
}

#[test]
fn datagrams_by_their_size_on_the_wire() {
    // RFC 9221 §3: max_datagram_frame_size counts the frame's type, length
    // and data; a frame of type 0x30 has no length.
    let config = QUICConfig { max_datagram_frame_size: 100, ..QUICConfig::default() };
    let state = |frame: Vec<u8>| {
        let mut network = Network::new(config.clone());
        network.run();
        network.client.send_extension_frame(frame).unwrap();
        network.run();
        network.server().state
    };
    let without_length = |size: usize| {
        let mut frame = vec![0x30];
        frame.resize(size, 1);
        frame
    };
    assert_eq!(state(without_length(100)), QUICConnectionState::Established);
    assert_eq!(state(without_length(101)), QUICConnectionState::Closing);
    // The type, a Length of two bytes (97), and 97 bytes of data.
    let mut with_length = vec![0x31, 0x40, 97];
    with_length.resize(100, 1);
    assert_eq!(state(with_length.clone()), QUICConnectionState::Established);
    with_length[2] = 98;
    with_length.push(1);
    assert_eq!(state(with_length), QUICConnectionState::Closing);
}
