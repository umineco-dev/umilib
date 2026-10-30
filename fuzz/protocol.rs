//! Fuzz targets of `umilib::protocol`.

use umilib::platform::fuzz::FuzzTarget;

/// The codecs of HTTP's semantics return without panicking: structured
/// fields that parse serialize to text that parses the same (RFC 9651
/// §4.1), authorities and targets, priorities, and content decoding under
/// a limit.
#[cfg(umilib_feature = "protocol-http")]
pub const HTTP: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-http", |data| {
        use umilib::protocol::http::{
            HTTPAuthority, HTTPContentDecoder, HTTPPriority, HTTPStructuredField, HTTPTarget,
        };
        let Some((&selector, rest)) = data.split_first() else { return };
        match selector % 5 {
            0 => {
                if let Ok(list) = HTTPStructuredField::parse_list(rest) {
                    let mut text = Vec::new();
                    if HTTPStructuredField::serialize_list(&list, &mut text).is_ok() {
                        assert_eq!(HTTPStructuredField::parse_list(&text).expect("a list serialized parses"), list);
                    }
                }
            }
            1 => {
                if let Ok(dictionary) = HTTPStructuredField::parse_dictionary(rest) {
                    let mut text = Vec::new();
                    if HTTPStructuredField::serialize_dictionary(&dictionary, &mut text).is_ok() {
                        let again =
                            HTTPStructuredField::parse_dictionary(&text).expect("a dictionary serialized parses");
                        assert_eq!(again, dictionary);
                    }
                }
            }
            2 => {
                if let Ok(item) = HTTPStructuredField::parse_item(rest) {
                    let mut text = Vec::new();
                    if HTTPStructuredField::serialize_item(&item, &mut text).is_ok() {
                        assert_eq!(HTTPStructuredField::parse_item(&text).expect("an item serialized parses"), item);
                    }
                }
                let _ = HTTPPriority::parse(rest);
            }
            3 => {
                if let Ok(authority) = HTTPAuthority::parse(rest) {
                    let mut text = Vec::new();
                    authority.write(&mut text);
                    assert_eq!(HTTPAuthority::parse(&text).expect("an authority written parses"), authority);
                }
                let _ = HTTPTarget::parse(rest);
            }
            _ => {
                let Some(split) = rest.iter().position(|&byte| byte == b'\n') else { return };
                if let Ok(mut decoder) = HTTPContentDecoder::new(&rest[..split], 1 << 16) {
                    let mut out = Vec::new();
                    if decoder.decode(&rest[split + 1..], &mut out).is_ok() {
                        let _ = decoder.finish();
                    }
                    assert!(out.len() <= 1 << 16, "the limit holds");
                }
            }
        }
    });

/// HTTP/1.1 servers and clients given any bytes, in pieces, return without
/// panicking; each request is answered and its content read.
#[cfg(umilib_feature = "protocol-http-v1")]
pub const HTTP_V1: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-http-v1", |data| {
        use umilib::protocol::http::v1::{H1Config, H1Connection};
        use umilib::protocol::http::{HTTPConnection, HTTPEvent, HTTPMethod, HTTPRequest, HTTPResponse, HTTPStatus};
        use umilib::runtime::Instant;
        let Some((&selector, rest)) = data.split_first() else { return };
        let now = Instant::from_nanos(1);
        let config = H1Config { maximum_pipelined: 4, ..H1Config::default() };
        let mut server = H1Connection::server(config.clone(), now);
        let mut client = H1Connection::client(config, now);
        let _ = client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"http", b"a", b"/"), true);
        let _ = client.send_request(&HTTPRequest::new(HTTPMethod::HEAD, b"http", b"a", b"/"), true);
        let mut buffer = [0u8; 256];
        let mut out = Vec::new();
        for piece in rest.chunks(usize::from(selector).max(1)) {
            for connection in [&mut server, &mut client] {
                connection.receive(piece, now);
                while let Some(event) = connection.poll_event() {
                    match event {
                        HTTPEvent::Request { stream, .. } => {
                            let _ = connection.send_response(stream, &HTTPResponse::new(HTTPStatus::OK), false);
                            let _ = connection.send_data(stream, b"ok", true);
                        }
                        HTTPEvent::Data { stream } => {
                            while connection.read_data(stream, &mut buffer).is_ok_and(|count| count > 0) {}
                        }
                        _ => {}
                    }
                }
                connection.transmit(&mut out);
                out.clear();
            }
        }
        server.receive_close(now);
        client.receive_close(now);
        server.expire(Instant::from_nanos(u64::MAX / 2));
    });

/// HTTP/2 servers and clients given any frames after their prefaces return
/// without panicking; requests are answered and content read.
#[cfg(umilib_feature = "protocol-http-v2")]
pub const HTTP_V2: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-http-v2", |data| {
        use umilib::protocol::http::v2::{H2Config, H2Connection};
        use umilib::protocol::http::{HTTPConnection, HTTPEvent, HTTPMethod, HTTPRequest, HTTPResponse, HTTPStatus};
        use umilib::runtime::Instant;
        let Some((&selector, rest)) = data.split_first() else { return };
        let now = Instant::from_nanos(1);
        let config = H2Config { enable_connect_protocol: true, ..H2Config::default() };
        let mut server = H2Connection::server(config, now);
        let mut client = H2Connection::client(config, now);
        let _ = client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"https", b"a", b"/"), true);
        let mut out = Vec::new();
        client.transmit(&mut out);
        // The client's preface and SETTINGS, then the input, to the server; the input alone to the client.
        let preface = out.clone();
        out.clear();
        server.receive(&preface, now);
        let mut buffer = [0u8; 256];
        for piece in rest.chunks(usize::from(selector).max(9)) {
            for connection in [&mut server, &mut client] {
                connection.receive(piece, now);
                while let Some(event) = connection.poll_event() {
                    match event {
                        HTTPEvent::Request { stream, .. } => {
                            let _ = connection.send_response(stream, &HTTPResponse::new(HTTPStatus::OK), false);
                            let _ = connection.send_data(stream, b"ok", true);
                        }
                        HTTPEvent::Data { stream } => {
                            while connection.read_data(stream, &mut buffer).is_ok_and(|count| count > 0) {}
                        }
                        _ => {}
                    }
                }
                connection.transmit(&mut out);
                out.clear();
            }
        }
        server.expire(Instant::from_nanos(u64::MAX / 2));
        client.receive_close();
    });

/// The codecs of HTTP/3 return without panicking: frame headers, and
/// SETTINGS that decode encode to SETTINGS that decode the same.
#[cfg(umilib_feature = "protocol-http-v3")]
pub const HTTP_V3: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-http-v3", |data| {
        use umilib::protocol::http::v3::{H3FrameHeader, H3Settings};
        let mut input = data;
        while let Some((header, length)) = H3FrameHeader::decode(input) {
            input = &input[length..];
            let take = usize::try_from(header.length).unwrap_or(usize::MAX).min(input.len());
            if let Ok(settings) = H3Settings::decode(&input[..take]) {
                let mut again = Vec::new();
                settings.encode(None, &mut again);
                assert_eq!(H3Settings::decode(&again).expect("SETTINGS written decode"), settings);
            }
            input = &input[take..];
        }
    });

/// WebSocket clients and servers, with and without permessage-deflate,
/// given any bytes in pieces return without panicking and never deliver a
/// message larger than their limit; frame headers that decode encode the same.
#[cfg(umilib_feature = "protocol-websocket")]
pub const WEBSOCKET: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-websocket", |data| {
        use umilib::protocol::websocket::{
            WebSocketConfig, WebSocketConnection, WebSocketDeflateParameters, WebSocketEvent, WebSocketFrameHeader,
            WebSocketRole,
        };
        let Some((&selector, rest)) = data.split_first() else { return };
        if let Ok(Some((header, length))) = WebSocketFrameHeader::decode(rest) {
            let mut again = Vec::new();
            header.encode(&mut again);
            assert_eq!(WebSocketFrameHeader::decode(&again), Ok(Some((header, length))));
        }
        let role = if selector & 1 == 0 { WebSocketRole::Client } else { WebSocketRole::Server };
        let deflate = (selector & 2 != 0).then(WebSocketDeflateParameters::default);
        let config =
            WebSocketConfig { maximum_message_size: 1 << 12, maximum_frame_size: 512, ..WebSocketConfig::default() };
        let random =
            umilib::crypto::random::HMACDRBG::<umilib::hash::sha::v2::SHA256>::new(&[5; 32], &[6; 16], b"fuzz")
                .expect("a DRBG");
        let Ok(mut connection) = WebSocketConnection::new(role, config, deflate, Box::new(random)) else { return };
        let mut out = Vec::new();
        for piece in rest.chunks(usize::from(selector >> 2).max(1)) {
            connection.receive(piece);
            while let Some(event) = connection.poll_event() {
                match event {
                    WebSocketEvent::Text(text) => assert!(text.len() <= 1 << 12),
                    WebSocketEvent::Binary(data) => {
                        assert!(data.len() <= 1 << 12);
                        let _ = connection.send_binary(&data);
                    }
                    _ => {}
                }
            }
            connection.transmit(&mut out);
            out.clear();
        }
        connection.receive_close();
    });

/// JWKs, JWK Sets, JWS, JWE and JWT claims decode without panicking; what
/// decodes writes back to what decodes the same (the compact serializations
/// to their text); verification and decryption under fixed keys return.
#[cfg(umilib_feature = "protocol-jwt")]
pub const JWT: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-jwt", |data| {
        use umilib::protocol::jwt::{
            JWE, JWEAlgorithm, JWEConfig, JWEEncryption, JWK, JWKSet, JWS, JWSAlgorithm, JWSConfig, JWT, JWTClaims,
            JWTValidation,
        };
        let Some((&selector, rest)) = data.split_first() else { return };
        let keys = JWTKeys::all();
        let mut random = JWTKeys::random();
        let signing = JWSConfig::new(&JWSAlgorithm::ALL);
        let mut decryption = JWEConfig::new(&JWEAlgorithm::ALL, &JWEEncryption::ALL);
        // Bounded work per input: the fewest PBES2 iterations, a small plaintext after decompression.
        decryption.maximum_pbes2_count = JWEAlgorithm::MINIMUM_PBES2_COUNT;
        decryption.compression = true;
        decryption.maximum_decompressed = 1 << 16;
        let text = core::str::from_utf8(rest).ok();
        match selector % 7 {
            0 => {
                if let Ok(jwk) = JWK::from_json(rest) {
                    let again = JWK::from_json(jwk.to_json().as_bytes()).expect("a JWK written reads back");
                    assert_eq!(again.to_json(), jwk.to_json());
                    assert_eq!(again.thumbprint_input().ok(), jwk.thumbprint_input().ok());
                    let _ = jwk.check();
                    let _ = jwk.to_public();
                }
            }
            1 => {
                if let Ok(set) = JWKSet::from_json(rest) {
                    let again = JWKSet::from_json(set.to_json().as_bytes()).expect("a set written reads back");
                    assert_eq!(again.keys.len(), set.keys.len());
                }
            }
            2 => {
                if let Some(text) = text
                    && let Ok(jws) = JWS::from_compact(text)
                {
                    assert_eq!(jws.to_compact().expect("a compact JWS read writes back"), text);
                    for key in &keys {
                        let _ = jws.verify(key, &signing);
                    }
                    let _ = jws.verify_unsecured();
                }
            }
            3 => {
                if let Ok(jws) = JWS::from_json(rest) {
                    let again = JWS::from_json(jws.to_json().expect("a JWS read writes").as_bytes());
                    assert_eq!(again.expect("a JWS written reads back"), jws);
                    for key in &keys {
                        let _ = jws.verify(key, &signing);
                    }
                }
            }
            4 => {
                if let Some(text) = text
                    && let Ok(jwe) = JWE::from_compact(text)
                {
                    assert_eq!(jwe.to_compact().expect("a compact JWE read writes back"), text);
                    for key in &keys {
                        let _ = jwe.decrypt(key, &decryption, &mut random);
                    }
                }
            }
            5 => {
                if let Ok(jwe) = JWE::from_json(rest) {
                    let again = JWE::from_json(jwe.to_json().expect("a JWE read writes").as_bytes());
                    assert_eq!(again.expect("a JWE written reads back"), jwe);
                    for key in &keys {
                        let _ = jwe.decrypt(key, &decryption, &mut random);
                    }
                }
            }
            _ => {
                if let Ok(claims) = JWTClaims::decode(rest) {
                    assert_eq!(
                        JWTClaims::decode(claims.encode().as_bytes()).expect("claims written read back"),
                        claims
                    );
                    let _ = JWTValidation::new(1_300_000_000).validate(&Default::default(), &claims);
                }
                if let Some(text) = text {
                    for key in &keys {
                        let _ = JWT::verify(text, key, &signing, &JWTValidation::new(1_300_000_000));
                        let _ = JWT::decrypt(text, key, &decryption, &JWTValidation::new(1_300_000_000), &mut random);
                    }
                }
            }
        }
    });

/// The keys the JWT target verifies and decrypts with: a symmetric key of
/// each size of AES, a password, and keys of P-256 (RFC 7518 appendix C)
/// and X25519 (RFC 7748 §6.1).
#[cfg(umilib_feature = "protocol-jwt")]
pub struct JWTKeys;

#[cfg(umilib_feature = "protocol-jwt")]
impl JWTKeys {
    pub fn all() -> Vec<umilib::protocol::jwt::JWK> {
        use umilib::protocol::jwt::JWK;
        let mut keys: Vec<JWK> =
            [16usize, 24, 32, 48, 64].iter().map(|&size| JWK::symmetric(&vec![0x42; size])).collect();
        keys.push(JWK::symmetric(b"password"));
        for text in [
            r#"{"kty":"EC","crv":"P-256","x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ","y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck","d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#,
            r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08","d":"XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os"}"#,
        ] {
            keys.push(JWK::from_json(text.as_bytes()).expect("a fixed key"));
        }
        keys
    }

    /// The generator of the target (the same bytes on every run).
    pub fn random() -> umilib::crypto::random::HMACDRBG<umilib::hash::sha::v2::SHA256> {
        umilib::crypto::random::HMACDRBG::new(&[5; 32], &[6; 16], b"umilib fuzz jwt").expect("a fixed seed")
    }
}

/// Address texts read back from what they write; the checksum does not
/// depend on how its data is split and its incremental update agrees with
/// recomputing it; the reassembly buffer keeps its ranges in order and apart.
#[cfg(umilib_feature = "protocol-ip")]
pub const IP: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-ip", |data| {
        use umilib::protocol::ip::{IPAddress, IPFragmentBuffer, InternetChecksum};
        let Some((&selector, rest)) = data.split_first() else { return };
        match selector % 3 {
            0 => {
                if let Ok(address) = IPAddress::from_ascii(rest) {
                    let text = address.to_string();
                    assert_eq!(text.parse::<IPAddress>(), Ok(address), "{text}");
                }
            }
            1 => {
                let split = rest.first().map_or(0, |&split| split as usize % (rest.len() + 1));
                let mut checksum = InternetChecksum::new();
                checksum.update(&rest[..split]);
                checksum.update(&rest[split..]);
                assert_eq!(checksum.finish(), InternetChecksum::checksum(rest));
                if rest.len() >= 4 {
                    let mut changed = rest.to_vec();
                    let at = split & !1;
                    if at + 2 <= changed.len() {
                        let old = u16::from_be_bytes([changed[at], changed[at + 1]]);
                        changed[at] ^= 0x5A;
                        let new = u16::from_be_bytes([changed[at], changed[at + 1]]);
                        let adjusted = InternetChecksum::adjust(InternetChecksum::checksum(rest), old, new);
                        // One's complement has two zeros: the adjusted and recomputed sums are the same number.
                        assert_eq!(
                            InternetChecksum::fold(adjusted as u64 + 1),
                            InternetChecksum::fold(InternetChecksum::checksum(&changed) as u64 + 1)
                        );
                    }
                }
            }
            _ => {
                let mut buffer = IPFragmentBuffer::new();
                for operation in rest.chunks(4) {
                    let [offset, length, flags, fill] =
                        [0, 1, 2, 3].map(|index| operation.get(index).copied().unwrap_or(0));
                    let bytes = [fill; 64];
                    let _ = buffer.insert(offset as usize, &bytes[..length as usize % 64], flags & 1 != 0, 512);
                    // The fragments are apart, end with the data, and add up to the count received.
                    let ends: Vec<(usize, usize)> =
                        buffer.fragments.iter().map(|(&start, &end)| (start, end)).collect();
                    assert!(ends.windows(2).all(|pair| pair[0].1 <= pair[1].0));
                    assert!(ends.iter().all(|&(start, end)| start < end));
                    assert_eq!(buffer.data.len(), ends.last().map_or(0, |&(_, end)| end));
                    assert_eq!(buffer.received_length(), ends.iter().map(|&(start, end)| end - start).sum::<usize>());
                    assert_eq!(buffer.is_complete(), buffer.length == Some(buffer.received_length()));
                    assert!(buffer.length.is_none_or(|length| buffer.data.len() <= length));
                }
            }
        }
    });

/// Headers that decode write back to headers that decode the same; a
/// datagram cut into fragments for any MTU reassembles in any order; the
/// reassembler counts the bytes it holds.
#[cfg(umilib_feature = "protocol-ip-v4")]
pub const IP_V4: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-ip-v4", |data| {
        use umilib::bytes::Buffer;
        use umilib::protocol::ip::v4::{IPv4Fragmenter, IPv4Header, IPv4Reassembler, IPv4ReassemblyConfig};
        use umilib::runtime::Instant;
        let Some((&selector, rest)) = data.split_first() else { return };
        let Ok((header, payload)) = IPv4Header::decode(rest) else {
            if selector % 2 == 1 {
                IPv4Fuzz::reassemble_fragments(rest);
            }
            return;
        };
        let mut bytes = Buffer::new();
        header.encode(&mut bytes).expect("a buffer takes the header");
        let mut again = bytes.into_vec();
        again.extend_from_slice(payload);
        assert_eq!(IPv4Header::decode(&again), Ok((header, payload)));
        let mtu = 68 + selector as usize * 7;
        if let Ok(fragmenter) =
            IPv4Fragmenter::new(IPv4Header { more_fragments: false, fragment_offset: 0, ..header }, payload, mtu)
        {
            let fragments: Vec<_> = fragmenter.collect();
            let mut reassembler = IPv4Reassembler::new(IPv4ReassemblyConfig::default());
            let mut whole = None;
            for (fragment, part) in fragments.iter().rev() {
                assert!(fragment.total_length as usize <= mtu.max(header.header_length() + payload.len()));
                whole = whole.or(reassembler
                    .receive(fragment, part, Instant::ZERO)
                    .expect("fragments of one datagram reassemble"));
            }
            assert_eq!(whole.map(|(_, data)| data).as_deref(), Some(payload));
        }
    });

/// The steps of the IPv4 target.
#[cfg(umilib_feature = "protocol-ip-v4")]
pub struct IPv4Fuzz;

#[cfg(umilib_feature = "protocol-ip-v4")]
impl IPv4Fuzz {
    /// Feeds fragments made of `data` (offset, flags, length and fill of each) to a reassembler
    /// with small limits, checking its accounting.
    pub fn reassemble_fragments(data: &[u8]) {
        use umilib::protocol::ip::v4::{IPv4Header, IPv4Reassembler, IPv4ReassemblyConfig};
        use umilib::protocol::ip::{IPProtocol, IPv4Address};
        use umilib::runtime::Instant;
        let config = IPv4ReassemblyConfig {
            maximum_datagrams: 4,
            maximum_buffered: 4096,
            maximum_length: 2048,
            ..IPv4ReassemblyConfig::default()
        };
        let mut reassembler = IPv4Reassembler::new(config);
        for (step, operation) in data.chunks(4).enumerate() {
            let [offset, flags, length, fill] = [0, 1, 2, 3].map(|index| operation.get(index).copied().unwrap_or(0));
            let mut header = IPv4Header::new(IPv4Address::LOOPBACK, IPv4Address::LOOPBACK, IPProtocol::UDP, 0)
                .expect("an empty datagram");
            header.identification = (flags >> 4) as u16;
            header.more_fragments = flags & 1 != 0;
            header.fragment_offset = offset as u16 * 3;
            let part = [fill; 255];
            let now = Instant::from_nanos(step as u64 * 7_000_000_000);
            let _ = reassembler.receive(&header, &part[..length as usize], now);
            while reassembler.expire(now).is_some() {}
            let held: usize = reassembler.table.entries.values().map(|reassembly| reassembly.memory()).sum();
            assert_eq!(reassembler.table.buffered, held);
            assert!(
                reassembler.table.buffered <= config.maximum_buffered
                    && reassembler.table.len() <= config.maximum_datagrams
            );
        }
    }
}

/// Headers and extension header chains decode without panicking and write
/// back the same; a packet cut into fragments for any MTU reassembles; the
/// reassembler counts the bytes it holds.
#[cfg(umilib_feature = "protocol-ip-v6")]
pub const IP_V6: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-ip-v6", |data| {
        use umilib::bytes::Buffer;
        use umilib::protocol::ip::IPProtocol;
        use umilib::protocol::ip::v6::{
            IPv6ExtensionHeaders, IPv6Fragmenter, IPv6Header, IPv6OptionsHeader, IPv6Reassembler, IPv6ReassemblyConfig,
            IPv6RoutingHeader,
        };
        use umilib::runtime::Instant;
        let Some((&selector, rest)) = data.split_first() else { return };
        let Ok((header, payload)) = IPv6Header::decode(rest) else { return };
        let mut bytes = Buffer::new();
        header.encode(&mut bytes).expect("a buffer takes the header");
        assert_eq!(bytes.as_slice(), &rest[..IPv6Header::LENGTH]);
        for extension in IPv6ExtensionHeaders::new(header.next_header, payload) {
            let Ok(extension) = extension else { break };
            match extension.kind {
                IPProtocol::HOP_BY_HOP_OPTIONS | IPProtocol::IPV6_DESTINATION_OPTIONS => {
                    if let Ok(options) = IPv6OptionsHeader::decode(extension.bytes) {
                        let mut written = Buffer::new();
                        options.encode(&mut written).expect("options that fit write");
                        assert_eq!(written.as_slice(), extension.bytes);
                        for option in options.iter() {
                            option.expect("decoded options iterate");
                        }
                    }
                }
                IPProtocol::IPV6_ROUTING => {
                    if let Ok(routing) = IPv6RoutingHeader::decode(extension.bytes) {
                        let mut written = Buffer::new();
                        routing.encode(&mut written).expect("a routing header read writes");
                        assert_eq!(written.as_slice(), extension.bytes);
                    }
                }
                _ => {}
            }
        }
        let mut reassembler =
            IPv6Reassembler::new(IPv6ReassemblyConfig { maximum_datagrams: 2, ..IPv6ReassemblyConfig::default() });
        let _ = reassembler.receive(&header, payload, Instant::ZERO);
        let held: usize = reassembler.table.entries.values().map(|reassembly| reassembly.memory()).sum();
        assert_eq!(reassembler.table.buffered, held);
        let mtu = 1280 + selector as usize * 3;
        if let Ok(fragmenter) = IPv6Fragmenter::new(header, payload, 1, mtu) {
            let mut reassembler = IPv6Reassembler::new(IPv6ReassemblyConfig::default());
            let mut whole = None;
            for fragment in fragmenter {
                let mut packet = Buffer::new();
                fragment.encode(&mut packet).expect("a buffer takes the fragment");
                assert!(packet.len() <= mtu.max(IPv6Header::LENGTH + payload.len()));
                let (decoded, part) = IPv6Header::decode(packet.as_slice()).expect("a fragment decodes");
                if let Ok(done) = reassembler.receive(&decoded, part, Instant::ZERO) {
                    whole = whole.or(done);
                }
            }
            if let Some((_, reassembled)) = whole {
                assert_eq!(reassembled, payload);
            }
        }
    });

/// Headers that decode write back to headers that decode the same; MAC
/// address texts read back from what they write.
#[cfg(umilib_feature = "protocol-ethernet")]
pub const ETHERNET: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-ethernet", |data| {
        use umilib::bytes::Buffer;
        use umilib::protocol::ethernet::{EthernetError, EthernetFrame, EthernetHeader, MACAddress};
        if let Ok(address) = MACAddress::from_ascii(data) {
            assert_eq!(address.to_string().parse::<MACAddress>(), Ok(address));
        }
        if let Ok((header, payload)) = EthernetHeader::decode(data) {
            let mut bytes = Buffer::new();
            // A decoded header writes back, except a tag with the reserved
            // VLAN identifier 4,095, which is read but never sent (IEEE 802.1Q).
            let reserved = header.tags.iter().flatten().any(|tag| tag.identifier == 4095);
            if let Err(error) = header.encode(&mut bytes) {
                assert!(reserved && error == EthernetError::Tag, "{error}");
                return;
            }
            assert_eq!(bytes.as_slice(), &data[..header.length()]);
            let mut again = bytes.into_vec();
            again.extend_from_slice(payload);
            assert_eq!(EthernetHeader::decode(&again), Ok((header, payload)));
        }
        let mut frame = data.to_vec();
        frame.extend_from_slice(&EthernetFrame::fcs(data));
        assert!(EthernetFrame::verify(&frame));
    });

/// Packets that decode write back the same; a cache fed any packets and
/// times answers and stays within its limits.
#[cfg(umilib_feature = "protocol-arp")]
pub const ARP: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-arp", |data| {
        use umilib::bytes::Buffer;
        use umilib::protocol::arp::{ARPCache, ARPConfig, ARPPacket};
        use umilib::protocol::ethernet::MACAddress;
        use umilib::protocol::ip::IPv4Address;
        use umilib::runtime::Instant;
        let config = ARPConfig { maximum_entries: 8, maximum_queued: 2, ..ARPConfig::default() };
        let mut cache: ARPCache = ARPCache::new(config);
        let local = [IPv4Address::new(10, 0, 0, 1), IPv4Address::new(10, 0, 0, 2)];
        let hardware = MACAddress([2, 0, 0, 0, 0, 1]);
        for (step, chunk) in data.chunks(29).enumerate() {
            let now = Instant::from_nanos(step as u64 * 400_000_000);
            if let Ok(packet) = ARPPacket::<MACAddress, IPv4Address>::decode(&chunk[1..]) {
                let mut bytes = Buffer::new();
                packet.encode(&mut bytes).expect("a decoded packet writes");
                assert_eq!(bytes.as_slice(), &chunk[1..29]);
                let reception = cache.receive(&packet, hardware, &local, now);
                if let Some(reply) = reception.reply {
                    assert_eq!(reply.sender_hardware, hardware);
                    assert!(local.contains(&reply.sender_protocol));
                }
            } else if let Some(&last) = chunk.last() {
                let _ = cache.resolve(IPv4Address::new(10, 0, 0, last % 16), Some(chunk.to_vec()), now);
            }
            while cache.poll(now).is_some() {}
            assert!(cache.entries.len() <= config.maximum_entries);
        }
    });

/// Extension structures that decode write back to structures of the same
/// objects; bodies split into an original datagram and a structure that
/// decodes; a rate limiter never holds more tokens than its burst.
#[cfg(umilib_feature = "protocol-icmp")]
pub const ICMP: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-icmp", |data| {
        use core::time::Duration;
        use umilib::bytes::Buffer;
        use umilib::protocol::icmp::{ICMPExtensions, ICMPRateLimitConfig, ICMPRateLimiter};
        use umilib::runtime::Instant;
        let Some((&selector, rest)) = data.split_first() else { return };
        if let Ok(extensions) = ICMPExtensions::decode(rest) {
            let objects: Vec<_> = extensions.iter().map(|object| object.expect("decoded objects iterate")).collect();
            let mut bytes = Buffer::new();
            ICMPExtensions { checksum: 0, objects: extensions.objects }.encode(&mut bytes).expect("a structure writes");
            let again = ICMPExtensions::decode(bytes.as_slice()).expect("a written structure decodes");
            assert_eq!(again.objects, extensions.objects);
            assert_eq!(again.iter().map(Result::unwrap).collect::<Vec<_>>(), objects);
            let mut body = Buffer::new();
            if let Ok(attribute) = extensions.encode_body(rest, 4 << (selector & 1), &mut body) {
                let (original, found) =
                    ICMPExtensions::split_body(body.as_slice(), attribute, 4 << (selector & 1)).expect("a body splits");
                assert_eq!(&original[..rest.len()], rest);
                assert_eq!(found.expect("the structure follows").objects, extensions.objects);
            }
        }
        if let Ok((original, Some(extensions))) = ICMPExtensions::split_body(rest, selector, 4) {
            assert_eq!(original.len(), selector as usize * 4);
            assert!(ICMPExtensions::decode(&rest[original.len()..]).is_ok_and(|again| again == extensions));
        }
        let config = ICMPRateLimitConfig { burst: u32::from(selector & 15), interval: Duration::from_millis(100) };
        let mut limiter = ICMPRateLimiter::new(config, Instant::ZERO);
        let mut now = 0u64;
        for &step in rest {
            now = now.saturating_add(u64::from(step) * 1_000_000);
            limiter.allow(Instant::from_nanos(now));
            assert!(limiter.tokens <= config.burst);
        }
    });

/// Messages built from any bytes write what decodes back to them; the
/// fields, the invoking datagram and the rules of error messages answer.
#[cfg(umilib_feature = "protocol-icmp-v4")]
pub const ICMP_V4: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-icmp-v4", |data| {
        use umilib::bytes::Buffer;
        use umilib::protocol::icmp::v4::{ICMPv4Message, ICMPv4Type};
        use umilib::protocol::ip::v4::IPv4Header;
        let Some(header) = data.first_chunk::<8>() else { return };
        let message = ICMPv4Message {
            kind: ICMPv4Type(header[0]),
            code: header[1],
            rest: [header[4], header[5], header[6], header[7]],
            body: &data[8..],
        };
        let mut bytes = Buffer::new();
        message.encode(&mut bytes).expect("a buffer takes the message");
        assert_eq!(ICMPv4Message::decode(bytes.as_slice()), Ok(message));
        let _ =
            (message.timestamps(), message.next_hop_mtu(), message.pointer(), message.gateway(), message.is_query());
        if let Some(reply) = message.echo_reply() {
            assert_eq!(
                (reply.identifier(), reply.sequence(), reply.body),
                (message.identifier(), message.sequence(), message.body)
            );
        }
        if let Ok((original, extensions)) = message.original() {
            assert!(original.len() <= message.body.len());
            if let Some(extensions) = extensions {
                for object in extensions.iter() {
                    object.expect("decoded objects iterate");
                }
            }
        }
        if let Some((invoking, quoted)) = message.invoking() {
            assert!(quoted.len() <= message.body.len());
            let _ = ICMPv4Message::may_report(&invoking, quoted, header[1] & 1 == 1);
        }
        if let Ok((datagram, payload)) = IPv4Header::decode(message.body) {
            let quote = ICMPv4Message::quote(message.body, datagram.header_length());
            assert!(
                quote.len() + datagram.header_length() + ICMPv4Message::HEADER_LENGTH
                    <= ICMPv4Message::MAXIMUM_ERROR_LENGTH
            );
            let _ = ICMPv4Message::may_report(&datagram, payload, false);
        }
    });

/// Messages built from any bytes write what decodes back to them; the
/// Neighbor Discovery messages and options that decode write back the same;
/// a neighbor cache fed any messages and times stays within its limits.
#[cfg(umilib_feature = "protocol-icmp-v6")]
pub const ICMP_V6: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-icmp-v6", |data| {
        use umilib::bytes::Buffer;
        use umilib::protocol::icmp::ICMPError;
        use umilib::protocol::icmp::v6::{
            ICMPv6Message, ICMPv6Type, NDPMessage, NDPNeighborAdvertisement, NDPNeighborSolicitation, NDPOptionKind,
            NDPOptions, NDPPrefixInformation, NDPRecursiveDNSServers, NDPRedirect, NDPRouteInformation,
            NDPRouterAdvertisement, NDPRouterSolicitation, NeighborCache, NeighborConfig,
        };
        use umilib::protocol::ip::v6::IPv6Header;
        use umilib::protocol::ip::{IPProtocol, IPv6Address};
        use umilib::runtime::Instant;
        let Some((&selector, data)) = data.split_first() else { return };
        let Some(header) = data.first_chunk::<8>() else { return };
        let addresses = [
            IPv6Address::UNSPECIFIED,
            "fe80::1".parse().unwrap(),
            "fe80::2".parse().unwrap(),
            "ff02::1".parse().unwrap(),
            "ff02::1:ff00:2".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ];
        let source = addresses[usize::from(selector & 7) % addresses.len()];
        let destination = addresses[usize::from(selector >> 3 & 7) % addresses.len()];
        let message = ICMPv6Message {
            kind: ICMPv6Type(header[0]),
            code: header[1],
            rest: [header[4], header[5], header[6], header[7]],
            body: &data[8..],
        };
        let encoded = |write: &dyn Fn(&mut Buffer) -> Result<(), ICMPError>| {
            let mut bytes = Buffer::new();
            write(&mut bytes).expect("a buffer takes the message");
            bytes.into_vec()
        };
        let bytes = encoded(&|out| message.encode(source, destination, out));
        assert_eq!(ICMPv6Message::decode(&bytes, source, destination), Ok(message));
        let _ = (
            message.mtu(),
            message.pointer(),
            message.is_echo(),
            message.echo_reply(),
            message.original(),
            message.invoking(),
        );
        let Ok(mut packet) = IPv6Header::new(source, destination, IPProtocol::ICMPV6, bytes.len()) else { return };
        packet.hop_limit = if selector & 0x40 == 0 { NDPMessage::HOP_LIMIT } else { 64 };
        let _ = ICMPv6Message::may_report(&packet, &bytes, selector & 0x80 != 0, &message);
        // A message that decodes as Neighbor Discovery writes back to a message of the same length
        // that decodes the same.
        let rewritten = match message.kind {
            ICMPv6Type::ROUTER_SOLICITATION => NDPRouterSolicitation::decode(&message, &packet)
                .map(|decoded| encoded(&|out| decoded.encode(source, destination, out))),
            ICMPv6Type::ROUTER_ADVERTISEMENT => NDPRouterAdvertisement::decode(&message, &packet).map(|decoded| {
                let bytes = encoded(&|out| decoded.encode(source, destination, out));
                let again = ICMPv6Message::decode(&bytes, source, destination).expect("a written message decodes");
                assert_eq!(NDPRouterAdvertisement::decode(&again, &packet), Ok(decoded));
                bytes
            }),
            ICMPv6Type::NEIGHBOR_SOLICITATION => NDPNeighborSolicitation::decode(&message, &packet)
                .map(|decoded| encoded(&|out| decoded.encode(source, destination, out))),
            ICMPv6Type::NEIGHBOR_ADVERTISEMENT => NDPNeighborAdvertisement::decode(&message, &packet)
                .map(|decoded| encoded(&|out| decoded.encode(source, destination, out))),
            ICMPv6Type::REDIRECT => NDPRedirect::decode(&message, &packet)
                .map(|decoded| encoded(&|out| decoded.encode(source, destination, out))),
            _ => Err(ICMPError::Invalid),
        };
        if let Ok(rewritten) = rewritten {
            // Reserved bits and fields are written as zero (RFC 4861 §4).
            assert_eq!(rewritten.len(), bytes.len());
            let again = ICMPv6Message::decode(&rewritten, source, destination).expect("a written message decodes");
            assert_eq!((again.kind, again.code), (message.kind, message.code));
        }
        for option in NDPOptions::new(message.body) {
            let Ok(option) = option else { break };
            match option.kind {
                NDPOptionKind::PREFIX_INFORMATION => {
                    if let Ok(information) = NDPPrefixInformation::decode(option.data) {
                        let written = encoded(&|out| information.encode(out));
                        assert_eq!(NDPPrefixInformation::decode(&written[2..]), Ok(information));
                    }
                }
                NDPOptionKind::ROUTE_INFORMATION => {
                    if let Ok(information) = NDPRouteInformation::decode(option.data) {
                        let written = encoded(&|out| information.encode(out));
                        assert_eq!(NDPRouteInformation::decode(&written[2..]), Ok(information));
                    }
                }
                NDPOptionKind::RECURSIVE_DNS_SERVERS => {
                    if let Ok(servers) = NDPRecursiveDNSServers::decode(option.data) {
                        // The reserved field is written as zero (RFC 8106 §5.1), so the bytes may differ.
                        let written = encoded(&|out| servers.encode(out));
                        assert_eq!(NDPRecursiveDNSServers::decode(&written[2..]), Ok(servers));
                    }
                }
                _ => {}
            }
        }
        let config = NeighborConfig { maximum_entries: 4, maximum_queued: 2, ..NeighborConfig::default() };
        let mut cache: NeighborCache = NeighborCache::new(config);
        for (step, chunk) in message.body.chunks(9).enumerate() {
            let now = Instant::from_nanos(step as u64 * 700_000_000);
            let target = addresses[usize::from(chunk[0] >> 4) % addresses.len()];
            let link = [chunk[0], 0, 0, 0, 0, chunk.len() as u8];
            match chunk[0] & 7 {
                0 | 1 => drop(cache.resolve(target, Some(chunk.to_vec()), now)),
                2 => cache.confirm(&target, now),
                3 => drop(cache.learn(
                    target,
                    (chunk[0] & 64 == 0).then_some(link),
                    (chunk[0] & 8 != 0).then_some(chunk[0] & 16 != 0),
                    now,
                )),
                4 => drop(cache.remove(&target)),
                _ => {
                    let options = encoded(&|out| {
                        umilib::protocol::icmp::v6::NDPOption::encode(NDPOptionKind::TARGET_LINK_ADDRESS, &link, out)
                    });
                    let advertisement = NDPNeighborAdvertisement {
                        router_flag: chunk[0] & 8 != 0,
                        solicited_flag: chunk[0] & 16 != 0,
                        override_flag: chunk[0] & 32 != 0,
                        target,
                        options: if chunk[0] & 64 != 0 { &[] } else { &options },
                    };
                    drop(cache.receive_advertisement(&advertisement, now));
                }
            }
            while cache.poll(now).is_some() {}
            assert!(cache.entries.len() <= config.maximum_entries);
            assert!(cache.poll_timeout().is_none_or(|deadline| deadline > now));
        }
    });

/// Datagrams that decode write back to datagrams that decode the same (the
/// length field of a jumbogram and bytes after the length aside); headers
/// read back what they write; endpoint texts read back from what they write,
/// and an endpoint matches the pattern of its own address and port.
#[cfg(umilib_feature = "protocol-udp")]
pub const UDP: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-udp", |data| {
        use umilib::bytes::Buffer;
        use umilib::protocol::ip::{IPAddress, IPEndpoint, IPEndpointPattern, IPv4Address, IPv6Address};
        use umilib::protocol::udp::{UDPConfig, UDPDatagram, UDPHeader};
        if let Ok(endpoint) = IPEndpoint::from_ascii(data) {
            assert_eq!(endpoint.to_string().parse::<IPEndpoint>(), Ok(endpoint));
            assert!(IPEndpointPattern::port(endpoint.port).with_address(endpoint.address).matches(&endpoint));
        }
        let Some((&selector, rest)) = data.split_first() else { return };
        if let Ok(header) = UDPHeader::decode(rest) {
            assert_eq!(UDPHeader::decode(&header.to_bytes()), Ok(header));
        }
        let (source, destination) = match selector & 3 {
            0 => (IPAddress::V4(IPv4Address::new(192, 0, 2, 1)), IPAddress::V4(IPv4Address::new(192, 0, 2, 2))),
            1 => (
                IPAddress::V6(IPv6Address::from_words([0x2001, 0xDB8, 0, 0, 0, 0, 0, 1])),
                IPAddress::V6(IPv6Address::from_words([0x2001, 0xDB8, 0, 0, 0, 0, 0, 2])),
            ),
            2 => (IPAddress::V4(IPv4Address::new(10, 0, 0, 1)), IPAddress::V6(IPv6Address::LOOPBACK)),
            _ => (IPAddress::V6(IPv6Address::LOOPBACK), IPAddress::V6(IPv6Address::LOOPBACK)),
        };
        let port = UDPHeader::decode(rest).map_or(0, |header| header.destination_port);
        let source_port = UDPHeader::decode(rest).map_or(0, |header| header.source_port);
        let config = if selector & 4 != 0 {
            UDPConfig { zero_checksum_receive_ports: vec![port], zero_checksum_send_ports: vec![source_port] }
        } else {
            UDPConfig::default()
        };
        if let Ok(datagram) = UDPDatagram::decode(rest, source, destination, &config) {
            assert!(datagram.payload.len() + UDPHeader::LENGTH <= rest.len());
            let mut bytes = Buffer::new();
            datagram.encode(source, destination, &config, &mut bytes).expect("a datagram read writes");
            assert_eq!(UDPDatagram::decode(bytes.as_slice(), source, destination, &config), Ok(datagram));
            let header = UDPHeader::decode(rest).unwrap();
            if header.length != 0 && datagram.checksummed {
                assert_eq!(bytes.as_slice(), &rest[..header.length as usize]);
            }
        }
    });

/// Segments that decode write back the same; options that decode write
/// back to options that decode the same; a connection fed any segments at
/// any times keeps its sequence numbers in order and never panics; two
/// connections over a network that the input drops, duplicates and reorders
/// deliver what was sent, in order.
#[cfg(umilib_feature = "protocol-tcp")]
pub const TCP: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-tcp", |data| {
        use umilib::bytes::Buffer;
        use umilib::protocol::ip::{IPAddress, IPEndpoint, IPv4Address};
        use umilib::protocol::tcp::{
            TCPConfig, TCPConnection, TCPFlags, TCPOptionSet, TCPSegment, TCPSequence, TCPState,
        };
        use umilib::runtime::Instant;
        let Some((&selector, rest)) = data.split_first() else { return };
        let (a_end, b_end) = (
            IPEndpoint::new(IPAddress::V4(IPv4Address::new(192, 0, 2, 1)), 40000),
            IPEndpoint::new(IPAddress::V4(IPv4Address::new(192, 0, 2, 2)), 7000),
        );
        if let Ok(segment) = TCPSegment::decode(rest, a_end.address, b_end.address) {
            let mut bytes = Buffer::new();
            segment.encode(a_end.address, b_end.address, &mut bytes).expect("a segment read writes");
            // The fields read back; the bytes may differ in the reserved bits, which are
            // written as zero, and in a checksum of 0xFFFF, which verifies as 0x0000 does.
            let again =
                TCPSegment::decode(bytes.as_slice(), a_end.address, b_end.address).expect("a segment written reads");
            assert_eq!(again, segment);
        }
        if let Ok(options) = TCPOptionSet::decode(rest) {
            let mut bytes = Buffer::new();
            if options.encode(&mut bytes).is_ok() {
                assert_eq!(TCPOptionSet::decode(bytes.as_slice()), Ok(options));
            }
        }
        let config = TCPConfig {
            sack: selector & 1 == 0,
            timestamps: selector & 2 == 0,
            window_scale: selector & 4 == 0,
            nagle: selector & 8 == 0,
            receive_buffer: 4096 << (selector >> 6),
            ..TCPConfig::default()
        };
        // A connection fed segments made from the input, against a peer that answers properly.
        let mut a = TCPConnection::connect(config, a_end, b_end, TCPSequence(1000), Instant::ZERO).unwrap();
        let mut syn = Buffer::new();
        a.transmit(Instant::ZERO, &mut syn).unwrap();
        let syn_segment = TCPSegment::decode(syn.as_slice(), a_end.address, b_end.address).unwrap();
        let mut b =
            TCPConnection::accept(config, b_end, a_end, &syn_segment, TCPSequence(9_000_000), Instant::ZERO).unwrap();
        let mut now = 0u64;
        let mut sent = 0usize;
        let mut received = Vec::new();
        let mut queue: Vec<(bool, Vec<u8>)> = Vec::new();
        for (step, chunk) in rest.chunks(8).enumerate() {
            now += u64::from(chunk[0]) * 3_000_000;
            let at = Instant::from_nanos(now);
            if b.state.can_send() && step % 3 == 0 {
                let payload: Vec<u8> = (0..chunk.len() * 97).map(|index| (sent + index) as u8).collect();
                sent += b.send(&payload).unwrap_or(0);
            }
            // A forged segment to A, from the input, now and then.
            if chunk.len() == 8 && chunk[1] & 7 == 0 {
                let forged = TCPSegment {
                    source_port: b_end.port,
                    destination_port: a_end.port,
                    sequence: a.receive_next().add(u32::from(chunk[2]) * 1000).sub(u32::from(chunk[3]) * 1000),
                    acknowledgment: a.send_unacknowledged.add(u32::from(chunk[4])),
                    flags: TCPFlags(chunk[5]),
                    window: u16::from_be_bytes([chunk[6], chunk[7]]),
                    ..TCPSegment::default()
                };
                a.receive(&forged, false, at);
            }
            for (from_b, connection) in [(true, &mut b), (false, &mut a)] {
                loop {
                    let mut bytes = Buffer::new();
                    match connection.transmit(at, &mut bytes) {
                        Ok(Some(_)) => queue.push((from_b, bytes.into_vec())),
                        Ok(None) => break,
                        Err(error) => panic!("{error}"),
                    }
                    if queue.len() > 10_000 {
                        break;
                    }
                }
            }
            let mut index = 0;
            while index < queue.len() {
                let action = chunk.get(1 + index % 7).copied().unwrap_or(0) % 16;
                let (from_b, bytes) = queue[index].clone();
                let (source, destination) = if from_b { (b_end, a_end) } else { (a_end, b_end) };
                let segment =
                    TCPSegment::decode(&bytes, source.address, destination.address).expect("a segment written reads");
                let receiver = if from_b { &mut a } else { &mut b };
                match action {
                    0 => {}
                    1 => {
                        index += 1;
                        continue;
                    }
                    2 => {
                        receiver.receive(&segment, false, at);
                        receiver.receive(&segment, false, at);
                    }
                    _ => receiver.receive(&segment, action == 3, at),
                }
                queue.remove(index);
            }
            let mut out = [0u8; 4096];
            loop {
                let count = a.read(&mut out);
                if count == 0 {
                    break;
                }
                received.extend_from_slice(&out[..count]);
            }
            for connection in [&a, &b] {
                assert!(
                    connection
                        .send_unacknowledged
                        .is_at_or_before(connection.send_next.max(connection.send_unacknowledged))
                );
                assert!(connection.send_next.is_at_or_before(connection.send_maximum.max(connection.send_next)));
                assert!(connection.receive.space() <= connection.config.receive_buffer);
            }
        }
        // What arrived is a prefix of what was sent, in order, unless forged data got in.
        let forged = rest.chunks(8).any(|chunk| chunk.len() == 8 && chunk[1] & 7 == 0);
        if !forged && a.state != TCPState::Closed {
            let expected: Vec<u8> = (0..received.len()).map(|index| index as u8).collect();
            assert_eq!(received, expected);
        }
    });

/// The certificates and configurations of the TLS targets: those of the
/// tests (`tests/vectors/protocol/tls/certificates`), built once.
#[cfg(umilib_feature = "protocol-tls")]
pub struct TLSFixture {
    pub client: std::sync::Arc<umilib::protocol::tls::TLSClientConfig>,
    pub server: std::sync::Arc<umilib::protocol::tls::TLSServerConfig>,
}

#[cfg(umilib_feature = "protocol-tls")]
impl TLSFixture {
    /// 2027-01-01, inside the validity of the certificates.
    pub const TIME: i64 = 1_798_761_600;

    pub fn get() -> &'static TLSFixture {
        static FIXTURE: std::sync::OnceLock<TLSFixture> = std::sync::OnceLock::new();
        FIXTURE.get_or_init(|| {
            use std::sync::Arc;
            use umilib::auth::cert::key::{KeyLimits, PrivateKey};
            use umilib::auth::cert::path::TrustAnchor;
            use umilib::auth::cert::x509::Certificate;
            use umilib::protocol::tls::{
                TLSCertifiedKey, TLSClientConfig, TLSPathVerifier, TLSServerConfig, TLSSessionCache, TLSTicketKey,
                TLSTicketKeys,
            };
            let root = include_bytes!("../tests/vectors/protocol/tls/certificates/root.der");
            let certificate = include_bytes!("../tests/vectors/protocol/tls/certificates/server-p256.der");
            let key = PrivateKey::from_pem(include_str!("../tests/vectors/protocol/tls/certificates/server-p256.key"))
                .expect("the fixture's key");
            let anchor = Certificate::from_der(root).expect("the fixture's root").into_owned();
            let anchor = TrustAnchor::from_certificate(anchor, &KeyLimits::default()).expect("an anchor");
            let mut client = TLSClientConfig::new(Arc::new(TLSPathVerifier::servers(vec![anchor])));
            client.sessions = Some(Arc::new(TLSSessionCache::new(4)));
            let mut server = TLSServerConfig::new(vec![Arc::new(TLSCertifiedKey {
                chain: vec![certificate.to_vec()],
                key,
                ocsp: None,
            })]);
            server.tickets =
                Some(Arc::new(TLSTicketKeys::new(vec![TLSTicketKey::new([1; 16], &[2; 32]).expect("a ticket key")])));
            TLSFixture { client: Arc::new(client), server: Arc::new(server) }
        })
    }

    pub fn random(seed: u8) -> Box<umilib::crypto::random::HMACDRBG<umilib::hash::sha::v2::SHA256>> {
        Box::new(umilib::crypto::random::HMACDRBG::new(&[seed; 32], &[seed; 16], b"fuzz").expect("a DRBG"))
    }
}

/// The codecs of TLS: what decodes writes back to what decodes the same —
/// hellos, the extensions' contents, the messages of each version, records,
/// session states and the structures of ECH — and the reassembly of
/// handshake messages from any fragments neither panics nor exceeds its limit.
#[cfg(umilib_feature = "protocol-tls")]
pub const TLS_CODEC: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> = umilib::platform::fuzz::FuzzFunction::new(
    "protocol-tls-codec",
    |data| {
        use umilib::bytes::Buffer;
        use umilib::protocol::tls::{
            TLSCertificateStatus, TLSClientHello, TLSECH, TLSECHClientHello, TLSECHConfig, TLSExtensionContext,
            TLSHandshakeReassembler, TLSKeyShare, TLSPreSharedKey, TLSProtocolNames, TLSRecord, TLSServerHello,
            TLSServerNames, TLSSessionState, TLSSignatureSchemes, TLSSupportedGroups,
        };
        let Some((&selector, rest)) = data.split_first() else { return };
        // `decode` then `encode` then `decode` gives the first value again.
        macro_rules! round_trip {
            ($decode:expr, $value:ident => $encode:expr) => {
                if let Ok($value) = $decode(rest) {
                    let mut bytes = Buffer::new();
                    $encode(&$value, &mut bytes).expect("a value read writes");
                    assert_eq!($decode(bytes.as_slice()).expect("a value written reads"), $value);
                }
            };
        }
        let contexts = [
            TLSExtensionContext::ClientHello,
            TLSExtensionContext::ServerHello,
            TLSExtensionContext::HelloRetryRequest,
        ];
        let context = contexts[usize::from(selector >> 4) % contexts.len()];
        match selector % 13 {
            0 => {
                round_trip!(TLSClientHello::decode, hello => |hello: &TLSClientHello, out: &mut Buffer| hello.encode(out))
            }
            1 => {
                round_trip!(TLSServerHello::decode, hello => |hello: &TLSServerHello, out: &mut Buffer| hello.encode(out))
            }
            2 => {
                round_trip!(TLSServerNames::decode, names => |names: &TLSServerNames, out: &mut Buffer| names.encode(out))
            }
            3 => {
                round_trip!(TLSSupportedGroups::decode, groups => |groups: &TLSSupportedGroups, out: &mut Buffer| groups.encode(out))
            }
            4 => {
                round_trip!(TLSSignatureSchemes::decode, schemes => |schemes: &TLSSignatureSchemes, out: &mut Buffer| schemes.encode(out))
            }
            5 => {
                round_trip!(TLSProtocolNames::decode, names => |names: &TLSProtocolNames, out: &mut Buffer| names.encode(out))
            }
            6 => {
                round_trip!(|data| TLSKeyShare::decode(data, context), share => |share: &TLSKeyShare, out: &mut Buffer| share.encode(out))
            }
            7 => {
                round_trip!(|data| TLSPreSharedKey::decode(data, context), offered => |offered: &TLSPreSharedKey, out: &mut Buffer| offered.encode(out))
            }
            8 => {
                round_trip!(|data| TLSCertificateStatus::decode(data, selector & 0x10 != 0), status => |status: &TLSCertificateStatus, out: &mut Buffer| status.encode(out))
            }
            9 => {
                round_trip!(TLSECHClientHello::decode, hello => |hello: &TLSECHClientHello, out: &mut Buffer| hello.encode(out));
                if let Ok(configs) = TLSECHConfig::decode_list(rest)
                    && !configs.is_empty()
                {
                    let mut bytes = Buffer::new();
                    TLSECHConfig::encode_list(&configs, &mut bytes).expect("configurations read write");
                    assert_eq!(TLSECHConfig::decode_list(bytes.as_slice()).expect("they read again"), configs);
                    let _ = configs.iter().map(TLSECHConfig::usable_suite).count();
                }
            }
            10 => {
                // A ClientHelloInner of any encoding against a fixed outer one: its rules hold or it fails.
                let outer = TLSClientHello {
                    legacy_version: umilib::protocol::tls::TLSVersion::TLS1_2,
                    random: [7; 32],
                    legacy_session_id: vec![1; 32],
                    cipher_suites: vec![umilib::protocol::tls::TLSCipherSuite::TLS_AES_128_GCM_SHA256],
                    legacy_compression_methods: vec![0],
                    extensions: vec![
                        umilib::protocol::tls::TLSExtension::new(
                            umilib::protocol::tls::TLSExtensionType::SUPPORTED_GROUPS,
                            vec![0, 2, 0, 0x1D],
                        ),
                        umilib::protocol::tls::TLSExtension::new(
                            umilib::protocol::tls::TLSExtensionType::KEY_SHARE,
                            vec![0, 4, 0, 0x1D, 0, 0],
                        ),
                    ],
                };
                if let Ok(inner) = TLSECH::decode_inner(rest, &outer) {
                    assert_eq!(inner.legacy_session_id, outer.legacy_session_id);
                    let _ = TLSECH::check_inner(&inner);
                    // Its padding reads the server name, which may be malformed here.
                    if let Ok(encoded) = TLSECH::encode_inner(&inner, selector) {
                        assert_eq!(encoded.len() % 32, 0);
                        assert_eq!(
                            TLSECH::decode_inner(&encoded, &outer).expect("an encoded inner hello reads"),
                            inner
                        );
                    }
                }
            }
            11 => {
                if let Ok(state) = TLSSessionState::decode(rest) {
                    let mut bytes = Buffer::new();
                    state.encode(&mut bytes).expect("a state read writes");
                    let again = TLSSessionState::decode(bytes.as_slice()).expect("a state written reads");
                    assert_eq!(again.psk.expose(), state.psk.expose());
                    assert_eq!(
                        (again.time, again.lifetime, again.age_add),
                        (state.time, state.lifetime, state.age_add)
                    );
                    let _ = (state.is_current(selector.into()), state.is_fresh(u32::from(selector), 0, 10));
                }
            }
            _ => {
                // Records, and handshake messages joined from fragments of any size.
                let mut offset = 0;
                while let Ok(Some((record, length))) = TLSRecord::decode(&rest[offset..], 1 << 14) {
                    let mut bytes = Buffer::new();
                    record.encode(&mut bytes).expect("a record read writes");
                    assert_eq!(bytes.as_slice(), &rest[offset..offset + length]);
                    offset += length;
                }
                let mut reassembler = TLSHandshakeReassembler::new(1 << 12);
                for fragment in rest.chunks(usize::from(selector >> 4) + 1) {
                    if reassembler.push(fragment).is_err() {
                        break;
                    }
                    while let Ok(Some(message)) = reassembler.pop() {
                        assert!(message.body.len() <= 1 << 12);
                    }
                }
            }
        }
    },
);

/// Clients and servers of both versions given the bytes of the input, or
/// the bytes of a real handshake the input changes, return without
/// panicking; unchanged, the handshake completes and carries data.
#[cfg(umilib_feature = "protocol-tls")]
pub const TLS_HANDSHAKE: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-tls-handshake", |data| {
        use std::sync::Arc;
        use umilib::protocol::tls::{TLSConnection, TLSVersion};
        let Some((&selector, rest)) = data.split_first() else { return };
        let fixture = TLSFixture::get();
        let (mut client_config, mut server_config) = ((*fixture.client).clone(), (*fixture.server).clone());
        let version = if selector & 1 == 0 { TLSVersion::TLS1_3 } else { TLSVersion::TLS1_2 };
        client_config.config.versions = vec![version];
        server_config.config.versions = vec![version];
        let (client_config, server_config) = (Arc::new(client_config), Arc::new(server_config));
        let connect = |seed: u8| {
            let client = TLSConnection::client(
                client_config.clone(),
                Some("server.example"),
                TLSFixture::random(seed),
                TLSFixture::TIME,
            );
            let server = TLSConnection::server(server_config.clone(), TLSFixture::random(seed + 1), TLSFixture::TIME);
            (client.expect("a client"), server.expect("a server"))
        };
        // Any bytes to a fresh server and to a client that sent its ClientHello.
        let (mut client, mut server) = connect(1);
        let _ = server.receive(rest);
        let _ = client.receive(rest);
        // A handshake whose flights the input changes: at a flight, a byte flipped, or the flight replaced.
        let (mut client, mut server) = connect(3);
        let changes: Vec<(usize, usize, u8)> = rest
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&[at, high, low, value]| (usize::from(at % 8), usize::from(u16::from_be_bytes([high, low])), value))
            .collect();
        let mut flight = 0;
        let mut failed = false;
        for _ in 0..16 {
            let mut moved = false;
            for to_server in [true, false] {
                let (from, to) = if to_server { (&mut client, &mut server) } else { (&mut server, &mut client) };
                let mut bytes = Vec::new();
                from.transmit(&mut bytes).expect("bytes go out");
                if bytes.is_empty() {
                    continue;
                }
                moved = true;
                for &(at, offset, value) in &changes {
                    if at == flight && !bytes.is_empty() {
                        let index = offset % bytes.len();
                        bytes[index] ^= value | 1;
                    }
                }
                flight += 1;
                failed |= to.receive(&bytes).is_err();
            }
            if !moved {
                break;
            }
        }
        if changes.iter().all(|&(at, _, _)| at >= flight) {
            assert!(
                !failed && !client.is_handshaking() && !server.is_handshaking(),
                "an unchanged handshake completes"
            );
            client.send(rest).expect("data goes out");
            let mut bytes = Vec::new();
            client.transmit(&mut bytes).expect("bytes go out");
            server.receive(&bytes).expect("data comes in");
            let mut read = vec![0; rest.len()];
            assert_eq!(server.read(&mut read), rest.len());
            assert_eq!(read, rest);
        }
    });

/// The codecs of QUIC: packets and invariant headers read without
/// panicking; frames, transport parameters and varints that read write back
/// to what reads the same; ACK ranges stay in order and above zero.
#[cfg(umilib_feature = "protocol-quic")]
pub const QUIC_CODEC: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-quic-codec", |data| {
        use umilib::bytes::Reader;
        use umilib::protocol::quic::{
            QUICFrame, QUICInvariantHeader, QUICPacket, QUICPacketNumber, QUICRole, QUICTransportParameters, QUICVarint,
        };
        let Some((&selector, rest)) = data.split_first() else { return };
        match selector % 5 {
            0 => {
                // Coalesced packets: each takes at least a byte and stays within the datagram.
                let mut offset = 0;
                while offset < rest.len() {
                    let Ok(packet) = QUICPacket::decode(&rest[offset..], usize::from(selector >> 3) % 21) else {
                        break;
                    };
                    let length = packet.length(&rest[offset..]);
                    assert!(length > 0 && offset + length <= rest.len());
                    offset += length;
                }
                let _ = QUICInvariantHeader::decode(rest, 8);
            }
            1 => {
                let mut reader = Reader::new(rest);
                while !reader.is_empty() {
                    let Ok(frame) = QUICFrame::decode(&mut reader) else { break };
                    let mut bytes = Vec::new();
                    frame.encode(&mut bytes).expect("a frame read writes");
                    assert_eq!(bytes.len(), frame.encoded_length());
                    assert_eq!(QUICFrame::decode(&mut Reader::new(&bytes)).expect("a frame written reads"), frame);
                    if let QUICFrame::ACK(ack) = frame {
                        let ranges: Vec<_> = ack.ranges().collect();
                        assert!(ranges.windows(2).all(|pair| pair[1].end() + 1 < *pair[0].start()));
                    }
                }
            }
            2 => {
                let role = if selector & 0x10 == 0 { QUICRole::Client } else { QUICRole::Server };
                if let Ok(parameters) = QUICTransportParameters::decode(rest, role) {
                    let mut bytes = Vec::new();
                    parameters.encode(&[], &mut bytes).expect("parameters read write");
                    assert_eq!(
                        QUICTransportParameters::decode(&bytes, role).expect("parameters written read"),
                        parameters
                    );
                }
            }
            3 => {
                let mut reader = Reader::new(rest);
                while let Ok((value, length)) = QUICVarint::read_with_length(&mut reader) {
                    let mut bytes = Vec::new();
                    QUICVarint::write_with_length(&mut bytes, value, length).expect("a varint read writes");
                    assert_eq!(QUICVarint::read(&mut Reader::new(&bytes)), Ok(value));
                }
            }
            _ => {
                // Packet numbers: what is encoded as A.2 asks is recovered (RFC 9000 Appendix A).
                if let [a, b, c, d, e, f, g, h, rest @ ..] = rest {
                    let number = u64::from_be_bytes([0, 0, *a & 0x3F, *b, *c, *d, *e, *f]);
                    let acknowledged = u64::from_be_bytes([0, 0, 0, 0, *g, *h, 0, 0]) >> 8;
                    let largest = number.checked_sub(acknowledged);
                    if let Some(length) = QUICPacketNumber::length(number, largest) {
                        let truncated = number & ((1u64 << (8 * length)) - 1);
                        assert_eq!(QUICPacketNumber::decode(truncated, length, largest), number);
                    }
                    let _ = rest;
                }
            }
        }
    });

/// QUIC connections given any datagram, or the datagrams of a real
/// handshake the input changes, return without panicking; unchanged, the
/// handshake completes and a stream carries data.
#[cfg(umilib_feature = "protocol-quic")]
pub const QUIC_CONNECTION: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-quic-connection", |data| {
        use std::sync::Arc;
        use umilib::protocol::ip::{IPAddress, IPEndpoint, IPv4Address};
        use umilib::protocol::quic::{QUICConfig, QUICECN, QUICEndpoint, QUICEndpointConfig};
        use umilib::runtime::Instant;
        let Some((&selector, rest)) = data.split_first() else { return };
        let fixture = TLSFixture::get();
        let (mut client_tls, mut server_tls) = ((*fixture.client).clone(), (*fixture.server).clone());
        client_tls.config.protocols = vec![b"fuzz".to_vec()];
        server_tls.config.protocols = vec![b"fuzz".to_vec()];
        let client_tls = Arc::new(client_tls);
        let quic = Arc::new(QUICConfig { reset_key: Some([3; 32]), ..QUICConfig::default() });
        let mut server_config = QUICEndpointConfig::new(quic.clone(), Some(Arc::new(server_tls)));
        server_config.token_key = Some([4; 32]);
        server_config.retry = selector & 1 == 1;
        let client_address = IPEndpoint::new(IPAddress::V4(IPv4Address::new(192, 0, 2, 2)), 50000);
        let server_address = IPEndpoint::new(IPAddress::V4(IPv4Address::new(192, 0, 2, 1)), 443);
        let now = Instant::from_nanos(1_000_000_000);
        let time = TLSFixture::TIME;
        let mut server = QUICEndpoint::new(server_config, TLSFixture::random(1)).expect("a server");
        let mut client =
            QUICEndpoint::new(QUICEndpointConfig::new(quic, None), TLSFixture::random(2)).expect("a client");
        let handle = client
            .connect(client_tls, Some("server.example"), server_address, None, TLSFixture::random(3), now, time)
            .expect("a connection");
        // Any datagram to both, before anything else.
        let _ = server.receive(rest, client_address, QUICECN::NotECT, now, time);
        let _ = client.receive(rest, server_address, QUICECN::NotECT, now, time);
        // The handshake, its datagrams changed as the input says: (datagram, offset, value).
        let changes: Vec<(usize, usize, u8)> = rest
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&[at, high, low, value]| (usize::from(at % 16), usize::from(u16::from_be_bytes([high, low])), value))
            .collect();
        let mut count = 0;
        let mut out = Vec::new();
        for _ in 0..64 {
            let mut moved = false;
            for to_server in [true, false] {
                let (from, to, source) = if to_server {
                    (&mut client, &mut server, client_address)
                } else {
                    (&mut server, &mut client, server_address)
                };
                while from.transmit(now, &mut out).is_some() {
                    moved = true;
                    for &(at, offset, value) in &changes {
                        if at == count && !out.is_empty() {
                            let index = offset % out.len();
                            out[index] ^= value | 1;
                        }
                    }
                    count += 1;
                    let _ = to.receive(&out, source, QUICECN::NotECT, now, time);
                }
            }
            if !moved {
                break;
            }
        }
        if changes.iter().all(|&(at, _, _)| at >= count) {
            let connection = client.connection(handle).expect("the connection");
            assert!(connection.handshake_confirmed, "an unchanged handshake completes");
            let stream = connection.open_stream(true).expect("a stream");
            connection.stream_send(stream, rest, true).expect("data goes out");
            for _ in 0..64 {
                let mut moved = false;
                while client.transmit(now, &mut out).is_some() {
                    moved = true;
                    server.receive(&out, client_address, QUICECN::NotECT, now, time);
                }
                while server.transmit(now, &mut out).is_some() {
                    moved = true;
                    client.receive(&out, server_address, QUICECN::NotECT, now, time);
                }
                if !moved {
                    break;
                }
            }
            let accepted = server.accept().expect("the server's connection");
            let connection = server.connection(accepted).expect("the server's connection");
            let mut read = vec![0; rest.len() + 1];
            let (count, fin) = connection.stream_read(stream, &mut read).expect("the stream");
            assert_eq!((&read[..count], fin), (rest, true));
        }
    });

/// Messages that decode encode to messages that decode the same; records
/// written in their presentation format read back the same; the text of a
/// zone file that reads gives records whose text reads back the same.
#[cfg(umilib_feature = "protocol-dns")]
pub const DNS: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-dns", |data| {
        use umilib::protocol::dns::{DNSMessage, DNSName, DNSZoneFile};
        let reread = |text: &str| DNSZoneFile { origin: None, default_ttl: Some(0) }.parse(text);
        if let Ok(message) = DNSMessage::decode(data) {
            let bytes = message.encode(DNSMessage::MAXIMUM_SIZE).expect("a decoded message encodes");
            assert_eq!(DNSMessage::decode(&bytes).as_ref(), Ok(&message));
            for record in message.answers.iter().chain(&message.authorities).chain(&message.additionals) {
                let text = record.to_string();
                assert_eq!(reread(&text).map(|records| records.into_iter().next()), Ok(Some(record.clone())), "{text}");
            }
            if let Ok(limited) = message.encode(512) {
                assert!(limited.len() <= 512);
                assert!(DNSMessage::decode(&limited).is_ok());
            }
        }
        if let Ok(text) = core::str::from_utf8(data) {
            if let Ok(name) = DNSName::parse(text, None) {
                assert_eq!(DNSName::parse(&name.to_string(), None).as_ref(), Ok(&name));
                assert_eq!(DNSName::from_wire(name.wire()).as_ref(), Ok(&name));
            }
            if let Ok(records) = reread(text) {
                for record in records {
                    let written = record.to_string();
                    assert_eq!(reread(&written).map(|again| again.into_iter().next()), Ok(Some(record)), "{written}");
                }
            }
        }
    });

/// An authoritative server answers any bytes without panicking, each
/// response a message of the query's limit; a resolver takes any bytes as
/// a response to its query without panicking.
#[cfg(umilib_feature = "protocol-dns")]
pub const DNS_SERVER: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> = umilib::platform::fuzz::FuzzFunction::new(
    "protocol-dns-server",
    |data| {
        use std::sync::OnceLock;

        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::protocol::dns::{
            DNSAuthority, DNSAuthorityConfig, DNSMessage, DNSName, DNSPeer, DNSQuestion, DNSResolver,
            DNSResolverConfig, DNSTransport, DNSType, DNSUpstream, DNSZone, DNSZoneFile,
        };
        use umilib::protocol::ip::{IPEndpoint, IPEndpointPattern};
        use umilib::runtime::Instant;
        static AUTHORITY: OnceLock<DNSAuthority> = OnceLock::new();
        let authority = AUTHORITY.get_or_init(|| {
            let text = "@ 3600 IN SOA ns admin 1 3600 600 86400 300\n@ NS ns\nns A 192.0.2.53\nwww CNAME web\nweb A 192.0.2.80\n\
                        *.wild TXT \"w\"\nold DNAME new.example.\nsub NS ns.sub\nns.sub A 192.0.2.9\n";
            let origin = DNSName::parse("example.", None).unwrap();
            let records = DNSZoneFile::new(Some(origin.clone())).parse(text).unwrap();
            let config = DNSAuthorityConfig { minimal: false, transfers: vec![IPEndpointPattern::ANY], cookie_secrets: vec![[1; 16]], ..DNSAuthorityConfig::default() };
            DNSAuthority::new(vec![DNSZone::new(origin, records).unwrap()], config)
        });
        let Some((&selector, rest)) = data.split_first() else { return };
        let transport = if selector & 1 == 0 { DNSTransport::UDP } else { DNSTransport::TLS };
        let peer = DNSPeer { endpoint: IPEndpoint::from_ascii(b"198.51.100.1:40000").unwrap(), transport };
        for response in authority.respond(rest, &peer, 1_700_000_000) {
            let decoded = DNSMessage::decode(&response).expect("a response is a message");
            assert!(decoded.header.response);
            if transport == DNSTransport::UDP {
                let limit = DNSMessage::decode(rest).map_or(512, |query| query.udp_response_limit(1232));
                assert!(response.len() <= limit, "{} > {limit}", response.len());
            }
        }
        let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"fuzz").unwrap();
        let upstream = DNSUpstream {
            endpoint: IPEndpoint::from_ascii(b"192.0.2.53:53").unwrap(),
            transport: DNSTransport::UDP,
            name: None,
        };
        let mut resolver = DNSResolver::new(
            DNSResolverConfig { upstreams: vec![upstream], ..DNSResolverConfig::default() },
            &mut random,
        )
        .unwrap();
        let question = DNSQuestion::new(DNSName::parse("www.example.", None).unwrap(), DNSType::A);
        let query = resolver.resolve(question, Instant::ZERO, &mut random).unwrap();
        resolver.receive(query, 0, DNSTransport::UDP, rest, Instant::ZERO, &mut random);
        while resolver.poll_event().is_some() {}
    },
);

/// DHCPv4 messages that decode encode to messages that decode the same; a
/// server and a client take any bytes without panicking.
#[cfg(umilib_feature = "protocol-dhcp-v4")]
pub const DHCP_V4: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-dhcp-v4", |data| {
        use core::time::Duration;

        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::protocol::dhcp::v4::{
            DHCPv4Client, DHCPv4ClientConfig, DHCPv4Message, DHCPv4Options, DHCPv4Server, DHCPv4ServerConfig,
        };
        use umilib::protocol::ethernet::MACAddress;
        use umilib::protocol::ip::IPv4Address;
        use umilib::runtime::Instant;
        if let Ok(message) = DHCPv4Message::decode(data) {
            assert_eq!(DHCPv4Message::decode(&message.encode()).as_ref(), Ok(&message));
            let _ = message.options.routes();
        }
        let mut server = DHCPv4Server::new(DHCPv4ServerConfig {
            address: IPv4Address::new(192, 0, 2, 1),
            first: IPv4Address::new(192, 0, 2, 100),
            last: IPv4Address::new(192, 0, 2, 110),
            reservations: Vec::new(),
            lease: Some(Duration::from_secs(3600)),
            offer_time: Duration::from_secs(60),
            decline_time: Duration::from_secs(600),
            options: DHCPv4Options::new(),
            authoritative: true,
        })
        .unwrap();
        if let Some(reply) = server.receive(data, Instant::ZERO) {
            assert!(DHCPv4Message::decode(&reply.message.encode()).is_ok());
        }
        let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"fuzz").unwrap();
        let mut client = DHCPv4Client::new(DHCPv4ClientConfig::new(MACAddress([2, 0, 0, 0, 0, 1])), Instant::ZERO);
        client.start(None, Instant::ZERO, &mut random).unwrap();
        client.receive(data, Instant::ZERO, &mut random);
    });

/// DHCPv6 messages and relay messages that decode encode to the same
/// bytes; a server and a client take any bytes without panicking.
#[cfg(umilib_feature = "protocol-dhcp-v6")]
pub const DHCP_V6: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-dhcp-v6", |data| {
        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::protocol::dhcp::DHCPDUID;
        use umilib::protocol::dhcp::v6::{
            DHCPv6Client, DHCPv6ClientConfig, DHCPv6Message, DHCPv6Options, DHCPv6RelayMessage, DHCPv6Server,
            DHCPv6ServerConfig,
        };
        use umilib::protocol::ip::IPv6Address;
        use umilib::runtime::Instant;
        if let Ok(message) = DHCPv6Message::decode(data) {
            assert_eq!(message.encode().as_deref(), Ok(data));
        }
        if let Ok(relay) = DHCPv6RelayMessage::decode(data) {
            assert_eq!(relay.encode().as_deref(), Ok(data));
        }
        if let Ok(duid) = DHCPDUID::decode(data) {
            assert_eq!(duid.encode().as_deref(), Ok(data));
        }
        let duid = DHCPDUID::LL { hardware: 1, address: vec![2, 0, 0, 0, 0, 1] };
        let mut base = [0u8; 16];
        base[..2].copy_from_slice(&[0x20, 0x01]);
        let mut server = DHCPv6Server::new(DHCPv6ServerConfig {
            duid: duid.clone(),
            addresses: Some((IPv6Address(base), IPv6Address(base))),
            prefixes: Some((IPv6Address(base), 48, 56)),
            preferred: 300,
            valid: 600,
            t1: 0,
            t2: 0,
            preference: 0,
            rapid_commit: true,
            options: DHCPv6Options::new(),
        })
        .unwrap();
        if let Some(reply) = server.receive(data, Instant::ZERO) {
            assert!(DHCPv6Message::decode(&reply).is_ok() || DHCPv6RelayMessage::decode(&reply).is_ok());
        }
        let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"fuzz").unwrap();
        let mut client = DHCPv6Client::new(DHCPv6ClientConfig::new(duid, 1), Instant::ZERO);
        client.start(Instant::ZERO, &mut random).unwrap();
        client.receive(data, Instant::ZERO, &mut random);
    });

/// CoAP messages that decode encode to messages that decode the same;
/// links read back from what they write; an endpoint takes any datagram
/// without panicking, and what it sends back decodes.
#[cfg(umilib_feature = "protocol-coap")]
pub const COAP: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-coap", |data| {
        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::protocol::coap::{CoAPBlock, CoAPConfig, CoAPEndpoint, CoAPLink, CoAPMessage};
        use umilib::protocol::ip::IPEndpoint;
        use umilib::runtime::Instant;
        if let Ok(message) = CoAPMessage::decode(data) {
            let bytes = message.encode().expect("a decoded message encodes");
            assert_eq!(CoAPMessage::decode(&bytes).as_ref(), Ok(&message));
            let _ = message.options.check();
            let _ = message.options.usable();
        }
        if let Ok(block) = CoAPBlock::decode(data) {
            assert_eq!(CoAPBlock::decode(&block.encode()), Ok(block));
        }
        if let Ok(text) = core::str::from_utf8(data)
            && let Ok(links) = CoAPLink::parse(text)
        {
            assert_eq!(CoAPLink::parse(&CoAPLink::format(&links)).as_ref(), Ok(&links));
        }
        let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"fuzz").unwrap();
        let mut endpoint = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
        let peer = IPEndpoint::from_ascii(b"192.0.2.2:5683").unwrap();
        endpoint.receive(peer, data, Instant::ZERO, &mut random);
        while let Some(transmission) = endpoint.transmit() {
            assert!(CoAPMessage::decode(&transmission.message).is_ok());
        }
        endpoint.expire(Instant::from_nanos(1 << 40));
    });

/// SMTP: commands and replies that read write back to what reads the
/// same; mail data that is taken reads back as written; a server and a
/// client take any input without panicking, and what they send reads.
#[cfg(umilib_feature = "protocol-smtp")]
pub const SMTP: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-smtp", |data| {
        use umilib::protocol::smtp::{
            SMTPClient, SMTPCommand, SMTPConfig, SMTPData, SMTPDataReader, SMTPReply, SMTPReplyReader, SMTPServer,
            SMTPServerConfig, SMTPServerEvent,
        };
        use umilib::runtime::Instant;
        let replies = |bytes: &[u8]| {
            let mut reader = SMTPReplyReader::new();
            for line in bytes.split(|byte| *byte == b'\n').filter_map(|line| line.strip_suffix(b"\r")) {
                assert!(reader.push(line, usize::MAX).is_ok(), "{:?}", String::from_utf8_lossy(bytes));
            }
        };
        for line in data.split(|byte| *byte == b'\n') {
            for utf8 in [false, true] {
                if let Ok(command) = SMTPCommand::parse(line, utf8) {
                    let text = format!("{command}");
                    assert_eq!(SMTPCommand::parse(text.as_bytes(), utf8).as_ref(), Ok(&command), "{text}");
                }
            }
        }
        let mut reader = SMTPReplyReader::new();
        for line in data.split(|byte| *byte == b'\n') {
            if let Ok(Some(reply)) = reader.push(line.strip_suffix(b"\r").unwrap_or(line), 64) {
                let mut wire = Vec::new();
                reply.encode(&mut wire);
                let mut again = SMTPReplyReader::new();
                let lines: Vec<&[u8]> =
                    wire.split(|byte| *byte == b'\n').filter_map(|line| line.strip_suffix(b"\r")).collect();
                let read = lines.iter().map(|line| again.push(line, 64)).last();
                assert_eq!(read, Some(Ok(Some(reply))));
            }
        }
        if SMTPData::check(data, 1000).is_ok() {
            let mut encoded = Vec::new();
            SMTPData::encode(data, 1000, &mut encoded).unwrap();
            let mut decoded = Vec::new();
            let mut reader = SMTPDataReader::new(u64::MAX, 1000);
            assert_eq!(reader.read(&encoded, &mut decoded), encoded.len());
            assert!(reader.is_end() && reader.error().is_none());
            let mut expected = data.to_vec();
            if !expected.is_empty() && !expected.ends_with(b"\r\n") {
                expected.extend_from_slice(b"\r\n");
            }
            assert_eq!(decoded, expected);
        }
        let settings = SMTPServerConfig { auth_mechanisms: vec![String::from("PLAIN")], ..SMTPServerConfig::default() };
        let mut server = SMTPServer::new(SMTPConfig::default(), settings, false).unwrap();
        server.greet(server.greeting(), Instant::ZERO).unwrap();
        server.receive(data, Instant::ZERO);
        for _ in 0..64 {
            let Some(event) = server.poll_event() else { break };
            let reply = match event {
                SMTPServerEvent::Command(SMTPCommand::Data) => SMTPReply::new(354, "go ahead"),
                SMTPServerEvent::Command(_) | SMTPServerEvent::DataEnd { .. } => SMTPReply::new(250, "OK"),
                SMTPServerEvent::AuthResponse(_) => SMTPReply::new(235, "2.7.0 OK"),
                _ => continue,
            };
            let _ = server.reply(reply, Instant::ZERO);
        }
        let mut out = Vec::new();
        server.transmit(&mut out);
        replies(&out);
        let mut client = SMTPClient::new(SMTPConfig::default(), false, Instant::ZERO).unwrap();
        let _ = client.receive(data, Instant::ZERO);
        let _ = client.send(SMTPCommand::Ehlo(String::from("client.test")), Instant::ZERO);
        while client.poll_event().is_some() {}
        client.expire(Instant::from_nanos(1 << 50));
    });

/// POP3: commands and status lines that read write back to what reads the
/// same; multi-line data reads back as written; a server and a client take
/// any input without panicking.
#[cfg(umilib_feature = "protocol-pop-v3")]
pub const POP_V3: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-pop-v3", |data| {
        use umilib::protocol::pop::v3::{
            POP3Capabilities, POP3Client, POP3Command, POP3Config, POP3MultiLineReader, POP3MultiLineWriter,
            POP3Response, POP3Server, POP3ServerConfig, POP3ServerEvent,
        };
        use umilib::runtime::Instant;
        for line in data.split(|byte| *byte == b'\n') {
            for utf8 in [false, true] {
                if let Ok(command) = POP3Command::parse(line, utf8) {
                    let text = format!("{command}");
                    assert_eq!(POP3Command::parse(text.as_bytes(), utf8).as_ref(), Ok(&command), "{text}");
                }
            }
            if let Ok(response) = POP3Response::parse(line) {
                let mut wire = Vec::new();
                response.encode(&mut wire);
                assert_eq!(POP3Response::parse(&wire[..wire.len() - 2]).as_ref(), Ok(&response));
            }
        }
        let capabilities = POP3Capabilities::parse(data);
        let mut list = Vec::new();
        capabilities.encode(&mut list);
        assert_eq!(POP3Capabilities::parse(&list), capabilities);
        let mut writer = POP3MultiLineWriter::new();
        let mut written = Vec::new();
        writer.write(data, &mut written);
        writer.finish(&mut written);
        let mut reader = POP3MultiLineReader::new();
        let mut lines = Vec::new();
        assert_eq!(reader.read(&written, &mut lines), written.len());
        assert!(reader.is_end());
        assert!(lines.len() as u64 >= POP3MultiLineWriter::canonical_length(data));
        let settings = POP3ServerConfig {
            sasl_mechanisms: vec![String::from("PLAIN")],
            passwords_require_tls: false,
            ..POP3ServerConfig::default()
        };
        let mut server = POP3Server::new(POP3Config::default(), settings, false).unwrap();
        server.greet(POP3Response::ok("ready <1@fuzz>"), Instant::ZERO).unwrap();
        server.receive(data, Instant::ZERO);
        for _ in 0..64 {
            let Some(event) = server.poll_event() else { break };
            match event {
                POP3ServerEvent::Command(command) => {
                    let _ = server.reply(POP3Response::ok(""), Instant::ZERO);
                    if command.is_multi_line() {
                        let _ = server.send_data(b"line\r\n.dot\r\n");
                        let _ = server.end_data(Instant::ZERO);
                    }
                }
                POP3ServerEvent::AuthResponse(_) => {
                    let _ = server.reply(POP3Response::ok("in"), Instant::ZERO);
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        server.transmit(&mut out);
        let mut client = POP3Client::new(POP3Config::default(), false, Instant::ZERO).unwrap();
        let _ = client.receive(data, Instant::ZERO);
        let _ = client.send(POP3Command::Capa, Instant::ZERO);
        let _ = client.receive(&out, Instant::ZERO);
        while client.poll_event().is_some() {}
        client.expire(Instant::from_nanos(1 << 50));
    });

/// IMAP: commands and responses that read write back to what reads the
/// same; a server and a client take any input without panicking, and what
/// the server sends the client reads.
#[cfg(umilib_feature = "protocol-imap-v4")]
pub const IMAP_V4: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-imap-v4", |data| {
        use umilib::codec::mail::{MIMEEntity, MailConfig};
        use umilib::protocol::imap::v4::{
            IMAPBody, IMAPClient, IMAPCommand, IMAPCondition, IMAPConfig, IMAPLiteralMode, IMAPReader, IMAPResponse,
            IMAPSection, IMAPServer, IMAPServerConfig, IMAPServerEvent, IMAPWriter,
        };
        use umilib::runtime::Instant;
        let line = |write: &dyn Fn(&mut IMAPWriter)| {
            let mut writer = IMAPWriter::new(IMAPLiteralMode::Server, true);
            write(&mut writer);
            let mut out = writer.out;
            out.truncate(out.len() - 2);
            out
        };
        for utf8 in [false, true] {
            if let Ok(command) = IMAPCommand::parse(data, utf8, 32) {
                let text = line(&|writer| command.write(writer));
                assert_eq!(
                    IMAPCommand::parse(&text, true, 32).as_ref(),
                    Ok(&command),
                    "{:?}",
                    String::from_utf8_lossy(&text)
                );
            }
            if let Ok(response) = IMAPResponse::parse(data, utf8, 32)
                && response.check().is_ok()
            {
                let text = line(&|writer| response.write(writer));
                assert_eq!(
                    IMAPResponse::parse(&text, true, 32).as_ref(),
                    Ok(&response),
                    "{:?}",
                    String::from_utf8_lossy(&text)
                );
            }
        }
        if let Ok(entity) = MIMEEntity::decode(data, &MailConfig::default()) {
            let body = IMAPBody::from_entity(&entity, data, true);
            let text = line(&|writer| {
                body.write(writer);
                writer.raw(b"\r\n");
            });
            assert_eq!(IMAPBody::read(&mut IMAPReader::new(&text, 64)).as_ref(), Ok(&body));
            for spec in [&b"[1]"[..], b"[TEXT]", b"[1.2.MIME]", b"[HEADER.FIELDS (SUBJECT)]"] {
                let section = IMAPSection::read(&mut IMAPReader::new(spec, 8), false).unwrap();
                let _ = section.extract(&entity, data);
            }
        }
        let settings = IMAPServerConfig {
            passwords_require_tls: false,
            auth_mechanisms: vec![String::from("PLAIN")],
            ..IMAPServerConfig::default()
        };
        let mut server = IMAPServer::new(IMAPConfig::default(), settings, false).unwrap();
        server.greet(IMAPCondition::OK, "ready", Instant::ZERO).unwrap();
        server.receive(data, Instant::ZERO);
        for _ in 0..64 {
            let Some(event) = server.poll_event() else { break };
            match event {
                IMAPServerEvent::Command(_)
                | IMAPServerEvent::AuthenticateResponse { .. }
                | IMAPServerEvent::IdleDone { .. } => {
                    let _ = server.respond(&IMAPResponse::untagged(IMAPCondition::OK, None, "fine"));
                    let _ = server.complete(IMAPCondition::OK, None, "done", Instant::ZERO);
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        server.transmit(&mut out);
        let mut client = IMAPClient::new(IMAPConfig::default(), false, "f", Instant::ZERO).unwrap();
        let _ = client.receive(&out, Instant::ZERO);
        while client.poll_event().is_some() {}
        let mut client = IMAPClient::new(IMAPConfig::default(), false, "f", Instant::ZERO).unwrap();
        let _ = client.receive(data, Instant::ZERO);
        while client.poll_event().is_some() {}
        client.expire(Instant::from_nanos(1 << 50));
    });

/// FTP: commands, replies, data addresses, facts and times that read
/// write back to what reads the same; a server and a client take any input
/// without panicking, and what the server sends reads as replies.
#[cfg(umilib_feature = "protocol-ftp")]
pub const FTP: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("protocol-ftp", |data| {
        use umilib::protocol::ftp::{
            FTPClient, FTPCommand, FTPConfig, FTPDataAddress, FTPFacts, FTPReply, FTPReplyReader, FTPServer,
            FTPServerConfig, FTPServerEvent, FTPTime,
        };
        use umilib::protocol::ip::{IPAddress, IPv4Address};
        use umilib::runtime::Instant;
        let mut reader = FTPReplyReader::new();
        for line in data.split(|byte| *byte == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if let Ok(command) = FTPCommand::parse(line) {
                let mut wire = Vec::new();
                if command.encode(&mut wire).is_ok() {
                    assert_eq!(FTPCommand::parse(&wire[..wire.len() - 2]).as_ref(), Ok(&command));
                }
            }
            // A line between the first and the last that begins with three digits is padded when
            // written (RFC 959 §4.2), so the reply written once is what is written ever after.
            if let Ok(Some(reply)) = reader.push(line, 64) {
                let mut wire = Vec::new();
                reply.encode(&mut wire);
                let mut again = FTPReplyReader::new();
                let read = wire
                    .split(|byte| *byte == b'\n')
                    .filter_map(|line| line.strip_suffix(b"\r"))
                    .map(|line| again.push(line, 64))
                    .last();
                let Some(Ok(Some(read))) = read else { panic!("a written reply reads") };
                assert_eq!(read.code, reply.code);
                let mut rewritten = Vec::new();
                read.encode(&mut rewritten);
                assert_eq!(rewritten, wire);
            }
            if let Ok(text) = core::str::from_utf8(line) {
                if let Ok(facts) = FTPFacts::parse(text) {
                    assert_eq!(FTPFacts::parse(&format!("{facts}")).as_ref(), Ok(&facts));
                }
                if let Ok(time) = FTPTime::parse(text) {
                    assert_eq!(FTPTime::parse(&format!("{time}")), Ok(time));
                }
                if let Ok(address) = FTPDataAddress::parse_port(text) {
                    assert_eq!(FTPDataAddress::parse_port(&address.format_port().unwrap()), Ok(address));
                }
                if let Ok(address) = FTPDataAddress::parse_eprt(text) {
                    assert_eq!(FTPDataAddress::parse_eprt(&address.format_eprt().unwrap()), Ok(address));
                }
            }
        }
        let peer = IPAddress::V4(IPv4Address::new(127, 0, 0, 1));
        let mut server = FTPServer::new(FTPConfig::default(), FTPServerConfig::default(), peer, false).unwrap();
        server.greet(FTPReply::new(220, "ready"), Instant::ZERO).unwrap();
        server.receive(data, Instant::ZERO);
        for _ in 0..64 {
            let Some(event) = server.poll_event() else { break };
            if let FTPServerEvent::Command(command) = event {
                if command.transfers() {
                    let _ = server.reply(FTPReply::new(150, "opening"), Instant::ZERO);
                    let _ = server.reply(FTPReply::new(226, "done"), Instant::ZERO);
                } else {
                    let _ = server.reply(FTPReply::new(250, "OK"), Instant::ZERO);
                }
            }
        }
        let mut out = Vec::new();
        server.transmit(&mut out);
        let mut reader = FTPReplyReader::new();
        for line in out.split(|byte| *byte == b'\n').filter_map(|line| line.strip_suffix(b"\r")) {
            assert!(reader.push(line, usize::MAX).is_ok());
        }
        let mut client = FTPClient::new(FTPConfig::default(), false, Instant::ZERO).unwrap();
        let _ = client.receive(data, Instant::ZERO);
        while client.poll_event().is_some() {}
        client.expire(Instant::from_nanos(1 << 50));
    });

pub const TARGETS: &[&dyn FuzzTarget] = &[
    #[cfg(umilib_feature = "protocol-arp")]
    &ARP,
    #[cfg(umilib_feature = "protocol-coap")]
    &COAP,
    #[cfg(umilib_feature = "protocol-dhcp-v4")]
    &DHCP_V4,
    #[cfg(umilib_feature = "protocol-dhcp-v6")]
    &DHCP_V6,
    #[cfg(umilib_feature = "protocol-dns")]
    &DNS,
    #[cfg(umilib_feature = "protocol-dns")]
    &DNS_SERVER,
    #[cfg(umilib_feature = "protocol-ethernet")]
    &ETHERNET,
    #[cfg(umilib_feature = "protocol-ftp")]
    &FTP,
    #[cfg(umilib_feature = "protocol-http")]
    &HTTP,
    #[cfg(umilib_feature = "protocol-http-v1")]
    &HTTP_V1,
    #[cfg(umilib_feature = "protocol-http-v2")]
    &HTTP_V2,
    #[cfg(umilib_feature = "protocol-http-v3")]
    &HTTP_V3,
    #[cfg(umilib_feature = "protocol-icmp")]
    &ICMP,
    #[cfg(umilib_feature = "protocol-icmp-v4")]
    &ICMP_V4,
    #[cfg(umilib_feature = "protocol-icmp-v6")]
    &ICMP_V6,
    #[cfg(umilib_feature = "protocol-imap-v4")]
    &IMAP_V4,
    #[cfg(umilib_feature = "protocol-ip")]
    &IP,
    #[cfg(umilib_feature = "protocol-ip-v4")]
    &IP_V4,
    #[cfg(umilib_feature = "protocol-ip-v6")]
    &IP_V6,
    #[cfg(umilib_feature = "protocol-jwt")]
    &JWT,
    #[cfg(umilib_feature = "protocol-pop-v3")]
    &POP_V3,
    #[cfg(umilib_feature = "protocol-quic")]
    &QUIC_CODEC,
    #[cfg(umilib_feature = "protocol-quic")]
    &QUIC_CONNECTION,
    #[cfg(umilib_feature = "protocol-smtp")]
    &SMTP,
    #[cfg(umilib_feature = "protocol-tcp")]
    &TCP,
    #[cfg(umilib_feature = "protocol-tls")]
    &TLS_CODEC,
    #[cfg(umilib_feature = "protocol-tls")]
    &TLS_HANDSHAKE,
    #[cfg(umilib_feature = "protocol-udp")]
    &UDP,
    #[cfg(umilib_feature = "protocol-websocket")]
    &WEBSOCKET,
];
