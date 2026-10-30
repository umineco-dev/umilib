//! Benchmarks of `umilib::protocol`.

use umilib::platform::bench::Bench;

pub struct Benchmarks;

impl Benchmarks {
    pub fn run(bench: &mut Bench) {
        #[cfg(umilib_feature = "protocol-ip")]
        Benchmarks::ip(bench);
        #[cfg(umilib_feature = "protocol-ip-v4")]
        Benchmarks::ip_v4(bench);
        #[cfg(umilib_feature = "protocol-ip-v6")]
        Benchmarks::ip_v6(bench);
        #[cfg(umilib_feature = "protocol-ethernet")]
        Benchmarks::ethernet(bench);
        #[cfg(umilib_feature = "protocol-arp")]
        Benchmarks::arp(bench);
        #[cfg(umilib_feature = "protocol-coap")]
        Benchmarks::coap(bench);
        #[cfg(umilib_feature = "protocol-dhcp-v4")]
        Benchmarks::dhcp_v4(bench);
        #[cfg(umilib_feature = "protocol-dns")]
        Benchmarks::dns(bench);
        #[cfg(umilib_feature = "protocol-ftp")]
        Benchmarks::ftp(bench);
        #[cfg(umilib_feature = "protocol-dns-dnssec")]
        Benchmarks::dns_dnssec(bench);
        #[cfg(umilib_feature = "protocol-icmp-v4")]
        Benchmarks::icmp_v4(bench);
        #[cfg(umilib_feature = "protocol-imap-v4")]
        Benchmarks::imap_v4(bench);
        #[cfg(umilib_feature = "protocol-icmp-v6")]
        Benchmarks::icmp_v6(bench);
        #[cfg(umilib_feature = "protocol-jwt")]
        Benchmarks::jwt(bench);
        #[cfg(umilib_feature = "protocol-http")]
        Benchmarks::http(bench);
        #[cfg(umilib_feature = "protocol-http-v1")]
        Benchmarks::http_v1(bench);
        #[cfg(umilib_feature = "protocol-http-v2")]
        Benchmarks::http_v2(bench);
        #[cfg(umilib_feature = "protocol-pop-v3")]
        Benchmarks::pop_v3(bench);
        #[cfg(umilib_feature = "protocol-quic")]
        Benchmarks::quic(bench);
        #[cfg(umilib_feature = "protocol-smtp")]
        Benchmarks::smtp(bench);
        #[cfg(umilib_feature = "protocol-tcp")]
        Benchmarks::tcp(bench);
        #[cfg(umilib_feature = "protocol-tls")]
        Benchmarks::tls(bench);
        #[cfg(umilib_feature = "protocol-udp")]
        Benchmarks::udp(bench);
        #[cfg(umilib_feature = "protocol-websocket")]
        Benchmarks::websocket(bench);
        let _ = bench;
    }

    /// The Internet checksum of a 1,500-byte packet, and the text forms of addresses.
    #[cfg(umilib_feature = "protocol-ip")]
    pub fn ip(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::platform::bench::Throughput;
        use umilib::protocol::ip::{IPv6Address, InternetChecksum};
        let packet: Vec<u8> = (0..1500u32).map(|index| index as u8).collect();
        bench.run("protocol-ip-checksum-1500", Some(Throughput::Bytes(packet.len() as u64)), || {
            black_box(InternetChecksum::checksum(black_box(&packet)));
        });
        bench.run("protocol-ip-ipv6-address-parse", Some(Throughput::Elements(1)), || {
            black_box(black_box("2001:db8:0:1:1:1:1:1").parse::<IPv6Address>().unwrap());
        });
        let address: IPv6Address = "2001:db8::1:0:0:1".parse().unwrap();
        bench.run("protocol-ip-ipv6-address-format", Some(Throughput::Elements(1)), || {
            black_box(black_box(&address).to_string());
        });
    }

    /// The IPv4 header read and written, and a datagram of 64 KiB cut into
    /// fragments for an MTU of 1,500 and reassembled.
    #[cfg(umilib_feature = "protocol-ip-v4")]
    pub fn ip_v4(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::bytes::Buffer;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::ip::v4::{IPv4Fragmenter, IPv4Header, IPv4Reassembler, IPv4ReassemblyConfig};
        use umilib::protocol::ip::{IPProtocol, IPv4Address};
        use umilib::runtime::Instant;
        let data = vec![0x5A; 65_000];
        let header = IPv4Header::new(
            IPv4Address::new(192, 0, 2, 1),
            IPv4Address::new(192, 0, 2, 2),
            IPProtocol::UDP,
            data.len(),
        )
        .unwrap();
        let mut bytes = Buffer::new();
        header.encode(&mut bytes).unwrap();
        let mut packet = bytes.into_vec();
        packet.extend_from_slice(&data[..1480]);
        packet[2..4].copy_from_slice(&1500u16.to_be_bytes());
        let mut checksum = umilib::protocol::ip::InternetChecksum::new();
        packet[10..12].copy_from_slice(&[0, 0]);
        checksum.update(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.finish().to_be_bytes());
        bench.run("protocol-ip-v4-header-decode", Some(Throughput::Elements(1)), || {
            black_box(IPv4Header::decode(black_box(&packet)).unwrap());
        });
        bench.run("protocol-ip-v4-header-encode", Some(Throughput::Elements(1)), || {
            black_box(black_box(&header).to_bytes());
        });
        bench.run("protocol-ip-v4-fragment-reassemble-65000", Some(Throughput::Bytes(data.len() as u64)), || {
            let mut reassembler = IPv4Reassembler::new(IPv4ReassemblyConfig::default());
            let mut whole = None;
            for (fragment, part) in IPv4Fragmenter::new(header, &data, 1500).unwrap() {
                whole = whole.or(reassembler.receive(&fragment, part, Instant::ZERO).unwrap());
            }
            black_box(whole.unwrap());
        });
    }

    /// The extension headers of an IPv6 packet walked, and a packet of 64 KiB
    /// cut into fragments for an MTU of 1,280 and reassembled.
    #[cfg(umilib_feature = "protocol-ip-v6")]
    pub fn ip_v6(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::bytes::Buffer;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::ip::v6::{
            IPv6ExtensionHeaders, IPv6Fragmenter, IPv6Header, IPv6Reassembler, IPv6ReassemblyConfig,
        };
        use umilib::protocol::ip::{IPProtocol, IPv6Address};
        use umilib::runtime::Instant;
        let source: IPv6Address = "2001:db8::1".parse().unwrap();
        let destination: IPv6Address = "2001:db8::2".parse().unwrap();
        let chain = [60, 0, 1, 4, 0, 0, 0, 0, 17, 0, 1, 4, 0, 0, 0, 0];
        bench.run("protocol-ip-v6-extension-headers", Some(Throughput::Elements(1)), || {
            black_box(IPv6ExtensionHeaders::upper_layer(IPProtocol::HOP_BY_HOP_OPTIONS, black_box(&chain)).unwrap());
        });
        let data = vec![0x5A; 65_000];
        let header = IPv6Header::new(source, destination, IPProtocol::UDP, data.len()).unwrap();
        bench.run("protocol-ip-v6-fragment-reassemble-65000", Some(Throughput::Bytes(data.len() as u64)), || {
            let mut reassembler = IPv6Reassembler::new(IPv6ReassemblyConfig::default());
            let mut whole = None;
            for fragment in IPv6Fragmenter::new(header, &data, 7, 1280).unwrap() {
                let mut packet = Buffer::new();
                fragment.encode(&mut packet).unwrap();
                let (decoded, payload) = IPv6Header::decode(packet.as_slice()).unwrap();
                whole = whole.or(reassembler.receive(&decoded, payload, Instant::ZERO).unwrap());
            }
            black_box(whole.unwrap());
        });
    }

    /// An Ethernet header with two VLAN tags read and written, and the frame
    /// check sequence of a 1,514-byte frame.
    #[cfg(umilib_feature = "protocol-ethernet")]
    pub fn ethernet(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::bytes::Buffer;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::ethernet::{EtherType, EthernetFrame, EthernetHeader, MACAddress, VLANTag};
        let mut header = EthernetHeader::new(MACAddress::BROADCAST, MACAddress([2, 0, 0, 0, 0, 1]), EtherType::IPV4);
        let tag = VLANTag { protocol: EtherType::SERVICE_VLAN, priority: 0, drop_eligible: false, identifier: 200 };
        header.tags = [Some(tag), Some(VLANTag { protocol: EtherType::VLAN, identifier: 300, ..tag })];
        let mut bytes = Buffer::new();
        header.encode(&mut bytes).unwrap();
        let frame = bytes.into_vec();
        bench.run("protocol-ethernet-header-decode", Some(Throughput::Elements(1)), || {
            black_box(EthernetHeader::decode(black_box(&frame)).unwrap());
        });
        let large = vec![0xA5; 1514];
        bench.run("protocol-ethernet-fcs-1514", Some(Throughput::Bytes(large.len() as u64)), || {
            black_box(EthernetFrame::fcs(black_box(&large)));
        });
    }

    /// A request answered by a cache of 512 addresses.
    #[cfg(umilib_feature = "protocol-arp")]
    pub fn arp(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::platform::bench::Throughput;
        use umilib::protocol::arp::{ARPCache, ARPConfig, ARPPacket};
        use umilib::protocol::ethernet::MACAddress;
        use umilib::protocol::ip::IPv4Address;
        use umilib::runtime::Instant;
        let mut cache: ARPCache = ARPCache::new(ARPConfig::default());
        for index in 0..511u32 {
            cache.insert_static(
                IPv4Address::from_bits(0x0A00_0000 | index),
                MACAddress([2, 0, 0, 0, (index >> 8) as u8, index as u8]),
            );
        }
        let local = [IPv4Address::new(10, 0, 1, 255)];
        let request =
            ARPPacket::ethernet_request(MACAddress([2, 0, 0, 0, 0, 5]), IPv4Address::new(10, 0, 0, 5), local[0]);
        bench.run("protocol-arp-receive-request", Some(Throughput::Elements(1)), || {
            black_box(cache.receive(black_box(&request), MACAddress([2, 0, 0, 0, 1, 255]), &local, Instant::ZERO));
        });
    }

    /// The reply to an Echo Request of 56 bytes, read and written.
    #[cfg(umilib_feature = "protocol-icmp-v4")]
    pub fn icmp_v4(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::bytes::Buffer;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::icmp::v4::ICMPv4Message;
        let data = [0x5A; 56];
        let mut bytes = Buffer::new();
        ICMPv4Message::echo_request(1, 1, &data).encode(&mut bytes).unwrap();
        let request = bytes.into_vec();
        let mut reply = Buffer::with_capacity(request.len());
        bench.run("protocol-icmp-v4-echo-reply", Some(Throughput::Elements(1)), || {
            reply.clear();
            let message = ICMPv4Message::decode(black_box(&request)).unwrap();
            message.echo_reply().unwrap().encode(&mut reply).unwrap();
            black_box(reply.as_slice());
        });
    }

    /// An error message of 1,232 bytes checked, a Neighbor Solicitation
    /// validated, and an address resolved by a cache of 512 neighbors.
    #[cfg(umilib_feature = "protocol-icmp-v6")]
    pub fn icmp_v6(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::bytes::Buffer;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::icmp::v6::{
            ICMPv6Message, ICMPv6Type, NDPMessage, NDPNeighborSolicitation, NDPOption, NDPOptionKind, NeighborCache,
            NeighborConfig,
        };
        use umilib::protocol::ip::v6::IPv6Header;
        use umilib::protocol::ip::{IPProtocol, IPv6Address};
        use umilib::runtime::Instant;
        let source: IPv6Address = "fe80::1".parse().unwrap();
        let destination: IPv6Address = "fe80::2".parse().unwrap();
        let quoted = [0xA5; 1224];
        let error = ICMPv6Message { kind: ICMPv6Type::PACKET_TOO_BIG, code: 0, rest: [0, 0, 5, 0], body: &quoted };
        let mut bytes = Buffer::new();
        error.encode(source, destination, &mut bytes).unwrap();
        let error = bytes.into_vec();
        bench.run("protocol-icmp-v6-message-decode-1232", Some(Throughput::Bytes(error.len() as u64)), || {
            black_box(ICMPv6Message::decode(black_box(&error), source, destination).unwrap());
        });
        let target = destination.solicited_node();
        let mut options = Buffer::new();
        NDPOption::encode(NDPOptionKind::SOURCE_LINK_ADDRESS, &[2, 0, 0, 0, 0, 1], &mut options).unwrap();
        let mut bytes = Buffer::new();
        NDPNeighborSolicitation { target: destination, options: options.as_slice() }
            .encode(source, target, &mut bytes)
            .unwrap();
        let solicitation = bytes.into_vec();
        let mut header = IPv6Header::new(source, target, IPProtocol::ICMPV6, solicitation.len()).unwrap();
        header.hop_limit = NDPMessage::HOP_LIMIT;
        bench.run("protocol-icmp-v6-neighbor-solicitation-decode", Some(Throughput::Elements(1)), || {
            let message = ICMPv6Message::decode(black_box(&solicitation), source, target).unwrap();
            black_box(NDPNeighborSolicitation::decode(&message, &header).unwrap());
        });
        let mut cache: NeighborCache = NeighborCache::new(NeighborConfig::default());
        let mut words = [0xFE80, 0, 0, 0, 0, 0, 0, 0];
        for index in 0..512u16 {
            words[7] = index;
            cache.learn(
                IPv6Address::from_words(words),
                Some([2, 0, 0, 0, (index >> 8) as u8, index as u8]),
                None,
                Instant::ZERO,
            );
        }
        words[7] = 300;
        let neighbor = IPv6Address::from_words(words);
        bench.run("protocol-icmp-v6-neighbor-cache-resolve", Some(Throughput::Elements(1)), || {
            black_box(cache.resolve(black_box(neighbor), None, Instant::ZERO).unwrap());
        });
    }

    /// The JWT of RFC 7519 §3.1 signed and verified with HS256 and Ed25519,
    /// and encrypted and decrypted with A128KW and A128GCM and ECDH-ES on P-256.
    #[cfg(umilib_feature = "protocol-jwt")]
    pub fn jwt(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::jwt::{
            JOSEHeader, JWEAlgorithm, JWEConfig, JWEEncryption, JWK, JWSAlgorithm, JWSConfig, JWT, JWTClaims,
            JWTValidation,
        };
        let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"umilib bench jwt").unwrap();
        let claims = JWTClaims::decode(br#"{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"#).unwrap();
        let validation = JWTValidation::new(1300819379);
        let header = |text: &str| JOSEHeader::decode(text.as_bytes()).unwrap();
        let hmac = JWK::symmetric(&[7; 32]);
        let token = JWT::sign(&claims, &header(r#"{"alg":"HS256"}"#), &hmac, &mut random).unwrap();
        let hs256 = JWSConfig::new(&[JWSAlgorithm::HS256]);
        bench.run("protocol-jwt-hs256-verify", Some(Throughput::Elements(1)), || {
            black_box(JWT::verify(black_box(&token), &hmac, &hs256, &validation).unwrap());
        });
        let ed25519 = JWK::from_json(
            br#"{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
        )
        .unwrap();
        let signing = header(r#"{"alg":"Ed25519"}"#);
        bench.run("protocol-jwt-ed25519-sign", Some(Throughput::Elements(1)), || {
            black_box(JWT::sign(&claims, &signing, &ed25519, &mut random).unwrap());
        });
        let token = JWT::sign(&claims, &signing, &ed25519, &mut random).unwrap();
        let public = ed25519.to_public().unwrap();
        let ed = JWSConfig::new(&[JWSAlgorithm::Ed25519]);
        bench.run("protocol-jwt-ed25519-verify", Some(Throughput::Elements(1)), || {
            black_box(JWT::verify(black_box(&token), &public, &ed, &validation).unwrap());
        });
        let wrapping = JWK::symmetric(&[5; 16]);
        let encryption = header(r#"{"alg":"A128KW","enc":"A128GCM"}"#);
        let token = JWT::encrypt(&claims, &encryption, &wrapping, &mut random).unwrap();
        let kw = JWEConfig::new(&[JWEAlgorithm::A128KW], &[JWEEncryption::A128GCM]);
        bench.run("protocol-jwt-a128kw-a128gcm-decrypt", Some(Throughput::Elements(1)), || {
            black_box(JWT::decrypt(black_box(&token), &wrapping, &kw, &validation, &mut random).unwrap());
        });
        let p256 = JWK::from_json(
            br#"{"kty":"EC","crv":"P-256","x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ","y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck","d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#,
        )
        .unwrap();
        let agreement = header(r#"{"alg":"ECDH-ES","enc":"A128GCM"}"#);
        let recipient = p256.to_public().unwrap();
        bench.run("protocol-jwt-ecdh-es-p256-encrypt", Some(Throughput::Elements(1)), || {
            black_box(JWT::encrypt(&claims, &agreement, &recipient, &mut random).unwrap());
        });
        let token = JWT::encrypt(&claims, &agreement, &recipient, &mut random).unwrap();
        let ecdh = JWEConfig::new(&[JWEAlgorithm::ECDHES], &[JWEEncryption::A128GCM]);
        bench.run("protocol-jwt-ecdh-es-p256-decrypt", Some(Throughput::Elements(1)), || {
            black_box(JWT::decrypt(black_box(&token), &p256, &ecdh, &validation, &mut random).unwrap());
        });
    }

    /// A datagram of 1,472 bytes (an Ethernet MTU over IPv4) checked and
    /// written over IPv6, and a router rule matched.
    #[cfg(umilib_feature = "protocol-udp")]
    pub fn udp(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::bytes::Buffer;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::ip::{IPAddress, IPEndpointPattern, IPv6Address};
        use umilib::protocol::udp::{UDPConfig, UDPDatagram, UDPRequest, UDPRule};
        use umilib::service::Rule;
        let source = IPAddress::V6(IPv6Address::from_words([0x2001, 0xDB8, 0, 0, 0, 0, 0, 1]));
        let destination = IPAddress::V6(IPv6Address::from_words([0x2001, 0xDB8, 0, 0, 0, 0, 0, 2]));
        let config = UDPConfig::default();
        let payload = vec![0x5A; 1464];
        let datagram = UDPDatagram { source_port: 40000, destination_port: 53, checksummed: true, payload: &payload };
        let mut bytes = Buffer::new();
        datagram.encode(source, destination, &config, &mut bytes).unwrap();
        let bytes = bytes.into_vec();
        bench.run("protocol-udp-decode-1472", Some(Throughput::Bytes(bytes.len() as u64)), || {
            black_box(UDPDatagram::decode(black_box(&bytes), source, destination, &config).unwrap());
        });
        let mut out = Buffer::with_capacity(bytes.len());
        bench.run("protocol-udp-encode-1472", Some(Throughput::Bytes(bytes.len() as u64)), || {
            out.clear();
            black_box(&datagram).encode(source, destination, &config, &mut out).unwrap();
            black_box(out.as_slice());
        });
        let rule = UDPRule::new(IPEndpointPattern::port(53).with_address(destination))
            .with_remote(IPEndpointPattern::ANY.with_prefix(source, 48));
        let request = UDPRequest {
            local: "[2001:db8::2]:53".parse().unwrap(),
            remote: "[2001:db8::1]:40000".parse().unwrap(),
            payload: Vec::new(),
        };
        bench.run("protocol-udp-rule-matches", Some(Throughput::Elements(1)), || {
            black_box(rule.matches(black_box(&request)));
        });
    }

    /// Full handshakes of TLS 1.3 and TLS 1.2 (X25519, ECDSA P-256), a
    /// resumption of TLS 1.3, and a megabyte each way through a connection.
    #[cfg(umilib_feature = "protocol-tls")]
    pub fn tls(bench: &mut Bench) {
        use std::hint::black_box;
        use std::sync::Arc;

        use umilib::auth::cert::key::{KeyLimits, PrivateKey};
        use umilib::auth::cert::path::TrustAnchor;
        use umilib::auth::cert::x509::Certificate;
        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::tls::{
            TLSCertifiedKey, TLSClientConfig, TLSConnection, TLSNamedGroup, TLSPathVerifier, TLSServerConfig,
            TLSSessionCache, TLSTicketKey, TLSTicketKeys, TLSVersion,
        };
        const TIME: i64 = 1_798_761_600;
        let root = include_bytes!("../tests/vectors/protocol/tls/certificates/root.der");
        let anchor = Certificate::from_der(root).unwrap().into_owned();
        let anchor = TrustAnchor::from_certificate(anchor, &KeyLimits::default()).unwrap();
        let random = |seed: u8| Box::new(HMACDRBG::<SHA256>::new(&[seed; 32], &[seed; 16], b"bench").unwrap());
        let mut client = TLSClientConfig::new(Arc::new(TLSPathVerifier::servers(vec![anchor])));
        client.config.groups = vec![TLSNamedGroup::X25519, TLSNamedGroup::SECP256R1];
        client.key_share_groups = vec![TLSNamedGroup::X25519];
        let key =
            PrivateKey::from_pem(include_str!("../tests/vectors/protocol/tls/certificates/server-p256.key")).unwrap();
        let certificate = include_bytes!("../tests/vectors/protocol/tls/certificates/server-p256.der").to_vec();
        let mut server =
            TLSServerConfig::new(vec![Arc::new(TLSCertifiedKey { chain: vec![certificate], key, ocsp: None })]);
        server.config.groups = vec![TLSNamedGroup::X25519];
        // Moves bytes both ways until neither side has more.
        let run = |client: &mut TLSConnection, server: &mut TLSConnection| loop {
            let mut moved = false;
            for to_server in [true, false] {
                let (from, to) = if to_server { (&mut *client, &mut *server) } else { (&mut *server, &mut *client) };
                let mut bytes = Vec::new();
                from.transmit(&mut bytes).unwrap();
                if !bytes.is_empty() {
                    to.receive(&bytes).unwrap();
                    moved = true;
                }
            }
            if !moved {
                return;
            }
        };
        for version in [TLSVersion::TLS1_3, TLSVersion::TLS1_2] {
            let (mut client, mut server) = (client.clone(), server.clone());
            client.config.versions = vec![version];
            server.config.versions = vec![version];
            let (client, server) = (Arc::new(client), Arc::new(server));
            let name = if version == TLSVersion::TLS1_3 {
                "protocol-tls-v1_3-handshake"
            } else {
                "protocol-tls-v1_2-handshake"
            };
            bench.run(name, None, || {
                let mut a = TLSConnection::client(client.clone(), Some("server.example"), random(1), TIME).unwrap();
                let mut b = TLSConnection::server(server.clone(), random(2), TIME).unwrap();
                run(&mut a, &mut b);
                black_box(a.is_handshaking());
            });
        }
        let mut resuming = client.clone();
        resuming.sessions = Some(Arc::new(TLSSessionCache::new(1 << 16)));
        let mut tickets = server.clone();
        tickets.tickets = Some(Arc::new(TLSTicketKeys::new(vec![TLSTicketKey::new([1; 16], &[2; 32]).unwrap()])));
        tickets.ticket_count = 1;
        let (resuming, tickets) = (Arc::new(resuming), Arc::new(tickets));
        let mut first = TLSConnection::client(resuming.clone(), Some("server.example"), random(3), TIME).unwrap();
        let mut second = TLSConnection::server(tickets.clone(), random(4), TIME).unwrap();
        run(&mut first, &mut second);
        bench.run("protocol-tls-v1_3-resumption", None, || {
            let mut a = TLSConnection::client(resuming.clone(), Some("server.example"), random(5), TIME).unwrap();
            let mut b = TLSConnection::server(tickets.clone(), random(6), TIME).unwrap();
            run(&mut a, &mut b);
            assert!(a.session.resumed);
        });
        let (client, server) = (Arc::new(client), Arc::new(server));
        let mut a = TLSConnection::client(client, Some("server.example"), random(7), TIME).unwrap();
        let mut b = TLSConnection::server(server, random(8), TIME).unwrap();
        run(&mut a, &mut b);
        let total = 1 << 20;
        let data = vec![7u8; total];
        let mut read = vec![0u8; total];
        bench.run("protocol-tls-v1_3-loopback-1mib", Some(Throughput::Bytes(total as u64)), || {
            a.send(&data).unwrap();
            let mut bytes = Vec::new();
            a.transmit(&mut bytes).unwrap();
            b.receive(&bytes).unwrap();
            assert_eq!(b.read(&mut read), total);
        });
    }

    /// HTTP's semantics: a structured field parsed, a rule matched.
    #[cfg(umilib_feature = "protocol-http")]
    pub fn http(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::platform::bench::Throughput;
        use umilib::protocol::http::{HTTPMethod, HTTPRequest, HTTPRule, HTTPStructuredField};
        use umilib::service::{Pattern, Rule};
        let value = b"sugar, tea;q=0.5, rum;a=1;b=?0, (\"x\" :YWJj:);c=1.5";
        bench.run("protocol-http-structured-parse-list", Some(Throughput::Bytes(value.len() as u64)), || {
            black_box(HTTPStructuredField::parse_list(black_box(value)).unwrap());
        });
        let rule =
            HTTPRule::new(Pattern::suffix(b".example.com"), Pattern::prefix(b"/api/")).with_method(HTTPMethod::POST);
        let mut request = HTTPRequest::new(HTTPMethod::POST, b"https", b"auth.example.com:443", b"/api/token");
        request.fields.append(b"content-type", b"application/json").unwrap();
        bench.run("protocol-http-rule-matches", Some(Throughput::Elements(1)), || {
            black_box(rule.matches(black_box(&request)));
        });
    }

    /// The exchanges of an HTTP/1.1 client and server: a small GET, and a
    /// megabyte uploaded with chunked framing.
    #[cfg(umilib_feature = "protocol-http-v1")]
    pub fn http_v1(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::platform::bench::Throughput;
        use umilib::protocol::http::v1::{H1Config, H1Connection};
        use umilib::protocol::http::{HTTPConnection, HTTPEvent, HTTPMethod, HTTPRequest, HTTPResponse, HTTPStatus};
        use umilib::runtime::Instant;
        let now = Instant::from_nanos(1);
        let content = vec![0x5Au8; 1 << 20];
        let mut buffer = vec![0u8; 1 << 16];
        let mut wire = Vec::new();
        bench.run("protocol-http-v1-get", Some(Throughput::Elements(1)), || {
            let mut client = H1Connection::client(H1Config::default(), now);
            let mut server = H1Connection::server(H1Config::default(), now);
            let stream = client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"http", b"a", b"/"), true).unwrap();
            client.transmit(&mut wire);
            server.receive(&wire, now);
            wire.clear();
            let Some(HTTPEvent::Request { stream: served, .. }) = server.poll_event() else { panic!() };
            server.send_response(served, &HTTPResponse::new(HTTPStatus::OK), false).unwrap();
            server.send_data(served, b"ok", true).unwrap();
            server.transmit(&mut wire);
            client.receive(&wire, now);
            wire.clear();
            black_box(client.read_data(stream, &mut buffer).unwrap());
        });
        bench.run("protocol-http-v1-upload-1MiB", Some(Throughput::Bytes(content.len() as u64)), || {
            let mut client = H1Connection::client(H1Config::default(), now);
            let mut server = H1Connection::server(H1Config::default(), now);
            let stream = client.send_request(&HTTPRequest::new(HTTPMethod::POST, b"http", b"a", b"/"), false).unwrap();
            let mut sent = 0;
            let mut received = 0;
            while received < content.len() {
                if sent < content.len() {
                    sent += client.send_data(stream, &content[sent..], true).unwrap();
                }
                client.transmit(&mut wire);
                server.receive(&wire, now);
                wire.clear();
                while let Some(event) = server.poll_event() {
                    if let HTTPEvent::Data { stream } = event {
                        loop {
                            let count = server.read_data(stream, &mut buffer).unwrap();
                            if count == 0 {
                                break;
                            }
                            received += count;
                        }
                    }
                }
            }
            black_box(received);
        });
    }

    /// A megabyte from an HTTP/2 server to its client, through flow control.
    #[cfg(umilib_feature = "protocol-http-v2")]
    pub fn http_v2(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::platform::bench::Throughput;
        use umilib::protocol::http::v2::{H2Config, H2Connection};
        use umilib::protocol::http::{HTTPConnection, HTTPEvent, HTTPMethod, HTTPRequest, HTTPResponse, HTTPStatus};
        use umilib::runtime::Instant;
        let now = Instant::from_nanos(1);
        let content = vec![0x5Au8; 1 << 20];
        let mut buffer = vec![0u8; 1 << 16];
        let mut wire = Vec::new();
        bench.run("protocol-http-v2-download-1MiB", Some(Throughput::Bytes(content.len() as u64)), || {
            let mut client = H2Connection::client(H2Config::default(), now);
            let mut server = H2Connection::server(H2Config::default(), now);
            let stream = client.send_request(&HTTPRequest::new(HTTPMethod::GET, b"https", b"a", b"/"), true).unwrap();
            let mut served = None;
            let mut sent = 0;
            let mut received = 0;
            while received < content.len() {
                client.transmit(&mut wire);
                server.receive(&wire, now);
                wire.clear();
                while let Some(event) = server.poll_event() {
                    if let HTTPEvent::Request { stream, .. } = event {
                        server.send_response(stream, &HTTPResponse::new(HTTPStatus::OK), false).unwrap();
                        served = Some(stream);
                    }
                }
                if let Some(served) = served.filter(|_| sent < content.len()) {
                    sent += server.send_data(served, &content[sent..], true).unwrap();
                }
                server.transmit(&mut wire);
                client.receive(&wire, now);
                wire.clear();
                while client.poll_event().is_some() {}
                loop {
                    let count = client.read_data(stream, &mut buffer).unwrap();
                    if count == 0 {
                        break;
                    }
                    received += count;
                }
            }
            black_box(received);
        });
    }

    /// QUIC: a packet protected and read back (AES-128-GCM and its header
    /// protection), the frames of a full packet decoded, a handshake, and a
    /// megabyte on a stream between two connections in memory.
    #[cfg(umilib_feature = "protocol-quic")]
    pub fn quic(bench: &mut Bench) {
        use std::hint::black_box;
        use std::sync::Arc;

        use umilib::auth::cert::key::{KeyLimits, PrivateKey};
        use umilib::auth::cert::path::TrustAnchor;
        use umilib::auth::cert::x509::Certificate;
        use umilib::bytes::Reader;
        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::ip::IPEndpoint;
        use umilib::protocol::quic::{
            QUICAcceptance, QUICConfig, QUICConnection, QUICConnectionID, QUICECN, QUICFrame, QUICHeader, QUICPacket,
            QUICRole, QUICSecret, QUICShortHeader, QUICStreamID, QUICVersion,
        };
        use umilib::protocol::tls::{
            TLSCertifiedKey, TLSClientConfig, TLSNamedGroup, TLSPathVerifier, TLSServerConfig,
        };
        use umilib::runtime::Instant;
        const TIME: i64 = 1_798_761_600;
        let profile = QUICVersion::V1.profile().or(QUICVersion::V2.profile()).unwrap();
        let secret = QUICSecret::initial(profile, &QUICConnectionID::new(&[1; 8]).unwrap(), QUICRole::Client).unwrap();
        let (key, header) = (secret.packet_key(profile).unwrap(), secret.header_protection(profile).unwrap());
        let short = QUICHeader::Short(QUICShortHeader {
            destination: QUICConnectionID::new(&[2; 8]).unwrap(),
            spin: false,
            key_phase: false,
        });
        let payload = vec![0u8; 1200 - 1 - 8 - 4 - 16];
        bench.run("protocol-quic-protect-1200", Some(Throughput::Bytes(1200)), || {
            let mut packet = Vec::with_capacity(1200);
            let offset = short.encode(true, 7, 4, payload.len() + 16, &mut packet).unwrap();
            let start = packet.len();
            packet.extend_from_slice(&payload);
            key.seal(7, start, &mut packet).unwrap();
            header.apply(&mut packet, offset, 4).unwrap();
            let (length, _) = header.remove(&mut packet, offset).unwrap();
            black_box(key.open(7, offset + length, &mut packet).unwrap());
        });
        let mut frames = Vec::new();
        for index in 0..100u64 {
            QUICFrame::Stream {
                stream: QUICStreamID(index * 4),
                offset: index * 1000,
                data: b"0123456789",
                fin: false,
            }
            .encode(&mut frames)
            .unwrap();
        }
        bench.run("protocol-quic-frames-decode", Some(Throughput::Bytes(frames.len() as u64)), || {
            let mut reader = Reader::new(&frames);
            while !reader.is_empty() {
                black_box(QUICFrame::decode(&mut reader).unwrap());
            }
        });
        let root = include_bytes!("../tests/vectors/protocol/tls/certificates/root.der");
        let anchor = Certificate::from_der(root).unwrap().into_owned();
        let anchor = TrustAnchor::from_certificate(anchor, &KeyLimits::default()).unwrap();
        let random = |seed: u8| Box::new(HMACDRBG::<SHA256>::new(&[seed; 32], &[seed; 16], b"bench").unwrap());
        let mut client = TLSClientConfig::new(Arc::new(TLSPathVerifier::servers(vec![anchor])));
        client.config.groups = vec![TLSNamedGroup::X25519, TLSNamedGroup::SECP256R1];
        client.key_share_groups = vec![TLSNamedGroup::X25519];
        client.config.protocols = vec![b"bench".to_vec()];
        let key =
            PrivateKey::from_pem(include_str!("../tests/vectors/protocol/tls/certificates/server-p256.key")).unwrap();
        let certificate = include_bytes!("../tests/vectors/protocol/tls/certificates/server-p256.der").to_vec();
        let mut server =
            TLSServerConfig::new(vec![Arc::new(TLSCertifiedKey { chain: vec![certificate], key, ocsp: None })]);
        server.config.groups = vec![TLSNamedGroup::X25519];
        server.config.protocols = vec![b"bench".to_vec()];
        let (client, server) = (Arc::new(client), Arc::new(server));
        let config = Arc::new(QUICConfig { pacing: false, ..QUICConfig::default() });
        let (a_end, b_end): (IPEndpoint, IPEndpoint) =
            ("192.0.2.1:40000".parse().unwrap(), "192.0.2.2:443".parse().unwrap());
        let now = Instant::from_nanos(1_000_000_000);
        // Moves datagrams both ways until neither side has more.
        let run = |a: &mut QUICConnection, b: &mut QUICConnection| loop {
            let mut moved = false;
            let mut out = Vec::new();
            while a.transmit(now, &mut out).is_some() {
                b.receive(&out, a_end, QUICECN::NotECT, now);
                moved = true;
            }
            while b.transmit(now, &mut out).is_some() {
                a.receive(&out, b_end, QUICECN::NotECT, now);
                moved = true;
            }
            if !moved {
                break;
            }
        };
        let connect = |seed: u8| {
            let mut a = QUICConnection::client(
                config.clone(),
                client.clone(),
                Some("server.example"),
                b_end,
                random(seed),
                now,
                TIME,
            )
            .unwrap();
            let mut first = Vec::new();
            a.transmit(now, &mut first).unwrap();
            let Ok(QUICPacket::Protected(packet)) = QUICPacket::decode(&first, 8) else { panic!() };
            let QUICHeader::Long(long) = packet.header else { panic!() };
            let acceptance = QUICAcceptance {
                version: long.version,
                original_destination: long.destination,
                destination: long.destination,
                source: long.source,
                retry_source: None,
                validated: false,
            };
            let mut b =
                QUICConnection::server(config.clone(), server.clone(), acceptance, a_end, random(seed + 1), now, TIME)
                    .unwrap();
            b.receive(&first, a_end, QUICECN::NotECT, now);
            (a, b)
        };
        let mut seed = 0u8;
        bench.run("protocol-quic-handshake", None, || {
            seed = seed.wrapping_add(2);
            let (mut a, mut b) = connect(seed);
            run(&mut a, &mut b);
            assert!(a.handshake_confirmed);
        });
        let (mut a, mut b) = connect(1);
        run(&mut a, &mut b);
        let total = 1 << 20;
        let data = vec![7u8; total];
        let mut read = vec![0u8; 65536];
        bench.run("protocol-quic-loopback-1mib", Some(Throughput::Bytes(total as u64)), || {
            let stream = a.open_stream(false).unwrap();
            let mut written = 0;
            let mut received = 0;
            while received < total {
                if written < total {
                    written += a.stream_send(stream, &data[written..], true).unwrap();
                }
                run(&mut a, &mut b);
                loop {
                    let (count, _) = b.stream_read(stream, &mut read).unwrap_or((0, false));
                    received += count;
                    if count == 0 {
                        break;
                    }
                }
                run(&mut a, &mut b);
            }
        });
    }

    /// A segment of 1,448 bytes with timestamps checked and written, and a
    /// megabyte through two connections in memory.
    #[cfg(umilib_feature = "protocol-tcp")]
    pub fn tcp(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::bytes::Buffer;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::ip::IPEndpoint;
        use umilib::protocol::tcp::{
            TCPConfig, TCPConnection, TCPFlags, TCPOptionSet, TCPSegment, TCPSequence, TCPTimestamps,
        };
        use umilib::runtime::Instant;
        let (a_end, b_end): (IPEndpoint, IPEndpoint) =
            ("192.0.2.1:40000".parse().unwrap(), "192.0.2.2:80".parse().unwrap());
        let mut options = Buffer::new();
        TCPOptionSet { timestamps: Some(TCPTimestamps { value: 1, echo_reply: 2 }), ..TCPOptionSet::default() }
            .encode(&mut options)
            .unwrap();
        let payload = vec![0x5A; 1448];
        let segment = TCPSegment {
            source_port: 40000,
            destination_port: 80,
            sequence: TCPSequence(1),
            acknowledgment: TCPSequence(2),
            flags: TCPFlags::ACK.union(TCPFlags::PSH),
            window: 1000,
            urgent_pointer: 0,
            options: options.as_slice(),
            payload: &payload,
        };
        let mut bytes = Buffer::new();
        segment.encode(a_end.address, b_end.address, &mut bytes).unwrap();
        let bytes = bytes.into_vec();
        bench.run("protocol-tcp-segment-decode-1500", Some(Throughput::Bytes(bytes.len() as u64)), || {
            black_box(TCPSegment::decode(black_box(&bytes), a_end.address, b_end.address).unwrap());
        });
        let mut out = Buffer::with_capacity(bytes.len());
        bench.run("protocol-tcp-segment-encode-1500", Some(Throughput::Bytes(bytes.len() as u64)), || {
            out.clear();
            black_box(&segment).encode(a_end.address, b_end.address, &mut out).unwrap();
            black_box(out.as_slice());
        });
        let total = 1 << 20;
        let data = vec![7u8; total];
        bench.run("protocol-tcp-loopback-1mib", Some(Throughput::Bytes(total as u64)), || {
            let config = TCPConfig::default();
            let mut a = TCPConnection::connect(config, a_end, b_end, TCPSequence(1), Instant::ZERO).unwrap();
            let mut syn = Buffer::new();
            a.transmit(Instant::ZERO, &mut syn).unwrap();
            let syn = TCPSegment::decode(syn.as_slice(), a_end.address, b_end.address).unwrap();
            let mut b = TCPConnection::accept(config, b_end, a_end, &syn, TCPSequence(2), Instant::ZERO).unwrap();
            let (mut sent, mut received) = (0, 0);
            let mut read = vec![0u8; 65536];
            let mut now = 0u64;
            while received < total {
                if sent < total {
                    sent += a.send(&data[sent..]).unwrap();
                }
                let mut moved = false;
                let at = Instant::from_nanos(now);
                for from_a in [true, false] {
                    loop {
                        let mut bytes = Buffer::new();
                        let (sender, source, destination) =
                            if from_a { (&mut a, a_end, b_end) } else { (&mut b, b_end, a_end) };
                        if sender.transmit(at, &mut bytes).unwrap().is_none() {
                            break;
                        }
                        moved = true;
                        let segment =
                            TCPSegment::decode(bytes.as_slice(), source.address, destination.address).unwrap();
                        let receiver = if from_a { &mut b } else { &mut a };
                        receiver.receive(&segment, false, at);
                    }
                }
                received += b.read(&mut read);
                if !moved {
                    now = [a.poll_timeout(), b.poll_timeout()]
                        .into_iter()
                        .flatten()
                        .min()
                        .map_or(now + 1, Instant::as_nanos);
                }
            }
            black_box(received);
        });
    }
    /// WebSocket: 64 KiB messages from a client (masked) to a server, plain
    /// and with permessage-deflate.
    #[cfg(umilib_feature = "protocol-websocket")]
    pub fn websocket(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::websocket::{
            WebSocketConfig, WebSocketConnection, WebSocketDeflateParameters, WebSocketRole,
        };
        let random = || Box::new(HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"bench").unwrap());
        let message: Vec<u8> = (0..1u32 << 16).map(|index| (index % 251) as u8).collect();
        for (name, deflate) in [("plain", None), ("deflate", Some(WebSocketDeflateParameters::default()))] {
            let mut client =
                WebSocketConnection::new(WebSocketRole::Client, WebSocketConfig::default(), deflate, random()).unwrap();
            let mut server =
                WebSocketConnection::new(WebSocketRole::Server, WebSocketConfig::default(), deflate, random()).unwrap();
            let mut wire = Vec::new();
            bench.run(
                &format!("protocol-websocket-{name}-64KiB"),
                Some(Throughput::Bytes(message.len() as u64)),
                || {
                    client.send_binary(black_box(&message)).unwrap();
                    client.transmit(&mut wire);
                    server.receive(&wire);
                    wire.clear();
                    black_box(server.poll_event().unwrap());
                },
            );
        }
    }

    /// A message of 64 KiB through an SMTP client and server (MAIL, RCPT, DATA and its end),
    /// and the mail data read alone.
    #[cfg(umilib_feature = "protocol-smtp")]
    pub fn smtp(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::platform::bench::Throughput;
        use umilib::protocol::smtp::{
            SMTPClient, SMTPClientEvent, SMTPCommand, SMTPConfig, SMTPData, SMTPDataReader, SMTPReply, SMTPServer,
            SMTPServerConfig, SMTPServerEvent,
        };
        use umilib::runtime::Instant;
        let message: Vec<u8> = (0..64 * 1024u32)
            .map(|index| if index % 72 == 71 { b'\n' } else { b'a' + (index % 26) as u8 })
            .collect::<Vec<u8>>()
            .split(|byte| *byte == b'\n')
            .collect::<Vec<_>>()
            .join(&b"\r\n"[..]);
        let mut encoded = Vec::new();
        SMTPData::encode(&message, 1000, &mut encoded).unwrap();
        bench.run("protocol-smtp-data-read-64k", Some(Throughput::Bytes(message.len() as u64)), || {
            let mut reader = SMTPDataReader::new(u64::MAX, 1000);
            let mut out = Vec::with_capacity(message.len());
            black_box(reader.read(black_box(&encoded), &mut out));
        });
        let now = Instant::ZERO;
        let mut client = SMTPClient::new(SMTPConfig::default(), false, now).unwrap();
        let mut server = SMTPServer::new(SMTPConfig::default(), SMTPServerConfig::default(), false).unwrap();
        let mut wire = Vec::new();
        let exchange = |client: &mut SMTPClient, server: &mut SMTPServer, wire: &mut Vec<u8>| loop {
            wire.clear();
            client.transmit(wire);
            server.receive(wire, now);
            let sent = wire.len();
            wire.clear();
            server.transmit(wire);
            client.receive(wire, now).unwrap();
            if sent == 0 && wire.is_empty() {
                break;
            }
        };
        server.greet(server.greeting(), now).unwrap();
        exchange(&mut client, &mut server, &mut wire);
        client.send(SMTPCommand::Ehlo(String::from("client.test")), now).unwrap();
        exchange(&mut client, &mut server, &mut wire);
        while server.poll_event().is_some() {}
        server.reply(SMTPReply::new(250, "server.test"), now).unwrap();
        exchange(&mut client, &mut server, &mut wire);
        while client.poll_event().is_some() {}
        let mail = SMTPCommand::parse(b"MAIL FROM:<a@client.test>", false).unwrap();
        let rcpt = SMTPCommand::parse(b"RCPT TO:<b@server.test>", false).unwrap();
        bench.run("protocol-smtp-transaction-64k", Some(Throughput::Bytes(message.len() as u64)), || {
            for command in [mail.clone(), rcpt.clone(), SMTPCommand::Data] {
                client.send(command, now).unwrap();
                exchange(&mut client, &mut server, &mut wire);
                while let Some(event) = server.poll_event() {
                    if let SMTPServerEvent::Command(command) = event {
                        let code = if command == SMTPCommand::Data { 354 } else { 250 };
                        server.reply(SMTPReply::new(code, "OK"), now).unwrap();
                    }
                }
                exchange(&mut client, &mut server, &mut wire);
            }
            client.send_data(black_box(&message), now).unwrap();
            exchange(&mut client, &mut server, &mut wire);
            while let Some(event) = server.poll_event() {
                if let SMTPServerEvent::DataEnd { .. } = event {
                    server.reply(SMTPReply::new(250, "queued"), now).unwrap();
                }
            }
            exchange(&mut client, &mut server, &mut wire);
            while let Some(event) = client.poll_event() {
                black_box(matches!(event, SMTPClientEvent::DataReply(_)));
            }
        });
    }

    /// A message of 64 KiB sent by a POP3 server as the lines of RETR and read by a client.
    #[cfg(umilib_feature = "protocol-pop-v3")]
    pub fn pop_v3(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::platform::bench::Throughput;
        use umilib::protocol::pop::v3::{
            POP3Client, POP3Command, POP3Config, POP3Response, POP3Server, POP3ServerConfig, POP3ServerEvent,
        };
        use umilib::runtime::Instant;
        let now = Instant::ZERO;
        let message: Vec<u8> = (0..64 * 1024u32).map(|index| if index % 72 == 71 { b'\n' } else { b'.' }).collect();
        let settings = POP3ServerConfig { passwords_require_tls: false, ..POP3ServerConfig::default() };
        let mut server = POP3Server::new(POP3Config::default(), settings, false).unwrap();
        let client_config = POP3Config { passwords_require_tls: false, ..POP3Config::default() };
        let mut client = POP3Client::new(client_config, false, now).unwrap();
        let mut wire = Vec::new();
        let answer = |server: &mut POP3Server, data: Option<&[u8]>| {
            while let Some(event) = server.poll_event() {
                if let POP3ServerEvent::Command(_) = event {
                    server.reply(POP3Response::ok(""), now).unwrap();
                    if let Some(data) = data {
                        server.send_data(data).unwrap();
                        server.end_data(now).unwrap();
                    }
                }
            }
        };
        server.greet(POP3Response::ok("ready"), now).unwrap();
        server.transmit(&mut wire);
        client.receive(&wire, now).unwrap();
        for line in [&b"USER tim"[..], b"PASS tanstaaf"] {
            client.send(POP3Command::parse(line, false).unwrap(), now).unwrap();
            wire.clear();
            client.transmit(&mut wire);
            server.receive(&wire, now);
            answer(&mut server, None);
            wire.clear();
            server.transmit(&mut wire);
            client.receive(&wire, now).unwrap();
        }
        while client.poll_event().is_some() {}
        bench.run("protocol-pop-v3-retr-64k", Some(Throughput::Bytes(message.len() as u64)), || {
            client.send(POP3Command::Retr(1), now).unwrap();
            wire.clear();
            client.transmit(&mut wire);
            server.receive(&wire, now);
            answer(&mut server, Some(black_box(&message)));
            wire.clear();
            server.transmit(&mut wire);
            client.receive(&wire, now).unwrap();
            while let Some(event) = client.poll_event() {
                black_box(event);
            }
        });
    }

    /// An IMAP command and a FETCH response of an envelope and a body structure read and written,
    /// and the BODYSTRUCTURE of a multipart message made.
    #[cfg(umilib_feature = "protocol-imap-v4")]
    pub fn imap_v4(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::codec::mail::{MIMEEntity, MailConfig};
        use umilib::platform::bench::Throughput;
        use umilib::protocol::imap::v4::{IMAPBody, IMAPCommand, IMAPLiteralMode, IMAPResponse, IMAPWriter};
        let command =
            b"a003 UID FETCH 1:100,200:* (FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER.FIELDS (DATE FROM SUBJECT)])";
        bench.run("protocol-imap-v4-command-parse", Some(Throughput::Bytes(command.len() as u64)), || {
            black_box(IMAPCommand::parse(black_box(command), true, 32).unwrap());
        });
        let response = b"* 12 FETCH (FLAGS (\\Seen) INTERNALDATE \"17-Jul-1996 02:44:25 -0700\" RFC822.SIZE 4286 ENVELOPE (\"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)\" \"IMAP4rev2 WG mtg summary and minutes\" ((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) ((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) ((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) ((NIL NIL \"imap\" \"cac.washington.edu\")) ((NIL NIL \"minutes\" \"CNRI.Reston.VA.US\") (\"John Klensin\" NIL \"KLENSIN\" \"MIT.EDU\")) NIL NIL \"<B27397-0100000@cac.washington.edu>\") BODY (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 3028 92))";
        let parsed = IMAPResponse::parse(response, true, 32).unwrap();
        bench.run("protocol-imap-v4-fetch-response-parse", Some(Throughput::Bytes(response.len() as u64)), || {
            black_box(IMAPResponse::parse(black_box(response), true, 32).unwrap());
        });
        bench.run("protocol-imap-v4-fetch-response-write", Some(Throughput::Bytes(response.len() as u64)), || {
            let mut writer = IMAPWriter::new(IMAPLiteralMode::Server, true);
            black_box(&parsed).write(&mut writer);
            black_box(writer.out);
        });
        let mut message = b"Subject: x\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n".to_vec();
        for part in 0..16 {
            message.extend_from_slice(
                format!("--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\npart {part}\r\n").as_bytes(),
            );
        }
        message.extend_from_slice(b"--b--\r\n");
        let entity = MIMEEntity::decode(&message, &MailConfig::default()).unwrap();
        bench.run("protocol-imap-v4-bodystructure-16-parts", Some(Throughput::Elements(1)), || {
            black_box(IMAPBody::from_entity(black_box(&entity), &message, true));
        });
    }

    /// An FTP command read and written, a reply to FEAT read, and the facts of an MLSD line read.
    #[cfg(umilib_feature = "protocol-ftp")]
    pub fn ftp(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::platform::bench::Throughput;
        use umilib::protocol::ftp::{FTPCommand, FTPFacts, FTPReplyReader};
        let line = b"EPRT |2|1080::8:800:200C:417A|5282|";
        bench.run("protocol-ftp-command-parse-encode", Some(Throughput::Elements(1)), || {
            let command = FTPCommand::parse(black_box(line)).unwrap();
            let mut out = Vec::new();
            command.encode(&mut out).unwrap();
            black_box(out);
        });
        let feat: [&[u8]; 7] = [
            b"211-Features:",
            b" MDTM",
            b" SIZE",
            b" REST STREAM",
            b" MLST type*;size*;modify*;perm;unique;",
            b" UTF8",
            b"211 End",
        ];
        bench.run("protocol-ftp-reply-read-feat", Some(Throughput::Elements(1)), || {
            let mut reader = FTPReplyReader::new();
            for line in feat {
                black_box(reader.push(black_box(line), 64).unwrap());
            }
        });
        let facts = "type=file;size=1024990;modify=19980615100045.014;perm=adfr;unique=AQkAAAAAAAABCAAA; cap60.pcap";
        bench.run("protocol-ftp-facts-parse", Some(Throughput::Bytes(facts.len() as u64)), || {
            black_box(FTPFacts::parse(black_box(facts)).unwrap());
        });
    }

    /// A CoAP message read and written, and a Confirmable request answered
    /// in its ACK between two endpoints.
    #[cfg(umilib_feature = "protocol-coap")]
    pub fn coap(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::coap::{
            CoAPCode, CoAPConfig, CoAPEndpoint, CoAPEvent, CoAPMessage, CoAPOptionNumber, CoAPType,
        };
        use umilib::protocol::ip::IPEndpoint;
        use umilib::runtime::Instant;
        let mut message = CoAPMessage::new(CoAPType::Confirmable, CoAPCode::GET, 1);
        message.token = vec![1, 2, 3, 4];
        message.options.set_uri("/sensors/temperature/celsius", Some("unit=c"));
        message.options.set_uint(CoAPOptionNumber::ACCEPT, 50);
        let bytes = message.encode().unwrap();
        bench.run("protocol-coap-message-decode", Some(Throughput::Bytes(bytes.len() as u64)), || {
            black_box(CoAPMessage::decode(black_box(&bytes)).unwrap());
        });
        bench.run("protocol-coap-message-encode", Some(Throughput::Bytes(bytes.len() as u64)), || {
            black_box(black_box(&message).encode().unwrap());
        });
        let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"bench").unwrap();
        let mut client = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
        let mut server = CoAPEndpoint::new(CoAPConfig::default(), &mut random).unwrap();
        let (client_address, server_address) =
            (IPEndpoint::from_ascii(b"192.0.2.2:40000").unwrap(), IPEndpoint::from_ascii(b"192.0.2.1:5683").unwrap());
        let mut now = 0u64;
        bench.run("protocol-coap-exchange", Some(Throughput::Elements(1)), || {
            now += 1_000_000;
            let at = Instant::from_nanos(now);
            client.request(server_address, message.clone(), at, &mut random).unwrap();
            let request = client.transmit().unwrap();
            server.receive(client_address, &request.message, at, &mut random);
            let Some(CoAPEvent::Request { exchange, .. }) = server.poll_event() else { unreachable!() };
            server
                .respond(exchange, CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0), at, &mut random)
                .unwrap();
            let response = server.transmit().unwrap();
            client.receive(server_address, &response.message, at, &mut random);
            black_box(client.poll_event().unwrap());
        });
    }

    /// A DHCPv4 DISCOVER read and written, and answered by a server.
    #[cfg(umilib_feature = "protocol-dhcp-v4")]
    pub fn dhcp_v4(bench: &mut Bench) {
        use core::time::Duration;
        use std::hint::black_box;

        use umilib::platform::bench::Throughput;
        use umilib::protocol::dhcp::v4::{
            DHCPv4Message, DHCPv4MessageType, DHCPv4OptionCode, DHCPv4Options, DHCPv4Server, DHCPv4ServerConfig,
        };
        use umilib::protocol::ethernet::MACAddress;
        use umilib::protocol::ip::IPv4Address;
        use umilib::runtime::Instant;
        let mut message = DHCPv4Message::request(DHCPv4MessageType::DISCOVER, MACAddress([2, 0, 0, 0, 0, 1]), 7);
        message.options.set(DHCPv4OptionCode::PARAMETER_REQUEST_LIST, vec![1, 3, 6, 15, 26, 28, 119, 121]);
        let bytes = message.encode();
        bench.run("protocol-dhcp-v4-message-decode", Some(Throughput::Bytes(bytes.len() as u64)), || {
            black_box(DHCPv4Message::decode(black_box(&bytes)).unwrap());
        });
        bench.run("protocol-dhcp-v4-message-encode", Some(Throughput::Bytes(bytes.len() as u64)), || {
            black_box(black_box(&message).encode());
        });
        let mut options = DHCPv4Options::new();
        options.set_addresses(DHCPv4OptionCode::ROUTER, &[IPv4Address::new(192, 0, 2, 1)]);
        let mut server = DHCPv4Server::new(DHCPv4ServerConfig {
            address: IPv4Address::new(192, 0, 2, 1),
            first: IPv4Address::new(10, 0, 0, 0),
            last: IPv4Address::new(10, 0, 255, 255),
            reservations: Vec::new(),
            lease: Some(Duration::from_secs(3600)),
            offer_time: Duration::from_secs(60),
            decline_time: Duration::from_secs(600),
            options,
            authoritative: true,
        })
        .unwrap();
        bench.run("protocol-dhcp-v4-server-offer", Some(Throughput::Elements(1)), || {
            black_box(server.receive(black_box(&bytes), Instant::ZERO).unwrap());
        });
    }

    /// A DNS response read and written, a zone's lookup, and the answer of
    /// an authoritative server to a query's bytes.
    #[cfg(umilib_feature = "protocol-dns")]
    pub fn dns(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::platform::bench::Throughput;
        use umilib::protocol::dns::{
            DNSAuthority, DNSAuthorityConfig, DNSMessage, DNSName, DNSPeer, DNSQuestion, DNSRecord, DNSTransport,
            DNSType, DNSZone, DNSZoneFile,
        };
        use umilib::protocol::ip::IPEndpoint;
        let origin = DNSName::parse("example.", None).unwrap();
        let mut text = String::from("@ 3600 IN SOA ns admin 1 3600 600 86400 300\n@ NS ns\nns A 192.0.2.53\n");
        for index in 0..1000 {
            text.push_str(&format!(
                "host{index} 300 IN A 192.0.2.{}\nhost{index} 300 IN AAAA 2001:db8::{index:x}\n",
                index % 250
            ));
        }
        let records: Vec<DNSRecord> = DNSZoneFile::new(Some(origin.clone())).parse(&text).unwrap();
        bench.run("protocol-dns-zone-file-parse-2003", Some(Throughput::Bytes(text.len() as u64)), || {
            black_box(DNSZoneFile::new(Some(origin.clone())).parse(black_box(&text)).unwrap());
        });
        let zone = DNSZone::new(origin, records).unwrap();
        let name = DNSName::parse("host500.example.", None).unwrap();
        bench.run("protocol-dns-zone-lookup", Some(Throughput::Elements(1)), || {
            black_box(zone.lookup(black_box(&name), DNSType::A, false, false, 16));
        });
        let authority =
            DNSAuthority::new(vec![zone], DNSAuthorityConfig { minimal: false, ..DNSAuthorityConfig::default() });
        let query = DNSMessage::query(1, DNSQuestion::new(name, DNSType::A)).encode(512).unwrap();
        let peer =
            DNSPeer { endpoint: IPEndpoint::from_ascii(b"198.51.100.1:40000").unwrap(), transport: DNSTransport::UDP };
        let response = authority.respond(&query, &peer, 0).remove(0);
        bench.run("protocol-dns-authority-respond", Some(Throughput::Elements(1)), || {
            black_box(authority.respond(black_box(&query), &peer, 0));
        });
        bench.run("protocol-dns-message-decode", Some(Throughput::Bytes(response.len() as u64)), || {
            black_box(DNSMessage::decode(black_box(&response)).unwrap());
        });
        let message = DNSMessage::decode(&response).unwrap();
        bench.run("protocol-dns-message-encode", Some(Throughput::Bytes(response.len() as u64)), || {
            black_box(black_box(&message).encode(512).unwrap());
        });
    }

    /// The verification of an RRset's signature of each kind of key, and an NSEC3 hash.
    #[cfg(umilib_feature = "protocol-dns-dnssec")]
    pub fn dns_dnssec(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::dns::dnssec::{
            DNSSECAlgorithm, DNSSECKey, DNSSECPrivateKey, DNSSECSigner, DNSSECValidator,
        };
        use umilib::protocol::dns::{DNSData, DNSNSEC3, DNSName, DNSRecord};
        let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"bench").unwrap();
        let origin = DNSName::parse("example.", None).unwrap();
        let records =
            vec![DNSRecord::new(DNSName::parse("www.example.", None).unwrap(), 300, DNSData::A([192, 0, 2, 1].into()))];
        let validator = DNSSECValidator::default();
        for (algorithm, bits, label) in [
            (DNSSECAlgorithm::RSASHA256, 2048, "rsasha256-2048"),
            (DNSSECAlgorithm::ECDSAP256SHA256, 0, "ecdsap256sha256"),
            (DNSSECAlgorithm::ED25519, 0, "ed25519"),
        ] {
            let key = DNSSECPrivateKey::generate(algorithm, bits, &mut random).unwrap();
            let signer = DNSSECSigner::new(origin.clone(), DNSSECKey::ZONE, key);
            let signature = signer.sign(&records, 0, u32::MAX >> 1, &mut random).unwrap();
            let keys = vec![signer.dnskey(3600)];
            bench.run(&format!("protocol-dns-dnssec-verify-{label}"), Some(Throughput::Elements(1)), || {
                black_box(
                    validator.verify(black_box(&records), core::slice::from_ref(&signature), &keys, 1000).unwrap(),
                );
            });
        }
        let name = DNSName::parse("a.b.c.example.", None).unwrap();
        bench.run("protocol-dns-dnssec-nsec3-hash-0", Some(Throughput::Elements(1)), || {
            black_box(DNSNSEC3::digest(1, 0, &[], black_box(&name)));
        });
    }
}
