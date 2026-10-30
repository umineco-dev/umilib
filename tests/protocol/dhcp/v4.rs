//! DHCPv4: the message and its options (RFC 2131 §2, RFC 2132, RFC 3396,
//! RFC 3442), and a client and a server of RFC 2131 §4 exchanging.

use core::time::Duration;

use umilib::protocol::dhcp::v4::{
    DHCPv4Client, DHCPv4ClientConfig, DHCPv4ClientEvent, DHCPv4ClientState, DHCPv4Message, DHCPv4MessageType,
    DHCPv4OptionCode, DHCPv4Options, DHCPv4Reply, DHCPv4Route, DHCPv4Server, DHCPv4ServerConfig,
};
use umilib::protocol::ethernet::MACAddress;
use umilib::protocol::ip::IPv4Address;

use super::{at, random};

const HARDWARE: MACAddress = MACAddress([0x02, 0, 0, 0, 0, 0x01]);
const SERVER: IPv4Address = IPv4Address([192, 0, 2, 1]);

fn server_config() -> DHCPv4ServerConfig {
    let mut options = DHCPv4Options::new();
    options.set_address(DHCPv4OptionCode::SUBNET_MASK, IPv4Address([255, 255, 255, 0]));
    options.set_addresses(DHCPv4OptionCode::ROUTER, &[SERVER]);
    options.set_addresses(DHCPv4OptionCode::DOMAIN_NAME_SERVER, &[IPv4Address([192, 0, 2, 53])]);
    DHCPv4ServerConfig {
        address: SERVER,
        first: IPv4Address([192, 0, 2, 100]),
        last: IPv4Address([192, 0, 2, 102]),
        reservations: Vec::new(),
        lease: Some(Duration::from_secs(3600)),
        offer_time: Duration::from_secs(60),
        decline_time: Duration::from_secs(600),
        options,
        authoritative: true,
    }
}

/// The client's next message, through the server: its reply if any.
fn exchange(client: &mut DHCPv4Client, server: &mut DHCPv4Server, now: u64) -> Option<DHCPv4Reply> {
    let transmission = client.transmit()?;
    let reply = server.receive(&transmission.message.encode(), at(now));
    if let Some(reply) = &reply {
        client.receive(&reply.message.encode(), at(now), &mut random(3));
    }
    reply
}

fn bound(client: &mut DHCPv4Client) -> Option<IPv4Address> {
    std::iter::from_fn(|| client.poll_event()).find_map(|event| match event {
        DHCPv4ClientEvent::Bound(lease) => Some(lease.address),
        _ => None,
    })
}

#[test]
fn the_message_of_rfc_2131() {
    let mut message = DHCPv4Message::request(DHCPv4MessageType::DISCOVER, HARDWARE, 0x1234_5678);
    message.options.set(DHCPv4OptionCode::HOST_NAME, b"host".to_vec());
    let bytes = message.encode();
    // §2: 236 bytes of header, the magic cookie, the options and END; padded to 300 (RFC 1542 §2.1).
    assert_eq!(bytes.len(), 300);
    assert_eq!((bytes[0], bytes[1], bytes[2]), (1, 1, 6));
    assert_eq!(bytes[4..8], [0x12, 0x34, 0x56, 0x78]);
    assert_eq!(bytes[28..34], HARDWARE.0);
    assert_eq!(bytes[236..240], [99, 130, 83, 99]);
    assert_eq!(bytes[240..243], [53, 1, 1]);
    assert_eq!(DHCPv4Message::decode(&bytes).unwrap(), message);
    // Without the cookie it is BOOTP; shorter than the header, nothing; an op of 3, neither.
    let mut bootp = bytes.clone();
    bootp[236] = 0;
    assert!(DHCPv4Message::decode(&bootp).is_err());
    assert!(DHCPv4Message::decode(&bytes[..239]).is_err());
    let mut op = bytes.clone();
    op[0] = 3;
    assert!(DHCPv4Message::decode(&op).is_err());
    // RFC 2132 §2: PAD alone, nothing read after END; an option cut short is an error.
    let mut padded = bytes[..240].to_vec();
    padded.extend_from_slice(&[0, 0, 53, 1, 3, 255, 12, 9]);
    assert_eq!(DHCPv4Message::decode(&padded).unwrap().message_type(), Some(DHCPv4MessageType::REQUEST));
    let mut cut = bytes[..240].to_vec();
    cut.extend_from_slice(&[12, 5, b'a']);
    assert!(DHCPv4Message::decode(&cut).is_err());
}

#[test]
fn long_options_and_overload() {
    // RFC 3396 §7: the parts of an option are one, in order, across the options, file and sname.
    let mut bytes = DHCPv4Message::default().encode()[..240].to_vec();
    bytes.extend_from_slice(&[52, 1, 3, 53, 1, 1, 12, 2, b'a', b'b', 255]);
    bytes.resize(300, 0);
    bytes[108..113].copy_from_slice(&[12, 2, b'c', b'd', 255]);
    bytes[44..49].copy_from_slice(&[12, 2, b'e', b'f', 255]);
    let message = DHCPv4Message::decode(&bytes).unwrap();
    assert_eq!(message.options.get(DHCPv4OptionCode::HOST_NAME), Some(&b"abcdef"[..]));
    assert!(message.file.iter().all(|byte| *byte == 0) && message.sname.iter().all(|byte| *byte == 0));
    // Without overload (its option made PAD), file and sname are not options.
    let overload = bytes[240..243].to_vec();
    bytes[240..243].copy_from_slice(&[0, 0, 0]);
    let message = DHCPv4Message::decode(&bytes).unwrap();
    assert_eq!(message.options.get(DHCPv4OptionCode::HOST_NAME), Some(&b"ab"[..]));
    // An overload of another value is malformed (RFC 2132 §9.3).
    bytes[240..243].copy_from_slice(&overload);
    bytes[242] = 4;
    assert!(DHCPv4Message::decode(&bytes).is_err());
    // RFC 3396 §6: an option longer than 255 bytes is written in parts.
    let mut long = DHCPv4Message::default();
    long.options.set(DHCPv4OptionCode::VENDOR_SPECIFIC, vec![7; 600]);
    let encoded = long.encode();
    assert_eq!((encoded[240], encoded[241], encoded[240 + 257], encoded[240 + 258]), (43, 255, 43, 255));
    assert_eq!(
        DHCPv4Message::decode(&encoded).unwrap().options.get(DHCPv4OptionCode::VENDOR_SPECIFIC).unwrap().len(),
        600
    );
}

#[test]
fn the_routes_of_rfc_3442() {
    // §2: the destination descriptors of its table.
    let router = IPv4Address([192, 0, 2, 1]);
    let examples: [([u8; 4], u8, &[u8]); 7] = [
        ([0, 0, 0, 0], 0, &[0]),
        ([10, 0, 0, 0], 8, &[8, 10]),
        ([10, 0, 0, 0], 24, &[24, 10, 0, 0]),
        ([10, 17, 0, 0], 16, &[16, 10, 17]),
        ([10, 27, 129, 0], 24, &[24, 10, 27, 129]),
        ([10, 229, 0, 128], 25, &[25, 10, 229, 0, 128]),
        ([10, 198, 122, 47], 32, &[32, 10, 198, 122, 47]),
    ];
    for (destination, prefix, descriptor) in examples {
        let route = DHCPv4Route { destination: IPv4Address(destination), prefix, router };
        let mut options = DHCPv4Options::new();
        options.set_routes(&[route]);
        assert_eq!(options.get(DHCPv4OptionCode::CLASSLESS_STATIC_ROUTE).unwrap(), [descriptor, &router.0].concat());
        assert_eq!(options.routes().unwrap(), [route]);
    }
    // The bits beyond the prefix are zeroed: 129.210.177.132/25 is 129.210.177.128.
    let mut options = DHCPv4Options::new();
    options.set(DHCPv4OptionCode::CLASSLESS_STATIC_ROUTE, vec![25, 129, 210, 177, 132, 192, 0, 2, 1]);
    assert_eq!(options.routes().unwrap()[0].destination, IPv4Address([129, 210, 177, 128]));
    for malformed in [vec![33, 1, 2, 3, 4, 5, 6, 7, 8], vec![24, 10, 0], vec![8, 10, 1, 2, 3]] {
        options.set(DHCPv4OptionCode::CLASSLESS_STATIC_ROUTE, malformed);
        assert!(options.routes().is_err());
    }
}

#[test]
fn a_lease_from_discovery_to_expiry() {
    let mut server = DHCPv4Server::new(server_config()).unwrap();
    let mut client = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(0));
    let mut random = random(1);
    client.start(None, at(0), &mut random).unwrap();
    // §4.4.1: DISCOVER broadcast; the OFFER unicast to the client's hardware address (§4.1).
    let offer = exchange(&mut client, &mut server, 0).unwrap();
    assert_eq!(offer.message.message_type(), Some(DHCPv4MessageType::OFFER));
    assert_eq!((offer.destination, offer.link), (IPv4Address([192, 0, 2, 100]), Some(HARDWARE)));
    assert_eq!(offer.message.options.address(DHCPv4OptionCode::SERVER_IDENTIFIER), Some(SERVER));
    // REQUEST of SELECTING: the server identifier and the address, ciaddr 0, broadcast.
    assert_eq!(client.state, DHCPv4ClientState::Requesting);
    let request = client.transmissions.front().unwrap().clone();
    assert_eq!(request.destination, IPv4Address::BROADCAST);
    assert_eq!(request.message.options.address(DHCPv4OptionCode::SERVER_IDENTIFIER), Some(SERVER));
    assert_eq!(
        request.message.options.address(DHCPv4OptionCode::REQUESTED_ADDRESS),
        Some(IPv4Address([192, 0, 2, 100]))
    );
    assert_eq!(request.message.ciaddr, IPv4Address::UNSPECIFIED);
    // §3.4: an INFORM meanwhile is an exchange of its own, leaving the REQUEST's.
    let (xid, started) = (client.xid, client.started);
    let inform = client.inform(IPv4Address([192, 0, 2, 50]), at(1), &mut random).unwrap();
    assert!(inform.message.xid != xid && inform.message.secs == 0);
    assert_eq!((client.xid, client.started, client.state), (xid, started, DHCPv4ClientState::Requesting));
    let ack = exchange(&mut client, &mut server, 1).unwrap();
    assert_eq!(ack.message.message_type(), Some(DHCPv4MessageType::ACK));
    assert_eq!(bound(&mut client), Some(IPv4Address([192, 0, 2, 100])));
    let lease = client.lease.clone().unwrap();
    // §4.4.5: T1 and T2 are half and seven eighths of the lease, from the request.
    assert_eq!(
        (lease.lease, lease.renewal, lease.rebinding),
        (Some(Duration::from_secs(3600)), Some(Duration::from_secs(1800)), Some(Duration::from_secs(3150)))
    );
    assert_eq!(client.poll_timeout(), Some(at(1800)));
    assert_eq!(lease.options.addresses(DHCPv4OptionCode::ROUTER), [SERVER]);
    // RENEWING at T1: unicast to the server, ciaddr the address, no server identifier.
    client.expire(at(1800), &mut random);
    assert_eq!(client.state, DHCPv4ClientState::Renewing);
    let renew = client.transmissions.front().unwrap().clone();
    assert_eq!((renew.destination, renew.message.ciaddr), (SERVER, IPv4Address([192, 0, 2, 100])));
    assert!(renew.message.options.get(DHCPv4OptionCode::SERVER_IDENTIFIER).is_none());
    assert!(renew.message.options.get(DHCPv4OptionCode::REQUESTED_ADDRESS).is_none());
    // Unanswered, it is sent again after half the time to T2, at least 60 s.
    client.transmit();
    assert_eq!(client.poll_timeout(), Some(at(1800 + 675)));
    // REBINDING at T2: broadcast.
    client.expire(at(2475), &mut random);
    client.transmit();
    client.expire(at(3150), &mut random);
    assert_eq!(client.state, DHCPv4ClientState::Rebinding);
    assert_eq!(client.transmissions.front().unwrap().destination, IPv4Address::BROADCAST);
    // The ACK of rebinding extends the lease.
    let reply = exchange(&mut client, &mut server, 3200).unwrap();
    assert_eq!(reply.message.message_type(), Some(DHCPv4MessageType::ACK));
    assert_eq!((reply.destination, reply.link), (IPv4Address([192, 0, 2, 100]), None));
    assert_eq!(client.state, DHCPv4ClientState::Bound);
    assert_eq!(bound(&mut client), Some(IPv4Address([192, 0, 2, 100])));
    // Without answers, the lease ends: told, and discovery again.
    client.expire(at(3200 + 1800), &mut random);
    for second in (3200 + 1800..3200 + 3600).step_by(30) {
        client.expire(at(second), &mut random);
    }
    client.expire(at(3200 + 3600), &mut random);
    let events: Vec<DHCPv4ClientEvent> = std::iter::from_fn(|| client.poll_event()).collect();
    assert!(events.contains(&DHCPv4ClientEvent::Expired), "{events:?}");
    assert_eq!(client.state, DHCPv4ClientState::Selecting);
}

#[test]
fn retransmissions_of_rfc_2131() {
    let mut client = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(0));
    let mut random = random(2);
    client.start(None, at(0), &mut random).unwrap();
    // §4.1: 4 s, then 8, 16, 32, 64, each a second more or less; then the exchange is given up.
    let mut now = at(0);
    let mut delays = Vec::new();
    while client.transmit().is_some() {
        let deadline = client.poll_timeout().unwrap();
        delays.push(deadline.saturating_duration_since(now).as_millis());
        now = deadline;
        client.expire(now, &mut random);
    }
    assert_eq!(delays.len(), 5);
    for (delay, base) in delays.iter().zip([4000, 8000, 16000, 32000, 64000]) {
        assert!((base - 1000..=base + 1000).contains(delay), "{delays:?}");
    }
    assert!(std::iter::from_fn(|| client.poll_event()).any(|event| event == DHCPv4ClientEvent::Unanswered));
    // The same xid throughout an exchange; secs counts from its start.
    let mut client = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(0));
    client.start(None, at(0), &mut random).unwrap();
    let first = client.transmit().unwrap().message;
    client.expire(client.poll_timeout().unwrap(), &mut random);
    let second = client.transmit().unwrap().message;
    assert_eq!(first.xid, second.xid);
    assert!(second.secs >= 3);
}

#[test]
fn refusals_and_the_states_of_rfc_2131() {
    let mut server = DHCPv4Server::new(server_config()).unwrap();
    let mut random = random(4);
    // INIT-REBOOT (§3.2): a REQUEST of the address alone; a foreign one is refused (NAK, broadcast).
    let mut client = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(0));
    client.start(Some(IPv4Address([198, 51, 100, 9])), at(0), &mut random).unwrap();
    let request = client.transmissions.front().unwrap().message.clone();
    assert!(request.options.get(DHCPv4OptionCode::SERVER_IDENTIFIER).is_none());
    let nak = exchange(&mut client, &mut server, 0).unwrap();
    assert_eq!((nak.message.message_type(), nak.destination), (Some(DHCPv4MessageType::NAK), IPv4Address::BROADCAST));
    assert!(std::iter::from_fn(|| client.poll_event()).any(|event| event == DHCPv4ClientEvent::Refused));
    assert_eq!(client.state, DHCPv4ClientState::Selecting);
    // A non-authoritative server is silent for an address it does not know.
    let mut quiet = DHCPv4Server::new(DHCPv4ServerConfig { authoritative: false, ..server_config() }).unwrap();
    let mut client = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(0));
    client.start(Some(IPv4Address([198, 51, 100, 9])), at(0), &mut random).unwrap();
    assert!(exchange(&mut client, &mut quiet, 0).is_none());
    // An address the client had is given again on INIT-REBOOT.
    let mut client = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(0));
    client.start(None, at(0), &mut random).unwrap();
    exchange(&mut client, &mut server, 0);
    exchange(&mut client, &mut server, 0);
    let address = bound(&mut client).unwrap();
    let mut again = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(10));
    again.start(Some(address), at(10), &mut random).unwrap();
    exchange(&mut again, &mut server, 10);
    assert_eq!(bound(&mut again), Some(address));
    // DECLINE (§4.4.1): the address is not leased for a while; the client discovers after ten seconds.
    again.decline(at(11), &mut random).unwrap();
    let decline = again.transmit().unwrap();
    assert_eq!(decline.message.options.address(DHCPv4OptionCode::REQUESTED_ADDRESS), Some(address));
    server.receive(&decline.message.encode(), at(11));
    assert_eq!(again.poll_timeout(), Some(at(21)));
    let other = MACAddress([0x02, 0, 0, 0, 0, 0x02]);
    let mut second = DHCPv4Client::new(DHCPv4ClientConfig::new(other), at(12));
    second.start(None, at(12), &mut random).unwrap();
    let offer = exchange(&mut second, &mut server, 12).unwrap();
    assert_ne!(offer.message.yiaddr, address);
    // RELEASE (§4.4.6): unicast to the server; the address is free again.
    exchange(&mut second, &mut server, 12);
    let released = bound(&mut second).unwrap();
    second.release(at(13)).unwrap();
    let release = second.transmit().unwrap();
    assert_eq!((release.destination, release.message.ciaddr), (SERVER, released));
    server.receive(&release.message.encode(), at(13));
    assert!(server.is_free(released, &[0, 1, 2, 0, 0, 0, 0, 9], at(14)));
    // The pool exhausted, no OFFER.
    let mut full =
        DHCPv4Server::new(DHCPv4ServerConfig { last: IPv4Address([192, 0, 2, 100]), ..server_config() }).unwrap();
    let mut first = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(0));
    first.start(None, at(0), &mut random).unwrap();
    assert!(exchange(&mut first, &mut full, 0).is_some());
    let mut late = DHCPv4Client::new(DHCPv4ClientConfig::new(other), at(0));
    late.start(None, at(0), &mut random).unwrap();
    assert!(exchange(&mut late, &mut full, 1).is_none());
    // Once the offer's hold passes, the address is offered to another.
    let mut later = DHCPv4Client::new(DHCPv4ClientConfig::new(other), at(100));
    later.start(None, at(100), &mut random).unwrap();
    assert!(exchange(&mut later, &mut full, 100).is_some());
}

#[test]
fn client_identifiers_of_rfc_4361_and_rfc_6842() {
    let mut server = DHCPv4Server::new(server_config()).unwrap();
    let mut random = random(5);
    let identifier = [
        &[255u8, 0, 0, 0, 1][..],
        &umilib::protocol::dhcp::DHCPDUID::LL { hardware: 1, address: HARDWARE.0.to_vec() }.encode().unwrap(),
    ]
    .concat();
    let config =
        DHCPv4ClientConfig { client_identifier: Some(identifier.clone()), ..DHCPv4ClientConfig::new(HARDWARE) };
    let mut client = DHCPv4Client::new(config, at(0));
    client.start(None, at(0), &mut random).unwrap();
    let offer = exchange(&mut client, &mut server, 0).unwrap();
    // RFC 6842 §3: the server echoes the client identifier.
    assert_eq!(offer.message.options.get(DHCPv4OptionCode::CLIENT_IDENTIFIER), Some(identifier.as_slice()));
    // The server knows the client by it, not by the hardware address.
    exchange(&mut client, &mut server, 0);
    assert!(server.bindings.values().any(|binding| binding.client == identifier));
    // A reply with another identifier is not the client's.
    let mut client = DHCPv4Client::new(
        DHCPv4ClientConfig { client_identifier: Some(identifier.clone()), ..DHCPv4ClientConfig::new(HARDWARE) },
        at(0),
    );
    client.start(None, at(0), &mut random).unwrap();
    let discover = client.transmit().unwrap().message;
    let mut forged = server.receive(&discover.encode(), at(1)).unwrap().message;
    forged.options.set(DHCPv4OptionCode::CLIENT_IDENTIFIER, vec![255, 9]);
    client.receive(&forged.encode(), at(1), &mut random);
    assert_eq!(client.state, DHCPv4ClientState::Selecting);
    // Nor a reply of another xid or hardware address.
    let mut other = server.receive(&discover.encode(), at(1)).unwrap().message;
    other.xid ^= 1;
    client.receive(&other.encode(), at(1), &mut random);
    assert_eq!(client.state, DHCPv4ClientState::Selecting);
}

#[test]
fn ipv6_only_of_rfc_8925() {
    let mut config = server_config();
    config.options.set_time(DHCPv4OptionCode::IPV6_ONLY_PREFERRED, Some(Duration::from_secs(60)));
    let mut server = DHCPv4Server::new(config).unwrap();
    let mut random = random(6);
    // §3.3: given only to a client that asks for it.
    let mut plain = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(0));
    plain.start(None, at(0), &mut random).unwrap();
    let offer = exchange(&mut plain, &mut server, 0).unwrap();
    assert!(offer.message.options.get(DHCPv4OptionCode::IPV6_ONLY_PREFERRED).is_none());
    // §3.2: a client that asks stops for the time, at least MIN_V6ONLY_WAIT.
    let mut client = DHCPv4Client::new(
        DHCPv4ClientConfig { ipv6_only: true, ..DHCPv4ClientConfig::new(MACAddress([2, 0, 0, 0, 0, 3])) },
        at(0),
    );
    client.start(None, at(0), &mut random).unwrap();
    let parameters = client
        .transmissions
        .front()
        .unwrap()
        .message
        .options
        .get(DHCPv4OptionCode::PARAMETER_REQUEST_LIST)
        .unwrap()
        .to_vec();
    assert!(parameters.contains(&108));
    exchange(&mut client, &mut server, 0);
    assert!(
        std::iter::from_fn(|| client.poll_event())
            .any(|event| event == DHCPv4ClientEvent::IPv6Only(Duration::from_secs(300)))
    );
    assert_eq!((client.state, client.poll_timeout()), (DHCPv4ClientState::Init, Some(at(300))));
    assert!(client.transmit().is_none());
}

#[test]
fn where_replies_go() {
    let mut server = DHCPv4Server::new(server_config()).unwrap();
    let discover = |change: &dyn Fn(&mut DHCPv4Message)| {
        let mut message = DHCPv4Message::request(DHCPv4MessageType::DISCOVER, HARDWARE, 7);
        change(&mut message);
        message.encode()
    };
    // §4.1: to a relay at giaddr, port 67; broadcast if asked; else unicast at the hardware address.
    let relayed = server.receive(&discover(&|message| message.giaddr = IPv4Address([198, 51, 100, 1])), at(0)).unwrap();
    assert_eq!((relayed.destination, relayed.port, relayed.link), (IPv4Address([198, 51, 100, 1]), 67, None));
    let broadcast = server.receive(&discover(&|message| message.flags = DHCPv4Message::BROADCAST), at(0)).unwrap();
    assert_eq!((broadcast.destination, broadcast.port), (IPv4Address::BROADCAST, 68));
    // §4.3.5: an INFORM is answered at its ciaddr, with no lease time and no yiaddr.
    let mut inform = DHCPv4Message::request(DHCPv4MessageType::INFORM, HARDWARE, 8);
    inform.ciaddr = IPv4Address([192, 0, 2, 50]);
    let reply = server.receive(&inform.encode(), at(0)).unwrap();
    assert_eq!(
        (reply.destination, reply.message.message_type()),
        (IPv4Address([192, 0, 2, 50]), Some(DHCPv4MessageType::ACK))
    );
    assert!(reply.message.options.get(DHCPv4OptionCode::LEASE_TIME).is_none());
    assert_eq!(reply.message.yiaddr, IPv4Address::UNSPECIFIED);
    // A reply is not answered; a REQUEST naming another server ends the offer.
    let mut reply = DHCPv4Message::reply(&inform, DHCPv4MessageType::ACK);
    reply.op = DHCPv4Message::BOOTREPLY;
    assert!(server.receive(&reply.encode(), at(0)).is_none());
    let offered = server.bindings.len();
    let mut elsewhere = DHCPv4Message::request(DHCPv4MessageType::REQUEST, HARDWARE, 7);
    elsewhere.options.set_address(DHCPv4OptionCode::SERVER_IDENTIFIER, IPv4Address([192, 0, 2, 9]));
    assert!(server.receive(&elsewhere.encode(), at(0)).is_none());
    assert!(server.bindings.len() < offered);
    // Reservations: the address fixed for the client.
    let key = [0u8, 1, 2, 0, 0, 0, 0, 1].to_vec();
    let reserved = IPv4Address([192, 0, 2, 200]);
    let mut server =
        DHCPv4Server::new(DHCPv4ServerConfig { reservations: vec![(key, reserved)], ..server_config() }).unwrap();
    assert_eq!(server.receive(&discover(&|_| {}), at(0)).unwrap().message.yiaddr, reserved);
}

#[test]
fn what_a_client_and_a_server_refuse() {
    let mut random = random(6);
    let six = DHCPv4ClientConfig { ipv6_only: true, ..DHCPv4ClientConfig::new(MACAddress([2, 0, 0, 0, 0, 6])) };
    // RFC 8925 §3.3: a server SHOULD offer 0.0.0.0 with option 108; the client stops (§3.2).
    let mut config = server_config();
    config.options.set_time(DHCPv4OptionCode::IPV6_ONLY_PREFERRED, Some(Duration::from_secs(600)));
    let mut server = DHCPv4Server::new(config).unwrap();
    let mut client = DHCPv4Client::new(six.clone(), at(0));
    client.start(None, at(0), &mut random).unwrap();
    let discover = client.transmit().unwrap();
    let mut offer = server.receive(&discover.message.encode(), at(0)).unwrap().message;
    offer.yiaddr = IPv4Address::UNSPECIFIED;
    client.receive(&offer.encode(), at(0), &mut random);
    assert!(
        std::iter::from_fn(|| client.poll_event())
            .any(|event| event == DHCPv4ClientEvent::IPv6Only(Duration::from_secs(600)))
    );
    // §3.2: an ACK with option 108 in REQUESTING leaves the address in use.
    let mut plain = DHCPv4Server::new(server_config()).unwrap();
    let mut client = DHCPv4Client::new(six, at(0));
    client.start(None, at(0), &mut random).unwrap();
    exchange(&mut client, &mut plain, 0);
    let request = client.transmit().unwrap();
    let mut ack = plain.receive(&request.message.encode(), at(0)).unwrap().message;
    ack.options.set_time(DHCPv4OptionCode::IPV6_ONLY_PREFERRED, Some(Duration::from_secs(600)));
    client.receive(&ack.encode(), at(0), &mut random);
    assert!(bound(&mut client).is_some());
    // RFC 2131 Table 3: an ACK without a lease time, which it MUST have, is not a lease.
    let mut server = DHCPv4Server::new(server_config()).unwrap();
    let mut client = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(0));
    client.start(None, at(0), &mut random).unwrap();
    exchange(&mut client, &mut server, 0);
    let request = client.transmit().unwrap();
    let mut ack = server.receive(&request.message.encode(), at(0)).unwrap().message;
    ack.options.set(DHCPv4OptionCode::LEASE_TIME, vec![0, 1]);
    client.receive(&ack.encode(), at(0), &mut random);
    assert!(bound(&mut client).is_none());
    assert_eq!(client.state, DHCPv4ClientState::Requesting);
    // §4.3.2: INIT-REBOOT of an address of this network by a client the server has no record of: silence.
    let mut stranger = DHCPv4Client::new(DHCPv4ClientConfig::new(MACAddress([2, 0, 0, 0, 0, 7])), at(0));
    stranger.start(Some(IPv4Address([192, 0, 2, 101])), at(0), &mut random).unwrap();
    assert!(exchange(&mut stranger, &mut server, 0).is_none());
    // A DISCOVER from a client of a lease keeps it bound.
    let mut client = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(0));
    client.start(None, at(0), &mut random).unwrap();
    exchange(&mut client, &mut server, 0);
    exchange(&mut client, &mut server, 0);
    let address = bound(&mut client).unwrap();
    let mut again = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(1));
    again.start(None, at(1), &mut random).unwrap();
    let offer = exchange(&mut again, &mut server, 1).unwrap();
    assert_eq!(offer.message.yiaddr, address);
    server.expire(at(120));
    assert_eq!(server.bindings[&address].state, umilib::protocol::dhcp::v4::DHCPv4BindingState::Bound);
    // §4.3.5: an INFORM without ciaddr is not answered.
    let inform = DHCPv4Message::request(DHCPv4MessageType::INFORM, HARDWARE, 9);
    assert!(server.receive(&inform.encode(), at(2)).is_none());
    // A lease of the longest duration does not overflow its T2.
    let config = DHCPv4ServerConfig { lease: Some(Duration::MAX), ..server_config() };
    let mut long = DHCPv4Server::new(config).unwrap();
    let mut client = DHCPv4Client::new(DHCPv4ClientConfig::new(HARDWARE), at(0));
    client.start(None, at(0), &mut random).unwrap();
    assert!(exchange(&mut client, &mut long, 0).is_some());
}
