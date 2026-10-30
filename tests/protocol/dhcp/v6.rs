//! DHCPv6 (RFC 9915): its messages and options, the retransmissions of
//! §15, and a client and a server of §18 exchanging, directly and relayed.

use core::time::Duration;

use umilib::protocol::dhcp::DHCPDUID;
use umilib::protocol::dhcp::v6::{
    DHCPv6Client, DHCPv6ClientConfig, DHCPv6ClientEvent, DHCPv6ClientState, DHCPv6IA, DHCPv6IAAddress, DHCPv6IAPrefix,
    DHCPv6Message, DHCPv6MessageType, DHCPv6OptionCode, DHCPv6Options, DHCPv6RelayMessage, DHCPv6Retransmission,
    DHCPv6Server, DHCPv6ServerConfig, DHCPv6StatusCode,
};
use umilib::protocol::ip::IPv6Address;

use super::{at, at_millis, random};

fn address(last: u8) -> IPv6Address {
    let mut bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    bytes[15] = last;
    IPv6Address(bytes)
}

fn server_duid() -> DHCPDUID {
    DHCPDUID::LL { hardware: 1, address: vec![2, 0, 0, 0, 0, 0x53] }
}

fn client_duid(last: u8) -> DHCPDUID {
    DHCPDUID::LL { hardware: 1, address: vec![2, 0, 0, 0, 0, last] }
}

fn server_config() -> DHCPv6ServerConfig {
    let mut options = DHCPv6Options::new();
    options.push(DHCPv6OptionCode::DNS_SERVERS, address(53).0.to_vec());
    let mut prefix = [0u8; 16];
    prefix[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x10, 0]);
    DHCPv6ServerConfig {
        duid: server_duid(),
        addresses: Some((address(100), address(101))),
        prefixes: Some((IPv6Address(prefix), 48, 56)),
        preferred: 3000,
        valid: 4000,
        t1: 1000,
        t2: 1600,
        preference: 0,
        rapid_commit: false,
        options,
    }
}

/// The client's next message through the server: whether one was answered.
fn exchange(client: &mut DHCPv6Client, server: &mut DHCPv6Server, now: u64) -> bool {
    let Some(message) = client.transmit() else { return false };
    let Some(reply) = server.receive(&message.encode().unwrap(), at(now)) else { return false };
    client.receive(&reply, at(now), &mut random(9));
    true
}

fn bound(client: &mut DHCPv6Client) -> Option<Vec<IPv6Address>> {
    std::iter::from_fn(|| client.poll_event()).find_map(|event| match event {
        DHCPv6ClientEvent::Bound(lease) => Some(lease.addresses().iter().map(|address| address.address).collect()),
        _ => None,
    })
}

#[test]
fn the_messages_of_rfc_9915() {
    // §8: the type, 24 bits of transaction ID, then the options (§21.1).
    let mut message = DHCPv6Message::new(DHCPv6MessageType::SOLICIT, 0x0012_3456);
    message.options.push(DHCPv6OptionCode::CLIENT_ID, client_duid(1).encode().unwrap());
    message.options.push(DHCPv6OptionCode::ELAPSED_TIME, vec![0, 0]);
    let bytes = message.encode().unwrap();
    assert_eq!(bytes[..8], [1, 0x12, 0x34, 0x56, 0, 1, 0, 10]);
    assert_eq!(DHCPv6Message::decode(&bytes).unwrap(), message);
    assert!(DHCPv6Message::decode(&bytes[..3]).is_err());
    assert!(DHCPv6Message::decode(&bytes[..bytes.len() - 1]).is_err());
    // §9: relay messages, their hop count and addresses, and the relayed message.
    let mut relay = DHCPv6RelayMessage {
        kind: DHCPv6MessageType::RELAY_FORW,
        hops: 0,
        link: address(1),
        peer: address(2),
        options: DHCPv6Options::new(),
    };
    relay.options.push(DHCPv6OptionCode::RELAY_MSG, bytes.clone());
    let encoded = relay.encode().unwrap();
    assert_eq!((encoded[0], encoded[1], encoded.len()), (12, 0, 34 + 4 + bytes.len()));
    assert_eq!(DHCPv6RelayMessage::decode(&encoded).unwrap().relayed(), Some(bytes.as_slice()));
    assert!(DHCPv6Message::decode(&encoded).is_err() && DHCPv6RelayMessage::decode(&bytes).is_err());
    // Encoding refuses what decoding refuses: the other kind of message, 25 bits of transaction ID.
    assert!(DHCPv6Message { kind: DHCPv6MessageType::RELAY_FORW, ..message.clone() }.encode().is_err());
    assert!(DHCPv6Message { transaction: 0x0100_0000, ..message.clone() }.encode().is_err());
    assert!(DHCPv6RelayMessage { kind: DHCPv6MessageType::SOLICIT, ..relay.clone() }.encode().is_err());
    let prefix =
        DHCPv6IAPrefix { preferred: 1, valid: 2, length: 129, prefix: address(0), options: DHCPv6Options::new() };
    assert!(prefix.encode().is_err());
    assert!(DHCPv6IAPrefix { length: 128, ..prefix }.encode().is_ok());
    // §21.4, §21.6: an IA_NA and its address, and the status of §21.13.
    let mut ia = DHCPv6IA::new(DHCPv6OptionCode::IA_NA, 7);
    (ia.t1, ia.t2) = (100, 200);
    let held = DHCPv6IAAddress { address: address(9), preferred: 300, valid: 400, options: DHCPv6Options::new() };
    ia.options.push(DHCPv6OptionCode::IAADDR, held.encode().unwrap());
    ia.options.push(DHCPv6OptionCode::STATUS_CODE, DHCPv6StatusCode::new(DHCPv6StatusCode::SUCCESS, "ok").encode());
    let option = ia.encode().unwrap();
    assert_eq!(option.data[..12], [0, 0, 0, 7, 0, 0, 0, 100, 0, 0, 0, 200]);
    let decoded = DHCPv6IA::decode(DHCPv6OptionCode::IA_NA, &option.data).unwrap();
    assert_eq!((decoded.addresses(), decoded.options.status().unwrap().message), (vec![held], "ok".to_string()));
    assert!(DHCPv6IA::decode(DHCPv6OptionCode::IA_NA, &[0; 11]).is_err());
}

#[test]
fn retransmissions_of_section_15() {
    let mut random = random(1);
    for _ in 0..200 {
        // RT = IRT + RAND × IRT, RAND within ±0.1, and above 0 for Solicit (§18.2.1).
        let first = DHCPv6Retransmission::SOLICIT.first(&mut random).as_millis();
        assert!((1001..=1100).contains(&first), "{first}");
        let request = DHCPv6Retransmission::REQUEST.first(&mut random).as_millis();
        assert!((900..=1100).contains(&request));
        // RT = 2 × RTprev + RAND × RTprev; above MRT, MRT + RAND × MRT.
        let next = DHCPv6Retransmission::REQUEST.next(Duration::from_secs(4), &mut random).as_millis();
        assert!((7600..=8400).contains(&next), "{next}");
        let capped = DHCPv6Retransmission::REQUEST.next(Duration::from_secs(20), &mut random).as_millis();
        assert!((27_000..=33_000).contains(&capped), "{capped}");
    }
    // MRC and MRD end an exchange.
    assert!(!DHCPv6Retransmission::REQUEST.is_over(9, at(0), at(100)));
    assert!(DHCPv6Retransmission::REQUEST.is_over(10, at(0), at(0)));
    assert!(DHCPv6Retransmission::CONFIRM.is_over(1, at(0), at(10)));
    assert!(!DHCPv6Retransmission::SOLICIT.is_over(10_000, at(0), at(1_000_000)));
    // §21.9: hundredths of a second, at most 0xFFFF.
    assert_eq!(DHCPv6Retransmission::elapsed(at(0), at_millis(1234)), 123);
    assert_eq!(DHCPv6Retransmission::elapsed(at(0), at(1000)), 0xFFFF);
}

#[test]
fn addresses_and_prefixes_from_solicit_to_rebind() {
    let mut server = DHCPv6Server::new(server_config()).unwrap();
    let config = DHCPv6ClientConfig { prefix: Some(Some(56)), ..DHCPv6ClientConfig::new(client_duid(1), 1) };
    let mut client = DHCPv6Client::new(config, at(0));
    let mut random = random(2);
    client.start(at(0), &mut random).unwrap();
    // §18.2.1: the first Solicit after a random delay of up to a second.
    assert!(client.transmit().is_none());
    let delay = client.poll_timeout().unwrap();
    assert!(delay <= at(1));
    client.expire(delay, &mut random);
    let solicit = client.transmissions.front().unwrap().clone();
    assert_eq!(solicit.kind, DHCPv6MessageType::SOLICIT);
    assert!(
        solicit.options.contains(DHCPv6OptionCode::CLIENT_ID) && !solicit.options.contains(DHCPv6OptionCode::SERVER_ID)
    );
    assert_eq!(solicit.options.get(DHCPv6OptionCode::ELAPSED_TIME), Some(&[0u8, 0][..]));
    assert_eq!(
        (solicit.options.ias(DHCPv6OptionCode::IA_NA).len(), solicit.options.ias(DHCPv6OptionCode::IA_PD).len()),
        (1, 1)
    );
    // §18.2.9: an Advertise below preference 255 is kept until the first timeout passes.
    assert!(exchange(&mut client, &mut server, 1));
    assert_eq!(client.state, DHCPv6ClientState::Soliciting);
    client.expire(client.poll_timeout().unwrap(), &mut random);
    assert_eq!(client.state, DHCPv6ClientState::Requesting);
    let request = client.transmissions.front().unwrap().clone();
    assert_eq!(request.options.duid(DHCPv6OptionCode::SERVER_ID), Some(server_duid()));
    assert!(exchange(&mut client, &mut server, 2));
    assert_eq!(bound(&mut client), Some(vec![address(100)]));
    let lease = client.lease.clone().unwrap();
    assert_eq!(lease.prefixes()[0].length, 56);
    // T1 and T2 of the IAs; the lifetimes from the exchange's start.
    assert_eq!(
        (lease.renewal, lease.rebinding, lease.valid),
        (Some(Duration::from_secs(1000)), Some(Duration::from_secs(1600)), Some(Duration::from_secs(4000)))
    );
    // The options asked for (§21.7): DNS servers.
    assert_eq!(lease.options.addresses(DHCPv6OptionCode::DNS_SERVERS), [address(53)]);
    // Renew at T1, to the server; Rebind at T2, to any.
    let renew_at = lease.at(lease.renewal).unwrap();
    client.expire(renew_at, &mut random);
    let renew = client.transmit().unwrap();
    assert_eq!(renew.kind, DHCPv6MessageType::RENEW);
    assert_eq!(renew.options.duid(DHCPv6OptionCode::SERVER_ID), Some(server_duid()));
    let mut now = renew_at;
    while client.state == DHCPv6ClientState::Renewing {
        now = client.poll_timeout().unwrap();
        client.expire(now, &mut random);
        client.transmissions.clear();
    }
    assert_eq!(client.state, DHCPv6ClientState::Rebinding);
    assert!(now >= lease.at(lease.rebinding).unwrap());
    client.transmissions.clear();
    client.expire(client.poll_timeout().unwrap(), &mut random);
    let rebind = client.transmissions.front().unwrap().clone();
    assert_eq!(rebind.kind, DHCPv6MessageType::REBIND);
    assert!(!rebind.options.contains(DHCPv6OptionCode::SERVER_ID));
    assert!(exchange(&mut client, &mut server, 1700));
    assert_eq!(bound(&mut client), Some(vec![address(100)]));
}

#[test]
fn rapid_commit_preference_and_exhaustion() {
    let mut random = random(3);
    // §18.3.1: Rapid Commit on both ends, a Reply to the Solicit.
    let mut server = DHCPv6Server::new(DHCPv6ServerConfig { rapid_commit: true, ..server_config() }).unwrap();
    let mut client = DHCPv6Client::new(
        DHCPv6ClientConfig { rapid_commit: true, ..DHCPv6ClientConfig::new(client_duid(1), 1) },
        at(0),
    );
    client.start(at(0), &mut random).unwrap();
    client.expire(at(1), &mut random);
    assert!(exchange(&mut client, &mut server, 1));
    assert_eq!(bound(&mut client), Some(vec![address(100)]));
    // §18.2.9: preference 255, at once.
    let mut server = DHCPv6Server::new(DHCPv6ServerConfig { preference: 255, ..server_config() }).unwrap();
    let mut client = DHCPv6Client::new(DHCPv6ClientConfig::new(client_duid(1), 1), at(0));
    client.start(at(0), &mut random).unwrap();
    client.expire(at(1), &mut random);
    assert!(exchange(&mut client, &mut server, 1));
    assert_eq!(client.state, DHCPv6ClientState::Requesting);
    // An Advertise of no addresses (NoAddrsAvail) is ignored.
    let mut server = DHCPv6Server::new(DHCPv6ServerConfig {
        addresses: Some((address(100), address(100))),
        prefixes: None,
        ..server_config()
    })
    .unwrap();
    let mut first = DHCPv6Client::new(DHCPv6ClientConfig::new(client_duid(1), 1), at(0));
    first.start(at(0), &mut random).unwrap();
    first.expire(at(1), &mut random);
    exchange(&mut first, &mut server, 1);
    first.expire(first.poll_timeout().unwrap(), &mut random);
    exchange(&mut first, &mut server, 3);
    assert!(bound(&mut first).is_some());
    let mut second = DHCPv6Client::new(DHCPv6ClientConfig::new(client_duid(2), 1), at(0));
    second.start(at(0), &mut random).unwrap();
    second.expire(at(1), &mut random);
    let solicit = second.transmit().unwrap();
    let reply = DHCPv6Message::decode(&server.receive(&solicit.encode().unwrap(), at(2)).unwrap()).unwrap();
    let ia = &reply.options.ias(DHCPv6OptionCode::IA_NA)[0];
    assert_eq!(ia.options.status().unwrap().code, DHCPv6StatusCode::NO_ADDRS_AVAIL);
    second.receive(&reply.encode().unwrap(), at(2), &mut random);
    assert!(second.advertise.is_none());
}

#[test]
fn the_checks_of_section_16() {
    let mut server = DHCPv6Server::new(server_config()).unwrap();
    let message = |kind: DHCPv6MessageType, client: bool, server_id: Option<DHCPDUID>| {
        let mut message = DHCPv6Message::new(kind, 1);
        if client {
            message.options.push(DHCPv6OptionCode::CLIENT_ID, client_duid(1).encode().unwrap());
        }
        if let Some(server) = server_id {
            message.options.push(DHCPv6OptionCode::SERVER_ID, server.encode().unwrap());
        }
        message.encode().unwrap()
    };
    let other = client_duid(99);
    for (kind, client, server_id, answered) in [
        (DHCPv6MessageType::SOLICIT, true, None, true),
        (DHCPv6MessageType::SOLICIT, false, None, false),
        (DHCPv6MessageType::SOLICIT, true, Some(server_duid()), false),
        (DHCPv6MessageType::REQUEST, true, Some(server_duid()), true),
        (DHCPv6MessageType::REQUEST, true, Some(other.clone()), false),
        (DHCPv6MessageType::REQUEST, true, None, false),
        (DHCPv6MessageType::RENEW, true, Some(other.clone()), false),
        (DHCPv6MessageType::REBIND, true, Some(server_duid()), false),
        (DHCPv6MessageType::INFORMATION_REQUEST, false, None, true),
        (DHCPv6MessageType::INFORMATION_REQUEST, false, Some(other), false),
        (DHCPv6MessageType::ADVERTISE, true, Some(server_duid()), false),
        (DHCPv6MessageType::REPLY, true, Some(server_duid()), false),
    ] {
        assert_eq!(
            server.receive(&message(kind, client, server_id.clone()), at(0)).is_some(),
            answered,
            "{kind:?} {client} {server_id:?}"
        );
    }
    // A Renew of no binding: the IA's status is NoBinding (§18.3.4); the client then requests.
    let mut client = DHCPv6Client::new(DHCPv6ClientConfig::new(client_duid(1), 1), at(0));
    let mut random = random(4);
    client.start(at(0), &mut random).unwrap();
    client.expire(at(1), &mut random);
    exchange(&mut client, &mut server, 1);
    client.expire(client.poll_timeout().unwrap(), &mut random);
    exchange(&mut client, &mut server, 2);
    bound(&mut client).unwrap();
    let mut forgetful = DHCPv6Server::new(server_config()).unwrap();
    let lease = client.lease.clone().unwrap();
    client.expire(lease.at(lease.renewal).unwrap(), &mut random);
    let renew = client.transmit().unwrap();
    let reply = DHCPv6Message::decode(&forgetful.receive(&renew.encode().unwrap(), at(1000)).unwrap()).unwrap();
    assert_eq!(
        reply.options.ias(DHCPv6OptionCode::IA_NA)[0].options.status().unwrap().code,
        DHCPv6StatusCode::NO_BINDING
    );
    client.receive(&reply.encode().unwrap(), at(1000), &mut random);
    assert_eq!(client.state, DHCPv6ClientState::Requesting);
    assert!(exchange(&mut client, &mut forgetful, 1001));
    assert!(bound(&mut client).is_some());
}

#[test]
fn release_decline_confirm_and_information() {
    let mut server = DHCPv6Server::new(server_config()).unwrap();
    let mut random = random(5);
    let mut client = DHCPv6Client::new(DHCPv6ClientConfig::new(client_duid(1), 1), at(0));
    client.start(at(0), &mut random).unwrap();
    client.expire(at(1), &mut random);
    exchange(&mut client, &mut server, 1);
    client.expire(client.poll_timeout().unwrap(), &mut random);
    exchange(&mut client, &mut server, 2);
    let held = bound(&mut client).unwrap()[0];
    // §18.2.3: Confirm after a link change; on the link, the lease is kept.
    client.confirm(at(10), &mut random).unwrap();
    client.expire(client.poll_timeout().unwrap(), &mut random);
    let confirm = client.transmissions.front().unwrap().clone();
    assert!(!confirm.options.contains(DHCPv6OptionCode::SERVER_ID));
    assert_eq!(confirm.options.ias(DHCPv6OptionCode::IA_NA)[0].t1, 0);
    exchange(&mut client, &mut server, 11);
    assert_eq!(client.state, DHCPv6ClientState::Bound);
    // Off the link, NotOnLink: the client solicits again.
    let mut elsewhere =
        DHCPv6Server::new(DHCPv6ServerConfig { addresses: Some((address(200), address(201))), ..server_config() })
            .unwrap();
    let mut moved = client.clone();
    moved.confirm(at(20), &mut random).unwrap();
    moved.expire(moved.poll_timeout().unwrap(), &mut random);
    exchange(&mut moved, &mut elsewhere, 21);
    assert_eq!(moved.state, DHCPv6ClientState::Soliciting);
    // §18.2.8: Decline of an address DAD found in use; the server leases it no more.
    let mut declining = client.clone();
    declining.decline(vec![held], at(30), &mut random).unwrap();
    let decline = declining.transmissions.front().unwrap().clone();
    assert_eq!(decline.kind, DHCPv6MessageType::DECLINE);
    exchange(&mut declining, &mut server, 30);
    assert!(std::iter::from_fn(|| declining.poll_event()).any(|event| event == DHCPv6ClientEvent::Released));
    let other = DHCPv6IA::new(DHCPv6OptionCode::IA_NA, 9);
    assert!(server.is_taken(&held, None, &client_duid(5).encode().unwrap(), &other, at(31)));
    // §18.2.7: Release; the server frees the address.
    let mut releasing = client.clone();
    let mut fresh = DHCPv6Server::new(server_config()).unwrap();
    fresh.bindings = server
        .bindings
        .iter()
        .filter(|(_, binding)| !binding.declined)
        .map(|(key, binding)| (*key, binding.clone()))
        .collect();
    let mut rebound = DHCPv6Client::new(DHCPv6ClientConfig::new(client_duid(1), 1), at(0));
    rebound.start(at(0), &mut random).unwrap();
    rebound.expire(at(1), &mut random);
    exchange(&mut rebound, &mut fresh, 1);
    rebound.expire(rebound.poll_timeout().unwrap(), &mut random);
    exchange(&mut rebound, &mut fresh, 2);
    let released = bound(&mut rebound).unwrap()[0];
    releasing.lease = rebound.lease.clone();
    releasing.release(at(40), &mut random).unwrap();
    exchange(&mut releasing, &mut fresh, 40);
    assert_eq!(releasing.state, DHCPv6ClientState::Init);
    assert!(!fresh.is_taken(&released, None, &client_duid(7).encode().unwrap(), &other, at(41)));
    // §18.2.6: stateless configuration, refreshed after its refresh time, at least IRT_MINIMUM.
    let config = DHCPv6ClientConfig { addresses: false, prefix: None, ..DHCPv6ClientConfig::new(client_duid(3), 1) };
    let mut stateless = DHCPv6Client::new(config, at(0));
    stateless.start(at(0), &mut random).unwrap();
    stateless.expire(at(1), &mut random);
    let request = stateless.transmissions.front().unwrap().clone();
    assert_eq!(request.kind, DHCPv6MessageType::INFORMATION_REQUEST);
    assert!(request.options.ias(DHCPv6OptionCode::IA_NA).is_empty());
    exchange(&mut stateless, &mut server, 1);
    let informed = std::iter::from_fn(|| stateless.poll_event()).find_map(|event| match event {
        DHCPv6ClientEvent::Informed(options) => Some(options),
        _ => None,
    });
    assert_eq!(informed.unwrap().addresses(DHCPv6OptionCode::DNS_SERVERS), [address(53)]);
    assert_eq!(stateless.poll_timeout(), Some(at(1 + 86_400)));
}

#[test]
fn relayed_messages_of_section_19() {
    let mut server = DHCPv6Server::new(server_config()).unwrap();
    let mut solicit = DHCPv6Message::new(DHCPv6MessageType::SOLICIT, 5);
    solicit.options.push(DHCPv6OptionCode::CLIENT_ID, client_duid(1).encode().unwrap());
    solicit.options.entries.push(DHCPv6IA::new(DHCPv6OptionCode::IA_NA, 1).encode().unwrap());
    let mut inner = DHCPv6RelayMessage {
        kind: DHCPv6MessageType::RELAY_FORW,
        hops: 0,
        link: address(1),
        peer: address(2),
        options: DHCPv6Options::new(),
    };
    inner.options.push(DHCPv6OptionCode::INTERFACE_ID, b"eth1".to_vec());
    inner.options.push(DHCPv6OptionCode::RELAY_MSG, solicit.encode().unwrap());
    let mut outer = DHCPv6RelayMessage { hops: 1, link: address(3), ..inner.clone() };
    outer.options = DHCPv6Options::new();
    outer.options.push(DHCPv6OptionCode::RELAY_MSG, inner.encode().unwrap());
    // §19.3: the reply in Relay-reply messages of the same addresses, the Interface-Id echoed, nested.
    let reply = DHCPv6RelayMessage::decode(&server.receive(&outer.encode().unwrap(), at(0)).unwrap()).unwrap();
    assert_eq!(
        (reply.kind, reply.hops, reply.link, reply.peer),
        (DHCPv6MessageType::RELAY_REPL, 1, address(3), address(2))
    );
    let nested = DHCPv6RelayMessage::decode(reply.relayed().unwrap()).unwrap();
    assert_eq!(
        (nested.hops, nested.link, nested.options.get(DHCPv6OptionCode::INTERFACE_ID)),
        (0, address(1), Some(&b"eth1"[..]))
    );
    let advertise = DHCPv6Message::decode(nested.relayed().unwrap()).unwrap();
    assert_eq!((advertise.kind, advertise.transaction), (DHCPv6MessageType::ADVERTISE, 5));
    // §7.6: a message passes at most HOP_COUNT_LIMIT (8) relays; more nested ones are not answered.
    let nest = |levels: u8| {
        let mut bytes = solicit.encode().unwrap();
        for hops in 0..levels {
            let mut relay = DHCPv6RelayMessage { hops, options: DHCPv6Options::new(), ..inner.clone() };
            relay.options.push(DHCPv6OptionCode::RELAY_MSG, bytes);
            bytes = relay.encode().unwrap();
        }
        bytes
    };
    assert!(server.receive(&nest(DHCPv6RelayMessage::HOP_COUNT_LIMIT), at(0)).is_some());
    assert!(server.receive(&nest(DHCPv6RelayMessage::HOP_COUNT_LIMIT + 1), at(0)).is_none());
    assert!(server.receive(&nest(200), at(0)).is_none());
}

#[test]
fn identity_associations_of_section_12() {
    // §12, §21.4: each IA of a client has addresses of its own, in an Advertise as in a Reply.
    let mut server = DHCPv6Server::new(server_config()).unwrap();
    let client = client_duid(3).encode().unwrap();
    for kind in [DHCPv6MessageType::SOLICIT, DHCPv6MessageType::REQUEST] {
        let mut message = DHCPv6Message::new(kind, 7);
        message.options.push(DHCPv6OptionCode::CLIENT_ID, client.clone());
        if kind == DHCPv6MessageType::REQUEST {
            message.options.push(DHCPv6OptionCode::SERVER_ID, server_duid().encode().unwrap());
        }
        for iaid in [1, 2] {
            message.options.entries.push(DHCPv6IA::new(DHCPv6OptionCode::IA_NA, iaid).encode().unwrap());
        }
        let reply = DHCPv6Message::decode(&server.receive(&message.encode().unwrap(), at(0)).unwrap()).unwrap();
        let addresses: Vec<IPv6Address> = reply
            .options
            .ias(DHCPv6OptionCode::IA_NA)
            .iter()
            .flat_map(|ia| ia.addresses().into_iter().map(|held| held.address))
            .collect();
        assert_eq!(addresses.len(), 2, "{kind:?}");
        assert_ne!(addresses[0], addresses[1], "{kind:?}");
    }
    assert_eq!(server.bindings.len(), 2);
    // §16.12: an Information-request with an IA is discarded.
    let mut information = DHCPv6Message::new(DHCPv6MessageType::INFORMATION_REQUEST, 8);
    information.options.push(DHCPv6OptionCode::CLIENT_ID, client.clone());
    assert!(server.receive(&information.encode().unwrap(), at(1)).is_some());
    information.options.entries.push(DHCPv6IA::new(DHCPv6OptionCode::IA_NA, 1).encode().unwrap());
    assert!(server.receive(&information.encode().unwrap(), at(1)).is_none());
    // A delegation of prefixes of length 0 is no configuration.
    let config = DHCPv6ServerConfig { prefixes: Some((IPv6Address([0; 16]), 0, 0)), ..server_config() };
    assert!(DHCPv6Server::new(config).is_err());
}

/// A client bound through `server`, of addresses and a prefix.
fn bound_client(server: &mut DHCPv6Server) -> DHCPv6Client {
    let config = DHCPv6ClientConfig { prefix: Some(Some(56)), ..DHCPv6ClientConfig::new(client_duid(1), 1) };
    let mut client = DHCPv6Client::new(config, at(0));
    let mut random = random(2);
    client.start(at(0), &mut random).unwrap();
    client.expire(client.poll_timeout().unwrap(), &mut random);
    exchange(&mut client, server, 1);
    client.expire(client.poll_timeout().unwrap(), &mut random);
    exchange(&mut client, server, 2);
    assert_eq!(client.state, DHCPv6ClientState::Bound);
    client
}

/// The Reply to the client's next message, of the IAs `ias`.
fn reply_of(client: &mut DHCPv6Client, ias: &[DHCPv6IA]) -> Vec<u8> {
    let message = client.transmit().unwrap();
    let mut reply = DHCPv6Message::new(DHCPv6MessageType::REPLY, message.transaction);
    reply.options.push(DHCPv6OptionCode::SERVER_ID, server_duid().encode().unwrap());
    reply.options.push(DHCPv6OptionCode::CLIENT_ID, client_duid(1).encode().unwrap());
    for ia in ias {
        reply.options.entries.push(ia.encode().unwrap());
    }
    reply.encode().unwrap()
}

fn ia_of(t1: u32, t2: u32, held: &[(u8, u32, u32)]) -> DHCPv6IA {
    let mut ia = DHCPv6IA::new(DHCPv6OptionCode::IA_NA, 1);
    (ia.t1, ia.t2) = (t1, t2);
    for (last, preferred, valid) in held {
        let address = DHCPv6IAAddress {
            address: address(*last),
            preferred: *preferred,
            valid: *valid,
            options: DHCPv6Options::new(),
        };
        ia.options.push(DHCPv6OptionCode::IAADDR, address.encode().unwrap());
    }
    ia
}

#[test]
fn what_a_client_keeps_of_a_reply() {
    let mut random = random(4);
    let mut server = DHCPv6Server::new(server_config()).unwrap();
    // §21.4 with §14.2: T1 and T2 of 0 come from the least preferred lifetime that is not 0,
    // so a deprecated address does not make the client renew at once.
    let mut client = bound_client(&mut server);
    client.expire(client.poll_timeout().unwrap(), &mut random);
    assert_eq!(client.state, DHCPv6ClientState::Renewing);
    let renewed = client.started;
    let reply = reply_of(&mut client, &[ia_of(0, 0, &[(100, 3600, 7200), (101, 0, 600)])]);
    client.receive(&reply, renewed, &mut random);
    let lease = client.lease.clone().unwrap();
    assert_eq!((lease.renewal, lease.rebinding), (Some(Duration::from_secs(1800)), Some(Duration::from_secs(2880))));
    assert!(client.poll_timeout().unwrap() > renewed);
    // §18.2.10.1: the prefix the Reply to Renew did not name is kept, aged since it was bound.
    assert_eq!(lease.prefixes().len(), 1);
    assert!(lease.prefixes()[0].valid < 4000);
    // §21.6: an address of a preferred lifetime above its valid one is discarded;
    // §21.4: an IA of T1 above T2 is discarded.
    let mut client = bound_client(&mut server);
    client.expire(client.poll_timeout().unwrap(), &mut random);
    let reply = reply_of(&mut client, &[ia_of(100, 200, &[(100, 3600, 7200), (102, 9000, 600)])]);
    client.receive(&reply, client.started, &mut random);
    let addresses: Vec<IPv6Address> =
        client.lease.as_ref().unwrap().addresses().iter().map(|held| held.address).collect();
    assert_eq!(addresses, [address(100)]);
    let mut client = bound_client(&mut server);
    let before = client.lease.clone();
    client.expire(client.poll_timeout().unwrap(), &mut random);
    let reply = reply_of(&mut client, &[ia_of(5000, 100, &[(100, 3600, 7200)])]);
    client.receive(&reply, client.started, &mut random);
    assert_eq!(client.lease.as_ref().unwrap().ias.len(), before.unwrap().ias.len());
}
