//! DHCPv4 and DHCPv6 servers and clients over UDP sockets, to try umilib's
//! DHCP against other implementations (`examples/dhcp.sh` runs them in
//! Docker against ISC dhclient, BusyBox udhcpc and dnsmasq).
//!
//! ```text
//! dhcp server4 INTERFACE ADDRESS FIRST LAST [--router ADDRESS] [--dns ADDRESS] [--lease SECONDS]
//! dhcp client4 INTERFACE [--configure] [--release]
//! dhcp server6 INTERFACE FIRST LAST [--prefix PREFIX/LENGTH/DELEGATED] [--dns ADDRESS] [--rapid-commit]
//! dhcp client6 INTERFACE [--prefix LENGTH] [--no-addresses] [--rapid-commit] [--release]
//! ```
//!
//! A server serves the network of `INTERFACE` until it is stopped, and
//! prints `lease: ADDRESS` for each address it leases (`ADDRESS/LENGTH` for
//! a prefix). A DHCPv4 server sends to a client without an address by
//! broadcast (RFC 2131 §4.1), since a socket cannot write the client's
//! hardware address. A client prints `bound: ADDRESS` for each address and
//! prefix, and the options it got, one `option: NAME VALUE` a line (with
//! neither addresses nor prefixes, the configuration of an
//! Information-request), then with `--release` gives them back and prints
//! `released`. A DHCPv4 server prints `release: ADDRESS` for each RELEASE.
//! The DHCPv4 client sends from 0.0.0.0 and asks for broadcast replies;
//! with `--configure` it adds its address to the interface with ip(8), so
//! that its RELEASE goes to the server by unicast (RFC 2131 §4.4.6). Both
//! ends of DHCPv4 send to 255.255.255.255, for which their interfaces need a
//! route. The examples run on Linux, whose interfaces they read from
//! /sys/class/net.
#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::time::{Duration, Instant as Clock};

#[cfg(target_os = "linux")]
use umilib::platform::native::Random;
use umilib::protocol::dhcp::DHCPDUID;
use umilib::protocol::dhcp::v4::{
    DHCPv4Client, DHCPv4ClientConfig, DHCPv4ClientEvent, DHCPv4Message, DHCPv4MessageType, DHCPv4OptionCode,
    DHCPv4Server, DHCPv4ServerConfig,
};
use umilib::protocol::dhcp::v6::{
    DHCPv6Client, DHCPv6ClientConfig, DHCPv6ClientEvent, DHCPv6Message, DHCPv6OptionCode, DHCPv6Server,
    DHCPv6ServerConfig,
};
use umilib::protocol::ethernet::MACAddress;
use umilib::protocol::ip::{IPv4Address, IPv6Address};
use umilib::runtime::Instant;

/// The command line: positional arguments and `--name value` options.
pub struct Arguments {
    pub positional: Vec<String>,
    pub options: Vec<(String, Option<String>)>,
}

impl Arguments {
    /// The options that take no value.
    pub const FLAGS: [&'static str; 4] = ["--release", "--rapid-commit", "--no-addresses", "--configure"];

    pub fn parse() -> Arguments {
        let mut positional = Vec::new();
        let mut options = Vec::new();
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            if !argument.starts_with("--") {
                positional.push(argument);
            } else if Arguments::FLAGS.contains(&argument.as_str()) {
                options.push((argument, None));
            } else {
                let value = arguments.next().unwrap_or_else(|| Tool::fail(&format!("{argument} needs a value")));
                options.push((argument, Some(value)));
            }
        }
        Arguments { positional, options }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.options.iter().find(|(option, _)| option == name).and_then(|(_, value)| value.as_deref())
    }

    pub fn has(&self, name: &str) -> bool {
        self.options.iter().any(|(option, _)| option == name)
    }

    pub fn position(&self, index: usize, what: &str) -> &str {
        self.positional.get(index).map(String::as_str).unwrap_or_else(|| Tool::fail(what))
    }
}

/// The helpers of the tool.
pub struct Tool;

impl Tool {
    /// How long a client tries before it gives up.
    pub const BUDGET: Duration = Duration::from_secs(60);

    pub fn fail(message: &str) -> ! {
        eprintln!("error: {message}");
        std::process::exit(2)
    }

    /// The state machines' clock: nanoseconds since the tool started.
    pub fn now(start: Clock) -> Instant {
        Instant::from_nanos(start.elapsed().as_nanos() as u64)
    }

    /// How long to wait for a datagram before `deadline`, between 1 ms and 100 ms.
    pub fn wait(deadline: Option<Instant>, now: Instant) -> Duration {
        deadline
            .map_or(Duration::from_millis(100), |deadline| {
                Duration::from_nanos(deadline.as_nanos().saturating_sub(now.as_nanos()))
            })
            .clamp(Duration::from_millis(1), Duration::from_millis(100))
    }

    pub fn interface(name: &str, file: &str) -> String {
        let path = format!("/sys/class/net/{name}/{file}");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| Tool::fail(&format!("{path}: {error}")))
            .trim()
            .to_string()
    }

    pub fn hardware(interface: &str) -> MACAddress {
        let text = Tool::interface(interface, "address");
        let mut bytes = [0u8; 6];
        for (byte, part) in bytes.iter_mut().zip(text.split(':')) {
            *byte = u8::from_str_radix(part, 16).unwrap_or_else(|_| Tool::fail(&format!("a MAC address: {text}")));
        }
        MACAddress(bytes)
    }

    pub fn index(interface: &str) -> u32 {
        Tool::interface(interface, "ifindex").parse().unwrap_or_else(|_| Tool::fail("an interface index"))
    }

    pub fn v4(text: &str) -> IPv4Address {
        IPv4Address(
            text.parse::<Ipv4Addr>().unwrap_or_else(|_| Tool::fail(&format!("an IPv4 address: {text}"))).octets(),
        )
    }

    pub fn v6(text: &str) -> IPv6Address {
        IPv6Address(
            text.parse::<Ipv6Addr>().unwrap_or_else(|_| Tool::fail(&format!("an IPv6 address: {text}"))).octets(),
        )
    }

    pub fn bind(address: SocketAddr) -> UdpSocket {
        UdpSocket::bind(address).unwrap_or_else(|error| Tool::fail(&format!("bind {address}: {error}")))
    }
}

#[cfg(target_os = "linux")]
fn main() {
    let arguments = Arguments::parse();
    match arguments.positional.first().map(String::as_str) {
        Some("server4") => Server::v4(&arguments),
        Some("client4") => Client::v4(&arguments),
        Some("server6") => Server::v6(&arguments),
        Some("client6") => Client::v6(&arguments),
        _ => Tool::fail("usage: dhcp server4|client4|server6|client6 INTERFACE ..."),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    Tool::fail("the example runs on Linux");
}

/// The servers.
pub struct Server;

#[cfg(target_os = "linux")]
impl Server {
    pub fn v4(arguments: &Arguments) {
        let address = Tool::v4(arguments.position(2, "the server's address"));
        let mut config = DHCPv4ServerConfig::new(
            address,
            Tool::v4(arguments.position(3, "the first address")),
            Tool::v4(arguments.position(4, "the last address")),
        );
        config.options.set_address(DHCPv4OptionCode::SUBNET_MASK, IPv4Address([255, 255, 255, 0]));
        if let Some(router) = arguments.get("--router") {
            config.options.set_addresses(DHCPv4OptionCode::ROUTER, &[Tool::v4(router)]);
        }
        if let Some(dns) = arguments.get("--dns") {
            config.options.set_addresses(DHCPv4OptionCode::DOMAIN_NAME_SERVER, &[Tool::v4(dns)]);
        }
        if let Some(lease) = arguments.get("--lease") {
            config.lease = Some(Duration::from_secs(lease.parse().unwrap_or_else(|_| Tool::fail("a lease"))));
        }
        config.authoritative = true;
        let mut server = DHCPv4Server::new(config).unwrap_or_else(|error| Tool::fail(&format!("{error}")));
        let socket = Tool::bind(SocketAddr::from(([0, 0, 0, 0], DHCPv4Message::SERVER_PORT)));
        socket.set_broadcast(true).expect("broadcast");
        println!("listening: dhcpv4");
        let start = Clock::now();
        let mut buffer = vec![0u8; 65536];
        loop {
            let Ok((count, _)) = socket.recv_from(&mut buffer) else { continue };
            let now = Tool::now(start);
            server.expire(now);
            if let Ok(message) = DHCPv4Message::decode(&buffer[..count])
                && message.message_type() == Some(DHCPv4MessageType::RELEASE)
            {
                println!("release: {}", message.ciaddr);
            }
            let Some(reply) = server.receive(&buffer[..count], now) else { continue };
            if reply.message.message_type() == Some(DHCPv4MessageType::ACK) && reply.message.yiaddr.0 != [0; 4] {
                println!("lease: {}", reply.message.yiaddr);
            }
            // A client without an address is reached by broadcast: a socket cannot write its hardware address.
            let destination = match reply.link {
                Some(_) => Ipv4Addr::BROADCAST,
                None => Ipv4Addr::from(reply.destination.0),
            };
            let target = SocketAddr::from((destination, reply.port));
            if let Err(error) = socket.send_to(&reply.message.encode(), target) {
                eprintln!("send to {target}: {error}");
            }
        }
    }

    pub fn v6(arguments: &Arguments) {
        let interface = arguments.position(1, "the interface");
        let index = Tool::index(interface);
        let duid = DHCPDUID::LL { hardware: DHCPDUID::ETHERNET, address: Tool::hardware(interface).0.to_vec() };
        let mut config = DHCPv6ServerConfig::new(duid);
        config.addresses = Some((
            Tool::v6(arguments.position(2, "the first address")),
            Tool::v6(arguments.position(3, "the last address")),
        ));
        if let Some(prefix) = arguments.get("--prefix") {
            let parts: Vec<&str> = prefix.split('/').collect();
            let [address, length, delegated] = parts[..] else { Tool::fail("--prefix PREFIX/LENGTH/DELEGATED") };
            config.prefixes = Some((
                Tool::v6(address),
                length.parse().unwrap_or_else(|_| Tool::fail("a length")),
                delegated.parse().unwrap_or_else(|_| Tool::fail("a length")),
            ));
        }
        if let Some(dns) = arguments.get("--dns") {
            config.options.push(DHCPv6OptionCode::DNS_SERVERS, Tool::v6(dns).0.to_vec());
        }
        config.rapid_commit = arguments.has("--rapid-commit");
        let mut server = DHCPv6Server::new(config).unwrap_or_else(|error| Tool::fail(&format!("{error}")));
        let socket = Tool::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, DHCPv6Message::SERVER_PORT)));
        let group = Ipv6Addr::from(DHCPv6Message::ALL_RELAY_AGENTS_AND_SERVERS.0);
        socket.join_multicast_v6(&group, index).unwrap_or_else(|error| Tool::fail(&format!("join: {error}")));
        println!("listening: dhcpv6");
        let start = Clock::now();
        let mut buffer = vec![0u8; 65536];
        loop {
            let Ok((count, from)) = socket.recv_from(&mut buffer) else { continue };
            let now = Tool::now(start);
            server.expire(now);
            let Some(reply) = server.receive(&buffer[..count], now) else { continue };
            if let Ok(message) = DHCPv6Message::decode(&reply) {
                for ia in message.options.ias(DHCPv6OptionCode::IA_NA) {
                    for held in ia.addresses() {
                        println!("lease: {}", held.address);
                    }
                }
                for ia in message.options.ias(DHCPv6OptionCode::IA_PD) {
                    for prefix in ia.prefixes() {
                        println!("lease: {}/{}", prefix.prefix, prefix.length);
                    }
                }
            }
            // §18.3: the reply goes to the address and port the message came from.
            let _ = socket.send_to(&reply, from);
        }
    }
}

/// The clients.
pub struct Client;

#[cfg(target_os = "linux")]
impl Client {
    pub fn v4(arguments: &Arguments) {
        let interface = arguments.position(1, "the interface");
        let mut config = DHCPv4ClientConfig::new(Tool::hardware(interface));
        config.broadcast = true;
        let start = Clock::now();
        let mut client = DHCPv4Client::new(config, Tool::now(start));
        let socket = Tool::bind(SocketAddr::from(([0, 0, 0, 0], DHCPv4Message::CLIENT_PORT)));
        socket.set_broadcast(true).expect("broadcast");
        client.start(None, Tool::now(start), &mut Random).unwrap_or_else(|error| Tool::fail(&format!("{error}")));
        let mut buffer = vec![0u8; 65536];
        let deadline = Clock::now() + Tool::BUDGET;
        while Clock::now() < deadline {
            while let Some(transmission) = client.transmit() {
                let destination = Ipv4Addr::from(transmission.destination.0);
                let target = SocketAddr::from((destination, DHCPv4Message::SERVER_PORT));
                if let Err(error) = socket.send_to(&transmission.message.encode(), target) {
                    Tool::fail(&format!("send to {target}: {error}"));
                }
            }
            let now = Tool::now(start);
            socket.set_read_timeout(Some(Tool::wait(client.poll_timeout(), now))).expect("a timeout");
            if let Ok((count, _)) = socket.recv_from(&mut buffer) {
                client.receive(&buffer[..count], Tool::now(start), &mut Random);
            }
            let now = Tool::now(start);
            if client.poll_timeout().is_some_and(|timeout| timeout <= now) {
                client.expire(now, &mut Random);
            }
            while let Some(event) = client.poll_event() {
                match event {
                    DHCPv4ClientEvent::Bound(lease) => {
                        println!("bound: {}", lease.address);
                        println!("option: server {}", lease.server);
                        if let Some(time) = lease.lease {
                            println!("option: lease {}", time.as_secs());
                        }
                        for router in lease.options.addresses(DHCPv4OptionCode::ROUTER) {
                            println!("option: router {router}");
                        }
                        for server in lease.options.addresses(DHCPv4OptionCode::DOMAIN_NAME_SERVER) {
                            println!("option: dns {server}");
                        }
                        if let Some(mask) = lease.options.address(DHCPv4OptionCode::SUBNET_MASK) {
                            println!("option: mask {mask}");
                        }
                        if arguments.has("--configure") {
                            let mask =
                                lease.options.address(DHCPv4OptionCode::SUBNET_MASK).unwrap_or(IPv4Address([255; 4]));
                            let length = u32::from_be_bytes(mask.0).leading_ones();
                            Client::run(
                                "ip",
                                &["address", "add", &format!("{}/{length}", lease.address), "dev", interface],
                            );
                        }
                        if arguments.has("--release") {
                            client.release(Tool::now(start)).unwrap_or_else(|error| Tool::fail(&format!("{error}")));
                            while let Some(transmission) = client.transmit() {
                                let destination = Ipv4Addr::from(transmission.destination.0);
                                let target = SocketAddr::from((destination, DHCPv4Message::SERVER_PORT));
                                let _ = socket.send_to(&transmission.message.encode(), target);
                            }
                            println!("released");
                        }
                        return;
                    }
                    DHCPv4ClientEvent::Refused => println!("refused"),
                    other => println!("event: {other:?}"),
                }
            }
        }
        Tool::fail("no lease in time");
    }

    /// Runs `program` with `arguments`, failing if it fails.
    pub fn run(program: &str, arguments: &[&str]) {
        let status = std::process::Command::new(program).args(arguments).status();
        if !status.is_ok_and(|status| status.success()) {
            Tool::fail(&format!("{program} {}", arguments.join(" ")));
        }
    }

    pub fn v6(arguments: &Arguments) {
        let interface = arguments.position(1, "the interface");
        let index = Tool::index(interface);
        let duid = DHCPDUID::LL { hardware: DHCPDUID::ETHERNET, address: Tool::hardware(interface).0.to_vec() };
        let mut config = DHCPv6ClientConfig::new(duid, index);
        config.addresses = !arguments.has("--no-addresses");
        config.prefix = arguments.get("--prefix").map(|length| length.parse().ok());
        config.rapid_commit = arguments.has("--rapid-commit");
        let start = Clock::now();
        let mut client = DHCPv6Client::new(config, Tool::now(start));
        let socket = Tool::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, DHCPv6Message::CLIENT_PORT)));
        let group = Ipv6Addr::from(DHCPv6Message::ALL_RELAY_AGENTS_AND_SERVERS.0);
        let servers = SocketAddrV6::new(group, DHCPv6Message::SERVER_PORT, 0, index);
        client.start(Tool::now(start), &mut Random).unwrap_or_else(|error| Tool::fail(&format!("{error}")));
        let mut buffer = vec![0u8; 65536];
        let mut releasing = false;
        let deadline = Clock::now() + Tool::BUDGET;
        while Clock::now() < deadline {
            while let Some(message) = client.transmit() {
                let bytes = message.encode().unwrap_or_else(|error| Tool::fail(&format!("{error}")));
                if let Err(error) = socket.send_to(&bytes, servers) {
                    Tool::fail(&format!("send: {error}"));
                }
            }
            let now = Tool::now(start);
            socket.set_read_timeout(Some(Tool::wait(client.poll_timeout(), now))).expect("a timeout");
            if let Ok((count, _)) = socket.recv_from(&mut buffer) {
                client.receive(&buffer[..count], Tool::now(start), &mut Random);
            }
            let now = Tool::now(start);
            if client.poll_timeout().is_some_and(|timeout| timeout <= now) {
                client.expire(now, &mut Random);
            }
            while let Some(event) = client.poll_event() {
                match event {
                    DHCPv6ClientEvent::Bound(lease) => {
                        for held in lease.addresses() {
                            println!("bound: {}", held.address);
                        }
                        for prefix in lease.prefixes() {
                            println!("bound: {}/{}", prefix.prefix, prefix.length);
                        }
                        for server in lease.options.addresses(DHCPv6OptionCode::DNS_SERVERS) {
                            println!("option: dns {server}");
                        }
                        if !arguments.has("--release") {
                            return;
                        }
                        client
                            .release(Tool::now(start), &mut Random)
                            .unwrap_or_else(|error| Tool::fail(&format!("{error}")));
                        releasing = true;
                    }
                    DHCPv6ClientEvent::Informed(options) => {
                        println!("informed");
                        for server in options.addresses(DHCPv6OptionCode::DNS_SERVERS) {
                            println!("option: dns {server}");
                        }
                        return;
                    }
                    DHCPv6ClientEvent::Released if releasing => {
                        println!("released");
                        return;
                    }
                    other => println!("event: {other:?}"),
                }
            }
        }
        Tool::fail("no lease in time");
    }
}
