use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::time::Duration;

use crate::protocol::ethernet::MACAddress;
use crate::protocol::ip::IPv4Address;
use crate::runtime::Instant;

use super::super::DHCPError;
use super::{DHCPv4Message, DHCPv4MessageType, DHCPv4OptionCode, DHCPv4Options};

/// What a server leases and gives.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv4ServerConfig {
    /// The server's address: its server identifier (RFC 2132 §9.7).
    pub address: IPv4Address,
    /// The first and last addresses it leases.
    pub first: IPv4Address,
    pub last: IPv4Address,
    /// Addresses fixed for clients, by client key ([`DHCPv4Message::client_key`]).
    pub reservations: Vec<(Vec<u8>, IPv4Address)>,
    /// The lease time; None for infinity. T1 and T2 are half and seven
    /// eighths of it (RFC 2131 §4.4.5).
    pub lease: Option<Duration>,
    /// How long an offered address is kept for the client before it is
    /// free again (RFC 2131 §4.3.1: the server "should not" reuse it meanwhile).
    pub offer_time: Duration,
    /// How long a declined address is not leased (RFC 2131 §4.3.3).
    pub decline_time: Duration,
    /// The options given to every client (subnet mask, routers, DNS servers…), those it asks for first.
    pub options: DHCPv4Options,
    /// Whether the server is the only one of its network: it refuses (NAK)
    /// a REQUEST for an address it does not know (RFC 2131 §4.3.2).
    pub authoritative: bool,
}

impl DHCPv4ServerConfig {
    /// A server at `address` leasing `first` to `last` for a day, giving no options.
    pub fn new(address: IPv4Address, first: IPv4Address, last: IPv4Address) -> DHCPv4ServerConfig {
        DHCPv4ServerConfig {
            address,
            first,
            last,
            reservations: Vec::new(),
            lease: Some(Duration::from_secs(86_400)),
            offer_time: Duration::from_secs(60),
            decline_time: Duration::from_secs(3600),
            options: DHCPv4Options::new(),
            authoritative: false,
        }
    }
}

/// What a server knows of an address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DHCPv4BindingState {
    Offered,
    Bound,
    /// Declined by a client: in use by a host the server does not know.
    Declined,
}

/// An address given: to which client, how, and until when (None for ever).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv4Binding {
    pub client: Vec<u8>,
    pub state: DHCPv4BindingState,
    pub expires: Option<Instant>,
}

/// A reply for a server to send: to `destination` and `port`, and, for a
/// client without an address that did not ask for broadcast, to its
/// hardware address `link` without ARP (RFC 2131 §4.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv4Reply {
    pub destination: IPv4Address,
    pub port: u16,
    pub link: Option<MACAddress>,
    pub message: DHCPv4Message,
}

/// A DHCPv4 server (RFC 2131 §4.3), Sans-I/O: it answers each client
/// message with the reply of its rules, from the addresses of its pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DHCPv4Server {
    pub config: DHCPv4ServerConfig,
    pub bindings: BTreeMap<IPv4Address, DHCPv4Binding>,
}

impl DHCPv4Server {
    /// A server of `config`; fails for a pool whose first address is after its last.
    pub fn new(config: DHCPv4ServerConfig) -> Result<DHCPv4Server, DHCPError> {
        if u32::from_be_bytes(config.first.0) > u32::from_be_bytes(config.last.0) {
            return Err(DHCPError::Config);
        }
        Ok(DHCPv4Server { config, bindings: BTreeMap::new() })
    }

    /// Whether `address` is the server's to lease: of its pool or a reservation.
    pub fn owns(&self, address: IPv4Address) -> bool {
        let value = u32::from_be_bytes(address.0);
        let pool = u32::from_be_bytes(self.config.first.0)..=u32::from_be_bytes(self.config.last.0);
        pool.contains(&value) || self.config.reservations.iter().any(|(_, reserved)| *reserved == address)
    }

    /// Whether `address` may be given to `client` at `now`.
    pub fn is_free(&self, address: IPv4Address, client: &[u8], now: Instant) -> bool {
        if !self.owns(address) || address == self.config.address {
            return false;
        }
        let reserved = self.config.reservations.iter().find(|(_, reserved)| *reserved == address);
        if reserved.is_some_and(|(owner, _)| owner.as_slice() != client) {
            return false;
        }
        match self.bindings.get(&address) {
            None => true,
            Some(binding) => {
                binding.expires.is_some_and(|expires| now >= expires)
                    || (binding.client == client && binding.state != DHCPv4BindingState::Declined)
            }
        }
    }

    /// The address for `client` (RFC 2131 §4.3.1): its reservation, its
    /// current or last binding, the address it asks for, or the first free
    /// one; a reservation another host is found to use (declined) is not.
    pub fn choose(&self, client: &[u8], requested: Option<IPv4Address>, now: Instant) -> Option<IPv4Address> {
        let reserved = self.config.reservations.iter().find(|(owner, _)| owner.as_slice() == client);
        if let Some((_, reserved)) = reserved.filter(|(_, reserved)| self.is_free(*reserved, client, now)) {
            return Some(*reserved);
        }
        let own = self
            .bindings
            .iter()
            .find(|(_, binding)| binding.client == client && binding.state != DHCPv4BindingState::Declined);
        if let Some((address, _)) = own {
            return Some(*address);
        }
        if let Some(requested) = requested.filter(|requested| self.is_free(*requested, client, now)) {
            return Some(requested);
        }
        let (first, last) = (u32::from_be_bytes(self.config.first.0), u32::from_be_bytes(self.config.last.0));
        (first..=last).map(|value| IPv4Address(value.to_be_bytes())).find(|address| self.is_free(*address, client, now))
    }

    /// The reply to the message `bytes` from a client at `now`, if one is due.
    pub fn receive(&mut self, bytes: &[u8], now: Instant) -> Option<DHCPv4Reply> {
        let request = DHCPv4Message::decode(bytes).ok()?;
        if request.op != DHCPv4Message::BOOTREQUEST {
            return None;
        }
        let client = request.client_key();
        let server = request.options.address(DHCPv4OptionCode::SERVER_IDENTIFIER);
        let requested = request.options.address(DHCPv4OptionCode::REQUESTED_ADDRESS);
        match request.message_type()? {
            DHCPv4MessageType::DISCOVER => {
                let address = self.choose(&client, requested, now)?;
                // A lease the client holds stays bound; only a free address is held for the offer.
                let held = self.bindings.get(&address).is_some_and(|binding| {
                    binding.client == client
                        && binding.state == DHCPv4BindingState::Bound
                        && binding.expires.is_none_or(|expires| now < expires)
                });
                if !held {
                    let expires = Some(now.saturating_add(self.config.offer_time));
                    let binding = DHCPv4Binding { client: client.clone(), state: DHCPv4BindingState::Offered, expires };
                    self.bindings.insert(address, binding);
                }
                Some(self.reply(&request, DHCPv4MessageType::OFFER, address))
            }
            DHCPv4MessageType::REQUEST => {
                // RFC 2131 §4.3.2: SELECTING names a server; INIT-REBOOT asks
                // for an address; RENEWING and REBINDING have it in ciaddr.
                let address = match (server, requested) {
                    (Some(server), _) if server != self.config.address => {
                        // The client chose another server: what was offered is free again.
                        self.bindings.retain(|_, binding| {
                            !(binding.client == client && binding.state == DHCPv4BindingState::Offered)
                        });
                        return None;
                    }
                    (Some(_), Some(requested)) => requested,
                    // INIT-REBOOT (§4.3.2): an address of another network is refused below;
                    // of this one, a server with no record of the client MUST remain silent.
                    (None, Some(requested)) => {
                        let known = self.bindings.values().any(|binding| binding.client == client)
                            || self.config.reservations.iter().any(|(owner, _)| *owner == client);
                        if !known && self.owns(requested) {
                            return None;
                        }
                        requested
                    }
                    (None, None) if request.ciaddr != IPv4Address::UNSPECIFIED => request.ciaddr,
                    _ => return None,
                };
                if !self.owns(address) {
                    return self
                        .config
                        .authoritative
                        .then(|| self.reply(&request, DHCPv4MessageType::NAK, IPv4Address::UNSPECIFIED));
                }
                if !self.is_free(address, &client, now) || self.choose(&client, Some(address), now) != Some(address) {
                    return Some(self.reply(&request, DHCPv4MessageType::NAK, IPv4Address::UNSPECIFIED));
                }
                self.bindings.insert(
                    address,
                    DHCPv4Binding {
                        client,
                        state: DHCPv4BindingState::Bound,
                        expires: self.config.lease.map(|lease| now.saturating_add(lease)),
                    },
                );
                Some(self.reply(&request, DHCPv4MessageType::ACK, address))
            }
            DHCPv4MessageType::DECLINE => {
                // RFC 2131 §4.3.3: the address is in use; it is not leased for a while.
                let address = requested?;
                if self.bindings.get(&address).is_some_and(|binding| binding.client == client) {
                    self.bindings.insert(
                        address,
                        DHCPv4Binding {
                            client: Vec::new(),
                            state: DHCPv4BindingState::Declined,
                            expires: Some(now.saturating_add(self.config.decline_time)),
                        },
                    );
                }
                None
            }
            DHCPv4MessageType::RELEASE => {
                // RFC 2131 §4.3.4: the binding ends; the address is kept as the client's last.
                if let Some(binding) = self.bindings.get_mut(&request.ciaddr)
                    && binding.client == client
                {
                    binding.expires = Some(now);
                }
                None
            }
            // RFC 2131 §4.3.5: configuration only, to ciaddr (an INFORM without one is not); no lease.
            DHCPv4MessageType::INFORM if request.ciaddr != IPv4Address::UNSPECIFIED => {
                Some(self.reply(&request, DHCPv4MessageType::ACK, IPv4Address::UNSPECIFIED))
            }
            _ => None,
        }
    }

    /// The reply of `kind` to `request` giving `address` (RFC 2131 §4.3.1,
    /// table 3): the options the server gives, those the client asked for
    /// first; and where it goes (§4.1).
    pub fn reply(&self, request: &DHCPv4Message, kind: DHCPv4MessageType, address: IPv4Address) -> DHCPv4Reply {
        let mut reply = DHCPv4Message::reply(request, kind);
        reply.options.set_address(DHCPv4OptionCode::SERVER_IDENTIFIER, self.config.address);
        if kind != DHCPv4MessageType::NAK {
            reply.yiaddr = address;
            if kind != DHCPv4MessageType::ACK || address != IPv4Address::UNSPECIFIED {
                reply.options.set_time(DHCPv4OptionCode::LEASE_TIME, self.config.lease);
                reply.options.set_time(DHCPv4OptionCode::RENEWAL_TIME, self.config.lease.map(|lease| lease / 2));
                reply.options.set_time(DHCPv4OptionCode::REBINDING_TIME, self.config.lease.map(|lease| lease / 8 * 7));
            }
            let asked = request.options.get(DHCPv4OptionCode::PARAMETER_REQUEST_LIST).unwrap_or_default();
            let mut given: Vec<&(DHCPv4OptionCode, Vec<u8>)> = self.config.options.entries.iter().collect();
            given.sort_by_key(|(code, _)| asked.iter().position(|asked| *asked == code.0).unwrap_or(usize::MAX));
            for (code, data) in given {
                // RFC 8925 §3.3: option 108 only to a client that asks for it.
                if *code == DHCPv4OptionCode::IPV6_ONLY_PREFERRED && !asked.contains(&code.0) {
                    continue;
                }
                reply.options.set(*code, data.clone());
            }
        }
        let broadcast = IPv4Address::BROADCAST;
        let (destination, port, link) = if request.giaddr != IPv4Address::UNSPECIFIED {
            (request.giaddr, DHCPv4Message::SERVER_PORT, None)
        } else if kind == DHCPv4MessageType::NAK {
            (broadcast, DHCPv4Message::CLIENT_PORT, None)
        } else if request.ciaddr != IPv4Address::UNSPECIFIED {
            (request.ciaddr, DHCPv4Message::CLIENT_PORT, None)
        } else if request.is_broadcast() || request.hardware_length != 6 {
            (broadcast, DHCPv4Message::CLIENT_PORT, None)
        } else {
            let hardware: [u8; 6] = request.chaddr[..6].try_into().unwrap_or_default();
            (address, DHCPv4Message::CLIENT_PORT, Some(MACAddress(hardware)))
        };
        if request.giaddr != IPv4Address::UNSPECIFIED && kind == DHCPv4MessageType::NAK {
            reply.flags |= DHCPv4Message::BROADCAST;
        }
        DHCPv4Reply { destination, port, link, message: reply }
    }

    /// Forgets the bindings expired at `now`.
    pub fn expire(&mut self, now: Instant) {
        self.bindings.retain(|_, binding| {
            binding.expires.is_none_or(|expires| now < expires) || binding.state == DHCPv4BindingState::Bound
        });
    }
}
