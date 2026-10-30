use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::time::Duration;

use crate::protocol::ip::IPv6Address;
use crate::runtime::Instant;

use super::super::{DHCPDUID, DHCPError};
use super::{
    DHCPv6IA, DHCPv6IAAddress, DHCPv6IAPrefix, DHCPv6Message, DHCPv6MessageType, DHCPv6OptionCode, DHCPv6Options,
    DHCPv6RelayMessage, DHCPv6StatusCode,
};

/// What a server leases and gives.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv6ServerConfig {
    pub duid: DHCPDUID,
    /// The first and last addresses it leases in IA_NA.
    pub addresses: Option<(IPv6Address, IPv6Address)>,
    /// The prefix it delegates from, its length, and the length of each delegated prefix (IA_PD).
    pub prefixes: Option<(IPv6Address, u8, u8)>,
    /// The lifetimes it gives, in seconds (0xFFFFFFFF for infinity), and T1
    /// and T2 (0: half and four fifths of the preferred lifetime, RFC 9915 §21.4).
    pub preferred: u32,
    pub valid: u32,
    pub t1: u32,
    pub t2: u32,
    /// The preference of its Advertise messages (§21.8).
    pub preference: u8,
    /// Answers a Solicit with Rapid Commit with a Reply (§18.3.1).
    pub rapid_commit: bool,
    /// The options it gives (DNS servers, domains…), each to a client that asks for it.
    pub options: DHCPv6Options,
}

impl DHCPv6ServerConfig {
    /// A server of `duid` leasing nothing yet, of lifetimes of a day
    /// preferred and two valid, T1 and T2 derived, giving no options.
    pub fn new(duid: DHCPDUID) -> DHCPv6ServerConfig {
        DHCPv6ServerConfig {
            duid,
            addresses: None,
            prefixes: None,
            preferred: 86_400,
            valid: 172_800,
            t1: 0,
            t2: 0,
            preference: 0,
            rapid_commit: false,
            options: DHCPv6Options::new(),
        }
    }
}

/// An address or a prefix bound to a client's IA.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv6Binding {
    pub client: Vec<u8>,
    pub kind: DHCPv6OptionCode,
    pub iaid: u32,
    pub address: IPv6Address,
    /// None for an address, the length for a prefix.
    pub length: Option<u8>,
    /// None: declined, not leased again (§18.3.8).
    pub expires: Option<Instant>,
    pub declined: bool,
}

/// A DHCPv6 server (RFC 9915 §18.3), Sans-I/O: it answers each client
/// message, relayed or not, with the reply of its rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DHCPv6Server {
    pub config: DHCPv6ServerConfig,
    /// The bindings by address and, for a prefix, its length.
    pub bindings: BTreeMap<(IPv6Address, Option<u8>), DHCPv6Binding>,
}

impl DHCPv6Server {
    pub fn new(config: DHCPv6ServerConfig) -> Result<DHCPv6Server, DHCPError> {
        if let Some((first, last)) = config.addresses
            && first.0 > last.0
        {
            return Err(DHCPError::Config);
        }
        if let Some((_, length, delegated)) = config.prefixes
            && (length > delegated || delegated == 0 || delegated > 128 || delegated - length > 32)
        {
            return Err(DHCPError::Config);
        }
        config.duid.encode().map_err(|_| DHCPError::Config)?;
        Ok(DHCPv6Server { config, bindings: BTreeMap::new() })
    }

    /// The reply to `bytes` at `now`: of a client's message, or of a
    /// Relay-forward, whose relayed message is answered inside a
    /// Relay-reply of the same addresses and Interface-Id (§19.3).
    pub fn receive(&mut self, bytes: &[u8], now: Instant) -> Option<Vec<u8>> {
        self.receive_relayed(bytes, now, 0)
    }

    /// [`DHCPv6Server::receive`] of a message inside `relays` Relay-forward
    /// messages: none past HOP_COUNT_LIMIT of them, the most relays a
    /// message passes (§7.6, §19.1.2).
    pub fn receive_relayed(&mut self, bytes: &[u8], now: Instant, relays: u8) -> Option<Vec<u8>> {
        let kind = DHCPv6MessageType(*bytes.first()?);
        if kind == DHCPv6MessageType::RELAY_FORW {
            if relays >= DHCPv6RelayMessage::HOP_COUNT_LIMIT {
                return None;
            }
            let relay = DHCPv6RelayMessage::decode(bytes).ok()?;
            let inner = self.receive_relayed(relay.relayed()?, now, relays + 1)?;
            let mut reply = DHCPv6RelayMessage {
                kind: DHCPv6MessageType::RELAY_REPL,
                options: DHCPv6Options::new(),
                ..relay.clone()
            };
            if let Some(interface) = relay.options.get(DHCPv6OptionCode::INTERFACE_ID) {
                reply.options.push(DHCPv6OptionCode::INTERFACE_ID, interface.to_vec());
            }
            reply.options.push(DHCPv6OptionCode::RELAY_MSG, inner);
            return reply.encode().ok();
        }
        let message = DHCPv6Message::decode(bytes).ok()?;
        self.answer(&message, now).and_then(|reply| reply.encode().ok())
    }

    /// The answer to `message`, after the checks of §16: a Client
    /// Identifier, and the server's identifier where the type needs it and
    /// none where it must not be.
    pub fn answer(&mut self, message: &DHCPv6Message, now: Instant) -> Option<DHCPv6Message> {
        let client = message.options.get(DHCPv6OptionCode::CLIENT_ID).map(<[u8]>::to_vec);
        let server = message.options.get(DHCPv6OptionCode::SERVER_ID);
        let duid = self.config.duid.encode().ok()?;
        let ours = server == Some(&duid[..]);
        use DHCPv6MessageType as Kind;
        let valid = match message.kind {
            Kind::SOLICIT | Kind::REBIND | Kind::CONFIRM => client.is_some() && server.is_none(),
            Kind::REQUEST | Kind::RENEW | Kind::RELEASE | Kind::DECLINE => client.is_some() && ours,
            // §16.12: nor an IA of any kind.
            Kind::INFORMATION_REQUEST => {
                (server.is_none() || ours)
                    && ![DHCPv6OptionCode::IA_NA, DHCPv6OptionCode::IA_TA, DHCPv6OptionCode::IA_PD]
                        .iter()
                        .any(|code| message.options.contains(*code))
            }
            _ => false,
        };
        if !valid {
            return None;
        }
        let client = client.unwrap_or_default();
        let kind = match message.kind {
            Kind::SOLICIT if self.config.rapid_commit && message.options.contains(DHCPv6OptionCode::RAPID_COMMIT) => {
                Kind::REPLY
            }
            Kind::SOLICIT => Kind::ADVERTISE,
            _ => Kind::REPLY,
        };
        let mut reply = DHCPv6Message::new(kind, message.transaction);
        reply.options.push(DHCPv6OptionCode::SERVER_ID, duid);
        if !client.is_empty() {
            reply.options.push(DHCPv6OptionCode::CLIENT_ID, client.clone());
        }
        match message.kind {
            Kind::SOLICIT => {
                let commit = kind == Kind::REPLY;
                if commit {
                    reply.options.push(DHCPv6OptionCode::RAPID_COMMIT, Vec::new());
                }
                if self.config.preference != 0 {
                    reply.options.push(DHCPv6OptionCode::PREFERENCE, alloc::vec![self.config.preference]);
                }
                self.assign(message, &mut reply, &client, commit, now);
            }
            Kind::REQUEST | Kind::RENEW | Kind::REBIND => {
                let known = message.kind != Kind::REQUEST;
                self.extend(message, &mut reply, &client, known, now);
            }
            Kind::RELEASE | Kind::DECLINE => {
                // §18.3.7, §18.3.8: the bindings named end; a declined address is not leased again.
                for ia in DHCPv6Server::ias(&message.options) {
                    for held in ia
                        .addresses()
                        .iter()
                        .map(|address| address.address)
                        .chain(ia.prefixes().iter().map(|prefix| prefix.prefix))
                    {
                        for binding in self.bindings.values_mut().filter(|binding| {
                            binding.client == client && binding.iaid == ia.iaid && binding.address == held
                        }) {
                            if message.kind == Kind::DECLINE {
                                binding.declined = true;
                                binding.client.clear();
                            } else {
                                binding.expires = Some(now);
                            }
                        }
                    }
                }
                reply
                    .options
                    .push(DHCPv6OptionCode::STATUS_CODE, DHCPv6StatusCode::new(DHCPv6StatusCode::SUCCESS, "").encode());
            }
            Kind::CONFIRM => {
                // §18.3.3: whether the addresses are on the server's link.
                let addresses: Vec<IPv6Address> = DHCPv6Server::ias(&message.options)
                    .iter()
                    .flat_map(DHCPv6IA::addresses)
                    .map(|address| address.address)
                    .collect();
                if addresses.is_empty() {
                    return None;
                }
                let on_link = addresses.iter().all(|address| self.in_pool(address));
                let code = if on_link { DHCPv6StatusCode::SUCCESS } else { DHCPv6StatusCode::NOT_ON_LINK };
                reply.options.push(DHCPv6OptionCode::STATUS_CODE, DHCPv6StatusCode::new(code, "").encode());
            }
            _ => {}
        }
        self.give(&message.options, &mut reply.options);
        Some(reply)
    }

    /// The IA_NA and IA_PD of `options` (IA_TA is ignored, §21.5).
    pub fn ias(options: &DHCPv6Options) -> Vec<DHCPv6IA> {
        [options.ias(DHCPv6OptionCode::IA_NA), options.ias(DHCPv6OptionCode::IA_PD)].concat()
    }

    /// Adds the configured options the client asked for (§18.3.9).
    pub fn give(&self, request: &DHCPv6Options, reply: &mut DHCPv6Options) {
        let asked = request.requested();
        for option in &self.config.options.entries {
            if asked.contains(&option.code) {
                reply.entries.push(option.clone());
            }
        }
    }

    pub fn in_pool(&self, address: &IPv6Address) -> bool {
        self.config.addresses.is_some_and(|(first, last)| first.0 <= address.0 && address.0 <= last.0)
    }

    /// Whether `address` (or the prefix of `length` there) is declined, or
    /// held at `now` by another IA than `ia` of `client`: each IA has
    /// addresses of its own (§12, §21.4).
    pub fn is_taken(
        &self,
        address: &IPv6Address,
        length: Option<u8>,
        client: &[u8],
        ia: &DHCPv6IA,
        now: Instant,
    ) -> bool {
        self.bindings.get(&(*address, length)).is_some_and(|binding| {
            let own = binding.client == client && binding.kind == ia.kind && binding.iaid == ia.iaid;
            binding.declined || (!own && binding.expires.is_none_or(|expires| now < expires))
        })
    }

    /// A free address of the pool, or a free prefix, for the IA `ia` of
    /// `client`, but none of `chosen` (those given to its other IAs).
    pub fn allocate(
        &self,
        ia: &DHCPv6IA,
        client: &[u8],
        chosen: &[(IPv6Address, Option<u8>)],
        now: Instant,
    ) -> Option<(IPv6Address, Option<u8>)> {
        let free = |candidate: &(IPv6Address, Option<u8>)| {
            !chosen.contains(candidate) && !self.is_taken(&candidate.0, candidate.1, client, ia, now)
        };
        match ia.kind {
            DHCPv6OptionCode::IA_NA => {
                let (first, last) = self.config.addresses?;
                let (first, last) = (u128::from_be_bytes(first.0), u128::from_be_bytes(last.0));
                (first..=last.min(first.saturating_add(65_535)))
                    .map(|value| (IPv6Address(value.to_be_bytes()), None))
                    .find(free)
            }
            DHCPv6OptionCode::IA_PD => {
                let (base, length, delegated) = self.config.prefixes?;
                let count = 1u64 << (delegated.saturating_sub(length)).min(16);
                let base = u128::from_be_bytes(base.0);
                let step = 128 - u32::from(delegated);
                (0..count)
                    .filter_map(|index| u128::from(index).checked_shl(step))
                    .map(|offset| (IPv6Address((base | offset).to_be_bytes()), Some(delegated)))
                    .find(free)
            }
            _ => None,
        }
    }

    /// The addresses or prefixes the bindings of `client` give its IA `ia`.
    pub fn held(&self, client: &[u8], ia: &DHCPv6IA) -> Vec<(IPv6Address, Option<u8>)> {
        self.bindings
            .values()
            .filter(|binding| {
                binding.client == client && binding.iaid == ia.iaid && binding.kind == ia.kind && !binding.declined
            })
            .map(|binding| (binding.address, binding.length))
            .collect()
    }

    /// The IAs of a reply: for each IA of the request, the client's
    /// bindings of it, or new ones (if `commit` binds them), or the status
    /// of none available (§18.3.1, §18.3.9).
    pub fn assign(
        &mut self,
        request: &DHCPv6Message,
        reply: &mut DHCPv6Message,
        client: &[u8],
        commit: bool,
        now: Instant,
    ) {
        let mut chosen: Vec<(IPv6Address, Option<u8>)> = Vec::new();
        for ia in DHCPv6Server::ias(&request.options) {
            let mut held = self.held(client, &ia);
            if held.is_empty()
                && let Some(new) = self.allocate(&ia, client, &chosen, now)
            {
                held.push(new);
            }
            chosen.extend_from_slice(&held);
            let mut answer = DHCPv6IA::new(ia.kind, ia.iaid);
            if held.is_empty() {
                let code = if ia.kind == DHCPv6OptionCode::IA_PD {
                    DHCPv6StatusCode::NO_PREFIX_AVAIL
                } else {
                    DHCPv6StatusCode::NO_ADDRS_AVAIL
                };
                answer.options.push(DHCPv6OptionCode::STATUS_CODE, DHCPv6StatusCode::new(code, "").encode());
            } else {
                self.fill(&mut answer, &held);
                if commit {
                    for (address, length) in held {
                        self.bind(client, &ia, address, length, now);
                    }
                }
            }
            if let Ok(option) = answer.encode() {
                reply.options.entries.push(option);
            }
        }
    }

    /// Request, Renew and Rebind (§18.3.2, §18.3.4, §18.3.5): bindings
    /// made or extended; for Renew and Rebind, an IA the server has no
    /// binding of has the status NoBinding.
    pub fn extend(
        &mut self,
        request: &DHCPv6Message,
        reply: &mut DHCPv6Message,
        client: &[u8],
        known: bool,
        now: Instant,
    ) {
        if !known {
            self.assign(request, reply, client, true, now);
            return;
        }
        for ia in DHCPv6Server::ias(&request.options) {
            let held = self.held(client, &ia);
            let mut answer = DHCPv6IA::new(ia.kind, ia.iaid);
            if held.is_empty() {
                answer.options.push(
                    DHCPv6OptionCode::STATUS_CODE,
                    DHCPv6StatusCode::new(DHCPv6StatusCode::NO_BINDING, "").encode(),
                );
            } else {
                self.fill(&mut answer, &held);
                for (address, length) in held {
                    self.bind(client, &ia, address, length, now);
                }
            }
            if let Ok(option) = answer.encode() {
                reply.options.entries.push(option);
            }
        }
    }

    /// The IA's T1, T2 and addresses or prefixes, of the configured lifetimes.
    pub fn fill(&self, answer: &mut DHCPv6IA, held: &[(IPv6Address, Option<u8>)]) {
        let config = &self.config;
        answer.t1 = config.t1;
        answer.t2 = config.t2;
        for (address, length) in held {
            let data = match length {
                None => DHCPv6IAAddress {
                    address: *address,
                    preferred: config.preferred,
                    valid: config.valid,
                    options: DHCPv6Options::new(),
                }
                .encode(),
                Some(length) => DHCPv6IAPrefix {
                    preferred: config.preferred,
                    valid: config.valid,
                    length: *length,
                    prefix: *address,
                    options: DHCPv6Options::new(),
                }
                .encode(),
            };
            let code = if length.is_some() { DHCPv6OptionCode::IAPREFIX } else { DHCPv6OptionCode::IAADDR };
            if let Ok(data) = data {
                answer.options.push(code, data);
            }
        }
    }

    /// Records `address` for the IA `ia` of `client` until its valid lifetime ends.
    pub fn bind(&mut self, client: &[u8], ia: &DHCPv6IA, address: IPv6Address, length: Option<u8>, now: Instant) {
        let expires = (self.config.valid != DHCPv6IA::INFINITY)
            .then(|| now.saturating_add(Duration::from_secs(u64::from(self.config.valid))));
        let binding = DHCPv6Binding {
            client: client.to_vec(),
            kind: ia.kind,
            iaid: ia.iaid,
            address,
            length,
            expires,
            declined: false,
        };
        self.bindings.insert((address, length), binding);
    }

    /// Forgets the bindings expired at `now`.
    pub fn expire(&mut self, now: Instant) {
        self.bindings.retain(|_, binding| binding.declined || binding.expires.is_none_or(|expires| now < expires));
    }
}
