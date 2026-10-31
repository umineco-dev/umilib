use alloc::collections::{BTreeMap, BTreeSet};
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
    /// The prefix it delegates from (no bit set past its length), its
    /// length, and the length of each delegated prefix (IA_PD), at most 32
    /// bits longer.
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
    /// How long a declined address or prefix is not leased (§18.3.8).
    pub decline_time: Duration,
    /// The most IAs of a message given addresses or prefixes; the others
    /// are answered NoAddrsAvail or NoPrefixAvail (§18.3.9).
    pub maximum_ias: usize,
    /// The most bindings kept, declined ones and ended ones not yet
    /// forgotten by [`DHCPv6Server::expire`] among them; when full, no new
    /// address or prefix is given.
    pub maximum_bindings: usize,
}

impl DHCPv6ServerConfig {
    /// A server of `duid` leasing nothing yet, of lifetimes of a day
    /// preferred and two valid, T1 and T2 derived, giving no options; a
    /// declined address not leased for an hour, 16 IAs of a message
    /// answered, and 65536 bindings kept.
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
            decline_time: Duration::from_secs(3600),
            maximum_ias: 16,
            maximum_bindings: 65_536,
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
    /// When it ends (None: never): its valid lifetime, or, declined, the
    /// end of `decline_time` (§18.3.8).
    pub expires: Option<Instant>,
    pub declined: bool,
}

impl DHCPv6Binding {
    /// Whether it keeps its address or prefix from the IA `ia` of `client`
    /// at `now`: declined, or held by another IA, until it ends. Each IA
    /// has addresses of its own (§12, §21.4).
    pub fn blocks(&self, client: &[u8], ia: &DHCPv6IA, now: Instant) -> bool {
        let own = self.client == client && self.kind == ia.kind && self.iaid == ia.iaid;
        let live = self.expires.is_none_or(|expires| now < expires);
        live && (self.declined || !own)
    }
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
    /// A server of `config`; fails for a pool whose first address is after
    /// its last, or prefixes of bits set past their length, longer than
    /// their delegated length, or more than 32 bits shorter.
    pub fn new(config: DHCPv6ServerConfig) -> Result<DHCPv6Server, DHCPError> {
        if let Some((first, last)) = config.addresses
            && first.0 > last.0
        {
            return Err(DHCPError::Config);
        }
        if let Some((base, length, delegated)) = config.prefixes
            && (length > delegated
                || delegated == 0
                || delegated > 128
                || delegated - length > 32
                || u128::from_be_bytes(base.0).checked_shl(u32::from(length)).unwrap_or(0) != 0)
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
                // §18.3.7, §18.3.8: the bindings named end; a declined address
                // is not leased for `decline_time`.
                let declined = now.saturating_add(self.config.decline_time);
                for ia in DHCPv6Server::ias(&message.options) {
                    let keys = ia
                        .addresses()
                        .iter()
                        .map(|address| (address.address, None))
                        .chain(ia.prefixes().iter().map(|prefix| (prefix.prefix, Some(prefix.length))))
                        .collect::<Vec<_>>();
                    for key in keys {
                        let Some(binding) = self.bindings.get_mut(&key) else { continue };
                        if binding.client != client || binding.kind != ia.kind || binding.iaid != ia.iaid {
                            continue;
                        }
                        if message.kind == Kind::DECLINE {
                            binding.declined = true;
                            binding.client.clear();
                            binding.expires = Some(declined);
                        } else {
                            binding.expires = Some(now);
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

    /// Whether `address` (or the prefix of `length` there) is kept from
    /// the IA `ia` of `client` at `now` ([`DHCPv6Binding::blocks`]).
    pub fn is_taken(
        &self,
        address: &IPv6Address,
        length: Option<u8>,
        client: &[u8],
        ia: &DHCPv6IA,
        now: Instant,
    ) -> bool {
        self.bindings.get(&(*address, length)).is_some_and(|binding| binding.blocks(client, ia, now))
    }

    /// The first free address of the pool, or free prefix, for the IA `ia`
    /// of `client`, but none of `chosen` (those given to its other IAs).
    /// The whole pool is searched, in a time of the bindings in it and of
    /// `chosen`, not of its size: every candidate passed over is a binding
    /// or one of `chosen`.
    pub fn allocate(
        &self,
        ia: &DHCPv6IA,
        client: &[u8],
        chosen: &BTreeSet<(IPv6Address, Option<u8>)>,
        now: Instant,
    ) -> Option<(IPv6Address, Option<u8>)> {
        // The candidates are start + (index << shift), for index from 0 to last.
        let (start, shift, last, length) = match ia.kind {
            DHCPv6OptionCode::IA_NA => {
                let (first, last) = self.config.addresses?;
                let (first, last) = (u128::from_be_bytes(first.0), u128::from_be_bytes(last.0));
                (first, 0, last.checked_sub(first)?, None)
            }
            DHCPv6OptionCode::IA_PD => {
                let (base, length, delegated) = self.config.prefixes?;
                // A configuration changed after DHCPv6Server::new is checked again, to never overflow.
                let bits = delegated.checked_sub(length).filter(|bits| *bits <= 32 && delegated <= 128)?;
                (u128::from_be_bytes(base.0), 128 - u32::from(delegated), (1u128 << bits) - 1, Some(delegated))
            }
            _ => return None,
        };
        let end = start.checked_add(last << shift)?;
        let candidate = |index: u128| (IPv6Address((start + (index << shift)).to_be_bytes()), length);
        let mut index = 0u128;
        for (key, binding) in
            self.bindings.range((IPv6Address(start.to_be_bytes()), length)..=(IPv6Address(end.to_be_bytes()), length))
        {
            let offset = u128::from_be_bytes(key.0.0) - start;
            if key.1 != length || offset & ((1u128 << shift) - 1) != 0 {
                continue;
            }
            let found = offset >> shift;
            while index < found {
                if !chosen.contains(&candidate(index)) {
                    return Some(candidate(index));
                }
                index += 1;
            }
            if index == found {
                if !binding.blocks(client, ia, now) && !chosen.contains(&candidate(index)) {
                    return Some(candidate(index));
                }
                index = index.checked_add(1)?;
            }
        }
        while index <= last {
            if !chosen.contains(&candidate(index)) {
                return Some(candidate(index));
            }
            index = index.checked_add(1)?;
        }
        None
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

    /// The answer to an IA given nothing: the status NoPrefixAvail for an
    /// IA_PD, NoAddrsAvail for others (§18.3.1, §18.3.9).
    pub fn unavailable(ia: &DHCPv6IA) -> DHCPv6IA {
        let code = match ia.kind {
            DHCPv6OptionCode::IA_PD => DHCPv6StatusCode::NO_PREFIX_AVAIL,
            _ => DHCPv6StatusCode::NO_ADDRS_AVAIL,
        };
        let mut answer = DHCPv6IA::new(ia.kind, ia.iaid);
        answer.options.push(DHCPv6OptionCode::STATUS_CODE, DHCPv6StatusCode::new(code, "").encode());
        answer
    }

    /// The IAs of a reply: for each of the first `maximum_ias` IAs of the
    /// request, the client's bindings of it, or a new one (if `commit`
    /// binds it) while fewer than `maximum_bindings` are kept; for an IA
    /// given nothing, [`DHCPv6Server::unavailable`] (§18.3.1, §18.3.9).
    pub fn assign(
        &mut self,
        request: &DHCPv6Message,
        reply: &mut DHCPv6Message,
        client: &[u8],
        commit: bool,
        now: Instant,
    ) {
        let mut chosen: BTreeSet<(IPv6Address, Option<u8>)> = BTreeSet::new();
        // The bindings this message adds, counted whether bound or not, so
        // that an Advertise offers what a Request would get.
        let mut added = 0usize;
        for (position, ia) in DHCPv6Server::ias(&request.options).into_iter().enumerate() {
            if position >= self.config.maximum_ias {
                if let Ok(option) = DHCPv6Server::unavailable(&ia).encode() {
                    reply.options.entries.push(option);
                }
                continue;
            }
            let mut held = self.held(client, &ia);
            if held.is_empty()
                && self.bindings.len().saturating_add(added) < self.config.maximum_bindings
                && let Some(new) = self.allocate(&ia, client, &chosen, now)
            {
                if !commit && !self.bindings.contains_key(&new) {
                    added += 1;
                }
                held.push(new);
            }
            chosen.extend(held.iter().copied());
            let mut answer = DHCPv6IA::new(ia.kind, ia.iaid);
            if held.is_empty() {
                answer = DHCPv6Server::unavailable(&ia);
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
    /// binding of has the status NoBinding, and an IA past the first
    /// `maximum_ias` is extended no more ([`DHCPv6Server::unavailable`]).
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
        for (position, ia) in DHCPv6Server::ias(&request.options).into_iter().enumerate() {
            if position >= self.config.maximum_ias {
                if let Ok(option) = DHCPv6Server::unavailable(&ia).encode() {
                    reply.options.entries.push(option);
                }
                continue;
            }
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

    /// Forgets the bindings ended at `now`: leases past their valid
    /// lifetime, declined ones past `decline_time`.
    pub fn expire(&mut self, now: Instant) {
        self.bindings.retain(|_, binding| binding.expires.is_none_or(|expires| now < expires));
    }
}
