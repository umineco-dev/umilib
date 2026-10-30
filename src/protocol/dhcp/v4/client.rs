use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::time::Duration;

use crate::crypto::random::Random;
use crate::protocol::ethernet::MACAddress;
use crate::protocol::ip::IPv4Address;
use crate::runtime::Instant;

use super::super::DHCPError;
use super::{DHCPv4Message, DHCPv4MessageType, DHCPv4OptionCode, DHCPv4Options};

/// How a client asks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv4ClientConfig {
    pub hardware: MACAddress,
    /// The client identifier (option 61): of RFC 4361 §6.1, the type 255,
    /// an IAID and a DUID; none to be known by the hardware address.
    pub client_identifier: Option<Vec<u8>>,
    pub host_name: Option<Vec<u8>>,
    /// The options asked for (RFC 2132 §9.8).
    pub parameters: Vec<DHCPv4OptionCode>,
    /// Asks servers to broadcast their replies, for a client that cannot
    /// take unicast before it has an address (RFC 2131 §4.1).
    pub broadcast: bool,
    pub maximum_message_size: u16,
    /// The retransmissions of a DISCOVER or REQUEST before the exchange is
    /// given up (RFC 2131 §4.1: 4 s doubled each time, up to 64 s).
    pub retransmissions: usize,
    /// The client can do without IPv4 (RFC 8925 §3.2): it asks for option 108.
    pub ipv6_only: bool,
}

impl DHCPv4ClientConfig {
    pub fn new(hardware: MACAddress) -> DHCPv4ClientConfig {
        DHCPv4ClientConfig {
            hardware,
            client_identifier: None,
            host_name: None,
            parameters: alloc::vec![
                DHCPv4OptionCode::SUBNET_MASK,
                DHCPv4OptionCode::ROUTER,
                DHCPv4OptionCode::DOMAIN_NAME_SERVER,
                DHCPv4OptionCode::DOMAIN_NAME,
                DHCPv4OptionCode::INTERFACE_MTU,
                DHCPv4OptionCode::BROADCAST_ADDRESS,
                DHCPv4OptionCode::DOMAIN_SEARCH,
                DHCPv4OptionCode::CLASSLESS_STATIC_ROUTE,
            ],
            broadcast: false,
            maximum_message_size: 1500,
            retransmissions: 4,
            ipv6_only: false,
        }
    }
}

/// The states of a client (RFC 2131 §4.4, figure 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DHCPv4ClientState {
    Init,
    Selecting,
    Requesting,
    Rebooting,
    Bound,
    Renewing,
    Rebinding,
}

/// An address leased, from a server, with its times: None for infinity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv4Lease {
    pub address: IPv4Address,
    pub server: IPv4Address,
    pub lease: Option<Duration>,
    /// T1 and T2 (RFC 2131 §4.4.5).
    pub renewal: Option<Duration>,
    pub rebinding: Option<Duration>,
    /// When the exchange the ACK ends began (its DISCOVER, or the REQUEST
    /// of INIT-REBOOT, RENEWING or REBINDING), from which the times run:
    /// no later than the REQUEST, so that the lease is not lengthened.
    pub acquired: Instant,
    /// The options of the ACK.
    pub options: DHCPv4Options,
}

impl DHCPv4Lease {
    /// When the time `time` after acquisition comes; None for infinity.
    pub fn at(&self, time: Option<Duration>) -> Option<Instant> {
        time.map(|time| self.acquired.saturating_add(time))
    }
}

/// What a client tells.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DHCPv4ClientEvent {
    /// An address is leased, or the lease extended; the client should check
    /// that no other host has it (RFC 2131 §4.4.1) and, if one does, decline it.
    Bound(DHCPv4Lease),
    /// A server refused the address (DHCPNAK): it is no longer the client's.
    Refused,
    /// The lease ended without being extended: the address is no longer the client's.
    Expired,
    /// No server answered the exchange; it starts again later.
    Unanswered,
    /// The network prefers that the client use IPv6 only, for this long (RFC 8925 §3.2).
    IPv6Only(Duration),
}

/// A message for a client to send, to `destination` (255.255.255.255 to broadcast), port 67.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv4Transmission {
    pub destination: IPv4Address,
    pub message: DHCPv4Message,
}

/// A DHCPv4 client (RFC 2131 §4.4), Sans-I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DHCPv4Client {
    pub config: DHCPv4ClientConfig,
    pub state: DHCPv4ClientState,
    pub xid: u32,
    /// When the exchange began, from which `secs` counts (RFC 2131 §2).
    pub started: Instant,
    pub attempt: usize,
    /// When the next retransmission, or the next step of the lease, is due.
    pub deadline: Option<Instant>,
    /// The server and address chosen from an OFFER.
    pub offer: Option<(IPv4Address, IPv4Address)>,
    pub lease: Option<DHCPv4Lease>,
    pub transmissions: VecDeque<DHCPv4Transmission>,
    pub events: VecDeque<DHCPv4ClientEvent>,
}

impl DHCPv4Client {
    /// The least time the client waits for IPv6-only (RFC 8925 §3.4: MIN_V6ONLY_WAIT).
    pub const MINIMUM_IPV6_ONLY_WAIT: Duration = Duration::from_secs(300);
    /// The least time before retransmitting a REQUEST of RENEWING or REBINDING (RFC 2131 §4.4.5).
    pub const MINIMUM_RENEWAL_WAIT: Duration = Duration::from_secs(60);
    /// The wait after a DECLINE (RFC 2131 §3.1.5) and before discovering again after no answer.
    pub const RESTART_WAIT: Duration = Duration::from_secs(10);

    pub fn new(config: DHCPv4ClientConfig, now: Instant) -> DHCPv4Client {
        DHCPv4Client {
            config,
            state: DHCPv4ClientState::Init,
            xid: 0,
            started: now,
            attempt: 0,
            deadline: None,
            offer: None,
            lease: None,
            transmissions: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Starts: with `previous`, an address the client had, by asking for it
    /// again (INIT-REBOOT, RFC 2131 §3.2); else by discovering servers.
    pub fn start<R: Random>(
        &mut self,
        previous: Option<IPv4Address>,
        now: Instant,
        random: &mut R,
    ) -> Result<(), DHCPError> {
        self.begin(now, random)?;
        match previous {
            Some(address) => {
                self.state = DHCPv4ClientState::Rebooting;
                self.offer = Some((IPv4Address::UNSPECIFIED, address));
                self.send_request(now, random)
            }
            None => self.discover(now, random),
        }
    }

    /// A new exchange: a new xid, the first attempt.
    pub fn begin<R: Random>(&mut self, now: Instant, random: &mut R) -> Result<(), DHCPError> {
        let mut xid = [0u8; 4];
        random.fill(&mut xid).map_err(|_| DHCPError::Random)?;
        self.xid = u32::from_be_bytes(xid);
        self.started = now;
        self.attempt = 0;
        Ok(())
    }

    /// The message of `kind` with what every message of the client carries.
    pub fn message(&self, kind: DHCPv4MessageType, now: Instant) -> DHCPv4Message {
        let mut message = DHCPv4Message::request(kind, self.config.hardware, self.xid);
        message.secs = now.saturating_duration_since(self.started).as_secs().min(u64::from(u16::MAX)) as u16;
        if self.config.broadcast {
            message.flags |= DHCPv4Message::BROADCAST;
        }
        let options = &mut message.options;
        if let Some(identifier) = &self.config.client_identifier {
            options.set(DHCPv4OptionCode::CLIENT_IDENTIFIER, identifier.clone());
        }
        if kind != DHCPv4MessageType::DECLINE && kind != DHCPv4MessageType::RELEASE {
            options.set(
                DHCPv4OptionCode::MAXIMUM_MESSAGE_SIZE,
                self.config.maximum_message_size.max(576).to_be_bytes().to_vec(),
            );
            let mut parameters: Vec<u8> = self.config.parameters.iter().map(|code| code.0).collect();
            if self.config.ipv6_only {
                parameters.push(DHCPv4OptionCode::IPV6_ONLY_PREFERRED.0);
            }
            options.set(DHCPv4OptionCode::PARAMETER_REQUEST_LIST, parameters);
            if let Some(name) = &self.config.host_name {
                options.set(DHCPv4OptionCode::HOST_NAME, name.clone());
            }
        }
        message
    }

    /// The delay of the `attempt`th retransmission: 4 s doubled each time,
    /// at most 64 s, with up to a second more or less (RFC 2131 §4.1).
    pub fn backoff<R: Random>(attempt: usize, random: &mut R) -> Duration {
        let base = 4u64 << attempt.min(4);
        let jitter = random.next_u32().map_or(1000, |value| u64::from(value % 2001));
        Duration::from_millis(base * 1000 + jitter - 1000)
    }

    /// Sends a DISCOVER (SELECTING), asking for the address the client last had.
    pub fn discover<R: Random>(&mut self, now: Instant, random: &mut R) -> Result<(), DHCPError> {
        self.state = DHCPv4ClientState::Selecting;
        let mut message = self.message(DHCPv4MessageType::DISCOVER, now);
        if let Some(lease) = &self.lease {
            message.options.set_address(DHCPv4OptionCode::REQUESTED_ADDRESS, lease.address);
        }
        self.transmissions.push_back(DHCPv4Transmission { destination: IPv4Address::BROADCAST, message });
        self.deadline = Some(now.saturating_add(DHCPv4Client::backoff(self.attempt, random)));
        Ok(())
    }

    /// Sends the REQUEST of the state (RFC 2131 §4.3.2): of SELECTING with
    /// the server identifier and the offered address; of INIT-REBOOT with
    /// the address alone; of RENEWING to the server, and of REBINDING to
    /// all, with the address in ciaddr.
    pub fn send_request<R: Random>(&mut self, now: Instant, random: &mut R) -> Result<(), DHCPError> {
        let mut message = self.message(DHCPv4MessageType::REQUEST, now);
        let mut destination = IPv4Address::BROADCAST;
        let delay = match self.state {
            DHCPv4ClientState::Requesting | DHCPv4ClientState::Rebooting => {
                let (server, address) = self.offer.ok_or(DHCPError::State)?;
                message.options.set_address(DHCPv4OptionCode::REQUESTED_ADDRESS, address);
                if self.state == DHCPv4ClientState::Requesting {
                    message.options.set_address(DHCPv4OptionCode::SERVER_IDENTIFIER, server);
                }
                DHCPv4Client::backoff(self.attempt, random)
            }
            DHCPv4ClientState::Renewing | DHCPv4ClientState::Rebinding => {
                let lease = self.lease.as_ref().ok_or(DHCPError::State)?;
                message.ciaddr = lease.address;
                message.flags &= !DHCPv4Message::BROADCAST;
                let until = match self.state {
                    DHCPv4ClientState::Renewing => {
                        destination = lease.server;
                        lease.at(lease.rebinding)
                    }
                    _ => lease.at(lease.lease),
                };
                // Half the time left, at least 60 s (RFC 2131 §4.4.5).
                let left = until.map_or(Duration::from_secs(3600), |until| until.saturating_duration_since(now));
                (left / 2).max(DHCPv4Client::MINIMUM_RENEWAL_WAIT)
            }
            _ => return Err(DHCPError::State),
        };
        self.transmissions.push_back(DHCPv4Transmission { destination, message });
        self.deadline = Some(now.saturating_add(delay));
        Ok(())
    }

    /// Takes `bytes`, a server's reply; ignored unless it is a reply to the
    /// client's exchange, of its hardware address and client identifier
    /// (RFC 6842 §3), of a type the state expects.
    pub fn receive<R: Random>(&mut self, bytes: &[u8], now: Instant, random: &mut R) {
        let Ok(reply) = DHCPv4Message::decode(bytes) else { return };
        if reply.op != DHCPv4Message::BOOTREPLY || reply.xid != self.xid || reply.chaddr[..6] != self.config.hardware.0
        {
            return;
        }
        if let (Some(sent), Some(echoed)) =
            (&self.config.client_identifier, reply.options.get(DHCPv4OptionCode::CLIENT_IDENTIFIER))
            && sent.as_slice() != echoed
        {
            return;
        }
        let server = reply.options.address(DHCPv4OptionCode::SERVER_IDENTIFIER);
        match (self.state, reply.message_type()) {
            (DHCPv4ClientState::Selecting, Some(DHCPv4MessageType::OFFER)) => {
                let Some(server) = server else { return };
                // RFC 8925 §3.3: an offer of IPv6-only may be of 0.0.0.0.
                if self.config.ipv6_only && self.prefers_ipv6(&reply, now) {
                    return;
                }
                if reply.yiaddr == IPv4Address::UNSPECIFIED {
                    return;
                }
                self.offer = Some((server, reply.yiaddr));
                self.state = DHCPv4ClientState::Requesting;
                self.attempt = 0;
                let _ = self.send_request(now, random);
            }
            (DHCPv4ClientState::Requesting | DHCPv4ClientState::Rebooting, Some(kind))
                if kind == DHCPv4MessageType::ACK || kind == DHCPv4MessageType::NAK =>
            {
                // In REQUESTING, only the chosen server's answer counts (RFC 2131 §4.4.1).
                let chosen = self.offer.map(|(server, _)| server);
                if self.state == DHCPv4ClientState::Requesting && server != chosen {
                    return;
                }
                if kind == DHCPv4MessageType::NAK {
                    self.refuse(now, random);
                    return;
                }
                // RFC 8925 §3.2: only INIT-REBOOT stops; in REQUESTING the address is used.
                if self.state == DHCPv4ClientState::Rebooting && self.config.ipv6_only && self.prefers_ipv6(&reply, now)
                {
                    return;
                }
                self.bind(&reply, now);
            }
            (DHCPv4ClientState::Renewing | DHCPv4ClientState::Rebinding, Some(DHCPv4MessageType::ACK)) => {
                let renewing = self.state == DHCPv4ClientState::Renewing;
                let from = self.lease.as_ref().map(|lease| lease.server);
                if renewing && server.is_some() && server != from {
                    return;
                }
                self.bind(&reply, now);
            }
            (DHCPv4ClientState::Renewing | DHCPv4ClientState::Rebinding, Some(DHCPv4MessageType::NAK)) => {
                self.refuse(now, random);
            }
            _ => {}
        }
    }

    /// Whether the reply has option 108 (RFC 8925 §3.2): then the client
    /// stops for its time, at least MIN_V6ONLY_WAIT.
    pub fn prefers_ipv6(&mut self, reply: &DHCPv4Message, now: Instant) -> bool {
        let Some(wait) = reply.options.time(DHCPv4OptionCode::IPV6_ONLY_PREFERRED) else { return false };
        let wait = wait.unwrap_or(Duration::from_secs(u64::from(u32::MAX))).max(DHCPv4Client::MINIMUM_IPV6_ONLY_WAIT);
        self.state = DHCPv4ClientState::Init;
        self.offer = None;
        self.deadline = Some(now.saturating_add(wait));
        self.events.push_back(DHCPv4ClientEvent::IPv6Only(wait));
        true
    }

    /// Binds the address of the ACK `reply`: its lease, and T1 and T2 of the
    /// ACK or, if absent or not in order, half and seven eighths of the
    /// lease (RFC 2131 §4.4.5); the times run from the first message of the
    /// exchange. An ACK without a valid lease time, which it MUST have
    /// (RFC 2131 Table 3), is ignored.
    pub fn bind(&mut self, reply: &DHCPv4Message, now: Instant) {
        let Some(lease_time) = reply.options.time(DHCPv4OptionCode::LEASE_TIME) else { return };
        let address = match reply.yiaddr {
            IPv4Address::UNSPECIFIED => self.lease.as_ref().map_or(reply.yiaddr, |lease| lease.address),
            address => address,
        };
        let default = |fraction: u32, of: u32| lease_time.map(|lease| lease * fraction / of);
        let mut renewal = reply.options.time(DHCPv4OptionCode::RENEWAL_TIME).unwrap_or_else(|| default(1, 2));
        let mut rebinding = reply.options.time(DHCPv4OptionCode::REBINDING_TIME).unwrap_or_else(|| default(7, 8));
        let ordered = |a: Option<Duration>, b: Option<Duration>| match (a, b) {
            (Some(a), Some(b)) => a <= b,
            (_, None) => true,
            (None, Some(_)) => false,
        };
        if !ordered(renewal, rebinding) || !ordered(rebinding, lease_time) {
            (renewal, rebinding) = (default(1, 2), default(7, 8));
        }
        let server = reply.options.address(DHCPv4OptionCode::SERVER_IDENTIFIER).unwrap_or(reply.siaddr);
        let lease = DHCPv4Lease {
            address,
            server,
            lease: lease_time,
            renewal,
            rebinding,
            acquired: self.started.min(now),
            options: reply.options.clone(),
        };
        self.state = DHCPv4ClientState::Bound;
        self.offer = None;
        self.deadline = lease.at(lease.renewal);
        self.lease = Some(lease.clone());
        self.events.push_back(DHCPv4ClientEvent::Bound(lease));
    }

    /// A NAK: the address is not the client's; it discovers again.
    pub fn refuse<R: Random>(&mut self, now: Instant, random: &mut R) {
        self.lease = None;
        self.offer = None;
        self.events.push_back(DHCPv4ClientEvent::Refused);
        if self.begin(now, random).is_ok() {
            let _ = self.discover(now, random);
        }
    }

    /// Declines the address of the lease, which another host has (RFC 2131
    /// §4.4.1): a DECLINE, then discovery again after ten seconds (§3.1.5).
    pub fn decline<R: Random>(&mut self, now: Instant, random: &mut R) -> Result<(), DHCPError> {
        let lease = self.lease.take().ok_or(DHCPError::State)?;
        let mut message = self.message(DHCPv4MessageType::DECLINE, now);
        message.options.set_address(DHCPv4OptionCode::REQUESTED_ADDRESS, lease.address);
        message.options.set_address(DHCPv4OptionCode::SERVER_IDENTIFIER, lease.server);
        self.transmissions.push_back(DHCPv4Transmission { destination: IPv4Address::BROADCAST, message });
        self.state = DHCPv4ClientState::Init;
        self.deadline = Some(now.saturating_add(DHCPv4Client::RESTART_WAIT));
        self.begin(now, random)
    }

    /// Gives the address back (RFC 2131 §4.4.6): a RELEASE to the server; the client stops.
    pub fn release(&mut self, now: Instant) -> Result<(), DHCPError> {
        let lease = self.lease.take().ok_or(DHCPError::State)?;
        let mut message = self.message(DHCPv4MessageType::RELEASE, now);
        message.ciaddr = lease.address;
        message.flags &= !DHCPv4Message::BROADCAST;
        message.options.set_address(DHCPv4OptionCode::SERVER_IDENTIFIER, lease.server);
        self.transmissions.push_back(DHCPv4Transmission { destination: lease.server, message });
        self.state = DHCPv4ClientState::Init;
        self.deadline = None;
        Ok(())
    }

    /// Asks for configuration only, for a client whose address `address` is
    /// configured otherwise (DHCPINFORM, RFC 2131 §3.4), under an xid of its
    /// own: the client's exchange goes on, and the ACK, of that xid, is the
    /// caller's to read.
    pub fn inform<R: Random>(
        &self,
        address: IPv4Address,
        now: Instant,
        random: &mut R,
    ) -> Result<DHCPv4Transmission, DHCPError> {
        let mut message = self.message(DHCPv4MessageType::INFORM, now);
        message.xid = random.next_u32().map_err(|_| DHCPError::Random)?;
        message.secs = 0;
        message.ciaddr = address;
        message.flags &= !DHCPv4Message::BROADCAST;
        Ok(DHCPv4Transmission { destination: IPv4Address::BROADCAST, message })
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        self.deadline
    }

    /// What is due at `now`: a retransmission, giving up an exchange, or
    /// the next step of the lease — RENEWING at T1, REBINDING at T2, and
    /// its end (RFC 2131 §4.4.5).
    pub fn expire<R: Random>(&mut self, now: Instant, random: &mut R) {
        if self.deadline.is_none_or(|deadline| now < deadline) {
            return;
        }
        match self.state {
            DHCPv4ClientState::Init => {
                if self.begin(now, random).is_ok() {
                    let _ = self.discover(now, random);
                }
            }
            DHCPv4ClientState::Selecting | DHCPv4ClientState::Requesting | DHCPv4ClientState::Rebooting => {
                self.attempt += 1;
                if self.attempt > self.config.retransmissions {
                    self.events.push_back(DHCPv4ClientEvent::Unanswered);
                    self.state = DHCPv4ClientState::Init;
                    self.offer = None;
                    self.deadline = Some(now.saturating_add(DHCPv4Client::RESTART_WAIT));
                    return;
                }
                let _ = match self.state {
                    DHCPv4ClientState::Selecting => self.discover(now, random),
                    _ => self.send_request(now, random),
                };
            }
            DHCPv4ClientState::Bound | DHCPv4ClientState::Renewing | DHCPv4ClientState::Rebinding => {
                let Some(lease) = self.lease.clone() else { return };
                if lease.at(lease.lease).is_some_and(|end| now >= end) {
                    self.lease = None;
                    self.state = DHCPv4ClientState::Init;
                    self.events.push_back(DHCPv4ClientEvent::Expired);
                    if self.begin(now, random).is_ok() {
                        let _ = self.discover(now, random);
                    }
                    return;
                }
                let rebind = lease.at(lease.rebinding).is_some_and(|rebind| now >= rebind);
                let next = if rebind { DHCPv4ClientState::Rebinding } else { DHCPv4ClientState::Renewing };
                if next != self.state {
                    // A new exchange of the new state.
                    if self.begin(now, random).is_err() {
                        return;
                    }
                    self.state = next;
                }
                let _ = self.send_request(now, random);
                // The retransmission waits no later than the next step.
                let step = match next {
                    DHCPv4ClientState::Renewing => lease.at(lease.rebinding),
                    _ => lease.at(lease.lease),
                };
                if let (Some(deadline), Some(step)) = (self.deadline, step) {
                    self.deadline = Some(deadline.min(step));
                }
            }
        }
    }

    pub fn transmit(&mut self) -> Option<DHCPv4Transmission> {
        self.transmissions.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<DHCPv4ClientEvent> {
        self.events.pop_front()
    }
}
