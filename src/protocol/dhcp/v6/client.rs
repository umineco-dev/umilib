use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::time::Duration;

use crate::crypto::random::Random;
use crate::protocol::ip::IPv6Address;
use crate::runtime::Instant;

use super::super::{DHCPDUID, DHCPError};
use super::{
    DHCPv6IA, DHCPv6IAAddress, DHCPv6IAPrefix, DHCPv6Message, DHCPv6MessageType, DHCPv6OptionCode, DHCPv6Options,
    DHCPv6Retransmission, DHCPv6StatusCode,
};

/// How a client asks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv6ClientConfig {
    pub duid: DHCPDUID,
    /// The IAID of its IA_NA and IA_PD (RFC 9915 §12).
    pub iaid: u32,
    /// Asks for addresses (IA_NA).
    pub addresses: bool,
    /// Asks for a prefix (IA_PD), of this length if some.
    pub prefix: Option<Option<u8>>,
    /// The options asked for (§21.7).
    pub requested: Vec<DHCPv6OptionCode>,
    /// Offers to take a Reply to its Solicit (§18.2.1, Rapid Commit).
    pub rapid_commit: bool,
}

impl DHCPv6ClientConfig {
    pub fn new(duid: DHCPDUID, iaid: u32) -> DHCPv6ClientConfig {
        DHCPv6ClientConfig {
            duid,
            iaid,
            addresses: true,
            prefix: None,
            requested: alloc::vec![
                DHCPv6OptionCode::DNS_SERVERS,
                DHCPv6OptionCode::DOMAIN_LIST,
                DHCPv6OptionCode::SOL_MAX_RT
            ],
            rapid_commit: false,
        }
    }
}

/// The exchanges of a client (RFC 9915 §18.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DHCPv6ClientState {
    Init,
    Soliciting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    Confirming,
    Releasing,
    Declining,
    Informing,
    /// Stateless, configured, until it refreshes (§18.2.12).
    Informed,
}

/// The bindings of a client from a server.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv6Lease {
    pub server: DHCPDUID,
    pub ias: Vec<DHCPv6IA>,
    /// The options of the Reply.
    pub options: DHCPv6Options,
    /// When the exchange began, from which the times run.
    pub acquired: Instant,
    /// When to Renew and Rebind (§18.2.4, §18.2.5) and when the last of
    /// its addresses and prefixes is no longer valid; None for infinity.
    pub renewal: Option<Duration>,
    pub rebinding: Option<Duration>,
    pub valid: Option<Duration>,
}

impl DHCPv6Lease {
    pub fn at(&self, time: Option<Duration>) -> Option<Instant> {
        time.map(|time| self.acquired.saturating_add(time))
    }

    pub fn addresses(&self) -> Vec<DHCPv6IAAddress> {
        self.ias.iter().flat_map(DHCPv6IA::addresses).collect()
    }

    pub fn prefixes(&self) -> Vec<DHCPv6IAPrefix> {
        self.ias.iter().flat_map(DHCPv6IA::prefixes).collect()
    }
}

/// What a client tells.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DHCPv6ClientEvent {
    /// Addresses or prefixes are bound, or their lifetimes extended; the
    /// client should check its addresses with DAD and decline those in use (§18.2.10.1).
    Bound(DHCPv6Lease),
    /// The lease ended without being extended.
    Expired,
    /// The configuration of an Information-request's Reply (§18.2.6).
    Informed(DHCPv6Options),
    /// The server took the Release or Decline, or no server answered it in time.
    Released,
    /// No server answered the exchange; it starts again.
    Unanswered,
}

/// A DHCPv6 client (RFC 9915 §18.2), Sans-I/O; its messages go to
/// All_DHCP_Relay_Agents_and_Servers ([`DHCPv6Message::ALL_RELAY_AGENTS_AND_SERVERS`]), port 547.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DHCPv6Client {
    pub config: DHCPv6ClientConfig,
    pub state: DHCPv6ClientState,
    pub transaction: u32,
    pub started: Instant,
    pub retransmission: DHCPv6Retransmission,
    pub sent: usize,
    pub timeout: Duration,
    pub deadline: Option<Instant>,
    /// The best Advertise yet: its preference and message (§18.2.9).
    pub advertise: Option<(u8, DHCPv6Message)>,
    pub lease: Option<DHCPv6Lease>,
    /// The addresses of a Decline.
    pub declined: Vec<IPv6Address>,
    /// SOL_MAX_RT and INF_MAX_RT as the server sets them (§21.24, §21.25).
    pub solicit_maximum: Duration,
    pub information_maximum: Duration,
    pub transmissions: VecDeque<DHCPv6Message>,
    pub events: VecDeque<DHCPv6ClientEvent>,
}

impl DHCPv6Client {
    /// The most delay of a first Solicit, Confirm or Information-request (§7.6).
    pub const MAXIMUM_DELAY: Duration = Duration::from_secs(1);
    /// The refresh time of stateless configuration, and its least (§7.6: IRT_DEFAULT, IRT_MINIMUM).
    pub const REFRESH_DEFAULT: Duration = Duration::from_secs(86_400);
    pub const REFRESH_MINIMUM: Duration = Duration::from_secs(600);

    pub fn new(config: DHCPv6ClientConfig, now: Instant) -> DHCPv6Client {
        DHCPv6Client {
            config,
            state: DHCPv6ClientState::Init,
            transaction: 0,
            started: now,
            retransmission: DHCPv6Retransmission::SOLICIT,
            sent: 0,
            timeout: Duration::ZERO,
            deadline: None,
            advertise: None,
            lease: None,
            declined: Vec::new(),
            solicit_maximum: Duration::from_secs(3600),
            information_maximum: Duration::from_secs(3600),
            transmissions: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Starts: Solicit for addresses or prefixes, or, asking for neither,
    /// Information-request (§18.2.6); the first after a random delay of up to a second.
    pub fn start<R: Random>(&mut self, now: Instant, random: &mut R) -> Result<(), DHCPError> {
        match self.config.addresses || self.config.prefix.is_some() {
            true => self.exchange(DHCPv6ClientState::Soliciting, now, random, true),
            false => self.exchange(DHCPv6ClientState::Informing, now, random, true),
        }
    }

    /// Begins the exchange of `state`: a new transaction ID, sent at once
    /// or, if `delayed`, after a random delay of up to MAXIMUM_DELAY.
    pub fn exchange<R: Random>(
        &mut self,
        state: DHCPv6ClientState,
        now: Instant,
        random: &mut R,
        delayed: bool,
    ) -> Result<(), DHCPError> {
        let mut transaction = [0u8; 4];
        random.fill(&mut transaction).map_err(|_| DHCPError::Random)?;
        self.transaction = u32::from_be_bytes(transaction) & 0xFF_FFFF;
        self.state = state;
        self.started = now;
        self.sent = 0;
        if state == DHCPv6ClientState::Soliciting {
            self.advertise = None;
        }
        let mut retransmission = match state {
            DHCPv6ClientState::Soliciting => {
                DHCPv6Retransmission { maximum: Some(self.solicit_maximum), ..DHCPv6Retransmission::SOLICIT }
            }
            DHCPv6ClientState::Requesting => DHCPv6Retransmission::REQUEST,
            DHCPv6ClientState::Renewing => DHCPv6Retransmission::RENEW,
            DHCPv6ClientState::Rebinding => DHCPv6Retransmission::REBIND,
            DHCPv6ClientState::Confirming => DHCPv6Retransmission::CONFIRM,
            DHCPv6ClientState::Releasing => DHCPv6Retransmission::RELEASE,
            DHCPv6ClientState::Declining => DHCPv6Retransmission::DECLINE,
            DHCPv6ClientState::Informing => DHCPv6Retransmission {
                maximum: Some(self.information_maximum),
                ..DHCPv6Retransmission::INFORMATION_REQUEST
            },
            _ => return Err(DHCPError::State),
        };
        // Renew lasts until T2, Rebind until the bindings are no longer valid (§18.2.4, §18.2.5).
        if let Some(lease) = &self.lease {
            let until = match state {
                DHCPv6ClientState::Renewing => lease.at(lease.rebinding),
                DHCPv6ClientState::Rebinding => lease.at(lease.valid),
                _ => None,
            };
            if let Some(until) = until {
                retransmission.duration = Some(until.saturating_duration_since(now));
            }
        }
        self.retransmission = retransmission;
        self.timeout = retransmission.first(random);
        if delayed {
            let delay = Duration::from_millis(u64::from(random.next_u32().unwrap_or(0) % 1001));
            self.deadline = Some(now.saturating_add(delay));
            return Ok(());
        }
        self.send(now)
    }

    /// The message of the exchange (§18.2): the client's DUID, the elapsed
    /// time, the options asked for, its IAs, and the server's DUID where it names one.
    pub fn message(&self, now: Instant) -> Result<DHCPv6Message, DHCPError> {
        let kind = match self.state {
            DHCPv6ClientState::Soliciting => DHCPv6MessageType::SOLICIT,
            DHCPv6ClientState::Requesting => DHCPv6MessageType::REQUEST,
            DHCPv6ClientState::Renewing => DHCPv6MessageType::RENEW,
            DHCPv6ClientState::Rebinding => DHCPv6MessageType::REBIND,
            DHCPv6ClientState::Confirming => DHCPv6MessageType::CONFIRM,
            DHCPv6ClientState::Releasing => DHCPv6MessageType::RELEASE,
            DHCPv6ClientState::Declining => DHCPv6MessageType::DECLINE,
            DHCPv6ClientState::Informing => DHCPv6MessageType::INFORMATION_REQUEST,
            _ => return Err(DHCPError::State),
        };
        let mut message = DHCPv6Message::new(kind, self.transaction);
        let options = &mut message.options;
        options.push(DHCPv6OptionCode::CLIENT_ID, self.config.duid.encode()?);
        let elapsed = if self.sent == 0 { 0 } else { DHCPv6Retransmission::elapsed(self.started, now) };
        options.push(DHCPv6OptionCode::ELAPSED_TIME, elapsed.to_be_bytes().to_vec());
        let asks =
            !matches!(kind, DHCPv6MessageType::RELEASE | DHCPv6MessageType::DECLINE | DHCPv6MessageType::CONFIRM);
        if asks && !self.config.requested.is_empty() {
            let mut requested = self.config.requested.clone();
            if kind == DHCPv6MessageType::INFORMATION_REQUEST {
                requested.extend([DHCPv6OptionCode::INFORMATION_REFRESH_TIME, DHCPv6OptionCode::INF_MAX_RT]);
            }
            options.push(DHCPv6OptionCode::ORO, requested.iter().flat_map(|code| code.0.to_be_bytes()).collect());
        }
        let server = match kind {
            DHCPv6MessageType::REQUEST => self
                .advertise
                .as_ref()
                .and_then(|(_, advertise)| advertise.options.get(DHCPv6OptionCode::SERVER_ID))
                .map(<[u8]>::to_vec),
            DHCPv6MessageType::RENEW | DHCPv6MessageType::RELEASE | DHCPv6MessageType::DECLINE => {
                self.lease.as_ref().map(|lease| lease.server.encode()).transpose()?
            }
            _ => None,
        };
        if let Some(server) = server {
            options.push(DHCPv6OptionCode::SERVER_ID, server);
        }
        if kind == DHCPv6MessageType::SOLICIT && self.config.rapid_commit {
            options.push(DHCPv6OptionCode::RAPID_COMMIT, Vec::new());
        }
        if kind != DHCPv6MessageType::INFORMATION_REQUEST {
            for ia in self.ias(kind)? {
                message.options.entries.push(ia.encode()?);
            }
        }
        Ok(message)
    }

    /// The IAs of a message of `kind`: for Solicit, empty ones (a prefix
    /// length as a hint, §18.2.1); for Request, the Advertise's; for the
    /// others, the lease's (for Confirm, lifetimes 0, §18.2.3; for
    /// Decline, the declined addresses only).
    pub fn ias(&self, kind: DHCPv6MessageType) -> Result<Vec<DHCPv6IA>, DHCPError> {
        let mut ias = Vec::new();
        if kind == DHCPv6MessageType::SOLICIT {
            if self.config.addresses {
                ias.push(DHCPv6IA::new(DHCPv6OptionCode::IA_NA, self.config.iaid));
            }
            if let Some(length) = self.config.prefix {
                let mut ia = DHCPv6IA::new(DHCPv6OptionCode::IA_PD, self.config.iaid);
                if let Some(length) = length {
                    let hint = DHCPv6IAPrefix {
                        preferred: 0,
                        valid: 0,
                        length,
                        prefix: IPv6Address::UNSPECIFIED,
                        options: DHCPv6Options::new(),
                    };
                    ia.options.push(DHCPv6OptionCode::IAPREFIX, hint.encode()?);
                }
                ias.push(ia);
            }
            return Ok(ias);
        }
        let source = match kind {
            DHCPv6MessageType::REQUEST => self.advertise.as_ref().map(|(_, advertise)| {
                [advertise.options.ias(DHCPv6OptionCode::IA_NA), advertise.options.ias(DHCPv6OptionCode::IA_PD)]
                    .concat()
            }),
            _ => self.lease.as_ref().map(|lease| lease.ias.clone()),
        };
        for mut ia in source.unwrap_or_default() {
            ia.options.remove(DHCPv6OptionCode::STATUS_CODE);
            if kind == DHCPv6MessageType::CONFIRM || kind == DHCPv6MessageType::REQUEST {
                ia.t1 = 0;
                ia.t2 = 0;
            }
            if kind == DHCPv6MessageType::DECLINE {
                let declined: Vec<DHCPv6IAAddress> =
                    ia.addresses().into_iter().filter(|address| self.declined.contains(&address.address)).collect();
                if declined.is_empty() {
                    continue;
                }
                ia.options = DHCPv6Options::new();
                for address in declined {
                    ia.options.push(DHCPv6OptionCode::IAADDR, address.encode()?);
                }
            }
            if kind == DHCPv6MessageType::CONFIRM && ia.kind != DHCPv6OptionCode::IA_NA {
                continue;
            }
            ias.push(ia);
        }
        Ok(ias)
    }

    /// Sends the exchange's message and sets its next timeout.
    pub fn send(&mut self, now: Instant) -> Result<(), DHCPError> {
        let message = self.message(now)?;
        self.transmissions.push_back(message);
        self.sent += 1;
        self.deadline = Some(now.saturating_add(self.timeout));
        Ok(())
    }

    /// Takes `bytes`, a server's Advertise or Reply; ignored unless of the
    /// exchange's transaction, with the client's DUID and a server's (§16).
    pub fn receive<R: Random>(&mut self, bytes: &[u8], now: Instant, random: &mut R) {
        let Ok(message) = DHCPv6Message::decode(bytes) else { return };
        if message.transaction != self.transaction || message.kind == DHCPv6MessageType::RECONFIGURE {
            // A Reconfigure needs the authentication of §20.4, which the client
            // does not offer (it sends no Reconfigure Accept): it is discarded (§18.2.11).
            return;
        }
        let ours = self
            .config
            .duid
            .encode()
            .is_ok_and(|duid| message.options.get(DHCPv6OptionCode::CLIENT_ID) == Some(&duid[..]));
        let Some(server) = message.options.duid(DHCPv6OptionCode::SERVER_ID) else { return };
        if !ours {
            return;
        }
        self.limits(&message.options);
        match (self.state, message.kind) {
            (DHCPv6ClientState::Soliciting, DHCPv6MessageType::ADVERTISE) => {
                if !self.offers(&message.options) {
                    return;
                }
                let preference = message
                    .options
                    .get(DHCPv6OptionCode::PREFERENCE)
                    .and_then(|data| data.first().copied())
                    .unwrap_or(0);
                if self.advertise.as_ref().is_none_or(|(best, _)| preference > *best) {
                    self.advertise = Some((preference, message));
                }
                // §18.2.9: at once for 255, or once the first timeout has passed.
                let waited = self.sent > 1 || now.saturating_duration_since(self.started) >= self.timeout;
                if preference == 255 || waited {
                    self.request(now, random);
                }
            }
            (DHCPv6ClientState::Soliciting, DHCPv6MessageType::REPLY)
                if self.config.rapid_commit && message.options.contains(DHCPv6OptionCode::RAPID_COMMIT) =>
            {
                self.bind(&message, server, now, random);
            }
            (
                DHCPv6ClientState::Requesting | DHCPv6ClientState::Renewing | DHCPv6ClientState::Rebinding,
                DHCPv6MessageType::REPLY,
            ) => {
                let chosen = match self.state {
                    DHCPv6ClientState::Requesting => self
                        .advertise
                        .as_ref()
                        .and_then(|(_, advertise)| advertise.options.duid(DHCPv6OptionCode::SERVER_ID)),
                    DHCPv6ClientState::Renewing => self.lease.as_ref().map(|lease| lease.server.clone()),
                    _ => Some(server.clone()),
                };
                if chosen.as_ref() != Some(&server) {
                    return;
                }
                if message.options.status().is_ok_and(|status| status.code == DHCPv6StatusCode::UNSPEC_FAIL) {
                    return;
                }
                self.bind(&message, server, now, random);
            }
            (DHCPv6ClientState::Confirming, DHCPv6MessageType::REPLY) => match message.options.status() {
                // §18.2.10.1: still on the link; else find a server anew.
                Ok(status) if status.code == DHCPv6StatusCode::SUCCESS => {
                    self.state = DHCPv6ClientState::Bound;
                    self.deadline = self.lease.as_ref().and_then(|lease| lease.at(lease.renewal));
                    if let Some(lease) = &self.lease {
                        self.events.push_back(DHCPv6ClientEvent::Bound(lease.clone()));
                    }
                }
                _ => {
                    self.lease = None;
                    let _ = self.exchange(DHCPv6ClientState::Soliciting, now, random, false);
                }
            },
            (DHCPv6ClientState::Releasing | DHCPv6ClientState::Declining, DHCPv6MessageType::REPLY) => {
                self.end_release(now, random);
            }
            (DHCPv6ClientState::Informing, DHCPv6MessageType::REPLY) => {
                // §21.23: the refresh time, at least IRT_MINIMUM.
                let refresh = message
                    .options
                    .get(DHCPv6OptionCode::INFORMATION_REFRESH_TIME)
                    .and_then(|data| <[u8; 4]>::try_from(data).ok())
                    .map_or(DHCPv6Client::REFRESH_DEFAULT, |data| {
                        Duration::from_secs(u64::from(u32::from_be_bytes(data)))
                    })
                    .max(DHCPv6Client::REFRESH_MINIMUM);
                self.state = DHCPv6ClientState::Informed;
                self.deadline = Some(now.saturating_add(refresh));
                self.events.push_back(DHCPv6ClientEvent::Informed(message.options));
            }
            _ => {}
        }
    }

    /// Takes SOL_MAX_RT and INF_MAX_RT of `options`, from 60 to 86400 s (§21.24, §21.25).
    pub fn limits(&mut self, options: &DHCPv6Options) {
        let value = |code| {
            options
                .get(code)
                .and_then(|data| <[u8; 4]>::try_from(data).ok())
                .map(|data| u64::from(u32::from_be_bytes(data)))
                .filter(|seconds| (60..=86_400).contains(seconds))
                .map(Duration::from_secs)
        };
        if let Some(maximum) = value(DHCPv6OptionCode::SOL_MAX_RT) {
            self.solicit_maximum = maximum;
        }
        if let Some(maximum) = value(DHCPv6OptionCode::INF_MAX_RT) {
            self.information_maximum = maximum;
        }
    }

    /// Whether an Advertise offers anything: not every IA asked for without
    /// addresses or prefixes for lack of them (§18.2.9).
    pub fn offers(&self, options: &DHCPv6Options) -> bool {
        let ias = [options.ias(DHCPv6OptionCode::IA_NA), options.ias(DHCPv6OptionCode::IA_PD)].concat();
        ias.iter().any(|ia| {
            !ia.lifetimes().is_empty()
                && ia.options.status().is_ok_and(|status| status.code == DHCPv6StatusCode::SUCCESS)
        })
    }

    /// Requests from the best Advertise (§18.2.2).
    pub fn request<R: Random>(&mut self, now: Instant, random: &mut R) {
        let _ = self.exchange(DHCPv6ClientState::Requesting, now, random, false);
    }

    /// Binds the IAs of the Reply `reply` of `server` (§18.2.10.1): those
    /// usable ([`DHCPv6IA::usable`]); an IA the server has no binding of is
    /// asked for with a Request. A Reply to Renew or Rebind leaves the IAs
    /// it does not name as they were. T1 and T2 are the least of the IAs it names, or, set
    /// to 0, half and four fifths of the least nonzero preferred lifetime
    /// (or valid, if none is) (§21.4), so never at once (§14.2).
    pub fn bind<R: Random>(&mut self, reply: &DHCPv6Message, server: DHCPDUID, now: Instant, random: &mut R) {
        let ias = [reply.options.ias(DHCPv6OptionCode::IA_NA), reply.options.ias(DHCPv6OptionCode::IA_PD)].concat();
        if matches!(self.state, DHCPv6ClientState::Renewing | DHCPv6ClientState::Rebinding)
            && ias.iter().any(|ia| ia.options.status().is_ok_and(|status| status.code == DHCPv6StatusCode::NO_BINDING))
        {
            self.advertise = Some((0, reply.clone()));
            let _ = self.exchange(DHCPv6ClientState::Requesting, now, random, false);
            return;
        }
        let given: Vec<DHCPv6IA> = ias
            .into_iter()
            .filter(|ia| {
                ia.iaid == self.config.iaid
                    && ia.options.status().is_ok_and(|status| status.code == DHCPv6StatusCode::SUCCESS)
            })
            .filter_map(|ia| ia.usable())
            .collect();
        if given.is_empty() {
            if self.state == DHCPv6ClientState::Requesting || self.state == DHCPv6ClientState::Soliciting {
                let _ = self.exchange(DHCPv6ClientState::Soliciting, now, random, false);
            }
            return;
        }
        // §18.2.10.1: leases the Reply does not name are left unchanged, aged since they were bound.
        let mut bound: Vec<DHCPv6IA> = Vec::new();
        if matches!(self.state, DHCPv6ClientState::Renewing | DHCPv6ClientState::Rebinding)
            && let Some(lease) = &self.lease
        {
            let elapsed = self.started.saturating_duration_since(lease.acquired).as_secs().min(u64::from(u32::MAX));
            bound.extend(
                lease
                    .ias
                    .iter()
                    .filter(|old| !given.iter().any(|ia| ia.kind == old.kind && ia.iaid == old.iaid))
                    .filter_map(|old| old.aged(elapsed as u32).usable()),
            );
        }
        // T1 and T2 are of the IAs the server just answered; the lease lasts as its longest lifetime.
        let seconds = |value: u32| (value != DHCPv6IA::INFINITY).then(|| Duration::from_secs(u64::from(value)));
        let lifetimes: Vec<(u32, u32)> = given.iter().flat_map(DHCPv6IA::lifetimes).collect();
        let preferred = lifetimes
            .iter()
            .map(|(preferred, _)| *preferred)
            .filter(|preferred| *preferred > 0)
            .min()
            .or_else(|| lifetimes.iter().map(|(_, valid)| *valid).min())
            .unwrap_or(0);
        let pick = |of: fn(&DHCPv6IA) -> u32, fraction: (u32, u32)| -> Option<Duration> {
            let least = given.iter().map(of).min().unwrap_or(0);
            match least {
                0 => seconds(preferred).map(|preferred| preferred * fraction.0 / fraction.1),
                value => seconds(value),
            }
        };
        let (renewal, rebinding) = (pick(|ia| ia.t1, (1, 2)), pick(|ia| ia.t2, (4, 5)));
        bound.extend(given);
        let valid = bound.iter().flat_map(DHCPv6IA::lifetimes).map(|(_, valid)| valid).max().unwrap_or(0);
        let lease = DHCPv6Lease {
            server,
            ias: bound.clone(),
            options: reply.options.clone(),
            acquired: self.started,
            renewal,
            rebinding,
            valid: seconds(valid),
        };
        self.state = DHCPv6ClientState::Bound;
        self.deadline = lease.at(lease.renewal).or(lease.at(lease.valid));
        self.lease = Some(lease.clone());
        self.events.push_back(DHCPv6ClientEvent::Bound(lease));
    }

    /// Releases the lease (§18.2.7); the client stops.
    pub fn release<R: Random>(&mut self, now: Instant, random: &mut R) -> Result<(), DHCPError> {
        if self.lease.is_none() {
            return Err(DHCPError::State);
        }
        self.exchange(DHCPv6ClientState::Releasing, now, random, false)
    }

    /// Declines `addresses` of the lease, which DAD found in use (§18.2.8).
    pub fn decline<R: Random>(
        &mut self,
        addresses: Vec<IPv6Address>,
        now: Instant,
        random: &mut R,
    ) -> Result<(), DHCPError> {
        if self.lease.is_none() || addresses.is_empty() {
            return Err(DHCPError::State);
        }
        self.declined = addresses;
        self.exchange(DHCPv6ClientState::Declining, now, random, false)
    }

    /// Confirms the lease after the link may have changed (§18.2.3).
    pub fn confirm<R: Random>(&mut self, now: Instant, random: &mut R) -> Result<(), DHCPError> {
        if self.lease.is_none() {
            return Err(DHCPError::State);
        }
        self.exchange(DHCPv6ClientState::Confirming, now, random, true)
    }

    /// The end of a Release or Decline: told, the lease or the declined addresses gone.
    pub fn end_release<R: Random>(&mut self, now: Instant, random: &mut R) {
        let declining = self.state == DHCPv6ClientState::Declining;
        self.events.push_back(DHCPv6ClientEvent::Released);
        if declining {
            // §18.2.8: the declined addresses are gone; for new ones, Solicit again.
            self.lease = None;
            self.declined.clear();
            let _ = self.exchange(DHCPv6ClientState::Soliciting, now, random, false);
        } else {
            self.lease = None;
            self.state = DHCPv6ClientState::Init;
            self.deadline = None;
        }
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        self.deadline
    }

    /// What is due at `now`: a delayed first message, a retransmission or
    /// the end of an exchange (§15), Renew at T1, Rebind at T2, the end of
    /// the lease, or a refresh of stateless configuration (§18.2.12).
    pub fn expire<R: Random>(&mut self, now: Instant, random: &mut R) {
        if self.deadline.is_none_or(|deadline| now < deadline) {
            return;
        }
        match self.state {
            DHCPv6ClientState::Init => {}
            DHCPv6ClientState::Informed => {
                let _ = self.exchange(DHCPv6ClientState::Informing, now, random, false);
            }
            DHCPv6ClientState::Bound => {
                let Some(lease) = &self.lease else { return };
                if lease.at(lease.valid).is_some_and(|end| now >= end) {
                    self.expired(now, random);
                    return;
                }
                let state = match lease.at(lease.rebinding) {
                    Some(rebinding) if now >= rebinding => DHCPv6ClientState::Rebinding,
                    _ => DHCPv6ClientState::Renewing,
                };
                let _ = self.exchange(state, now, random, false);
            }
            _ if self.sent == 0 => {
                let _ = self.send(now);
            }
            DHCPv6ClientState::Soliciting if self.advertise.is_some() => self.request(now, random),
            state => {
                if !self.retransmission.is_over(self.sent, self.started, now) {
                    self.timeout = self.retransmission.next(self.timeout, random);
                    if let Some(duration) = self.retransmission.duration {
                        // MRD: the last timeout ends with the exchange.
                        let end = self.started.saturating_add(duration);
                        self.timeout =
                            self.timeout.min(end.saturating_duration_since(now)).max(Duration::from_millis(1));
                    }
                    let _ = self.send(now);
                    return;
                }
                match state {
                    DHCPv6ClientState::Renewing => {
                        let _ = self.exchange(DHCPv6ClientState::Rebinding, now, random, false);
                    }
                    DHCPv6ClientState::Rebinding => self.expired(now, random),
                    DHCPv6ClientState::Releasing | DHCPv6ClientState::Declining => self.end_release(now, random),
                    DHCPv6ClientState::Confirming => {
                        // §18.2.3: no answer to Confirm, the lease is kept.
                        self.state = DHCPv6ClientState::Bound;
                        self.deadline = self.lease.as_ref().and_then(|lease| lease.at(lease.renewal));
                    }
                    _ => {
                        self.events.push_back(DHCPv6ClientEvent::Unanswered);
                        let _ = self.exchange(DHCPv6ClientState::Soliciting, now, random, false);
                    }
                }
            }
        }
    }

    /// The lease ended: told, and servers solicited anew.
    pub fn expired<R: Random>(&mut self, now: Instant, random: &mut R) {
        self.lease = None;
        self.events.push_back(DHCPv6ClientEvent::Expired);
        let _ = self.exchange(DHCPv6ClientState::Soliciting, now, random, false);
    }

    pub fn transmit(&mut self) -> Option<DHCPv6Message> {
        self.transmissions.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<DHCPv6ClientEvent> {
        self.events.pop_front()
    }
}
