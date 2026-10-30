use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use crate::bytes::{Reader, Writer};
use crate::crypto::random::Random;
use crate::runtime::SpinLock;
use crate::secret::Secret;

use super::{TLSAEAD, TLSAEADAlgorithm, TLSCipherSuite, TLSError, TLSVector, TLSVersion};

/// A session that can be resumed (RFC 9846 §4.6.1): what a server seals in
/// a ticket, and what a client keeps with the ticket.
#[derive(Clone, Debug)]
pub struct TLSSessionState {
    pub version: TLSVersion,
    pub cipher_suite: TLSCipherSuite,
    /// The PSK the ticket stands for: HKDF-Expand-Label(resumption secret,
    /// "resumption", ticket_nonce) (RFC 9846 §4.6.1).
    pub psk: Secret<Vec<u8>>,
    /// When the ticket was issued (the server's) or received (the
    /// client's), in seconds since 1970.
    pub time: i64,
    /// Seconds from `time` the ticket may be used, at most seven days.
    pub lifetime: u32,
    pub age_add: u32,
    /// The most early data the ticket allows; 0 if none (RFC 9846 §4.3.10).
    pub maximum_early_data: u32,
    /// The application protocol of the session, which 0-RTT keeps (RFC 9846 §4.3.10).
    pub protocol: Option<Vec<u8>>,
    /// The name the session was for (`server_name`), which a resumption must ask for again.
    pub server_name: Option<String>,
    /// The peer's certificate chain in the session, if it had one.
    pub peer_certificates: Vec<Vec<u8>>,
    /// The application's data of the session ([`TLSSession::application`](super::TLSSession::application)):
    /// a server accepts early data only when it is the same again.
    pub application: Vec<u8>,
}

impl TLSSessionState {
    /// Whether the ticket may still be used at `time` (RFC 9846 §4.6.1).
    pub fn is_current(&self, time: i64) -> bool {
        time >= self.time && time.abs_diff(self.time) < u64::from(self.lifetime)
    }

    /// The client's `obfuscated_ticket_age` at `time`: the age in
    /// milliseconds plus `age_add`, modulo 2^32 (RFC 9846 §4.3.11.1).
    pub fn obfuscated_age(&self, time: i64) -> u32 {
        let age = if time > self.time { time.abs_diff(self.time).wrapping_mul(1000) } else { 0 };
        (age as u32).wrapping_add(self.age_add)
    }

    /// Whether a ClientHello whose ticket age is `obfuscated_age` arrives
    /// at `time` within `window` seconds of when it should (RFC 9846 §8.3):
    /// the freshness check that 0-RTT needs.
    pub fn is_fresh(&self, obfuscated_age: u32, time: i64, window: i64) -> bool {
        let age = i64::from(obfuscated_age.wrapping_sub(self.age_add));
        let expected = self.time.saturating_mul(1000).saturating_add(age);
        time.saturating_mul(1000).abs_diff(expected) <= window.max(0).unsigned_abs().saturating_mul(1000)
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write_be(self.version.0)?;
        out.write_be(self.cipher_suite.0)?;
        TLSVector::write(out, 1, 0xFF, self.psk.expose())?;
        out.write_be(self.time as u64)?;
        out.write_be(self.lifetime)?;
        out.write_be(self.age_add)?;
        out.write_be(self.maximum_early_data)?;
        TLSVector::write(out, 1, 0xFF, self.protocol.as_deref().unwrap_or(&[]))?;
        TLSVector::write(out, 2, 0xFFFF, self.server_name.as_deref().unwrap_or("").as_bytes())?;
        TLSVector::write_with(out, 3, 0xFF_FFFF, |list| {
            self.peer_certificates.iter().try_for_each(|certificate| TLSVector::write(list, 3, 0xFF_FFFF, certificate))
        })?;
        TLSVector::write(out, 2, 0xFFFF, &self.application)
    }

    pub fn decode(bytes: &[u8]) -> Result<TLSSessionState, TLSError> {
        let mut reader = Reader::new(bytes);
        let decode = |_| TLSError::decode();
        let version = TLSVersion(reader.read_be().map_err(decode)?);
        let cipher_suite = TLSCipherSuite(reader.read_be().map_err(decode)?);
        let psk = Secret::new(TLSVector::read(&mut reader, 1, 1, 0xFF)?.to_vec());
        let time = reader.read_be::<u64>().map_err(decode)? as i64;
        let lifetime = reader.read_be().map_err(decode)?;
        let age_add = reader.read_be().map_err(decode)?;
        let maximum_early_data = reader.read_be().map_err(decode)?;
        let protocol = TLSVector::read(&mut reader, 1, 0, 0xFF)?.to_vec();
        let server_name = TLSVector::read(&mut reader, 2, 0, 0xFFFF)?.to_vec();
        let mut list = TLSVector::read_reader(&mut reader, 3, 0, 0xFF_FFFF)?;
        let application = TLSVector::read(&mut reader, 2, 0, 0xFFFF)?.to_vec();
        TLSVector::finish(&reader)?;
        let mut peer_certificates = Vec::new();
        while !list.is_empty() {
            peer_certificates.push(TLSVector::read(&mut list, 3, 1, 0xFF_FFFF)?.to_vec());
        }
        Ok(TLSSessionState {
            version,
            cipher_suite,
            psk,
            time,
            lifetime,
            age_add,
            maximum_early_data,
            protocol: (!protocol.is_empty()).then_some(protocol),
            server_name: (!server_name.is_empty())
                .then(|| String::from_utf8(server_name).map_err(|_| TLSError::decode()))
                .transpose()?,
            peer_certificates,
            application,
        })
    }
}

/// A ticket a client received and the session it resumes.
#[derive(Clone, Debug)]
pub struct TLSSessionTicket {
    /// The ticket, opaque to the client.
    pub ticket: Vec<u8>,
    pub state: TLSSessionState,
}

/// What turns a server's session state into a ticket and back. Tickets
/// must be confidential and authentic: [`TLSTicketKeys`] seals them with
/// an AEAD (RFC 9846 §4.6.1 leaves the format to the server).
pub trait TLSTicketer: Send + Sync {
    /// The ticket of `state`, or `None` if it cannot make one.
    fn seal(&self, state: &[u8], random: &mut dyn Random) -> Option<Vec<u8>>;

    /// The state of a ticket this ticketer made, or `None`.
    fn open(&self, ticket: &[u8]) -> Option<Vec<u8>>;
}

/// A key of [`TLSTicketKeys`]: its name, which tickets carry, and AES-256-GCM.
#[derive(Debug)]
pub struct TLSTicketKey {
    pub name: [u8; 16],
    pub aead: TLSAEAD,
}

impl TLSTicketKey {
    pub fn new(name: [u8; 16], key: &[u8; 32]) -> Result<TLSTicketKey, TLSError> {
        Ok(TLSTicketKey { name, aead: TLSAEAD::new(TLSAEADAlgorithm::AES256GCM, key)? })
    }

    /// A key of random name and value.
    pub fn generate(random: &mut dyn Random) -> Result<TLSTicketKey, TLSError> {
        let mut name = [0u8; 16];
        let mut key = Secret::new([0u8; 32]);
        random.fill(&mut name).map_err(|_| TLSError::Config)?;
        random.fill(key.expose_mut()).map_err(|_| TLSError::Config)?;
        TLSTicketKey::new(name, key.expose())
    }
}

/// Tickets sealed with AES-256-GCM: the key's name (16 bytes), a random
/// nonce (12 bytes), then the sealed state, whose additional data is the
/// name. The first key seals; every key opens, so a key is rotated by
/// putting the new one first and keeping the old one until its tickets
/// expire.
#[derive(Debug)]
pub struct TLSTicketKeys {
    pub keys: Vec<TLSTicketKey>,
}

impl TLSTicketKeys {
    pub const NONCE_LENGTH: usize = 12;

    pub fn new(keys: Vec<TLSTicketKey>) -> TLSTicketKeys {
        TLSTicketKeys { keys }
    }
}

impl TLSTicketer for TLSTicketKeys {
    fn seal(&self, state: &[u8], random: &mut dyn Random) -> Option<Vec<u8>> {
        let key = self.keys.first()?;
        let mut nonce = [0u8; TLSTicketKeys::NONCE_LENGTH];
        random.fill(&mut nonce).ok()?;
        let mut sealed = state.to_vec();
        key.aead.seal(&nonce, &key.name, &mut sealed).ok()?;
        let mut ticket = Vec::with_capacity(key.name.len() + nonce.len() + sealed.len());
        ticket.extend_from_slice(&key.name);
        ticket.extend_from_slice(&nonce);
        ticket.extend_from_slice(&sealed);
        Some(ticket)
    }

    fn open(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        let (name, rest) = ticket.split_first_chunk::<16>()?;
        let (nonce, sealed) = rest.split_first_chunk::<{ TLSTicketKeys::NONCE_LENGTH }>()?;
        let key = self.keys.iter().find(|key| key.name == *name)?;
        let mut state = sealed.to_vec();
        key.aead.open(nonce, name, &mut state).ok()?;
        Some(state)
    }
}

/// Where a client keeps the tickets it received, by the name of the server
/// it connected to. A ticket is used once (RFC 9846 Appendix C.4), so
/// `take` removes it.
pub trait TLSSessionStore: Send + Sync {
    fn put(&self, name: &str, ticket: TLSSessionTicket);

    /// The most recent ticket for `name`, removed.
    fn take(&self, name: &str) -> Option<TLSSessionTicket>;
}

/// A [`TLSSessionStore`] in memory: the most recent `capacity` tickets of
/// all names; the oldest is dropped when it is full.
#[derive(Debug)]
pub struct TLSSessionCache {
    pub capacity: usize,
    pub tickets: SpinLock<VecDeque<(String, TLSSessionTicket)>>,
}

impl TLSSessionCache {
    pub fn new(capacity: usize) -> TLSSessionCache {
        TLSSessionCache { capacity, tickets: SpinLock::new(VecDeque::new()) }
    }
}

impl TLSSessionStore for TLSSessionCache {
    fn put(&self, name: &str, ticket: TLSSessionTicket) {
        if self.capacity == 0 {
            return;
        }
        let mut tickets = self.tickets.lock();
        if tickets.len() == self.capacity {
            tickets.pop_front();
        }
        tickets.push_back((String::from(name), ticket));
    }

    fn take(&self, name: &str) -> Option<TLSSessionTicket> {
        let mut tickets = self.tickets.lock();
        let position = tickets.iter().rposition(|(stored, _)| stored == name)?;
        tickets.remove(position).map(|(_, ticket)| ticket)
    }
}

/// What lets a server accept 0-RTT data only once (RFC 9846 §8): each
/// ClientHello that carries early data is presented by its PSK binder,
/// which is unique to it.
pub trait TLSAntiReplay: Send + Sync {
    /// Whether the early data of the ClientHello of `binder`, at `time`
    /// (seconds since 1970), may be accepted; it is recorded so that a
    /// replay is not.
    fn accept(&self, binder: &[u8], time: i64) -> bool;
}

/// ClientHello recording (RFC 9846 §8.2): the binders seen while a replay
/// of them could still pass the freshness check (§8.3) with the same
/// `window`. A ClientHello is fresh within `window` seconds of when it
/// should arrive, so its replay may come up to twice the window after the
/// first one, and a second more for the whole seconds of both checks: a
/// binder is kept 2 × `window` + 2 seconds. When `capacity` binders are
/// recorded, early data is refused until some expire: refusing is always safe.
#[derive(Debug)]
pub struct TLSReplayCache {
    pub window: i64,
    pub capacity: usize,
    /// Each binder seen and when.
    pub seen: SpinLock<BTreeMap<Vec<u8>, i64>>,
}

impl TLSReplayCache {
    pub fn new(window: i64, capacity: usize) -> TLSReplayCache {
        TLSReplayCache { window, capacity, seen: SpinLock::new(BTreeMap::new()) }
    }
}

impl TLSAntiReplay for TLSReplayCache {
    fn accept(&self, binder: &[u8], time: i64) -> bool {
        let mut seen = self.seen.lock();
        let kept = self.window.saturating_mul(2).saturating_add(2);
        seen.retain(|_, seen_at| time.saturating_sub(*seen_at) <= kept);
        if seen.contains_key(binder) || seen.len() >= self.capacity {
            return false;
        }
        seen.insert(binder.to_vec(), time);
        true
    }
}
