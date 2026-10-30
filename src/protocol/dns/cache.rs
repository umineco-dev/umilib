use alloc::collections::BTreeMap;
use core::time::Duration;

use crate::runtime::Instant;

use super::{DNSData, DNSError, DNSMessage, DNSQuestion, DNSResponseCode, DNSType};

/// The limits of a cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DNSCacheConfig {
    /// The most entries; when full, the one that expires first goes.
    pub maximum_entries: usize,
    /// No answer is kept longer, whatever its TTL (RFC 8767 §4 suggests 7
    /// days at most; a day is less).
    pub maximum_ttl: Duration,
    /// No answer is kept shorter.
    pub minimum_ttl: Duration,
    /// No negative answer is kept longer (RFC 2308 §5: one to three hours).
    pub maximum_negative_ttl: Duration,
    /// How long a failure is kept (RFC 9520 §3.2: at least a second, at
    /// most five minutes); zero keeps none.
    pub failure_ttl: Duration,
}

impl Default for DNSCacheConfig {
    fn default() -> DNSCacheConfig {
        DNSCacheConfig {
            maximum_entries: 4096,
            maximum_ttl: Duration::from_secs(86_400),
            minimum_ttl: Duration::ZERO,
            maximum_negative_ttl: Duration::from_secs(3 * 3600),
            failure_ttl: Duration::from_secs(5),
        }
    }
}

/// A cached answer: the response or the failure, when it was stored and
/// when it expires.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSCacheEntry {
    pub result: Result<DNSMessage, DNSError>,
    pub stored: Instant,
    pub expires: Instant,
}

/// A cache of responses by question (RFC 1034 §4.3.4): positive answers
/// for their least TTL, negative ones for the TTL of RFC 2308 §5, failures
/// briefly (RFC 9520).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DNSCache {
    pub config: DNSCacheConfig,
    pub entries: BTreeMap<DNSQuestion, DNSCacheEntry>,
}

impl DNSCache {
    pub fn new(config: DNSCacheConfig) -> DNSCache {
        DNSCache { config, entries: BTreeMap::new() }
    }

    /// How long `response` may be kept: the least TTL of its answer, or,
    /// for NXDOMAIN and no data, the lesser of the SOA's TTL and minimum
    /// (RFC 2308 §5), within the configured bounds. A negative answer
    /// without an SOA is not kept (§5); nor is an answer of another code.
    pub fn lifetime(&self, response: &DNSMessage) -> Option<Duration> {
        let rcode = response.rcode();
        let ttl = match rcode {
            DNSResponseCode::NOERROR if !response.answers.is_empty() => {
                response.answers.iter().map(|record| record.ttl).min()?
            }
            DNSResponseCode::NOERROR | DNSResponseCode::NXDOMAIN => {
                let soa = response.authorities.iter().find(|record| record.kind == DNSType::SOA)?;
                let DNSData::SOA(data) = &soa.data else { return None };
                let ttl = soa.ttl.min(data.minimum);
                return Some(
                    Duration::from_secs(u64::from(ttl))
                        .min(self.config.maximum_negative_ttl)
                        .max(self.config.minimum_ttl),
                );
            }
            _ => return None,
        };
        Some(Duration::from_secs(u64::from(ttl)).min(self.config.maximum_ttl).max(self.config.minimum_ttl))
    }

    /// Keeps `result` for `question` from `now`: a response for its
    /// lifetime, a failure (an error, or SERVFAIL) for the failure TTL.
    pub fn insert(&mut self, question: &DNSQuestion, result: Result<DNSMessage, DNSError>, now: Instant) {
        let lifetime = match &result {
            Ok(response) if response.rcode() != DNSResponseCode::SERVFAIL => self.lifetime(response),
            _ => Some(self.config.failure_ttl),
        };
        let Some(lifetime) = lifetime.filter(|lifetime| !lifetime.is_zero()) else { return };
        if self.config.maximum_entries == 0 {
            return;
        }
        self.expire(now);
        let key = DNSQuestion { name: question.name.canonical(), ..question.clone() };
        if self.entries.len() >= self.config.maximum_entries && !self.entries.contains_key(&key) {
            let first =
                self.entries.iter().min_by_key(|(_, entry)| entry.expires).map(|(question, _)| question.clone());
            if let Some(first) = first {
                self.entries.remove(&first);
            }
        }
        self.entries.insert(key, DNSCacheEntry { result, stored: now, expires: now.saturating_add(lifetime) });
    }

    /// The result kept for `question` at `now`, the TTLs of its records less
    /// the time it has been kept (RFC 1035 §7.4), and at most the time it
    /// is still kept (the configured bounds included).
    pub fn get(&self, question: &DNSQuestion, now: Instant) -> Option<Result<DNSMessage, DNSError>> {
        let key = DNSQuestion { name: question.name.canonical(), ..question.clone() };
        let entry = self.entries.get(&key).filter(|entry| now < entry.expires)?;
        let elapsed = now.saturating_duration_since(entry.stored).as_secs().min(u64::from(u32::MAX)) as u32;
        let left = entry.expires.saturating_duration_since(now).as_secs().min(u64::from(u32::MAX)) as u32;
        let mut result = entry.result.clone();
        if let Ok(response) = &mut result {
            for record in response.answers.iter_mut().chain(&mut response.authorities).chain(&mut response.additionals)
            {
                record.ttl = record.ttl.saturating_sub(elapsed).min(left);
            }
        }
        Some(result)
    }

    /// Removes the entries expired at `now`.
    pub fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, entry| now < entry.expires);
    }
}
