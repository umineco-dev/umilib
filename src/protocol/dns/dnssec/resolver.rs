use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::crypto::random::Random;
use crate::runtime::Instant;

use super::super::{
    DNSData, DNSError, DNSExtendedError, DNSMessage, DNSName, DNSQuestion, DNSRecord, DNSResolver, DNSResolverConfig,
    DNSResolverEvent, DNSResponseCode, DNSTransmission, DNSTransport, DNSType,
};
use super::{DNSSECConfig, DNSSECNSEC, DNSSECNSEC3, DNSSECProof, DNSSECTrust, DNSSECTrustAnchor, DNSSECValidator};

/// What the data of a name is, once its zone is known (RFC 4035 §4.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DNSSECZoneTrust {
    /// The name is in `zone`, whose DNSKEY RRset `keys` is secure.
    Secure { zone: DNSName, keys: Vec<DNSRecord> },
    /// The name is in an unsigned zone, or below no trust anchor, with the
    /// extended error that tells why, if one does.
    Insecure(Option<u16>),
    /// What should prove either does not.
    Bogus(DNSError),
}

/// What a validation needs or gives.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DNSSECStep<T> {
    Done(T),
    /// The response to this question, which is to be asked.
    Need(DNSQuestion),
}

/// The status of a validated answer (RFC 4035 §4.3); a bogus one is an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DNSSECStatus {
    Secure,
    Insecure(Option<u16>),
}

/// What a validating resolver tells.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DNSSECResolverEvent {
    /// The question is answered: the response, with AD set if it is secure
    /// and its TTLs at most what its signatures allow (RFC 4035 §5.3.3),
    /// and its status; or the error, bogus for a failed validation.
    Resolved { query: u64, question: DNSQuestion, result: Result<(DNSMessage, DNSSECStatus), DNSError> },
}

/// A question asked by the user, and its response once it came.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSSECValidation {
    pub question: DNSQuestion,
    pub response: Option<DNSMessage>,
    /// The questions asked to validate it.
    pub asked: usize,
}

/// A validating stub resolver (RFC 4035 §4.9.3): it asks with DO and CD
/// (§3.2.2), and validates every answer itself from a trust anchor down:
/// each zone's keys by the DS records its parent signs or the anchor,
/// each RRset by its zone's keys, and each denial by its NSEC or NSEC3
/// records; for that it asks the DS and DNSKEY questions it needs, through
/// the same [`DNSResolver`]. A name whose zone is unsigned is insecure,
/// as its parent proves (§5.2); a name below no anchor is insecure too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DNSSECResolver {
    pub resolver: DNSResolver,
    pub validator: DNSSECValidator,
    pub anchor: DNSSECTrustAnchor,
    /// The most questions asked to validate one answer.
    pub maximum_questions: usize,
    pub validations: BTreeMap<u64, DNSSECValidation>,
    /// The questions asked to validate, by query, and their responses once
    /// come, each until it expires: as long as the resolver's cache would
    /// keep it (RFC 2308 §5, RFC 9520 §3.2), at most as many as it keeps.
    pub asked: BTreeMap<u64, DNSQuestion>,
    pub responses: BTreeMap<DNSQuestion, (Result<DNSMessage, DNSError>, Instant)>,
    /// What each name's data is, as found, and until when.
    pub trusts: BTreeMap<DNSName, (DNSSECZoneTrust, Instant)>,
    pub events: VecDeque<DNSSECResolverEvent>,
}

impl DNSSECResolver {
    /// The most questions asked to validate one answer, by default.
    pub const MAXIMUM_QUESTIONS: usize = 64;
    /// The least time a response asked to validate is kept, so that the
    /// validations waiting for it take it.
    pub const MINIMUM_HOLD: core::time::Duration = core::time::Duration::from_secs(1);

    /// A resolver of `config`, whose queries are made with DO and CD, of
    /// `validator` and the trust anchor `anchor`.
    pub fn new<R: Random>(
        mut config: DNSResolverConfig,
        validator: DNSSECConfig,
        anchor: DNSSECTrustAnchor,
        random: &mut R,
    ) -> Result<DNSSECResolver, DNSError> {
        config.edns = true;
        config.dnssec_ok = true;
        config.checking_disabled = true;
        Ok(DNSSECResolver {
            resolver: DNSResolver::new(config, random)?,
            validator: DNSSECValidator::new(validator),
            anchor,
            maximum_questions: DNSSECResolver::MAXIMUM_QUESTIONS,
            validations: BTreeMap::new(),
            asked: BTreeMap::new(),
            responses: BTreeMap::new(),
            trusts: BTreeMap::new(),
            events: VecDeque::new(),
        })
    }

    /// Starts resolving and validating `question`.
    pub fn resolve<R: Random>(
        &mut self,
        question: DNSQuestion,
        now: Instant,
        time: u64,
        random: &mut R,
    ) -> Result<u64, DNSError> {
        let query = self.resolver.resolve(question.clone(), now, random)?;
        self.validations.insert(query, DNSSECValidation { question, response: None, asked: 0 });
        self.drain(now, time, random);
        Ok(query)
    }

    pub fn transmit(&mut self) -> Option<DNSTransmission> {
        self.resolver.transmit()
    }

    /// [`DNSResolver::receive`], then the validations it allows, at `now`
    /// and `time` (seconds since 1970, for the signatures' validity).
    #[allow(clippy::too_many_arguments)]
    pub fn receive<R: Random>(
        &mut self,
        query: u64,
        upstream: usize,
        transport: DNSTransport,
        bytes: &[u8],
        now: Instant,
        time: u64,
        random: &mut R,
    ) {
        self.resolver.receive(query, upstream, transport, bytes, now, random);
        self.drain(now, time, random);
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        self.resolver.poll_timeout()
    }

    /// [`DNSResolver::expire`], then the validations it allows.
    pub fn expire<R: Random>(&mut self, now: Instant, time: u64, random: &mut R) {
        self.resolver.expire(now, random);
        self.trusts.retain(|_, (_, until)| now < *until);
        self.responses.retain(|_, (_, until)| now < *until);
        self.drain(now, time, random);
    }

    pub fn poll_event(&mut self) -> Option<DNSSECResolverEvent> {
        self.events.pop_front()
    }

    /// Takes the resolver's answers and goes on with every validation.
    pub fn drain<R: Random>(&mut self, now: Instant, time: u64, random: &mut R) {
        loop {
            let mut progressed = false;
            while let Some(DNSResolverEvent::Resolved { query, question, result }) = self.resolver.poll_event() {
                progressed = true;
                if self.asked.remove(&query).is_some() {
                    self.keep(question, result, now);
                    continue;
                }
                let Some(validation) = self.validations.get_mut(&query) else { continue };
                match result {
                    Ok(response) => validation.response = Some(response),
                    Err(error) => {
                        let question =
                            self.validations.remove(&query).map(|validation| validation.question).unwrap_or(question);
                        self.events.push_back(DNSSECResolverEvent::Resolved { query, question, result: Err(error) });
                    }
                }
            }
            let ready: Vec<u64> = self
                .validations
                .iter()
                .filter(|(_, validation)| validation.response.is_some())
                .map(|(query, _)| *query)
                .collect();
            for query in ready {
                let Some(validation) = self.validations.get(&query) else { continue };
                let (question, response) =
                    (validation.question.clone(), validation.response.clone().unwrap_or_default());
                match self.validate(&question, &response, now, time) {
                    DNSSECStep::Done(result) => {
                        self.validations.remove(&query);
                        let result = result.map(|(status, authentic)| {
                            (DNSSECResolver::mark(response, status, authentic, time as u32), status)
                        });
                        self.events.push_back(DNSSECResolverEvent::Resolved { query, question, result });
                    }
                    DNSSECStep::Need(needed) => {
                        if self.asked.values().any(|asked| *asked == needed) {
                            continue;
                        }
                        let Some(validation) = self.validations.get_mut(&query) else { continue };
                        validation.asked += 1;
                        let exhausted = validation.asked > self.maximum_questions;
                        let asked = (!exhausted).then(|| self.resolver.resolve(needed.clone(), now, random));
                        match asked {
                            Some(Ok(handle)) => {
                                self.asked.insert(handle, needed);
                                progressed = true;
                            }
                            _ => {
                                self.validations.remove(&query);
                                let error = DNSError::Bogus {
                                    code: DNSExtendedError::DNSSEC_INDETERMINATE,
                                    reason: "too many questions to validate",
                                };
                                self.events.push_back(DNSSECResolverEvent::Resolved {
                                    query,
                                    question,
                                    result: Err(error),
                                });
                            }
                        }
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        if self.validations.is_empty() && self.asked.is_empty() {
            self.responses.clear();
        }
    }

    /// Keeps `result`, the response to `question` asked to validate, for
    /// as long as the resolver's cache would, and no more responses than it keeps.
    pub fn keep(&mut self, question: DNSQuestion, result: Result<DNSMessage, DNSError>, now: Instant) {
        let lifetime = result.as_ref().ok().and_then(|response| self.resolver.cache.lifetime(response));
        let hold = lifetime.unwrap_or(self.resolver.config.cache.failure_ttl).max(DNSSECResolver::MINIMUM_HOLD);
        self.responses.insert(question, (result, now.saturating_add(hold)));
        while self.responses.len() > self.resolver.config.cache.maximum_entries.max(1) {
            let first =
                self.responses.iter().min_by_key(|(_, (_, until))| *until).map(|(question, _)| question.clone());
            let Some(first) = first else { break };
            self.responses.remove(&first);
        }
    }

    /// `response` with AD set if `status` is secure (RFC 4035 §3.2.3); a
    /// secure one keeps of its authority section only `authentic`, the
    /// records validated, and none of its additional section, which
    /// nothing validated, and its TTLs are at most what its signatures
    /// allow at `time` (RFC 4035 §5.3.3).
    pub fn mark(mut response: DNSMessage, status: DNSSECStatus, authentic: Vec<DNSRecord>, time: u32) -> DNSMessage {
        response.header.authentic_data = status == DNSSECStatus::Secure;
        if status == DNSSECStatus::Secure {
            response.authorities = authentic;
            response.additionals.clear();
            DNSSECResolver::cap(&mut response.answers, time);
            DNSSECResolver::cap(&mut response.authorities, time);
        }
        response
    }

    /// Lowers the TTL of each RRset of `records` and of its signatures to
    /// the original TTL and the time left at `time` of every signature
    /// that covers it (RFC 4035 §5.3.3).
    pub fn cap(records: &mut [DNSRecord], time: u32) {
        let limits: Vec<(DNSName, DNSType, u32)> = records
            .iter()
            .filter_map(|record| match &record.data {
                DNSData::RRSIG(rrsig) => Some((
                    record.name.clone(),
                    rrsig.type_covered,
                    rrsig.original_ttl.min(rrsig.expiration.wrapping_sub(time)),
                )),
                _ => None,
            })
            .collect();
        for record in records.iter_mut() {
            let kind = match &record.data {
                DNSData::RRSIG(rrsig) => rrsig.type_covered,
                _ => record.kind,
            };
            for (name, covered, limit) in &limits {
                if record.name == *name && kind == *covered {
                    record.ttl = record.ttl.min(*limit);
                }
            }
        }
    }

    /// The response to `question` asked to validate, unexpired at `now`, or the need to ask it.
    pub fn fetch(&self, question: DNSQuestion, now: Instant) -> Result<&DNSMessage, DNSSECStep<DNSSECZoneTrust>> {
        match self.responses.get(&question) {
            Some((Ok(response), until)) if now < *until => Ok(response),
            Some((Err(error), until)) if now < *until => Err(DNSSECStep::Done(DNSSECZoneTrust::Bogus(*error))),
            _ => Err(DNSSECStep::Need(question)),
        }
    }

    /// The RRsets of `records` that `zone` signs, with their signatures:
    /// what a denial of `zone` may use, among the records of other zones a
    /// response may carry.
    pub fn signed_by(records: &[DNSRecord], zone: &DNSName) -> Vec<DNSRecord> {
        let signs = |name: &DNSName, kind: DNSType| {
            records.iter().any(|record| {
                matches!(&record.data, DNSData::RRSIG(rrsig)
                    if record.name == *name && rrsig.type_covered == kind && rrsig.signer == *zone)
            })
        };
        records
            .iter()
            .filter(|record| match &record.data {
                DNSData::RRSIG(rrsig) => rrsig.signer == *zone,
                _ => signs(&record.name, record.kind),
            })
            .cloned()
            .collect()
    }

    /// What the data of `name` is (see [`DNSSECZoneTrust`]): for the
    /// anchor's zone, its DNSKEY RRset checked against the anchor; for
    /// another name, its DS RRset signed by the zone above it, then its
    /// DNSKEY RRset checked against that; or, without DS, the denial of
    /// the zone above it, which tells whether the name is an unsigned
    /// delegation or only a name of that zone (RFC 4035 §5.2).
    /// What is found is kept for as long as the records that tell it.
    pub fn trust(&mut self, name: &DNSName, now: Instant, time: u64) -> DNSSECStep<DNSSECZoneTrust> {
        if let Some((trust, until)) = self.trusts.get(&name.canonical())
            && now < *until
        {
            return DNSSECStep::Done(trust.clone());
        }
        let (step, ttl) = self.find_trust(name, now, time);
        if let (DNSSECStep::Done(trust), Some(ttl)) = (&step, ttl)
            && !matches!(trust, DNSSECZoneTrust::Bogus(_))
        {
            let until = now.saturating_add(core::time::Duration::from_secs(u64::from(ttl)));
            self.trusts.insert(name.canonical(), (trust.clone(), until));
        }
        step
    }

    /// [`DNSSECResolver::trust`] found anew, and for how long (seconds) it may be kept.
    pub fn find_trust(
        &mut self,
        name: &DNSName,
        now: Instant,
        time: u64,
    ) -> (DNSSECStep<DNSSECZoneTrust>, Option<u32>) {
        let bogus = |error: DNSError| (DNSSECStep::Done(DNSSECZoneTrust::Bogus(error)), None);
        let seconds = time as u32;
        if !name.is_subdomain_of(&self.anchor.zone) {
            return (DNSSECStep::Done(DNSSECZoneTrust::Insecure(None)), None);
        }
        if *name == self.anchor.zone {
            let response = match self.fetch(DNSQuestion::new(name.clone(), DNSType::DNSKEY), now) {
                Ok(response) => response,
                Err(step) => return (step, None),
            };
            let own = DNSSECResolver::of(&response.answers, name, DNSType::DNSKEY);
            let anchors = self.anchor.delegations(time as i64);
            return match self.validator.verify_keys(&own, &response.answers, &anchors, seconds) {
                Ok(DNSSECTrust::Secure(verified)) => {
                    (DNSSECStep::Done(DNSSECZoneTrust::Secure { zone: name.clone(), keys: own }), Some(verified.ttl))
                }
                Ok(DNSSECTrust::Insecure(code)) => (DNSSECStep::Done(DNSSECZoneTrust::Insecure(Some(code))), None),
                Err(error) => bogus(error),
            };
        }
        let response = match self.fetch(DNSQuestion::new(name.clone(), DNSType::DS), now) {
            Ok(response) => response.clone(),
            Err(step) => return (step, None),
        };
        let parent = name.parent().unwrap_or_else(DNSName::root);
        // A CNAME at the name: no zone is cut there (RFC 2181 §10.1), the
        // name is of its parent's zone, which signs the CNAME if it is secure.
        let cname = DNSSECResolver::of(&response.answers, name, DNSType::CNAME);
        if !cname.is_empty() {
            return match self.trust(&parent, now, time) {
                DNSSECStep::Done(DNSSECZoneTrust::Secure { zone, keys }) => {
                    match self.validator.verify(&cname, &response.answers, &keys, seconds) {
                        Ok(verified) => (DNSSECStep::Done(DNSSECZoneTrust::Secure { zone, keys }), Some(verified.ttl)),
                        Err(error) => bogus(error),
                    }
                }
                other => (other, None),
            };
        }
        let ds = DNSSECResolver::of(&response.answers, name, DNSType::DS);
        if !ds.is_empty() {
            let Some(signer) = DNSSECResolver::signer(&response.answers, name, DNSType::DS) else {
                // An unsigned DS is of an unsigned parent zone, or bogus.
                return match self.trust(&parent, now, time) {
                    DNSSECStep::Done(DNSSECZoneTrust::Secure { .. }) => bogus(DNSSECResolver::missing()),
                    other => (other, None),
                };
            };
            if signer == *name || !name.is_subdomain_of(&signer) {
                return bogus(DNSSECValidator::bogus("a DS signed by a zone not above it"));
            }
            let keys = match self.trust(&signer, now, time) {
                DNSSECStep::Done(DNSSECZoneTrust::Secure { zone, keys }) if zone == signer => keys,
                DNSSECStep::Done(DNSSECZoneTrust::Secure { .. }) => {
                    return bogus(DNSSECValidator::bogus("a signer that is not a zone"));
                }
                other => return (other, None),
            };
            if let Err(error) = self.validator.verify(&ds, &response.answers, &keys, seconds) {
                return bogus(error);
            }
            let response = match self.fetch(DNSQuestion::new(name.clone(), DNSType::DNSKEY), now) {
                Ok(response) => response,
                Err(step) => return (step, None),
            };
            let own = DNSSECResolver::of(&response.answers, name, DNSType::DNSKEY);
            return match self.validator.verify_keys(&own, &response.answers, &ds, seconds) {
                Ok(DNSSECTrust::Secure(verified)) => {
                    (DNSSECStep::Done(DNSSECZoneTrust::Secure { zone: name.clone(), keys: own }), Some(verified.ttl))
                }
                Ok(DNSSECTrust::Insecure(code)) => (DNSSECStep::Done(DNSSECZoneTrust::Insecure(Some(code))), None),
                Err(error) => bogus(error),
            };
        }
        // No DS: the zone that answered, by its SOA, says what the name is.
        let Some(soa) = response
            .authorities
            .iter()
            .find(|record| record.kind == DNSType::SOA && name.is_subdomain_of(&record.name))
        else {
            return match self.trust(&parent, now, time) {
                DNSSECStep::Done(DNSSECZoneTrust::Secure { .. }) => {
                    bogus(DNSSECValidator::missing("a denial of DS without SOA"))
                }
                other => (other, None),
            };
        };
        let zone = soa.name.clone();
        if zone == *name {
            // The zone below the cut answered (RFC 4035 §3.1.4.1): only an unsigned parent excuses it.
            return match self.trust(&parent, now, time) {
                DNSSECStep::Done(DNSSECZoneTrust::Secure { .. }) => {
                    bogus(DNSSECValidator::bogus("a DS denied by the zone below its cut"))
                }
                other => (other, None),
            };
        }
        let keys = match self.trust(&zone, now, time) {
            DNSSECStep::Done(DNSSECZoneTrust::Secure { zone: found, keys }) if found == zone => keys,
            DNSSECStep::Done(DNSSECZoneTrust::Secure { .. }) => {
                return bogus(DNSSECValidator::bogus("an SOA not at a zone's apex"));
            }
            other => return (other, None),
        };
        let authentic = DNSSECResolver::signed_by(&response.authorities, &zone);
        let ttl = match self.verify_all(&authentic, &keys, seconds) {
            Ok(ttl) => ttl,
            Err(error) => return bogus(error),
        };
        let proof = match response.rcode() {
            DNSResponseCode::NXDOMAIN => self.validator.prove_nonexistence(name, &zone, &authentic),
            _ => self.validator.prove_nodata(name, DNSType::DS, &zone, &authentic),
        };
        let trust = match proof {
            Err(error) => return bogus(error),
            Ok(DNSSECProof::Insecure(code)) => DNSSECZoneTrust::Insecure(code),
            Ok(DNSSECProof::Secure) if DNSSECResolver::is_cut(&authentic, name, &zone) => {
                DNSSECZoneTrust::Insecure(None)
            }
            Ok(DNSSECProof::Secure) => DNSSECZoneTrust::Secure { zone, keys },
        };
        (DNSSECStep::Done(trust), Some(ttl))
    }

    /// Whether the denial of `records` lists NS at `name`: an unsigned delegation of `zone`.
    pub fn is_cut(records: &[DNSRecord], name: &DNSName, zone: &DNSName) -> bool {
        let nsec = DNSSECNSEC::of(records, zone);
        if let Some(matching) = nsec.iter().find(|record| record.owner == name) {
            return matching.types.contains(DNSType::NS);
        }
        let chain = DNSSECNSEC3::of(records, zone);
        let hash = DNSSECValidator::nsec3_hash(&chain, name);
        chain.iter().any(|record| record.matches(&hash) && record.data.types.contains(DNSType::NS))
    }

    /// Verifies every RRset of `records` but RRSIG with `keys`.
    pub fn verify_all(&self, records: &[DNSRecord], keys: &[DNSRecord], time: u32) -> Result<u32, DNSError> {
        let mut ttl = u32::MAX;
        let mut done: Vec<(&DNSName, DNSType)> = Vec::new();
        for record in records.iter().filter(|record| record.kind != DNSType::RRSIG) {
            if done.iter().any(|(name, kind)| *name == &record.name && *kind == record.kind) {
                continue;
            }
            done.push((&record.name, record.kind));
            let set = DNSSECResolver::of(records, &record.name, record.kind);
            ttl = ttl.min(self.validator.verify(&set, records, keys, time)?.ttl);
        }
        Ok(ttl)
    }

    /// The records of `records` owned by `name` of type `kind`.
    pub fn of(records: &[DNSRecord], name: &DNSName, kind: DNSType) -> Vec<DNSRecord> {
        records.iter().filter(|record| record.name == *name && record.kind == kind).cloned().collect()
    }

    /// The signer of the first RRSIG of `records` covering `kind` at `name`.
    pub fn signer(records: &[DNSRecord], name: &DNSName, kind: DNSType) -> Option<DNSName> {
        records.iter().find_map(|record| match &record.data {
            DNSData::RRSIG(rrsig) if record.name == *name && rrsig.type_covered == kind => Some(rrsig.signer.clone()),
            _ => None,
        })
    }

    pub fn missing() -> DNSError {
        DNSError::Bogus { code: DNSExtendedError::RRSIGS_MISSING, reason: "no signature in a signed zone" }
    }

    /// Validates `response` to `question`: every RRset of its answer by the
    /// keys of its signer's zone, or, unsigned, as of an insecure zone; a
    /// CNAME that a validated DNAME synthesizes (RFC 6672 §5.3.3); a
    /// wildcard's expansion by its denial; and, if the answer does not end
    /// in the type asked or the response is NXDOMAIN, the denial of the
    /// last name of its chain (RFC 4035 §5.4, RFC 6604 §3), which an
    /// answer at that name contradicts. Each denial uses only the records
    /// its zone signs (a response may carry other zones' too). Insecure is
    /// the result if anything is, bogus if anything is; with the records of
    /// the authority section it validated.
    #[allow(clippy::type_complexity)]
    pub fn validate(
        &mut self,
        question: &DNSQuestion,
        response: &DNSMessage,
        now: Instant,
        time: u64,
    ) -> DNSSECStep<Result<(DNSSECStatus, Vec<DNSRecord>), DNSError>> {
        // Only an answer or a denial is validated; an error has nothing to authenticate.
        if !matches!(response.rcode(), DNSResponseCode::NOERROR | DNSResponseCode::NXDOMAIN) {
            return DNSSECStep::Done(Ok((DNSSECStatus::Insecure(None), Vec::new())));
        }
        let seconds = time as u32;
        let mut status = DNSSECStatus::Secure;
        let mut insecure = |code: Option<u16>| {
            status = DNSSECStatus::Insecure(code);
        };
        let mut authentic: Vec<DNSRecord> = Vec::new();
        let answers = &response.answers;
        let mut seen: BTreeSet<(DNSName, DNSType)> = BTreeSet::new();
        for record in answers.iter().filter(|record| record.kind != DNSType::RRSIG) {
            if !seen.insert((record.name.canonical(), record.kind)) {
                continue;
            }
            if record.kind == DNSType::CNAME && DNSSECResolver::synthesized(answers, record) {
                continue;
            }
            let set = DNSSECResolver::of(answers, &record.name, record.kind);
            let Some(signer) = DNSSECResolver::signer(answers, &record.name, record.kind) else {
                match self.trust(&record.name, now, time) {
                    DNSSECStep::Done(DNSSECZoneTrust::Insecure(code)) => insecure(code),
                    DNSSECStep::Done(DNSSECZoneTrust::Secure { .. }) => {
                        return DNSSECStep::Done(Err(DNSSECResolver::missing()));
                    }
                    DNSSECStep::Done(DNSSECZoneTrust::Bogus(error)) => return DNSSECStep::Done(Err(error)),
                    DNSSECStep::Need(needed) => return DNSSECStep::Need(needed),
                }
                continue;
            };
            let keys = match self.trust(&signer, now, time) {
                DNSSECStep::Done(DNSSECZoneTrust::Secure { zone, keys }) if zone == signer => keys,
                DNSSECStep::Done(DNSSECZoneTrust::Secure { .. }) => {
                    return DNSSECStep::Done(Err(DNSSECValidator::bogus("a signer that is not a zone")));
                }
                DNSSECStep::Done(DNSSECZoneTrust::Insecure(code)) => {
                    insecure(code);
                    continue;
                }
                DNSSECStep::Done(DNSSECZoneTrust::Bogus(error)) => return DNSSECStep::Done(Err(error)),
                DNSSECStep::Need(needed) => return DNSSECStep::Need(needed),
            };
            let verified = match self.validator.verify(&set, answers, &keys, seconds) {
                Ok(verified) => verified,
                Err(error) => return DNSSECStep::Done(Err(error)),
            };
            if let Some(encloser) = verified.closest_encloser {
                let denial = DNSSECResolver::signed_by(&response.authorities, &signer);
                if let Err(error) = self.verify_all(&denial, &keys, seconds) {
                    return DNSSECStep::Done(Err(error));
                }
                match self.validator.prove_expansion(&record.name, &encloser, &signer, &denial) {
                    Ok(DNSSECProof::Secure) => {}
                    Ok(DNSSECProof::Insecure(code)) => insecure(code),
                    Err(error) => return DNSSECStep::Done(Err(error)),
                }
                authentic.extend(denial);
            }
        }
        // A question of CNAME or ANY is answered by the records at its name, a CNAME among them (RFC 1034 §4.3.2).
        let follows = !matches!(question.kind, DNSType::CNAME | DNSType::ANY);
        let last = if follows { DNSSECResolver::chain_end(answers, &question.name) } else { question.name.clone() };
        let answered = answers.iter().any(|record| {
            record.name == last
                && record.kind != DNSType::RRSIG
                && (record.kind == question.kind || question.kind == DNSType::ANY)
        });
        let nxdomain = response.rcode() == DNSResponseCode::NXDOMAIN;
        if nxdomain && answered {
            return DNSSECStep::Done(Err(DNSSECValidator::bogus("an answer to a name that NXDOMAIN denies")));
        }
        if nxdomain || !answered {
            let soa = response
                .authorities
                .iter()
                .find(|record| record.kind == DNSType::SOA && last.is_subdomain_of(&record.name));
            let Some(soa) = soa else {
                return match self.trust(&last, now, time) {
                    DNSSECStep::Done(DNSSECZoneTrust::Insecure(code)) => {
                        DNSSECStep::Done(Ok((DNSSECStatus::Insecure(code), Vec::new())))
                    }
                    DNSSECStep::Done(DNSSECZoneTrust::Bogus(error)) => DNSSECStep::Done(Err(error)),
                    DNSSECStep::Done(DNSSECZoneTrust::Secure { .. }) => {
                        DNSSECStep::Done(Err(DNSSECValidator::missing("a denial without SOA")))
                    }
                    DNSSECStep::Need(needed) => DNSSECStep::Need(needed),
                };
            };
            let zone = soa.name.clone();
            let keys = match self.trust(&zone, now, time) {
                DNSSECStep::Done(DNSSECZoneTrust::Secure { zone: found, keys }) if found == zone => keys,
                DNSSECStep::Done(DNSSECZoneTrust::Secure { .. }) => {
                    return DNSSECStep::Done(Err(DNSSECValidator::bogus("an SOA not at a zone's apex")));
                }
                DNSSECStep::Done(DNSSECZoneTrust::Insecure(code)) => {
                    return DNSSECStep::Done(Ok((DNSSECStatus::Insecure(code), Vec::new())));
                }
                DNSSECStep::Done(DNSSECZoneTrust::Bogus(error)) => return DNSSECStep::Done(Err(error)),
                DNSSECStep::Need(needed) => return DNSSECStep::Need(needed),
            };
            let denial = DNSSECResolver::signed_by(&response.authorities, &zone);
            if let Err(error) = self.verify_all(&denial, &keys, seconds) {
                return DNSSECStep::Done(Err(error));
            }
            let proof = match nxdomain {
                true => self.validator.prove_nonexistence(&last, &zone, &denial),
                false => self.validator.prove_nodata(&last, question.kind, &zone, &denial),
            };
            match proof {
                Ok(DNSSECProof::Secure) => {}
                Ok(DNSSECProof::Insecure(code)) => insecure(code),
                Err(error) => return DNSSECStep::Done(Err(error)),
            }
            authentic.extend(denial);
        }
        let mut unique: Vec<DNSRecord> = Vec::with_capacity(authentic.len());
        for record in authentic {
            if !unique.contains(&record) {
                unique.push(record);
            }
        }
        DNSSECStep::Done(Ok((status, unique)))
    }

    /// Whether the CNAME `record` is the one a DNAME of `records` above its
    /// owner synthesizes (RFC 6672 §2.2), which is not signed.
    pub fn synthesized(records: &[DNSRecord], record: &DNSRecord) -> bool {
        let DNSData::CNAME(target) = &record.data else { return false };
        records.iter().any(|dname| {
            let DNSData::DNAME(substitute) = &dname.data else { return false };
            if dname.name == record.name || !record.name.is_subdomain_of(&dname.name) {
                return false;
            }
            let mut wire = record.name.wire()[..record.name.wire().len() - dname.name.wire().len()].to_vec();
            wire.extend_from_slice(substitute.wire());
            DNSName::from_wire(&wire).is_ok_and(|expected| expected == *target)
        })
    }

    /// The last name of the CNAME chain of `records` from `name`.
    pub fn chain_end(records: &[DNSRecord], name: &DNSName) -> DNSName {
        let mut current = name.clone();
        for _ in 0..records.len() {
            let next = records.iter().find_map(|record| match &record.data {
                DNSData::CNAME(target) if record.name == current => Some(target.clone()),
                _ => None,
            });
            match next {
                Some(target) => current = target,
                None => break,
            }
        }
        current
    }
}
