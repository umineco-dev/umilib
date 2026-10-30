use alloc::vec::Vec;

use super::super::{DNSData, DNSError, DNSExtendedError, DNSName, DNSRRSIG, DNSRecord, DNSType};
use super::{DNSSECAlgorithm, DNSSECDigest, DNSSECKey, DNSSECPublicKey};

/// What a validator accepts.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSSECConfig {
    /// The algorithms of keys and signatures it uses; a zone whose DS
    /// records name none of them is insecure (RFC 4035 §5.2). Removing the
    /// SHA-1 algorithms (5 and 7) is a local policy RFC 9904 §3 allows.
    pub algorithms: Vec<DNSSECAlgorithm>,
    /// The digests of DS records it uses (RFC 9904 §4).
    pub digests: Vec<DNSSECDigest>,
    /// RSA keys of fewer bits are treated as of an algorithm not supported.
    pub minimum_rsa_bits: u32,
    /// NSEC3 records of more iterations make a denial insecure (RFC 9276 §3.2).
    pub insecure_nsec3_iterations: u16,
    /// NSEC3 records of more iterations make a denial bogus (RFC 9276 §3.2).
    pub bogus_nsec3_iterations: u16,
    /// The most signatures one call verifies, so that a response of many
    /// keys and signatures cannot take long (CVE-2023-50387, "KeyTrap").
    pub maximum_verifications: usize,
    /// The seconds a signature is accepted before its inception and after
    /// its expiration, for clocks that are not exact.
    pub clock_skew: u32,
    /// RSA keys of a public exponent of more bits are treated as of an
    /// algorithm not supported: verifying with a large exponent costs
    /// hundreds of times more (RFC 3110 §2 allows up to 4096 bits; keys
    /// use 3 or 65537). 64, as OpenSSL bounds the exponents of large keys.
    pub maximum_rsa_exponent_bits: u32,
}

impl Default for DNSSECConfig {
    fn default() -> DNSSECConfig {
        DNSSECConfig {
            algorithms: DNSSECAlgorithm::IMPLEMENTED.to_vec(),
            digests: DNSSECDigest::IMPLEMENTED.to_vec(),
            minimum_rsa_bits: 1024,
            insecure_nsec3_iterations: 50,
            bogus_nsec3_iterations: 150,
            maximum_verifications: 8,
            clock_skew: 0,
            maximum_rsa_exponent_bits: 64,
        }
    }
}

/// An RRset whose signature verified.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSSECVerified {
    /// The TTL the RRset keeps: at most its TTL, the original TTL and the
    /// time until the signature expires (RFC 4035 §5.3.3).
    pub ttl: u32,
    /// The zone that signed it.
    pub signer: DNSName,
    /// The tag of the key whose signature verified.
    pub key_tag: u16,
    /// For records expanded from a wildcard, the closest encloser: the name
    /// below which the wildcard is (RFC 4035 §5.3.4). The denial that the
    /// owner exists must be verified too ([`super::DNSSECValidator::prove_expansion`]).
    pub closest_encloser: Option<DNSName>,
}

/// What a zone's keys are, once checked against what its parent delegates.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DNSSECTrust {
    /// The DNSKEY RRset is signed by a key that a DS or a trust anchor names.
    Secure(DNSSECVerified),
    /// No DS or trust anchor is of an algorithm or digest in use; the zone
    /// is treated as unsigned, with the extended error that tells why.
    Insecure(u16),
}

/// What a denial of existence proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DNSSECProof {
    Secure,
    /// What it denies may exist unsigned (NSEC3 Opt-Out, RFC 5155 §6), or
    /// it cannot be checked (RFC 9276 §3.2), with the extended error if one
    /// tells why.
    Insecure(Option<u16>),
}

/// A DNSSEC validator (RFC 4035 §5): it checks signatures with keys and
/// keys with what their parent delegates. Finding the records is the
/// resolver's work; every record given is from the response or cache.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DNSSECValidator {
    pub config: DNSSECConfig,
}

impl DNSSECValidator {
    pub fn new(config: DNSSECConfig) -> DNSSECValidator {
        DNSSECValidator { config }
    }

    /// The public key of the DNSKEY `key`, if the validator may use it: a
    /// zone key (RFC 4034 §2.1.1) of protocol 3, not revoked (RFC 5011
    /// §2.1), of an algorithm in use and, for RSA, of enough bits and an
    /// exponent of not too many.
    pub fn usable_key(&self, key: &DNSSECKey<'_>) -> Option<DNSSECPublicKey> {
        if !key.is_zone_key() || key.is_revoked() || key.protocol != DNSSECKey::PROTOCOL {
            return None;
        }
        if !self.config.algorithms.contains(&key.algorithm) {
            return None;
        }
        let public = DNSSECPublicKey::decode(key.algorithm, key.public_key).ok()?;
        if key.algorithm.is_rsa()
            && (public.bits() < self.config.minimum_rsa_bits
                || public.exponent_bits() > self.config.maximum_rsa_exponent_bits)
        {
            return None;
        }
        Some(public)
    }

    /// Verifies the RRset `records` with one of the RRSIG records
    /// `signatures` made by one of the DNSKEY records `keys` of the zone
    /// that has it (RFC 4035 §5.3). Signatures of other RRsets among
    /// `signatures` are ignored. One valid signature is enough (RFC 6840
    /// §5.11). The error, if none is valid, is of the signature that came
    /// nearest: bogus over expired over missing key over missing signature.
    pub fn verify(
        &self,
        records: &[DNSRecord],
        signatures: &[DNSRecord],
        keys: &[DNSRecord],
        now: u32,
    ) -> Result<DNSSECVerified, DNSError> {
        let first =
            records.first().ok_or(DNSError::Bogus { code: DNSExtendedError::OTHER, reason: "an empty RRset" })?;
        if records.iter().any(|record| !record.same_set(first)) {
            return Err(DNSError::Bogus { code: DNSExtendedError::OTHER, reason: "records not of one RRset" });
        }
        let mut error = DNSError::Bogus { code: DNSExtendedError::RRSIGS_MISSING, reason: "no signature of the RRset" };
        let mut rank = 0;
        let mut verifications = 0;
        let mut fail = |candidate: DNSError, candidate_rank: u8| {
            if candidate_rank > rank {
                (error, rank) = (candidate, candidate_rank);
            }
        };
        let covering =
            signatures.iter().filter(|signature| signature.name == first.name && signature.class == first.class);
        for signature in covering {
            let DNSData::RRSIG(rrsig) = &signature.data else { continue };
            if rrsig.type_covered != first.kind || signature.kind != DNSType::RRSIG {
                continue;
            }
            let algorithm = DNSSECAlgorithm(rrsig.algorithm);
            if !self.config.algorithms.contains(&algorithm) {
                fail(
                    DNSError::Bogus {
                        code: DNSExtendedError::DNSSEC_BOGUS,
                        reason: "no signature of an algorithm in use",
                    },
                    1,
                );
                continue;
            }
            if !first.name.is_subdomain_of(&rrsig.signer) {
                fail(
                    DNSError::Bogus {
                        code: DNSExtendedError::DNSSEC_BOGUS,
                        reason: "a signer above which the owner is not",
                    },
                    3,
                );
                continue;
            }
            let Some(data) = rrsig.signed_data(records) else {
                fail(
                    DNSError::Bogus { code: DNSExtendedError::DNSSEC_BOGUS, reason: "more labels than the owner has" },
                    3,
                );
                continue;
            };
            if let Err(expired) = rrsig.check_time(now, self.config.clock_skew) {
                fail(expired, 3);
                continue;
            }
            let matching = keys.iter().filter_map(|record| {
                let key = DNSSECKey::from_data(&record.data)?;
                (record.kind == DNSType::DNSKEY
                    && record.name == rrsig.signer
                    && key.algorithm == algorithm
                    && key.tag() == rrsig.key_tag)
                    .then_some(key)
            });
            let mut found = false;
            for key in matching {
                let Some(public) = self.usable_key(&key) else {
                    let code = if key.is_zone_key() {
                        DNSExtendedError::DNSKEY_MISSING
                    } else {
                        DNSExtendedError::NO_ZONE_KEY_BIT_SET
                    };
                    fail(DNSError::Bogus { code, reason: "no key that may verify the signature" }, 2);
                    continue;
                };
                found = true;
                if verifications == self.config.maximum_verifications {
                    return Err(DNSError::Bogus {
                        code: DNSExtendedError::DNSSEC_BOGUS,
                        reason: "more signatures than may be verified",
                    });
                }
                verifications += 1;
                match public.verify(&data, &rrsig.signature) {
                    Ok(()) => {
                        let remaining = (rrsig.expiration.wrapping_sub(now) as i32).max(0) as u32;
                        let ttl = records.iter().map(|record| record.ttl).min().unwrap_or(0);
                        let labels = usize::from(rrsig.labels);
                        let expanded = labels < DNSRRSIG::label_count(&first.name);
                        return Ok(DNSSECVerified {
                            ttl: ttl.min(rrsig.original_ttl).min(remaining),
                            signer: rrsig.signer.clone(),
                            key_tag: rrsig.key_tag,
                            closest_encloser: expanded.then(|| first.name.suffix(labels)),
                        });
                    }
                    Err(bogus) => fail(bogus, 4),
                }
            }
            if !found {
                fail(DNSError::Bogus { code: DNSExtendedError::DNSKEY_MISSING, reason: "no key of the signature" }, 2);
            }
        }
        Err(error)
    }

    /// Checks the DNSKEY RRset `keys` of a zone against `anchors`: the
    /// zone's DS RRset as its parent signed it, or trust anchors as DS or
    /// DNSKEY records (RFC 4035 §5.2). The RRset is secure if a key that a
    /// usable anchor names signs it; it is insecure if no anchor is of an
    /// algorithm and digest in use. DS records of SHA-1 are ignored when
    /// others are usable (RFC 4509 §3).
    pub fn verify_keys(
        &self,
        keys: &[DNSRecord],
        signatures: &[DNSRecord],
        anchors: &[DNSRecord],
        now: u32,
    ) -> Result<DNSSECTrust, DNSError> {
        let missing = DNSError::Bogus { code: DNSExtendedError::DNSKEY_MISSING, reason: "no key that a DS names" };
        let zone = &keys.first().ok_or(missing)?.name;
        let usable_algorithm = |algorithm: u8| {
            let algorithm = DNSSECAlgorithm(algorithm);
            algorithm.is_implemented() && self.config.algorithms.contains(&algorithm)
        };
        let usable_digest = |digest: u8| {
            let digest = DNSSECDigest(digest);
            digest.is_implemented() && self.config.digests.contains(&digest)
        };
        let mut usable: Vec<&DNSRecord> = Vec::new();
        let mut unsupported = DNSExtendedError::UNSUPPORTED_DNSKEY_ALGORITHM;
        for anchor in anchors.iter().filter(|anchor| anchor.name == *zone) {
            match &anchor.data {
                DNSData::DS { algorithm, digest_type, .. } if anchor.kind == DNSType::DS => {
                    if !usable_algorithm(*algorithm) {
                        continue;
                    }
                    if !usable_digest(*digest_type) {
                        unsupported = DNSExtendedError::UNSUPPORTED_DS_DIGEST_TYPE;
                        continue;
                    }
                    usable.push(anchor);
                }
                DNSData::DNSKEY { algorithm, .. } if anchor.kind == DNSType::DNSKEY && usable_algorithm(*algorithm) => {
                    usable.push(anchor);
                }
                _ => {}
            }
        }
        let strong = |anchor: &&DNSRecord| !matches!(anchor.data, DNSData::DS { digest_type, .. } if digest_type == DNSSECDigest::SHA1.0);
        if usable.iter().any(strong) {
            usable.retain(strong);
        }
        if usable.is_empty() {
            return match anchors.iter().any(|anchor| anchor.name == *zone) {
                true => Ok(DNSSECTrust::Insecure(unsupported)),
                false => Err(missing),
            };
        }
        let mut named = Vec::new();
        let mut unusable = false;
        for record in keys.iter().filter(|record| record.kind == DNSType::DNSKEY && record.name == *zone) {
            let Some(key) = DNSSECKey::from_data(&record.data) else { continue };
            if !usable.iter().any(|anchor| DNSSECValidator::names(anchor, &key)) {
                continue;
            }
            match self.usable_key(&key) {
                Some(_) => named.push(record.clone()),
                None => unusable = true,
            }
        }
        if named.is_empty() {
            return match unusable {
                true => Ok(DNSSECTrust::Insecure(DNSExtendedError::UNSUPPORTED_DNSKEY_ALGORITHM)),
                false => Err(missing),
            };
        }
        Ok(DNSSECTrust::Secure(self.verify(keys, signatures, &named, now)?))
    }

    /// Whether the DS or DNSKEY record `anchor` names `key`: a DS of its
    /// tag, algorithm and digest (RFC 4034 §5.1.4), or the same key.
    pub fn names(anchor: &DNSRecord, key: &DNSSECKey<'_>) -> bool {
        match &anchor.data {
            DNSData::DS { key_tag, algorithm, digest_type, digest } => {
                *key_tag == key.tag()
                    && *algorithm == key.algorithm.0
                    && DNSSECDigest(*digest_type).delegation(&anchor.name, key).is_some_and(
                        |data| matches!(data, DNSData::DS { digest: ref computed, .. } if computed == digest),
                    )
            }
            DNSData::DNSKEY { .. } => {
                DNSSECKey::from_data(&anchor.data).is_some_and(|anchor| anchor.rdata() == key.rdata())
            }
            _ => false,
        }
    }
}
