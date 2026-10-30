use alloc::vec::Vec;

use crate::crypto::random::Random;

use super::super::{DNSData, DNSError, DNSName, DNSRRSIG, DNSRecord, DNSType};
use super::{DNSSECDigest, DNSSECKey, DNSSECPrivateKey};

/// A key that signs the RRsets of a zone (RFC 4035 §2).
#[derive(Debug)]
pub struct DNSSECSigner {
    pub zone: DNSName,
    /// The flags of its DNSKEY: [`DNSSECKey::ZONE`], and
    /// [`DNSSECKey::SECURE_ENTRY_POINT`] for a key-signing key.
    pub flags: u16,
    pub key: DNSSECPrivateKey,
    /// The public key field of its DNSKEY.
    pub public_key: Vec<u8>,
}

impl DNSSECSigner {
    pub fn new(zone: DNSName, flags: u16, key: DNSSECPrivateKey) -> DNSSECSigner {
        let public_key = key.public_key().encode();
        DNSSECSigner { zone, flags, key, public_key }
    }

    /// The fields of its DNSKEY.
    pub fn dnskey_fields(&self) -> DNSSECKey<'_> {
        DNSSECKey {
            flags: self.flags,
            protocol: DNSSECKey::PROTOCOL,
            algorithm: self.key.algorithm(),
            public_key: &self.public_key,
        }
    }

    pub fn tag(&self) -> u16 {
        self.dnskey_fields().tag()
    }

    /// Its DNSKEY record, at the zone's apex.
    pub fn dnskey(&self, ttl: u32) -> DNSRecord {
        let data = DNSData::DNSKEY {
            flags: self.flags,
            protocol: DNSSECKey::PROTOCOL,
            algorithm: self.key.algorithm().0,
            public_key: self.public_key.clone(),
        };
        DNSRecord::new(self.zone.clone(), ttl, data)
    }

    /// The DS record of its DNSKEY of `digest`, for the parent zone (RFC 4034 §5).
    pub fn delegation(&self, digest: DNSSECDigest, ttl: u32) -> Option<DNSRecord> {
        let data = digest.delegation(&self.zone, &self.dnskey_fields())?;
        Some(DNSRecord::new(self.zone.clone(), ttl, data))
    }

    /// The RRSIG record of the RRset `records`, valid from `inception` to
    /// `expiration` (seconds since 1970, modulo 2^32): of the RRset's TTL,
    /// owner and class (RFC 4034 §3). The RRset is the zone's, not RRSIG.
    pub fn sign<R: Random>(
        &self,
        records: &[DNSRecord],
        inception: u32,
        expiration: u32,
        random: &mut R,
    ) -> Result<DNSRecord, DNSError> {
        let first = records.first().ok_or(DNSError::State)?;
        if records.iter().any(|record| !record.same_set(first) || record.ttl != first.ttl)
            || first.kind == DNSType::RRSIG
            || !first.name.is_subdomain_of(&self.zone)
        {
            return Err(DNSError::State);
        }
        let mut rrsig = DNSRRSIG {
            type_covered: first.kind,
            algorithm: self.key.algorithm().0,
            labels: DNSRRSIG::label_count(&first.name) as u8,
            original_ttl: first.ttl,
            expiration,
            inception,
            key_tag: self.tag(),
            signer: self.zone.clone(),
            signature: Vec::new(),
        };
        let data = rrsig.signed_data(records).ok_or(DNSError::State)?;
        rrsig.signature = self.key.sign(&data, random)?;
        Ok(DNSRecord {
            class: first.class,
            ..DNSRecord::new(first.name.clone(), first.ttl, DNSData::RRSIG(alloc::boxed::Box::new(rrsig)))
        })
    }
}
