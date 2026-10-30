use alloc::vec::Vec;

use super::super::{DNSError, DNSExtendedError, DNSName, DNSRRSIG, DNSRecord};

impl DNSRRSIG {
    /// The labels of `owner` that the Labels field counts: all but the root
    /// and a leading wildcard (RFC 4034 §3.1.3).
    pub fn label_count(owner: &DNSName) -> usize {
        owner.label_count() - usize::from(owner.is_wildcard())
    }

    /// The name the signature covers for records owned by `owner`: `owner`
    /// itself, or, if Labels is fewer than its labels, the wildcard that
    /// was expanded to it (RFC 4035 §5.3.2). None if Labels is more.
    pub fn signed_owner(&self, owner: &DNSName) -> Option<DNSName> {
        let labels = usize::from(self.labels);
        match labels.cmp(&DNSRRSIG::label_count(owner)) {
            core::cmp::Ordering::Equal => Some(owner.clone()),
            core::cmp::Ordering::Less => owner.suffix(labels).prepend(b"*").ok(),
            core::cmp::Ordering::Greater => None,
        }
    }

    /// The data the signature signs (RFC 4034 §3.1.8.1): its RDATA up to
    /// the signature, then each record of the RRset `records` in canonical
    /// form (§6.2) and order (§6.3), duplicates removed, the owner the
    /// signed owner and the TTL the original TTL. None if `records` is empty
    /// or Labels is more than the owner's labels.
    pub fn signed_data(&self, records: &[DNSRecord]) -> Option<Vec<u8>> {
        let first = records.first()?;
        let owner = self.signed_owner(&first.name)?.canonical();
        let signer = DNSRRSIG { signer: self.signer.canonical(), signature: Vec::new(), ..self.clone() };
        let mut data = Vec::with_capacity(256);
        signer.encode_fields(&mut data);
        let mut rdatas: Vec<Vec<u8>> = records.iter().map(|record| record.data.canonical(record.kind)).collect();
        rdatas.sort();
        rdatas.dedup();
        for rdata in &rdatas {
            data.extend_from_slice(owner.wire());
            data.extend_from_slice(&first.kind.0.to_be_bytes());
            data.extend_from_slice(&first.class.0.to_be_bytes());
            data.extend_from_slice(&self.original_ttl.to_be_bytes());
            data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            data.extend_from_slice(rdata);
        }
        Some(data)
    }

    /// Succeeds if `now` (seconds since 1970, modulo 2^32) is within the
    /// validity period, `skew` seconds allowed on each side, in the serial
    /// arithmetic of RFC 1982 (RFC 4034 §3.1.5, RFC 4035 §5.3.1).
    pub fn check_time(&self, now: u32, skew: u32) -> Result<(), DNSError> {
        let after = |a: u32, b: u32| a.wrapping_sub(b) as i32 >= 0;
        if !after(self.expiration, self.inception) {
            return Err(DNSError::Bogus {
                code: DNSExtendedError::SIGNATURE_EXPIRED_BEFORE_VALID,
                reason: "a signature that expires before its inception",
            });
        }
        if !after(now.wrapping_add(skew), self.inception) {
            return Err(DNSError::Bogus {
                code: DNSExtendedError::SIGNATURE_NOT_YET_VALID,
                reason: "a signature not yet valid",
            });
        }
        if !after(self.expiration.wrapping_add(skew), now) {
            return Err(DNSError::Bogus { code: DNSExtendedError::SIGNATURE_EXPIRED, reason: "an expired signature" });
        }
        Ok(())
    }
}
