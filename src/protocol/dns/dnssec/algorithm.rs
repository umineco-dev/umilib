use alloc::vec::Vec;
use core::fmt;

use crate::hash::Digest;
use crate::hash::sha::v1::SHA1;
use crate::hash::sha::v2::{SHA256, SHA384};

use super::super::{DNSData, DNSName};
use super::DNSSECKey;

/// A DNSSEC signing algorithm (IANA's DNS Security Algorithm Numbers, RFC 9904).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DNSSECAlgorithm(pub u8);

impl DNSSECAlgorithm {
    pub const RSAMD5: DNSSECAlgorithm = DNSSECAlgorithm(1);
    pub const DSA: DNSSECAlgorithm = DNSSECAlgorithm(3);
    pub const RSASHA1: DNSSECAlgorithm = DNSSECAlgorithm(5);
    pub const DSA_NSEC3_SHA1: DNSSECAlgorithm = DNSSECAlgorithm(6);
    pub const RSASHA1_NSEC3_SHA1: DNSSECAlgorithm = DNSSECAlgorithm(7);
    pub const RSASHA256: DNSSECAlgorithm = DNSSECAlgorithm(8);
    pub const RSASHA512: DNSSECAlgorithm = DNSSECAlgorithm(10);
    pub const ECC_GOST: DNSSECAlgorithm = DNSSECAlgorithm(12);
    pub const ECDSAP256SHA256: DNSSECAlgorithm = DNSSECAlgorithm(13);
    pub const ECDSAP384SHA384: DNSSECAlgorithm = DNSSECAlgorithm(14);
    pub const ED25519: DNSSECAlgorithm = DNSSECAlgorithm(15);
    pub const ED448: DNSSECAlgorithm = DNSSECAlgorithm(16);

    /// The algorithms this crate signs and validates: every one RFC 9904
    /// §3 says to implement for validation (MUST or RECOMMENDED).
    pub const IMPLEMENTED: [DNSSECAlgorithm; 8] = [
        DNSSECAlgorithm::RSASHA1,
        DNSSECAlgorithm::RSASHA1_NSEC3_SHA1,
        DNSSECAlgorithm::RSASHA256,
        DNSSECAlgorithm::RSASHA512,
        DNSSECAlgorithm::ECDSAP256SHA256,
        DNSSECAlgorithm::ECDSAP384SHA384,
        DNSSECAlgorithm::ED25519,
        DNSSECAlgorithm::ED448,
    ];

    pub const NAMES: [(DNSSECAlgorithm, &'static str); 12] = [
        (DNSSECAlgorithm::RSAMD5, "RSAMD5"),
        (DNSSECAlgorithm::DSA, "DSA"),
        (DNSSECAlgorithm::RSASHA1, "RSASHA1"),
        (DNSSECAlgorithm::DSA_NSEC3_SHA1, "DSA-NSEC3-SHA1"),
        (DNSSECAlgorithm::RSASHA1_NSEC3_SHA1, "RSASHA1-NSEC3-SHA1"),
        (DNSSECAlgorithm::RSASHA256, "RSASHA256"),
        (DNSSECAlgorithm::RSASHA512, "RSASHA512"),
        (DNSSECAlgorithm::ECC_GOST, "ECC-GOST"),
        (DNSSECAlgorithm::ECDSAP256SHA256, "ECDSAP256SHA256"),
        (DNSSECAlgorithm::ECDSAP384SHA384, "ECDSAP384SHA384"),
        (DNSSECAlgorithm::ED25519, "ED25519"),
        (DNSSECAlgorithm::ED448, "ED448"),
    ];

    /// The mnemonic, if the algorithm has one here.
    pub fn name(&self) -> Option<&'static str> {
        DNSSECAlgorithm::NAMES.iter().find(|(algorithm, _)| algorithm == self).map(|(_, name)| *name)
    }

    pub fn is_implemented(&self) -> bool {
        DNSSECAlgorithm::IMPLEMENTED.contains(self)
    }

    /// Whether the algorithm is RSA, whose keys have the form of RFC 3110 §2.
    pub fn is_rsa(&self) -> bool {
        matches!(
            *self,
            DNSSECAlgorithm::RSAMD5
                | DNSSECAlgorithm::RSASHA1
                | DNSSECAlgorithm::RSASHA1_NSEC3_SHA1
                | DNSSECAlgorithm::RSASHA256
                | DNSSECAlgorithm::RSASHA512
        )
    }
}

impl fmt::Display for DNSSECAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => formatter.write_str(name),
            None => write!(formatter, "{}", self.0),
        }
    }
}

/// A digest of a DS record (IANA's DS RR Type Digest Algorithms, RFC 9904 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DNSSECDigest(pub u8);

impl DNSSECDigest {
    pub const SHA1: DNSSECDigest = DNSSECDigest(1);
    pub const SHA256: DNSSECDigest = DNSSECDigest(2);
    pub const GOST: DNSSECDigest = DNSSECDigest(3);
    pub const SHA384: DNSSECDigest = DNSSECDigest(4);

    /// The digests this crate computes: every one RFC 9904 §4 says to
    /// implement for validation (MUST or RECOMMENDED).
    pub const IMPLEMENTED: [DNSSECDigest; 3] = [DNSSECDigest::SHA1, DNSSECDigest::SHA256, DNSSECDigest::SHA384];

    pub fn is_implemented(&self) -> bool {
        DNSSECDigest::IMPLEMENTED.contains(self)
    }

    /// The bytes of a digest, for those implemented.
    pub fn length(&self) -> Option<usize> {
        match *self {
            DNSSECDigest::SHA1 => Some(20),
            DNSSECDigest::SHA256 => Some(32),
            DNSSECDigest::SHA384 => Some(48),
            _ => None,
        }
    }

    /// The digest of `data`, for those implemented.
    pub fn digest(&self, data: &[u8]) -> Option<Vec<u8>> {
        match *self {
            DNSSECDigest::SHA1 => Some(SHA1::digest(data).to_vec()),
            DNSSECDigest::SHA256 => Some(SHA256::digest(data).to_vec()),
            DNSSECDigest::SHA384 => Some(SHA384::digest(data).to_vec()),
            _ => None,
        }
    }

    /// The DS record of `key`, owned by `owner`: this digest of the owner
    /// in canonical form and the DNSKEY RDATA (RFC 4034 §5.1.4).
    pub fn delegation(&self, owner: &DNSName, key: &DNSSECKey<'_>) -> Option<DNSData> {
        let mut data = owner.canonical().wire().to_vec();
        data.extend_from_slice(&key.rdata());
        Some(DNSData::DS {
            key_tag: key.tag(),
            algorithm: key.algorithm.0,
            digest_type: self.0,
            digest: self.digest(&data)?,
        })
    }
}
