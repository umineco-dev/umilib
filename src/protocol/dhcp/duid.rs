use alloc::vec::Vec;

use super::DHCPError;

/// A DHCP Unique Identifier (RFC 9915 §11): of the type of its first two
/// bytes, compared as bytes (§11.1). Of 2 to 130 bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DHCPDUID {
    /// DUID-LLT (§11.2): a hardware type, the seconds since 2000-01-01 UTC
    /// modulo 2^32, and a link-layer address.
    LLT { hardware: u16, time: u32, address: Vec<u8> },
    /// DUID-EN (§11.3): a vendor's enterprise number and identifier.
    EN { enterprise: u32, identifier: Vec<u8> },
    /// DUID-LL (§11.4): a hardware type and a link-layer address.
    LL { hardware: u16, address: Vec<u8> },
    /// DUID-UUID (RFC 6355 §4).
    UUID([u8; 16]),
    /// A type this crate does not know, with its data.
    Other { kind: u16, data: Vec<u8> },
}

impl DHCPDUID {
    /// The hardware type of Ethernet (IANA's ARP parameters).
    pub const ETHERNET: u16 = 1;
    /// The longest DUID: 2 bytes of type and 128 of data (§11.1).
    pub const MAXIMUM_LENGTH: usize = 130;

    pub fn decode(bytes: &[u8]) -> Result<DHCPDUID, DHCPError> {
        let malformed = DHCPError::Malformed("a DUID of a wrong length");
        if bytes.len() < 3 || bytes.len() > DHCPDUID::MAXIMUM_LENGTH {
            return Err(malformed);
        }
        let kind = u16::from_be_bytes([bytes[0], bytes[1]]);
        let rest = &bytes[2..];
        Ok(match kind {
            1 if rest.len() >= 7 => DHCPDUID::LLT {
                hardware: u16::from_be_bytes([rest[0], rest[1]]),
                time: u32::from_be_bytes([rest[2], rest[3], rest[4], rest[5]]),
                address: rest[6..].to_vec(),
            },
            2 if rest.len() >= 5 => DHCPDUID::EN {
                enterprise: u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]),
                identifier: rest[4..].to_vec(),
            },
            3 if rest.len() >= 3 => {
                DHCPDUID::LL { hardware: u16::from_be_bytes([rest[0], rest[1]]), address: rest[2..].to_vec() }
            }
            4 => DHCPDUID::UUID(rest.try_into().map_err(|_| malformed)?),
            1..=3 => return Err(malformed),
            _ => DHCPDUID::Other { kind, data: rest.to_vec() },
        })
    }

    /// Its bytes; fails for what [`DHCPDUID::decode`] would not give back:
    /// an empty address or identifier, a known type as `Other`, or more
    /// than [`DHCPDUID::MAXIMUM_LENGTH`] bytes.
    pub fn encode(&self) -> Result<Vec<u8>, DHCPError> {
        let empty = match self {
            DHCPDUID::LLT { address, .. } | DHCPDUID::LL { address, .. } => address.is_empty(),
            DHCPDUID::EN { identifier, .. } => identifier.is_empty(),
            DHCPDUID::UUID(_) => false,
            DHCPDUID::Other { kind, data } => (1..=4).contains(kind) || data.is_empty(),
        };
        if empty {
            return Err(DHCPError::Malformed("a DUID without the data of its type"));
        }
        let mut out = Vec::with_capacity(20);
        match self {
            DHCPDUID::LLT { hardware, time, address } => {
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&hardware.to_be_bytes());
                out.extend_from_slice(&time.to_be_bytes());
                out.extend_from_slice(address);
            }
            DHCPDUID::EN { enterprise, identifier } => {
                out.extend_from_slice(&2u16.to_be_bytes());
                out.extend_from_slice(&enterprise.to_be_bytes());
                out.extend_from_slice(identifier);
            }
            DHCPDUID::LL { hardware, address } => {
                out.extend_from_slice(&3u16.to_be_bytes());
                out.extend_from_slice(&hardware.to_be_bytes());
                out.extend_from_slice(address);
            }
            DHCPDUID::UUID(uuid) => {
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(uuid);
            }
            DHCPDUID::Other { kind, data } => {
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(data);
            }
        }
        if out.len() > DHCPDUID::MAXIMUM_LENGTH {
            return Err(DHCPError::Malformed("a DUID of a wrong length"));
        }
        Ok(out)
    }

    /// The DUID-LLT time of `unix` seconds since 1970 (§11.2: since 2000-01-01, modulo 2^32).
    pub fn time(unix: u64) -> u32 {
        unix.wrapping_sub(946_684_800) as u32
    }
}
