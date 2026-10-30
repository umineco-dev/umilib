//! DNS (RFC 1034, RFC 1035): messages, names, records and zone files,
//! without I/O.
//!
//! This root module is the codec — [`DNSMessage`], [`DNSName`],
//! [`DNSRecord`] and the data of each type ([`DNSData`], with SVCB and
//! HTTPS of RFC 9460 in [`DNSServiceBinding`]), EDNS(0) ([`DNSEDNS`]) and
//! zone files ([`DNSZoneFile`]) — and [`DNSRule`] to route messages. Its
//! child modules are DNSSEC (`dnssec`) and the transports: `udp`, `tcp`,
//! `tls` (DNS over TLS), `https` (DNS over HTTPS) and `quic` (DNS over QUIC).

mod authority;
mod bitmap;
mod cache;
mod data;
mod edns;
mod error;
mod header;
mod kind;
mod message;
mod name;
mod record;
mod resolver;
mod rule;
mod svcb;
mod token;
mod transport;
mod zone;

#[cfg(umilib_feature = "protocol-dns-dnssec")]
pub mod dnssec;
#[cfg(umilib_feature = "protocol-dns-https")]
pub mod https;
#[cfg(umilib_feature = "protocol-dns-quic")]
pub mod quic;
#[cfg(umilib_feature = "protocol-dns-tcp")]
pub mod tcp;
#[cfg(umilib_feature = "protocol-dns-tls")]
pub mod tls;
#[cfg(umilib_feature = "protocol-dns-udp")]
pub mod udp;

pub use authority::{DNSAuthority, DNSAuthorityConfig, DNSDescent, DNSLookup, DNSResponse, DNSZone};
pub use bitmap::DNSTypeBitmap;
pub use cache::{DNSCache, DNSCacheConfig, DNSCacheEntry};
pub use data::{DNSData, DNSDataDisplay, DNSField, DNSNAPTR, DNSNSEC3, DNSRRSIG, DNSReader, DNSSOA, DNSTokens};
pub use edns::{DNSCookie, DNSEDNS, DNSExtendedError, DNSKeepalive, DNSOption, DNSOptionCode};
pub use error::DNSError;
pub use header::DNSHeader;
pub use kind::{DNSClass, DNSOpcode, DNSResponseCode, DNSType};
pub use message::DNSMessage;
pub use name::{DNSCompression, DNSLabels, DNSName};
pub use record::{DNSQuestion, DNSRecord};
pub use resolver::{
    DNSAttempt, DNSPendingQuery, DNSResolver, DNSResolverConfig, DNSResolverEvent, DNSTransmission, DNSUpstream,
};
pub use rule::DNSRule;
pub use svcb::{DNSServiceBinding, DNSServiceKey};
pub use token::DNSToken;
pub use transport::{DNSPeer, DNSTransport};
pub use zone::{DNSZoneError, DNSZoneFile};
