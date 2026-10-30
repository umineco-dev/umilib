//! The Address Resolution Protocol (RFC 826): its packets, of any hardware
//! and protocol address types, and the cache that resolves addresses with
//! them (RFC 1122 §2.3.2), without I/O. Probes and announcements are those
//! of RFC 5227.

mod address;
mod cache;
mod error;
mod packet;

pub use address::ARPAddress;
pub use cache::{ARPCache, ARPConfig, ARPEntry, ARPEvent, ARPReception, ARPResolution};
pub use error::ARPError;
pub use packet::{ARPHardwareType, ARPOperation, ARPPacket};
