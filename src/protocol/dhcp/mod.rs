//! DHCP: what both versions share — the errors, and the DHCP Unique
//! Identifier (RFC 9915 §11), which DHCPv4 clients also use in their
//! client identifier (RFC 4361 §6.1).

mod duid;
mod error;

#[cfg(umilib_feature = "protocol-dhcp-v4")]
pub mod v4;
#[cfg(umilib_feature = "protocol-dhcp-v6")]
pub mod v6;

pub use duid::DHCPDUID;
pub use error::DHCPError;
