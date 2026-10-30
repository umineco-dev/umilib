//! DHCP: `v6` — DHCP for IPv6 (RFC 9915): its messages and those of relay
//! agents, the options of addresses (IA_NA) and prefixes (IA_PD), the
//! retransmissions of §15, a client of every exchange of §18.2 and a
//! server of address and prefix pools that answers relayed messages too.
//! IA_TA and the Server Unicast option are obsolete and ignored (§21.5,
//! §21.12); Reconfigure, which needs authentication, is not accepted.

mod client;
mod message;
mod option;
mod server;

pub use client::{DHCPv6Client, DHCPv6ClientConfig, DHCPv6ClientEvent, DHCPv6ClientState, DHCPv6Lease};
pub use message::{DHCPv6Message, DHCPv6MessageType, DHCPv6RelayMessage, DHCPv6Retransmission};
pub use option::{
    DHCPv6IA, DHCPv6IAAddress, DHCPv6IAPrefix, DHCPv6Option, DHCPv6OptionCode, DHCPv6Options, DHCPv6StatusCode,
};
pub use server::{DHCPv6Binding, DHCPv6Server, DHCPv6ServerConfig};
