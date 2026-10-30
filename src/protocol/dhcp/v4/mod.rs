//! DHCP: `v4` — DHCP for IPv4 (RFC 2131): the message of BOOTP's header
//! and the options of RFC 2132, long options (RFC 3396) and overload, the
//! client identifier of RFC 4361 echoed by servers (RFC 6842), a client of
//! every state of RFC 2131 §4.4 and a server of an address pool.

mod client;
mod message;
mod option;
mod server;

pub use client::{
    DHCPv4Client, DHCPv4ClientConfig, DHCPv4ClientEvent, DHCPv4ClientState, DHCPv4Lease, DHCPv4Transmission,
};
pub use message::DHCPv4Message;
pub use option::{DHCPv4MessageType, DHCPv4OptionCode, DHCPv4Options, DHCPv4Route};
pub use server::{DHCPv4Binding, DHCPv4BindingState, DHCPv4Reply, DHCPv4Server, DHCPv4ServerConfig};
