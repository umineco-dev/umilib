//! Ethernet (IEEE 802.3): MAC addresses, EtherTypes, the header with its
//! VLAN tags (IEEE 802.1Q, 802.1ad), and the padding and frame check
//! sequence of a frame. IPv4 over Ethernet is RFC 894, IPv6 RFC 2464.

mod error;
mod ether_type;
mod frame;
mod header;
mod mac_address;

pub use error::EthernetError;
pub use ether_type::EtherType;
pub use frame::EthernetFrame;
pub use header::{EthernetHeader, VLANTag};
pub use mac_address::MACAddress;
