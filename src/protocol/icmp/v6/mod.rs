//! ICMPv6 (RFC 4443): the messages, their types and codes, the rules of
//! error messages, the extensions of RFC 4884; and Neighbor Discovery (RFC
//! 4861): its messages, their options and validity checks, and the Neighbor
//! Cache with its reachability state machine, without I/O.

mod kind;
mod message;
mod ndp;
mod neighbor;
mod option;

pub use kind::{ICMPv6Code, ICMPv6Type};
pub use message::ICMPv6Message;
pub use ndp::{
    NDPMessage, NDPNeighborAdvertisement, NDPNeighborSolicitation, NDPRedirect, NDPRouterAdvertisement,
    NDPRouterSolicitation,
};
pub use neighbor::{
    NDPLinkAddress, NeighborCache, NeighborConfig, NeighborEntry, NeighborEvent, NeighborReception, NeighborResolution,
    NeighborState,
};
pub use option::{
    NDPOption, NDPOptionKind, NDPOptions, NDPPreference, NDPPrefixInformation, NDPRecursiveDNSServers,
    NDPRouteInformation,
};
