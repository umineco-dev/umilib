use alloc::vec::Vec;

/// What a node allows of UDP beyond RFC 768: the ports of the zero checksum
/// of IPv6 (RFC 6935, RFC 6936). By default there are none: every IPv6
/// datagram is sent with a checksum, as RFC 6936 §4 (2) recommends, and one
/// received without is discarded, as §4 (5) requires. IPv4 datagrams may always go without one
/// (RFC 768).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UDPConfig {
    /// The local ports that may send IPv6 datagrams with a zero checksum (RFC 6936 §4 (3)).
    pub zero_checksum_send_ports: Vec<u16>,
    /// The local ports that may receive IPv6 datagrams with a zero checksum (RFC 6936 §4 (6)).
    pub zero_checksum_receive_ports: Vec<u16>,
}
