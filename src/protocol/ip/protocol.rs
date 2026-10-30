use core::fmt;

/// An IP protocol number: the Protocol field of IPv4 and the Next Header
/// field of IPv6, from the IANA registry "Assigned Internet Protocol
/// Numbers". Numbers without a constant here are kept as they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct IPProtocol(pub u8);

impl IPProtocol {
    pub const HOP_BY_HOP_OPTIONS: IPProtocol = IPProtocol(0);
    pub const ICMP: IPProtocol = IPProtocol(1);
    pub const IGMP: IPProtocol = IPProtocol(2);
    pub const IPV4: IPProtocol = IPProtocol(4);
    pub const TCP: IPProtocol = IPProtocol(6);
    pub const UDP: IPProtocol = IPProtocol(17);
    pub const IPV6: IPProtocol = IPProtocol(41);
    pub const IPV6_ROUTING: IPProtocol = IPProtocol(43);
    pub const IPV6_FRAGMENT: IPProtocol = IPProtocol(44);
    pub const ESP: IPProtocol = IPProtocol(50);
    pub const AH: IPProtocol = IPProtocol(51);
    pub const ICMPV6: IPProtocol = IPProtocol(58);
    pub const IPV6_NO_NEXT_HEADER: IPProtocol = IPProtocol(59);
    pub const IPV6_DESTINATION_OPTIONS: IPProtocol = IPProtocol(60);
    pub const SCTP: IPProtocol = IPProtocol(132);
    pub const MOBILITY: IPProtocol = IPProtocol(135);
    pub const HIP: IPProtocol = IPProtocol(139);
    pub const SHIM6: IPProtocol = IPProtocol(140);
    /// The numbers for experimentation and testing (RFC 3692).
    pub const EXPERIMENT_1: IPProtocol = IPProtocol(253);
    pub const EXPERIMENT_2: IPProtocol = IPProtocol(254);

    /// The keyword of the registry, for the numbers with a constant here.
    pub fn name(&self) -> Option<&'static str> {
        Some(match *self {
            IPProtocol::HOP_BY_HOP_OPTIONS => "HOPOPT",
            IPProtocol::ICMP => "ICMP",
            IPProtocol::IGMP => "IGMP",
            IPProtocol::IPV4 => "IPv4",
            IPProtocol::TCP => "TCP",
            IPProtocol::UDP => "UDP",
            IPProtocol::IPV6 => "IPv6",
            IPProtocol::IPV6_ROUTING => "IPv6-Route",
            IPProtocol::IPV6_FRAGMENT => "IPv6-Frag",
            IPProtocol::ESP => "ESP",
            IPProtocol::AH => "AH",
            IPProtocol::ICMPV6 => "IPv6-ICMP",
            IPProtocol::IPV6_NO_NEXT_HEADER => "IPv6-NoNxt",
            IPProtocol::IPV6_DESTINATION_OPTIONS => "IPv6-Opts",
            IPProtocol::SCTP => "SCTP",
            IPProtocol::MOBILITY => "Mobility Header",
            IPProtocol::HIP => "HIP",
            IPProtocol::SHIM6 => "Shim6",
            _ => return None,
        })
    }
}

impl fmt::Display for IPProtocol {
    /// The keyword of the registry, or the number.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => formatter.write_str(name),
            None => write!(formatter, "{}", self.0),
        }
    }
}
