use core::fmt;

/// The type of an ICMPv6 message, from the IANA registry "ICMPv6 'type'
/// Numbers". Types without a constant here are kept as they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ICMPv6Type(pub u8);

impl ICMPv6Type {
    pub const DESTINATION_UNREACHABLE: ICMPv6Type = ICMPv6Type(1);
    pub const PACKET_TOO_BIG: ICMPv6Type = ICMPv6Type(2);
    pub const TIME_EXCEEDED: ICMPv6Type = ICMPv6Type(3);
    pub const PARAMETER_PROBLEM: ICMPv6Type = ICMPv6Type(4);
    pub const ECHO_REQUEST: ICMPv6Type = ICMPv6Type(128);
    pub const ECHO_REPLY: ICMPv6Type = ICMPv6Type(129);
    pub const MULTICAST_LISTENER_QUERY: ICMPv6Type = ICMPv6Type(130);
    pub const MULTICAST_LISTENER_REPORT: ICMPv6Type = ICMPv6Type(131);
    pub const MULTICAST_LISTENER_DONE: ICMPv6Type = ICMPv6Type(132);
    pub const ROUTER_SOLICITATION: ICMPv6Type = ICMPv6Type(133);
    pub const ROUTER_ADVERTISEMENT: ICMPv6Type = ICMPv6Type(134);
    pub const NEIGHBOR_SOLICITATION: ICMPv6Type = ICMPv6Type(135);
    pub const NEIGHBOR_ADVERTISEMENT: ICMPv6Type = ICMPv6Type(136);
    pub const REDIRECT: ICMPv6Type = ICMPv6Type(137);
    /// RFC 3810.
    pub const MULTICAST_LISTENER_REPORT_V2: ICMPv6Type = ICMPv6Type(143);
    /// RFC 8335.
    pub const EXTENDED_ECHO_REQUEST: ICMPv6Type = ICMPv6Type(160);
    /// RFC 8335.
    pub const EXTENDED_ECHO_REPLY: ICMPv6Type = ICMPv6Type(161);

    /// Whether the type is that of an error message: below 128 (RFC 4443 §2.1).
    pub const fn is_error(&self) -> bool {
        self.0 < 128
    }

    /// Whether an error of this type carries the length attribute of RFC
    /// 4884 and may have extensions: Destination Unreachable and Time Exceeded.
    pub const fn is_extensible(&self) -> bool {
        matches!(self.0, 1 | 3)
    }
}

impl fmt::Display for ICMPv6Type {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// The codes of ICMPv6 error messages, by type (RFC 4443 §3, RFC 7112, RFC 8883).
#[derive(Clone, Copy, Debug)]
pub struct ICMPv6Code;

impl ICMPv6Code {
    // Destination Unreachable.
    pub const NO_ROUTE: u8 = 0;
    pub const ADMINISTRATIVELY_PROHIBITED: u8 = 1;
    pub const BEYOND_SCOPE: u8 = 2;
    pub const ADDRESS_UNREACHABLE: u8 = 3;
    pub const PORT_UNREACHABLE: u8 = 4;
    pub const SOURCE_POLICY_FAILED: u8 = 5;
    pub const REJECT_ROUTE: u8 = 6;
    /// RFC 8883.
    pub const SOURCE_ROUTING_HEADER_ERROR: u8 = 7;
    /// RFC 8883.
    pub const HEADERS_TOO_LONG: u8 = 8;
    // Time Exceeded.
    pub const HOP_LIMIT_EXCEEDED: u8 = 0;
    pub const REASSEMBLY_TIME_EXCEEDED: u8 = 1;
    // Parameter Problem.
    pub const ERRONEOUS_HEADER_FIELD: u8 = 0;
    pub const UNRECOGNIZED_NEXT_HEADER: u8 = 1;
    pub const UNRECOGNIZED_OPTION: u8 = 2;
    /// RFC 7112: a first fragment without the whole header chain.
    pub const INCOMPLETE_HEADER_CHAIN: u8 = 3;
}
