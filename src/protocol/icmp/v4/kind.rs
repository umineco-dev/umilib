use core::fmt;

/// The type of an ICMP message, from the IANA registry "ICMP Type
/// Numbers". Types without a constant here are kept as they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ICMPv4Type(pub u8);

impl ICMPv4Type {
    pub const ECHO_REPLY: ICMPv4Type = ICMPv4Type(0);
    pub const DESTINATION_UNREACHABLE: ICMPv4Type = ICMPv4Type(3);
    /// Deprecated (RFC 6633): not to be sent, and ignored when received.
    pub const SOURCE_QUENCH: ICMPv4Type = ICMPv4Type(4);
    pub const REDIRECT: ICMPv4Type = ICMPv4Type(5);
    pub const ECHO_REQUEST: ICMPv4Type = ICMPv4Type(8);
    /// RFC 1256.
    pub const ROUTER_ADVERTISEMENT: ICMPv4Type = ICMPv4Type(9);
    /// RFC 1256.
    pub const ROUTER_SOLICITATION: ICMPv4Type = ICMPv4Type(10);
    pub const TIME_EXCEEDED: ICMPv4Type = ICMPv4Type(11);
    pub const PARAMETER_PROBLEM: ICMPv4Type = ICMPv4Type(12);
    pub const TIMESTAMP: ICMPv4Type = ICMPv4Type(13);
    pub const TIMESTAMP_REPLY: ICMPv4Type = ICMPv4Type(14);
    /// RFC 8335.
    pub const EXTENDED_ECHO_REQUEST: ICMPv4Type = ICMPv4Type(42);
    /// RFC 8335.
    pub const EXTENDED_ECHO_REPLY: ICMPv4Type = ICMPv4Type(43);

    /// Whether the type is that of an error message (RFC 1122 §3.2.2):
    /// Destination Unreachable, Source Quench, Redirect, Time Exceeded and
    /// Parameter Problem.
    pub const fn is_error(&self) -> bool {
        matches!(self.0, 3 | 4 | 5 | 11 | 12)
    }

    /// Whether the type is deprecated (RFC 6633, RFC 6918): Source Quench,
    /// Alternate Host Address, Information, Address Mask, Traceroute,
    /// Datagram Conversion Error, Mobile Host Redirect, the IPv6 types,
    /// Mobile Registration, Domain Name and SKIP.
    pub const fn is_deprecated(&self) -> bool {
        matches!(self.0, 4 | 6 | 15..=18 | 30..=39)
    }

    /// Whether an error of this type carries the length attribute of RFC
    /// 4884 and may have extensions: Destination Unreachable, Time
    /// Exceeded and Parameter Problem.
    pub const fn is_extensible(&self) -> bool {
        matches!(self.0, 3 | 11 | 12)
    }
}

impl fmt::Display for ICMPv4Type {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// The codes of ICMP messages, by type (RFC 792, RFC 1122 §3.2.2, RFC 1812
/// §5.2.7.1, RFC 1191).
#[derive(Clone, Copy, Debug)]
pub struct ICMPv4Code;

impl ICMPv4Code {
    // Destination Unreachable.
    pub const NETWORK_UNREACHABLE: u8 = 0;
    pub const HOST_UNREACHABLE: u8 = 1;
    pub const PROTOCOL_UNREACHABLE: u8 = 2;
    pub const PORT_UNREACHABLE: u8 = 3;
    /// With the MTU of the next hop (RFC 1191).
    pub const FRAGMENTATION_NEEDED: u8 = 4;
    pub const SOURCE_ROUTE_FAILED: u8 = 5;
    pub const DESTINATION_NETWORK_UNKNOWN: u8 = 6;
    pub const DESTINATION_HOST_UNKNOWN: u8 = 7;
    pub const SOURCE_HOST_ISOLATED: u8 = 8;
    pub const NETWORK_PROHIBITED: u8 = 9;
    pub const HOST_PROHIBITED: u8 = 10;
    pub const NETWORK_UNREACHABLE_FOR_TOS: u8 = 11;
    pub const HOST_UNREACHABLE_FOR_TOS: u8 = 12;
    pub const COMMUNICATION_PROHIBITED: u8 = 13;
    pub const HOST_PRECEDENCE_VIOLATION: u8 = 14;
    pub const PRECEDENCE_CUTOFF: u8 = 15;
    // Redirect.
    pub const REDIRECT_NETWORK: u8 = 0;
    pub const REDIRECT_HOST: u8 = 1;
    pub const REDIRECT_TOS_NETWORK: u8 = 2;
    pub const REDIRECT_TOS_HOST: u8 = 3;
    // Time Exceeded.
    pub const TIME_TO_LIVE_EXCEEDED: u8 = 0;
    pub const REASSEMBLY_TIME_EXCEEDED: u8 = 1;
    // Parameter Problem.
    pub const POINTER: u8 = 0;
    pub const MISSING_OPTION: u8 = 1;
    pub const BAD_LENGTH: u8 = 2;
}
