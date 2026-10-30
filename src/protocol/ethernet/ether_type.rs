use core::fmt;

/// The type field of an Ethernet frame: an EtherType (from 0x0600, IEEE
/// 802.3 §3.2.6, from the IEEE and IANA registries; RFC 7042) or, up to
/// 1,500, the length of an IEEE 802.3 frame's data. Values without a
/// constant here are kept as they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EtherType(pub u16);

impl EtherType {
    pub const IPV4: EtherType = EtherType(0x0800);
    pub const ARP: EtherType = EtherType(0x0806);
    pub const WAKE_ON_LAN: EtherType = EtherType(0x0842);
    /// The customer VLAN tag of IEEE 802.1Q.
    pub const VLAN: EtherType = EtherType(0x8100);
    pub const IPV6: EtherType = EtherType(0x86DD);
    pub const MPLS: EtherType = EtherType(0x8847);
    pub const MPLS_MULTICAST: EtherType = EtherType(0x8848);
    pub const PPPOE_DISCOVERY: EtherType = EtherType(0x8863);
    pub const PPPOE_SESSION: EtherType = EtherType(0x8864);
    /// The service VLAN tag of IEEE 802.1ad.
    pub const SERVICE_VLAN: EtherType = EtherType(0x88A8);
    pub const LLDP: EtherType = EtherType(0x88CC);
    pub const MACSEC: EtherType = EtherType(0x88E5);
    /// The local experimental EtherTypes of IEEE 802 (RFC 7042 §2.4).
    pub const EXPERIMENTAL_1: EtherType = EtherType(0x88B5);
    pub const EXPERIMENTAL_2: EtherType = EtherType(0x88B6);
    /// The largest length of an IEEE 802.3 frame's data.
    pub const MAXIMUM_LENGTH: u16 = 1500;
    /// The smallest EtherType.
    pub const MINIMUM: u16 = 0x0600;

    /// Whether the field is the length of an IEEE 802.3 frame's data.
    pub const fn is_length(&self) -> bool {
        self.0 <= EtherType::MAXIMUM_LENGTH
    }

    pub const fn is_ether_type(&self) -> bool {
        self.0 >= EtherType::MINIMUM
    }

    /// Whether the EtherType is that of a VLAN tag (IEEE 802.1Q, 802.1ad).
    pub const fn is_tag(&self) -> bool {
        matches!(*self, EtherType::VLAN | EtherType::SERVICE_VLAN)
    }
}

impl fmt::Display for EtherType {
    /// The hexadecimal value, as `0x86dd`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:#06x}", self.0)
    }
}
