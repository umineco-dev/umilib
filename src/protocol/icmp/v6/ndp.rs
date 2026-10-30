use crate::bytes::{Buffer, Writer};
use crate::protocol::icmp::ICMPError;
use crate::protocol::ip::IPv6Address;
use crate::protocol::ip::v6::IPv6Header;

use super::{ICMPv6Message, ICMPv6Type, NDPOptionKind, NDPOptions, NDPPreference};

/// What every Neighbor Discovery message is checked for (RFC 4861 §6.1,
/// §7.1, §8.1), and its writing.
#[derive(Clone, Copy, Debug)]
pub struct NDPMessage;

impl NDPMessage {
    /// The hop limit of every Neighbor Discovery message: it cannot have been forwarded.
    pub const HOP_LIMIT: u8 = 255;

    /// Checks that `message` is of `kind`, code 0, with at least `length`
    /// bytes of body, sent with a hop limit of 255 (`header`), and that the
    /// options after those `length` bytes have lengths greater than zero.
    pub fn check(
        message: &ICMPv6Message,
        header: &IPv6Header,
        kind: ICMPv6Type,
        length: usize,
    ) -> Result<(), ICMPError> {
        if message.kind != kind
            || message.code != 0
            || header.hop_limit != NDPMessage::HOP_LIMIT
            || message.body.len() < length
        {
            return Err(ICMPError::Invalid);
        }
        NDPOptions::check(&message.body[length..])
    }

    /// Whether `address` is a solicited-node multicast address (`ff02::1:ff00:0/104`).
    pub fn is_solicited_node(address: &IPv6Address) -> bool {
        address.has_prefix(&IPv6Address::from_words([0xFF02, 0, 0, 0, 0, 1, 0xFF00, 0]), 104)
    }

    /// Writes the message of `kind`, `rest` and the body `body` from `source` to `destination`.
    pub fn encode(
        kind: ICMPv6Type,
        rest: [u8; 4],
        body: &[u8],
        source: IPv6Address,
        destination: IPv6Address,
        out: &mut impl Writer,
    ) -> Result<(), ICMPError> {
        ICMPv6Message { kind, code: 0, rest, body }.encode(source, destination, out)
    }
}

/// A Router Solicitation (RFC 4861 §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NDPRouterSolicitation<'a> {
    pub options: &'a [u8],
}

impl<'a> NDPRouterSolicitation<'a> {
    /// The solicitation of `message`, carried by the packet of `header`,
    /// which must pass the validity checks of RFC 4861 §6.1.1.
    pub fn decode(message: &ICMPv6Message<'a>, header: &IPv6Header) -> Result<NDPRouterSolicitation<'a>, ICMPError> {
        NDPMessage::check(message, header, ICMPv6Type::ROUTER_SOLICITATION, 0)?;
        let options = message.body;
        if header.source.is_unspecified() && NDPOptions::find(options, NDPOptionKind::SOURCE_LINK_ADDRESS).is_some() {
            return Err(ICMPError::Invalid);
        }
        Ok(NDPRouterSolicitation { options })
    }

    pub fn encode(
        &self,
        source: IPv6Address,
        destination: IPv6Address,
        out: &mut impl Writer,
    ) -> Result<(), ICMPError> {
        NDPMessage::encode(ICMPv6Type::ROUTER_SOLICITATION, [0; 4], self.options, source, destination, out)
    }

    /// The link-layer address of the sender, if given.
    pub fn source_link_address(&self) -> Option<&'a [u8]> {
        NDPOptions::find(self.options, NDPOptionKind::SOURCE_LINK_ADDRESS)
    }
}

/// A Router Advertisement (RFC 4861 §4.2, with the preference of RFC 4191).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NDPRouterAdvertisement<'a> {
    /// The hop limit hosts are to use; 0 if unspecified.
    pub current_hop_limit: u8,
    /// Addresses are available from DHCPv6 (the M flag).
    pub managed_flag: bool,
    /// Other configuration is available from DHCPv6 (the O flag).
    pub other_flag: bool,
    /// The preference of the router as a default router ([`NDPPreference`],
    /// RFC 4191 §2.2); medium (0) when the router lifetime is 0.
    pub preference: u8,
    /// The bits of the flags field that have no field here, as received:
    /// those defined after RFC 4861 (the H flag of RFC 6275, the P flag of
    /// RFC 4389) and the reserved ones.
    pub flags: u8,
    /// Seconds; 0 if the router is not a default router.
    pub router_lifetime: u16,
    /// Milliseconds; 0 if unspecified.
    pub reachable_time: u32,
    /// Milliseconds; 0 if unspecified.
    pub retransmission_timer: u32,
    pub options: &'a [u8],
}

impl<'a> NDPRouterAdvertisement<'a> {
    /// The bits of the flags field that [`NDPRouterAdvertisement::flags`] holds.
    pub const FLAGS: u8 = 0x27;

    /// The advertisement of `message`, carried by the packet of `header`,
    /// which must pass the validity checks of RFC 4861 §6.1.2. A reserved
    /// preference, or any preference with a router lifetime of 0, is read as
    /// medium (RFC 4191 §2.2).
    pub fn decode(message: &ICMPv6Message<'a>, header: &IPv6Header) -> Result<NDPRouterAdvertisement<'a>, ICMPError> {
        NDPMessage::check(message, header, ICMPv6Type::ROUTER_ADVERTISEMENT, 8)?;
        if !header.source.is_link_local() {
            return Err(ICMPError::Invalid);
        }
        let body = message.body;
        let [current_hop_limit, flags, lifetime_high, lifetime_low] = message.rest;
        let router_lifetime = u16::from_be_bytes([lifetime_high, lifetime_low]);
        let preference = (flags >> 3) & 0b11;
        Ok(NDPRouterAdvertisement {
            current_hop_limit,
            managed_flag: flags & 0x80 != 0,
            other_flag: flags & 0x40 != 0,
            preference: if router_lifetime == 0 || preference == NDPPreference::RESERVED {
                NDPPreference::MEDIUM
            } else {
                preference
            },
            flags: flags & NDPRouterAdvertisement::FLAGS,
            router_lifetime,
            reachable_time: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
            retransmission_timer: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
            options: &body[8..],
        })
    }

    /// Writes the advertisement; the preference must be one of the three
    /// that are sent, and medium when the router lifetime is 0 (RFC 4191
    /// §2.2), and `flags` must hold only its bits.
    pub fn encode(
        &self,
        source: IPv6Address,
        destination: IPv6Address,
        out: &mut impl Writer,
    ) -> Result<(), ICMPError> {
        if !NDPPreference::is_valid(self.preference)
            || (self.router_lifetime == 0 && self.preference != NDPPreference::MEDIUM)
            || self.flags & !NDPRouterAdvertisement::FLAGS != 0
        {
            return Err(ICMPError::Invalid);
        }
        let flags = (self.managed_flag as u8) << 7 | (self.other_flag as u8) << 6 | self.preference << 3 | self.flags;
        let [high, low] = self.router_lifetime.to_be_bytes();
        let mut body = Buffer::new();
        body.write(&self.reachable_time.to_be_bytes())?;
        body.write(&self.retransmission_timer.to_be_bytes())?;
        body.write(self.options)?;
        let rest = [self.current_hop_limit, flags, high, low];
        NDPMessage::encode(ICMPv6Type::ROUTER_ADVERTISEMENT, rest, body.as_slice(), source, destination, out)
    }

    /// The link-layer address of the router, if given.
    pub fn source_link_address(&self) -> Option<&'a [u8]> {
        NDPOptions::find(self.options, NDPOptionKind::SOURCE_LINK_ADDRESS)
    }
}

/// A Neighbor Solicitation (RFC 4861 §4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NDPNeighborSolicitation<'a> {
    pub target: IPv6Address,
    pub options: &'a [u8],
}

impl<'a> NDPNeighborSolicitation<'a> {
    /// The solicitation of `message`, carried by the packet of `header`,
    /// which must pass the validity checks of RFC 4861 §7.1.1.
    pub fn decode(message: &ICMPv6Message<'a>, header: &IPv6Header) -> Result<NDPNeighborSolicitation<'a>, ICMPError> {
        NDPMessage::check(message, header, ICMPv6Type::NEIGHBOR_SOLICITATION, 16)?;
        let target = IPv6Address(message.body[..16].try_into().map_err(|_| ICMPError::Invalid)?);
        let options = &message.body[16..];
        if target.is_multicast() {
            return Err(ICMPError::Invalid);
        }
        let unspecified = header.source.is_unspecified();
        if unspecified
            && (!NDPMessage::is_solicited_node(&header.destination)
                || NDPOptions::find(options, NDPOptionKind::SOURCE_LINK_ADDRESS).is_some())
        {
            return Err(ICMPError::Invalid);
        }
        Ok(NDPNeighborSolicitation { target, options })
    }

    pub fn encode(
        &self,
        source: IPv6Address,
        destination: IPv6Address,
        out: &mut impl Writer,
    ) -> Result<(), ICMPError> {
        let mut body = Buffer::new();
        body.write(&self.target.0)?;
        body.write(self.options)?;
        NDPMessage::encode(ICMPv6Type::NEIGHBOR_SOLICITATION, [0; 4], body.as_slice(), source, destination, out)
    }

    /// The link-layer address of the sender, if given.
    pub fn source_link_address(&self) -> Option<&'a [u8]> {
        NDPOptions::find(self.options, NDPOptionKind::SOURCE_LINK_ADDRESS)
    }

    /// Whether the solicitation is of duplicate address detection: from the
    /// unspecified address (RFC 4862 §5.4.2).
    pub fn is_duplicate_address_detection(header: &IPv6Header) -> bool {
        header.source.is_unspecified()
    }
}

/// A Neighbor Advertisement (RFC 4861 §4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NDPNeighborAdvertisement<'a> {
    /// The sender is a router (the R flag).
    pub router_flag: bool,
    /// The advertisement answers a solicitation (the S flag).
    pub solicited_flag: bool,
    /// The advertisement overrides a cached link-layer address (the O flag).
    pub override_flag: bool,
    pub target: IPv6Address,
    pub options: &'a [u8],
}

impl<'a> NDPNeighborAdvertisement<'a> {
    /// The advertisement of `message`, carried by the packet of `header`,
    /// which must pass the validity checks of RFC 4861 §7.1.2.
    pub fn decode(message: &ICMPv6Message<'a>, header: &IPv6Header) -> Result<NDPNeighborAdvertisement<'a>, ICMPError> {
        NDPMessage::check(message, header, ICMPv6Type::NEIGHBOR_ADVERTISEMENT, 16)?;
        let target = IPv6Address(message.body[..16].try_into().map_err(|_| ICMPError::Invalid)?);
        let flags = message.rest[0];
        let advertisement = NDPNeighborAdvertisement {
            router_flag: flags & 0x80 != 0,
            solicited_flag: flags & 0x40 != 0,
            override_flag: flags & 0x20 != 0,
            target,
            options: &message.body[16..],
        };
        if target.is_multicast() || (header.destination.is_multicast() && advertisement.solicited_flag) {
            return Err(ICMPError::Invalid);
        }
        Ok(advertisement)
    }

    pub fn encode(
        &self,
        source: IPv6Address,
        destination: IPv6Address,
        out: &mut impl Writer,
    ) -> Result<(), ICMPError> {
        let flags = (self.router_flag as u8) << 7 | (self.solicited_flag as u8) << 6 | (self.override_flag as u8) << 5;
        let mut body = Buffer::new();
        body.write(&self.target.0)?;
        body.write(self.options)?;
        NDPMessage::encode(
            ICMPv6Type::NEIGHBOR_ADVERTISEMENT,
            [flags, 0, 0, 0],
            body.as_slice(),
            source,
            destination,
            out,
        )
    }

    /// The link-layer address of the target, if given.
    pub fn target_link_address(&self) -> Option<&'a [u8]> {
        NDPOptions::find(self.options, NDPOptionKind::TARGET_LINK_ADDRESS)
    }
}

/// A Redirect (RFC 4861 §4.5): a better first hop (`target`) for `destination`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NDPRedirect<'a> {
    pub target: IPv6Address,
    pub destination: IPv6Address,
    pub options: &'a [u8],
}

impl<'a> NDPRedirect<'a> {
    /// The redirect of `message`, carried by the packet of `header`, which
    /// must pass the validity checks of RFC 4861 §8.1 but the one that
    /// needs the routing state: that the source is the current first hop for
    /// `destination`, which the caller checks.
    pub fn decode(message: &ICMPv6Message<'a>, header: &IPv6Header) -> Result<NDPRedirect<'a>, ICMPError> {
        NDPMessage::check(message, header, ICMPv6Type::REDIRECT, 32)?;
        let target = IPv6Address(message.body[..16].try_into().map_err(|_| ICMPError::Invalid)?);
        let destination = IPv6Address(message.body[16..32].try_into().map_err(|_| ICMPError::Invalid)?);
        if !header.source.is_link_local()
            || destination.is_multicast()
            || !(target.is_link_local() || target == destination)
        {
            return Err(ICMPError::Invalid);
        }
        Ok(NDPRedirect { target, destination, options: &message.body[32..] })
    }

    pub fn encode(
        &self,
        source: IPv6Address,
        destination: IPv6Address,
        out: &mut impl Writer,
    ) -> Result<(), ICMPError> {
        let mut body = Buffer::new();
        body.write(&self.target.0)?;
        body.write(&self.destination.0)?;
        body.write(self.options)?;
        NDPMessage::encode(ICMPv6Type::REDIRECT, [0; 4], body.as_slice(), source, destination, out)
    }

    /// The link-layer address of the target, if given.
    pub fn target_link_address(&self) -> Option<&'a [u8]> {
        NDPOptions::find(self.options, NDPOptionKind::TARGET_LINK_ADDRESS)
    }
}
