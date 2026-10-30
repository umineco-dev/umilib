use crate::bytes::Writer;
use crate::protocol::icmp::{ICMPError, ICMPExtensions};
use crate::protocol::ip::v6::{
    IPv6ExtensionHeader, IPv6ExtensionHeaders, IPv6FragmentHeader, IPv6Header, IPv6OptionKind,
};
use crate::protocol::ip::{IPProtocol, IPPseudoHeader, IPv6Address};

use super::{ICMPv6Code, ICMPv6Type};

/// An ICMPv6 message (RFC 4443): its type, its code, the four bytes after
/// the checksum, whose meaning depends on the type, and the body. The
/// checksum covers the pseudo-header of the packet's addresses (RFC 8200
/// §8.1) and is not kept: [`ICMPv6Message::decode`] checks it and
/// [`ICMPv6Message::encode`] computes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ICMPv6Message<'a> {
    pub kind: ICMPv6Type,
    pub code: u8,
    pub rest: [u8; 4],
    pub body: &'a [u8],
}

impl<'a> ICMPv6Message<'a> {
    pub const HEADER_LENGTH: usize = 8;
    /// The largest packet an error message makes: the minimum IPv6 MTU (RFC 4443 §2.4 (c)).
    pub const MAXIMUM_ERROR_LENGTH: usize = 1280;
    /// The word of the length attribute of RFC 4884.
    pub const WORD: usize = 8;

    /// The message that `bytes` is, carried from `source` to `destination`;
    /// its checksum must be right.
    pub fn decode(
        bytes: &'a [u8],
        source: IPv6Address,
        destination: IPv6Address,
    ) -> Result<ICMPv6Message<'a>, ICMPError> {
        let header = bytes.get(..ICMPv6Message::HEADER_LENGTH).ok_or(ICMPError::Length)?;
        let pseudo =
            IPPseudoHeader::V6 { source, destination, next_header: IPProtocol::ICMPV6, length: bytes.len() as u32 };
        let mut checksum = pseudo.checksum();
        checksum.update(bytes);
        if bytes.len() > u32::MAX as usize || checksum.sum16() != 0xFFFF {
            return Err(ICMPError::Checksum);
        }
        Ok(ICMPv6Message {
            kind: ICMPv6Type(header[0]),
            code: header[1],
            rest: [header[4], header[5], header[6], header[7]],
            body: &bytes[ICMPv6Message::HEADER_LENGTH..],
        })
    }

    /// The bytes of the header, with the checksum of the whole message
    /// carried from `source` to `destination`; the length of the message
    /// must fit the 32 bits of the pseudo-header, or [`ICMPError::Length`].
    pub fn header(
        &self,
        source: IPv6Address,
        destination: IPv6Address,
    ) -> Result<[u8; ICMPv6Message::HEADER_LENGTH], ICMPError> {
        let [a, b, c, d] = self.rest;
        let mut header = [self.kind.0, self.code, 0, 0, a, b, c, d];
        let length = u32::try_from(self.length()).map_err(|_| ICMPError::Length)?;
        let mut checksum =
            IPPseudoHeader::V6 { source, destination, next_header: IPProtocol::ICMPV6, length }.checksum();
        checksum.update(&header);
        checksum.update(self.body);
        header[2..4].copy_from_slice(&checksum.finish().to_be_bytes());
        Ok(header)
    }

    /// Writes the message with its checksum for `source` and `destination`.
    pub fn encode(
        &self,
        source: IPv6Address,
        destination: IPv6Address,
        out: &mut impl Writer,
    ) -> Result<(), ICMPError> {
        out.write(&self.header(source, destination)?)?;
        Ok(out.write(self.body)?)
    }

    pub fn length(&self) -> usize {
        ICMPv6Message::HEADER_LENGTH + self.body.len()
    }

    /// An Echo Request of `identifier`, `sequence` and `data`.
    pub fn echo_request(identifier: u16, sequence: u16, data: &'a [u8]) -> ICMPv6Message<'a> {
        let [a, b] = identifier.to_be_bytes();
        let [c, d] = sequence.to_be_bytes();
        ICMPv6Message { kind: ICMPv6Type::ECHO_REQUEST, code: 0, rest: [a, b, c, d], body: data }
    }

    /// The Echo Reply to this Echo Request: the same identifier, sequence
    /// and data (RFC 4443 §4.2).
    pub fn echo_reply(&self) -> Option<ICMPv6Message<'a>> {
        (self.kind == ICMPv6Type::ECHO_REQUEST).then_some(ICMPv6Message {
            kind: ICMPv6Type::ECHO_REPLY,
            code: 0,
            ..*self
        })
    }

    /// The identifier of an Echo Request or Reply.
    pub fn identifier(&self) -> Option<u16> {
        self.is_echo().then(|| u16::from_be_bytes([self.rest[0], self.rest[1]]))
    }

    /// The sequence number of an Echo Request or Reply.
    pub fn sequence(&self) -> Option<u16> {
        self.is_echo().then(|| u16::from_be_bytes([self.rest[2], self.rest[3]]))
    }

    pub fn is_echo(&self) -> bool {
        matches!(self.kind, ICMPv6Type::ECHO_REQUEST | ICMPv6Type::ECHO_REPLY)
    }

    /// The MTU of the next hop of a Packet Too Big message (RFC 4443 §3.2).
    pub fn mtu(&self) -> Option<u32> {
        (self.kind == ICMPv6Type::PACKET_TOO_BIG).then(|| u32::from_be_bytes(self.rest))
    }

    /// The offset in the invoking packet a Parameter Problem points to (RFC 4443 §3.4).
    pub fn pointer(&self) -> Option<u32> {
        (self.kind == ICMPv6Type::PARAMETER_PROBLEM).then(|| u32::from_be_bytes(self.rest))
    }

    /// The invoking packet an error message quotes and its extension
    /// structure (RFC 4884), if any: the length attribute of the extensible
    /// types says where the quote ends; the body of other errors is all quote.
    pub fn original(&self) -> Result<(&'a [u8], Option<ICMPExtensions<'a>>), ICMPError> {
        let attribute = if self.kind.is_extensible() { self.rest[0] } else { 0 };
        ICMPExtensions::split_body(self.body, attribute, ICMPv6Message::WORD)
    }

    /// The header of the invoking packet an error message quotes and the
    /// part of its payload quoted (RFC 4443 §2.4 (d)). The quote starts the
    /// body even when its extensions are malformed, so it is read then from
    /// the whole body.
    pub fn invoking(&self) -> Option<(IPv6Header, &'a [u8])> {
        let original = self.original().map_or(self.body, |(original, _)| original);
        IPv6Header::decode_truncated(original).ok()
    }

    /// The start of `packet`, a packet received, that an error message
    /// quotes: as much as keeps the error within the minimum IPv6 MTU (RFC
    /// 4443 §2.4 (c)) after an IPv6 header and `headers` bytes of extension headers.
    pub fn quote(packet: &[u8], headers: usize) -> &[u8] {
        &packet[..ICMPv6Message::quote_length(packet.len(), headers)]
    }

    /// The bytes of a packet of `length` bytes that [`ICMPv6Message::quote`] keeps.
    pub fn quote_length(length: usize, headers: usize) -> usize {
        let before = headers.saturating_add(IPv6Header::LENGTH + ICMPv6Message::HEADER_LENGTH);
        length.min(ICMPv6Message::MAXIMUM_ERROR_LENGTH.saturating_sub(before))
    }

    /// Whether the error `error` may be sent about the packet of `header`
    /// and `payload` (RFC 4443 §2.4 (e)); its body is not read. Not about an
    /// ICMPv6 error message or Redirect, nor about a packet to a multicast
    /// address or received as a link-layer multicast or broadcast
    /// (`multicast`), except for Packet Too Big and a Parameter Problem
    /// (code 2) pointing to an unrecognized option whose type has its two
    /// highest bits 10, nor about a packet whose source is not a single node
    /// (unspecified or multicast; an anycast address is for the caller to
    /// know). A packet that may be ICMPv6 but whose type cannot be read (cut
    /// short, or a fragment other than the first) counts as an error message;
    /// one whose header chain cannot be read, or that ends in an ESP header,
    /// is not known to be ICMPv6 and may be reported, so that a Parameter
    /// Problem can be sent about the chain.
    pub fn may_report(header: &IPv6Header, payload: &[u8], multicast: bool, error: &ICMPv6Message) -> bool {
        let about_error = match ICMPv6Message::invoking_kind(header, payload) {
            Ok(Some(kind)) => kind.is_error() || kind == ICMPv6Type::REDIRECT,
            Ok(None) => false,
            Err(_) => true,
        };
        let option = error
            .pointer()
            .filter(|_| error.code == ICMPv6Code::UNRECOGNIZED_OPTION)
            .and_then(|pointer| usize::try_from(pointer).ok()?.checked_sub(IPv6Header::LENGTH))
            .and_then(|offset| payload.get(offset))
            .map(|&kind| IPv6OptionKind(kind));
        let exception = error.kind == ICMPv6Type::PACKET_TOO_BIG || option.is_some_and(|option| option.action() == 2);
        let to_group = multicast || header.destination.is_multicast();
        !about_error && (!to_group || exception) && !header.source.is_unspecified() && !header.source.is_multicast()
    }

    /// The ICMPv6 type of the packet of `header` and `payload`: `None` if it
    /// is not ICMPv6 (or its header chain cannot be read), and
    /// [`ICMPError::Length`] if it may be ICMPv6 but its type cannot be read:
    /// it is cut short, or it is a fragment other than the first whose data
    /// starts with ICMPv6 or another extension header. Such a fragment's data
    /// is not read as headers.
    pub fn invoking_kind(header: &IPv6Header, payload: &[u8]) -> Result<Option<ICMPv6Type>, ICMPError> {
        let mut headers = IPv6ExtensionHeaders::new(header.next_header, payload);
        for extension in &mut headers {
            let Ok(extension) = extension else { return Ok(None) };
            if extension.kind != IPProtocol::IPV6_FRAGMENT {
                continue;
            }
            let Ok(fragment) = IPv6FragmentHeader::decode(extension.bytes) else { return Ok(None) };
            let next = fragment.next_header;
            if fragment.fragment_offset != 0 {
                let may_be_icmp = next == IPProtocol::ICMPV6 || IPv6ExtensionHeader::is_extension(next);
                return if may_be_icmp { Err(ICMPError::Length) } else { Ok(None) };
            }
        }
        if headers.next_header != IPProtocol::ICMPV6 {
            return Ok(None);
        }
        payload.get(headers.offset).map(|&kind| Some(ICMPv6Type(kind))).ok_or(ICMPError::Length)
    }
}
