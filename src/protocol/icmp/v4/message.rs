use crate::bytes::Writer;
use crate::protocol::icmp::{ICMPError, ICMPExtensions};
use crate::protocol::ip::v4::IPv4Header;
use crate::protocol::ip::{IPProtocol, IPv4Address, InternetChecksum};

use super::ICMPv4Type;

/// An ICMP message (RFC 792): its type, its code, the four bytes after the
/// checksum, whose meaning depends on the type, and the body. The checksum
/// is not kept: [`ICMPv4Message::decode`] checks it and
/// [`ICMPv4Message::encode`] computes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ICMPv4Message<'a> {
    pub kind: ICMPv4Type,
    pub code: u8,
    pub rest: [u8; 4],
    pub body: &'a [u8],
}

impl<'a> ICMPv4Message<'a> {
    pub const HEADER_LENGTH: usize = 8;
    /// The largest datagram an error message makes (RFC 1812 §4.3.2.3: the
    /// smallest reassembly buffer of RFC 791).
    pub const MAXIMUM_ERROR_LENGTH: usize = 576;
    /// The fewest bytes of the original datagram's data an error quotes
    /// after its header (RFC 792).
    pub const MINIMUM_QUOTE: usize = 8;
    /// The word of the length attribute of RFC 4884.
    pub const WORD: usize = 4;

    /// The message that `bytes` is; its checksum must be right.
    pub fn decode(bytes: &'a [u8]) -> Result<ICMPv4Message<'a>, ICMPError> {
        let header = bytes.get(..ICMPv4Message::HEADER_LENGTH).ok_or(ICMPError::Length)?;
        if !InternetChecksum::verify(bytes) {
            return Err(ICMPError::Checksum);
        }
        Ok(ICMPv4Message {
            kind: ICMPv4Type(header[0]),
            code: header[1],
            rest: [header[4], header[5], header[6], header[7]],
            body: &bytes[ICMPv4Message::HEADER_LENGTH..],
        })
    }

    /// The bytes of the header, with the checksum of the whole message.
    pub fn header(&self) -> [u8; ICMPv4Message::HEADER_LENGTH] {
        let [a, b, c, d] = self.rest;
        let mut header = [self.kind.0, self.code, 0, 0, a, b, c, d];
        let mut checksum = InternetChecksum::new();
        checksum.update(&header);
        checksum.update(self.body);
        header[2..4].copy_from_slice(&checksum.finish().to_be_bytes());
        header
    }

    /// Writes the message with its checksum.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), ICMPError> {
        out.write(&self.header())?;
        Ok(out.write(self.body)?)
    }

    pub fn length(&self) -> usize {
        ICMPv4Message::HEADER_LENGTH + self.body.len()
    }

    /// An Echo Request of `identifier`, `sequence` and `data`.
    pub fn echo_request(identifier: u16, sequence: u16, data: &'a [u8]) -> ICMPv4Message<'a> {
        let [a, b] = identifier.to_be_bytes();
        let [c, d] = sequence.to_be_bytes();
        ICMPv4Message { kind: ICMPv4Type::ECHO_REQUEST, code: 0, rest: [a, b, c, d], body: data }
    }

    /// The Echo Reply to this Echo Request: the same identifier, sequence
    /// and data (RFC 792, RFC 1122 §3.2.2.6).
    pub fn echo_reply(&self) -> Option<ICMPv4Message<'a>> {
        (self.kind == ICMPv4Type::ECHO_REQUEST).then_some(ICMPv4Message {
            kind: ICMPv4Type::ECHO_REPLY,
            code: 0,
            ..*self
        })
    }

    /// The identifier of an Echo, Timestamp or their replies.
    pub fn identifier(&self) -> Option<u16> {
        self.is_query().then(|| u16::from_be_bytes([self.rest[0], self.rest[1]]))
    }

    /// The sequence number of an Echo, Timestamp or their replies.
    pub fn sequence(&self) -> Option<u16> {
        self.is_query().then(|| u16::from_be_bytes([self.rest[2], self.rest[3]]))
    }

    /// Whether the message is an Echo, a Timestamp or their replies.
    pub fn is_query(&self) -> bool {
        matches!(
            self.kind,
            ICMPv4Type::ECHO_REQUEST | ICMPv4Type::ECHO_REPLY | ICMPv4Type::TIMESTAMP | ICMPv4Type::TIMESTAMP_REPLY
        )
    }

    /// The originate, receive and transmit timestamps of a Timestamp or
    /// Timestamp Reply (milliseconds since midnight UT, RFC 792).
    pub fn timestamps(&self) -> Option<[u32; 3]> {
        if !matches!(self.kind, ICMPv4Type::TIMESTAMP | ICMPv4Type::TIMESTAMP_REPLY) {
            return None;
        }
        let body = self.body.get(..12)?;
        let word = |index: usize| u32::from_be_bytes([body[index], body[index + 1], body[index + 2], body[index + 3]]);
        Some([word(0), word(4), word(8)])
    }

    /// The MTU of the next hop of a Fragmentation Needed message (RFC 1191 §4);
    /// zero from a router older than RFC 1191.
    pub fn next_hop_mtu(&self) -> Option<u16> {
        (self.kind == ICMPv4Type::DESTINATION_UNREACHABLE && self.code == super::ICMPv4Code::FRAGMENTATION_NEEDED)
            .then(|| u16::from_be_bytes([self.rest[2], self.rest[3]]))
    }

    /// The octet of the original datagram a Parameter Problem points to.
    pub fn pointer(&self) -> Option<u8> {
        (self.kind == ICMPv4Type::PARAMETER_PROBLEM).then_some(self.rest[0])
    }

    /// The gateway a Redirect names.
    pub fn gateway(&self) -> Option<IPv4Address> {
        (self.kind == ICMPv4Type::REDIRECT).then_some(IPv4Address(self.rest))
    }

    /// The original datagram an error message quotes and its extension
    /// structure (RFC 4884), if any: the length attribute of the extensible
    /// types says where the quote ends; the body of other errors is all quote.
    pub fn original(&self) -> Result<(&'a [u8], Option<ICMPExtensions<'a>>), ICMPError> {
        let attribute = if self.kind.is_extensible() { self.rest[1] } else { 0 };
        ICMPExtensions::split_body(self.body, attribute, ICMPv4Message::WORD)
    }

    /// The header of the original datagram an error message quotes and the
    /// part of its data quoted (at least 8 bytes, RFC 792): what the upper
    /// layer that sent it needs to find the error's flow. The quote starts
    /// the body even when its extensions are malformed, so it is read then
    /// from the whole body.
    pub fn invoking(&self) -> Option<(IPv4Header, &'a [u8])> {
        let original = self.original().map_or(self.body, |(original, _)| original);
        IPv4Header::decode_truncated(original).ok()
    }

    /// The start of `datagram`, a datagram received, that an error message
    /// quotes: as much as keeps the error within 576 bytes (RFC 1812
    /// §4.3.2.3) under an IPv4 header of `header_length` bytes.
    pub fn quote(datagram: &[u8], header_length: usize) -> &[u8] {
        &datagram[..ICMPv4Message::quote_length(datagram.len(), header_length)]
    }

    /// The bytes of a datagram of `length` bytes that [`ICMPv4Message::quote`] keeps.
    pub fn quote_length(length: usize, header_length: usize) -> usize {
        let before = header_length.saturating_add(ICMPv4Message::HEADER_LENGTH);
        length.min(ICMPv4Message::MAXIMUM_ERROR_LENGTH.saturating_sub(before))
    }

    /// Whether an error message may be sent about the datagram of `header`
    /// and `payload` (RFC 1122 §3.2.2): not about an ICMP error message, a
    /// datagram to a broadcast or multicast address, a datagram received
    /// as a link-layer broadcast or to a broadcast address of the interface
    /// (`broadcast`), a fragment other than the first, or a datagram whose
    /// source is not a single host (0.0.0.0/8, 127.0.0.0/8, multicast,
    /// 240.0.0.0/4 and 255.255.255.255).
    pub fn may_report(header: &IPv4Header, payload: &[u8], broadcast: bool) -> bool {
        let is_error =
            header.protocol == IPProtocol::ICMP && payload.first().is_none_or(|&kind| ICMPv4Type(kind).is_error());
        let source = header.source;
        let single_host = !(source.0[0] == 0 || source.is_loopback() || source.is_multicast() || source.0[0] >= 240);
        !is_error
            && !broadcast
            && !header.destination.is_broadcast()
            && !header.destination.is_multicast()
            && header.fragment_offset == 0
            && single_host
    }
}
