use super::super::IPProtocol;
use super::IPv6Error;

/// One extension header of a header chain: its kind (the Next Header value
/// that names it), the Next Header value it holds, and all of its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPv6ExtensionHeader<'a> {
    pub kind: IPProtocol,
    pub next_header: IPProtocol,
    pub bytes: &'a [u8],
}

impl IPv6ExtensionHeader<'_> {
    /// Whether `kind` names an extension header that a chain continues
    /// after: those of the IANA registry "IPv6 Extension Header Types"
    /// (RFC 7045) but the Encapsulating Security Payload, whose contents
    /// are encrypted, so that it ends the chain as an upper layer does.
    pub fn is_extension(kind: IPProtocol) -> bool {
        matches!(
            kind,
            IPProtocol::HOP_BY_HOP_OPTIONS
                | IPProtocol::IPV6_ROUTING
                | IPProtocol::IPV6_FRAGMENT
                | IPProtocol::AH
                | IPProtocol::IPV6_DESTINATION_OPTIONS
                | IPProtocol::MOBILITY
                | IPProtocol::HIP
                | IPProtocol::SHIM6
                | IPProtocol::EXPERIMENT_1
                | IPProtocol::EXPERIMENT_2
        )
    }

    /// The length of the extension header of `kind` that `bytes` starts
    /// with: 8 bytes for a Fragment header, `(length + 2) × 4` for an
    /// Authentication header (RFC 4302 §2.2), and `(length + 1) × 8` for the
    /// others (RFC 8200 §4, RFC 6564).
    pub fn length(kind: IPProtocol, bytes: &[u8]) -> Result<usize, IPv6Error> {
        let length = match kind {
            IPProtocol::IPV6_FRAGMENT => 8,
            IPProtocol::AH => (*bytes.get(1).ok_or(IPv6Error::Length)? as usize + 2) * 4,
            _ => (*bytes.get(1).ok_or(IPv6Error::Length)? as usize + 1) * 8,
        };
        if length > bytes.len() {
            return Err(IPv6Error::Length);
        }
        Ok(length)
    }
}

/// The extension headers of a payload, in order (RFC 8200 §4.1): a
/// Hop-by-Hop Options header after the first fails with
/// [`IPv6Error::ExtensionHeader`]. When it ends, `next_header` is the
/// upper layer (or ESP, or No Next Header) and `bytes` its data.
#[derive(Clone, Debug)]
pub struct IPv6ExtensionHeaders<'a> {
    pub next_header: IPProtocol,
    pub bytes: &'a [u8],
    /// The offset of `bytes` in the payload.
    pub offset: usize,
    pub failed: bool,
}

impl<'a> IPv6ExtensionHeaders<'a> {
    /// The headers of `payload`, the first of which is named by the Next
    /// Header field `next_header` of the IPv6 header.
    pub fn new(next_header: IPProtocol, payload: &'a [u8]) -> IPv6ExtensionHeaders<'a> {
        IPv6ExtensionHeaders { next_header, bytes: payload, offset: 0, failed: false }
    }

    /// The upper layer of `payload` and the offset of its data, after every
    /// extension header.
    pub fn upper_layer(next_header: IPProtocol, payload: &'a [u8]) -> Result<(IPProtocol, usize), IPv6Error> {
        let mut headers = IPv6ExtensionHeaders::new(next_header, payload);
        for header in &mut headers {
            header?;
        }
        Ok((headers.next_header, headers.offset))
    }
}

impl<'a> Iterator for IPv6ExtensionHeaders<'a> {
    type Item = Result<IPv6ExtensionHeader<'a>, IPv6Error>;

    fn next(&mut self) -> Option<Result<IPv6ExtensionHeader<'a>, IPv6Error>> {
        let kind = self.next_header;
        if self.failed || !IPv6ExtensionHeader::is_extension(kind) {
            return None;
        }
        let result = if kind == IPProtocol::HOP_BY_HOP_OPTIONS && self.offset != 0 {
            Err(IPv6Error::ExtensionHeader)
        } else {
            IPv6ExtensionHeader::length(kind, self.bytes)
        };
        let length = match result {
            Ok(length) => length,
            Err(error) => {
                self.failed = true;
                return Some(Err(error));
            }
        };
        let (bytes, rest) = self.bytes.split_at(length);
        let header = IPv6ExtensionHeader { kind, next_header: IPProtocol(bytes[0]), bytes };
        self.next_header = header.next_header;
        self.bytes = rest;
        self.offset += length;
        Some(Ok(header))
    }
}
