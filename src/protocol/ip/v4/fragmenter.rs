use super::{IPv4Error, IPv4Header};

/// The fragments of a datagram that fit an MTU (RFC 791 §3.2): each is a
/// header and the part of the data it carries, every part but the last a
/// multiple of 8 bytes. The first fragment has every option, the others
/// those with the copied flag. A fragment can itself be fragmented again:
/// the offsets are relative to its own, and the last part keeps its More
/// Fragments flag. A datagram that fits is one fragment, unchanged but for
/// its total length.
#[derive(Clone, Debug)]
pub struct IPv4Fragmenter<'a> {
    pub header: IPv4Header,
    pub payload: &'a [u8],
    pub mtu: usize,
    /// The offset in `payload` of the next fragment's data; past the end when done.
    pub position: usize,
    pub done: bool,
}

impl<'a> IPv4Fragmenter<'a> {
    /// The fragments of `payload` after `header` for `mtu`. Fails with
    /// [`IPv4Error::Fragment`] if the datagram is larger than `mtu` and
    /// has Don't Fragment set, or if a fragment could not carry 8 bytes,
    /// and with [`IPv4Error::Length`] if the datagram would be larger than
    /// 65,535 bytes.
    pub fn new(header: IPv4Header, payload: &'a [u8], mtu: usize) -> Result<IPv4Fragmenter<'a>, IPv4Error> {
        let end = header.fragment_offset as usize * IPv4Header::FRAGMENT_UNIT + payload.len();
        if header.header_length() + end > IPv4Header::MAXIMUM_TOTAL_LENGTH {
            return Err(IPv4Error::Length);
        }
        if header.header_length() + payload.len() > mtu {
            let later = IPv4Header { options: header.options.copied(), ..header };
            let room = |header: &IPv4Header| mtu.saturating_sub(header.header_length()) / IPv4Header::FRAGMENT_UNIT;
            if header.dont_fragment || room(&header) == 0 || room(&later) == 0 {
                return Err(IPv4Error::Fragment);
            }
        }
        Ok(IPv4Fragmenter { header, payload, mtu, position: 0, done: false })
    }
}

impl<'a> Iterator for IPv4Fragmenter<'a> {
    type Item = (IPv4Header, &'a [u8]);

    fn next(&mut self) -> Option<(IPv4Header, &'a [u8])> {
        if self.done {
            return None;
        }
        let mut header = self.header;
        if self.position > 0 {
            header.options = header.options.copied();
        }
        let remaining = self.payload.len() - self.position;
        let room = self.mtu.saturating_sub(header.header_length());
        let length =
            if remaining <= room { remaining } else { room / IPv4Header::FRAGMENT_UNIT * IPv4Header::FRAGMENT_UNIT };
        let last = length == remaining;
        let data = &self.payload[self.position..self.position + length];
        header.fragment_offset = self.header.fragment_offset + (self.position / IPv4Header::FRAGMENT_UNIT) as u16;
        header.more_fragments = !last || self.header.more_fragments;
        // The length fits: the whole datagram does (checked by `new`).
        header.total_length = (header.header_length() + length) as u16;
        self.position += length;
        self.done = last;
        Some((header, data))
    }
}
