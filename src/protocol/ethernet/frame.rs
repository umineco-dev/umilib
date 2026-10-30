use crate::hash::crc::{CRC, CRCCatalogue};

/// The parts of an Ethernet frame around its header and data (IEEE 802.3
/// §3.2): the padding to the smallest frame and the frame check sequence,
/// the CRC-32 (`CRC-32/ISO-HDLC`) of the header and the data, sent least
/// significant byte first. Interfaces that hand over frames without their
/// frame check sequence (packet sockets, TAP devices) need neither.
#[derive(Clone, Copy, Debug)]
pub struct EthernetFrame;

impl EthernetFrame {
    pub const FCS_LENGTH: usize = 4;
    /// The smallest frame, its frame check sequence included.
    pub const MINIMUM_LENGTH: usize = 64;
    /// The largest data of an untagged frame (the MTU of RFC 894).
    pub const MAXIMUM_DATA_LENGTH: usize = 1500;

    /// The frame check sequence of `frame` (the header and the data), in the order it is sent.
    pub fn fcs(frame: &[u8]) -> [u8; EthernetFrame::FCS_LENGTH] {
        CRC::checksum(CRCCatalogue::CRC32_ISO_HDLC, frame).to_le_bytes()
    }

    /// Whether `frame` ends with the right frame check sequence.
    pub fn verify(frame: &[u8]) -> bool {
        let Some(split) = frame.len().checked_sub(EthernetFrame::FCS_LENGTH) else { return false };
        let (body, fcs) = frame.split_at(split);
        EthernetFrame::fcs(body) == *fcs
    }

    /// The zero bytes to append to a header and data of `length` bytes to
    /// make the smallest frame.
    pub fn padding(length: usize) -> usize {
        (EthernetFrame::MINIMUM_LENGTH - EthernetFrame::FCS_LENGTH).saturating_sub(length)
    }
}
