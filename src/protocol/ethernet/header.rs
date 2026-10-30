use crate::bytes::Writer;

use super::{EtherType, EthernetError, MACAddress};

/// A VLAN tag (IEEE 802.1Q): the tag protocol identifier (0x8100 for a
/// customer tag, 0x88A8 for a service tag of IEEE 802.1ad), the priority
/// code point, the drop eligible indicator and the VLAN identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct VLANTag {
    pub protocol: EtherType,
    /// 0 to 7.
    pub priority: u8,
    pub drop_eligible: bool,
    /// 0 to 4,094; 0 marks a frame that carries only a priority. 4,095 is
    /// reserved (IEEE 802.1Q): it is read but not written.
    pub identifier: u16,
}

impl VLANTag {
    pub const LENGTH: usize = 4;
    pub const MAXIMUM_PRIORITY: u8 = 7;
    /// The largest identifier that may be sent.
    pub const MAXIMUM_IDENTIFIER: u16 = 4094;

    /// The tag of `protocol` with the tag control information `control`.
    pub const fn from_control(protocol: EtherType, control: u16) -> VLANTag {
        VLANTag {
            protocol,
            priority: (control >> 13) as u8,
            drop_eligible: control & 0x1000 != 0,
            identifier: control & 0x0FFF,
        }
    }

    /// The tag control information; `None` if a field does not fit or the
    /// identifier is the reserved 4,095.
    pub const fn control(&self) -> Option<u16> {
        if self.priority > VLANTag::MAXIMUM_PRIORITY || self.identifier > VLANTag::MAXIMUM_IDENTIFIER {
            return None;
        }
        Some((self.priority as u16) << 13 | (self.drop_eligible as u16) << 12 | self.identifier)
    }
}

/// The header of an Ethernet frame (IEEE 802.3 §3.1): the destination and
/// source addresses, up to [`EthernetHeader::MAXIMUM_TAGS`] VLAN tags,
/// outermost first, and the type field. The preamble and the frame check
/// sequence are not part of it (see [`super::EthernetFrame`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EthernetHeader {
    pub destination: MACAddress,
    pub source: MACAddress,
    /// The tags, outermost first; a `None` is followed only by `None`.
    pub tags: [Option<VLANTag>; EthernetHeader::MAXIMUM_TAGS],
    pub ether_type: EtherType,
}

impl EthernetHeader {
    pub const MINIMUM_LENGTH: usize = 14;
    /// A service tag and a customer tag (IEEE 802.1ad).
    pub const MAXIMUM_TAGS: usize = 2;

    /// An untagged header.
    pub const fn new(destination: MACAddress, source: MACAddress, ether_type: EtherType) -> EthernetHeader {
        EthernetHeader { destination, source, tags: [None; EthernetHeader::MAXIMUM_TAGS], ether_type }
    }

    /// The length of the header with its tags.
    pub fn length(&self) -> usize {
        EthernetHeader::MINIMUM_LENGTH + self.tags.iter().flatten().count() * VLANTag::LENGTH
    }

    /// The header at the start of `bytes` and the data after it. The data
    /// of an IEEE 802.3 frame, whose type field is a length, is that length
    /// (the padding after it is dropped); that of other frames is the rest.
    /// A tag with the reserved VLAN identifier 4,095 is read, so that the
    /// frame can be inspected, though [`EthernetHeader::encode`] refuses it.
    pub fn decode(bytes: &[u8]) -> Result<(EthernetHeader, &[u8]), EthernetError> {
        let fixed = bytes.get(..EthernetHeader::MINIMUM_LENGTH).ok_or(EthernetError::Length)?;
        let mut header = EthernetHeader::new(
            MACAddress([fixed[0], fixed[1], fixed[2], fixed[3], fixed[4], fixed[5]]),
            MACAddress([fixed[6], fixed[7], fixed[8], fixed[9], fixed[10], fixed[11]]),
            EtherType(u16::from_be_bytes([fixed[12], fixed[13]])),
        );
        let mut offset = EthernetHeader::MINIMUM_LENGTH;
        let mut count = 0;
        while header.ether_type.is_tag() {
            if count == EthernetHeader::MAXIMUM_TAGS {
                return Err(EthernetError::Tag);
            }
            let tag = bytes.get(offset..offset + VLANTag::LENGTH).ok_or(EthernetError::Length)?;
            header.tags[count] = Some(VLANTag::from_control(header.ether_type, u16::from_be_bytes([tag[0], tag[1]])));
            header.ether_type = EtherType(u16::from_be_bytes([tag[2], tag[3]]));
            offset += VLANTag::LENGTH;
            count += 1;
        }
        let data = &bytes[offset..];
        if header.ether_type.is_length() {
            return Ok((header, data.get(..header.ether_type.0 as usize).ok_or(EthernetError::Length)?));
        }
        if !header.ether_type.is_ether_type() {
            return Err(EthernetError::EtherType);
        }
        Ok((header, data))
    }

    /// Writes the header. The tags must be in order, with a tag protocol
    /// identifier of a tag and fields that fit, and the type field must not
    /// be a tag protocol identifier.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), EthernetError> {
        let mut bytes = [0u8; EthernetHeader::MINIMUM_LENGTH + EthernetHeader::MAXIMUM_TAGS * VLANTag::LENGTH];
        bytes[..6].copy_from_slice(&self.destination.0);
        bytes[6..12].copy_from_slice(&self.source.0);
        let mut offset = 12;
        let mut ended = false;
        for tag in &self.tags {
            match tag {
                Some(tag) if !ended && tag.protocol.is_tag() => {
                    let control = tag.control().ok_or(EthernetError::Tag)?;
                    bytes[offset..offset + 2].copy_from_slice(&tag.protocol.0.to_be_bytes());
                    bytes[offset + 2..offset + 4].copy_from_slice(&control.to_be_bytes());
                    offset += VLANTag::LENGTH;
                }
                Some(_) => return Err(EthernetError::Tag),
                None => ended = true,
            }
        }
        if !(self.ether_type.is_length() || self.ether_type.is_ether_type()) {
            return Err(EthernetError::EtherType);
        }
        // A tag protocol in the type field would be read back as one more tag.
        if self.ether_type.is_tag() {
            return Err(EthernetError::Tag);
        }
        bytes[offset..offset + 2].copy_from_slice(&self.ether_type.0.to_be_bytes());
        Ok(out.write(&bytes[..offset + 2])?)
    }
}
