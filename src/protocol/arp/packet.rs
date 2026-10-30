use crate::bytes::Writer;
use crate::protocol::ethernet::{EtherType, MACAddress};
use crate::protocol::ip::IPv4Address;

use super::{ARPAddress, ARPError};

/// The hardware type of an ARP packet, from the IANA registry "Hardware
/// Types" (RFC 5494). Values without a constant here are kept as they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ARPHardwareType(pub u16);

impl ARPHardwareType {
    pub const ETHERNET: ARPHardwareType = ARPHardwareType(1);
    pub const IEEE_802: ARPHardwareType = ARPHardwareType(6);
    pub const INFINIBAND: ARPHardwareType = ARPHardwareType(32);
}

/// The operation of an ARP packet, from the IANA registry "Operation Codes" (RFC 5494).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ARPOperation(pub u16);

impl ARPOperation {
    pub const REQUEST: ARPOperation = ARPOperation(1);
    pub const REPLY: ARPOperation = ARPOperation(2);
}

/// An ARP packet (RFC 826) whose hardware addresses are `H` and protocol
/// addresses are `P`: MAC and IPv4 addresses on Ethernet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ARPPacket<H: ARPAddress = MACAddress, P: ARPAddress = IPv4Address> {
    pub hardware_type: ARPHardwareType,
    /// The protocol, named by its EtherType.
    pub protocol_type: EtherType,
    pub operation: ARPOperation,
    pub sender_hardware: H,
    pub sender_protocol: P,
    /// Ignored in a request (RFC 5227 §2.1.1: sent as zeros).
    pub target_hardware: H,
    pub target_protocol: P,
}

impl<H: ARPAddress, P: ARPAddress> ARPPacket<H, P> {
    /// The length of the fixed fields before the addresses.
    pub const FIXED_LENGTH: usize = 8;

    pub fn length() -> usize {
        ARPPacket::<H, P>::FIXED_LENGTH + 2 * (H::LENGTH + P::LENGTH)
    }

    /// The packet at the start of `bytes` (any bytes after it, such as the
    /// padding of a frame, are ignored). Its address lengths must be those of `H` and `P`.
    pub fn decode(bytes: &[u8]) -> Result<ARPPacket<H, P>, ARPError> {
        let fixed = bytes.get(..ARPPacket::<H, P>::FIXED_LENGTH).ok_or(ARPError::Length)?;
        if fixed[4] as usize != H::LENGTH || fixed[5] as usize != P::LENGTH {
            return Err(ARPError::Length);
        }
        let addresses =
            bytes.get(ARPPacket::<H, P>::FIXED_LENGTH..ARPPacket::<H, P>::length()).ok_or(ARPError::Length)?;
        let (sender_hardware, rest) = addresses.split_at(H::LENGTH);
        let (sender_protocol, rest) = rest.split_at(P::LENGTH);
        let (target_hardware, target_protocol) = rest.split_at(H::LENGTH);
        Ok(ARPPacket {
            hardware_type: ARPHardwareType(u16::from_be_bytes([fixed[0], fixed[1]])),
            protocol_type: EtherType(u16::from_be_bytes([fixed[2], fixed[3]])),
            operation: ARPOperation(u16::from_be_bytes([fixed[6], fixed[7]])),
            sender_hardware: H::from_bytes(sender_hardware).ok_or(ARPError::Length)?,
            sender_protocol: P::from_bytes(sender_protocol).ok_or(ARPError::Length)?,
            target_hardware: H::from_bytes(target_hardware).ok_or(ARPError::Length)?,
            target_protocol: P::from_bytes(target_protocol).ok_or(ARPError::Length)?,
        })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), ARPError> {
        let lengths = [u8::try_from(H::LENGTH), u8::try_from(P::LENGTH)];
        let [Ok(hardware_length), Ok(protocol_length)] = lengths else { return Err(ARPError::Length) };
        out.write(&self.hardware_type.0.to_be_bytes())?;
        out.write(&self.protocol_type.0.to_be_bytes())?;
        out.write(&[hardware_length, protocol_length])?;
        out.write(&self.operation.0.to_be_bytes())?;
        out.write(self.sender_hardware.as_bytes())?;
        out.write(self.sender_protocol.as_bytes())?;
        out.write(self.target_hardware.as_bytes())?;
        Ok(out.write(self.target_protocol.as_bytes())?)
    }

    /// The reply to this request from `hardware`, the hardware address of
    /// its target (RFC 826: the fields swapped, the local addresses as sender).
    pub fn reply(&self, hardware: H) -> ARPPacket<H, P> {
        ARPPacket {
            operation: ARPOperation::REPLY,
            sender_hardware: hardware,
            sender_protocol: self.target_protocol,
            target_hardware: self.sender_hardware,
            target_protocol: self.sender_protocol,
            ..*self
        }
    }

    /// Whether the packet is a probe: a request with an unspecified sender
    /// protocol address (RFC 5227 §2.1.1).
    pub fn is_probe(&self) -> bool {
        self.operation == ARPOperation::REQUEST && self.sender_protocol.is_unspecified()
    }

    /// Whether the packet is an announcement (a gratuitous ARP): the sender
    /// and target protocol addresses are the same (RFC 5227 §2.3).
    pub fn is_announcement(&self) -> bool {
        self.sender_protocol == self.target_protocol && !self.sender_protocol.is_unspecified()
    }
}

impl ARPPacket<MACAddress, IPv4Address> {
    /// A request on Ethernet for the hardware address of `target` from
    /// `sender_hardware` and `sender_protocol` (unspecified for a probe).
    pub fn ethernet_request(
        sender_hardware: MACAddress,
        sender_protocol: IPv4Address,
        target: IPv4Address,
    ) -> ARPPacket<MACAddress, IPv4Address> {
        ARPPacket {
            hardware_type: ARPHardwareType::ETHERNET,
            protocol_type: EtherType::IPV4,
            operation: ARPOperation::REQUEST,
            sender_hardware,
            sender_protocol,
            target_hardware: MACAddress::ZERO,
            target_protocol: target,
        }
    }
}
