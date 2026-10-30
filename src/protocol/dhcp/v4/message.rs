use alloc::vec::Vec;

use crate::protocol::ethernet::MACAddress;
use crate::protocol::ip::IPv4Address;

use super::super::DHCPError;
use super::{DHCPv4MessageType, DHCPv4OptionCode, DHCPv4Options};

/// A DHCPv4 message (RFC 2131 §2): the BOOTP header and the options after
/// the magic cookie. Options that overload `sname` and `file` (RFC 2132
/// §9.3) are read into the options, and those fields left empty.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DHCPv4Message {
    pub op: u8,
    pub hardware_type: u8,
    pub hardware_length: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: IPv4Address,
    pub yiaddr: IPv4Address,
    pub siaddr: IPv4Address,
    pub giaddr: IPv4Address,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: DHCPv4Options,
}

impl Default for DHCPv4Message {
    fn default() -> DHCPv4Message {
        DHCPv4Message {
            op: DHCPv4Message::BOOTREQUEST,
            hardware_type: 1,
            hardware_length: 6,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: IPv4Address::UNSPECIFIED,
            yiaddr: IPv4Address::UNSPECIFIED,
            siaddr: IPv4Address::UNSPECIFIED,
            giaddr: IPv4Address::UNSPECIFIED,
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            options: DHCPv4Options::new(),
        }
    }
}

impl DHCPv4Message {
    pub const BOOTREQUEST: u8 = 1;
    pub const BOOTREPLY: u8 = 2;
    /// The flag asking for broadcast replies (RFC 2131 §2, figure 2).
    pub const BROADCAST: u16 = 0x8000;
    /// The magic cookie before the options (RFC 2131 §3).
    pub const MAGIC: [u8; 4] = [99, 130, 83, 99];
    /// The fixed part, before the magic cookie.
    pub const HEADER_LENGTH: usize = 236;
    /// The least length of a message, as BOOTP relays expect (RFC 1542 §2.1).
    pub const MINIMUM_LENGTH: usize = 300;
    /// The largest message every host takes (RFC 2131 §2).
    pub const MINIMUM_MAXIMUM: usize = 576;
    pub const SERVER_PORT: u16 = 67;
    pub const CLIENT_PORT: u16 = 68;

    /// A client's message of `kind` from `hardware`, of the transaction `xid`.
    pub fn request(kind: DHCPv4MessageType, hardware: MACAddress, xid: u32) -> DHCPv4Message {
        let mut message = DHCPv4Message { xid, ..DHCPv4Message::default() };
        message.chaddr[..6].copy_from_slice(&hardware.0);
        message.options.set(DHCPv4OptionCode::MESSAGE_TYPE, alloc::vec![kind.0]);
        message
    }

    /// The server's reply of `kind` to `request`: its xid, flags, giaddr and
    /// chaddr, and its client identifier (RFC 6842 §3).
    pub fn reply(request: &DHCPv4Message, kind: DHCPv4MessageType) -> DHCPv4Message {
        let mut reply = DHCPv4Message {
            op: DHCPv4Message::BOOTREPLY,
            hardware_type: request.hardware_type,
            hardware_length: request.hardware_length,
            xid: request.xid,
            flags: request.flags,
            giaddr: request.giaddr,
            chaddr: request.chaddr,
            ..DHCPv4Message::default()
        };
        reply.options.set(DHCPv4OptionCode::MESSAGE_TYPE, alloc::vec![kind.0]);
        if let Some(identifier) = request.options.get(DHCPv4OptionCode::CLIENT_IDENTIFIER) {
            reply.options.set(DHCPv4OptionCode::CLIENT_IDENTIFIER, identifier.to_vec());
        }
        reply
    }

    pub fn message_type(&self) -> Option<DHCPv4MessageType> {
        self.options.message_type()
    }

    /// The client's hardware address, of `hardware_length` bytes.
    pub fn hardware_address(&self) -> &[u8] {
        &self.chaddr[..usize::from(self.hardware_length).min(16)]
    }

    pub fn is_broadcast(&self) -> bool {
        self.flags & DHCPv4Message::BROADCAST != 0
    }

    /// The key a server knows the client by: its client identifier, or
    /// its hardware type and address (RFC 2131 §4.2, RFC 4361 §6.1).
    pub fn client_key(&self) -> Vec<u8> {
        match self.options.get(DHCPv4OptionCode::CLIENT_IDENTIFIER) {
            Some(identifier) => identifier.to_vec(),
            None => [&[0u8, self.hardware_type][..], self.hardware_address()].concat(),
        }
    }

    /// The message of `bytes`: of a BOOTP header and the magic cookie,
    /// options in the options area, then, as the overload option says, in
    /// `file`, then in `sname` (RFC 2131 §4.1). Without the cookie it is
    /// BOOTP, not DHCP, and fails.
    pub fn decode(bytes: &[u8]) -> Result<DHCPv4Message, DHCPError> {
        if bytes.len() < DHCPv4Message::HEADER_LENGTH + 4 {
            return Err(DHCPError::Malformed("a message shorter than its header"));
        }
        if bytes[236..240] != DHCPv4Message::MAGIC {
            return Err(DHCPError::Malformed("a message without the magic cookie"));
        }
        let address = |at: usize| IPv4Address([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        let mut message = DHCPv4Message {
            op: bytes[0],
            hardware_type: bytes[1],
            hardware_length: bytes[2],
            hops: bytes[3],
            xid: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            secs: u16::from_be_bytes([bytes[8], bytes[9]]),
            flags: u16::from_be_bytes([bytes[10], bytes[11]]),
            ciaddr: address(12),
            yiaddr: address(16),
            siaddr: address(20),
            giaddr: address(24),
            chaddr: bytes[28..44].try_into().unwrap_or_default(),
            sname: bytes[44..108].try_into().unwrap_or([0; 64]),
            file: bytes[108..236].try_into().unwrap_or([0; 128]),
            options: DHCPv4Options::new(),
        };
        if message.op != DHCPv4Message::BOOTREQUEST && message.op != DHCPv4Message::BOOTREPLY {
            return Err(DHCPError::Malformed("an op other than BOOTREQUEST and BOOTREPLY"));
        }
        message.options.decode_area(&bytes[240..])?;
        let overload = match message.options.get(DHCPv4OptionCode::OVERLOAD) {
            None => 0,
            Some([value @ 1..=3]) => *value,
            Some(_) => return Err(DHCPError::Malformed("an overload option of another value")),
        };
        if overload & 1 != 0 {
            message.options.decode_area(&bytes[108..236])?;
            message.file = [0; 128];
        }
        if overload & 2 != 0 {
            message.options.decode_area(&bytes[44..108])?;
            message.sname = [0; 64];
        }
        message.options.remove(DHCPv4OptionCode::OVERLOAD);
        Ok(message)
    }

    /// The message, its options after the magic cookie and END, padded to
    /// at least 300 bytes (RFC 1542 §2.1).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DHCPv4Message::MINIMUM_LENGTH.max(256 + 64));
        out.extend_from_slice(&[self.op, self.hardware_type, self.hardware_length, self.hops]);
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&self.secs.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        for address in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            out.extend_from_slice(&address.0);
        }
        out.extend_from_slice(&self.chaddr);
        out.extend_from_slice(&self.sname);
        out.extend_from_slice(&self.file);
        out.extend_from_slice(&DHCPv4Message::MAGIC);
        self.options.encode(&mut out);
        if out.len() < DHCPv4Message::MINIMUM_LENGTH {
            out.resize(DHCPv4Message::MINIMUM_LENGTH, 0);
        }
        out
    }
}
