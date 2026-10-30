use alloc::string::String;

use super::{FTPError, FTPReply};
use crate::protocol::ip::{IPAddress, IPv4Address, IPv6Address};

/// The address of a data connection: of PORT and PASV (RFC 959 §4.1.2),
/// of EPRT and EPSV (RFC 2428). The reply to EPSV gives no host: the
/// client connects to the server's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FTPDataAddress {
    pub host: Option<IPAddress>,
    pub port: u16,
}

impl FTPDataAddress {
    pub fn new(host: Option<IPAddress>, port: u16) -> FTPDataAddress {
        FTPDataAddress { host, port }
    }

    /// The address of `h1,h2,h3,h4,p1,p2` (PORT, and the reply to PASV): numbers of 0 to 255.
    pub fn parse_port(text: &str) -> Result<FTPDataAddress, FTPError> {
        let invalid = FTPError::Syntax { reason: "not h1,h2,h3,h4,p1,p2" };
        let mut numbers = [0u8; 6];
        let mut parts = text.trim().split(',');
        for number in &mut numbers {
            let part = parts.next().ok_or(invalid)?.trim();
            if part.is_empty() || part.len() > 3 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid);
            }
            *number = part.parse().map_err(|_| invalid)?;
        }
        if parts.next().is_some() {
            return Err(invalid);
        }
        let host = IPAddress::V4(IPv4Address::new(numbers[0], numbers[1], numbers[2], numbers[3]));
        Ok(FTPDataAddress { host: Some(host), port: u16::from_be_bytes([numbers[4], numbers[5]]) })
    }

    /// The text of PORT: `h1,h2,h3,h4,p1,p2`; IPv4 only.
    pub fn format_port(&self) -> Result<String, FTPError> {
        let Some(IPAddress::V4(host)) = self.host else {
            return Err(FTPError::State { reason: "PORT of no IPv4 address (EPRT is of others, RFC 2428)" });
        };
        let [a, b, c, d] = host.0;
        let [high, low] = self.port.to_be_bytes();
        Ok(alloc::format!("{a},{b},{c},{d},{high},{low}"))
    }

    /// The address of EPRT (RFC 2428 §2): `<d>net-prt<d>net-addr<d>tcp-port<d>`, of a printable
    /// delimiter; network protocol 1 for IPv4, 2 for IPv6. Another protocol is a State error
    /// (522, §2).
    pub fn parse_eprt(text: &str) -> Result<FTPDataAddress, FTPError> {
        let invalid = FTPError::Syntax { reason: "not an EPRT address" };
        let delimiter = text
            .chars()
            .next()
            .filter(|delimiter| (' '..='~').contains(delimiter) && !delimiter.is_ascii_digit())
            .ok_or(invalid)?;
        let fields: alloc::vec::Vec<&str> = text.split(delimiter).collect();
        let [empty, protocol, address, port, end] = fields.as_slice() else { return Err(invalid) };
        if !empty.is_empty() || !end.is_empty() {
            return Err(invalid);
        }
        let port = FTPDataAddress::port_of(port)?;
        let host = match *protocol {
            "1" => IPAddress::V4(address.parse::<IPv4Address>().map_err(|_| invalid)?),
            "2" => IPAddress::V6(address.parse::<IPv6Address>().map_err(|_| invalid)?),
            _ => return Err(FTPError::State { reason: "a network protocol not supported" }),
        };
        Ok(FTPDataAddress { host: Some(host), port })
    }

    /// A port of 1 to 65535, in decimal.
    pub fn port_of(text: &str) -> Result<u16, FTPError> {
        let valid = !text.is_empty() && text.len() <= 5 && text.bytes().all(|byte| byte.is_ascii_digit());
        valid
            .then(|| text.parse::<u16>().ok())
            .flatten()
            .filter(|port| *port > 0)
            .ok_or(FTPError::Syntax { reason: "not a port" })
    }

    /// The text of EPRT, delimited by `|`.
    pub fn format_eprt(&self) -> Result<String, FTPError> {
        match self.host {
            Some(IPAddress::V4(host)) => Ok(alloc::format!("|1|{host}|{}|", self.port)),
            Some(IPAddress::V6(host)) => Ok(alloc::format!("|2|{host}|{}|", self.port)),
            None => Err(FTPError::State { reason: "EPRT of no host" }),
        }
    }

    /// The address of a reply to PASV (227): the six numbers in its text, in parentheses or not.
    pub fn from_pasv(reply: &FTPReply) -> Result<FTPDataAddress, FTPError> {
        if reply.code != 227 {
            return Err(FTPError::State { reason: "not a reply of 227" });
        }
        let text = String::from_utf8_lossy(reply.lines.first().map(alloc::vec::Vec::as_slice).unwrap_or_default())
            .into_owned();
        let start = text
            .find(|character: char| character.is_ascii_digit())
            .ok_or(FTPError::Syntax { reason: "no address in 227" })?;
        let end = text[start..]
            .find(|character: char| !character.is_ascii_digit() && character != ',')
            .map_or(text.len(), |end| start + end);
        FTPDataAddress::parse_port(&text[start..end])
    }

    /// The reply to PASV of the address.
    pub fn pasv_reply(&self) -> Result<FTPReply, FTPError> {
        Ok(FTPReply::new(227, &alloc::format!("Entering Passive Mode ({})", self.format_port()?)))
    }

    /// The address of a reply to EPSV (229, RFC 2428 §3): the port of `(<d><d><d>port<d>)`, of no host.
    pub fn from_epsv(reply: &FTPReply) -> Result<FTPDataAddress, FTPError> {
        if reply.code != 229 {
            return Err(FTPError::State { reason: "not a reply of 229" });
        }
        let invalid = FTPError::Syntax { reason: "no port in 229" };
        let text = String::from_utf8_lossy(reply.lines.first().map(alloc::vec::Vec::as_slice).unwrap_or_default())
            .into_owned();
        let open = text.find('(').ok_or(invalid)?;
        let close = open + text[open..].find(')').ok_or(invalid)?;
        let inner = &text[open + 1..close];
        let delimiter = inner.chars().next().ok_or(invalid)?;
        let fields: alloc::vec::Vec<&str> = inner.split(delimiter).collect();
        let ["", "", "", port, ""] = fields.as_slice() else { return Err(invalid) };
        Ok(FTPDataAddress { host: None, port: FTPDataAddress::port_of(port)? })
    }

    /// The reply to EPSV of the port: `229 Entering Extended Passive Mode (|||port|)`.
    pub fn epsv_reply(&self) -> FTPReply {
        FTPReply::new(229, &alloc::format!("Entering Extended Passive Mode (|||{}|)", self.port))
    }
}
