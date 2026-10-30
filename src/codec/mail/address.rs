use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::{MailError, MailReader};

/// A mailbox (RFC 5322 §3.4): a display name, if any, and an address of a
/// local part and a domain. The display name is as written, its quoting
/// removed; [`MIMEEncodedWord::decode_text`](super::MIMEEncodedWord::decode_text)
/// decodes its encoded words (RFC 2047 §5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MailMailbox {
    pub name: Option<String>,
    pub local: String,
    pub domain: String,
}

/// An address (RFC 5322 §3.4): a mailbox, or a named group of mailboxes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MailAddress {
    Mailbox(MailMailbox),
    Group { name: String, members: Vec<MailMailbox> },
}

impl MailMailbox {
    pub fn new(name: Option<&str>, local: &str, domain: &str) -> MailMailbox {
        MailMailbox { name: name.map(String::from), local: String::from(local), domain: String::from(domain) }
    }

    /// The address: the local part, quoted if it is not a dot-atom, `@`, and the domain.
    pub fn address(&self) -> String {
        let mut address = MailMailbox::quote_if_needed(&self.local, true);
        address.push('@');
        address.push_str(&self.domain);
        address
    }

    /// `text` as it is if it is a dot-atom (or, for a phrase, atoms and
    /// spaces), else as a quoted string (RFC 5322 §3.2.4).
    pub fn quote_if_needed(text: &str, dotted: bool) -> String {
        let atom = |part: &str| !part.is_empty() && part.bytes().all(|byte| MailReader::is_atext(byte, true));
        let plain = match dotted {
            true => text.split('.').all(atom),
            false => text.split(' ').all(atom),
        };
        if plain {
            return String::from(text);
        }
        let mut quoted = String::with_capacity(text.len() + 2);
        quoted.push('"');
        for character in text.chars() {
            if character == '"' || character == '\\' {
                quoted.push('\\');
            }
            quoted.push(character);
        }
        quoted.push('"');
        quoted
    }

    /// The mailbox of `text`, and nothing after it but CFWS.
    pub fn parse(text: &[u8], utf8: bool) -> Result<MailMailbox, MailError> {
        let mut reader = MailReader::new(text, utf8);
        let mailbox = MailMailbox::read(&mut reader)?;
        reader.skip_cfws()?;
        match reader.is_end() {
            true => Ok(mailbox),
            false => Err(reader.error("more after a mailbox")),
        }
    }

    /// The mailboxes of a mailbox-list (RFC 5322 §3.4, with the empty
    /// elements of obs-mbox-list, §4.4).
    pub fn parse_list(text: &[u8], utf8: bool) -> Result<Vec<MailMailbox>, MailError> {
        let mut reader = MailReader::new(text, utf8);
        let mut mailboxes = Vec::new();
        loop {
            reader.skip_cfws()?;
            if reader.is_end() {
                break;
            }
            if reader.eat(b',') {
                continue;
            }
            mailboxes.push(MailMailbox::read(&mut reader)?);
            reader.skip_cfws()?;
            if !reader.is_end() {
                reader.expect(b',', "not a separator of mailboxes")?;
            }
        }
        match mailboxes.is_empty() {
            true => Err(reader.error("no mailbox")),
            false => Ok(mailboxes),
        }
    }

    /// Reads a mailbox: a name-addr or an addr-spec (RFC 5322 §3.4).
    pub fn read(reader: &mut MailReader<'_>) -> Result<MailMailbox, MailError> {
        reader.skip_cfws()?;
        if reader.peek() == Some(b'<') {
            return MailMailbox::angle_address(reader, None);
        }
        let start = *reader;
        let phrase = reader.phrase()?;
        if reader.peek() == Some(b'<') {
            let name = reader.text_of(phrase)?;
            return MailMailbox::angle_address(reader, Some(name));
        }
        *reader = start;
        let (local, domain) = MailMailbox::address_spec(reader)?;
        Ok(MailMailbox { name: None, local, domain })
    }

    /// An addr-spec (RFC 5322 §3.4.1): local part, `@`, domain.
    pub fn address_spec(reader: &mut MailReader<'_>) -> Result<(String, String), MailError> {
        let local = reader.local_part()?;
        reader.expect(b'@', "an address without @")?;
        let domain = reader.domain()?;
        Ok((local, domain))
    }

    /// An angle-addr, with the obs-route of §4.4, which is ignored.
    pub fn angle_address(reader: &mut MailReader<'_>, name: Option<String>) -> Result<MailMailbox, MailError> {
        reader.skip_cfws()?;
        reader.expect(b'<', "not an angle address")?;
        reader.skip_cfws()?;
        if matches!(reader.peek(), Some(b'@' | b',')) {
            loop {
                reader.skip_cfws()?;
                if reader.eat(b',') {
                    continue;
                }
                if reader.eat(b'@') {
                    reader.domain()?;
                    continue;
                }
                reader.expect(b':', "a route not ended by a colon")?;
                break;
            }
        }
        let (local, domain) = MailMailbox::address_spec(reader)?;
        reader.expect(b'>', "an angle address not closed")?;
        reader.skip_cfws()?;
        Ok(MailMailbox { name, local, domain })
    }
}

impl fmt::Display for MailMailbox {
    /// The mailbox as RFC 5322 §3.4 writes it: `name <address>`, or the address alone.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => write!(formatter, "{} <{}>", MailMailbox::quote_if_needed(name, false), self.address()),
            None => formatter.write_str(&self.address()),
        }
    }
}

impl MailAddress {
    /// The addresses of an address-list (RFC 5322 §3.4, with the empty
    /// elements of obs-addr-list, §4.4).
    pub fn parse_list(text: &[u8], utf8: bool) -> Result<Vec<MailAddress>, MailError> {
        let mut reader = MailReader::new(text, utf8);
        let mut addresses = Vec::new();
        loop {
            reader.skip_cfws()?;
            if reader.is_end() {
                break;
            }
            if reader.eat(b',') {
                continue;
            }
            addresses.push(MailAddress::read(&mut reader)?);
            reader.skip_cfws()?;
            if !reader.is_end() {
                reader.expect(b',', "not a separator of addresses")?;
            }
        }
        Ok(addresses)
    }

    /// The address of `text`, and nothing after it but CFWS.
    pub fn parse(text: &[u8], utf8: bool) -> Result<MailAddress, MailError> {
        let mut reader = MailReader::new(text, utf8);
        let address = MailAddress::read(&mut reader)?;
        reader.skip_cfws()?;
        match reader.is_end() {
            true => Ok(address),
            false => Err(reader.error("more after an address")),
        }
    }

    /// The mailboxes of the address: itself, or the members of the group.
    pub fn mailboxes(&self) -> &[MailMailbox] {
        match self {
            MailAddress::Mailbox(mailbox) => core::slice::from_ref(mailbox),
            MailAddress::Group { members, .. } => members,
        }
    }

    /// Reads an address: a group, a display name and a colon first (RFC 5322 §3.4), or a mailbox.
    pub fn read(reader: &mut MailReader<'_>) -> Result<MailAddress, MailError> {
        reader.skip_cfws()?;
        let start = *reader;
        if reader.peek() != Some(b'<')
            && let Ok(phrase) = reader.phrase()
            && reader.eat(b':')
        {
            let name = reader.text_of(phrase)?;
            let mut members = Vec::new();
            // §3.4: group-list = mailbox-list, its mailboxes separated by commas; empty items are
            // taken (the obsolete syntax of §4.4), two mailboxes without a comma are not.
            let mut separated = true;
            loop {
                reader.skip_cfws()?;
                if reader.eat(b';') {
                    break;
                }
                if reader.eat(b',') {
                    separated = true;
                    continue;
                }
                if reader.is_end() {
                    return Err(reader.error("a group not ended by a semicolon"));
                }
                if !separated {
                    return Err(reader.error("mailboxes of a group not separated by a comma"));
                }
                members.push(MailMailbox::read(reader)?);
                separated = false;
            }
            reader.skip_cfws()?;
            return Ok(MailAddress::Group { name, members });
        }
        *reader = start;
        MailMailbox::read(reader).map(MailAddress::Mailbox)
    }

    /// Writes `addresses` as an address-list, separated by commas.
    pub fn format_list(addresses: &[MailAddress]) -> String {
        let mut text = String::new();
        for (index, address) in addresses.iter().enumerate() {
            if index > 0 {
                text.push_str(", ");
            }
            text.push_str(&alloc::format!("{address}"));
        }
        text
    }
}

impl fmt::Display for MailAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MailAddress::Mailbox(mailbox) => write!(formatter, "{mailbox}"),
            MailAddress::Group { name, members } => {
                write!(formatter, "{}:", MailMailbox::quote_if_needed(name, false))?;
                for (index, member) in members.iter().enumerate() {
                    let separator = if index > 0 { ", " } else { " " };
                    write!(formatter, "{separator}{member}")?;
                }
                formatter.write_str(";")
            }
        }
    }
}
