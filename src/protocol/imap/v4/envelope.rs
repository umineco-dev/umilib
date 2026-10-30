use alloc::vec::Vec;

use super::{IMAPError, IMAPReader, IMAPWriter};
use crate::codec::mail::{MailAddress, MailFields};

/// An address of an envelope (RFC 9051 §9 `address`): a name, a route, a
/// mailbox and a host. A group is an address of a mailbox (its name) and no
/// host, its members, and an address of neither.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IMAPAddress {
    pub name: Option<Vec<u8>>,
    pub adl: Option<Vec<u8>>,
    pub mailbox: Option<Vec<u8>>,
    pub host: Option<Vec<u8>>,
}

/// The envelope of a message (RFC 9051 §7.5.2 ENVELOPE). An empty list of
/// addresses is NIL.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IMAPEnvelope {
    pub date: Option<Vec<u8>>,
    pub subject: Option<Vec<u8>>,
    pub from: Vec<IMAPAddress>,
    pub sender: Vec<IMAPAddress>,
    pub reply_to: Vec<IMAPAddress>,
    pub to: Vec<IMAPAddress>,
    pub cc: Vec<IMAPAddress>,
    pub bcc: Vec<IMAPAddress>,
    pub in_reply_to: Option<Vec<u8>>,
    pub message_id: Option<Vec<u8>>,
}

impl IMAPAddress {
    /// The addresses of `addresses` as an envelope has them: a group as its
    /// start, its members, and its end (§9 `addr-mailbox`).
    pub fn from_addresses(addresses: &[MailAddress]) -> Vec<IMAPAddress> {
        let mut list = Vec::new();
        for address in addresses {
            match address {
                MailAddress::Mailbox(mailbox) => list.push(IMAPAddress {
                    name: mailbox.name.as_ref().map(|name| name.clone().into_bytes()),
                    adl: None,
                    mailbox: Some(mailbox.local.clone().into_bytes()),
                    host: Some(mailbox.domain.clone().into_bytes()),
                }),
                MailAddress::Group { name, members } => {
                    list.push(IMAPAddress { mailbox: Some(name.clone().into_bytes()), ..IMAPAddress::default() });
                    list.extend(IMAPAddress::from_addresses(
                        &members.iter().cloned().map(MailAddress::Mailbox).collect::<Vec<_>>(),
                    ));
                    list.push(IMAPAddress::default());
                }
            }
        }
        list
    }

    pub fn read(reader: &mut IMAPReader<'_>) -> Result<IMAPAddress, IMAPError> {
        reader.expect(b'(', "not an address")?;
        let name = reader.nstring()?;
        reader.sp()?;
        let adl = reader.nstring()?;
        reader.sp()?;
        let mailbox = reader.nstring()?;
        reader.sp()?;
        let host = reader.nstring()?;
        reader.expect(b')', "an address not closed")?;
        Ok(IMAPAddress { name, adl, mailbox, host })
    }

    pub fn write(&self, writer: &mut IMAPWriter) {
        writer.raw(b"(");
        writer.nstring(self.name.as_deref()).sp();
        writer.nstring(self.adl.as_deref()).sp();
        writer.nstring(self.mailbox.as_deref()).sp();
        writer.nstring(self.host.as_deref());
        writer.raw(b")");
    }

    /// Reads a list of addresses, or NIL.
    pub fn read_list(reader: &mut IMAPReader<'_>) -> Result<Vec<IMAPAddress>, IMAPError> {
        if reader.eat_keyword("NIL") {
            return Ok(Vec::new());
        }
        reader.expect(b'(', "not a list of addresses")?;
        let mut list = Vec::new();
        while !reader.eat(b')') {
            list.push(IMAPAddress::read(reader)?);
            // Servers are known to put spaces between addresses; the grammar has none.
            reader.eat(b' ');
        }
        match list.is_empty() {
            true => Err(reader.error("an empty list of addresses")),
            false => Ok(list),
        }
    }

    /// Writes a list of addresses, NIL if it is empty.
    pub fn write_list(list: &[IMAPAddress], writer: &mut IMAPWriter) {
        if list.is_empty() {
            writer.raw(b"NIL");
            return;
        }
        writer.raw(b"(");
        for address in list {
            address.write(writer);
        }
        writer.raw(b")");
    }
}

impl IMAPEnvelope {
    /// The envelope of a header section (§7.5.2): the unfolded values of
    /// Date, Subject, In-Reply-To and Message-ID; the addresses of From,
    /// Sender, Reply-To, To, Cc and Bcc, a Sender or Reply-To absent or empty
    /// being From. A field of addresses that cannot be read is NIL.
    pub fn from_fields(fields: &MailFields) -> IMAPEnvelope {
        let text = |name: &str| {
            let field = fields.field(name)?;
            let value = field.unfolded();
            let trimmed = value.trim_ascii();
            Some(trimmed.to_vec())
        };
        let addresses = |name: &str| {
            fields.addresses(name).ok().flatten().map(|list| IMAPAddress::from_addresses(&list)).unwrap_or_default()
        };
        let from = addresses("From");
        let or_from = |list: Vec<IMAPAddress>| if list.is_empty() { from.clone() } else { list };
        IMAPEnvelope {
            date: text("Date"),
            subject: text("Subject"),
            sender: or_from(addresses("Sender")),
            reply_to: or_from(addresses("Reply-To")),
            from: from.clone(),
            to: addresses("To"),
            cc: addresses("Cc"),
            bcc: addresses("Bcc"),
            in_reply_to: text("In-Reply-To"),
            message_id: text("Message-ID"),
        }
    }

    pub fn read(reader: &mut IMAPReader<'_>) -> Result<IMAPEnvelope, IMAPError> {
        reader.expect(b'(', "not an envelope")?;
        let date = reader.nstring()?;
        reader.sp()?;
        let subject = reader.nstring()?;
        let mut lists: [Vec<IMAPAddress>; 6] = Default::default();
        for list in &mut lists {
            reader.sp()?;
            *list = IMAPAddress::read_list(reader)?;
        }
        reader.sp()?;
        let in_reply_to = reader.nstring()?;
        reader.sp()?;
        let message_id = reader.nstring()?;
        reader.expect(b')', "an envelope not closed")?;
        let [from, sender, reply_to, to, cc, bcc] = lists;
        Ok(IMAPEnvelope { date, subject, from, sender, reply_to, to, cc, bcc, in_reply_to, message_id })
    }

    pub fn write(&self, writer: &mut IMAPWriter) {
        writer.raw(b"(");
        writer.nstring(self.date.as_deref()).sp();
        writer.nstring(self.subject.as_deref());
        for list in [&self.from, &self.sender, &self.reply_to, &self.to, &self.cc, &self.bcc] {
            writer.sp();
            IMAPAddress::write_list(list, writer);
        }
        writer.sp();
        writer.nstring(self.in_reply_to.as_deref()).sp();
        writer.nstring(self.message_id.as_deref());
        writer.raw(b")");
    }
}
