use alloc::vec::Vec;

use super::{MailConfig, MailError, MailField, MailFields};

/// A message (RFC 5322 §2.1): a header section and a body.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct MailMessage {
    pub fields: MailFields,
    pub body: Vec<u8>,
}

impl MailMessage {
    /// The fields of RFC 5322 §3.6 that a message has at most once.
    pub const SINGLE_FIELDS: [&'static str; 11] =
        ["Date", "From", "Sender", "Reply-To", "To", "Cc", "Bcc", "Message-ID", "In-Reply-To", "References", "Subject"];

    pub fn new(fields: MailFields, body: Vec<u8>) -> MailMessage {
        MailMessage { fields, body }
    }

    /// The message of `text`; the body is what follows the empty line after the fields.
    pub fn decode(text: &[u8], config: &MailConfig) -> Result<MailMessage, MailError> {
        if text.len() > config.maximum_length {
            return Err(MailError::TooLong { length: text.len(), maximum: config.maximum_length });
        }
        let (fields, body) = MailFields::decode(text, config)?;
        Ok(MailMessage { fields, body: text[body..].to_vec() })
    }

    /// The message as it is written: its fields, an empty line, its body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 1024);
        self.fields.encode(&mut out);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    /// Checks what RFC 5322 requires of a message: a Date and a From field
    /// (§3.6), the fields of [`MailMessage::SINGLE_FIELDS`] at most once,
    /// a Sender of one mailbox if From has more than one (§3.6.2 as RFC
    /// 6854 §2.1 replaces it, groups counted by their mailboxes), the fields of
    /// addresses, dates and identifiers readable, CR and LF only together
    /// in the body and lines of at most 998 characters (§2.1.1, §2.3).
    pub fn validate(&self) -> Result<(), MailError> {
        let invalid = |reason| MailError::Syntax { position: 0, reason };
        for name in MailMessage::SINGLE_FIELDS {
            if self.fields.all(name).count() > 1 {
                return Err(invalid("a field given more than once"));
            }
        }
        self.fields.date("Date")?.ok_or(invalid("no Date field"))?;
        // RFC 6854 §2.1: From is an address list, Sender an address, a group of at most one mailbox.
        let from = self.fields.addresses("From")?.ok_or(invalid("no From field"))?;
        let authors: usize = from.iter().map(|address| address.mailboxes().len()).sum();
        // An empty group is an author that cannot be replied to (RFC 6854 §4).
        if from.is_empty() {
            return Err(invalid("no address in the From field"));
        }
        let sender = self.fields.address("Sender")?;
        if sender.as_ref().is_some_and(|sender| sender.mailboxes().len() > 1) {
            return Err(invalid("a Sender of more than one mailbox"));
        }
        if authors > 1 && sender.is_none() {
            return Err(invalid("more than one author and no Sender field"));
        }
        for name in ["Reply-To", "To", "Cc", "Bcc"] {
            self.fields.addresses(name)?;
        }
        for name in ["Message-ID", "In-Reply-To", "References"] {
            self.fields.message_ids(name)?;
        }
        if self.fields.message_ids("Message-ID")?.is_some_and(|identifiers| identifiers.len() != 1) {
            return Err(invalid("not one message identifier"));
        }
        let mut line = 0;
        for (position, byte) in self.body.iter().enumerate() {
            match byte {
                b'\r' if self.body.get(position + 1) == Some(&b'\n') => {}
                b'\n' if position > 0 && self.body[position - 1] == b'\r' => line = 0,
                b'\r' | b'\n' => return Err(MailError::Syntax { position, reason: "a CR or LF alone in the body" }),
                _ => {
                    line += 1;
                    if line > MailField::MAXIMUM_LINE {
                        return Err(MailError::TooLong { length: line, maximum: MailField::MAXIMUM_LINE });
                    }
                }
            }
        }
        Ok(())
    }
}
