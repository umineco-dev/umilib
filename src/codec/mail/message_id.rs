use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::{MailError, MailReader};

/// A message identifier (RFC 5322 §3.6.4): `<left@right>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MailMessageID {
    pub left: String,
    pub right: String,
}

impl MailMessageID {
    pub fn new(left: &str, right: &str) -> MailMessageID {
        MailMessageID { left: String::from(left), right: String::from(right) }
    }

    /// The identifiers of `text`: of Message-ID one, of In-Reply-To and
    /// References a list (§3.6.4), each `<id-left@id-right>` or of the
    /// obsolete forms of §4.5.4 (a local part, a domain); words between them
    /// in References, of obs-references, are skipped.
    pub fn parse_list(text: &[u8], utf8: bool) -> Result<Vec<MailMessageID>, MailError> {
        let mut reader = MailReader::new(text, utf8);
        let mut identifiers = Vec::new();
        loop {
            reader.skip_cfws()?;
            match reader.peek() {
                None => break,
                Some(b'<') => identifiers.push(MailMessageID::read(&mut reader)?),
                Some(_) => {
                    reader.word()?;
                }
            }
        }
        Ok(identifiers)
    }

    /// The one identifier of `text`.
    pub fn parse(text: &[u8], utf8: bool) -> Result<MailMessageID, MailError> {
        let mut reader = MailReader::new(text, utf8);
        let identifier = MailMessageID::read(&mut reader)?;
        match reader.is_end() {
            true => Ok(identifier),
            false => Err(reader.error("more after a message identifier")),
        }
    }

    pub fn read(reader: &mut MailReader<'_>) -> Result<MailMessageID, MailError> {
        reader.skip_cfws()?;
        reader.expect(b'<', "not a message identifier")?;
        let left = reader.local_part()?;
        reader.expect(b'@', "a message identifier without @")?;
        let right = reader.domain()?;
        reader.expect(b'>', "a message identifier not closed")?;
        reader.skip_cfws()?;
        Ok(MailMessageID { left, right })
    }
}

impl fmt::Display for MailMessageID {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The left part as `MailMessageID::read` reads it back: quoted unless a dot-atom.
        write!(formatter, "<{}@{}>", super::MailMailbox::quote_if_needed(&self.left, true), self.right)
    }
}
