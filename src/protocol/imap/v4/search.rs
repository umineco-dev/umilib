use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use super::{IMAPDate, IMAPError, IMAPReader, IMAPSequenceSet, IMAPWriter};

/// A search key (RFC 9051 §6.4.4), and NEW, OLD and RECENT of IMAP4rev1.
/// Strings are as they were sent; matching them is the mailbox's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPSearchKey {
    All,
    Answered,
    Bcc(Vec<u8>),
    Before(IMAPDate),
    Body(Vec<u8>),
    Cc(Vec<u8>),
    Deleted,
    Draft,
    Flagged,
    From(Vec<u8>),
    Header(Vec<u8>, Vec<u8>),
    Keyword(String),
    Larger(u64),
    Not(Box<IMAPSearchKey>),
    On(IMAPDate),
    Or(Box<IMAPSearchKey>, Box<IMAPSearchKey>),
    Seen,
    SentBefore(IMAPDate),
    SentOn(IMAPDate),
    SentSince(IMAPDate),
    Since(IMAPDate),
    Smaller(u64),
    Subject(Vec<u8>),
    Text(Vec<u8>),
    To(Vec<u8>),
    UID(IMAPSequenceSet),
    Unanswered,
    Undeleted,
    Undraft,
    Unflagged,
    Unkeyword(String),
    Unseen,
    Sequence(IMAPSequenceSet),
    /// A parenthesized list: every key matches.
    And(Vec<IMAPSearchKey>),
    New,
    Old,
    Recent,
}

/// A SEARCH command's program (RFC 9051 §6.4.4): its return options, a
/// character set if given, and its keys, which all match.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IMAPSearch {
    /// The return options (MIN, MAX, ALL, COUNT, SAVE), in upper case; `None` for no RETURN.
    pub returns: Option<Vec<String>>,
    pub charset: Option<String>,
    pub keys: Vec<IMAPSearchKey>,
}

impl IMAPSearchKey {
    /// Whether the key names messages by sequence number, which an EXPUNGE changes, so that a
    /// UID SEARCH of it is not pipelined (RFC 9051 §5.5).
    pub fn uses_sequence_numbers(&self) -> bool {
        match self {
            IMAPSearchKey::Sequence(_) => true,
            IMAPSearchKey::Not(key) => key.uses_sequence_numbers(),
            IMAPSearchKey::Or(left, right) => left.uses_sequence_numbers() || right.uses_sequence_numbers(),
            IMAPSearchKey::And(keys) => keys.iter().any(IMAPSearchKey::uses_sequence_numbers),
            _ => false,
        }
    }

    pub fn read(reader: &mut IMAPReader<'_>) -> Result<IMAPSearchKey, IMAPError> {
        if reader.peek() == Some(b'(') {
            reader.depth += 1;
            if reader.depth > reader.maximum_depth {
                return Err(reader.error("search keys nested too deep"));
            }
            reader.position += 1;
            let mut keys = alloc::vec![IMAPSearchKey::read(reader)?];
            while reader.eat(b' ') {
                keys.push(IMAPSearchKey::read(reader)?);
            }
            reader.expect(b')', "a list of keys not closed")?;
            reader.depth -= 1;
            return Ok(IMAPSearchKey::And(keys));
        }
        if reader.peek().is_some_and(|byte| byte.is_ascii_digit() || byte == b'*' || byte == b'$') {
            return IMAPSequenceSet::read(reader).map(IMAPSearchKey::Sequence);
        }
        let start = reader.position;
        let name = reader.keyword()?;
        let argument = |reader: &mut IMAPReader<'_>| -> Result<Vec<u8>, IMAPError> {
            reader.sp()?;
            reader.astring()
        };
        let date = |reader: &mut IMAPReader<'_>| -> Result<IMAPDate, IMAPError> {
            reader.sp()?;
            IMAPDate::read(reader)
        };
        let keyword = |reader: &mut IMAPReader<'_>| -> Result<String, IMAPError> {
            reader.sp()?;
            Ok(String::from_utf8_lossy(reader.atom()?).into_owned())
        };
        let nested = |reader: &mut IMAPReader<'_>| -> Result<Box<IMAPSearchKey>, IMAPError> {
            reader.sp()?;
            reader.depth += 1;
            if reader.depth > reader.maximum_depth {
                return Err(reader.error("search keys nested too deep"));
            }
            let key = IMAPSearchKey::read(reader)?;
            reader.depth -= 1;
            Ok(Box::new(key))
        };
        Ok(match name.as_str() {
            "ALL" => IMAPSearchKey::All,
            "ANSWERED" => IMAPSearchKey::Answered,
            "BCC" => IMAPSearchKey::Bcc(argument(reader)?),
            "BEFORE" => IMAPSearchKey::Before(date(reader)?),
            "BODY" => IMAPSearchKey::Body(argument(reader)?),
            "CC" => IMAPSearchKey::Cc(argument(reader)?),
            "DELETED" => IMAPSearchKey::Deleted,
            "DRAFT" => IMAPSearchKey::Draft,
            "FLAGGED" => IMAPSearchKey::Flagged,
            "FROM" => IMAPSearchKey::From(argument(reader)?),
            "HEADER" => {
                let field = argument(reader)?;
                IMAPSearchKey::Header(field, argument(reader)?)
            }
            "KEYWORD" => IMAPSearchKey::Keyword(keyword(reader)?),
            "LARGER" | "SMALLER" => {
                reader.sp()?;
                let size = reader.number64()?;
                if name == "LARGER" { IMAPSearchKey::Larger(size) } else { IMAPSearchKey::Smaller(size) }
            }
            "NOT" => IMAPSearchKey::Not(nested(reader)?),
            "ON" => IMAPSearchKey::On(date(reader)?),
            "OR" => {
                let first = nested(reader)?;
                IMAPSearchKey::Or(first, nested(reader)?)
            }
            "SEEN" => IMAPSearchKey::Seen,
            "SENTBEFORE" => IMAPSearchKey::SentBefore(date(reader)?),
            "SENTON" => IMAPSearchKey::SentOn(date(reader)?),
            "SENTSINCE" => IMAPSearchKey::SentSince(date(reader)?),
            "SINCE" => IMAPSearchKey::Since(date(reader)?),
            "SUBJECT" => IMAPSearchKey::Subject(argument(reader)?),
            "TEXT" => IMAPSearchKey::Text(argument(reader)?),
            "TO" => IMAPSearchKey::To(argument(reader)?),
            "UID" => {
                reader.sp()?;
                IMAPSearchKey::UID(IMAPSequenceSet::read(reader)?)
            }
            "UNANSWERED" => IMAPSearchKey::Unanswered,
            "UNDELETED" => IMAPSearchKey::Undeleted,
            "UNDRAFT" => IMAPSearchKey::Undraft,
            "UNFLAGGED" => IMAPSearchKey::Unflagged,
            "UNKEYWORD" => IMAPSearchKey::Unkeyword(keyword(reader)?),
            "UNSEEN" => IMAPSearchKey::Unseen,
            "NEW" => IMAPSearchKey::New,
            "OLD" => IMAPSearchKey::Old,
            "RECENT" => IMAPSearchKey::Recent,
            _ => return Err(IMAPError::Syntax { position: start, reason: "not a search key" }),
        })
    }

    pub fn write(&self, writer: &mut IMAPWriter) {
        let text = |writer: &mut IMAPWriter, name: &[u8], value: &[u8]| {
            writer.raw(name).sp().astring(value);
        };
        let date = |writer: &mut IMAPWriter, name: &str, date: &IMAPDate| {
            writer.raw(alloc::format!("{name} {date}").as_bytes());
        };
        match self {
            IMAPSearchKey::All => {
                writer.raw(b"ALL");
            }
            IMAPSearchKey::Answered => {
                writer.raw(b"ANSWERED");
            }
            IMAPSearchKey::Bcc(value) => text(writer, b"BCC", value),
            IMAPSearchKey::Before(value) => date(writer, "BEFORE", value),
            IMAPSearchKey::Body(value) => text(writer, b"BODY", value),
            IMAPSearchKey::Cc(value) => text(writer, b"CC", value),
            IMAPSearchKey::Deleted => {
                writer.raw(b"DELETED");
            }
            IMAPSearchKey::Draft => {
                writer.raw(b"DRAFT");
            }
            IMAPSearchKey::Flagged => {
                writer.raw(b"FLAGGED");
            }
            IMAPSearchKey::From(value) => text(writer, b"FROM", value),
            IMAPSearchKey::Header(field, value) => {
                writer.raw(b"HEADER ").astring(field).sp().astring(value);
            }
            IMAPSearchKey::Keyword(keyword) => {
                writer.raw(alloc::format!("KEYWORD {keyword}").as_bytes());
            }
            IMAPSearchKey::Larger(size) => {
                writer.raw(b"LARGER ").number(*size);
            }
            IMAPSearchKey::Not(key) => {
                writer.raw(b"NOT ");
                key.write(writer);
            }
            IMAPSearchKey::On(value) => date(writer, "ON", value),
            IMAPSearchKey::Or(first, second) => {
                writer.raw(b"OR ");
                first.write(writer);
                writer.sp();
                second.write(writer);
            }
            IMAPSearchKey::Seen => {
                writer.raw(b"SEEN");
            }
            IMAPSearchKey::SentBefore(value) => date(writer, "SENTBEFORE", value),
            IMAPSearchKey::SentOn(value) => date(writer, "SENTON", value),
            IMAPSearchKey::SentSince(value) => date(writer, "SENTSINCE", value),
            IMAPSearchKey::Since(value) => date(writer, "SINCE", value),
            IMAPSearchKey::Smaller(size) => {
                writer.raw(b"SMALLER ").number(*size);
            }
            IMAPSearchKey::Subject(value) => text(writer, b"SUBJECT", value),
            IMAPSearchKey::Text(value) => text(writer, b"TEXT", value),
            IMAPSearchKey::To(value) => text(writer, b"TO", value),
            IMAPSearchKey::UID(set) => {
                writer.raw(alloc::format!("UID {set}").as_bytes());
            }
            IMAPSearchKey::Unanswered => {
                writer.raw(b"UNANSWERED");
            }
            IMAPSearchKey::Undeleted => {
                writer.raw(b"UNDELETED");
            }
            IMAPSearchKey::Undraft => {
                writer.raw(b"UNDRAFT");
            }
            IMAPSearchKey::Unflagged => {
                writer.raw(b"UNFLAGGED");
            }
            IMAPSearchKey::Unkeyword(keyword) => {
                writer.raw(alloc::format!("UNKEYWORD {keyword}").as_bytes());
            }
            IMAPSearchKey::Unseen => {
                writer.raw(b"UNSEEN");
            }
            IMAPSearchKey::Sequence(set) => set.write(writer),
            IMAPSearchKey::And(keys) => {
                writer.raw(b"(");
                for (index, key) in keys.iter().enumerate() {
                    if index > 0 {
                        writer.sp();
                    }
                    key.write(writer);
                }
                writer.raw(b")");
            }
            IMAPSearchKey::New => {
                writer.raw(b"NEW");
            }
            IMAPSearchKey::Old => {
                writer.raw(b"OLD");
            }
            IMAPSearchKey::Recent => {
                writer.raw(b"RECENT");
            }
        }
    }
}

impl IMAPSearch {
    pub fn new(keys: Vec<IMAPSearchKey>) -> IMAPSearch {
        IMAPSearch { returns: None, charset: None, keys }
    }

    /// Reads `[search-return-opts] SP search-program` after the SEARCH keyword's space.
    pub fn read(reader: &mut IMAPReader<'_>) -> Result<IMAPSearch, IMAPError> {
        let mut returns = None;
        if reader.eat_keyword("RETURN") {
            reader.sp()?;
            returns = Some(reader.list(|reader| reader.keyword())?);
            reader.sp()?;
        }
        let mut charset = None;
        if reader.eat_keyword("CHARSET") {
            reader.sp()?;
            charset = Some(reader.astring_text()?);
            reader.sp()?;
        }
        let mut keys = alloc::vec![IMAPSearchKey::read(reader)?];
        while reader.eat(b' ') {
            keys.push(IMAPSearchKey::read(reader)?);
        }
        Ok(IMAPSearch { returns, charset, keys })
    }

    pub fn write(&self, writer: &mut IMAPWriter) {
        if let Some(returns) = &self.returns {
            writer.raw(b"RETURN ").list(returns, |writer, option| {
                writer.raw(option.as_bytes());
            });
            writer.sp();
        }
        if let Some(charset) = &self.charset {
            writer.raw(b"CHARSET ").astring(charset.as_bytes()).sp();
        }
        for (index, key) in self.keys.iter().enumerate() {
            if index > 0 {
                writer.sp();
            }
            key.write(writer);
        }
    }
}
