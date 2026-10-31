use alloc::string::String;
use alloc::vec::Vec;

use super::{IMAPCommandBody, IMAPError, IMAPFetchItem, IMAPMailbox, IMAPReader, IMAPSequenceSet, IMAPWriter};

/// The condition of a status response (RFC 9051 §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IMAPCondition {
    OK,
    NO,
    BAD,
    PREAUTH,
    BYE,
}

/// A response code (RFC 9051 §7.1): those with data, and the rest by name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPResponseCode {
    Alert,
    BadCharset(Vec<String>),
    Capability(Vec<String>),
    Parse,
    PermanentFlags(Vec<String>),
    ReadOnly,
    ReadWrite,
    TryCreate,
    UIDNext(u32),
    UIDValidity(u32),
    /// UNSEEN of IMAP4rev1 (RFC 3501 §7.1).
    Unseen(u32),
    AppendUID {
        validity: u32,
        uids: IMAPSequenceSet,
    },
    CopyUID {
        validity: u32,
        source: IMAPSequenceSet,
        destination: IMAPSequenceSet,
    },
    UIDNotSticky,
    Closed,
    /// A code of no data this type knows (UNAVAILABLE, AUTHENTICATIONFAILED, ..., or another
    /// atom), in upper case, and its text if it has one.
    Other {
        name: String,
        text: Option<String>,
    },
}

/// A namespace (RFC 9051 §7.3.5): the prefix of its mailboxes and their hierarchy delimiter.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IMAPNamespace {
    pub prefix: Vec<u8>,
    pub delimiter: Option<char>,
}

/// A data item of ESEARCH (RFC 9051 §7.3.4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPSearchData {
    Min(u32),
    Max(u32),
    All(IMAPSequenceSet),
    Count(u32),
    /// Another, its name in upper case and its value as it is.
    Other {
        name: String,
        value: Vec<u8>,
    },
}

/// A response (RFC 9051 §7), of a server to a client.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPResponse {
    /// A status response: tagged (OK, NO, BAD of a command) or untagged.
    Status {
        tag: Option<String>,
        condition: IMAPCondition,
        code: Option<IMAPResponseCode>,
        text: String,
    },
    /// A command continuation request: its text, or the base64 of an AUTHENTICATE challenge.
    Continuation(Vec<u8>),
    Capability(Vec<String>),
    Enabled(Vec<String>),
    Flags(Vec<String>),
    /// LIST (and LSUB of IMAP4rev1 where `subscribed`): attributes, the hierarchy delimiter, the
    /// mailbox, and the extended data items of RFC 5258 as they are.
    List {
        lsub: bool,
        attributes: Vec<String>,
        delimiter: Option<char>,
        mailbox: IMAPMailbox,
        extended: Vec<(String, Vec<u8>)>,
    },
    /// The prefixes and delimiters of the personal, other users' and shared namespaces (RFC 9051 §7.3.5).
    Namespace {
        personal: Vec<IMAPNamespace>,
        other: Vec<IMAPNamespace>,
        shared: Vec<IMAPNamespace>,
    },
    /// STATUS: the mailbox and its items, names in upper case.
    StatusData {
        mailbox: IMAPMailbox,
        items: Vec<(String, u64)>,
    },
    ESearch {
        tag: Option<String>,
        uid: bool,
        data: Vec<IMAPSearchData>,
    },
    /// SEARCH of IMAP4rev1.
    Search(Vec<u32>),
    Exists(u32),
    /// RECENT of IMAP4rev1.
    Recent(u32),
    Expunge(u32),
    Fetch {
        number: u32,
        items: Vec<IMAPFetchItem>,
    },
    /// A response of an extension (QUOTA, METADATA, `n MODSEQ`): its number if it has one, its
    /// name in upper case and the rest of its line as it is (RFC 9051 §7: a client MUST be
    /// ready for any response).
    Other {
        number: Option<u32>,
        name: String,
        data: Vec<u8>,
    },
}

impl IMAPCondition {
    pub fn name(self) -> &'static str {
        match self {
            IMAPCondition::OK => "OK",
            IMAPCondition::NO => "NO",
            IMAPCondition::BAD => "BAD",
            IMAPCondition::PREAUTH => "PREAUTH",
            IMAPCondition::BYE => "BYE",
        }
    }

    pub fn from_name(name: &str) -> Option<IMAPCondition> {
        [IMAPCondition::OK, IMAPCondition::NO, IMAPCondition::BAD, IMAPCondition::PREAUTH, IMAPCondition::BYE]
            .into_iter()
            .find(|condition| condition.name().eq_ignore_ascii_case(name))
    }
}

impl IMAPResponseCode {
    /// Reads `[code]`, its brackets included.
    pub fn read(reader: &mut IMAPReader<'_>) -> Result<IMAPResponseCode, IMAPError> {
        reader.expect(b'[', "not a response code")?;
        let name = reader.keyword()?;
        let code = match name.as_str() {
            "ALERT" => IMAPResponseCode::Alert,
            "PARSE" => IMAPResponseCode::Parse,
            "READ-ONLY" => IMAPResponseCode::ReadOnly,
            "READ-WRITE" => IMAPResponseCode::ReadWrite,
            "TRYCREATE" => IMAPResponseCode::TryCreate,
            "UIDNOTSTICKY" => IMAPResponseCode::UIDNotSticky,
            "CLOSED" => IMAPResponseCode::Closed,
            "BADCHARSET" => {
                let mut charsets = Vec::new();
                if reader.eat(b' ') {
                    charsets = reader.list(|reader| reader.astring_text())?;
                }
                IMAPResponseCode::BadCharset(charsets)
            }
            "CAPABILITY" => {
                let mut capabilities = Vec::new();
                while reader.eat(b' ') {
                    capabilities.push(reader.keyword()?);
                }
                IMAPResponseCode::Capability(capabilities)
            }
            "PERMANENTFLAGS" => {
                reader.sp()?;
                IMAPResponseCode::PermanentFlags(reader.list(|reader| reader.flag(true))?)
            }
            "UIDNEXT" | "UIDVALIDITY" | "UNSEEN" => {
                reader.sp()?;
                let number = reader.nz_number()?;
                match name.as_str() {
                    "UIDNEXT" => IMAPResponseCode::UIDNext(number),
                    "UIDVALIDITY" => IMAPResponseCode::UIDValidity(number),
                    _ => IMAPResponseCode::Unseen(number),
                }
            }
            "APPENDUID" => {
                reader.sp()?;
                let validity = reader.nz_number()?;
                reader.sp()?;
                IMAPResponseCode::AppendUID { validity, uids: IMAPSequenceSet::read(reader)? }
            }
            "COPYUID" => {
                reader.sp()?;
                let validity = reader.nz_number()?;
                reader.sp()?;
                let source = IMAPSequenceSet::read(reader)?;
                reader.sp()?;
                IMAPResponseCode::CopyUID { validity, source, destination: IMAPSequenceSet::read(reader)? }
            }
            _ => {
                let text = match reader.eat(b' ') {
                    true => {
                        let rest = reader.rest();
                        let end = rest
                            .iter()
                            .position(|byte| *byte == b']')
                            .ok_or(reader.error("a response code not closed"))?;
                        reader.position += end;
                        Some(String::from_utf8_lossy(&rest[..end]).into_owned())
                    }
                    false => None,
                };
                IMAPResponseCode::Other { name, text }
            }
        };
        reader.expect(b']', "a response code not closed")?;
        Ok(code)
    }

    pub fn write(&self, writer: &mut IMAPWriter) {
        let atoms = |writer: &mut IMAPWriter, atoms: &[String]| {
            writer.list(atoms, |writer, atom| {
                writer.raw(atom.as_bytes());
            });
        };
        writer.raw(b"[");
        match self {
            IMAPResponseCode::Alert => {
                writer.raw(b"ALERT");
            }
            IMAPResponseCode::Parse => {
                writer.raw(b"PARSE");
            }
            IMAPResponseCode::ReadOnly => {
                writer.raw(b"READ-ONLY");
            }
            IMAPResponseCode::ReadWrite => {
                writer.raw(b"READ-WRITE");
            }
            IMAPResponseCode::TryCreate => {
                writer.raw(b"TRYCREATE");
            }
            IMAPResponseCode::UIDNotSticky => {
                writer.raw(b"UIDNOTSTICKY");
            }
            IMAPResponseCode::Closed => {
                writer.raw(b"CLOSED");
            }
            IMAPResponseCode::BadCharset(charsets) => {
                writer.raw(b"BADCHARSET");
                if !charsets.is_empty() {
                    writer.sp();
                    writer.list(charsets, |writer, charset| {
                        writer.astring(charset.as_bytes());
                    });
                }
            }
            IMAPResponseCode::Capability(capabilities) => {
                writer.raw(b"CAPABILITY");
                for capability in capabilities {
                    writer.sp().raw(capability.as_bytes());
                }
            }
            IMAPResponseCode::PermanentFlags(flags) => {
                writer.raw(b"PERMANENTFLAGS ");
                atoms(writer, flags);
            }
            IMAPResponseCode::UIDNext(number) => {
                writer.raw(alloc::format!("UIDNEXT {number}").as_bytes());
            }
            IMAPResponseCode::UIDValidity(number) => {
                writer.raw(alloc::format!("UIDVALIDITY {number}").as_bytes());
            }
            IMAPResponseCode::Unseen(number) => {
                writer.raw(alloc::format!("UNSEEN {number}").as_bytes());
            }
            IMAPResponseCode::AppendUID { validity, uids } => {
                writer.raw(alloc::format!("APPENDUID {validity} {uids}").as_bytes());
            }
            IMAPResponseCode::CopyUID { validity, source, destination } => {
                writer.raw(alloc::format!("COPYUID {validity} {source} {destination}").as_bytes());
            }
            IMAPResponseCode::Other { name, text } => {
                writer.raw(name.as_bytes());
                if let Some(text) = text {
                    writer.sp().raw(text.as_bytes());
                }
            }
        }
        writer.raw(b"]");
    }
}

impl IMAPResponse {
    /// An untagged status response.
    pub fn untagged(condition: IMAPCondition, code: Option<IMAPResponseCode>, text: &str) -> IMAPResponse {
        IMAPResponse::Status { tag: None, condition, code, text: String::from(text) }
    }

    /// A tagged status response.
    pub fn tagged(tag: &str, condition: IMAPCondition, code: Option<IMAPResponseCode>, text: &str) -> IMAPResponse {
        IMAPResponse::Status { tag: Some(String::from(tag)), condition, code, text: String::from(text) }
    }

    /// Reads a hierarchy delimiter: a quoted character, or NIL.
    pub fn read_delimiter(reader: &mut IMAPReader<'_>) -> Result<Option<char>, IMAPError> {
        if reader.eat_keyword("NIL") {
            return Ok(None);
        }
        let quoted = reader.quoted()?;
        let text = String::from_utf8(quoted).map_err(|_| reader.error("not a delimiter"))?;
        let mut characters = text.chars();
        match (characters.next(), characters.next()) {
            (Some(character), None) => Ok(Some(character)),
            _ => Err(reader.error("a delimiter of not one character")),
        }
    }

    pub fn write_delimiter(delimiter: Option<char>, writer: &mut IMAPWriter) {
        match delimiter {
            Some(delimiter) => writer.quoted(delimiter.encode_utf8(&mut [0; 4]).as_bytes()),
            None => writer.raw(b"NIL"),
        };
    }

    /// Reads a namespace: a list of prefixes and delimiters, or NIL; their extensions are dropped.
    pub fn read_namespace(reader: &mut IMAPReader<'_>) -> Result<Vec<IMAPNamespace>, IMAPError> {
        if reader.eat_keyword("NIL") {
            return Ok(Vec::new());
        }
        reader.expect(b'(', "not a namespace")?;
        let mut namespaces = Vec::new();
        while reader.eat(b'(') {
            let prefix = reader.string()?;
            reader.sp()?;
            let delimiter = IMAPResponse::read_delimiter(reader)?;
            while reader.eat(b' ') {
                reader.string()?;
                reader.sp()?;
                reader.list(|reader| reader.string())?;
            }
            reader.expect(b')', "a namespace not closed")?;
            namespaces.push(IMAPNamespace { prefix, delimiter });
        }
        reader.expect(b')', "namespaces not closed")?;
        Ok(namespaces)
    }

    /// The response of a whole line from a server, its last CRLF removed; mailbox names of
    /// UTF-8 if `utf8` (IMAP4rev2).
    pub fn parse(line: &[u8], utf8: bool, maximum_depth: usize) -> Result<IMAPResponse, IMAPError> {
        let mut reader = IMAPReader::new(line, maximum_depth);
        let response = IMAPResponse::read(&mut reader, utf8)?;
        reader.end()?;
        Ok(response)
    }

    pub fn read(reader: &mut IMAPReader<'_>, utf8: bool) -> Result<IMAPResponse, IMAPError> {
        if reader.eat(b'+') {
            // "+" SP (resp-text / base64); servers are known to send "+" alone.
            reader.eat(b' ');
            let rest = reader.rest().to_vec();
            reader.position = reader.data.len();
            return Ok(IMAPResponse::Continuation(rest));
        }
        let tag = match reader.eat(b'*') {
            true => None,
            false => Some(
                String::from_utf8_lossy(
                    reader.take_while(|byte| IMAPReader::is_astring_char(byte) && byte != b'+', "not a tag")?,
                )
                .into_owned(),
            ),
        };
        reader.sp()?;
        if tag.is_none() && reader.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            let number = reader.number()?;
            reader.sp()?;
            let name = reader.keyword()?;
            return Ok(match name.as_str() {
                "EXISTS" => IMAPResponse::Exists(number),
                "RECENT" => IMAPResponse::Recent(number),
                "EXPUNGE" => IMAPResponse::Expunge(number),
                "FETCH" => {
                    reader.sp()?;
                    let items = reader.list(IMAPFetchItem::read)?;
                    if items.is_empty() {
                        return Err(reader.error("FETCH of no item"));
                    }
                    IMAPResponse::Fetch { number, items }
                }
                _ => {
                    let data = if reader.eat(b' ') { reader.rest().to_vec() } else { Vec::new() };
                    reader.position = reader.data.len();
                    IMAPResponse::Other { number: Some(number), name, data }
                }
            });
        }
        let name = reader.keyword()?;
        if let Some(condition) = IMAPCondition::from_name(&name) {
            if tag.is_some() && !matches!(condition, IMAPCondition::OK | IMAPCondition::NO | IMAPCondition::BAD) {
                return Err(reader.error("a tagged response not OK, NO or BAD"));
            }
            let mut code = None;
            let mut text = String::new();
            if reader.eat(b' ') {
                if reader.peek() == Some(b'[') {
                    code = Some(IMAPResponseCode::read(reader)?);
                    reader.eat(b' ');
                }
                text = reader.text()?;
            }
            return Ok(IMAPResponse::Status { tag, condition, code, text });
        }
        if tag.is_some() {
            return Err(reader.error("a tagged response of no condition"));
        }
        let response = match name.as_str() {
            "CAPABILITY" | "ENABLED" => {
                let mut capabilities = Vec::new();
                while reader.eat(b' ') {
                    capabilities.push(reader.keyword()?);
                }
                match name.as_str() {
                    "CAPABILITY" => IMAPResponse::Capability(capabilities),
                    _ => IMAPResponse::Enabled(capabilities),
                }
            }
            "FLAGS" => {
                reader.sp()?;
                IMAPResponse::Flags(reader.list(|reader| reader.flag(false))?)
            }
            "LIST" | "LSUB" => {
                reader.sp()?;
                let attributes = reader.list(|reader| reader.flag(false))?;
                reader.sp()?;
                let delimiter = IMAPResponse::read_delimiter(reader)?;
                reader.sp()?;
                let mailbox = IMAPCommandBody::read_mailbox(reader, utf8)?;
                let mut extended = Vec::new();
                if reader.eat(b' ') {
                    reader.expect(b'(', "not extended data")?;
                    while !reader.eat(b')') {
                        let tag = reader.astring_text()?.to_ascii_uppercase();
                        reader.sp()?;
                        let start = reader.position;
                        IMAPResponse::skip_value(reader)?;
                        extended.push((tag, reader.data[start..reader.position].to_vec()));
                        reader.eat(b' ');
                    }
                }
                IMAPResponse::List { lsub: name == "LSUB", attributes, delimiter, mailbox, extended }
            }
            "NAMESPACE" => {
                reader.sp()?;
                let personal = IMAPResponse::read_namespace(reader)?;
                reader.sp()?;
                let other = IMAPResponse::read_namespace(reader)?;
                reader.sp()?;
                let shared = IMAPResponse::read_namespace(reader)?;
                IMAPResponse::Namespace { personal, other, shared }
            }
            "STATUS" => {
                reader.sp()?;
                let mailbox = IMAPCommandBody::read_mailbox(reader, utf8)?;
                reader.sp()?;
                reader.expect(b'(', "not status items")?;
                let mut items = Vec::new();
                while !reader.eat(b')') {
                    let item = reader.keyword()?;
                    reader.sp()?;
                    items.push((item, reader.number64()?));
                    reader.eat(b' ');
                }
                IMAPResponse::StatusData { mailbox, items }
            }
            "ESEARCH" => {
                let mut tag = None;
                let mut uid = false;
                let mut data = Vec::new();
                if reader.rest().starts_with(b" (") {
                    reader.position += 2;
                    if !reader.eat_keyword("TAG") {
                        return Err(reader.error("not a search correlator"));
                    }
                    reader.sp()?;
                    tag = Some(reader.astring_text()?);
                    reader.expect(b')', "a search correlator not closed")?;
                }
                while reader.eat(b' ') {
                    let name = reader.keyword()?;
                    if name == "UID" && data.is_empty() && !uid {
                        uid = true;
                        continue;
                    }
                    reader.sp()?;
                    data.push(match name.as_str() {
                        "MIN" => IMAPSearchData::Min(reader.nz_number()?),
                        "MAX" => IMAPSearchData::Max(reader.nz_number()?),
                        "COUNT" => IMAPSearchData::Count(reader.number()?),
                        "ALL" => IMAPSearchData::All(IMAPSequenceSet::read(reader)?),
                        _ => {
                            let start = reader.position;
                            IMAPResponse::skip_value(reader)?;
                            IMAPSearchData::Other { name, value: reader.data[start..reader.position].to_vec() }
                        }
                    });
                }
                IMAPResponse::ESearch { tag, uid, data }
            }
            "SEARCH" => {
                let mut numbers = Vec::new();
                while reader.eat(b' ') {
                    numbers.push(reader.nz_number()?);
                }
                IMAPResponse::Search(numbers)
            }
            _ => {
                let data = if reader.eat(b' ') { reader.rest().to_vec() } else { Vec::new() };
                reader.position = reader.data.len();
                IMAPResponse::Other { number: None, name, data }
            }
        };
        Ok(response)
    }

    /// Reads a tagged-ext-val (RFC 9051 §9) and drops it: an atom or a number, a string, or a list.
    pub fn skip_value(reader: &mut IMAPReader<'_>) -> Result<(), IMAPError> {
        match reader.peek() {
            Some(b'(') => reader.list(IMAPResponse::skip_value).map(|_| ()),
            Some(b'"' | b'{') => reader.string().map(|_| ()),
            _ => reader
                .take_while(|byte| IMAPReader::is_astring_char(byte) || byte == b'*' || byte == b'$', "not a value")
                .map(|_| ()),
        }
    }

    /// Writes the response and its CRLF; mailbox names of UTF-8 if the writer's `utf8`.
    pub fn write(&self, writer: &mut IMAPWriter) {
        let atoms = |writer: &mut IMAPWriter, atoms: &[String]| {
            writer.list(atoms, |writer, atom| {
                writer.raw(atom.as_bytes());
            });
        };
        match self {
            IMAPResponse::Continuation(text) => {
                writer.raw(b"+ ").raw(text);
            }
            IMAPResponse::Status { tag, condition, code, text } => {
                writer.raw(tag.as_deref().unwrap_or("*").as_bytes()).sp().raw(condition.name().as_bytes());
                if let Some(code) = code {
                    writer.sp();
                    code.write(writer);
                }
                // resp-text: a code, a space, text; RFC 9051 §9 lets the text be absent.
                writer.sp().raw(text.as_bytes());
            }
            IMAPResponse::Capability(capabilities) | IMAPResponse::Enabled(capabilities) => {
                writer.raw(if matches!(self, IMAPResponse::Capability(_)) { b"* CAPABILITY" } else { b"* ENABLED" });
                for capability in capabilities {
                    writer.sp().raw(capability.as_bytes());
                }
            }
            IMAPResponse::Flags(flags) => {
                writer.raw(b"* FLAGS ");
                atoms(writer, flags);
            }
            IMAPResponse::List { lsub, attributes, delimiter, mailbox, extended } => {
                writer.raw(if *lsub { b"* LSUB " } else { b"* LIST " });
                atoms(writer, attributes);
                writer.sp();
                IMAPResponse::write_delimiter(*delimiter, writer);
                writer.sp();
                IMAPCommandBody::write_mailbox(mailbox, writer);
                if !extended.is_empty() {
                    writer.raw(b" (");
                    for (index, (tag, value)) in extended.iter().enumerate() {
                        if index > 0 {
                            writer.sp();
                        }
                        writer.astring(tag.as_bytes()).sp().raw(value);
                    }
                    writer.raw(b")");
                }
            }
            IMAPResponse::Namespace { personal, other, shared } => {
                writer.raw(b"* NAMESPACE");
                for namespaces in [personal, other, shared] {
                    writer.sp();
                    if namespaces.is_empty() {
                        writer.raw(b"NIL");
                        continue;
                    }
                    writer.raw(b"(");
                    for namespace in namespaces {
                        writer.raw(b"(").string(&namespace.prefix).sp();
                        IMAPResponse::write_delimiter(namespace.delimiter, writer);
                        writer.raw(b")");
                    }
                    writer.raw(b")");
                }
            }
            IMAPResponse::StatusData { mailbox, items } => {
                writer.raw(b"* STATUS ");
                IMAPCommandBody::write_mailbox(mailbox, writer);
                writer.sp().list(items, |writer, (item, value)| {
                    writer.raw(item.as_bytes()).sp().number(*value);
                });
            }
            IMAPResponse::ESearch { tag, uid, data } => {
                writer.raw(b"* ESEARCH");
                if let Some(tag) = tag {
                    writer.raw(b" (TAG ").string(tag.as_bytes()).raw(b")");
                }
                if *uid {
                    writer.raw(b" UID");
                }
                for item in data {
                    writer.sp();
                    match item {
                        IMAPSearchData::Min(value) => writer.raw(alloc::format!("MIN {value}").as_bytes()),
                        IMAPSearchData::Max(value) => writer.raw(alloc::format!("MAX {value}").as_bytes()),
                        IMAPSearchData::Count(value) => writer.raw(alloc::format!("COUNT {value}").as_bytes()),
                        IMAPSearchData::All(set) => writer.raw(alloc::format!("ALL {set}").as_bytes()),
                        IMAPSearchData::Other { name, value } => writer.raw(name.as_bytes()).sp().raw(value),
                    };
                }
            }
            IMAPResponse::Search(numbers) => {
                writer.raw(b"* SEARCH");
                for number in numbers {
                    writer.sp().number(u64::from(*number));
                }
            }
            IMAPResponse::Exists(number) => {
                writer.raw(alloc::format!("* {number} EXISTS").as_bytes());
            }
            IMAPResponse::Other { number, name, data } => {
                writer.raw(b"* ");
                if let Some(number) = number {
                    writer.raw(alloc::format!("{number} ").as_bytes());
                }
                writer.raw(name.as_bytes());
                if !data.is_empty() {
                    writer.sp().raw(data);
                }
            }
            IMAPResponse::Recent(number) => {
                writer.raw(alloc::format!("* {number} RECENT").as_bytes());
            }
            IMAPResponse::Expunge(number) => {
                writer.raw(alloc::format!("* {number} EXPUNGE").as_bytes());
            }
            IMAPResponse::Fetch { number, items } => {
                writer.raw(alloc::format!("* {number} FETCH ").as_bytes());
                writer.list(items, |writer, item| item.write(writer));
            }
        }
        writer.raw(b"\r\n");
    }

    /// Fails for a response that cannot be written: a tag that is not one, text with a CR, an
    /// LF or a NUL, a tagged response that is not OK, NO or BAD.
    pub fn check(&self) -> Result<(), IMAPError> {
        let invalid = |reason| Err(IMAPError::Syntax { position: 0, reason });
        match self {
            IMAPResponse::Other { name, data, .. }
                if name.is_empty()
                    || !name.bytes().all(IMAPReader::is_atom_char)
                    || data.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) =>
            {
                return invalid("a response of an extension that is not one line of an atom");
            }
            IMAPResponse::Status { tag: Some(tag), condition, .. } => {
                if !super::IMAPCommand::is_tag(tag.as_bytes()) {
                    return invalid("not a tag");
                }
                if !matches!(condition, IMAPCondition::OK | IMAPCondition::NO | IMAPCondition::BAD) {
                    return invalid("a tagged response not OK, NO or BAD");
                }
            }
            IMAPResponse::Continuation(text) if text.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) => {
                return invalid("a line break in a continuation request");
            }
            IMAPResponse::Fetch { items, .. }
                if items.iter().any(|item| matches!(item, IMAPFetchItem::InternalDate(date) if !date.is_valid())) =>
            {
                return invalid("an INTERNALDATE that date-time cannot write");
            }
            _ => {}
        }
        if let IMAPResponse::Status { text, code, .. } = self {
            let code_text = match code {
                Some(IMAPResponseCode::Other { text: Some(text), .. }) => text.as_bytes(),
                _ => b"",
            };
            if text.bytes().chain(code_text.iter().copied()).any(|byte| matches!(byte, b'\r' | b'\n' | 0))
                || code_text.contains(&b']')
            {
                return invalid("a line break in a response");
            }
            // resp-text (RFC 9051 §9): text after the condition that begins with "[" is read as a
            // response code, so without one it would be read back as a code the server never meant.
            if code.is_none() && text.starts_with('[') {
                return invalid("a text that would be read as a response code");
            }
        }
        Ok(())
    }
}
