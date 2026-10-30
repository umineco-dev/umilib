use alloc::string::String;
use alloc::vec::Vec;

use super::{
    IMAPDateTime, IMAPError, IMAPFetchAttribute, IMAPMailbox, IMAPReader, IMAPSearch, IMAPSequenceSet, IMAPWriter,
};
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;

/// How STORE changes the flags (RFC 9051 §6.4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IMAPStoreMode {
    /// FLAGS: replaces them.
    Replace,
    /// +FLAGS: adds to them.
    Add,
    /// -FLAGS: removes from them.
    Remove,
}

/// A return option of LIST (RFC 9051 §6.3.9).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPListReturn {
    Subscribed,
    Children,
    Status(Vec<String>),
    Other(String),
}

/// A command (RFC 9051 §6), and those of IMAP4rev1 (RFC 3501) a server of
/// both takes. Mailbox names are text; references and patterns of LIST
/// are the octets sent.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPCommandBody {
    Capability,
    Noop,
    Logout,
    StartTLS,
    /// A SASL exchange of a mechanism, with an initial response if given (SASL-IR, part of
    /// IMAP4rev2; `Some` of nothing is written `=`).
    Authenticate {
        mechanism: String,
        initial: Option<Vec<u8>>,
    },
    Login {
        user: Vec<u8>,
        password: Vec<u8>,
    },
    Enable(Vec<String>),
    Select(IMAPMailbox),
    Examine(IMAPMailbox),
    Create(IMAPMailbox),
    Delete(IMAPMailbox),
    Rename(IMAPMailbox, IMAPMailbox),
    Subscribe(IMAPMailbox),
    Unsubscribe(IMAPMailbox),
    List {
        selection: Vec<String>,
        reference: Vec<u8>,
        patterns: Vec<Vec<u8>>,
        returns: Vec<IMAPListReturn>,
    },
    Namespace,
    Status {
        mailbox: IMAPMailbox,
        items: Vec<String>,
    },
    Append {
        mailbox: IMAPMailbox,
        flags: Vec<String>,
        date: Option<IMAPDateTime>,
        message: Vec<u8>,
    },
    Idle,
    Close,
    Unselect,
    Expunge,
    /// UID EXPUNGE (RFC 9051 §6.4.9).
    UIDExpunge(IMAPSequenceSet),
    Search {
        uid: bool,
        search: IMAPSearch,
    },
    Fetch {
        uid: bool,
        set: IMAPSequenceSet,
        attributes: Vec<IMAPFetchAttribute>,
    },
    Store {
        uid: bool,
        set: IMAPSequenceSet,
        mode: IMAPStoreMode,
        silent: bool,
        flags: Vec<String>,
    },
    Copy {
        uid: bool,
        set: IMAPSequenceSet,
        mailbox: IMAPMailbox,
    },
    Move {
        uid: bool,
        set: IMAPSequenceSet,
        mailbox: IMAPMailbox,
    },
    /// LSUB and CHECK of IMAP4rev1.
    Lsub {
        reference: Vec<u8>,
        pattern: Vec<u8>,
    },
    Check,
    /// A command this type does not know: its name in upper case and the rest of its line.
    Other {
        name: String,
        arguments: Vec<u8>,
    },
}

/// A command and its tag.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IMAPCommand {
    pub tag: String,
    pub body: IMAPCommandBody,
}

/// The state of an IMAP session (RFC 9051 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IMAPState {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

impl IMAPCommandBody {
    /// The names of the commands of RFC 9051 and RFC 3501.
    pub const NAMES: [&'static str; 30] = [
        "CAPABILITY",
        "NOOP",
        "LOGOUT",
        "STARTTLS",
        "AUTHENTICATE",
        "LOGIN",
        "ENABLE",
        "SELECT",
        "EXAMINE",
        "CREATE",
        "DELETE",
        "RENAME",
        "SUBSCRIBE",
        "UNSUBSCRIBE",
        "LIST",
        "NAMESPACE",
        "STATUS",
        "APPEND",
        "IDLE",
        "CLOSE",
        "UNSELECT",
        "EXPUNGE",
        "SEARCH",
        "FETCH",
        "STORE",
        "COPY",
        "MOVE",
        "UID",
        "LSUB",
        "CHECK",
    ];

    /// The name of the command, in upper case; `UID` and the command after it for one of UIDs.
    pub fn name(&self) -> &str {
        match self {
            IMAPCommandBody::Capability => "CAPABILITY",
            IMAPCommandBody::Noop => "NOOP",
            IMAPCommandBody::Logout => "LOGOUT",
            IMAPCommandBody::StartTLS => "STARTTLS",
            IMAPCommandBody::Authenticate { .. } => "AUTHENTICATE",
            IMAPCommandBody::Login { .. } => "LOGIN",
            IMAPCommandBody::Enable(_) => "ENABLE",
            IMAPCommandBody::Select(_) => "SELECT",
            IMAPCommandBody::Examine(_) => "EXAMINE",
            IMAPCommandBody::Create(_) => "CREATE",
            IMAPCommandBody::Delete(_) => "DELETE",
            IMAPCommandBody::Rename(..) => "RENAME",
            IMAPCommandBody::Subscribe(_) => "SUBSCRIBE",
            IMAPCommandBody::Unsubscribe(_) => "UNSUBSCRIBE",
            IMAPCommandBody::List { .. } => "LIST",
            IMAPCommandBody::Namespace => "NAMESPACE",
            IMAPCommandBody::Status { .. } => "STATUS",
            IMAPCommandBody::Append { .. } => "APPEND",
            IMAPCommandBody::Idle => "IDLE",
            IMAPCommandBody::Close => "CLOSE",
            IMAPCommandBody::Unselect => "UNSELECT",
            IMAPCommandBody::Expunge => "EXPUNGE",
            IMAPCommandBody::UIDExpunge(_) => "UID EXPUNGE",
            IMAPCommandBody::Search { uid: true, .. } => "UID SEARCH",
            IMAPCommandBody::Search { .. } => "SEARCH",
            IMAPCommandBody::Fetch { uid: true, .. } => "UID FETCH",
            IMAPCommandBody::Fetch { .. } => "FETCH",
            IMAPCommandBody::Store { uid: true, .. } => "UID STORE",
            IMAPCommandBody::Store { .. } => "STORE",
            IMAPCommandBody::Copy { uid: true, .. } => "UID COPY",
            IMAPCommandBody::Copy { .. } => "COPY",
            IMAPCommandBody::Move { uid: true, .. } => "UID MOVE",
            IMAPCommandBody::Move { .. } => "MOVE",
            IMAPCommandBody::Lsub { .. } => "LSUB",
            IMAPCommandBody::Check => "CHECK",
            IMAPCommandBody::Other { name, .. } => name,
        }
    }

    /// Whether the command is taken in `state` (RFC 9051 §6.1 to §6.4).
    pub fn is_valid_in(&self, state: IMAPState) -> bool {
        match self {
            IMAPCommandBody::Capability
            | IMAPCommandBody::Noop
            | IMAPCommandBody::Logout
            | IMAPCommandBody::Other { .. } => state != IMAPState::Logout,
            IMAPCommandBody::StartTLS | IMAPCommandBody::Authenticate { .. } | IMAPCommandBody::Login { .. } => {
                state == IMAPState::NotAuthenticated
            }
            IMAPCommandBody::Close
            | IMAPCommandBody::Unselect
            | IMAPCommandBody::Expunge
            | IMAPCommandBody::UIDExpunge(_)
            | IMAPCommandBody::Search { .. }
            | IMAPCommandBody::Fetch { .. }
            | IMAPCommandBody::Store { .. }
            | IMAPCommandBody::Copy { .. }
            | IMAPCommandBody::Move { .. }
            | IMAPCommandBody::Check => state == IMAPState::Selected,
            // RFC 5161 §3.1: before a mailbox is selected.
            IMAPCommandBody::Enable(_) => state == IMAPState::Authenticated,
            _ => matches!(state, IMAPState::Authenticated | IMAPState::Selected),
        }
    }

    /// Reads a mailbox: an astring, INBOX in any case being INBOX; of UTF-8 if `utf8`, of
    /// modified UTF-7 otherwise (RFC 9051 §5.1, RFC 3501 §5.1.3).
    pub fn read_mailbox(reader: &mut IMAPReader<'_>, utf8: bool) -> Result<IMAPMailbox, IMAPError> {
        let position = reader.position;
        let name = reader.astring()?;
        IMAPMailbox::from_wire(&name, utf8).map_err(|_| IMAPError::Syntax { position, reason: "not a mailbox name" })
    }

    /// Reads a list-mailbox: list-chars (wildcards too) or a string.
    pub fn read_list_mailbox(reader: &mut IMAPReader<'_>) -> Result<Vec<u8>, IMAPError> {
        match reader.peek() {
            Some(b'"' | b'{') => reader.string(),
            _ => Ok(reader
                .take_while(
                    |byte| IMAPReader::is_astring_char(byte) || byte == b'%' || byte == b'*',
                    "not a list-mailbox",
                )?
                .to_vec()),
        }
    }

    /// Reads the flags of STORE or APPEND: a flag-list, or, where `bare`, flags not in a list.
    pub fn read_flags(reader: &mut IMAPReader<'_>, bare: bool) -> Result<Vec<String>, IMAPError> {
        let flags = match reader.peek() {
            Some(b'(') => reader.list(|reader| reader.flag(false))?,
            _ if bare => {
                let mut flags = alloc::vec![reader.flag(false)?];
                while reader.eat(b' ') {
                    flags.push(reader.flag(false)?);
                }
                flags
            }
            _ => return Err(reader.error("not a flag list")),
        };
        if flags.iter().any(|flag| flag.eq_ignore_ascii_case("\\Recent")) {
            return Err(reader.error("\\Recent is not stored (RFC 9051 §2.3.2)"));
        }
        Ok(flags)
    }

    /// The body of the command read after its tag and space; mailbox names of UTF-8 if `utf8`.
    pub fn read(reader: &mut IMAPReader<'_>, utf8: bool) -> Result<IMAPCommandBody, IMAPError> {
        let name = reader.keyword()?;
        let mut uid = false;
        let name = match name.as_str() {
            "UID" => {
                uid = true;
                reader.sp()?;
                reader.keyword()?
            }
            _ => name,
        };
        let mailbox = |reader: &mut IMAPReader<'_>| -> Result<IMAPMailbox, IMAPError> {
            reader.sp()?;
            IMAPCommandBody::read_mailbox(reader, utf8)
        };
        let set = |reader: &mut IMAPReader<'_>| -> Result<IMAPSequenceSet, IMAPError> {
            reader.sp()?;
            IMAPSequenceSet::read(reader)
        };
        let body = match name.as_str() {
            "FETCH" => {
                let set = set(reader)?;
                reader.sp()?;
                IMAPCommandBody::Fetch { uid, set, attributes: IMAPFetchAttribute::read_list(reader)? }
            }
            "STORE" => {
                let set = set(reader)?;
                reader.sp()?;
                let mode = match reader.peek() {
                    Some(b'+') => IMAPStoreMode::Add,
                    Some(b'-') => IMAPStoreMode::Remove,
                    _ => IMAPStoreMode::Replace,
                };
                if mode != IMAPStoreMode::Replace {
                    reader.position += 1;
                }
                if !reader.eat_prefix("FLAGS") {
                    return Err(reader.error("not FLAGS"));
                }
                let silent = reader.eat_keyword(".SILENT");
                reader.sp()?;
                IMAPCommandBody::Store { uid, set, mode, silent, flags: IMAPCommandBody::read_flags(reader, true)? }
            }
            "COPY" | "MOVE" => {
                let set = set(reader)?;
                let mailbox = mailbox(reader)?;
                match name.as_str() {
                    "COPY" => IMAPCommandBody::Copy { uid, set, mailbox },
                    _ => IMAPCommandBody::Move { uid, set, mailbox },
                }
            }
            "SEARCH" => {
                reader.sp()?;
                IMAPCommandBody::Search { uid, search: IMAPSearch::read(reader)? }
            }
            "EXPUNGE" if uid => IMAPCommandBody::UIDExpunge(set(reader)?),
            // A command of an extension of UIDs (UID SORT, UID THREAD): named with its UID, for
            // the server's `commands` to take it. UID before a command of RFC 9051 that is not of
            // UIDs stays an error.
            _ if uid && IMAPCommandBody::NAMES.contains(&name.as_str()) => {
                return Err(reader.error("UID before a command that is not of UIDs"));
            }
            _ if uid => {
                let arguments = match reader.eat(b' ') {
                    true => reader.rest().to_vec(),
                    false => Vec::new(),
                };
                reader.position = reader.data.len();
                IMAPCommandBody::Other { name: alloc::format!("UID {name}"), arguments }
            }
            "CAPABILITY" => IMAPCommandBody::Capability,
            "NOOP" => IMAPCommandBody::Noop,
            "LOGOUT" => IMAPCommandBody::Logout,
            "STARTTLS" => IMAPCommandBody::StartTLS,
            "NAMESPACE" => IMAPCommandBody::Namespace,
            "IDLE" => IMAPCommandBody::Idle,
            "CLOSE" => IMAPCommandBody::Close,
            "UNSELECT" => IMAPCommandBody::Unselect,
            "EXPUNGE" => IMAPCommandBody::Expunge,
            "CHECK" => IMAPCommandBody::Check,
            "AUTHENTICATE" => {
                reader.sp()?;
                let mechanism = reader.keyword()?;
                let initial = match reader.eat(b' ') {
                    false => None,
                    true if reader.rest() == b"=" => {
                        reader.position += 1;
                        Some(Vec::new())
                    }
                    true => Some(reader.base64()?),
                };
                IMAPCommandBody::Authenticate { mechanism, initial }
            }
            "LOGIN" => {
                reader.sp()?;
                let user = reader.astring()?;
                reader.sp()?;
                IMAPCommandBody::Login { user, password: reader.astring()? }
            }
            "ENABLE" => {
                let mut capabilities = Vec::new();
                while reader.eat(b' ') {
                    capabilities.push(reader.keyword()?);
                }
                if capabilities.is_empty() {
                    return Err(reader.error("ENABLE of nothing"));
                }
                IMAPCommandBody::Enable(capabilities)
            }
            "SELECT" => IMAPCommandBody::Select(mailbox(reader)?),
            "EXAMINE" => IMAPCommandBody::Examine(mailbox(reader)?),
            "CREATE" => IMAPCommandBody::Create(mailbox(reader)?),
            "DELETE" => IMAPCommandBody::Delete(mailbox(reader)?),
            "SUBSCRIBE" => IMAPCommandBody::Subscribe(mailbox(reader)?),
            "UNSUBSCRIBE" => IMAPCommandBody::Unsubscribe(mailbox(reader)?),
            "RENAME" => {
                let from = mailbox(reader)?;
                IMAPCommandBody::Rename(from, mailbox(reader)?)
            }
            "LIST" => {
                reader.sp()?;
                let mut selection = Vec::new();
                if reader.peek() == Some(b'(') {
                    selection = reader.list(|reader| reader.keyword())?;
                    reader.sp()?;
                }
                let reference = reader.astring()?;
                reader.sp()?;
                let patterns = match reader.peek() {
                    Some(b'(') => reader.list(IMAPCommandBody::read_list_mailbox)?,
                    _ => alloc::vec![IMAPCommandBody::read_list_mailbox(reader)?],
                };
                let mut returns = Vec::new();
                if reader.eat(b' ') {
                    if !reader.eat_keyword("RETURN") {
                        return Err(reader.error("not RETURN"));
                    }
                    reader.sp()?;
                    returns = reader.list(|reader| {
                        let option = reader.keyword()?;
                        Ok(match option.as_str() {
                            "SUBSCRIBED" => IMAPListReturn::Subscribed,
                            "CHILDREN" => IMAPListReturn::Children,
                            "STATUS" => {
                                reader.sp()?;
                                IMAPListReturn::Status(reader.list(|reader| reader.keyword())?)
                            }
                            _ => IMAPListReturn::Other(option),
                        })
                    })?;
                }
                IMAPCommandBody::List { selection, reference, patterns, returns }
            }
            "LSUB" => {
                reader.sp()?;
                let reference = reader.astring()?;
                reader.sp()?;
                IMAPCommandBody::Lsub { reference, pattern: IMAPCommandBody::read_list_mailbox(reader)? }
            }
            "STATUS" => {
                let mailbox = mailbox(reader)?;
                reader.sp()?;
                let items = reader.list(|reader| reader.keyword())?;
                if items.is_empty() {
                    return Err(reader.error("STATUS of no item"));
                }
                IMAPCommandBody::Status { mailbox, items }
            }
            "APPEND" => {
                let mailbox = mailbox(reader)?;
                reader.sp()?;
                let mut flags = Vec::new();
                if reader.peek() == Some(b'(') {
                    flags = IMAPCommandBody::read_flags(reader, false)?;
                    reader.sp()?;
                }
                let mut date = None;
                if reader.peek() == Some(b'"') {
                    date = Some(IMAPDateTime::read(reader)?);
                    reader.sp()?;
                }
                // A literal8 is taken too (BINARY, RFC 3516 §4.4).
                let message = reader.literal(true)?;
                IMAPCommandBody::Append { mailbox, flags, date, message }
            }
            _ => {
                let arguments = match reader.eat(b' ') {
                    true => reader.rest().to_vec(),
                    false => Vec::new(),
                };
                reader.position = reader.data.len();
                IMAPCommandBody::Other { name, arguments }
            }
        };
        Ok(body)
    }

    pub fn write_mailbox(mailbox: &IMAPMailbox, writer: &mut IMAPWriter) {
        let wire = mailbox.to_wire(writer.utf8);
        writer.astring(&wire);
    }

    /// Writes the body of the command; mailbox names of UTF-8 if the writer's `utf8`, of
    /// modified UTF-7 otherwise.
    pub fn write(&self, writer: &mut IMAPWriter) {
        let flags = |writer: &mut IMAPWriter, flags: &[String]| {
            writer.list(flags, |writer, flag| {
                writer.raw(flag.as_bytes());
            });
        };
        let uid = |writer: &mut IMAPWriter, uid: bool| {
            if uid {
                writer.raw(b"UID ");
            }
        };
        match self {
            IMAPCommandBody::Authenticate { mechanism, initial } => {
                writer.raw(b"AUTHENTICATE ").raw(mechanism.as_bytes());
                match initial {
                    None => {}
                    Some(initial) if initial.is_empty() => {
                        writer.raw(b" =");
                    }
                    Some(initial) => {
                        writer.sp().raw(Base64::STANDARD.encode(initial).as_bytes());
                    }
                }
            }
            IMAPCommandBody::Login { user, password } => {
                writer.raw(b"LOGIN ").astring(user).sp().astring(password);
            }
            IMAPCommandBody::Enable(capabilities) => {
                writer.raw(b"ENABLE");
                for capability in capabilities {
                    writer.sp().raw(capability.as_bytes());
                }
            }
            IMAPCommandBody::Select(mailbox)
            | IMAPCommandBody::Examine(mailbox)
            | IMAPCommandBody::Create(mailbox)
            | IMAPCommandBody::Delete(mailbox)
            | IMAPCommandBody::Subscribe(mailbox)
            | IMAPCommandBody::Unsubscribe(mailbox) => {
                writer.raw(self.name().as_bytes()).sp();
                IMAPCommandBody::write_mailbox(mailbox, writer);
            }
            IMAPCommandBody::Rename(from, to) => {
                writer.raw(b"RENAME ");
                IMAPCommandBody::write_mailbox(from, writer);
                writer.sp();
                IMAPCommandBody::write_mailbox(to, writer);
            }
            IMAPCommandBody::List { selection, reference, patterns, returns } => {
                writer.raw(b"LIST ");
                if !selection.is_empty() {
                    flags(writer, selection);
                    writer.sp();
                }
                match reference.is_empty() {
                    true => writer.quoted(b""),
                    false => writer.astring(reference),
                };
                writer.sp();
                let pattern = |writer: &mut IMAPWriter, pattern: &Vec<u8>| {
                    let plain = !pattern.is_empty()
                        && pattern
                            .iter()
                            .all(|byte| IMAPReader::is_astring_char(*byte) || *byte == b'%' || *byte == b'*');
                    match plain {
                        true => writer.raw(pattern),
                        false => writer.string(pattern),
                    };
                };
                match patterns.as_slice() {
                    [single] => pattern(writer, single),
                    _ => {
                        writer.list(patterns, pattern);
                    }
                }
                if !returns.is_empty() {
                    writer.raw(b" RETURN ").list(returns, |writer, option| {
                        match option {
                            IMAPListReturn::Subscribed => writer.raw(b"SUBSCRIBED"),
                            IMAPListReturn::Children => writer.raw(b"CHILDREN"),
                            IMAPListReturn::Status(items) => {
                                writer.raw(b"STATUS ");
                                flags(writer, items);
                                writer
                            }
                            IMAPListReturn::Other(option) => writer.raw(option.as_bytes()),
                        };
                    });
                }
            }
            IMAPCommandBody::Lsub { reference, pattern } => {
                writer.raw(b"LSUB ").astring(reference).sp().string(pattern);
            }
            IMAPCommandBody::Status { mailbox, items } => {
                writer.raw(b"STATUS ");
                IMAPCommandBody::write_mailbox(mailbox, writer);
                writer.sp();
                flags(writer, items);
            }
            IMAPCommandBody::Append { mailbox, flags: list, date, message } => {
                writer.raw(b"APPEND ");
                IMAPCommandBody::write_mailbox(mailbox, writer);
                if !list.is_empty() {
                    writer.sp();
                    flags(writer, list);
                }
                if let Some(date) = date {
                    writer.raw(alloc::format!(" {date}").as_bytes());
                }
                writer.sp();
                if message.contains(&0) {
                    writer.raw(b"~");
                }
                writer.literal(message);
            }
            IMAPCommandBody::UIDExpunge(set) => {
                writer.raw(alloc::format!("UID EXPUNGE {set}").as_bytes());
            }
            IMAPCommandBody::Search { uid: by_uid, search } => {
                uid(writer, *by_uid);
                writer.raw(b"SEARCH ");
                search.write(writer);
            }
            IMAPCommandBody::Fetch { uid: by_uid, set, attributes } => {
                uid(writer, *by_uid);
                writer.raw(alloc::format!("FETCH {set} ").as_bytes());
                match attributes.as_slice() {
                    [single] => single.write(writer),
                    _ => {
                        writer.list(attributes, |writer, attribute| attribute.write(writer));
                    }
                }
            }
            IMAPCommandBody::Store { uid: by_uid, set, mode, silent, flags: list } => {
                uid(writer, *by_uid);
                let sign = match mode {
                    IMAPStoreMode::Replace => "",
                    IMAPStoreMode::Add => "+",
                    IMAPStoreMode::Remove => "-",
                };
                writer
                    .raw(alloc::format!("STORE {set} {sign}FLAGS{} ", if *silent { ".SILENT" } else { "" }).as_bytes());
                flags(writer, list);
            }
            IMAPCommandBody::Copy { uid: by_uid, set, mailbox }
            | IMAPCommandBody::Move { uid: by_uid, set, mailbox } => {
                uid(writer, *by_uid);
                let name = if matches!(self, IMAPCommandBody::Copy { .. }) { "COPY" } else { "MOVE" };
                writer.raw(alloc::format!("{name} {set} ").as_bytes());
                IMAPCommandBody::write_mailbox(mailbox, writer);
            }
            IMAPCommandBody::Other { name, arguments } => {
                writer.raw(name.as_bytes());
                if !arguments.is_empty() {
                    writer.sp().raw(arguments);
                }
            }
            _ => {
                writer.raw(self.name().as_bytes());
            }
        }
    }
}

impl IMAPCommand {
    pub fn new(tag: &str, body: IMAPCommandBody) -> IMAPCommand {
        IMAPCommand { tag: String::from(tag), body }
    }

    /// Whether `tag` is a tag: ASTRING-CHARs but `+` (RFC 9051 §9).
    pub fn is_tag(tag: &[u8]) -> bool {
        !tag.is_empty() && tag.iter().all(|byte| IMAPReader::is_astring_char(*byte) && *byte != b'+')
    }

    /// The command of a whole command line, its last CRLF removed; mailbox names of UTF-8 if `utf8`.
    pub fn parse(line: &[u8], utf8: bool, maximum_depth: usize) -> Result<IMAPCommand, IMAPError> {
        let mut reader = IMAPReader::new(line, maximum_depth);
        let tag = reader.take_while(|byte| IMAPReader::is_astring_char(byte) && byte != b'+', "not a tag")?;
        let tag = String::from_utf8_lossy(tag).into_owned();
        reader.sp()?;
        let body = IMAPCommandBody::read(&mut reader, utf8)?;
        reader.end()?;
        Ok(IMAPCommand { tag, body })
    }

    /// The tag of a command line, if it begins with one: to answer BAD to a command that cannot
    /// be read (RFC 9051 §7.1.3).
    pub fn tag_of(line: &[u8]) -> Option<String> {
        let end = line.iter().position(|byte| *byte == b' ').unwrap_or(line.len());
        IMAPCommand::is_tag(&line[..end]).then(|| String::from_utf8_lossy(&line[..end]).into_owned())
    }

    /// Writes the command and its CRLF.
    pub fn write(&self, writer: &mut IMAPWriter) {
        writer.raw(self.tag.as_bytes()).sp();
        self.body.write(writer);
        writer.raw(b"\r\n");
    }
}
