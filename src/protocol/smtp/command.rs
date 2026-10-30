use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::{SMTPError, SMTPMailbox, SMTPPath};
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;

/// A parameter of MAIL or RCPT (RFC 5321 §4.1.2): a keyword, in upper
/// case as keywords compare without case, and a value if it has one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SMTPParameter {
    pub keyword: String,
    pub value: Option<String>,
}

/// A command (RFC 5321 §4.1.1 and the extensions). Arguments are as they
/// are written; a path is parsed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SMTPCommand {
    Helo(String),
    Ehlo(String),
    Mail {
        path: SMTPPath,
        parameters: Vec<SMTPParameter>,
    },
    Rcpt {
        path: SMTPPath,
        parameters: Vec<SMTPParameter>,
    },
    Data,
    /// A chunk of `size` octets, the last if `last` (RFC 3030 §2).
    Bdat {
        size: u64,
        last: bool,
    },
    Rset,
    Vrfy(String),
    Expn(String),
    Help(Option<String>),
    Noop(Option<String>),
    Quit,
    /// RFC 3207.
    StartTLS,
    /// A SASL exchange of a mechanism, with an initial response if given (RFC 4954 §4;
    /// `Some` of nothing is written `=`).
    Auth {
        mechanism: String,
        initial: Option<Vec<u8>>,
    },
    /// A command this type does not know: its verb in upper case and the rest of its line.
    Other {
        verb: String,
        arguments: String,
    },
}

impl SMTPParameter {
    pub fn new(keyword: &str, value: Option<&str>) -> SMTPParameter {
        SMTPParameter { keyword: keyword.to_ascii_uppercase(), value: value.map(String::from) }
    }

    /// Whether `keyword` is an esmtp-keyword: a letter or digit, then letters, digits and hyphens.
    pub fn is_keyword(keyword: &[u8]) -> bool {
        keyword.first().is_some_and(u8::is_ascii_alphanumeric)
            && keyword.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    }

    /// Whether `value` is an esmtp-value: printable US-ASCII but `=`, and
    /// UTF-8 with `utf8` (RFC 6531 §3.3).
    pub fn is_value(value: &[u8], utf8: bool) -> bool {
        !value.is_empty() && value.iter().all(|byte| matches!(byte, 33..=60 | 62..=126) || (utf8 && *byte >= 0x80))
    }

    /// The parameter of `keyword[=value]`.
    pub fn parse(text: &[u8], utf8: bool) -> Result<SMTPParameter, SMTPError> {
        let (keyword, value) = match text.iter().position(|byte| *byte == b'=') {
            Some(equals) => (&text[..equals], Some(&text[equals + 1..])),
            None => (text, None),
        };
        if !SMTPParameter::is_keyword(keyword) || value.is_some_and(|value| !SMTPParameter::is_value(value, utf8)) {
            return Err(SMTPError::Syntax { reason: "not a parameter" });
        }
        let text_of =
            |bytes: &[u8]| String::from_utf8(bytes.to_vec()).map_err(|_| SMTPError::Syntax { reason: "not UTF-8" });
        Ok(SMTPParameter { keyword: text_of(keyword)?.to_ascii_uppercase(), value: value.map(text_of).transpose()? })
    }

    /// The parameter named `keyword` of `parameters`.
    pub fn find<'a>(parameters: &'a [SMTPParameter], keyword: &str) -> Option<&'a SMTPParameter> {
        parameters.iter().find(|parameter| parameter.keyword.eq_ignore_ascii_case(keyword))
    }
}

impl fmt::Display for SMTPParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.keyword)?;
        match &self.value {
            Some(value) => write!(formatter, "={value}"),
            None => Ok(()),
        }
    }
}

impl SMTPCommand {
    /// The verb of the command, in upper case.
    pub fn verb(&self) -> &str {
        match self {
            SMTPCommand::Helo(_) => "HELO",
            SMTPCommand::Ehlo(_) => "EHLO",
            SMTPCommand::Mail { .. } => "MAIL",
            SMTPCommand::Rcpt { .. } => "RCPT",
            SMTPCommand::Data => "DATA",
            SMTPCommand::Bdat { .. } => "BDAT",
            SMTPCommand::Rset => "RSET",
            SMTPCommand::Vrfy(_) => "VRFY",
            SMTPCommand::Expn(_) => "EXPN",
            SMTPCommand::Help(_) => "HELP",
            SMTPCommand::Noop(_) => "NOOP",
            SMTPCommand::Quit => "QUIT",
            SMTPCommand::StartTLS => "STARTTLS",
            SMTPCommand::Auth { .. } => "AUTH",
            SMTPCommand::Other { verb, .. } => verb,
        }
    }

    /// Whether the command can only be the last of a pipelined group (RFC 2920 §3.1: EHLO,
    /// DATA, VRFY, EXPN, QUIT, NOOP, and commands of other extensions unless they say
    /// otherwise; RFC 3207 §4 STARTTLS; RFC 4954 §4 AUTH; RFC 3030 §4.2 lets BDAT be pipelined).
    pub fn ends_group(&self) -> bool {
        !matches!(
            self,
            SMTPCommand::Rset | SMTPCommand::Mail { .. } | SMTPCommand::Rcpt { .. } | SMTPCommand::Bdat { .. }
        )
    }

    /// The command of a line, its CRLF removed. Verbs and the `FROM:` and
    /// `TO:` of MAIL and RCPT compare without case; spaces after their colon
    /// are taken, as many clients write them.
    pub fn parse(line: &[u8], utf8: bool) -> Result<SMTPCommand, SMTPError> {
        let invalid = |reason| Err(SMTPError::Syntax { reason });
        if line.iter().any(|byte| byte.is_ascii_control() && *byte != b'\t') || (!utf8 && !line.is_ascii()) {
            return invalid("a control character or a byte of no US-ASCII character in a command");
        }
        let (verb, rest) = match line.iter().position(|byte| *byte == b' ') {
            Some(space) => (&line[..space], Some(&line[space + 1..])),
            None => (line, None),
        };
        let verb =
            String::from_utf8(verb.to_ascii_uppercase()).map_err(|_| SMTPError::Syntax { reason: "not a verb" })?;
        let text_of =
            |bytes: &[u8]| String::from_utf8(bytes.to_vec()).map_err(|_| SMTPError::Syntax { reason: "not UTF-8" });
        let none = |command: SMTPCommand| match rest {
            None => Ok(command),
            Some(_) => Err(SMTPError::Syntax { reason: "arguments to a command that takes none" }),
        };
        match verb.as_str() {
            "HELO" | "EHLO" => {
                let domain = rest.ok_or(SMTPError::Syntax { reason: "no domain" })?;
                if !SMTPMailbox::is_domain_of(domain, utf8) && !SMTPMailbox::is_address_literal(domain) {
                    return invalid("not a domain or an address literal");
                }
                let domain = text_of(domain)?;
                Ok(if verb == "HELO" { SMTPCommand::Helo(domain) } else { SMTPCommand::Ehlo(domain) })
            }
            "MAIL" | "RCPT" => {
                let prefix: &[u8] = if verb == "MAIL" { b"FROM:" } else { b"TO:" };
                let rest = rest.ok_or(SMTPError::Syntax { reason: "no path" })?;
                if rest.len() < prefix.len() || !rest[..prefix.len()].eq_ignore_ascii_case(prefix) {
                    return invalid("MAIL without FROM: or RCPT without TO:");
                }
                let rest = &rest[prefix.len()..];
                let rest = &rest[rest.iter().take_while(|byte| **byte == b' ').count()..];
                let end = SMTPCommand::path_end(rest).ok_or(SMTPError::Syntax { reason: "a path not closed" })?;
                let path = SMTPPath::parse(&rest[..end], utf8, verb == "RCPT")?;
                if verb == "MAIL" && path == SMTPPath::Postmaster {
                    return invalid("<Postmaster> as a reverse path");
                }
                if verb == "RCPT" && path == SMTPPath::Null {
                    return invalid("the null path as a forward path");
                }
                let parameters = match &rest[end..] {
                    [] => Vec::new(),
                    [b' ', parameters @ ..] => parameters
                        .split(|byte| *byte == b' ')
                        .map(|text| SMTPParameter::parse(text, utf8))
                        .collect::<Result<_, _>>()?,
                    _ => return invalid("no space before parameters"),
                };
                Ok(match verb.as_str() {
                    "MAIL" => SMTPCommand::Mail { path, parameters },
                    _ => SMTPCommand::Rcpt { path, parameters },
                })
            }
            "DATA" => none(SMTPCommand::Data),
            "RSET" => none(SMTPCommand::Rset),
            "QUIT" => none(SMTPCommand::Quit),
            "STARTTLS" => none(SMTPCommand::StartTLS),
            "VRFY" | "EXPN" => {
                let argument =
                    text_of(rest.filter(|rest| !rest.is_empty()).ok_or(SMTPError::Syntax { reason: "no argument" })?)?;
                Ok(if verb == "VRFY" { SMTPCommand::Vrfy(argument) } else { SMTPCommand::Expn(argument) })
            }
            "HELP" => Ok(SMTPCommand::Help(rest.map(text_of).transpose()?)),
            "NOOP" => Ok(SMTPCommand::Noop(rest.map(text_of).transpose()?)),
            "BDAT" => {
                let rest = rest.ok_or(SMTPError::Syntax { reason: "no chunk size" })?;
                let mut words = rest.split(|byte| *byte == b' ');
                let size = words.next().unwrap_or_default();
                if size.is_empty() || size.len() > 19 || !size.iter().all(u8::is_ascii_digit) {
                    return invalid("not a chunk size");
                }
                let size = core::str::from_utf8(size).ok().and_then(|size| size.parse().ok());
                let size = size.ok_or(SMTPError::Syntax { reason: "not a chunk size" })?;
                let last = match (words.next(), words.next()) {
                    (None, _) => false,
                    (Some(marker), None) if marker.eq_ignore_ascii_case(b"LAST") => true,
                    _ => return invalid("not the end marker of a chunk"),
                };
                Ok(SMTPCommand::Bdat { size, last })
            }
            "AUTH" => {
                let rest = rest.ok_or(SMTPError::Syntax { reason: "no mechanism" })?;
                let (mechanism, initial) = match rest.iter().position(|byte| *byte == b' ') {
                    Some(space) => (&rest[..space], Some(&rest[space + 1..])),
                    None => (rest, None),
                };
                let name =
                    |byte: &u8| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'-' || *byte == b'_';
                let mechanism = mechanism.to_ascii_uppercase();
                if !(1..=20).contains(&mechanism.len()) || !mechanism.iter().all(name) {
                    return invalid("not a mechanism name");
                }
                let initial = match initial {
                    None => None,
                    Some(b"=") => Some(Vec::new()),
                    Some(text) => {
                        Some(Base64::STANDARD.decode(text).map_err(|_| SMTPError::Syntax { reason: "not base64" })?)
                    }
                };
                Ok(SMTPCommand::Auth { mechanism: text_of(&mechanism)?, initial })
            }
            _ => {
                if !SMTPParameter::is_keyword(verb.as_bytes()) {
                    return invalid("not a verb");
                }
                Ok(SMTPCommand::Other { verb, arguments: text_of(rest.unwrap_or_default())? })
            }
        }
    }

    /// Where the path that begins `text` ends: after its `>`, a `>` in a
    /// quoted local part not counted.
    pub fn path_end(text: &[u8]) -> Option<usize> {
        if text.first() != Some(&b'<') {
            return None;
        }
        let mut quoted = false;
        let mut index = 1;
        while index < text.len() {
            match text[index] {
                b'\\' if quoted => index += 1,
                b'"' => quoted = !quoted,
                b'>' if !quoted => return Some(index + 1),
                _ => {}
            }
            index += 1;
        }
        None
    }

    /// Writes the command, its CRLF after it.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(alloc::format!("{self}").as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    /// Fails for a command that cannot be written as the one line it is: a CR, an LF or a NUL in
    /// a field, or a line that does not read back as a command (a domain with a space, say).
    /// What a client sends is checked so, that no field adds a command of its own.
    pub fn check(&self) -> Result<(), SMTPError> {
        let line = alloc::format!("{self}");
        if line.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(SMTPError::Syntax { reason: "a line break in a command" });
        }
        SMTPCommand::parse(line.as_bytes(), true).map(|_| ())
    }
}

impl fmt::Display for SMTPCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parameters = |formatter: &mut fmt::Formatter<'_>, parameters: &[SMTPParameter]| {
            parameters.iter().try_for_each(|parameter| write!(formatter, " {parameter}"))
        };
        match self {
            SMTPCommand::Helo(domain) | SMTPCommand::Ehlo(domain) => write!(formatter, "{} {domain}", self.verb()),
            SMTPCommand::Mail { path, parameters: list } => {
                write!(formatter, "MAIL FROM:{path}")?;
                parameters(formatter, list)
            }
            SMTPCommand::Rcpt { path, parameters: list } => {
                write!(formatter, "RCPT TO:{path}")?;
                parameters(formatter, list)
            }
            SMTPCommand::Bdat { size, last } => write!(formatter, "BDAT {size}{}", if *last { " LAST" } else { "" }),
            SMTPCommand::Vrfy(argument) | SMTPCommand::Expn(argument) => {
                write!(formatter, "{} {argument}", self.verb())
            }
            SMTPCommand::Help(Some(argument)) | SMTPCommand::Noop(Some(argument)) => {
                write!(formatter, "{} {argument}", self.verb())
            }
            SMTPCommand::Auth { mechanism, initial } => {
                write!(formatter, "AUTH {mechanism}")?;
                match initial {
                    None => Ok(()),
                    Some(initial) if initial.is_empty() => formatter.write_str(" ="),
                    Some(initial) => write!(formatter, " {}", Base64::STANDARD.encode(initial)),
                }
            }
            SMTPCommand::Other { verb, arguments } if arguments.is_empty() => formatter.write_str(verb),
            SMTPCommand::Other { verb, arguments } => write!(formatter, "{verb} {arguments}"),
            _ => formatter.write_str(self.verb()),
        }
    }
}
