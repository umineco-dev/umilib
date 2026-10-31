use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::POP3Error;
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;

/// A command (RFC 1939 §4 to §7, and the extensions). Message numbers are
/// 1 or more; whether a message of the number exists is the maildrop's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum POP3Command {
    User(String),
    /// The rest of the line: a password may have spaces (RFC 1939 §7).
    Pass(String),
    /// A name and the MD5 digest of the greeting's timestamp and a secret, in lower-case
    /// hexadecimal (RFC 1939 §7).
    Apop {
        name: String,
        digest: String,
    },
    Quit,
    Stat,
    List(Option<u32>),
    Retr(u32),
    Dele(u32),
    Noop,
    Rset,
    Top {
        message: u32,
        lines: u32,
    },
    Uidl(Option<u32>),
    /// RFC 2449 §5.
    Capa,
    /// RFC 2595 §4.
    Stls,
    /// A SASL exchange of a mechanism, with an initial response if given (RFC 5034 §4;
    /// `Some` of nothing is written `=`).
    Auth {
        mechanism: String,
        initial: Option<Vec<u8>>,
    },
    /// RFC 6856 §2.1.
    UTF8,
    /// A language range, or none for the list of languages (RFC 6856 §3).
    Lang(Option<String>),
    /// A command this type does not know: its keyword in upper case and its parameters.
    Other {
        keyword: String,
        parameters: Vec<String>,
    },
}

impl POP3Command {
    /// The keyword of the command, in upper case.
    pub fn keyword(&self) -> &str {
        match self {
            POP3Command::User(_) => "USER",
            POP3Command::Pass(_) => "PASS",
            POP3Command::Apop { .. } => "APOP",
            POP3Command::Quit => "QUIT",
            POP3Command::Stat => "STAT",
            POP3Command::List(_) => "LIST",
            POP3Command::Retr(_) => "RETR",
            POP3Command::Dele(_) => "DELE",
            POP3Command::Noop => "NOOP",
            POP3Command::Rset => "RSET",
            POP3Command::Top { .. } => "TOP",
            POP3Command::Uidl(_) => "UIDL",
            POP3Command::Capa => "CAPA",
            POP3Command::Stls => "STLS",
            POP3Command::Auth { .. } => "AUTH",
            POP3Command::UTF8 => "UTF8",
            POP3Command::Lang(_) => "LANG",
            POP3Command::Other { keyword, .. } => keyword,
        }
    }

    /// Whether a positive response to the command is multi-line (RFC 1939
    /// §5, §7; RFC 2449 §5; RFC 6856 §3).
    pub fn is_multi_line(&self) -> bool {
        matches!(
            self,
            POP3Command::List(None)
                | POP3Command::Uidl(None)
                | POP3Command::Retr(_)
                | POP3Command::Top { .. }
                | POP3Command::Capa
                | POP3Command::Lang(None)
        )
    }

    /// A message number: decimal digits of a value of 1 or more.
    pub fn number(text: &str) -> Result<u32, POP3Error> {
        let valid = !text.is_empty() && text.len() <= 10 && text.bytes().all(|byte| byte.is_ascii_digit());
        valid
            .then(|| text.parse::<u32>().ok())
            .flatten()
            .filter(|number| *number > 0)
            .ok_or(POP3Error::Syntax { reason: "not a message number" })
    }

    /// The command of a line, its CRLF removed: a keyword of 3 or 4
    /// characters in any case, and parameters separated by single spaces
    /// (RFC 2449 §3), of UTF-8 with `utf8` (RFC 6856 §2.2).
    pub fn parse(line: &[u8], utf8: bool) -> Result<POP3Command, POP3Error> {
        let invalid = |reason| Err(POP3Error::Syntax { reason });
        if line.iter().any(u8::is_ascii_control) || (!utf8 && !line.is_ascii()) {
            return invalid("a control character or a byte of no US-ASCII character in a command");
        }
        let line = core::str::from_utf8(line).map_err(|_| POP3Error::Syntax { reason: "not UTF-8" })?;
        let (keyword, rest) = match line.split_once(' ') {
            Some((keyword, rest)) => (keyword, Some(rest)),
            None => (line, None),
        };
        if !(3..=4).contains(&keyword.len()) || !keyword.bytes().all(|byte| byte.is_ascii_graphic()) {
            return invalid("not a keyword");
        }
        let keyword = keyword.to_ascii_uppercase();
        let parameters: Vec<&str> = rest.map(|rest| rest.split(' ').collect()).unwrap_or_default();
        if keyword != "PASS" && parameters.iter().any(|parameter| parameter.is_empty()) {
            return invalid("an empty parameter");
        }
        let count = |expected: core::ops::RangeInclusive<usize>| match expected.contains(&parameters.len()) {
            true => Ok(()),
            false => Err(POP3Error::Syntax { reason: "not the parameters of the command" }),
        };
        let optional_number =
            |parameters: &[&str]| parameters.first().map(|number| POP3Command::number(number)).transpose();
        Ok(match keyword.as_str() {
            "USER" => {
                count(1..=1)?;
                POP3Command::User(String::from(parameters[0]))
            }
            "PASS" => POP3Command::Pass(String::from(
                rest.filter(|rest| !rest.is_empty()).ok_or(POP3Error::Syntax { reason: "no password" })?,
            )),
            "APOP" => {
                count(2..=2)?;
                let digest = parameters[1];
                if digest.len() != 32
                    || !digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return invalid("not a digest of 32 lower-case hexadecimal digits");
                }
                POP3Command::Apop { name: String::from(parameters[0]), digest: String::from(digest) }
            }
            "QUIT" | "STAT" | "NOOP" | "RSET" | "CAPA" | "STLS" | "UTF8" => {
                count(0..=0)?;
                match keyword.as_str() {
                    "QUIT" => POP3Command::Quit,
                    "STAT" => POP3Command::Stat,
                    "NOOP" => POP3Command::Noop,
                    "RSET" => POP3Command::Rset,
                    "CAPA" => POP3Command::Capa,
                    "STLS" => POP3Command::Stls,
                    _ => POP3Command::UTF8,
                }
            }
            "LIST" | "UIDL" => {
                count(0..=1)?;
                let number = optional_number(&parameters)?;
                if keyword == "LIST" { POP3Command::List(number) } else { POP3Command::Uidl(number) }
            }
            "RETR" | "DELE" => {
                count(1..=1)?;
                let number = POP3Command::number(parameters[0])?;
                if keyword == "RETR" { POP3Command::Retr(number) } else { POP3Command::Dele(number) }
            }
            "TOP" => {
                count(2..=2)?;
                let lines = parameters[1];
                let valid = !lines.is_empty() && lines.len() <= 10 && lines.bytes().all(|byte| byte.is_ascii_digit());
                let lines = valid
                    .then(|| lines.parse::<u32>().ok())
                    .flatten()
                    .ok_or(POP3Error::Syntax { reason: "not a number of lines" })?;
                POP3Command::Top { message: POP3Command::number(parameters[0])?, lines }
            }
            "AUTH" => {
                count(1..=2)?;
                let mechanism = parameters[0].to_ascii_uppercase();
                let name =
                    |byte: u8| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_';
                if !(1..=20).contains(&mechanism.len()) || !mechanism.bytes().all(name) {
                    return invalid("not a mechanism name");
                }
                let initial = match parameters.get(1) {
                    None => None,
                    Some(&"=") => Some(Vec::new()),
                    Some(text) => Some(
                        Base64::STANDARD
                            .decode(text.as_bytes())
                            .map_err(|_| POP3Error::Syntax { reason: "not base64" })?,
                    ),
                };
                POP3Command::Auth { mechanism, initial }
            }
            "LANG" => {
                count(0..=1)?;
                POP3Command::Lang(parameters.first().map(|range| String::from(*range)))
            }
            _ => POP3Command::Other {
                keyword,
                parameters: parameters.iter().map(|parameter| String::from(*parameter)).collect(),
            },
        })
    }

    /// Writes the command, its CRLF after it.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(alloc::format!("{self}").as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    /// Fails for a command that cannot be written as the one line it is: a CR, an LF or a NUL in
    /// an argument, or a line that does not read back as a command (a name with a space, say).
    /// What a client sends is checked so, that no argument adds a command of its own.
    pub fn check(&self) -> Result<(), POP3Error> {
        let line = alloc::format!("{self}");
        if line.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(POP3Error::Syntax { reason: "a line break in a command" });
        }
        POP3Command::parse(line.as_bytes(), true).map(|_| ())
    }
}

impl fmt::Display for POP3Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let keyword = self.keyword();
        match self {
            POP3Command::User(argument) | POP3Command::Pass(argument) => write!(formatter, "{keyword} {argument}"),
            POP3Command::Apop { name, digest } => write!(formatter, "APOP {name} {digest}"),
            POP3Command::List(Some(number))
            | POP3Command::Uidl(Some(number))
            | POP3Command::Retr(number)
            | POP3Command::Dele(number) => {
                write!(formatter, "{keyword} {number}")
            }
            POP3Command::Top { message, lines } => write!(formatter, "TOP {message} {lines}"),
            POP3Command::Auth { mechanism, initial } => {
                write!(formatter, "AUTH {mechanism}")?;
                match initial {
                    None => Ok(()),
                    Some(initial) if initial.is_empty() => formatter.write_str(" ="),
                    Some(initial) => write!(formatter, " {}", Base64::STANDARD.encode(initial)),
                }
            }
            POP3Command::Lang(Some(range)) => write!(formatter, "LANG {range}"),
            POP3Command::Other { keyword, parameters } => {
                formatter.write_str(keyword)?;
                parameters.iter().try_for_each(|parameter| write!(formatter, " {parameter}"))
            }
            _ => formatter.write_str(keyword),
        }
    }
}

#[cfg(all(umilib_feature = "hash-md-v5", umilib_feature = "secret"))]
impl POP3Command {
    /// The digest of APOP (RFC 1939 §7): MD5 of the greeting's timestamp
    /// (with its angle brackets) and the shared secret, in lower-case
    /// hexadecimal. MD5 no longer protects the secret well; APOP is for
    /// servers that offer nothing better, and only under TLS.
    pub fn apop_digest(timestamp: &[u8], secret: &[u8]) -> String {
        use crate::hash::Digest;
        let mut md5 = crate::hash::md::v5::MD5::new();
        md5.update(timestamp);
        md5.update(secret);
        md5.finalize().iter().map(|byte| alloc::format!("{byte:02x}")).collect()
    }

    /// The APOP command of `name` for the greeting's timestamp and the shared secret.
    pub fn apop(name: &str, timestamp: &[u8], secret: &[u8]) -> POP3Command {
        POP3Command::Apop { name: String::from(name), digest: POP3Command::apop_digest(timestamp, secret) }
    }

    /// Whether `digest` is the APOP digest of the timestamp and the secret, compared in constant time.
    pub fn apop_matches(digest: &str, timestamp: &[u8], secret: &[u8]) -> bool {
        use crate::secret::ConstantTimeEq;
        let expected = POP3Command::apop_digest(timestamp, secret);
        digest.len() == expected.len() && digest.as_bytes().ct_eq(expected.as_bytes()).into_bool()
    }
}
