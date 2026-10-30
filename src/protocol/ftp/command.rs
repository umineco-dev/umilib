use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::{FTPDataAddress, FTPError};

/// A command (RFC 959 §4.1, and the extensions). Pathnames and other
/// arguments are text as sent (UTF-8, RFC 2640 §3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FTPCommand {
    User(String),
    Pass(String),
    Acct(String),
    Cwd(String),
    Cdup,
    Smnt(String),
    Quit,
    Rein,
    Port(FTPDataAddress),
    Pasv,
    /// TYPE and its argument as sent, in upper case (`A`, `I`, `A N`, `L 8`).
    Type(String),
    Stru(char),
    Mode(char),
    Retr(String),
    Stor(String),
    Stou,
    Appe(String),
    Allo(String),
    /// REST and its marker (RFC 959 §4.1.3; RFC 3659 §5: an octet offset of STREAM mode).
    Rest(String),
    Rnfr(String),
    Rnto(String),
    Abor,
    Dele(String),
    Rmd(String),
    Mkd(String),
    Pwd,
    List(Option<String>),
    Nlst(Option<String>),
    Site(String),
    Syst,
    Stat(Option<String>),
    Help(Option<String>),
    Noop,
    /// RFC 2389.
    Feat,
    Opts(String),
    /// RFC 2428: EPRT, and EPSV of a network protocol or ALL.
    Eprt(FTPDataAddress),
    Epsv(Option<String>),
    /// RFC 3659.
    Size(String),
    Mdtm(String),
    Mlst(Option<String>),
    Mlsd(Option<String>),
    /// RFC 7151.
    Host(String),
    /// RFC 4217: AUTH of a mechanism (TLS), PBSZ, PROT of a level, CCC.
    Auth(String),
    Pbsz(u64),
    Prot(char),
    Ccc,
    /// RFC 2640.
    Lang(Option<String>),
    /// A command this type does not know: its verb in upper case and its argument.
    Other {
        verb: String,
        argument: Option<String>,
    },
}

impl FTPCommand {
    pub fn verb(&self) -> &str {
        match self {
            FTPCommand::User(_) => "USER",
            FTPCommand::Pass(_) => "PASS",
            FTPCommand::Acct(_) => "ACCT",
            FTPCommand::Cwd(_) => "CWD",
            FTPCommand::Cdup => "CDUP",
            FTPCommand::Smnt(_) => "SMNT",
            FTPCommand::Quit => "QUIT",
            FTPCommand::Rein => "REIN",
            FTPCommand::Port(_) => "PORT",
            FTPCommand::Pasv => "PASV",
            FTPCommand::Type(_) => "TYPE",
            FTPCommand::Stru(_) => "STRU",
            FTPCommand::Mode(_) => "MODE",
            FTPCommand::Retr(_) => "RETR",
            FTPCommand::Stor(_) => "STOR",
            FTPCommand::Stou => "STOU",
            FTPCommand::Appe(_) => "APPE",
            FTPCommand::Allo(_) => "ALLO",
            FTPCommand::Rest(_) => "REST",
            FTPCommand::Rnfr(_) => "RNFR",
            FTPCommand::Rnto(_) => "RNTO",
            FTPCommand::Abor => "ABOR",
            FTPCommand::Dele(_) => "DELE",
            FTPCommand::Rmd(_) => "RMD",
            FTPCommand::Mkd(_) => "MKD",
            FTPCommand::Pwd => "PWD",
            FTPCommand::List(_) => "LIST",
            FTPCommand::Nlst(_) => "NLST",
            FTPCommand::Site(_) => "SITE",
            FTPCommand::Syst => "SYST",
            FTPCommand::Stat(_) => "STAT",
            FTPCommand::Help(_) => "HELP",
            FTPCommand::Noop => "NOOP",
            FTPCommand::Feat => "FEAT",
            FTPCommand::Opts(_) => "OPTS",
            FTPCommand::Eprt(_) => "EPRT",
            FTPCommand::Epsv(_) => "EPSV",
            FTPCommand::Size(_) => "SIZE",
            FTPCommand::Mdtm(_) => "MDTM",
            FTPCommand::Mlst(_) => "MLST",
            FTPCommand::Mlsd(_) => "MLSD",
            FTPCommand::Host(_) => "HOST",
            FTPCommand::Auth(_) => "AUTH",
            FTPCommand::Pbsz(_) => "PBSZ",
            FTPCommand::Prot(_) => "PROT",
            FTPCommand::Ccc => "CCC",
            FTPCommand::Lang(_) => "LANG",
            FTPCommand::Other { verb, .. } => verb,
        }
    }

    /// Whether the command transfers over a data connection: its replies are a preliminary 1xx
    /// and a final one (RFC 959 §5.4).
    pub fn transfers(&self) -> bool {
        matches!(
            self,
            FTPCommand::Retr(_)
                | FTPCommand::Stor(_)
                | FTPCommand::Stou
                | FTPCommand::Appe(_)
                | FTPCommand::List(_)
                | FTPCommand::Nlst(_)
                | FTPCommand::Mlsd(_)
        )
    }

    /// The command of a line, its CRLF removed: a verb of letters in any case, a space and an
    /// argument where it takes one (RFC 959 §5.3).
    pub fn parse(line: &[u8]) -> Result<FTPCommand, FTPError> {
        let invalid = |reason| Err(FTPError::Syntax { reason });
        if line.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return invalid("a CR, LF or NUL in a command");
        }
        let line = core::str::from_utf8(line).map_err(|_| FTPError::Syntax { reason: "not UTF-8 (RFC 2640 §3)" })?;
        let (verb, argument) = match line.split_once(' ') {
            Some((verb, argument)) => (verb, Some(argument)),
            None => (line, None),
        };
        if !(3..=4).contains(&verb.len()) || !verb.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return invalid("not a verb");
        }
        let verb = verb.to_ascii_uppercase();
        let text = |argument: Option<&str>| argument.filter(|argument| !argument.is_empty()).map(String::from);
        let required = |argument: Option<&str>| text(argument).ok_or(FTPError::Syntax { reason: "no argument" });
        let none = |command: FTPCommand| match argument {
            None => Ok(command),
            Some(_) => Err(FTPError::Syntax { reason: "an argument to a command that takes none" }),
        };
        let code = |argument: Option<&str>| -> Result<char, FTPError> {
            let argument = required(argument)?;
            let mut characters = argument.chars();
            match (characters.next(), characters.next()) {
                (Some(code), None) => Ok(code.to_ascii_uppercase()),
                _ => Err(FTPError::Syntax { reason: "not a code" }),
            }
        };
        Ok(match verb.as_str() {
            "USER" => FTPCommand::User(required(argument)?),
            "PASS" => FTPCommand::Pass(argument.map(String::from).unwrap_or_default()),
            "ACCT" => FTPCommand::Acct(required(argument)?),
            "CWD" => FTPCommand::Cwd(required(argument)?),
            "CDUP" => none(FTPCommand::Cdup)?,
            "SMNT" => FTPCommand::Smnt(required(argument)?),
            "QUIT" => none(FTPCommand::Quit)?,
            "REIN" => none(FTPCommand::Rein)?,
            "PORT" => FTPCommand::Port(FTPDataAddress::parse_port(&required(argument)?)?),
            "PASV" => none(FTPCommand::Pasv)?,
            "TYPE" => FTPCommand::Type(required(argument)?.to_ascii_uppercase()),
            "STRU" => FTPCommand::Stru(code(argument)?),
            "MODE" => FTPCommand::Mode(code(argument)?),
            "RETR" => FTPCommand::Retr(required(argument)?),
            "STOR" => FTPCommand::Stor(required(argument)?),
            "STOU" => none(FTPCommand::Stou)?,
            "APPE" => FTPCommand::Appe(required(argument)?),
            "ALLO" => FTPCommand::Allo(required(argument)?),
            "REST" => FTPCommand::Rest(required(argument)?),
            "RNFR" => FTPCommand::Rnfr(required(argument)?),
            "RNTO" => FTPCommand::Rnto(required(argument)?),
            "ABOR" => none(FTPCommand::Abor)?,
            "DELE" => FTPCommand::Dele(required(argument)?),
            "RMD" | "XRMD" => FTPCommand::Rmd(required(argument)?),
            "MKD" | "XMKD" => FTPCommand::Mkd(required(argument)?),
            "PWD" | "XPWD" => none(FTPCommand::Pwd)?,
            "LIST" => FTPCommand::List(text(argument)),
            "NLST" => FTPCommand::Nlst(text(argument)),
            "SITE" => FTPCommand::Site(required(argument)?),
            "SYST" => none(FTPCommand::Syst)?,
            "STAT" => FTPCommand::Stat(text(argument)),
            "HELP" => FTPCommand::Help(text(argument)),
            "NOOP" => none(FTPCommand::Noop)?,
            "FEAT" => none(FTPCommand::Feat)?,
            "OPTS" => FTPCommand::Opts(required(argument)?),
            "EPRT" => FTPCommand::Eprt(FTPDataAddress::parse_eprt(&required(argument)?)?),
            "EPSV" => FTPCommand::Epsv(text(argument).map(|argument| argument.to_ascii_uppercase())),
            "SIZE" => FTPCommand::Size(required(argument)?),
            "MDTM" => FTPCommand::Mdtm(required(argument)?),
            "MLST" => FTPCommand::Mlst(text(argument)),
            "MLSD" => FTPCommand::Mlsd(text(argument)),
            "HOST" => FTPCommand::Host(required(argument)?),
            "AUTH" => FTPCommand::Auth(required(argument)?.to_ascii_uppercase()),
            "PBSZ" => {
                let size = required(argument)?;
                let valid = size.len() <= 20 && size.bytes().all(|byte| byte.is_ascii_digit());
                FTPCommand::Pbsz(
                    valid
                        .then(|| size.parse().ok())
                        .flatten()
                        .ok_or(FTPError::Syntax { reason: "not a buffer size" })?,
                )
            }
            "PROT" => FTPCommand::Prot(code(argument)?),
            "CCC" => none(FTPCommand::Ccc)?,
            "LANG" => FTPCommand::Lang(text(argument)),
            _ => FTPCommand::Other { verb, argument: argument.map(String::from) },
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), FTPError> {
        let line = match self {
            FTPCommand::Port(address) => alloc::format!("PORT {}", address.format_port()?),
            FTPCommand::Eprt(address) => alloc::format!("EPRT {}", address.format_eprt()?),
            command => alloc::format!("{command}"),
        };
        if line.contains(['\r', '\n', '\0']) {
            return Err(FTPError::Syntax { reason: "a line break in a command" });
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
        Ok(())
    }
}

impl fmt::Display for FTPCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verb = self.verb();
        match self {
            FTPCommand::User(text)
            | FTPCommand::Acct(text)
            | FTPCommand::Cwd(text)
            | FTPCommand::Smnt(text)
            | FTPCommand::Type(text)
            | FTPCommand::Retr(text)
            | FTPCommand::Stor(text)
            | FTPCommand::Appe(text)
            | FTPCommand::Allo(text)
            | FTPCommand::Rest(text)
            | FTPCommand::Rnfr(text)
            | FTPCommand::Rnto(text)
            | FTPCommand::Dele(text)
            | FTPCommand::Rmd(text)
            | FTPCommand::Mkd(text)
            | FTPCommand::Site(text)
            | FTPCommand::Opts(text)
            | FTPCommand::Size(text)
            | FTPCommand::Mdtm(text)
            | FTPCommand::Host(text)
            | FTPCommand::Auth(text) => write!(formatter, "{verb} {text}"),
            FTPCommand::Pass(text) => write!(formatter, "PASS {text}"),
            FTPCommand::List(Some(text))
            | FTPCommand::Nlst(Some(text))
            | FTPCommand::Stat(Some(text))
            | FTPCommand::Help(Some(text))
            | FTPCommand::Epsv(Some(text))
            | FTPCommand::Mlst(Some(text))
            | FTPCommand::Mlsd(Some(text))
            | FTPCommand::Lang(Some(text)) => write!(formatter, "{verb} {text}"),
            FTPCommand::Port(address) => write!(formatter, "PORT {}", address.format_port().unwrap_or_default()),
            FTPCommand::Eprt(address) => write!(formatter, "EPRT {}", address.format_eprt().unwrap_or_default()),
            FTPCommand::Stru(code) | FTPCommand::Mode(code) | FTPCommand::Prot(code) => {
                write!(formatter, "{verb} {code}")
            }
            FTPCommand::Pbsz(size) => write!(formatter, "PBSZ {size}"),
            FTPCommand::Other { verb, argument: Some(argument) } => write!(formatter, "{verb} {argument}"),
            _ => formatter.write_str(verb),
        }
    }
}
