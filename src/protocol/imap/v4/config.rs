use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use super::IMAPError;

/// The limits and times of an IMAP connection, of a client or a server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IMAPConfig {
    /// The longest line between literals, its CRLF counted. RFC 9051 sets none; 8192 is what
    /// RFC 7162 §4 recommends a server take.
    pub maximum_line: usize,
    /// The largest literal taken (an APPEND's message the largest), in octets.
    pub maximum_literal: u64,
    /// The most octets of a command or a response, its literals counted.
    pub maximum_command: u64,
    /// The deepest nesting of parenthesized lists read.
    pub maximum_depth: usize,
    /// The most octets of input held while the other end has not been answered.
    pub maximum_buffered: usize,
    /// The time a client waits for the completion of a command; IDLE is not timed.
    pub command_timeout: Duration,
    /// The time a server waits for a command after authentication (RFC 9051 §5.4: at least 30 minutes).
    pub autologout: Duration,
    /// The time a server waits for a command before authentication (§5.4: it may be shorter).
    pub login_timeout: Duration,
    /// Whether a client sends a password as it is (LOGIN, AUTHENTICATE PLAIN or LOGIN) only
    /// under TLS (RFC 9051 §11.1, RFC 2595 §2.3: a client MUST be configurable to refuse to); a
    /// server's is of its [`IMAPServerConfig`].
    pub passwords_require_tls: bool,
}

impl Default for IMAPConfig {
    fn default() -> IMAPConfig {
        IMAPConfig {
            maximum_line: 8192,
            maximum_literal: 64 * 1024 * 1024,
            maximum_command: 65 * 1024 * 1024,
            maximum_depth: 64,
            maximum_buffered: 64 * 1024,
            command_timeout: Duration::from_secs(30 * 60),
            autologout: Duration::from_secs(30 * 60),
            login_timeout: Duration::from_secs(60),
            passwords_require_tls: true,
        }
    }
}

impl IMAPConfig {
    /// Fails for values a conforming end cannot have: an autologout under 30 minutes
    /// (RFC 9051 §5.4), a line too short for a command, a zero time.
    pub fn check(&self) -> Result<(), IMAPError> {
        let invalid = |reason| Err(IMAPError::State { reason });
        if self.maximum_line < 1000 || self.maximum_depth == 0 || self.maximum_command < self.maximum_line as u64 {
            return invalid("a limit too small for a command");
        }
        if self.maximum_buffered < self.maximum_line {
            return invalid("less buffered than one line");
        }
        if self.autologout < Duration::from_secs(30 * 60)
            || self.command_timeout.is_zero()
            || self.login_timeout.is_zero()
        {
            return invalid("an autologout under the 30 minutes of RFC 9051 §5.4, or a zero time");
        }
        Ok(())
    }
}

/// What an IMAP server offers and requires: the capabilities it announces
/// (RFC 9051 §6.1.1, §7.2.2), and its policies.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IMAPServerConfig {
    /// Whether IMAP4rev1 is offered too (RFC 9051 Appendix E): a client that does not ENABLE
    /// IMAP4rev2 is answered as RFC 3501 answers.
    pub rev1: bool,
    /// Whether STARTTLS is offered (RFC 9051 §6.2.1); never under TLS.
    pub starttls: bool,
    /// The SASL mechanisms of AUTHENTICATE, announced as AUTH= capabilities.
    pub auth_mechanisms: Vec<String>,
    /// The mechanisms of those that send a password as it is besides PLAIN (RFC 4616 §1), which
    /// always is one: so a list left empty never offers PLAIN without TLS by mistake.
    pub plaintext_mechanisms: Vec<String>,
    /// Whether LOGIN and the plaintext mechanisms are taken only under TLS (RFC 9051 §6.2.3:
    /// a server MUST NOT take a password without TLS unless so configured; LOGINDISABLED
    /// is announced then).
    pub passwords_require_tls: bool,
    /// Whether non-synchronizing literals of any size are taken (LITERAL+, RFC 7888); of at most
    /// 4096 octets otherwise (LITERAL-, part of IMAP4rev2).
    pub literal_plus: bool,
    /// Other capabilities announced as they are, of extensions the user implements.
    pub capabilities: Vec<String>,
    /// The commands of extensions the user implements, by name: they are told; another command
    /// this crate does not know is answered as not recognized.
    pub commands: Vec<String>,
}

impl Default for IMAPServerConfig {
    fn default() -> IMAPServerConfig {
        IMAPServerConfig {
            rev1: true,
            starttls: false,
            auth_mechanisms: Vec::new(),
            plaintext_mechanisms: Vec::new(),
            passwords_require_tls: true,
            literal_plus: false,
            capabilities: Vec::new(),
            commands: Vec::new(),
        }
    }
}

impl IMAPServerConfig {
    /// Fails for a mechanism name that is not one (RFC 4422 §3.1), or a capability that is not an atom.
    pub fn check(&self) -> Result<(), IMAPError> {
        let invalid = |reason| Err(IMAPError::State { reason });
        let name = |name: &String| {
            (1..=20).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_')
        };
        if !self.auth_mechanisms.iter().chain(&self.plaintext_mechanisms).all(name) {
            return invalid("not a SASL mechanism name");
        }
        if !self
            .capabilities
            .iter()
            .all(|capability| !capability.is_empty() && capability.bytes().all(super::IMAPReader::is_atom_char))
        {
            return invalid("a capability that is not an atom");
        }
        Ok(())
    }
}
