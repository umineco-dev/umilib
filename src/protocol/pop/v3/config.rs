use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use super::POP3Error;

/// The limits and times of a POP3 connection, of a client or a server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct POP3Config {
    /// The longest command line, its CRLF counted (RFC 2449 §4: at least 255).
    pub maximum_command_line: usize,
    /// The longest first line of a response, its CRLF counted (RFC 2449 §4: 512).
    pub maximum_response_line: usize,
    /// The longest line of an AUTH exchange, its CRLF counted (RFC 5034 §4: as long as the
    /// mechanisms need).
    pub maximum_auth_line: usize,
    /// The most octets of the capability list read (RFC 2449 §5).
    pub maximum_capabilities: usize,
    /// The most octets of input held while the other end has not been answered.
    pub maximum_buffered: usize,
    /// The time a client waits for a response.
    pub response_timeout: Duration,
    /// The time a server waits for a command, its autologout timer (RFC 1939 §3: at least 10 minutes).
    pub autologout: Duration,
    /// Whether a client sends a password as it is (USER and PASS, APOP, AUTH PLAIN or LOGIN)
    /// only under TLS (RFC 2595 §2.3: a client MUST be configurable to refuse to); a server's is
    /// of its [`POP3ServerConfig`].
    pub passwords_require_tls: bool,
}

impl Default for POP3Config {
    fn default() -> POP3Config {
        POP3Config {
            maximum_command_line: 255,
            maximum_response_line: 512,
            maximum_auth_line: 12288,
            maximum_capabilities: 64 * 1024,
            maximum_buffered: 64 * 1024,
            response_timeout: Duration::from_secs(10 * 60),
            autologout: Duration::from_secs(10 * 60),
            passwords_require_tls: true,
        }
    }
}

impl POP3Config {
    /// Fails for values RFC 1939 and RFC 2449 do not let a conforming end have.
    pub fn check(&self) -> Result<(), POP3Error> {
        let invalid = |reason| Err(POP3Error::State { reason });
        if self.maximum_command_line < 255 || self.maximum_response_line < 512 {
            return invalid("a line limit under the minimum of RFC 2449 §4");
        }
        if self.maximum_auth_line < self.maximum_command_line || self.maximum_capabilities < self.maximum_response_line
        {
            return invalid("an AUTH line shorter than a command, or capabilities shorter than a line");
        }
        if self.maximum_buffered < self.maximum_auth_line {
            return invalid("less buffered than one line");
        }
        if self.autologout < Duration::from_secs(10 * 60) || self.response_timeout.is_zero() {
            return invalid("an autologout timer under the 10 minutes of RFC 1939 §3, or a zero timeout");
        }
        Ok(())
    }
}

/// What a POP3 server offers and requires: the capabilities it announces
/// (RFC 2449 §6), and its policies.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct POP3ServerConfig {
    /// Whether USER and PASS are taken (RFC 1939 §7, RFC 2449 §6.2).
    pub user: bool,
    pub top: bool,
    pub uidl: bool,
    pub pipelining: bool,
    /// Whether responses carry the codes of RFC 2449 §8 (RESP-CODES, and AUTH-RESP-CODE of RFC 3206).
    pub response_codes: bool,
    /// Whether STLS is offered (RFC 2595 §4); never under TLS.
    pub stls: bool,
    /// The SASL mechanisms offered by AUTH (RFC 5034), by name.
    pub sasl_mechanisms: Vec<String>,
    /// The mechanisms of those that send a password as it is besides PLAIN (RFC 4616 §1), which
    /// always is one: so a list left empty never offers PLAIN without TLS by mistake.
    pub plaintext_mechanisms: Vec<String>,
    /// Whether passwords sent as they are, of USER and PASS, of APOP and of the plaintext
    /// mechanisms, are taken only under TLS (RFC 5034 §4: a server MUST be able not to take
    /// them without it, SHOULD by default).
    pub passwords_require_tls: bool,
    /// Whether UTF-8 mode is offered (RFC 6856 §2), and whether names and passwords of UTF-8 are (§2.2).
    pub utf8: bool,
    pub utf8_user: bool,
    /// Whether LANG is offered (RFC 6856 §3).
    pub lang: bool,
    /// The seconds between logins announced by LOGIN-DELAY (RFC 2449 §6.5).
    pub login_delay: Option<u32>,
    /// The days messages are kept, announced by EXPIRE (RFC 2449 §6.7): a number or NEVER.
    pub expire: Option<String>,
    /// The text of IMPLEMENTATION (RFC 2449 §6.9).
    pub implementation: Option<String>,
    /// The commands of extensions the user implements, by name: they are told; another command
    /// this crate does not know is answered as not recognized.
    pub commands: Vec<String>,
}

impl Default for POP3ServerConfig {
    fn default() -> POP3ServerConfig {
        POP3ServerConfig {
            user: true,
            top: true,
            uidl: true,
            pipelining: true,
            response_codes: true,
            stls: false,
            sasl_mechanisms: Vec::new(),
            plaintext_mechanisms: Vec::new(),
            passwords_require_tls: true,
            utf8: false,
            utf8_user: false,
            lang: false,
            login_delay: None,
            expire: None,
            implementation: None,
            commands: Vec::new(),
        }
    }
}

impl POP3ServerConfig {
    /// Fails for a mechanism name that is not one (RFC 4422 §3.1), an EXPIRE that is neither
    /// a number nor NEVER (RFC 2449 §6.7), a text of no printable US-ASCII, UTF-8 names without UTF-8.
    pub fn check(&self) -> Result<(), POP3Error> {
        let invalid = |reason| Err(POP3Error::State { reason });
        let name = |name: &String| {
            (1..=20).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_')
        };
        if !self.sasl_mechanisms.iter().chain(&self.plaintext_mechanisms).all(name) {
            return invalid("not a SASL mechanism name");
        }
        if let Some(expire) = &self.expire
            && expire != "NEVER"
            && (expire.is_empty() || !expire.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return invalid("an EXPIRE that is neither a number nor NEVER");
        }
        if self
            .implementation
            .as_ref()
            .is_some_and(|text| text.is_empty() || !text.bytes().all(|byte| (32..=126).contains(&byte)))
        {
            return invalid("an IMPLEMENTATION of no printable US-ASCII");
        }
        if self.utf8_user && !self.utf8 {
            return invalid("UTF-8 names without UTF8");
        }
        Ok(())
    }
}
