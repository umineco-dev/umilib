use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use super::SMTPError;

/// The limits and times of an SMTP connection, of a client or a server.
/// The defaults are the minimums and times of RFC 5321 §4.5.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SMTPConfig {
    /// The longest command line, its CRLF counted (§4.5.3.1.4: at least 512).
    pub maximum_command_line: usize,
    /// The longest reply line, its CRLF counted (§4.5.3.1.5: at least 512).
    pub maximum_reply_line: usize,
    /// The most lines of a reply.
    pub maximum_reply_lines: usize,
    /// The longest line of a message, its CRLF counted (§4.5.3.1.6: 1000).
    pub maximum_text_line: usize,
    /// The longest line of an AUTH exchange, its CRLF counted (RFC 4954 §4: 12288 suffices).
    pub maximum_auth_line: usize,
    /// The most octets of input held while the other end has not been answered (pipelined
    /// commands, RFC 2920); past it the connection stops reading.
    pub maximum_buffered: usize,
    /// The time for the 220 greeting (§4.5.3.2.1).
    pub greeting_timeout: Duration,
    /// The time for the reply to MAIL (§4.5.3.2.2), RCPT (§4.5.3.2.3) and other commands.
    pub command_timeout: Duration,
    /// The time for the 354 reply to DATA (§4.5.3.2.4).
    pub data_initiation_timeout: Duration,
    /// The time for the reply to the end of the data (§4.5.3.2.6).
    pub data_termination_timeout: Duration,
    /// The time a server waits for the next command, or for more data (§4.5.3.2.5, §4.5.3.2.7).
    pub server_timeout: Duration,
    /// Whether a client sends a password as it is (AUTH PLAIN or LOGIN) only under TLS (RFC
    /// 2595 §2.3: a client MUST be configurable to refuse to); a server's is of its
    /// [`SMTPServerConfig`].
    pub passwords_require_tls: bool,
}

impl Default for SMTPConfig {
    fn default() -> SMTPConfig {
        SMTPConfig {
            maximum_command_line: 512,
            maximum_reply_line: 512,
            maximum_reply_lines: 1000,
            maximum_text_line: 1000,
            maximum_auth_line: 12288,
            maximum_buffered: 64 * 1024,
            greeting_timeout: Duration::from_secs(5 * 60),
            command_timeout: Duration::from_secs(5 * 60),
            data_initiation_timeout: Duration::from_secs(2 * 60),
            data_termination_timeout: Duration::from_secs(10 * 60),
            server_timeout: Duration::from_secs(5 * 60),
            passwords_require_tls: true,
        }
    }
}

impl SMTPConfig {
    /// Fails for values RFC 5321 does not let a conforming end have: lines
    /// shorter than its minimums, nothing buffered, a zero time.
    pub fn check(&self) -> Result<(), SMTPError> {
        let invalid = |reason| Err(SMTPError::State { reason });
        if self.maximum_command_line < 512 || self.maximum_reply_line < 512 || self.maximum_text_line < 1000 {
            return invalid("a line limit under the minimum of RFC 5321 §4.5.3.1");
        }
        if self.maximum_auth_line < self.maximum_command_line || self.maximum_reply_lines == 0 {
            return invalid("an AUTH line shorter than a command, or no reply lines");
        }
        if self.maximum_buffered < self.maximum_auth_line {
            return invalid("less buffered than one line");
        }
        let times = [
            self.greeting_timeout,
            self.command_timeout,
            self.data_initiation_timeout,
            self.data_termination_timeout,
            self.server_timeout,
        ];
        if times.iter().any(Duration::is_zero) {
            return invalid("a zero timeout");
        }
        Ok(())
    }
}

/// What an SMTP server offers and requires: the extensions it advertises
/// in its reply to EHLO (RFC 5321 §4.1.1.1), and its policies.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SMTPServerConfig {
    /// The domain (or address literal) the server names itself by, first in the greeting
    /// and the reply to EHLO (§4.2, §4.1.1.1).
    pub domain: String,
    /// The largest message taken, advertised by SIZE (RFC 1870); 0 for no limit, which is advertised as "SIZE 0".
    pub maximum_message_size: u64,
    /// The most recipients of a transaction (RFC 5321 §4.5.3.1.8: at least 100).
    pub maximum_recipients: usize,
    pub pipelining: bool,
    pub eight_bit_mime: bool,
    pub smtputf8: bool,
    pub chunking: bool,
    pub binary_mime: bool,
    pub dsn: bool,
    pub enhanced_status_codes: bool,
    /// Whether STARTTLS is offered (RFC 3207); never after TLS has begun.
    pub starttls: bool,
    /// The SASL mechanisms offered by AUTH (RFC 4954), by name.
    pub auth_mechanisms: Vec<String>,
    /// The mechanisms of those that send a password as it is besides PLAIN (RFC 4616 §1), which
    /// always is one: so a list left empty never offers PLAIN without TLS by mistake.
    pub plaintext_mechanisms: Vec<String>,
    /// Whether the plaintext mechanisms are offered only under TLS (RFC 4954 §4: a server MUST
    /// be able not to take plaintext passwords without it).
    pub passwords_require_tls: bool,
    /// Whether every command but NOOP, EHLO, STARTTLS and QUIT is refused before TLS, with
    /// 530 (RFC 3207 §4); not for a publicly referenced server.
    pub requires_tls: bool,
    /// Whether MAIL is refused before AUTH, with 530 (RFC 4954 §6, RFC 6409 §4.3).
    pub requires_auth: bool,
    /// The commands of extensions the user implements, by name: they are told; another command
    /// this crate does not know is answered as not recognized.
    pub commands: Vec<String>,
}

impl Default for SMTPServerConfig {
    fn default() -> SMTPServerConfig {
        SMTPServerConfig {
            domain: String::from("localhost"),
            maximum_message_size: 32 * 1024 * 1024,
            maximum_recipients: 100,
            pipelining: true,
            eight_bit_mime: true,
            smtputf8: true,
            chunking: true,
            binary_mime: false,
            dsn: false,
            enhanced_status_codes: true,
            starttls: false,
            auth_mechanisms: Vec::new(),
            plaintext_mechanisms: Vec::new(),
            passwords_require_tls: true,
            requires_tls: false,
            requires_auth: false,
            commands: Vec::new(),
        }
    }
}

impl SMTPServerConfig {
    /// Fails for a configuration RFC 5321 and its extensions do not let a
    /// server have: fewer than 100 recipients, SMTPUTF8 without 8BITMIME
    /// (RFC 6531 §3.1), BINARYMIME without CHUNKING (RFC 3030 §3), a
    /// mechanism name that is not one (RFC 4422 §3.1), a domain that is
    /// neither a domain nor an address literal.
    pub fn check(&self) -> Result<(), SMTPError> {
        let invalid = |reason| Err(SMTPError::State { reason });
        if self.maximum_recipients < 100 {
            return invalid("fewer than the 100 recipients of RFC 5321 §4.5.3.1.8");
        }
        if self.smtputf8 && !self.eight_bit_mime {
            return invalid("SMTPUTF8 without 8BITMIME");
        }
        if self.binary_mime && !self.chunking {
            return invalid("BINARYMIME without CHUNKING");
        }
        let name = |name: &String| {
            (1..=20).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_')
        };
        if !self.auth_mechanisms.iter().chain(&self.plaintext_mechanisms).all(name) {
            return invalid("not a SASL mechanism name");
        }
        if !super::SMTPMailbox::is_domain(self.domain.as_bytes())
            && !super::SMTPMailbox::is_address_literal(self.domain.as_bytes())
        {
            return invalid("not a domain or an address literal");
        }
        Ok(())
    }
}
