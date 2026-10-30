use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use super::FTPError;

/// The limits and times of an FTP control connection, of a client or a server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FTPConfig {
    /// The longest line, its CRLF counted.
    pub maximum_line: usize,
    /// The most lines of a reply.
    pub maximum_reply_lines: usize,
    /// The most octets of input held while the other end has not been answered.
    pub maximum_buffered: usize,
    /// The time a client waits for a reply (a transfer's final reply excepted).
    pub reply_timeout: Duration,
    /// The time a server waits for a command.
    pub idle_timeout: Duration,
}

impl Default for FTPConfig {
    fn default() -> FTPConfig {
        FTPConfig {
            maximum_line: 4096,
            maximum_reply_lines: 1000,
            maximum_buffered: 64 * 1024,
            reply_timeout: Duration::from_secs(5 * 60),
            idle_timeout: Duration::from_secs(15 * 60),
        }
    }
}

impl FTPConfig {
    pub fn check(&self) -> Result<(), FTPError> {
        let invalid = |reason| Err(FTPError::State { reason });
        if self.maximum_line < 512 || self.maximum_reply_lines == 0 || self.maximum_buffered < self.maximum_line {
            return invalid("a limit too small for a line");
        }
        if self.reply_timeout.is_zero() || self.idle_timeout.is_zero() {
            return invalid("a zero time");
        }
        Ok(())
    }
}

/// What an FTP server offers and requires: the features it lists in its
/// reply to FEAT (RFC 2389), and its policies.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FTPServerConfig {
    /// The text of the reply to SYST (RFC 959 §4.1.3): the system's type of the IANA list.
    pub system: String,
    /// Whether AUTH TLS is offered (RFC 4217); never under TLS.
    pub tls: bool,
    /// Whether USER and PASS are refused before TLS, with 530 (RFC 4217 §11).
    pub require_tls: bool,
    /// Whether transfers are refused without PROT P, with 521 (RFC 4217 §9).
    pub require_protection: bool,
    /// Whether CCC clears the command connection (RFC 4217 §6); it is refused with 533 otherwise.
    pub allow_ccc: bool,
    /// Whether PORT and EPRT may name a host other than the client, or a port under 1024
    /// (RFC 2577 §3: the FTP bounce attack); they are refused otherwise.
    pub allow_foreign_data: bool,
    /// The features of RFC 3659 the user implements: SIZE, MDTM, REST STREAM, MLST and MLSD.
    pub size: bool,
    pub mdtm: bool,
    pub rest_stream: bool,
    /// The facts listed by MLST (RFC 3659 §7.8), each with `*` if given by default; empty for no MLST.
    pub mlst_facts: Vec<String>,
    /// Whether pathnames are UTF-8 (RFC 2640 §3).
    pub utf8: bool,
    /// Whether HOST is taken (RFC 7151).
    pub host: bool,
    /// Other features listed as they are, of extensions the user implements.
    pub features: Vec<String>,
    /// The commands of extensions the user implements, by name: they are told; another command
    /// this crate does not know is answered as not recognized.
    pub commands: Vec<String>,
}

impl Default for FTPServerConfig {
    fn default() -> FTPServerConfig {
        FTPServerConfig {
            system: String::from("UNIX Type: L8"),
            tls: false,
            require_tls: false,
            require_protection: false,
            allow_ccc: false,
            allow_foreign_data: false,
            size: true,
            mdtm: true,
            rest_stream: true,
            mlst_facts: ["type*", "size*", "modify*", "perm", "unique"]
                .iter()
                .map(|fact| String::from(*fact))
                .collect(),
            utf8: true,
            host: false,
            features: Vec::new(),
            commands: Vec::new(),
        }
    }
}

impl FTPServerConfig {
    /// Fails for a text or a feature with a line break, TLS required but not offered.
    pub fn check(&self) -> Result<(), FTPError> {
        let invalid = |reason| Err(FTPError::State { reason });
        let line = |text: &String| !text.is_empty() && !text.bytes().any(|byte| byte.is_ascii_control());
        if !line(&self.system) || !self.features.iter().all(line) || !self.mlst_facts.iter().all(line) {
            return invalid("a text with a control character");
        }
        if (self.require_tls || self.require_protection) && !self.tls {
            return invalid("TLS required but not offered");
        }
        Ok(())
    }
}
