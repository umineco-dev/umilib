use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use super::{
    POP3Capabilities, POP3Capability, POP3Command, POP3Config, POP3Error, POP3MultiLineWriter, POP3Response,
    POP3ServerConfig, POP3State,
};
use crate::bytes::LineBuffer;
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::runtime::Instant;

/// What a [`POP3Server`] tells its user.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum POP3ServerEvent {
    /// A command to answer with [`POP3Server::reply`]; a positive response
    /// of a multi-line command is followed by [`POP3Server::send_data`] and
    /// [`POP3Server::end_data`]. Commands the server answers itself (CAPA,
    /// NOOP, QUIT before authorization, and those of another state or of
    /// a capability not offered) are not told. QUIT in the TRANSACTION state
    /// is told: remove the deleted messages (the UPDATE state, RFC 1939 §6).
    Command(POP3Command),
    /// A response of an AUTH exchange, decoded (RFC 5034 §4).
    AuthResponse(Vec<u8>),
    /// The client cancelled AUTH, and the server answered -ERR.
    AuthCancelled,
    /// The +OK to STLS was sent: start TLS now. What the client sent before it is discarded
    /// (RFC 2595 §4, CVE-2011-0411).
    StartTLS,
    /// The connection is to be closed: after QUIT, the autologout timer (RFC 1939 §3), an error.
    Closed { error: Option<POP3Error> },
    /// The AUTH exchange failed, and the server answered -ERR itself: a response that is not
    /// base64, or a line too long (RFC 5034 §4). Its SASL state is to be dropped.
    AuthFailed,
}

/// What a server waits for its user to answer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum POP3ServerPending {
    Command(POP3Command),
    AuthResponse,
}

/// A POP3 server without I/O (RFC 1939): feed it what the client sends
/// with [`POP3Server::receive`], send what [`POP3Server::transmit`] gives,
/// and answer its events. The maildrop is the user's: the server keeps the
/// session's state, announces the configured capabilities, and answers
/// what RFC 1939 and its extensions decide.
#[derive(Clone, Debug)]
pub struct POP3Server {
    pub config: POP3Config,
    pub server: POP3ServerConfig,
    pub input: LineBuffer,
    pub output: Vec<u8>,
    pub events: VecDeque<POP3ServerEvent>,
    pub state: POP3State,
    pub greeted: bool,
    pub closed: bool,
    pub pending: Option<POP3ServerPending>,
    /// An AUTH challenge was sent: the next line is its response.
    pub auth_response: bool,
    /// The multi-line response being sent.
    pub sending: Option<POP3MultiLineWriter>,
    /// The name of the accepted USER (RFC 1939 §7).
    pub user: Option<String>,
    /// The timestamp of the greeting, which offers APOP (RFC 1939 §7).
    pub timestamp: Option<Vec<u8>>,
    pub secure: bool,
    pub utf8: bool,
    pub deadline: Option<Instant>,
}

impl POP3Server {
    /// A server of a new connection; `secure` if it is TLS from its start
    /// (POP3S, RFC 8314 §3.3). Send the greeting with [`POP3Server::greet`].
    pub fn new(config: POP3Config, server: POP3ServerConfig, secure: bool) -> Result<POP3Server, POP3Error> {
        config.check()?;
        server.check()?;
        Ok(POP3Server {
            config,
            server,
            input: LineBuffer::new(),
            output: Vec::new(),
            events: VecDeque::new(),
            state: POP3State::Authorization,
            greeted: false,
            closed: false,
            pending: None,
            auth_response: false,
            sending: None,
            user: None,
            timestamp: None,
            secure,
            utf8: false,
            deadline: None,
        })
    }

    pub fn is_open(&self) -> bool {
        !self.closed
    }

    pub fn wants_receive(&self) -> bool {
        self.is_open() && self.input.len() < self.config.maximum_buffered
    }

    /// Sends the greeting: +OK, and a timestamp (`<id@host>`, RFC 1939 §7)
    /// in its text if APOP is offered; -ERR closes the connection.
    pub fn greet(&mut self, response: POP3Response, now: Instant) -> Result<(), POP3Error> {
        if self.greeted {
            return Err(POP3Error::State { reason: "the greeting was sent" });
        }
        response.check()?;
        self.greeted = true;
        self.timestamp = response.timestamp().map(<[u8]>::to_vec);
        response.encode(&mut self.output);
        if !response.ok {
            self.close(None);
            return Ok(());
        }
        self.process(now);
        Ok(())
    }

    /// Whether passwords sent as they are are taken now (RFC 5034 §4).
    pub fn passwords_taken(&self) -> bool {
        self.secure || !self.server.passwords_require_tls
    }

    /// The mechanisms SASL offers now: those configured, a plaintext one only when passwords
    /// are taken.
    pub fn mechanisms_offered(&self) -> Vec<&str> {
        let server = &self.server;
        let plaintext = |mechanism: &&String| {
            mechanism.eq_ignore_ascii_case("PLAIN")
                || server.plaintext_mechanisms.iter().any(|plain| plain.eq_ignore_ascii_case(mechanism))
        };
        server
            .sasl_mechanisms
            .iter()
            .filter(|mechanism| self.passwords_taken() || !plaintext(mechanism))
            .map(String::as_str)
            .collect()
    }

    /// The capabilities announced now (RFC 2449 §6, RFC 2595 §4, RFC 6856).
    pub fn capabilities(&self) -> POP3Capabilities {
        let server = &self.server;
        let mut entries = Vec::new();
        let mut add = |enabled: bool, tag: &str, parameters: &[&str]| {
            if enabled {
                entries.push(POP3Capability::new(tag, parameters));
            }
        };
        add(server.top, "TOP", &[]);
        add(server.user && self.passwords_taken(), "USER", &[]);
        let mechanisms = self.mechanisms_offered();
        add(!mechanisms.is_empty(), "SASL", &mechanisms);
        add(server.response_codes, "RESP-CODES", &[]);
        add(server.response_codes, "AUTH-RESP-CODE", &[]);
        add(server.pipelining, "PIPELINING", &[]);
        add(server.uidl, "UIDL", &[]);
        add(server.stls && !self.secure && !self.utf8 && self.state == POP3State::Authorization, "STLS", &[]);
        add(server.utf8, "UTF8", if server.utf8_user { &["USER"] } else { &[] });
        add(server.lang, "LANG", &[]);
        let delay = server.login_delay.map(|delay| alloc::format!("{delay}"));
        add(delay.is_some(), "LOGIN-DELAY", &[delay.as_deref().unwrap_or_default()]);
        add(server.expire.is_some(), "EXPIRE", &[server.expire.as_deref().unwrap_or_default()]);
        let implementation: Vec<&str> = server
            .implementation
            .as_deref()
            .map(|text| text.split(' ').filter(|word| !word.is_empty()).collect())
            .unwrap_or_default();
        add(!implementation.is_empty(), "IMPLEMENTATION", &implementation);
        POP3Capabilities { entries }
    }

    pub fn receive(&mut self, bytes: &[u8], now: Instant) {
        if self.closed {
            return;
        }
        self.input.push(bytes);
        self.process(now);
    }

    /// Reads the commands that can be read: while none waits for its answer.
    pub fn process(&mut self, now: Instant) {
        while self.greeted && !self.closed && self.pending.is_none() && self.sending.is_none() {
            let maximum =
                if self.auth_response { self.config.maximum_auth_line } else { self.config.maximum_command_line };
            let line = match self.input.line(maximum) {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(_) => {
                    if self.auth_response {
                        self.events.push_back(POP3ServerEvent::AuthFailed);
                    }
                    self.auth_response = false;
                    self.answer(false, &[], "Line too long");
                    continue;
                }
            };
            if self.auth_response {
                self.auth_response = false;
                self.read_auth_response(&line);
                continue;
            }
            match POP3Command::parse(&line, self.utf8 || self.server.utf8_user) {
                Ok(command) => self.dispatch(command),
                Err(_) => self.answer(false, &[], "Syntax error"),
            }
        }
        let waiting = self.greeted && !self.closed && self.pending.is_none() && self.sending.is_none();
        self.deadline = waiting.then(|| now.saturating_add(self.config.autologout));
    }

    /// Writes a status line the server makes itself, its code only where response codes are announced.
    pub fn answer(&mut self, ok: bool, code: &[&str], text: &str) {
        let code = if self.server.response_codes { code } else { &[] };
        let response = POP3Response {
            ok,
            code: code.iter().map(|level| String::from(*level)).collect(),
            text: text.as_bytes().to_vec(),
        };
        response.encode(&mut self.output);
    }

    /// Answers a command the server decides itself, or tells it.
    pub fn dispatch(&mut self, command: POP3Command) {
        let authorization = self.state == POP3State::Authorization;
        let server = &self.server;
        match &command {
            POP3Command::Capa => {
                self.answer(true, &[], "Capability list follows");
                let mut list = Vec::new();
                self.capabilities().encode(&mut list);
                let mut writer = POP3MultiLineWriter::new();
                writer.write(&list, &mut self.output);
                writer.finish(&mut self.output);
                return;
            }
            POP3Command::Quit if authorization => {
                self.answer(true, &[], "Bye");
                return self.close(None);
            }
            POP3Command::Noop if !authorization => return self.answer(true, &[], "OK"),
            POP3Command::Other { keyword, .. }
                if !server.commands.iter().any(|known| known.eq_ignore_ascii_case(keyword)) =>
            {
                return self.answer(false, &[], "Unknown command");
            }
            POP3Command::User(_)
            | POP3Command::Pass(_)
            | POP3Command::Apop { .. }
            | POP3Command::Auth { .. }
            | POP3Command::Stls
            | POP3Command::Utf8
                if !authorization =>
            {
                return self.answer(false, &[], "Not in the TRANSACTION state");
            }
            POP3Command::Stat
            | POP3Command::List(_)
            | POP3Command::Retr(_)
            | POP3Command::Dele(_)
            | POP3Command::Noop
            | POP3Command::Rset
            | POP3Command::Top { .. }
            | POP3Command::Uidl(_)
                if authorization =>
            {
                return self.answer(false, &[], "Not in the AUTHORIZATION state");
            }
            POP3Command::Top { .. } if !server.top => return self.answer(false, &[], "TOP not offered"),
            POP3Command::Uidl(_) if !server.uidl => return self.answer(false, &[], "UIDL not offered"),
            POP3Command::User(_) | POP3Command::Pass(_) if !server.user => {
                return self.answer(false, &[], "USER not offered");
            }
            POP3Command::User(_) | POP3Command::Pass(_) | POP3Command::Apop { .. } if !self.passwords_taken() => {
                return self.answer(false, &["AUTH"], "Plaintext authentication is not taken without TLS");
            }
            POP3Command::Pass(_) if self.user.is_none() => return self.answer(false, &[], "USER first"),
            POP3Command::Apop { .. } if self.timestamp.is_none() => return self.answer(false, &[], "APOP not offered"),
            POP3Command::Auth { mechanism, .. } => {
                if !server.sasl_mechanisms.iter().any(|offered| offered.eq_ignore_ascii_case(mechanism)) {
                    return self.answer(false, &[], "Unrecognized authentication type");
                }
                if !self.mechanisms_offered().iter().any(|offered| offered.eq_ignore_ascii_case(mechanism)) {
                    return self.answer(false, &["AUTH"], "Plaintext authentication is not taken without TLS");
                }
            }
            POP3Command::Stls if !server.stls || self.secure || self.utf8 => {
                return self.answer(false, &[], "STLS not taken");
            }
            POP3Command::Utf8 if !server.utf8 => return self.answer(false, &[], "UTF8 not offered"),
            POP3Command::Lang(_) if !server.lang => return self.answer(false, &[], "LANG not offered"),
            _ => {}
        }
        self.pending = Some(POP3ServerPending::Command(command.clone()));
        self.events.push_back(POP3ServerEvent::Command(command));
    }

    /// Reads a response of an AUTH exchange.
    pub fn read_auth_response(&mut self, line: &[u8]) {
        if line == b"*" {
            self.answer(false, &[], "Authentication cancelled");
            self.events.push_back(POP3ServerEvent::AuthCancelled);
            return;
        }
        match Base64::STANDARD.decode(line) {
            Ok(response) => {
                self.pending = Some(POP3ServerPending::AuthResponse);
                self.events.push_back(POP3ServerEvent::AuthResponse(response));
            }
            // RFC 5034 §4: a response that is not base64 fails AUTH.
            Err(_) => {
                self.answer(false, &[], "Cannot decode the response");
                self.events.push_back(POP3ServerEvent::AuthFailed);
            }
        }
    }

    /// Sends a challenge of the AUTH exchange told (RFC 5034 §4): `+` and the challenge in base64.
    pub fn auth_challenge(&mut self, challenge: &[u8], now: Instant) -> Result<(), POP3Error> {
        if !matches!(
            self.pending,
            Some(POP3ServerPending::Command(POP3Command::Auth { .. }) | POP3ServerPending::AuthResponse)
        ) {
            return Err(POP3Error::State { reason: "no AUTH exchange" });
        }
        self.output.extend_from_slice(b"+ ");
        self.output.extend_from_slice(Base64::STANDARD.encode(challenge).as_bytes());
        self.output.extend_from_slice(b"\r\n");
        self.pending = None;
        self.auth_response = true;
        self.process(now);
        Ok(())
    }

    /// Answers the command told. A positive response to a multi-line
    /// command is followed by its lines ([`POP3Server::send_data`],
    /// [`POP3Server::end_data`]). A response code is sent only where
    /// response codes are announced. +OK to USER keeps the name; to PASS,
    /// APOP or AUTH it begins the TRANSACTION state; to STLS it starts TLS;
    /// to UTF8 it begins UTF-8 mode; QUIT closes the connection.
    pub fn reply(&mut self, response: POP3Response, now: Instant) -> Result<(), POP3Error> {
        response.check()?;
        let Some(pending) = self.pending.take() else {
            return Err(POP3Error::State { reason: "no command to answer" });
        };
        let mut response = response;
        if !self.server.response_codes {
            response.code.clear();
        }
        response.encode(&mut self.output);
        let ok = response.ok;
        let command = match pending {
            POP3ServerPending::AuthResponse => POP3Command::Auth { mechanism: String::new(), initial: None },
            POP3ServerPending::Command(command) => command,
        };
        match &command {
            POP3Command::User(name) => self.user = ok.then(|| name.clone()),
            POP3Command::Pass(_) | POP3Command::Apop { .. } | POP3Command::Auth { .. } => {
                self.user = None;
                if ok {
                    self.state = POP3State::Transaction;
                }
            }
            POP3Command::Stls if ok => {
                self.input.clear();
                self.user = None;
                self.secure = true;
                self.events.push_back(POP3ServerEvent::StartTLS);
            }
            POP3Command::Utf8 if ok => self.utf8 = true,
            POP3Command::Quit => {
                self.state = POP3State::Update;
                self.close(None);
                return Ok(());
            }
            _ => {}
        }
        if ok && command.is_multi_line() {
            self.sending = Some(POP3MultiLineWriter::new());
            return Ok(());
        }
        self.process(now);
        Ok(())
    }

    /// Sends lines of the multi-line response being sent: line breaks as CRLF, and a period
    /// before each line beginning with one (RFC 1939 §3).
    pub fn send_data(&mut self, data: &[u8]) -> Result<(), POP3Error> {
        let Some(writer) = &mut self.sending else {
            return Err(POP3Error::State { reason: "no multi-line response" });
        };
        writer.write(data, &mut self.output);
        Ok(())
    }

    /// Ends the multi-line response being sent.
    pub fn end_data(&mut self, now: Instant) -> Result<(), POP3Error> {
        let Some(mut writer) = self.sending.take() else {
            return Err(POP3Error::State { reason: "no multi-line response" });
        };
        writer.finish(&mut self.output);
        self.process(now);
        Ok(())
    }

    pub fn transmit(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.output);
    }

    pub fn poll_event(&mut self) -> Option<POP3ServerEvent> {
        self.events.pop_front()
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        self.deadline
    }

    /// Closes the connection, without a response and without the UPDATE state, if the client was
    /// silent past the autologout timer (RFC 1939 §3).
    pub fn expire(&mut self, now: Instant) {
        if self.deadline.is_some_and(|deadline| deadline <= now) {
            self.close(Some(POP3Error::Timeout));
        }
    }

    pub fn close(&mut self, error: Option<POP3Error>) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.pending = None;
        self.sending = None;
        self.deadline = None;
        self.events.push_back(POP3ServerEvent::Closed { error });
    }
}
