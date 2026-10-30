use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::{POP3Capabilities, POP3Command, POP3Config, POP3Error, POP3MultiLineReader, POP3Response};
use crate::bytes::LineBuffer;
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::runtime::Instant;

/// The state of a POP3 session (RFC 1939 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum POP3State {
    Authorization,
    Transaction,
    /// After QUIT in the TRANSACTION state: the server removes the deleted messages.
    Update,
}

/// What a [`POP3Client`] tells its user.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum POP3ClientEvent {
    Greeting(POP3Response),
    /// The response to a command: its status line. A positive one of a
    /// multi-line command is followed by [`POP3ClientEvent::Data`] and
    /// [`POP3ClientEvent::DataEnd`].
    Response {
        command: POP3Command,
        response: POP3Response,
    },
    /// Lines of a multi-line response, its added periods removed.
    Data(Vec<u8>),
    DataEnd,
    /// A challenge of an AUTH exchange, decoded (RFC 5034 §4): answer it with
    /// [`POP3Client::auth_respond`] or [`POP3Client::auth_cancel`].
    AuthChallenge(Vec<u8>),
    /// The server is ready for TLS (RFC 2595 §4): start it before anything else; the
    /// capabilities are forgotten, and CAPA SHOULD be sent again.
    StartTLS,
    Closed {
        error: Option<POP3Error>,
    },
}

/// A POP3 client without I/O (RFC 1939): feed it what the server sends
/// with [`POP3Client::receive`], send what [`POP3Client::transmit`] gives,
/// and answer its events. Commands are sent in order, pipelined when the
/// server announces PIPELINING (RFC 2449 §6.6); STLS and AUTH only when
/// announced (RFC 2595, RFC 5034), each in its state.
#[derive(Clone, Debug)]
pub struct POP3Client {
    pub config: POP3Config,
    pub input: LineBuffer,
    pub output: Vec<u8>,
    pub events: VecDeque<POP3ClientEvent>,
    pub queued: VecDeque<POP3Command>,
    /// The commands sent, waiting for their responses, with the time they wait until.
    pub sent: VecDeque<(POP3Command, Instant)>,
    pub state: POP3State,
    pub greeting: Option<POP3Response>,
    pub greeting_deadline: Option<Instant>,
    /// The capabilities of the last CAPA; `None` before it, or after TLS began.
    pub capabilities: Option<POP3Capabilities>,
    /// The multi-line response being read, and, for CAPA, its lines so far.
    pub reading: Option<(POP3MultiLineReader, Option<Vec<u8>>)>,
    /// When the multi-line response being read is late: its time from its last octets.
    pub reading_deadline: Option<Instant>,
    /// An AUTH challenge waits for its response.
    pub authenticating: bool,
    /// The initial response of an AUTH too long for its line, sent for the first empty challenge.
    pub held_response: Option<Vec<u8>>,
    /// USER was accepted: PASS is next (RFC 1939 §7).
    pub user_accepted: bool,
    /// UTF-8 mode is on (RFC 6856 §2.1): STLS is not sent after it.
    pub utf8: bool,
    pub secure: bool,
    pub closed: bool,
}

impl POP3Client {
    /// A client of a new connection, waiting for the greeting; `secure` if
    /// the connection is TLS from its start (POP3S, RFC 8314 §3.3).
    pub fn new(config: POP3Config, secure: bool, now: Instant) -> Result<POP3Client, POP3Error> {
        config.check()?;
        Ok(POP3Client {
            config,
            input: LineBuffer::new(),
            output: Vec::new(),
            events: VecDeque::new(),
            queued: VecDeque::new(),
            sent: VecDeque::new(),
            state: POP3State::Authorization,
            greeting: None,
            greeting_deadline: Some(now.saturating_add(config.response_timeout)),
            capabilities: None,
            reading: None,
            reading_deadline: None,
            authenticating: false,
            held_response: None,
            user_accepted: false,
            utf8: false,
            secure,
            closed: false,
        })
    }

    pub fn is_open(&self) -> bool {
        !self.closed
    }

    pub fn has_capability(&self, tag: &str) -> bool {
        self.capabilities.as_ref().is_some_and(|capabilities| capabilities.has(tag))
    }

    /// Takes what the server sent.
    pub fn receive(&mut self, bytes: &[u8], now: Instant) -> Result<(), POP3Error> {
        if self.closed {
            return Err(POP3Error::Closed);
        }
        self.input.push(bytes);
        loop {
            if let Some((reader, list)) = &mut self.reading {
                let mut data = Vec::new();
                let read = reader.read(self.input.unread(), &mut data);
                self.input.consume(read);
                let end = reader.is_end();
                let listed = list.as_mut().map(|list| {
                    list.extend_from_slice(&data);
                    list.len()
                });
                let maximum = self.config.maximum_capabilities;
                if let Some(length) = listed.filter(|length| *length > maximum) {
                    return self.fail(POP3Error::TooLong { length, maximum });
                }
                if read > 0 {
                    self.reading_deadline = Some(now.saturating_add(self.config.response_timeout));
                }
                if !data.is_empty() {
                    self.events.push_back(POP3ClientEvent::Data(data));
                }
                if !end {
                    break;
                }
                if let Some((_, Some(list))) = self.reading.take() {
                    self.capabilities = Some(POP3Capabilities::parse(&list));
                }
                self.reading_deadline = None;
                // The next response is timed from the end of this one.
                if let Some((_, deadline)) = self.sent.front_mut() {
                    *deadline = now.saturating_add(self.config.response_timeout);
                }
                self.events.push_back(POP3ClientEvent::DataEnd);
                continue;
            }
            let maximum = if self.authenticating || self.waiting_auth() {
                self.config.maximum_auth_line
            } else {
                self.config.maximum_response_line
            };
            let line = match self.input.line(maximum) {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(_) => return self.fail(POP3Error::TooLong { length: maximum + 1, maximum }),
            };
            let tls = self.handle(&line, now)?;
            if tls || self.closed {
                // RFC 2595 §4 and CVE-2011-0411: what the server sent before TLS is not believed after it.
                self.input.clear();
                break;
            }
        }
        if self.input.len() > self.config.maximum_buffered {
            return self.fail(POP3Error::TooLong { length: self.input.len(), maximum: self.config.maximum_buffered });
        }
        self.pump(now);
        Ok(())
    }

    /// Whether the oldest command waiting is AUTH, whose challenges may be long.
    pub fn waiting_auth(&self) -> bool {
        matches!(self.sent.front(), Some((POP3Command::Auth { .. }, _)))
    }

    /// Handles a line of the server; whether TLS is to start.
    pub fn handle(&mut self, line: &[u8], now: Instant) -> Result<bool, POP3Error> {
        if self.greeting.is_none() {
            let response = match POP3Response::parse(line) {
                Ok(response) => response,
                Err(error) => return self.fail(error),
            };
            self.greeting = Some(response.clone());
            self.greeting_deadline = None;
            let ok = response.ok;
            self.events.push_back(POP3ClientEvent::Greeting(response));
            if !ok {
                self.close(None);
            }
            return Ok(false);
        }
        if self.waiting_auth() && (line == b"+" || line.starts_with(b"+ ")) {
            let challenge = line.get(2..).unwrap_or_default();
            let Ok(challenge) = Base64::STANDARD.decode(challenge) else {
                // RFC 5034 §4: a challenge that is not base64 MUST be cancelled.
                self.output.extend_from_slice(b"*\r\n");
                return Ok(false);
            };
            if let Some((_, deadline)) = self.sent.front_mut() {
                *deadline = now.saturating_add(self.config.response_timeout);
            }
            match self.held_response.take() {
                Some(response) if challenge.is_empty() => self.write_response(&response),
                _ => {
                    self.authenticating = true;
                    self.events.push_back(POP3ClientEvent::AuthChallenge(challenge));
                }
            }
            return Ok(false);
        }
        let Some((command, _)) = self.sent.pop_front() else {
            return self.fail(POP3Error::Syntax { reason: "a response to no command" });
        };
        // RFC 1939 §3: each response is timed from the one before it, not from when it was sent.
        if let Some((_, deadline)) = self.sent.front_mut() {
            *deadline = now.saturating_add(self.config.response_timeout);
        }
        let response = match POP3Response::parse(line) {
            Ok(response) => response,
            Err(error) => return self.fail(error),
        };
        let ok = response.ok;
        let mut tls = false;
        match &command {
            POP3Command::User(_) => self.user_accepted = ok,
            POP3Command::Pass(_) | POP3Command::Apop { .. } | POP3Command::Auth { .. } => {
                self.user_accepted = false;
                self.authenticating = false;
                self.held_response = None;
                if ok {
                    self.state = POP3State::Transaction;
                }
            }
            POP3Command::Stls if ok => {
                tls = true;
                self.secure = true;
                self.capabilities = None;
                // RFC 2595 §4: what was known before TLS is forgotten, an accepted USER too.
                self.user_accepted = false;
            }
            POP3Command::Utf8 if ok => self.utf8 = true,
            POP3Command::Quit if self.state == POP3State::Transaction => self.state = POP3State::Update,
            _ => {}
        }
        if ok && command.is_multi_line() {
            let list = matches!(command, POP3Command::Capa).then(Vec::new);
            self.reading = Some((POP3MultiLineReader::new(), list));
            self.reading_deadline = Some(now.saturating_add(self.config.response_timeout));
        }
        let quit = matches!(command, POP3Command::Quit);
        self.events.push_back(POP3ClientEvent::Response { command, response });
        if tls {
            self.events.push_back(POP3ClientEvent::StartTLS);
        }
        if quit {
            self.close(None);
        }
        Ok(tls)
    }

    /// Queues `command`, to be sent in order. Fails, sending nothing, for a
    /// command not of the state (RFC 1939 §3), PASS not after an accepted
    /// USER (§7), STLS not announced, under TLS or after UTF8 (RFC 2595 §4,
    /// RFC 6856 §2.1), AUTH and its mechanism not announced, or after
    /// authentication (RFC 5034 §4), UTF8 and LANG not announced (RFC 6856).
    pub fn send(&mut self, command: POP3Command, now: Instant) -> Result<(), POP3Error> {
        command.check()?;
        self.check(&command)?;
        let command = match command {
            // RFC 5034 §4: an initial response that makes the line too long waits for the empty challenge.
            POP3Command::Auth { mechanism, initial: Some(initial) }
                if mechanism.len()
                    + Base64::STANDARD.maximum_encoded_length(initial.len()).unwrap_or(usize::MAX)
                    + 8
                    > self.config.maximum_command_line =>
            {
                self.held_response = Some(initial);
                POP3Command::Auth { mechanism, initial: None }
            }
            command => command,
        };
        self.queued.push_back(command);
        self.pump(now);
        Ok(())
    }

    /// Checks that `command` may be queued now.
    pub fn check(&self, command: &POP3Command) -> Result<(), POP3Error> {
        let state = |reason| Err(POP3Error::State { reason });
        if self.closed {
            return Err(POP3Error::Closed);
        }
        if self.greeting.is_none() {
            return state("no greeting yet");
        }
        if self.authenticating {
            return state("an AUTH challenge waits for its response");
        }
        let waiting = |keyword: &str| {
            self.queued
                .iter()
                .chain(self.sent.iter().map(|(command, _)| command))
                .any(|command| command.keyword() == keyword)
        };
        if waiting("STLS") || waiting("AUTH") || waiting("PASS") || waiting("APOP") || waiting("QUIT") {
            // Their responses change the state the next command is checked in.
            return state("a command that changes the state waits for its response");
        }
        let authorization = self.state == POP3State::Authorization;
        let capability = |tag: &str| self.has_capability(tag) && !waiting("CAPA");
        let plaintext = match command {
            POP3Command::User(_) | POP3Command::Pass(_) | POP3Command::Apop { .. } => true,
            POP3Command::Auth { mechanism, .. } => {
                ["PLAIN", "LOGIN"].iter().any(|plain| plain.eq_ignore_ascii_case(mechanism))
            }
            _ => false,
        };
        if plaintext && self.config.passwords_require_tls && !self.secure {
            return state("a password as it is without TLS (RFC 2595 §2.3)");
        }
        match command {
            POP3Command::User(_) | POP3Command::Apop { .. } | POP3Command::Utf8 if !authorization => {
                state("only in the AUTHORIZATION state")
            }
            POP3Command::Pass(_) if !authorization || !self.user_accepted => state("PASS only after an accepted USER"),
            POP3Command::Stls if !authorization || self.secure || self.utf8 => {
                state("STLS only before TLS and UTF8, while authorizing")
            }
            POP3Command::Stls if !capability("STLS") => state("STLS not announced"),
            POP3Command::Auth { mechanism, .. } => {
                let announced = self.capabilities.as_ref().is_some_and(|capabilities| {
                    capabilities.sasl_mechanisms().iter().any(|name| name.eq_ignore_ascii_case(mechanism))
                });
                if !authorization {
                    return state("AUTH only in the AUTHORIZATION state");
                }
                if !announced || waiting("CAPA") {
                    return state("SASL or its mechanism not announced");
                }
                Ok(())
            }
            POP3Command::Utf8 if !capability("UTF8") => state("UTF8 not announced"),
            POP3Command::Lang(_) if !capability("LANG") => state("LANG not announced"),
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
                state("only in the TRANSACTION state")
            }
            _ => Ok(()),
        }
    }

    /// Answers an AUTH challenge with `response` (RFC 5034 §4).
    pub fn auth_respond(&mut self, response: &[u8], now: Instant) -> Result<(), POP3Error> {
        if !self.authenticating {
            return Err(POP3Error::State { reason: "no AUTH challenge" });
        }
        self.authenticating = false;
        self.write_response(response);
        self.pump(now);
        Ok(())
    }

    /// Cancels an AUTH exchange with `*`, which the server rejects (RFC 5034 §4).
    pub fn auth_cancel(&mut self, now: Instant) -> Result<(), POP3Error> {
        if !self.authenticating {
            return Err(POP3Error::State { reason: "no AUTH challenge" });
        }
        self.authenticating = false;
        self.output.extend_from_slice(b"*\r\n");
        self.pump(now);
        Ok(())
    }

    pub fn write_response(&mut self, response: &[u8]) {
        self.output.extend_from_slice(Base64::STANDARD.encode(response).as_bytes());
        self.output.extend_from_slice(b"\r\n");
    }

    /// Sends what may be sent: one command at a time, or, with PIPELINING,
    /// every command but after one whose response changes the state (STLS,
    /// AUTH, USER, PASS, APOP, UTF8, QUIT).
    pub fn pump(&mut self, now: Instant) {
        let pipelining = self.has_capability("PIPELINING");
        while let Some(command) = self.queued.front() {
            let blocked = match self.sent.back() {
                None => false,
                Some((last, _)) => {
                    let changes = matches!(
                        last,
                        POP3Command::Stls
                            | POP3Command::Auth { .. }
                            | POP3Command::User(_)
                            | POP3Command::Pass(_)
                            | POP3Command::Apop { .. }
                            | POP3Command::Utf8
                            | POP3Command::Quit
                            | POP3Command::Capa
                    );
                    !pipelining || changes
                }
            };
            if self.closed || self.greeting.is_none() || self.authenticating || blocked {
                break;
            }
            command.encode(&mut self.output);
            let Some(command) = self.queued.pop_front() else { break };
            self.sent.push_back((command, now.saturating_add(self.config.response_timeout)));
        }
    }

    pub fn transmit(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.output);
    }

    pub fn poll_event(&mut self) -> Option<POP3ClientEvent> {
        self.events.pop_front()
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.closed {
            return None;
        }
        // While a multi-line response is read, its progress is what is timed.
        let waiting = match self.reading {
            Some(_) => self.reading_deadline,
            None => self.sent.front().map(|(_, deadline)| *deadline),
        };
        self.greeting_deadline.into_iter().chain(waiting).min()
    }

    pub fn expire(&mut self, now: Instant) {
        if self.poll_timeout().is_some_and(|deadline| deadline <= now) {
            self.close(Some(POP3Error::Timeout));
        }
    }

    pub fn close(&mut self, error: Option<POP3Error>) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.queued.clear();
        self.sent.clear();
        self.reading = None;
        self.reading_deadline = None;
        self.authenticating = false;
        self.events.push_back(POP3ClientEvent::Closed { error });
    }

    pub fn fail<T>(&mut self, error: POP3Error) -> Result<T, POP3Error> {
        self.close(Some(error));
        Err(error)
    }
}
