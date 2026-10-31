use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use super::{
    IMAPCommand, IMAPCommandBody, IMAPCondition, IMAPConfig, IMAPError, IMAPLineEvent, IMAPLineReader, IMAPLiteralMode,
    IMAPResponse, IMAPResponseCode, IMAPServerConfig, IMAPState, IMAPWriter,
};
use crate::bytes::LineBuffer;
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::runtime::Instant;

/// What an [`IMAPServer`] tells its user.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPServerEvent {
    /// A command: send its untagged responses with [`IMAPServer::respond`] and end it with
    /// [`IMAPServer::complete`]. Commands the server answers itself (CAPABILITY, LOGOUT, ENABLE,
    /// those of another state, LOGIN without TLS where it needs it, AUTHENTICATE of a
    /// mechanism not offered, those of no extension configured) are not told.
    Command(IMAPCommand),
    /// A response of AUTHENTICATE, decoded: answer it with another challenge or the completion.
    AuthenticateResponse { tag: String, data: Vec<u8> },
    /// The client cancelled AUTHENTICATE with `*`, and the server answered BAD (RFC 9051 §6.2.2).
    AuthenticateCancelled { tag: String },
    /// DONE ended IDLE (RFC 9051 §6.3.13): complete it.
    IdleDone { tag: String },
    /// The OK to STARTTLS was sent: start TLS now. What the client sent before it is discarded,
    /// and the capabilities may differ after it (RFC 9051 §6.2.1).
    StartTLS,
    /// The connection is to be closed: after LOGOUT, BYE, the autologout timer, an error.
    Closed { error: Option<IMAPError> },
}

/// What a server is in the middle of.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPServerPhase {
    Greeting,
    Commands,
    /// A challenge of AUTHENTICATE was sent: the next line is its response.
    AuthenticateResponse,
    /// IDLE was accepted: the next line is DONE.
    Idle,
    Closed,
}

/// An IMAP4rev2 server without I/O (RFC 9051), of IMAP4rev1 too (RFC
/// 3501): feed it what the client sends with [`IMAPServer::receive`],
/// send what [`IMAPServer::transmit`] gives, and answer its events. The
/// mailboxes are the user's: the server keeps the session's state and
/// literals, and answers what the protocol decides. Commands are told one
/// at a time, in order.
#[derive(Clone, Debug)]
pub struct IMAPServer {
    pub config: IMAPConfig,
    pub server: IMAPServerConfig,
    pub input: LineBuffer,
    pub reader: IMAPLineReader,
    pub output: Vec<u8>,
    pub events: VecDeque<IMAPServerEvent>,
    pub phase: IMAPServerPhase,
    pub state: IMAPState,
    /// The command told and not yet completed.
    pub pending: Option<IMAPCommand>,
    /// IMAP4rev2 is in use: offered alone, or enabled (RFC 9051 Appendix E).
    pub rev2: bool,
    pub secure: bool,
    pub deadline: Option<Instant>,
}

impl IMAPServer {
    /// The continuation request of a synchronizing literal.
    pub const LITERAL_READY: &'static [u8] = b"+ Ready for literal data\r\n";

    /// A server of a new connection; `secure` if it is TLS from its start (RFC 9051 §2.1, RFC
    /// 8314). Send the greeting with [`IMAPServer::greet`].
    pub fn new(config: IMAPConfig, server: IMAPServerConfig, secure: bool) -> Result<IMAPServer, IMAPError> {
        config.check()?;
        server.check()?;
        let rev2 = !server.rev1;
        Ok(IMAPServer {
            config,
            server,
            input: LineBuffer::new(),
            reader: IMAPLineReader::new(),
            output: Vec::new(),
            events: VecDeque::new(),
            phase: IMAPServerPhase::Greeting,
            state: IMAPState::NotAuthenticated,
            pending: None,
            rev2,
            secure,
            deadline: None,
        })
    }

    pub fn is_open(&self) -> bool {
        self.phase != IMAPServerPhase::Closed
    }

    pub fn wants_receive(&self) -> bool {
        self.is_open() && self.input.len() < self.config.maximum_buffered
    }

    /// Whether passwords sent as they are are taken now (RFC 9051 §6.2.3).
    pub fn passwords_taken(&self) -> bool {
        self.secure || !self.server.passwords_require_tls
    }

    /// The mechanisms AUTHENTICATE offers now: those configured, a plaintext one only when
    /// passwords are taken.
    pub fn mechanisms_offered(&self) -> Vec<&str> {
        let server = &self.server;
        let plaintext = |mechanism: &&String| {
            mechanism.eq_ignore_ascii_case("PLAIN")
                || server.plaintext_mechanisms.iter().any(|plain| plain.eq_ignore_ascii_case(mechanism))
        };
        server
            .auth_mechanisms
            .iter()
            .filter(|mechanism| self.passwords_taken() || !plaintext(mechanism))
            .map(String::as_str)
            .collect()
    }

    /// The capabilities announced now (RFC 9051 §6.1.1, §7.2.2): IMAP4rev1 if offered, IMAP4rev2,
    /// STARTTLS before TLS, LOGINDISABLED where LOGIN is not taken, the AUTH= of the
    /// mechanisms offered (before authentication), LITERAL+ if taken, and the configured ones.
    pub fn capabilities(&self) -> Vec<String> {
        let mut capabilities = Vec::new();
        if self.server.rev1 {
            capabilities.push(String::from("IMAP4rev1"));
        }
        capabilities.push(String::from("IMAP4rev2"));
        if self.state == IMAPState::NotAuthenticated {
            if self.server.starttls && !self.secure {
                capabilities.push(String::from("STARTTLS"));
            }
            if !self.passwords_taken() {
                capabilities.push(String::from("LOGINDISABLED"));
            }
            capabilities.extend(self.mechanisms_offered().iter().map(|mechanism| alloc::format!("AUTH={mechanism}")));
            if self.server.rev1 {
                // RFC 4959: part of IMAP4rev2, announced for clients of IMAP4rev1.
                capabilities.push(String::from("SASL-IR"));
            }
        }
        if self.server.rev1 {
            capabilities.push(String::from("ENABLE"));
        }
        capabilities.push(String::from(if self.server.literal_plus { "LITERAL+" } else { "LITERAL-" }));
        capabilities.extend(self.server.capabilities.iter().cloned());
        capabilities
    }

    /// Sends the greeting (RFC 9051 §7.1): OK, PREAUTH (the client is authenticated), or BYE (the
    /// connection is refused); with the capabilities if no code is given.
    pub fn greet(&mut self, condition: IMAPCondition, text: &str, now: Instant) -> Result<(), IMAPError> {
        if self.phase != IMAPServerPhase::Greeting {
            return Err(IMAPError::State { reason: "the greeting was sent" });
        }
        if !matches!(condition, IMAPCondition::OK | IMAPCondition::PREAUTH | IMAPCondition::BYE) {
            return Err(IMAPError::State { reason: "a greeting is OK, PREAUTH or BYE" });
        }
        if condition == IMAPCondition::PREAUTH {
            self.state = IMAPState::Authenticated;
        }
        let code = (condition != IMAPCondition::BYE).then(|| IMAPResponseCode::Capability(self.capabilities()));
        let response = IMAPResponse::untagged(condition, code, text);
        response.check()?;
        self.write(&response);
        if condition == IMAPCondition::BYE {
            self.close(None);
            return Ok(());
        }
        self.phase = IMAPServerPhase::Commands;
        self.process(now);
        Ok(())
    }

    /// Writes a response.
    /// Writes a response. A status response of no text is given the name of its condition as
    /// text for a client of IMAP4rev1, whose grammar requires text (RFC 3501 §9 `text`; RFC 9051
    /// §9 lets it be absent).
    pub fn write(&mut self, response: &IMAPResponse) {
        let mut writer = IMAPWriter::new(IMAPLiteralMode::Server, self.rev2);
        match response {
            IMAPResponse::Status { tag, condition, code, text } if text.is_empty() && !self.rev2 => {
                let named = IMAPResponse::Status {
                    tag: tag.clone(),
                    condition: *condition,
                    code: code.clone(),
                    text: String::from(condition.name()),
                };
                named.write(&mut writer);
            }
            response => response.write(&mut writer),
        }
        self.output.append(&mut writer.out);
    }

    /// Writes a tagged response the server makes itself.
    pub fn answer(&mut self, tag: &str, condition: IMAPCondition, code: Option<IMAPResponseCode>, text: &str) {
        self.write(&IMAPResponse::tagged(tag, condition, code, text));
    }

    pub fn receive(&mut self, bytes: &[u8], now: Instant) {
        if !self.is_open() {
            return;
        }
        self.input.push(bytes);
        self.process(now);
    }

    /// Reads what can be read: commands while none waits for its completion.
    pub fn process(&mut self, now: Instant) {
        loop {
            let reading = match self.phase {
                IMAPServerPhase::Commands => self.pending.is_none(),
                IMAPServerPhase::AuthenticateResponse | IMAPServerPhase::Idle => true,
                IMAPServerPhase::Greeting | IMAPServerPhase::Closed => false,
            };
            if !reading {
                break;
            }
            let event = match self.reader.next(&mut self.input, &self.config) {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(IMAPError::TooLong { length, .. }) if self.reader.literal > 0 => {
                    self.refuse_literal(length);
                    continue;
                }
                // The rest of a line too long was skipped, so whether a literal follows is not
                // known: the session ends, as RFC 7888 §4 lets a server end it, rather than take
                // a literal's octets as commands.
                Err(_) if self.reader.lost => {
                    self.reader.reset();
                    self.write(&IMAPResponse::untagged(IMAPCondition::BYE, None, "Command line too long"));
                    self.close(Some(IMAPError::TooLong {
                        length: self.config.maximum_line as u64 + 1,
                        maximum: self.config.maximum_line as u64,
                    }));
                    break;
                }
                Err(_) => {
                    match IMAPCommand::tag_of(&self.reader.current) {
                        Some(tag) => self.answer(&tag, IMAPCondition::BAD, None, "Command too long"),
                        None => self.write(&IMAPResponse::untagged(IMAPCondition::BAD, None, "Command too long")),
                    }
                    self.reader.reset();
                    continue;
                }
            };
            match event {
                IMAPLineEvent::Literal { length, synchronizing } => {
                    // RFC 7888 §5 (LITERAL-, part of IMAP4rev2): non-synchronizing literals of at most 4096 octets.
                    if !synchronizing && !self.server.literal_plus && length > 4096 {
                        self.refuse_literal(length);
                    } else if synchronizing {
                        self.output.extend_from_slice(IMAPServer::LITERAL_READY);
                    }
                }
                IMAPLineEvent::Discarded => {}
                IMAPLineEvent::Line(line) => self.read_line(line),
            }
        }
        // The client is waited for between commands and for a response of AUTHENTICATE, whose
        // command stays pending meanwhile (RFC 9051 §5.4).
        let waiting = (self.phase == IMAPServerPhase::Commands && self.pending.is_none())
            || self.phase == IMAPServerPhase::AuthenticateResponse;
        let time = match self.state {
            IMAPState::NotAuthenticated => self.config.login_timeout,
            _ => self.config.autologout,
        };
        self.deadline = (waiting || self.phase == IMAPServerPhase::Idle).then(|| now.saturating_add(time));
    }

    /// Refuses a literal larger than is taken: a synchronizing one with NO before its octets
    /// (the client sends neither them nor the rest of the command), a non-synchronizing one with
    /// BAD after them (RFC 7888 §4).
    pub fn refuse_literal(&mut self, length: u64) {
        let tag = IMAPCommand::tag_of(&self.reader.current).unwrap_or_else(|| String::from("*"));
        let synchronizing =
            IMAPLineReader::literal_of(&self.reader.current[..self.reader.current.len().saturating_sub(2)])
                .is_none_or(|(_, synchronizing)| synchronizing);
        // RFC 7888 §5: the BAD to an APPEND of a literal too large has TOOBIG (RFC 9051 §7.1).
        let append = self
            .reader
            .current
            .split(|byte| *byte == b' ')
            .nth(1)
            .is_some_and(|verb| verb.eq_ignore_ascii_case(b"APPEND"));
        let name = if append { "TOOBIG" } else { "LIMIT" };
        let code = Some(IMAPResponseCode::Other { name: String::from(name), text: None });
        let text = alloc::format!("A literal of {length} octets is not taken");
        match synchronizing {
            true => {
                self.reader.refuse_literal();
                self.answer(&tag, IMAPCondition::NO, code, &text);
            }
            false => {
                self.reader.discard_literal();
                self.answer(&tag, IMAPCondition::BAD, code, &text);
            }
        }
    }

    /// Handles a whole line: a command, a response of AUTHENTICATE, or DONE.
    pub fn read_line(&mut self, line: Vec<u8>) {
        match self.phase {
            IMAPServerPhase::AuthenticateResponse => {
                self.phase = IMAPServerPhase::Commands;
                let tag = self.pending.as_ref().map(|command| command.tag.clone()).unwrap_or_default();
                if line == b"*" {
                    self.pending = None;
                    self.answer(&tag, IMAPCondition::BAD, None, "AUTHENTICATE cancelled");
                    self.events.push_back(IMAPServerEvent::AuthenticateCancelled { tag });
                    return;
                }
                match Base64::STANDARD.decode(&line) {
                    Ok(data) => self.events.push_back(IMAPServerEvent::AuthenticateResponse { tag, data }),
                    Err(_) => {
                        self.pending = None;
                        self.answer(&tag, IMAPCondition::BAD, None, "Cannot decode the response");
                    }
                }
            }
            IMAPServerPhase::Idle => {
                let tag = self.pending.as_ref().map(|command| command.tag.clone()).unwrap_or_default();
                match line.eq_ignore_ascii_case(b"DONE") {
                    true => {
                        self.phase = IMAPServerPhase::Commands;
                        self.events.push_back(IMAPServerEvent::IdleDone { tag });
                    }
                    false => self.write(&IMAPResponse::untagged(IMAPCondition::BAD, None, "Expected DONE")),
                }
            }
            _ => match IMAPCommand::parse(&line, self.rev2, self.config.maximum_depth) {
                Ok(command) => self.dispatch(command),
                Err(_) => match IMAPCommand::tag_of(&line) {
                    Some(tag) => self.answer(&tag, IMAPCondition::BAD, None, "Syntax error"),
                    None => self.write(&IMAPResponse::untagged(IMAPCondition::BAD, None, "Syntax error")),
                },
            },
        }
    }

    /// Answers a command the server decides itself, or tells it.
    pub fn dispatch(&mut self, command: IMAPCommand) {
        let tag = command.tag.clone();
        if !command.body.is_valid_in(self.state) {
            return self.answer(&tag, IMAPCondition::BAD, None, "Command not valid in this state");
        }
        // Commands of IMAP4rev1 alone are not of IMAP4rev2 (RFC 9051 Appendix E).
        let rev1_only = matches!(command.body, IMAPCommandBody::Lsub { .. } | IMAPCommandBody::Check);
        if rev1_only && self.rev2 {
            return self.answer(&tag, IMAPCondition::BAD, None, "Not a command of IMAP4rev2");
        }
        match &command.body {
            IMAPCommandBody::Other { name, .. }
                if !self.server.commands.iter().any(|known| known.eq_ignore_ascii_case(name)) =>
            {
                return self.answer(&tag, IMAPCondition::BAD, None, "Unknown command");
            }
            IMAPCommandBody::Capability => {
                self.write(&IMAPResponse::Capability(self.capabilities()));
                return self.answer(&tag, IMAPCondition::OK, None, "CAPABILITY completed");
            }
            IMAPCommandBody::Logout => {
                self.write(&IMAPResponse::untagged(IMAPCondition::BYE, None, "Logging out"));
                self.answer(&tag, IMAPCondition::OK, None, "LOGOUT completed");
                self.state = IMAPState::Logout;
                return self.close(None);
            }
            IMAPCommandBody::Enable(capabilities) => {
                // RFC 5161, RFC 9051 §6.3.1: the extensions enabled are told (IMAP4rev2, by a server of it
                // alone too, as §8 shows); others are not enabled.
                let mut enabled = Vec::new();
                for capability in capabilities {
                    if capability.eq_ignore_ascii_case("IMAP4rev2")
                        && !enabled.iter().any(|known: &String| known == "IMAP4rev2")
                    {
                        self.rev2 = true;
                        enabled.push(String::from("IMAP4rev2"));
                    }
                }
                self.write(&IMAPResponse::Enabled(enabled));
                return self.answer(&tag, IMAPCondition::OK, None, "ENABLE completed");
            }
            IMAPCommandBody::StartTLS if !self.server.starttls || self.secure => {
                return self.answer(&tag, IMAPCondition::BAD, None, "STARTTLS not taken");
            }
            IMAPCommandBody::Login { .. } if !self.passwords_taken() => {
                let code = Some(IMAPResponseCode::Other { name: String::from("PRIVACYREQUIRED"), text: None });
                return self.answer(&tag, IMAPCondition::NO, code, "LOGIN is not taken without TLS");
            }
            IMAPCommandBody::Authenticate { mechanism, .. } => {
                if !self.server.auth_mechanisms.iter().any(|offered| offered.eq_ignore_ascii_case(mechanism)) {
                    return self.answer(&tag, IMAPCondition::NO, None, "Unsupported authentication mechanism");
                }
                if !self.mechanisms_offered().iter().any(|offered| offered.eq_ignore_ascii_case(mechanism)) {
                    let code = Some(IMAPResponseCode::Other { name: String::from("PRIVACYREQUIRED"), text: None });
                    return self.answer(&tag, IMAPCondition::NO, code, "The mechanism is not taken without TLS");
                }
            }
            _ => {}
        }
        self.pending = Some(command.clone());
        self.events.push_back(IMAPServerEvent::Command(command));
    }

    /// Sends an untagged response: of the command being answered, or not (RFC 9051 §5.3).
    pub fn respond(&mut self, response: &IMAPResponse) -> Result<(), IMAPError> {
        response.check()?;
        if matches!(response, IMAPResponse::Status { tag: Some(_), .. } | IMAPResponse::Continuation(_)) {
            return Err(IMAPError::State {
                reason: "a tagged response or a continuation is sent by complete or challenge",
            });
        }
        if !self.rev2 && matches!(response, IMAPResponse::ESearch { .. }) {
            // A client of IMAP4rev1 is answered with SEARCH unless it asked for ESEARCH with RETURN.
            let asked = matches!(&self.pending, Some(IMAPCommand { body: IMAPCommandBody::Search { search, .. }, .. }) if search.returns.is_some());
            if !asked {
                return Err(IMAPError::State { reason: "ESEARCH to a client of IMAP4rev1" });
            }
        }
        self.write(response);
        Ok(())
    }

    /// Sends a challenge of the AUTHENTICATE told (RFC 9051 §6.2.2): `+` and the challenge in base64.
    pub fn authenticate_challenge(&mut self, challenge: &[u8], now: Instant) -> Result<(), IMAPError> {
        if !matches!(&self.pending, Some(IMAPCommand { body: IMAPCommandBody::Authenticate { .. }, .. }))
            || self.phase != IMAPServerPhase::Commands
        {
            return Err(IMAPError::State { reason: "no AUTHENTICATE" });
        }
        self.write(&IMAPResponse::Continuation(Base64::STANDARD.encode(challenge).into_bytes()));
        self.phase = IMAPServerPhase::AuthenticateResponse;
        self.process(now);
        Ok(())
    }

    /// Accepts the IDLE told (RFC 9051 §6.3.13): `+` and `text`; untagged responses may be sent
    /// until the client's DONE is told.
    pub fn idle(&mut self, text: &str, now: Instant) -> Result<(), IMAPError> {
        if !matches!(&self.pending, Some(IMAPCommand { body: IMAPCommandBody::Idle, .. }))
            || self.phase != IMAPServerPhase::Commands
        {
            return Err(IMAPError::State { reason: "no IDLE" });
        }
        let response = IMAPResponse::Continuation(text.as_bytes().to_vec());
        response.check()?;
        self.write(&response);
        self.phase = IMAPServerPhase::Idle;
        self.process(now);
        Ok(())
    }

    /// Completes the command told with its tagged response (RFC 9051 §7.1). The response moves the
    /// session on: OK to LOGIN or AUTHENTICATE authenticates; SELECT and EXAMINE select the
    /// mailbox if OK, and leave none selected otherwise (§6.3.2); OK to CLOSE or UNSELECT
    /// leaves none; OK to STARTTLS starts TLS.
    pub fn complete(
        &mut self,
        condition: IMAPCondition,
        code: Option<IMAPResponseCode>,
        text: &str,
        now: Instant,
    ) -> Result<(), IMAPError> {
        if !matches!(condition, IMAPCondition::OK | IMAPCondition::NO | IMAPCondition::BAD) {
            return Err(IMAPError::State { reason: "a completion is OK, NO or BAD" });
        }
        if self.phase == IMAPServerPhase::Idle || self.phase == IMAPServerPhase::AuthenticateResponse {
            return Err(IMAPError::State { reason: "the client has not ended IDLE or answered the challenge" });
        }
        let Some(command) = self.pending.take() else {
            return Err(IMAPError::State { reason: "no command to complete" });
        };
        let response = IMAPResponse::tagged(&command.tag, condition, code, text);
        response.check()?;
        self.write(&response);
        let ok = condition == IMAPCondition::OK;
        match &command.body {
            IMAPCommandBody::Login { .. } | IMAPCommandBody::Authenticate { .. } if ok => {
                self.state = IMAPState::Authenticated
            }
            IMAPCommandBody::Select(_) | IMAPCommandBody::Examine(_) => {
                self.state = if ok { IMAPState::Selected } else { IMAPState::Authenticated };
            }
            IMAPCommandBody::Close | IMAPCommandBody::Unselect if ok => self.state = IMAPState::Authenticated,
            IMAPCommandBody::StartTLS if ok => {
                // RFC 9051 §6.2.1 and CVE-2011-0411: what the client sent before TLS is discarded.
                self.input.clear();
                self.reader.reset();
                self.secure = true;
                self.events.push_back(IMAPServerEvent::StartTLS);
            }
            _ => {}
        }
        self.process(now);
        Ok(())
    }

    /// Closes the connection with an untagged BYE and `text` (RFC 9051 §7.1.5): for shutting
    /// down. Fails for a text that cannot be written, a line break in it.
    pub fn shutdown(&mut self, text: &str) -> Result<(), IMAPError> {
        let response = IMAPResponse::untagged(IMAPCondition::BYE, None, text);
        response.check()?;
        if self.is_open() {
            self.write(&response);
            self.close(None);
        }
        Ok(())
    }

    pub fn transmit(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.output);
    }

    pub fn poll_event(&mut self) -> Option<IMAPServerEvent> {
        self.events.pop_front()
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        self.deadline
    }

    /// Closes the connection with BYE if the client was silent past its time (RFC 9051 §5.4).
    pub fn expire(&mut self, now: Instant) {
        if self.deadline.is_some_and(|deadline| deadline <= now) && self.is_open() {
            self.write(&IMAPResponse::untagged(IMAPCondition::BYE, None, "Autologout; idle for too long"));
            self.close(Some(IMAPError::Timeout));
        }
    }

    pub fn close(&mut self, error: Option<IMAPError>) {
        if !self.is_open() {
            return;
        }
        self.phase = IMAPServerPhase::Closed;
        self.pending = None;
        self.deadline = None;
        self.events.push_back(IMAPServerEvent::Closed { error });
    }
}
