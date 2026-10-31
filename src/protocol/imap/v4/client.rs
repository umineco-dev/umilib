use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use super::{
    IMAPCommand, IMAPCommandBody, IMAPCondition, IMAPConfig, IMAPError, IMAPLineEvent, IMAPLineReader, IMAPLiteralMode,
    IMAPResponse, IMAPResponseCode, IMAPState, IMAPWriter,
};
use crate::bytes::LineBuffer;
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::runtime::Instant;

/// What an [`IMAPClient`] tells its user.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPClientEvent {
    /// The greeting: OK, PREAUTH, or BYE (the connection is refused).
    Greeting(IMAPResponse),
    /// An untagged response: of a command in progress, or not (RFC 9051 §5.3).
    Untagged(IMAPResponse),
    /// The tagged response that completes a command.
    Completed {
        command: IMAPCommand,
        condition: IMAPCondition,
        code: Option<IMAPResponseCode>,
        text: String,
    },
    /// A challenge of AUTHENTICATE, decoded: answer it with [`IMAPClient::authenticate_respond`]
    /// or [`IMAPClient::authenticate_cancel`].
    AuthenticateChallenge {
        tag: String,
        data: Vec<u8>,
    },
    /// The server accepted IDLE: untagged responses follow until [`IMAPClient::idle_done`].
    Idling {
        tag: String,
    },
    /// The server is ready for TLS: start it before anything else; the capabilities are forgotten
    /// (RFC 9051 §6.2.1).
    StartTLS,
    Closed {
        error: Option<IMAPError>,
    },
}

/// A command sent, or to be sent: its parts, each after the server's
/// continuation request but the first (synchronizing literals, §4.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IMAPClientCommand {
    pub command: IMAPCommand,
    pub parts: VecDeque<Vec<u8>>,
    pub deadline: Option<Instant>,
}

/// An IMAP4rev2 client without I/O (RFC 9051), of servers of IMAP4rev1
/// too (RFC 3501): feed it what the server sends with
/// [`IMAPClient::receive`], send what [`IMAPClient::transmit`] gives, and
/// answer its events. It tags the commands, waits for continuation
/// requests before synchronizing literals (non-synchronizing ones where the
/// server takes them, LITERAL+ or LITERAL-), keeps the session's state, and
/// sends a command of a capability only when the server announced it.
#[derive(Clone, Debug)]
pub struct IMAPClient {
    pub config: IMAPConfig,
    pub input: LineBuffer,
    pub reader: IMAPLineReader,
    pub output: Vec<u8>,
    pub events: VecDeque<IMAPClientEvent>,
    pub queued: VecDeque<IMAPClientCommand>,
    /// The commands sent, waiting for their completion, in order.
    pub sent: VecDeque<IMAPClientCommand>,
    pub state: IMAPState,
    pub greeted: bool,
    pub greeting_deadline: Option<Instant>,
    /// The capabilities last announced; `None` before any, or after TLS began.
    pub capabilities: Option<Vec<String>>,
    /// IMAP4rev2 is in use: the server announced it alone, or it was enabled.
    pub rev2: bool,
    /// A challenge of AUTHENTICATE waits for its response.
    pub authenticating: bool,
    /// The initial response of an AUTHENTICATE to a server without SASL-IR, sent for the first empty challenge.
    pub held_response: Option<Vec<u8>>,
    /// IDLE was accepted: DONE ends it.
    pub idling: bool,
    /// A mailbox was selected or examined: ENABLE is no longer sent (RFC 9051 §6.3.1).
    pub selected: bool,
    pub secure: bool,
    pub closed: bool,
    /// The number of the next tag.
    pub next_tag: u64,
    /// The prefix of the tags.
    pub tag_prefix: String,
}

impl IMAPClient {
    /// A client of a new connection, waiting for the greeting; `secure` if the connection is TLS
    /// from its start (RFC 8314). Tags are `prefix` and a number.
    pub fn new(config: IMAPConfig, secure: bool, prefix: &str, now: Instant) -> Result<IMAPClient, IMAPError> {
        config.check()?;
        if !IMAPCommand::is_tag(alloc::format!("{prefix}1").as_bytes()) {
            return Err(IMAPError::State { reason: "a tag prefix that makes no tag" });
        }
        Ok(IMAPClient {
            config,
            input: LineBuffer::new(),
            reader: IMAPLineReader::new(),
            output: Vec::new(),
            events: VecDeque::new(),
            queued: VecDeque::new(),
            sent: VecDeque::new(),
            state: IMAPState::NotAuthenticated,
            greeted: false,
            greeting_deadline: Some(now.saturating_add(config.command_timeout)),
            capabilities: None,
            rev2: false,
            authenticating: false,
            held_response: None,
            idling: false,
            selected: false,
            secure,
            closed: false,
            next_tag: 1,
            tag_prefix: String::from(prefix),
        })
    }

    pub fn is_open(&self) -> bool {
        !self.closed
    }

    /// Whether the server announced `capability`.
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities
            .as_ref()
            .is_some_and(|capabilities| capabilities.iter().any(|known| known.eq_ignore_ascii_case(capability)))
    }

    /// Takes the capabilities announced: IMAP4rev2 is in use when the server offers it and not IMAP4rev1.
    pub fn learn_capabilities(&mut self, capabilities: &[String]) {
        self.capabilities = Some(capabilities.to_vec());
        let rev1 = self.has_capability("IMAP4rev1");
        if self.has_capability("IMAP4rev2") && !rev1 {
            self.rev2 = true;
        }
    }

    pub fn receive(&mut self, bytes: &[u8], now: Instant) -> Result<(), IMAPError> {
        if self.closed {
            return Err(IMAPError::Closed);
        }
        self.input.push(bytes);
        loop {
            let line = match self.reader.next(&mut self.input, &self.config) {
                Ok(Some(IMAPLineEvent::Line(line))) => line,
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(error) => return self.fail(error),
            };
            let response = match IMAPResponse::parse(&line, self.rev2, self.config.maximum_depth) {
                Ok(response) => response,
                Err(error) => return self.fail(error),
            };
            let tls = self.handle(response, now)?;
            if tls || self.closed {
                // RFC 9051 §6.2.1 and CVE-2011-0411: what came before TLS is not believed after it.
                self.input.clear();
                self.reader.reset();
                break;
            }
        }
        if self.input.len() > self.config.maximum_buffered && self.reader.literal == 0 {
            return self.fail(IMAPError::TooLong {
                length: self.input.len() as u64,
                maximum: self.config.maximum_buffered as u64,
            });
        }
        self.pump(now);
        Ok(())
    }

    /// Handles a response; whether TLS is to start.
    pub fn handle(&mut self, response: IMAPResponse, now: Instant) -> Result<bool, IMAPError> {
        if !self.greeted {
            self.greeted = true;
            self.greeting_deadline = None;
            let IMAPResponse::Status { tag: None, condition, code, .. } = &response else {
                return self.fail(IMAPError::Syntax { position: 0, reason: "a greeting that is no untagged status" });
            };
            if let Some(IMAPResponseCode::Capability(capabilities)) = code {
                self.learn_capabilities(&capabilities.clone());
            }
            let condition = *condition;
            if condition == IMAPCondition::PREAUTH {
                self.state = IMAPState::Authenticated;
            }
            self.events.push_back(IMAPClientEvent::Greeting(response));
            if !matches!(condition, IMAPCondition::OK | IMAPCondition::PREAUTH) {
                self.close(None);
            }
            return Ok(false);
        }
        match response {
            IMAPResponse::Continuation(text) => {
                let Some(current) = self.sent.back_mut() else {
                    return self
                        .fail(IMAPError::Syntax { position: 0, reason: "a continuation request of no command" });
                };
                let tag = current.command.tag.clone();
                if let Some(part) = current.parts.pop_front() {
                    self.output.extend_from_slice(&part);
                    return Ok(false);
                }
                match &current.command.body {
                    IMAPCommandBody::Authenticate { .. } => {
                        let Ok(challenge) = Base64::STANDARD.decode(text.trim_ascii()) else {
                            // A challenge that is not base64 is cancelled.
                            self.output.extend_from_slice(b"*\r\n");
                            return Ok(false);
                        };
                        match self.held_response.take() {
                            Some(response) if challenge.is_empty() => self.write_response(&response),
                            _ => {
                                self.authenticating = true;
                                self.events.push_back(IMAPClientEvent::AuthenticateChallenge { tag, data: challenge });
                            }
                        }
                    }
                    IMAPCommandBody::Idle => {
                        self.idling = true;
                        current.deadline = None;
                        self.events.push_back(IMAPClientEvent::Idling { tag });
                    }
                    _ => {
                        return self
                            .fail(IMAPError::Syntax { position: 0, reason: "an unexpected continuation request" });
                    }
                }
                Ok(false)
            }
            IMAPResponse::Status { tag: Some(tag), condition, code, text } => {
                let Some(index) = self.sent.iter().position(|sent| sent.command.tag == tag) else {
                    return self.fail(IMAPError::Syntax { position: 0, reason: "a completion of no command" });
                };
                let Some(sent) = self.sent.remove(index) else { return Ok(false) };
                if let Some(IMAPResponseCode::Capability(capabilities)) = &code {
                    self.learn_capabilities(&capabilities.clone());
                }
                let ok = condition == IMAPCondition::OK;
                let mut tls = false;
                match &sent.command.body {
                    IMAPCommandBody::Login { .. } | IMAPCommandBody::Authenticate { .. } => {
                        self.authenticating = false;
                        self.held_response = None;
                        if ok {
                            self.state = IMAPState::Authenticated;
                        }
                    }
                    IMAPCommandBody::Select(_) | IMAPCommandBody::Examine(_) => {
                        self.state = if ok { IMAPState::Selected } else { IMAPState::Authenticated };
                        self.selected = true;
                    }
                    IMAPCommandBody::Close | IMAPCommandBody::Unselect if ok => self.state = IMAPState::Authenticated,
                    IMAPCommandBody::Idle => self.idling = false,
                    IMAPCommandBody::StartTLS if ok => {
                        tls = true;
                        self.secure = true;
                        // RFC 9051 §6.2.1: what was known before TLS is forgotten, IMAP4rev2 too,
                        // so that a man in the middle cannot make the client speak it to a server
                        // of IMAP4rev1.
                        self.capabilities = None;
                        self.rev2 = false;
                    }
                    IMAPCommandBody::Logout => self.state = IMAPState::Logout,
                    _ => {}
                }
                let logout = self.state == IMAPState::Logout;
                self.events.push_back(IMAPClientEvent::Completed { command: sent.command, condition, code, text });
                if tls {
                    self.events.push_back(IMAPClientEvent::StartTLS);
                }
                if logout {
                    self.close(None);
                }
                Ok(tls)
            }
            response => {
                match &response {
                    IMAPResponse::Capability(capabilities) => self.learn_capabilities(&capabilities.clone()),
                    IMAPResponse::Enabled(capabilities) => {
                        if capabilities.iter().any(|capability| capability.eq_ignore_ascii_case("IMAP4rev2")) {
                            self.rev2 = true;
                        }
                    }
                    IMAPResponse::Status { code: Some(IMAPResponseCode::Capability(capabilities)), .. } => {
                        self.learn_capabilities(&capabilities.clone());
                    }
                    _ => {}
                }
                let bye = matches!(response, IMAPResponse::Status { condition: IMAPCondition::BYE, .. });
                self.events.push_back(IMAPClientEvent::Untagged(response));
                // BYE: the server closes the connection; LOGOUT's completion may follow it.
                if bye && !self.sent.iter().any(|sent| sent.command.body == IMAPCommandBody::Logout) {
                    self.state = IMAPState::Logout;
                    self.close(None);
                }
                let _ = now;
                Ok(false)
            }
        }
    }

    /// The mode of the literals the server takes: LITERAL+ of any size, LITERAL- (and
    /// IMAP4rev2) of at most 4096 octets (RFC 7888), synchronizing otherwise.
    pub fn literal_mode(&self) -> IMAPLiteralMode {
        if self.has_capability("LITERAL+") {
            IMAPLiteralMode::NonSynchronizing { maximum: u64::MAX }
        } else if self.has_capability("LITERAL-") || self.rev2 {
            IMAPLiteralMode::NonSynchronizing { maximum: 4096 }
        } else {
            IMAPLiteralMode::Synchronizing
        }
    }

    /// Queues the command of `body`, to be sent in order; its tag. Fails, sending nothing, for a
    /// command not of the state (RFC 9051 §3), one sent while a command that changes the state
    /// is in progress, STARTTLS not announced or under TLS (§6.2.1), LOGIN where LOGINDISABLED
    /// is announced (§6.2.3), AUTHENTICATE of a mechanism not announced (where capabilities are
    /// known), a command of IMAP4rev1 alone under IMAP4rev2.
    pub fn send(&mut self, body: IMAPCommandBody, now: Instant) -> Result<String, IMAPError> {
        let tag = alloc::format!("{}{}", self.tag_prefix, self.next_tag);
        self.send_with_tag(&tag, body, now)?;
        self.next_tag += 1;
        Ok(tag)
    }

    /// Queues the command of `body` with `tag`, which must be a tag no command in progress has
    /// (RFC 9051 §2.2.1); as [`IMAPClient::send`] otherwise.
    pub fn send_with_tag(&mut self, tag: &str, body: IMAPCommandBody, now: Instant) -> Result<(), IMAPError> {
        self.check(&body)?;
        if !IMAPCommand::is_tag(tag.as_bytes())
            || self.queued.iter().chain(&self.sent).any(|command| command.command.tag == tag)
        {
            return Err(IMAPError::State { reason: "not a tag, or the tag of a command in progress" });
        }
        let body = match body {
            // RFC 4959: without SASL-IR (IMAP4rev2 has it), the initial response waits for the empty challenge.
            // Capabilities not known (TLS began, CAPABILITY not sent again) do not hold it, as in
            // the sample of RFC 9051 §8.
            IMAPCommandBody::Authenticate { mechanism, initial: Some(initial) }
                if self.capabilities.is_some() && !self.rev2 && !self.has_capability("SASL-IR") =>
            {
                self.held_response = Some(initial);
                IMAPCommandBody::Authenticate { mechanism, initial: None }
            }
            body => body,
        };
        let command = IMAPCommand::new(tag, body);
        let mut writer = IMAPWriter::new(self.literal_mode(), self.rev2);
        command.write(&mut writer);
        // What is written must read back as the one command it is: a flag, a capability or an
        // argument of a line break would otherwise add commands of its own.
        let line = &writer.out[..writer.out.len() - 2];
        IMAPCommand::parse(line, self.rev2, self.config.maximum_depth)?;
        // Nor may its last line end as the announcement of a literal the writer did not write
        // (RFC 9051 §4.3): the server would take what follows as the literal's octets.
        if IMAPLineReader::literal_of(&line[writer.literal_end.min(line.len())..]).is_some() {
            return Err(IMAPError::Syntax {
                position: line.len(),
                reason: "a command ending as the length of a literal",
            });
        }
        let mut parts = VecDeque::new();
        let mut start = 0;
        for wait in writer.waits.iter().copied().chain(core::iter::once(writer.out.len())) {
            parts.push_back(writer.out[start..wait].to_vec());
            start = wait;
        }
        self.queued.push_back(IMAPClientCommand { command, parts, deadline: None });
        self.pump(now);
        Ok(())
    }

    /// Checks that a command of `body` may be queued now.
    pub fn check(&self, body: &IMAPCommandBody) -> Result<(), IMAPError> {
        let state = |reason| Err(IMAPError::State { reason });
        if self.closed {
            return Err(IMAPError::Closed);
        }
        if !self.greeted {
            return state("no greeting yet");
        }
        if self.authenticating || self.idling {
            return state("AUTHENTICATE or IDLE waits to be answered");
        }
        if !body.is_valid_in(self.state) {
            return state("a command not of the state");
        }
        let changing =
            self.queued.iter().chain(&self.sent).any(|command| IMAPClient::changes_state(&command.command.body));
        if changing {
            return state("a command that changes the state waits for its completion");
        }
        let plaintext = match body {
            IMAPCommandBody::Login { .. } => true,
            IMAPCommandBody::Authenticate { mechanism, .. } => {
                ["PLAIN", "LOGIN"].iter().any(|plain| plain.eq_ignore_ascii_case(mechanism))
            }
            _ => false,
        };
        if plaintext && self.config.passwords_require_tls && !self.secure {
            return state("a password as it is without TLS (RFC 9051 §11.1)");
        }
        // A command of an extension IMAP4rev1 has not is sent only where it is announced, once the
        // capabilities are known; IMAP4rev2 has them all (RFC 9051 §1), so a server that announces
        // it takes them before ENABLE too.
        let extension = match body {
            IMAPCommandBody::Idle => Some("IDLE"),
            IMAPCommandBody::Move { .. } => Some("MOVE"),
            IMAPCommandBody::Unselect => Some("UNSELECT"),
            IMAPCommandBody::UIDExpunge(_) => Some("UIDPLUS"),
            IMAPCommandBody::Namespace => Some("NAMESPACE"),
            IMAPCommandBody::Search { search, .. } if search.returns.is_some() => Some("ESEARCH"),
            IMAPCommandBody::List { selection, returns, .. } if !selection.is_empty() || !returns.is_empty() => {
                Some("LIST-EXTENDED")
            }
            _ => None,
        };
        if let Some(extension) = extension
            && !self.rev2
            && self.capabilities.is_some()
            && !self.has_capability(extension)
            && !self.has_capability("IMAP4rev2")
        {
            return state("a command of an extension not announced");
        }
        if matches!(body, IMAPCommandBody::Other { arguments, .. } if arguments.iter().any(|byte| matches!(byte, b'\r' | b'\n')))
        {
            // Its arguments are written as they are, and read back as the rest of the line: a line
            // break would end the command there, and begin another. (A literal the arguments end
            // with is refused by send_with_tag, as of any command.)
            return state("a command of an extension with a line break");
        }
        match body {
            IMAPCommandBody::StartTLS if self.secure || !self.has_capability("STARTTLS") => {
                state("STARTTLS not announced, or TLS in use")
            }
            // RFC 9051 §6.3.1: no ENABLE once a mailbox was selected.
            IMAPCommandBody::Enable(_) if self.selected => state("ENABLE after SELECT or EXAMINE"),
            IMAPCommandBody::Login { .. } if self.has_capability("LOGINDISABLED") => state("LOGINDISABLED"),
            // Capabilities not known (TLS began and CAPABILITY was not sent again, which RFC 9051
            // §6.2.1 says a client SHOULD do) do not stop AUTHENTICATE: the server refuses what it lacks.
            IMAPCommandBody::Authenticate { mechanism, .. }
                if self.capabilities.is_some() && !self.has_capability(&alloc::format!("AUTH={mechanism}")) =>
            {
                state("the mechanism not announced")
            }
            IMAPCommandBody::Lsub { .. } | IMAPCommandBody::Check if self.rev2 => state("a command of IMAP4rev1 alone"),
            // ENABLE is of IMAP4rev2 (RFC 9051 §6.3.1), and of ENABLE for a server of IMAP4rev1 (RFC 5161).
            IMAPCommandBody::Enable(_)
                if self.capabilities.is_some()
                    && !self.rev2
                    && !self.has_capability("ENABLE")
                    && !self.has_capability("IMAP4rev2") =>
            {
                state("ENABLE not announced")
            }
            _ => Ok(()),
        }
    }

    /// Whether the command's completion changes what the commands after it mean: they are not
    /// sent while it is in progress (RFC 9051 §5.5).
    pub fn changes_state(body: &IMAPCommandBody) -> bool {
        matches!(
            body,
            IMAPCommandBody::StartTLS
                | IMAPCommandBody::Login { .. }
                | IMAPCommandBody::Authenticate { .. }
                | IMAPCommandBody::Select(_)
                | IMAPCommandBody::Examine(_)
                | IMAPCommandBody::Close
                | IMAPCommandBody::Unselect
                | IMAPCommandBody::Logout
                | IMAPCommandBody::Idle
                | IMAPCommandBody::Enable(_)
        )
    }

    /// Whether the command may be in progress with others (RFC 9051 §5.5): of no message
    /// sequence numbers an EXPUNGE could change, and changing nothing the others mean.
    pub fn may_pipeline(body: &IMAPCommandBody) -> bool {
        // A UID SEARCH of sequence numbers is of numbers an EXPUNGE changes.
        if let IMAPCommandBody::Search { search, .. } = body
            && search.keys.iter().any(super::IMAPSearchKey::uses_sequence_numbers)
        {
            return false;
        }
        matches!(
            body,
            IMAPCommandBody::Capability
                | IMAPCommandBody::Noop
                | IMAPCommandBody::List { .. }
                | IMAPCommandBody::Lsub { .. }
                | IMAPCommandBody::Namespace
                | IMAPCommandBody::Status { .. }
                | IMAPCommandBody::Fetch { uid: true, .. }
                | IMAPCommandBody::Search { uid: true, .. }
                | IMAPCommandBody::Store { uid: true, .. }
                | IMAPCommandBody::Copy { uid: true, .. }
        )
    }

    /// Sends what may be sent: the first part of the next command when no command waits for a
    /// continuation request, and, while others are in progress, only one that may be pipelined
    /// after ones that may be.
    pub fn pump(&mut self, now: Instant) {
        while let Some(next) = self.queued.front() {
            let waiting_continuation = self.sent.iter().any(|sent| !sent.parts.is_empty());
            let pipelined = self.sent.iter().all(|sent| IMAPClient::may_pipeline(&sent.command.body))
                && IMAPClient::may_pipeline(&next.command.body);
            if self.closed
                || !self.greeted
                || waiting_continuation
                || self.idling
                || (!self.sent.is_empty() && !pipelined)
            {
                break;
            }
            let Some(mut command) = self.queued.pop_front() else { break };
            if let Some(first) = command.parts.pop_front() {
                self.output.extend_from_slice(&first);
            }
            command.deadline = Some(now.saturating_add(self.config.command_timeout));
            self.sent.push_back(command);
        }
    }

    /// Answers a challenge of AUTHENTICATE with `response` (RFC 9051 §6.2.2).
    pub fn authenticate_respond(&mut self, response: &[u8], now: Instant) -> Result<(), IMAPError> {
        if !self.authenticating {
            return Err(IMAPError::State { reason: "no AUTHENTICATE challenge" });
        }
        self.authenticating = false;
        self.write_response(response);
        self.pump(now);
        Ok(())
    }

    /// Cancels AUTHENTICATE with `*`, which the server answers with BAD.
    pub fn authenticate_cancel(&mut self, now: Instant) -> Result<(), IMAPError> {
        if !self.authenticating {
            return Err(IMAPError::State { reason: "no AUTHENTICATE challenge" });
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

    /// Ends IDLE with DONE (RFC 9051 §6.3.13); its completion follows.
    pub fn idle_done(&mut self, now: Instant) -> Result<(), IMAPError> {
        if !self.idling {
            return Err(IMAPError::State { reason: "not idling" });
        }
        self.idling = false;
        self.output.extend_from_slice(b"DONE\r\n");
        if let Some(sent) = self.sent.iter_mut().find(|sent| sent.command.body == IMAPCommandBody::Idle) {
            sent.deadline = Some(now.saturating_add(self.config.command_timeout));
        }
        Ok(())
    }

    pub fn transmit(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.output);
    }

    pub fn poll_event(&mut self) -> Option<IMAPClientEvent> {
        self.events.pop_front()
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.closed {
            return None;
        }
        self.greeting_deadline.into_iter().chain(self.sent.iter().filter_map(|sent| sent.deadline)).min()
    }

    pub fn expire(&mut self, now: Instant) {
        if self.poll_timeout().is_some_and(|deadline| deadline <= now) {
            self.close(Some(IMAPError::Timeout));
        }
    }

    pub fn close(&mut self, error: Option<IMAPError>) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.queued.clear();
        self.sent.clear();
        self.authenticating = false;
        self.idling = false;
        self.events.push_back(IMAPClientEvent::Closed { error });
    }

    pub fn fail<T>(&mut self, error: IMAPError) -> Result<T, IMAPError> {
        self.close(Some(error));
        Err(error)
    }
}
