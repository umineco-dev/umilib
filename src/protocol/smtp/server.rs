use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use super::{
    SMTPCommand, SMTPConfig, SMTPDataReader, SMTPEnhancedStatus, SMTPError, SMTPExtension, SMTPExtensions,
    SMTPParameter, SMTPPath, SMTPReply, SMTPServerConfig, SMTPXText,
};
use crate::bytes::LineBuffer;
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::runtime::Instant;

/// What an [`SMTPServer`] tells its user.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SMTPServerEvent {
    /// A command to answer with [`SMTPServer::reply`] (or, for AUTH,
    /// [`SMTPServer::auth_challenge`]). Commands the server answers itself
    /// (NOOP, RSET, QUIT, and those out of sequence or of an extension not
    /// offered) are not told.
    Command(SMTPCommand),
    /// Octets of the message of DATA or of a chunk of BDAT, the periods added for transparency removed.
    Data(Vec<u8>),
    /// The end of the mail data of DATA, or of a chunk (the last of the message if `last`):
    /// answer with [`SMTPServer::reply`].
    DataEnd { last: bool },
    /// The message was not taken, and the server replied itself: too large, or not of the
    /// data SMTP takes (a CR or an LF alone, a line longer than the limit).
    DataRejected(SMTPError),
    /// A response of an AUTH exchange, decoded (RFC 4954 §4): answer with another challenge
    /// or a reply.
    AuthResponse(Vec<u8>),
    /// The client cancelled AUTH, and the server replied 501.
    AuthCancelled,
    /// The AUTH exchange failed, and the server replied itself: a response that is not base64
    /// (501) or a line too long (500, RFC 4954 §4). Its SASL state is to be dropped.
    AuthFailed,
    /// The mail transaction was abandoned: RSET, a new EHLO or HELO, STARTTLS.
    Reset,
    /// The 220 to STARTTLS was sent: start TLS now. What the client sent before it is
    /// discarded, and the session is as after the greeting (RFC 3207 §4.2).
    StartTLS,
    /// The connection is to be closed: after QUIT, a 421, or an error.
    Closed { error: Option<SMTPError> },
}

/// What a server waits for its user to answer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SMTPServerPending {
    /// A command told.
    Command(SMTPCommand),
    /// The end of the mail data of DATA.
    DataEnd,
    /// The end of a chunk of BDAT.
    ChunkEnd { last: bool },
    /// A response of an AUTH exchange.
    AuthResponse,
}

/// What a server reads next.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SMTPServerPhase {
    /// The greeting is not sent yet.
    Greeting,
    Commands,
    /// The response of an AUTH exchange.
    AuthResponse,
    /// The mail data of DATA.
    Data(SMTPDataReader),
    /// The octets of a chunk: how many are left, whether it is the last, and, for a chunk
    /// refused before it was read, the reply to send after it.
    Chunk {
        remaining: u64,
        last: bool,
        refusal: Option<SMTPReply>,
    },
    Closed,
}

/// The mail transaction a server has begun: the reverse path and parameters of its MAIL.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SMTPServerTransaction {
    pub reverse_path: SMTPPath,
    pub parameters: Vec<SMTPParameter>,
    /// The recipients accepted.
    pub recipients: usize,
    /// The octets of the chunks read so far.
    pub size: u64,
    /// Chunks of BDAT have been sent: DATA is not taken (RFC 3030 §2).
    pub chunked: bool,
    /// A chunk was refused: no more are taken (RFC 3030 §2).
    pub failed: bool,
}

/// An SMTP server without I/O (RFC 5321): feed it what the client sends
/// with [`SMTPServer::receive`], send what [`SMTPServer::transmit`] gives,
/// and answer its events. Commands are told one at a time, in order (RFC
/// 2920 §3.2 (1)); what RFC 5321 and its extensions decide, the server
/// answers itself.
#[derive(Clone, Debug)]
pub struct SMTPServer {
    pub config: SMTPConfig,
    pub server: SMTPServerConfig,
    pub input: LineBuffer,
    pub output: Vec<u8>,
    pub events: VecDeque<SMTPServerEvent>,
    pub phase: SMTPServerPhase,
    /// What was told and not yet answered.
    pub pending: Option<SMTPServerPending>,
    /// The domain of the accepted EHLO or HELO, and whether it was EHLO.
    pub hello: Option<(String, bool)>,
    pub transaction: Option<SMTPServerTransaction>,
    /// TLS is in use: implicitly (RFC 8314) or after STARTTLS.
    pub secure: bool,
    pub authenticated: bool,
    /// The greeting was 554: every command but QUIT is answered 503 (RFC 5321 §3.1).
    pub refused: bool,
    /// When the server stops waiting for the client.
    pub deadline: Option<Instant>,
}

impl SMTPServer {
    /// A server of a new connection; `secure` if it is TLS from its start
    /// (RFC 8314 §3.3). Send the greeting with [`SMTPServer::greet`].
    pub fn new(config: SMTPConfig, server: SMTPServerConfig, secure: bool) -> Result<SMTPServer, SMTPError> {
        config.check()?;
        server.check()?;
        Ok(SMTPServer {
            config,
            server,
            input: LineBuffer::new(),
            output: Vec::new(),
            events: VecDeque::new(),
            phase: SMTPServerPhase::Greeting,
            pending: None,
            hello: None,
            transaction: None,
            secure,
            authenticated: false,
            refused: false,
            deadline: None,
        })
    }

    pub fn is_open(&self) -> bool {
        self.phase != SMTPServerPhase::Closed
    }

    /// Whether the server takes more input: it holds less than the configured maximum.
    pub fn wants_receive(&self) -> bool {
        self.is_open() && self.input.len() < self.config.maximum_buffered
    }

    /// The greeting of the configured domain: `220 domain ESMTP`.
    pub fn greeting(&self) -> SMTPReply {
        SMTPReply::new(220, &alloc::format!("{} ESMTP", self.server.domain))
    }

    /// Sends the greeting: 220, or 554 to take no mail (§3.1), after which
    /// only QUIT is taken.
    pub fn greet(&mut self, reply: SMTPReply, now: Instant) -> Result<(), SMTPError> {
        if self.phase != SMTPServerPhase::Greeting {
            return Err(SMTPError::State { reason: "the greeting was sent" });
        }
        reply.check()?;
        if !matches!(reply.code, 220 | 554) {
            return Err(SMTPError::State { reason: "a greeting is 220 or 554" });
        }
        self.refused = reply.code == 554;
        reply.encode(&mut self.output);
        self.phase = SMTPServerPhase::Commands;
        self.process(now);
        Ok(())
    }

    /// The extensions the reply to EHLO advertises now (RFC 5321 §4.1.1.1):
    /// those configured, STARTTLS only before TLS (RFC 3207 §4.2), AUTH only
    /// under TLS if so configured (RFC 4954 §4).
    pub fn extensions(&self) -> SMTPExtensions {
        let server = &self.server;
        let mut entries = Vec::new();
        let mut add = |enabled: bool, keyword: &str, parameters: &[&str]| {
            if enabled {
                entries.push(SMTPExtension::new(keyword, parameters));
            }
        };
        let size = alloc::format!("{}", server.maximum_message_size);
        add(true, "SIZE", &[&size]);
        add(server.pipelining, "PIPELINING", &[]);
        add(server.eight_bit_mime, "8BITMIME", &[]);
        add(server.smtputf8, "SMTPUTF8", &[]);
        add(server.chunking, "CHUNKING", &[]);
        add(server.binary_mime, "BINARYMIME", &[]);
        add(server.dsn, "DSN", &[]);
        add(server.enhanced_status_codes, "ENHANCEDSTATUSCODES", &[]);
        add(server.starttls && !self.secure, "STARTTLS", &[]);
        let mechanisms = self.mechanisms_offered();
        add(!mechanisms.is_empty(), "AUTH", &mechanisms);
        SMTPExtensions { greeting: alloc::format!("{} Hello", server.domain), entries }
    }

    /// The mechanisms AUTH offers now: those configured, a plaintext one only under TLS if so
    /// configured (RFC 4954 §4).
    pub fn mechanisms_offered(&self) -> Vec<&str> {
        let server = &self.server;
        let plaintext = |mechanism: &&String| {
            mechanism.eq_ignore_ascii_case("PLAIN")
                || server.plaintext_mechanisms.iter().any(|plain| plain.eq_ignore_ascii_case(mechanism))
        };
        let taken = |mechanism: &&String| self.secure || !server.passwords_require_tls || !plaintext(mechanism);
        server.auth_mechanisms.iter().filter(taken).map(String::as_str).collect()
    }

    /// Whether AUTH is offered now.
    pub fn auth_offered(&self) -> bool {
        !self.mechanisms_offered().is_empty()
    }

    /// Takes what the client sent.
    pub fn receive(&mut self, bytes: &[u8], now: Instant) {
        if !self.is_open() {
            return;
        }
        self.input.push(bytes);
        self.process(now);
    }

    /// Reads what can be read: commands while none waits for its answer, data, chunks.
    pub fn process(&mut self, now: Instant) {
        loop {
            if self.pending.is_some() || !self.is_open() {
                break;
            }
            let progressed = match &self.phase {
                SMTPServerPhase::Greeting | SMTPServerPhase::Closed => false,
                SMTPServerPhase::Commands => self.read_command(),
                SMTPServerPhase::AuthResponse => self.read_auth_response(),
                SMTPServerPhase::Data(_) => self.read_data(),
                SMTPServerPhase::Chunk { .. } => self.read_chunk(),
            };
            if !progressed {
                break;
            }
        }
        let waiting =
            self.pending.is_none() && !matches!(self.phase, SMTPServerPhase::Greeting | SMTPServerPhase::Closed);
        self.deadline = waiting.then(|| now.saturating_add(self.config.server_timeout));
    }

    /// Writes a reply the server makes itself, with an enhanced status code if offered.
    /// The text is a constant of the program (`&'static str`), never text received or made at run
    /// time, which would go unchecked into the reply: such text is sent with
    /// [`SMTPServer::reply`], which checks it.
    pub fn answer(&mut self, code: u16, status: SMTPEnhancedStatus, text: &'static str) {
        self.reply_of(code, status, text).encode(&mut self.output);
    }

    /// The reply the server makes itself: with an enhanced status code if offered.
    pub fn reply_of(&self, code: u16, status: SMTPEnhancedStatus, text: &str) -> SMTPReply {
        match self.server.enhanced_status_codes {
            true => SMTPReply::enhanced(code, status, text),
            false => SMTPReply::new(code, text),
        }
    }

    /// Refuses `command` with a reply of the server's own. The chunk of a BDAT refused is read
    /// and discarded first (RFC 3030 §2: the receiver MUST accept and discard it), so that its
    /// octets are never taken as commands. As for [`SMTPServer::answer`], the text is a constant.
    pub fn refuse(&mut self, command: &SMTPCommand, code: u16, status: SMTPEnhancedStatus, text: &'static str) {
        let reply = self.reply_of(code, status, text);
        match command {
            SMTPCommand::Bdat { size, last } => {
                if let Some(transaction) = &mut self.transaction {
                    transaction.failed = true;
                }
                self.phase = SMTPServerPhase::Chunk { remaining: *size, last: *last, refusal: Some(reply) };
            }
            _ => reply.encode(&mut self.output),
        }
    }

    /// Reads a command line, if a whole one is here; whether one was read.
    pub fn read_command(&mut self) -> bool {
        let line = match self.input.line(self.config.maximum_auth_line) {
            Ok(Some(line)) => line,
            Ok(None) => return false,
            Err(_) => {
                self.answer(500, SMTPEnhancedStatus::new(5, 5, 2), "Line too long");
                return true;
            }
        };
        let is_auth = line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"AUTH ");
        if line.len() + 2 > self.config.maximum_command_line && !is_auth {
            self.answer(500, SMTPEnhancedStatus::new(5, 5, 2), "Line too long");
            return true;
        }
        let utf8 = self.server.smtputf8 && self.hello.as_ref().is_some_and(|(_, extended)| *extended);
        match SMTPCommand::parse(&line, utf8) {
            Ok(command) => self.dispatch(command),
            Err(_) => {
                let known = [
                    "HELO", "EHLO", "MAIL", "RCPT", "DATA", "BDAT", "RSET", "VRFY", "EXPN", "HELP", "NOOP", "QUIT",
                    "STARTTLS", "AUTH",
                ];
                let verb = line.split(|byte| *byte == b' ').next().unwrap_or_default();
                match known.iter().any(|known| known.as_bytes().eq_ignore_ascii_case(verb)) {
                    true => {
                        self.answer(501, SMTPEnhancedStatus::new(5, 5, 2), "Syntax error in parameters or arguments")
                    }
                    false => self.answer(500, SMTPEnhancedStatus::new(5, 5, 1), "Command unrecognized"),
                }
            }
        }
        true
    }

    /// Answers a command the server decides itself, or tells it.
    pub fn dispatch(&mut self, command: SMTPCommand) {
        let sequence = SMTPEnhancedStatus::new(5, 5, 1);
        if self.refused && command != SMTPCommand::Quit {
            return self.refuse(&command, 503, sequence, "Bad sequence of commands");
        }
        // RFC 3207 §4: only NOOP, EHLO, STARTTLS and QUIT before TLS, if TLS is required.
        let before_tls =
            matches!(command, SMTPCommand::Noop(_) | SMTPCommand::Ehlo(_) | SMTPCommand::StartTLS | SMTPCommand::Quit);
        if self.server.requires_tls && !self.secure && !before_tls {
            return self.refuse(&command, 530, SMTPEnhancedStatus::new(5, 7, 0), "Must issue a STARTTLS command first");
        }
        let extended = self.hello.as_ref().is_some_and(|(_, extended)| *extended);
        match &command {
            SMTPCommand::Noop(_) => return self.answer(250, SMTPEnhancedStatus::new(2, 0, 0), "OK"),
            SMTPCommand::Quit => {
                self.answer(221, SMTPEnhancedStatus::new(2, 0, 0), "Bye");
                return self.close(None);
            }
            SMTPCommand::Rset => {
                self.reset();
                return self.answer(250, SMTPEnhancedStatus::new(2, 0, 0), "OK");
            }
            SMTPCommand::Other { verb, .. }
                if !self.server.commands.iter().any(|known| known.eq_ignore_ascii_case(verb)) =>
            {
                return self.answer(500, SMTPEnhancedStatus::new(5, 5, 1), "Command unrecognized");
            }
            SMTPCommand::StartTLS if !self.server.starttls => {
                return self.answer(502, SMTPEnhancedStatus::new(5, 5, 1), "Command not implemented");
            }
            SMTPCommand::StartTLS if self.secure => return self.answer(503, sequence, "TLS already active"),
            SMTPCommand::Auth { mechanism, .. } => {
                if self.server.auth_mechanisms.is_empty() {
                    return self.answer(502, SMTPEnhancedStatus::new(5, 5, 1), "Command not implemented");
                }
                if !extended || self.authenticated || self.transaction.is_some() {
                    return self.answer(503, sequence, "Bad sequence of commands");
                }
                if !self.server.auth_mechanisms.iter().any(|offered| offered.eq_ignore_ascii_case(mechanism)) {
                    return self.answer(504, SMTPEnhancedStatus::new(5, 5, 4), "Unrecognized authentication type");
                }
                if !self.mechanisms_offered().iter().any(|offered| offered.eq_ignore_ascii_case(mechanism)) {
                    return self.answer(
                        538,
                        SMTPEnhancedStatus::new(5, 7, 11),
                        "Encryption required for requested authentication mechanism",
                    );
                }
            }
            SMTPCommand::Mail { path, parameters } => {
                if self.hello.is_none() {
                    return self.answer(503, sequence, "Send EHLO first");
                }
                if self.server.requires_auth && !self.authenticated {
                    return self.answer(530, SMTPEnhancedStatus::new(5, 7, 0), "Authentication required");
                }
                if self.transaction.is_some() {
                    return self.answer(503, sequence, "Nested MAIL command");
                }
                if let Err((code, status, text)) = self.check_mail(path, parameters, extended) {
                    return self.answer(code, status, text);
                }
            }
            SMTPCommand::Rcpt { path, parameters } => {
                let Some(transaction) = &self.transaction else {
                    return self.answer(503, sequence, "Need MAIL command");
                };
                if transaction.recipients >= self.server.maximum_recipients {
                    return self.answer(452, SMTPEnhancedStatus::new(4, 5, 3), "Too many recipients");
                }
                let utf8 = SMTPParameter::find(&transaction.parameters, "SMTPUTF8").is_some();
                if path.mailbox().is_some_and(super::SMTPMailbox::is_utf8) && !utf8 {
                    return self.answer(553, SMTPEnhancedStatus::new(5, 6, 7), "Non-ASCII addresses need SMTPUTF8");
                }
                if let Err((code, status, text)) = self.check_rcpt(parameters, extended) {
                    return self.answer(code, status, text);
                }
            }
            SMTPCommand::Data => {
                let Some(transaction) = &self.transaction else {
                    return self.answer(503, sequence, "Need MAIL command");
                };
                let binary = SMTPParameter::find(&transaction.parameters, "BODY").is_some_and(|body| {
                    body.value.as_deref().is_some_and(|value| value.eq_ignore_ascii_case("BINARYMIME"))
                });
                if binary || transaction.chunked {
                    return self.answer(503, sequence, "BINARYMIME and chunks are sent with BDAT");
                }
                if transaction.recipients == 0 {
                    return self.answer(554, SMTPEnhancedStatus::new(5, 5, 1), "No valid recipients");
                }
            }
            SMTPCommand::Bdat { size, last } => return self.begin_chunk(*size, *last),
            _ => {}
        }
        self.pending = Some(SMTPServerPending::Command(command.clone()));
        self.events.push_back(SMTPServerEvent::Command(command));
    }

    /// The reply to MAIL that its parameters call for, if they are not
    /// taken: of an extension not offered (555, RFC 5321 §4.1.1.11), not of
    /// its syntax (501), a SIZE above the limit (552, RFC 1870 §6), a
    /// mailbox of UTF-8 without SMTPUTF8 (553, RFC 6531 §3.6).
    pub fn check_mail(
        &self,
        path: &SMTPPath,
        parameters: &[SMTPParameter],
        extended: bool,
    ) -> Result<(), (u16, SMTPEnhancedStatus, &'static str)> {
        let unknown = Err((555, SMTPEnhancedStatus::new(5, 5, 4), "Parameter not recognized"));
        let syntax = Err((501, SMTPEnhancedStatus::new(5, 5, 4), "Syntax error in parameters"));
        let server = &self.server;
        for (index, parameter) in parameters.iter().enumerate() {
            if !extended {
                return unknown;
            }
            if parameters[..index].iter().any(|earlier| earlier.keyword == parameter.keyword) {
                return syntax;
            }
            let value = parameter.value.as_deref();
            match parameter.keyword.as_str() {
                "SIZE" => {
                    let size = value
                        .filter(|value| value.len() <= 20 && value.bytes().all(|byte| byte.is_ascii_digit()))
                        .and_then(|value| value.parse::<u64>().ok());
                    let Some(size) = size else { return syntax };
                    if server.maximum_message_size > 0 && size > server.maximum_message_size {
                        return Err((
                            552,
                            SMTPEnhancedStatus::new(5, 3, 4),
                            "Message size exceeds fixed maximum message size",
                        ));
                    }
                }
                "BODY" => match value.map(str::to_ascii_uppercase).as_deref() {
                    Some("7BIT") => {}
                    Some("8BITMIME") if server.eight_bit_mime => {}
                    Some("BINARYMIME") if server.binary_mime => {}
                    Some("8BITMIME" | "BINARYMIME") => return unknown,
                    _ => return syntax,
                },
                "SMTPUTF8" if server.smtputf8 => {
                    if value.is_some() {
                        return syntax;
                    }
                }
                "RET" if server.dsn => {
                    if !value
                        .is_some_and(|value| value.eq_ignore_ascii_case("FULL") || value.eq_ignore_ascii_case("HDRS"))
                    {
                        return syntax;
                    }
                }
                "ENVID" if server.dsn => {
                    // RFC 3461 §4.4: xtext of at most 100 characters.
                    if !value.is_some_and(|value| value.len() <= 100 && SMTPXText::decode(value.as_bytes()).is_ok()) {
                        return syntax;
                    }
                }
                "AUTH" if self.auth_offered() => {
                    // RFC 4954 §5: xtext of a mailbox, or <>.
                    if !value.is_some_and(|value| value == "<>" || SMTPXText::decode(value.as_bytes()).is_ok()) {
                        return syntax;
                    }
                }
                _ => return unknown,
            }
        }
        let utf8 = SMTPParameter::find(parameters, "SMTPUTF8").is_some();
        if path.mailbox().is_some_and(super::SMTPMailbox::is_utf8) && !utf8 {
            return Err((553, SMTPEnhancedStatus::new(5, 6, 7), "Non-ASCII addresses need SMTPUTF8"));
        }
        Ok(())
    }

    /// The reply to RCPT that its parameters call for, if they are not
    /// taken: NOTIFY and ORCPT of DSN (RFC 3461 §4.1, §4.2), or another (555).
    pub fn check_rcpt(
        &self,
        parameters: &[SMTPParameter],
        extended: bool,
    ) -> Result<(), (u16, SMTPEnhancedStatus, &'static str)> {
        let unknown = Err((555, SMTPEnhancedStatus::new(5, 5, 4), "Parameter not recognized"));
        let syntax = Err((501, SMTPEnhancedStatus::new(5, 5, 4), "Syntax error in parameters"));
        for (index, parameter) in parameters.iter().enumerate() {
            // RFC 5321 §4.1.1.11: parameters are of extensions, which only EHLO opens.
            if !extended {
                return unknown;
            }
            if parameters[..index].iter().any(|earlier| earlier.keyword == parameter.keyword) {
                return syntax;
            }
            let value = parameter.value.as_deref().unwrap_or_default();
            match parameter.keyword.as_str() {
                "NOTIFY" if self.server.dsn => {
                    let values: Vec<String> = value.split(',').map(str::to_ascii_uppercase).collect();
                    let never = values.len() == 1 && values[0] == "NEVER";
                    let each = values.iter().enumerate().all(|(index, value)| {
                        matches!(value.as_str(), "SUCCESS" | "FAILURE" | "DELAY") && !values[..index].contains(value)
                    });
                    if !never && !each {
                        return syntax;
                    }
                }
                "ORCPT" if self.server.dsn => {
                    // addr-type ";" xtext
                    let valid = value.split_once(';').is_some_and(|(kind, address)| {
                        SMTPParameter::is_keyword(kind.as_bytes())
                            && !address.is_empty()
                            && SMTPXText::decode(address.as_bytes()).is_ok()
                    });
                    if !valid {
                        return syntax;
                    }
                }
                _ => return unknown,
            }
        }
        Ok(())
    }

    /// Begins reading a chunk of BDAT (RFC 3030 §2); a chunk not taken is
    /// read all the same, then refused.
    pub fn begin_chunk(&mut self, size: u64, last: bool) {
        let sequence = SMTPEnhancedStatus::new(5, 5, 1);
        let status = |code, status, text: &str| match self.server.enhanced_status_codes {
            true => SMTPReply::enhanced(code, status, text),
            false => SMTPReply::new(code, text),
        };
        let maximum = match self.server.maximum_message_size {
            0 => u64::MAX,
            maximum => maximum,
        };
        let refusal = match &self.transaction {
            _ if !self.server.chunking => {
                Some(status(502, SMTPEnhancedStatus::new(5, 5, 1), "Command not implemented"))
            }
            None => Some(status(503, sequence, "Need MAIL command")),
            Some(transaction) if transaction.failed => Some(status(503, sequence, "A chunk was refused")),
            Some(transaction) if transaction.recipients == 0 => {
                Some(status(554, SMTPEnhancedStatus::new(5, 5, 1), "No valid recipients"))
            }
            Some(transaction) if transaction.size.saturating_add(size) > maximum => {
                Some(status(552, SMTPEnhancedStatus::new(5, 3, 4), "Message size exceeds fixed maximum message size"))
            }
            Some(_) => None,
        };
        if refusal.is_some()
            && let Some(transaction) = &mut self.transaction
        {
            transaction.failed = true;
        }
        if let Some(transaction) = &mut self.transaction
            && refusal.is_none()
        {
            transaction.chunked = true;
            transaction.size += size;
        }
        self.phase = SMTPServerPhase::Chunk { remaining: size, last, refusal };
    }

    /// Reads octets of a chunk; whether any were read or the chunk ended.
    pub fn read_chunk(&mut self) -> bool {
        let SMTPServerPhase::Chunk { remaining, last, refusal } = &mut self.phase else {
            return false;
        };
        let count = usize::try_from(*remaining).unwrap_or(usize::MAX).min(self.input.len());
        let data = self.input.take(count);
        *remaining -= count as u64;
        let (done, last, refusal) = (*remaining == 0, *last, refusal.clone());
        if refusal.is_none() && !data.is_empty() {
            self.events.push_back(SMTPServerEvent::Data(data));
        }
        if !done {
            return count > 0;
        }
        self.phase = SMTPServerPhase::Commands;
        match refusal {
            Some(reply) => {
                reply.encode(&mut self.output);
                if last {
                    self.transaction = None;
                }
            }
            None => {
                self.pending = Some(SMTPServerPending::ChunkEnd { last });
                self.events.push_back(SMTPServerEvent::DataEnd { last });
            }
        }
        true
    }

    /// Reads mail data; whether any was read.
    pub fn read_data(&mut self) -> bool {
        let SMTPServerPhase::Data(reader) = &mut self.phase else {
            return false;
        };
        let mut data = Vec::new();
        let read = reader.read(self.input.unread(), &mut data);
        let (end, error) = (reader.is_end(), reader.error());
        self.input.consume(read);
        if !data.is_empty() && error.is_none() {
            self.events.push_back(SMTPServerEvent::Data(data));
        }
        if !end {
            return read > 0;
        }
        self.phase = SMTPServerPhase::Commands;
        match error {
            Some(error) => {
                self.transaction = None;
                match error {
                    SMTPError::TooLarge { .. } => {
                        self.answer(
                            552,
                            SMTPEnhancedStatus::new(5, 3, 4),
                            "Message size exceeds fixed maximum message size",
                        );
                    }
                    SMTPError::TooLong { .. } => {
                        self.answer(550, SMTPEnhancedStatus::new(5, 6, 0), "A line longer than 1000 octets")
                    }
                    _ => self.answer(550, SMTPEnhancedStatus::new(5, 6, 0), "A CR or an LF alone in the message"),
                }
                self.events.push_back(SMTPServerEvent::DataRejected(error));
            }
            None => {
                self.pending = Some(SMTPServerPending::DataEnd);
                self.events.push_back(SMTPServerEvent::DataEnd { last: true });
            }
        }
        true
    }

    /// Reads a response of an AUTH exchange; whether one was read.
    pub fn read_auth_response(&mut self) -> bool {
        let line = match self.input.line(self.config.maximum_auth_line) {
            Ok(Some(line)) => line,
            Ok(None) => return false,
            Err(_) => {
                // RFC 4954 §4: a line longer than the buffer fails AUTH with 500 (5.5.6).
                self.phase = SMTPServerPhase::Commands;
                self.answer(500, SMTPEnhancedStatus::new(5, 5, 6), "Authentication exchange line is too long");
                self.events.push_back(SMTPServerEvent::AuthFailed);
                return true;
            }
        };
        self.phase = SMTPServerPhase::Commands;
        if line == b"*" {
            self.answer(501, SMTPEnhancedStatus::new(5, 0, 0), "Authentication cancelled");
            self.events.push_back(SMTPServerEvent::AuthCancelled);
            return true;
        }
        match Base64::STANDARD.decode(&line) {
            Ok(response) => {
                self.pending = Some(SMTPServerPending::AuthResponse);
                self.events.push_back(SMTPServerEvent::AuthResponse(response));
            }
            Err(_) => {
                self.answer(501, SMTPEnhancedStatus::new(5, 5, 2), "Cannot decode the response");
                self.events.push_back(SMTPServerEvent::AuthFailed);
            }
        }
        true
    }

    /// Sends a challenge of the AUTH exchange told (RFC 4954 §4): `334` and the challenge in base64.
    pub fn auth_challenge(&mut self, challenge: &[u8], now: Instant) -> Result<(), SMTPError> {
        if !matches!(
            self.pending,
            Some(SMTPServerPending::Command(SMTPCommand::Auth { .. }) | SMTPServerPending::AuthResponse)
        ) {
            return Err(SMTPError::State { reason: "no AUTH exchange" });
        }
        self.output.extend_from_slice(b"334 ");
        self.output.extend_from_slice(Base64::STANDARD.encode(challenge).as_bytes());
        self.output.extend_from_slice(b"\r\n");
        self.pending = None;
        self.phase = SMTPServerPhase::AuthResponse;
        self.process(now);
        Ok(())
    }

    /// Answers the command told (or the end of data, or of a chunk). An
    /// enhanced status code is put first where one is offered and the reply
    /// has none (RFC 2034 §4). The reply moves the session on as RFC 5321
    /// says: EHLO advertises the extensions; MAIL begins a transaction,
    /// RCPT adds a recipient, 354 to DATA begins its data, the reply to its
    /// end ends the transaction; 235 authenticates; 220 to STARTTLS starts TLS.
    pub fn reply(&mut self, reply: SMTPReply, now: Instant) -> Result<(), SMTPError> {
        reply.check()?;
        let Some(pending) = self.pending.take() else {
            return Err(SMTPError::State { reason: "no command to answer" });
        };
        let positive = reply.is_positive();
        let mut reply = reply;
        let hello = matches!(pending, SMTPServerPending::Command(SMTPCommand::Ehlo(_) | SMTPCommand::Helo(_)));
        // RFC 2034 §4: the status code begins every line of a reply but 3xx and those to EHLO
        // and HELO: that of the first line where it has one, c.0.0 otherwise.
        if self.server.enhanced_status_codes && !hello && !reply.is_intermediate() {
            let status = reply.status().unwrap_or(SMTPEnhancedStatus::new(reply.severity() as u8, 0, 0));
            let code = reply.code;
            for line in &mut reply.lines {
                let has = SMTPEnhancedStatus::parse(line).is_some_and(|(status, _)| status.agrees_with(code));
                if !has {
                    line.splice(0..0, alloc::format!("{status} ").bytes());
                }
            }
        }
        let mut tls = false;
        match &pending {
            SMTPServerPending::Command(SMTPCommand::Ehlo(domain) | SMTPCommand::Helo(domain)) if positive => {
                self.reset();
                let extended = matches!(pending, SMTPServerPending::Command(SMTPCommand::Ehlo(_)));
                self.hello = Some((domain.clone(), extended));
                if extended {
                    let mut lines = reply.lines;
                    lines.truncate(1);
                    lines.extend(self.extensions().entries.iter().map(SMTPExtension::line));
                    reply = SMTPReply { code: reply.code, lines };
                }
            }
            SMTPServerPending::Command(SMTPCommand::Mail { path, parameters }) if positive => {
                self.transaction = Some(SMTPServerTransaction {
                    reverse_path: path.clone(),
                    parameters: parameters.clone(),
                    recipients: 0,
                    size: 0,
                    chunked: false,
                    failed: false,
                });
            }
            SMTPServerPending::Command(SMTPCommand::Rcpt { .. }) if positive => {
                if let Some(transaction) = &mut self.transaction {
                    transaction.recipients += 1;
                }
            }
            SMTPServerPending::Command(SMTPCommand::Data) if reply.code == 354 => {
                let maximum = match self.server.maximum_message_size {
                    0 => u64::MAX,
                    maximum => maximum,
                };
                self.phase = SMTPServerPhase::Data(SMTPDataReader::new(maximum, self.config.maximum_text_line));
            }
            SMTPServerPending::DataEnd => self.transaction = None,
            SMTPServerPending::ChunkEnd { last } => {
                if *last {
                    self.transaction = None;
                } else if !positive && let Some(transaction) = &mut self.transaction {
                    transaction.failed = true;
                }
            }
            SMTPServerPending::Command(SMTPCommand::Auth { .. }) | SMTPServerPending::AuthResponse
                if reply.code == 235 =>
            {
                self.authenticated = true;
            }
            SMTPServerPending::Command(SMTPCommand::StartTLS) if reply.code == 220 => tls = true,
            _ => {}
        }
        reply.encode(&mut self.output);
        if tls {
            // RFC 3207 §4.2 and CVE-2011-0411: what the client sent after STARTTLS is discarded,
            // and the session begins again under TLS.
            self.input.clear();
            self.reset();
            self.hello = None;
            self.authenticated = false;
            self.secure = true;
            self.events.push_back(SMTPServerEvent::StartTLS);
        }
        if reply.code == 421 {
            self.close(None);
        }
        self.process(now);
        Ok(())
    }

    /// Abandons the mail transaction, telling it if there was one.
    pub fn reset(&mut self) {
        if self.transaction.take().is_some() {
            self.events.push_back(SMTPServerEvent::Reset);
        }
    }

    /// Closes the connection with 421 and `text` (RFC 5321 §3.8): for shutting down. Fails for a
    /// text that cannot be written, a line break in it.
    pub fn shutdown(&mut self, text: &str) -> Result<(), SMTPError> {
        let reply = self.reply_of(421, SMTPEnhancedStatus::new(4, 3, 2), text);
        reply.check()?;
        if self.is_open() {
            reply.encode(&mut self.output);
            self.close(None);
        }
        Ok(())
    }

    /// Appends what is to be sent to `out`.
    pub fn transmit(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.output);
    }

    pub fn poll_event(&mut self) -> Option<SMTPServerEvent> {
        self.events.pop_front()
    }

    /// When the server stops waiting for the client, if it waits for it.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.deadline
    }

    /// Closes the connection with 421 if the client was silent past its time (RFC 5321 §4.5.3.2.7).
    pub fn expire(&mut self, now: Instant) {
        if self.deadline.is_some_and(|deadline| deadline <= now) && self.is_open() {
            self.answer(421, SMTPEnhancedStatus::new(4, 4, 2), "Timeout, closing the connection");
            self.close(Some(SMTPError::Timeout));
        }
    }

    pub fn close(&mut self, error: Option<SMTPError>) {
        if !self.is_open() {
            return;
        }
        self.phase = SMTPServerPhase::Closed;
        self.pending = None;
        self.deadline = None;
        self.events.push_back(SMTPServerEvent::Closed { error });
    }
}
