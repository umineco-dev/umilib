use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::time::Duration;

use super::{
    SMTPCommand, SMTPConfig, SMTPData, SMTPError, SMTPExtensions, SMTPParameter, SMTPPath, SMTPReply, SMTPReplyReader,
};
use crate::bytes::LineBuffer;
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::runtime::Instant;

/// What an [`SMTPClient`] tells its user.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SMTPClientEvent {
    /// The server's greeting: 220, or 554 if it takes no mail, after which the client SHOULD
    /// QUIT (RFC 5321 §3.1).
    Greeting(SMTPReply),
    /// The reply to a command.
    Reply { command: SMTPCommand, reply: SMTPReply },
    /// The reply to the end of the mail data of DATA.
    DataReply(SMTPReply),
    /// A challenge of an AUTH exchange, decoded (RFC 4954 §4); answer it with
    /// [`SMTPClient::auth_respond`] or [`SMTPClient::auth_cancel`].
    AuthChallenge(Vec<u8>),
    /// The server is ready for TLS (RFC 3207 §4): start it before anything else is sent; what
    /// was known of the server is forgotten, and the next command SHOULD be EHLO (§4.2).
    StartTLS,
    /// The connection is closed: after 221, after 421 (§3.8), or after an error.
    Closed { error: Option<SMTPError> },
}

/// What a sent command waits for: the reply to a command, or to the end of mail data.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SMTPClientPending {
    Command(SMTPCommand),
    Data,
}

/// What a client sent and waits for the reply to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SMTPClientSent {
    pub pending: SMTPClientPending,
    /// When its reply is late: its time from when the reply before it came (RFC 5321
    /// §4.5.3.2 times each reply), so that pipelined commands do not share one.
    pub deadline: Instant,
    pub timeout: Duration,
    /// The number of the transaction it was sent in.
    pub transaction: u64,
}

/// The mail transaction a client has begun: the parameters of its MAIL.
/// It ends when its data is sent, or with RSET or EHLO; a MAIL refused ends
/// it, a DATA or a chunk refused does not (the server may hold it, and
/// RSET ends it, RFC 2920 §3.1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SMTPClientTransaction {
    /// Its number: of the MAIL that began it.
    pub number: u64,
    /// The BODY parameter, in upper case (RFC 6152, RFC 3030).
    pub body: Option<alloc::string::String>,
    pub smtputf8: bool,
    /// A chunk was refused: no more are sent (RFC 3030 §2).
    pub failed: bool,
}

/// An SMTP client without I/O (RFC 5321): feed it what the server sends
/// with [`SMTPClient::receive`], send what [`SMTPClient::transmit`] gives,
/// and answer its events. Commands are sent in order, pipelined when the
/// server advertises PIPELINING (RFC 2920); a command of an extension is
/// sent only if the server advertised the extension.
#[derive(Clone, Debug)]
pub struct SMTPClient {
    pub config: SMTPConfig,
    pub input: LineBuffer,
    pub reader: SMTPReplyReader,
    pub output: Vec<u8>,
    pub events: VecDeque<SMTPClientEvent>,
    /// Commands not yet sent, each with the octets that follow its line (a BDAT chunk) and the
    /// number of the transaction it was queued in.
    pub queued: VecDeque<(SMTPCommand, Vec<u8>, u64)>,
    /// What was sent and waits for its reply, in order.
    pub sent: VecDeque<SMTPClientSent>,
    /// The number of the last transaction begun.
    pub transactions: u64,
    /// The extensions of the last reply to EHLO; `None` before it.
    pub extensions: Option<SMTPExtensions>,
    /// The transaction begun by the last MAIL sent, if any.
    pub transaction: Option<SMTPClientTransaction>,
    /// The greeting was received.
    pub greeted: bool,
    /// The deadline of the greeting.
    pub greeting_deadline: Option<Instant>,
    /// The server answered DATA with 354: [`SMTPClient::send_data`] is next.
    pub data_ready: bool,
    /// An AUTH challenge waits for its response.
    pub authenticating: bool,
    /// The initial response of an AUTH too long for its line, sent for the first empty challenge.
    pub held_response: Option<Vec<u8>>,
    /// TLS is in use: implicitly (RFC 8314) or after STARTTLS.
    pub secure: bool,
    pub closed: bool,
}

impl SMTPClient {
    /// A client of a new connection, waiting for the greeting; `secure` if
    /// the connection is TLS from its start (RFC 8314 §3.3).
    pub fn new(config: SMTPConfig, secure: bool, now: Instant) -> Result<SMTPClient, SMTPError> {
        config.check()?;
        Ok(SMTPClient {
            config,
            input: LineBuffer::new(),
            reader: SMTPReplyReader::new(),
            output: Vec::new(),
            events: VecDeque::new(),
            queued: VecDeque::new(),
            sent: VecDeque::new(),
            transactions: 0,
            extensions: None,
            transaction: None,
            greeted: false,
            greeting_deadline: Some(now.saturating_add(config.greeting_timeout)),
            data_ready: false,
            authenticating: false,
            held_response: None,
            secure,
            closed: false,
        })
    }

    pub fn is_open(&self) -> bool {
        !self.closed
    }

    /// Whether the server advertised `keyword` in its last reply to EHLO.
    pub fn has_extension(&self, keyword: &str) -> bool {
        self.extensions.as_ref().is_some_and(|extensions| extensions.has(keyword))
    }

    /// Takes what the server sent.
    pub fn receive(&mut self, bytes: &[u8], now: Instant) -> Result<(), SMTPError> {
        if self.closed {
            return Err(SMTPError::Closed);
        }
        self.input.push(bytes);
        loop {
            let maximum = self.config.maximum_reply_line;
            let line = match self.input.line(maximum) {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(_) => return self.fail(SMTPError::TooLong { length: maximum + 1, maximum }),
            };
            let reply = match self.reader.push(&line, self.config.maximum_reply_lines) {
                Ok(Some(reply)) => reply,
                Ok(None) => continue,
                Err(error) => return self.fail(error),
            };
            let tls = self.handle(reply, now)?;
            if tls || self.closed {
                // RFC 3207 §4.2 and CVE-2011-0411: what the server sent before TLS and after its
                // 220 is not to be believed.
                self.input.clear();
                break;
            }
        }
        if self.input.len() > self.config.maximum_buffered {
            return self.fail(SMTPError::TooLong { length: self.input.len(), maximum: self.config.maximum_buffered });
        }
        self.pump(now);
        Ok(())
    }

    /// Handles a reply; whether TLS is to start.
    pub fn handle(&mut self, reply: SMTPReply, now: Instant) -> Result<bool, SMTPError> {
        if !self.greeted {
            self.greeted = true;
            self.greeting_deadline = None;
            let closing = reply.code == 421;
            self.events.push_back(SMTPClientEvent::Greeting(reply));
            if closing {
                self.close(None);
            }
            return Ok(false);
        }
        let Some(sent) = self.sent.pop_front() else {
            if reply.code == 421 {
                self.close(None);
                return Ok(false);
            }
            return self.fail(SMTPError::Syntax { reason: "a reply to no command" });
        };
        if let Some(next) = self.sent.front_mut() {
            next.deadline = now.saturating_add(next.timeout);
        }
        let current = self.transaction.as_ref().is_some_and(|transaction| transaction.number == sent.transaction);
        let command = match sent.pending {
            SMTPClientPending::Data => {
                let closing = reply.code == 421;
                self.events.push_back(SMTPClientEvent::DataReply(reply));
                if closing {
                    self.close(None);
                }
                return Ok(false);
            }
            SMTPClientPending::Command(command) => command,
        };
        if reply.code == 334 && matches!(command, SMTPCommand::Auth { .. }) {
            let challenge = reply.lines.first().map(Vec::as_slice).unwrap_or_default();
            let timeout = self.config.command_timeout;
            self.sent.push_front(SMTPClientSent {
                pending: SMTPClientPending::Command(command),
                deadline: now.saturating_add(timeout),
                timeout,
                transaction: sent.transaction,
            });
            let Ok(challenge) = Base64::STANDARD.decode(challenge) else {
                // RFC 4954 §4: a challenge that is not base64 MUST be cancelled.
                self.output.extend_from_slice(b"*\r\n");
                return Ok(false);
            };
            match self.held_response.take() {
                Some(response) if challenge.is_empty() => self.write_response(&response),
                _ => {
                    self.authenticating = true;
                    self.events.push_back(SMTPClientEvent::AuthChallenge(challenge));
                }
            }
            return Ok(false);
        }
        let positive = reply.is_positive();
        let mut tls = false;
        match &command {
            SMTPCommand::Ehlo(_) if positive => match SMTPExtensions::from_reply(&reply) {
                Ok(extensions) => self.extensions = Some(extensions),
                // RFC 5321 §4.1.1.1: the reply of success to EHLO is 250.
                Err(error) => return self.fail(error),
            },
            SMTPCommand::Helo(_) if positive => self.extensions = Some(SMTPExtensions::default()),
            SMTPCommand::Mail { .. } if !positive && current => self.transaction = None,
            SMTPCommand::Data if reply.code == 354 => self.data_ready = true,
            SMTPCommand::Bdat { .. } if !positive && current => {
                if let Some(transaction) = &mut self.transaction {
                    transaction.failed = true;
                }
            }
            SMTPCommand::Auth { .. } => {
                self.authenticating = false;
                self.held_response = None;
            }
            SMTPCommand::StartTLS if reply.code == 220 => {
                tls = true;
                self.secure = true;
                self.extensions = None;
                self.transaction = None;
            }
            _ => {}
        }
        let closing = reply.code == 421 || (matches!(command, SMTPCommand::Quit) && reply.code == 221);
        self.events.push_back(SMTPClientEvent::Reply { command, reply });
        if tls {
            self.events.push_back(SMTPClientEvent::StartTLS);
        }
        if closing {
            self.close(None);
        }
        Ok(tls)
    }

    /// Queues `command`, to be sent in order. Fails, sending nothing, for
    /// a command out of sequence (RFC 5321 §4.1.4) and for one of an
    /// extension the server did not advertise: STARTTLS (and never under
    /// TLS, RFC 3207 §4.2), AUTH and its mechanism (RFC 4954 §4), and the
    /// parameters of SIZE, BODY, SMTPUTF8, DSN and AUTH; a declared SIZE
    /// larger than the server's (RFC 1870 §6); a mailbox of UTF-8 without
    /// SMTPUTF8 (RFC 6531 §3.4). Chunks are sent with [`SMTPClient::send_chunk`].
    pub fn send(&mut self, command: SMTPCommand, now: Instant) -> Result<(), SMTPError> {
        command.check()?;
        self.check(&command)?;
        match &command {
            SMTPCommand::Mail { parameters, .. } => {
                let body = SMTPParameter::find(parameters, "BODY").and_then(|parameter| parameter.value.as_deref());
                let smtputf8 = SMTPParameter::find(parameters, "SMTPUTF8").is_some();
                self.transactions += 1;
                let number = self.transactions;
                self.transaction = Some(SMTPClientTransaction {
                    number,
                    body: body.map(str::to_ascii_uppercase),
                    smtputf8,
                    failed: false,
                });
            }
            SMTPCommand::Rset | SMTPCommand::Ehlo(_) | SMTPCommand::Helo(_) => self.transaction = None,
            _ => {}
        }
        let command = match command {
            // RFC 4954 §4: an initial response that makes the line too long is sent for the
            // first empty challenge instead.
            SMTPCommand::Auth { mechanism, initial: Some(initial) }
                if mechanism.len()
                    + Base64::STANDARD.maximum_encoded_length(initial.len()).unwrap_or(usize::MAX)
                    + b"AUTH  \r\n".len()
                    > self.config.maximum_command_line =>
            {
                self.held_response = Some(initial);
                SMTPCommand::Auth { mechanism, initial: None }
            }
            command => command,
        };
        self.queued.push_back((command, Vec::new(), self.transactions));
        self.pump(now);
        Ok(())
    }

    /// Whether `verb` is queued or waits for its reply.
    pub fn waiting(&self, verb: &str) -> bool {
        self.queued.iter().any(|(queued, _, _)| queued.verb() == verb)
            || self
                .sent
                .iter()
                .any(|sent| matches!(&sent.pending, SMTPClientPending::Command(command) if command.verb() == verb))
    }

    /// Checks that a command may be queued now: the connection is open and
    /// greeted, and neither the data of DATA, an AUTH response nor the reply
    /// to STARTTLS is awaited.
    pub fn check_ready(&self) -> Result<(), SMTPError> {
        let state = |reason| Err(SMTPError::State { reason });
        if self.closed {
            return Err(SMTPError::Closed);
        }
        if !self.greeted {
            return state("no greeting yet");
        }
        if self.data_ready {
            return state("the mail data of DATA is next");
        }
        if self.authenticating {
            return state("an AUTH challenge waits for its response");
        }
        if self.waiting("STARTTLS") {
            return state("STARTTLS waits for its reply");
        }
        Ok(())
    }

    /// Checks that `command` may be queued now.
    pub fn check(&self, command: &SMTPCommand) -> Result<(), SMTPError> {
        let state = |reason| Err(SMTPError::State { reason });
        self.check_ready()?;
        let waiting = |verb: &str| self.waiting(verb);
        let hello = waiting("EHLO") || waiting("HELO");
        let extension =
            |keyword: &str| self.extensions.as_ref().is_some_and(|extensions| extensions.has(keyword)) && !hello;
        let utf8 = self.transaction.as_ref().is_some_and(|transaction| transaction.smtputf8);
        match command {
            SMTPCommand::Bdat { .. } => state("a chunk is sent with send_chunk"),
            SMTPCommand::StartTLS if self.secure => state("TLS is already in use"),
            SMTPCommand::StartTLS if !extension("STARTTLS") => state("STARTTLS not advertised"),
            SMTPCommand::Auth { mechanism, .. } => {
                let advertised = !hello
                    && self.extensions.as_ref().is_some_and(|extensions| {
                        extensions.auth_mechanisms().iter().any(|name| name.eq_ignore_ascii_case(mechanism))
                    });
                if self.transaction.is_some() {
                    return state("AUTH in a mail transaction");
                }
                if !advertised {
                    return state("AUTH or its mechanism not advertised");
                }
                let plaintext = ["PLAIN", "LOGIN"].iter().any(|plain| plain.eq_ignore_ascii_case(mechanism));
                if plaintext && self.config.passwords_require_tls && !self.secure {
                    return state("a password as it is without TLS (RFC 2595 §2.3)");
                }
                Ok(())
            }
            SMTPCommand::Mail { path, parameters } => {
                if self.extensions.is_none() && !hello {
                    return state("MAIL before EHLO or HELO (RFC 5321 §4.1.4)");
                }
                if self.transaction.is_some() {
                    return state("MAIL in a mail transaction");
                }
                let smtputf8 = SMTPParameter::find(parameters, "SMTPUTF8").is_some();
                for parameter in parameters {
                    let keyword = parameter.keyword.as_str();
                    let value = parameter.value.as_deref();
                    let advertised = match keyword {
                        "SIZE" => extension("SIZE"),
                        "BODY" => match value.map(str::to_ascii_uppercase).as_deref() {
                            Some("7BIT") => true,
                            Some("8BITMIME") => extension("8BITMIME"),
                            Some("BINARYMIME") => extension("BINARYMIME") && extension("CHUNKING"),
                            _ => return state("not a BODY of RFC 6152 or RFC 3030"),
                        },
                        "SMTPUTF8" => extension("SMTPUTF8") && value.is_none(),
                        "RET" | "ENVID" => extension("DSN"),
                        "AUTH" => extension("AUTH"),
                        _ => extension(keyword),
                    };
                    if !advertised {
                        return state("a MAIL parameter of an extension not advertised");
                    }
                }
                if let (Some(size), Some(maximum)) = (
                    SMTPParameter::find(parameters, "SIZE").and_then(|size| size.value.as_deref()?.parse::<u64>().ok()),
                    self.extensions.as_ref().and_then(SMTPExtensions::size),
                ) && maximum > 0
                    && size > maximum
                {
                    return Err(SMTPError::TooLarge { size, maximum });
                }
                if path.mailbox().is_some_and(super::SMTPMailbox::is_utf8) && !smtputf8 {
                    return state("a mailbox of UTF-8 without SMTPUTF8");
                }
                Ok(())
            }
            SMTPCommand::Rcpt { path, parameters } => {
                if self.transaction.is_none() {
                    return state("RCPT without MAIL");
                }
                for parameter in parameters {
                    let advertised = match parameter.keyword.as_str() {
                        "NOTIFY" | "ORCPT" => extension("DSN"),
                        keyword => extension(keyword),
                    };
                    if !advertised {
                        return state("an RCPT parameter of an extension not advertised");
                    }
                }
                if matches!(path, SMTPPath::Mailbox(mailbox) if mailbox.is_utf8()) && !utf8 {
                    return state("a mailbox of UTF-8 without SMTPUTF8");
                }
                Ok(())
            }
            SMTPCommand::Data => match &self.transaction {
                None => state("DATA without MAIL"),
                Some(transaction) if transaction.body.as_deref() == Some("BINARYMIME") => {
                    state("BINARYMIME is sent with BDAT (RFC 3030 §3)")
                }
                Some(_) => Ok(()),
            },
            _ => Ok(()),
        }
    }

    /// Sends the message after the server's 354 to DATA, as mail data
    /// (RFC 5321 §4.5.2). Fails for a message of a CR or an LF alone, of a
    /// line longer than 1000 octets (§4.5.3.1.6), or of 8-bit octets where
    /// neither BODY=8BITMIME nor SMTPUTF8 was given (RFC 6152 §3).
    pub fn send_data(&mut self, message: &[u8], now: Instant) -> Result<(), SMTPError> {
        if self.closed {
            return Err(SMTPError::Closed);
        }
        if !self.data_ready {
            return Err(SMTPError::State { reason: "no 354 reply to DATA" });
        }
        let transaction = self.transaction.clone().unwrap_or_default();
        let eight_bit = transaction.body.as_deref() == Some("8BITMIME") || transaction.smtputf8;
        if !eight_bit && !SMTPData::is_seven_bit(message) {
            return Err(SMTPError::Content { reason: "8-bit data without BODY=8BITMIME" });
        }
        SMTPData::encode(message, self.config.maximum_text_line, &mut self.output)?;
        self.data_ready = false;
        // The transaction is over when its data is sent; a later MAIL may be pipelined (RFC 2920 §3.1).
        self.transaction = None;
        let timeout = self.config.data_termination_timeout;
        self.sent.push_back(SMTPClientSent {
            pending: SMTPClientPending::Data,
            deadline: now.saturating_add(timeout),
            timeout,
            transaction: transaction.number,
        });
        self.pump(now);
        Ok(())
    }

    /// Sends a chunk of the message (RFC 3030 §2): `BDAT size [LAST]` and
    /// its octets as they are. Needs CHUNKING and a mail transaction.
    pub fn send_chunk(&mut self, data: &[u8], last: bool, now: Instant) -> Result<(), SMTPError> {
        let command = SMTPCommand::Bdat { size: data.len() as u64, last };
        self.check_ready()?;
        if !self.has_extension("CHUNKING") || self.waiting("EHLO") || self.waiting("HELO") {
            return Err(SMTPError::State { reason: "CHUNKING not advertised" });
        }
        let Some(transaction) = &self.transaction else {
            return Err(SMTPError::State { reason: "BDAT without MAIL" });
        };
        if transaction.failed {
            return Err(SMTPError::State { reason: "a chunk of the transaction was refused" });
        }
        let binary = transaction.body.as_deref() == Some("BINARYMIME");
        let eight_bit = binary || transaction.body.as_deref() == Some("8BITMIME") || transaction.smtputf8;
        if !eight_bit && !SMTPData::is_seven_bit(data) {
            return Err(SMTPError::Content { reason: "8-bit data without BODY=8BITMIME" });
        }
        let number = transaction.number;
        if last {
            // The transaction is over when the last chunk is sent; a later MAIL may be pipelined.
            self.transaction = None;
        }
        self.queued.push_back((command, data.to_vec(), number));
        self.pump(now);
        Ok(())
    }

    /// Answers an AUTH challenge with `response` (RFC 4954 §4).
    pub fn auth_respond(&mut self, response: &[u8], now: Instant) -> Result<(), SMTPError> {
        if !self.authenticating {
            return Err(SMTPError::State { reason: "no AUTH challenge" });
        }
        self.authenticating = false;
        self.write_response(response);
        self.pump(now);
        Ok(())
    }

    /// Cancels an AUTH exchange: `*`, which the server rejects with 501 (RFC 4954 §4).
    pub fn auth_cancel(&mut self, now: Instant) -> Result<(), SMTPError> {
        if !self.authenticating {
            return Err(SMTPError::State { reason: "no AUTH challenge" });
        }
        self.authenticating = false;
        self.output.extend_from_slice(b"*\r\n");
        self.pump(now);
        Ok(())
    }

    /// Writes a response of an AUTH exchange: base64, or nothing for an empty one.
    pub fn write_response(&mut self, response: &[u8]) {
        self.output.extend_from_slice(Base64::STANDARD.encode(response).as_bytes());
        self.output.extend_from_slice(b"\r\n");
    }

    /// Sends the queued commands that may be sent: after the greeting and
    /// the 354 of DATA, while no challenge waits, and, without
    /// PIPELINING, one at a time; with it, after the last command of a
    /// group only when that command has its reply (RFC 2920 §3.1).
    pub fn pump(&mut self, now: Instant) {
        let pipelining = self.has_extension("PIPELINING");
        while let Some((command, _, _)) = self.queued.front() {
            let blocked = match self.sent.back().map(|sent| &sent.pending) {
                None => false,
                Some(SMTPClientPending::Data) => !pipelining,
                Some(SMTPClientPending::Command(last)) => !pipelining || last.ends_group(),
            };
            if self.closed || !self.greeted || self.data_ready || self.authenticating || blocked {
                break;
            }
            let timeout = match command {
                SMTPCommand::Data => self.config.data_initiation_timeout,
                SMTPCommand::Bdat { last: true, .. } => self.config.data_termination_timeout,
                _ => self.config.command_timeout,
            };
            let Some((command, payload, transaction)) = self.queued.pop_front() else {
                break;
            };
            command.encode(&mut self.output);
            self.output.extend_from_slice(&payload);
            self.sent.push_back(SMTPClientSent {
                pending: SMTPClientPending::Command(command),
                deadline: now.saturating_add(timeout),
                timeout,
                transaction,
            });
        }
    }

    /// Appends what is to be sent to `out`.
    pub fn transmit(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.output);
    }

    pub fn poll_event(&mut self) -> Option<SMTPClientEvent> {
        self.events.pop_front()
    }

    /// When the client next times out, if it waits for anything.
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.closed {
            return None;
        }
        self.greeting_deadline.into_iter().chain(self.sent.front().map(|sent| sent.deadline)).min()
    }

    /// Times out what waits past `now`: the connection is closed (RFC 5321 §4.5.3.2).
    pub fn expire(&mut self, now: Instant) {
        if self.poll_timeout().is_some_and(|deadline| deadline <= now) {
            self.close(Some(SMTPError::Timeout));
        }
    }

    /// Closes the connection, telling why.
    pub fn close(&mut self, error: Option<SMTPError>) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.queued.clear();
        self.sent.clear();
        self.data_ready = false;
        self.authenticating = false;
        self.events.push_back(SMTPClientEvent::Closed { error });
    }

    /// Closes the connection for `error` and returns it.
    pub fn fail<T>(&mut self, error: SMTPError) -> Result<T, SMTPError> {
        self.close(Some(error));
        Err(error)
    }
}
