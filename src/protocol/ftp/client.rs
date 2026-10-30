use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::{FTPCommand, FTPConfig, FTPError, FTPFeatures, FTPReply, FTPReplyReader};
use crate::bytes::LineBuffer;
use crate::runtime::Instant;

/// What an [`FTPClient`] tells its user.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FTPClientEvent {
    /// The greeting: 220 (after 120, a delay, if any), or 421.
    Greeting(FTPReply),
    /// A preliminary reply (1xx) of a command: its final reply follows (RFC 959 §4.2).
    Preliminary {
        command: FTPCommand,
        reply: FTPReply,
    },
    /// The final reply of a command.
    Reply {
        command: FTPCommand,
        reply: FTPReply,
    },
    /// The server is ready for TLS on the control connection (234 to AUTH TLS, RFC 4217 §4):
    /// start it before anything else; the features are forgotten.
    StartTLS,
    /// The control connection is clear again (200 to CCC, RFC 4217 §6): TLS is to be closed on it.
    ClearCommandChannel,
    Closed {
        error: Option<FTPError>,
    },
}

/// An FTP client of the control connection, without I/O (RFC 959): feed
/// it what the server sends with [`FTPClient::receive`], send what
/// [`FTPClient::transmit`] gives, and answer its events. Commands are sent
/// one at a time (§5.4), but ABOR, STAT and QUIT during a transfer; the
/// data connections are the user's, at the addresses of
/// [`FTPDataAddress`](super::FTPDataAddress).
#[derive(Clone, Debug)]
pub struct FTPClient {
    pub config: FTPConfig,
    pub input: LineBuffer,
    pub reader: FTPReplyReader,
    pub output: Vec<u8>,
    pub events: VecDeque<FTPClientEvent>,
    pub queued: VecDeque<FTPCommand>,
    /// The commands sent, waiting for their final replies, with the time they wait until
    /// (none after the preliminary reply of a transfer), and whether a preliminary came.
    pub sent: VecDeque<(FTPCommand, Option<Instant>, bool)>,
    pub greeted: bool,
    pub greeting_deadline: Option<Instant>,
    /// The features of the last reply to FEAT; `None` before it, or after TLS began.
    pub features: Option<FTPFeatures>,
    /// USER was answered 331 or 332: PASS (or ACCT) is next.
    pub user_accepted: bool,
    pub logged_in: bool,
    /// RNFR was answered 350: RNTO is next.
    pub rename_ready: bool,
    /// TLS is on the control connection: implicitly, or after AUTH TLS.
    pub secure: bool,
    /// PBSZ was answered 200: PROT may follow (RFC 4217 §8).
    pub buffer_size_set: bool,
    pub closed: bool,
}

impl FTPClient {
    /// A client of a new control connection, waiting for the greeting; `secure` if it is TLS from
    /// its start (implicit FTPS).
    pub fn new(config: FTPConfig, secure: bool, now: Instant) -> Result<FTPClient, FTPError> {
        config.check()?;
        Ok(FTPClient {
            config,
            input: LineBuffer::new(),
            reader: FTPReplyReader::new(),
            output: Vec::new(),
            events: VecDeque::new(),
            queued: VecDeque::new(),
            sent: VecDeque::new(),
            greeted: false,
            greeting_deadline: Some(now.saturating_add(config.reply_timeout)),
            features: None,
            user_accepted: false,
            logged_in: false,
            rename_ready: false,
            secure,
            buffer_size_set: false,
            closed: false,
        })
    }

    pub fn is_open(&self) -> bool {
        !self.closed
    }

    /// Whether the server listed `name` in its reply to FEAT.
    pub fn has_feature(&self, name: &str) -> bool {
        self.features.as_ref().is_some_and(|features| features.has(name))
    }

    pub fn receive(&mut self, bytes: &[u8], now: Instant) -> Result<(), FTPError> {
        if self.closed {
            return Err(FTPError::Closed);
        }
        self.input.push(bytes);
        loop {
            let maximum = self.config.maximum_line;
            let line = match self.input.line(maximum) {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(_) => return self.fail(FTPError::TooLong { length: maximum + 1, maximum }),
            };
            let reply = match self.reader.push(&line, self.config.maximum_reply_lines) {
                Ok(Some(reply)) => reply,
                Ok(None) => continue,
                Err(error) => return self.fail(error),
            };
            let tls = self.handle(reply, now)?;
            if tls || self.closed {
                // RFC 4217 §4 and CVE-2011-0411: what came before TLS is not believed after it.
                self.input.clear();
                break;
            }
        }
        if self.input.len() > self.config.maximum_buffered {
            return self.fail(FTPError::TooLong { length: self.input.len(), maximum: self.config.maximum_buffered });
        }
        self.pump(now);
        Ok(())
    }

    /// Handles a reply; whether TLS is to start.
    pub fn handle(&mut self, reply: FTPReply, now: Instant) -> Result<bool, FTPError> {
        if !self.greeted {
            // 120 tells of a delay; 220 follows it (RFC 959 §5.4).
            if reply.code == 120 {
                return Ok(false);
            }
            self.greeted = true;
            self.greeting_deadline = None;
            let closing = reply.code != 220;
            self.events.push_back(FTPClientEvent::Greeting(reply));
            if closing {
                self.close(None);
            }
            return Ok(false);
        }
        if self.sent.is_empty() {
            if reply.code == 421 {
                self.close(None);
                return Ok(false);
            }
            return self.fail(FTPError::Syntax { reason: "a reply to no command" });
        }
        // A preliminary reply is of the oldest command that has had none; a final one of the oldest.
        if reply.is_preliminary() {
            let Some((command, deadline, preliminary)) = self.sent.iter_mut().find(|(_, _, preliminary)| !*preliminary)
            else {
                return self.fail(FTPError::Syntax { reason: "a second preliminary reply" });
            };
            *preliminary = true;
            // A transfer takes what time it takes.
            *deadline = None;
            let command = command.clone();
            self.events.push_back(FTPClientEvent::Preliminary { command, reply });
            return Ok(false);
        }
        // RFC 959 §4.1.3: STAT during a transfer is answered during it (211 to 213), before the
        // transfer's own final reply.
        let transferring =
            self.sent.front().is_some_and(|(command, _, preliminary)| *preliminary && command.transfers());
        let status = (211..=213)
            .contains(&reply.code)
            .then(|| self.sent.iter().position(|(command, _, _)| matches!(command, FTPCommand::Stat(None))));
        if transferring && let Some(Some(index)) = status {
            if let Some((command, _, _)) = self.sent.remove(index) {
                self.events.push_back(FTPClientEvent::Reply { command, reply });
            }
            return Ok(false);
        }
        let Some((command, _, _)) = self.sent.pop_front() else { return Ok(false) };
        let positive = reply.is_positive();
        let mut tls = false;
        match &command {
            FTPCommand::User(_) => {
                self.user_accepted = matches!(reply.code, 331 | 332);
                self.logged_in = reply.code == 230;
            }
            FTPCommand::Pass(_) | FTPCommand::Acct(_) => {
                self.user_accepted = reply.code == 332;
                self.logged_in = matches!(reply.code, 230 | 202);
            }
            // RFC 959 §4.1.1 and RFC 4217 §13: REIN ends the session as after the greeting, TLS
            // of the control connection too.
            FTPCommand::Rein if positive => {
                self.logged_in = false;
                self.user_accepted = false;
                self.rename_ready = false;
                self.buffer_size_set = false;
            }
            FTPCommand::Rnfr(_) => self.rename_ready = reply.code == 350,
            FTPCommand::Rnto(_) => self.rename_ready = false,
            FTPCommand::Feat if reply.code == 211 => self.features = FTPFeatures::from_reply(&reply).ok(),
            FTPCommand::Auth(_) if reply.code == 234 => {
                tls = true;
                self.secure = true;
                self.features = None;
                // RFC 4217 §4: the user authorizes again under TLS.
                self.logged_in = false;
                self.user_accepted = false;
                self.rename_ready = false;
            }
            FTPCommand::Pbsz(_) => self.buffer_size_set = positive,
            FTPCommand::Ccc if positive => {
                self.secure = false;
                self.buffer_size_set = false;
            }
            _ => {}
        }
        let clear =
            (matches!(command, FTPCommand::Ccc) || (matches!(command, FTPCommand::Rein) && self.secure)) && positive;
        if clear {
            self.secure = false;
        }
        let closing = reply.code == 421 || (matches!(command, FTPCommand::Quit) && reply.code == 221);
        self.events.push_back(FTPClientEvent::Reply { command, reply });
        if tls {
            self.events.push_back(FTPClientEvent::StartTLS);
        }
        if clear {
            self.events.push_back(FTPClientEvent::ClearCommandChannel);
        }
        if closing {
            self.close(None);
        }
        let _ = now;
        Ok(tls)
    }

    /// Queues `command`, to be sent in order. Fails, sending nothing, for PASS not after an
    /// accepted USER (RFC 959 §5.4), RNTO not after an accepted RNFR, AUTH, PBSZ, PROT and CCC out of
    /// their order or not listed by FEAT (RFC 4217), a feature of RFC 3659 or RFC 7151 FEAT did not
    /// list (when it was sent).
    pub fn send(&mut self, command: FTPCommand, now: Instant) -> Result<(), FTPError> {
        // A command that cannot be written as its one line (a line break in an argument) is
        // refused here, before anything is queued.
        command.encode(&mut Vec::new())?;
        self.check(&command)?;
        self.queued.push_back(command);
        self.pump(now);
        Ok(())
    }

    pub fn check(&self, command: &FTPCommand) -> Result<(), FTPError> {
        let state = |reason| Err(FTPError::State { reason });
        if self.closed {
            return Err(FTPError::Closed);
        }
        if !self.greeted {
            return state("no greeting yet");
        }
        let listed = |name: &str| self.features.as_ref().is_none_or(|features| features.has(name));
        match command {
            FTPCommand::Pass(_) if !self.user_accepted && !self.waiting("USER") => {
                state("PASS not after an accepted USER")
            }
            FTPCommand::Rnto(_) if !self.rename_ready && !self.waiting("RNFR") => {
                state("RNTO not after an accepted RNFR")
            }
            FTPCommand::Auth(mechanism) => {
                if self.secure {
                    return state("TLS is already in use");
                }
                match self.features.as_ref().is_none_or(|features| features.has_auth(mechanism)) {
                    true => Ok(()),
                    false => state("AUTH of a mechanism FEAT did not list"),
                }
            }
            FTPCommand::Pbsz(_) | FTPCommand::Ccc if !self.secure && !self.waiting("AUTH") => {
                state("PBSZ and CCC only under TLS")
            }
            FTPCommand::Prot(_) if !self.buffer_size_set && !self.waiting("PBSZ") => state("PROT not after PBSZ"),
            FTPCommand::Ccc if !listed("CCC") => state("CCC not listed by FEAT"),
            FTPCommand::Size(_) if !listed("SIZE") => state("SIZE not listed by FEAT"),
            FTPCommand::Mdtm(_) if !listed("MDTM") => state("MDTM not listed by FEAT"),
            FTPCommand::Mlst(_) | FTPCommand::Mlsd(_) if !listed("MLST") => state("MLST not listed by FEAT"),
            FTPCommand::Host(_) if !listed("HOST") || self.logged_in => {
                state("HOST not listed by FEAT, or after login")
            }
            FTPCommand::Lang(_) if !listed("LANG") => state("LANG not listed by FEAT"),
            _ => Ok(()),
        }
    }

    /// Whether a command of `verb` is queued or waits for its reply.
    pub fn waiting(&self, verb: &str) -> bool {
        self.queued.iter().chain(self.sent.iter().map(|(command, _, _)| command)).any(|command| command.verb() == verb)
    }

    /// Sends what may be sent: the next command when none waits for its reply; ABOR, STAT and
    /// QUIT also while a transfer is in progress (RFC 959 §4.1.3).
    pub fn pump(&mut self, now: Instant) {
        while let Some(next) = self.queued.front() {
            let transferring = self.sent.iter().all(|(command, _, preliminary)| command.transfers() && *preliminary);
            let during = matches!(next, FTPCommand::Abor | FTPCommand::Stat(None) | FTPCommand::Quit);
            if self.closed || !self.greeted || !(self.sent.is_empty() || (transferring && during)) {
                break;
            }
            let Some(command) = self.queued.pop_front() else { break };
            if let Err(error) = command.encode(&mut self.output) {
                self.close(Some(error));
                break;
            }
            self.sent.push_back((command, Some(now.saturating_add(self.config.reply_timeout)), false));
        }
    }

    pub fn transmit(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.output);
    }

    pub fn poll_event(&mut self) -> Option<FTPClientEvent> {
        self.events.pop_front()
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.closed {
            return None;
        }
        self.greeting_deadline.into_iter().chain(self.sent.iter().filter_map(|(_, deadline, _)| *deadline)).min()
    }

    pub fn expire(&mut self, now: Instant) {
        if self.poll_timeout().is_some_and(|deadline| deadline <= now) {
            self.close(Some(FTPError::Timeout));
        }
    }

    pub fn close(&mut self, error: Option<FTPError>) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.queued.clear();
        self.sent.clear();
        self.events.push_back(FTPClientEvent::Closed { error });
    }

    pub fn fail<T>(&mut self, error: FTPError) -> Result<T, FTPError> {
        self.close(Some(error));
        Err(error)
    }
}
