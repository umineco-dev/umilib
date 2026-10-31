use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use super::{FTPCommand, FTPConfig, FTPError, FTPFeature, FTPFeatures, FTPReply, FTPServerConfig};
use crate::bytes::LineBuffer;
use crate::protocol::ip::IPAddress;
use crate::runtime::Instant;

/// What an [`FTPServer`] tells its user.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FTPServerEvent {
    /// A command to answer with [`FTPServer::reply`]: a transfer with a preliminary reply (1xx)
    /// and then its final one. Commands the server answers itself (NOOP, FEAT, SYST, QUIT,
    /// TYPE, MODE, STRU, PBSZ, PROT, CCC, those out of sequence, before login, of a data
    /// address refused, of a feature not offered) are not told.
    Command(FTPCommand),
    /// The 234 to AUTH TLS was sent: start TLS on the control connection now. What the client
    /// sent before it is discarded (RFC 4217 §4, CVE-2011-0411).
    StartTLS,
    /// The 200 to CCC was sent: close TLS on the control connection (RFC 4217 §6).
    ClearCommandChannel,
    /// The connection is to be closed: after QUIT, a 421, the idle time, an error.
    Closed { error: Option<FTPError> },
}

/// An FTP server of the control connection, without I/O (RFC 959): feed
/// it what the client sends with [`FTPServer::receive`], send what
/// [`FTPServer::transmit`] gives, and answer its events. The files and the
/// data connections are the user's; the server keeps the session's state
/// and refuses what the protocol and the configuration refuse.
#[derive(Clone, Debug)]
pub struct FTPServer {
    pub config: FTPConfig,
    pub server: FTPServerConfig,
    /// The client's address: the only host PORT and EPRT may name (RFC 2577 §3).
    pub peer: IPAddress,
    pub input: LineBuffer,
    pub output: Vec<u8>,
    pub events: VecDeque<FTPServerEvent>,
    pub greeted: bool,
    pub closed: bool,
    /// The commands told and not yet given their final replies, in order, and whether a
    /// preliminary reply of each was sent: a transfer, and an ABOR told during it.
    pub pending: VecDeque<(FTPCommand, bool)>,
    /// QUIT came during a transfer: 221 follows the transfer's final reply (RFC 959 §4.1.1).
    pub quitting: bool,
    /// The name of a USER answered 331 or 332.
    pub user: Option<String>,
    pub logged_in: bool,
    /// RNFR was answered 350: RNTO may follow.
    pub rename_ready: bool,
    /// REST was answered 350: its marker, for the transfer that follows.
    pub restart: Option<String>,
    /// TLS is on the control connection.
    pub secure: bool,
    pub buffer_size_set: bool,
    /// The protection of data connections (RFC 4217 §9): C or P.
    pub protection: char,
    /// EPSV ALL was taken: only EPSV sets up data connections (RFC 2428 §4).
    pub epsv_all: bool,
    /// The representation type of TYPE (RFC 959 §3.1.1): `A N` (the default), `I` or `L 8`,
    /// for the application to transfer files as.
    pub representation: String,
    /// The transfer mode of MODE (§3.4): S.
    pub mode: char,
    /// The file structure of STRU (§3.1.2): F (the default) or R.
    pub structure: char,
    pub deadline: Option<Instant>,
}

impl FTPServer {
    /// A server of a new control connection from `peer`; `secure` if it is TLS from its start
    /// (implicit FTPS). Send the greeting with [`FTPServer::greet`].
    pub fn new(
        config: FTPConfig,
        server: FTPServerConfig,
        peer: IPAddress,
        secure: bool,
    ) -> Result<FTPServer, FTPError> {
        config.check()?;
        server.check()?;
        Ok(FTPServer {
            config,
            server,
            peer,
            input: LineBuffer::new(),
            output: Vec::new(),
            events: VecDeque::new(),
            greeted: false,
            closed: false,
            pending: VecDeque::new(),
            quitting: false,
            user: None,
            logged_in: false,
            rename_ready: false,
            restart: None,
            secure,
            buffer_size_set: false,
            protection: 'C',
            epsv_all: false,
            representation: String::from("A N"),
            mode: 'S',
            structure: 'F',
            deadline: None,
        })
    }

    pub fn is_open(&self) -> bool {
        !self.closed
    }

    pub fn wants_receive(&self) -> bool {
        self.is_open() && self.input.len() < self.config.maximum_buffered
    }

    /// The features listed by FEAT now (RFC 2389): AUTH TLS, PBSZ, PROT and CCC (RFC 4217), EPRT and
    /// EPSV (RFC 2428), those of RFC 3659 configured, UTF8 (RFC 2640), HOST (RFC 7151), and the configured ones.
    pub fn features(&self) -> FTPFeatures {
        let server = &self.server;
        let mut entries = Vec::new();
        let mut add = |enabled: bool, name: &str, parameters: &str| {
            if enabled {
                entries.push(FTPFeature::new(name, parameters));
            }
        };
        add(server.tls && !self.secure, "AUTH", "TLS");
        add(server.tls, "PBSZ", "");
        add(server.tls, "PROT", "");
        add(server.tls && server.allow_ccc, "CCC", "");
        add(true, "EPRT", "");
        add(true, "EPSV", "");
        add(server.size, "SIZE", "");
        add(server.mdtm, "MDTM", "");
        add(server.rest_stream, "REST", "STREAM");
        let facts: String = server.mlst_facts.iter().map(|fact| alloc::format!("{fact};")).collect();
        add(!server.mlst_facts.is_empty(), "MLST", &facts);
        add(server.utf8, "UTF8", "");
        add(server.host, "HOST", "");
        for feature in &server.features {
            let (name, parameters) = feature.split_once(' ').unwrap_or((feature, ""));
            entries.push(FTPFeature::new(name, parameters));
        }
        FTPFeatures { entries }
    }

    /// Sends the greeting: 220, or 421 to refuse the connection (RFC 959 §5.4).
    pub fn greet(&mut self, reply: FTPReply, now: Instant) -> Result<(), FTPError> {
        if self.greeted {
            return Err(FTPError::State { reason: "the greeting was sent" });
        }
        reply.check()?;
        if !matches!(reply.code, 120 | 220 | 421) {
            return Err(FTPError::State { reason: "a greeting is 120, 220 or 421" });
        }
        reply.encode(&mut self.output);
        if reply.code == 421 {
            self.close(None);
        }
        // After 120, a 220 is still to come.
        self.greeted = reply.code != 120;
        self.process(now);
        Ok(())
    }

    pub fn receive(&mut self, bytes: &[u8], now: Instant) {
        if self.closed {
            return;
        }
        self.input.push(bytes);
        self.process(now);
    }

    /// Removes the Telnet commands of a command line (RFC 959 §4.1, RFC 854): IAC and a
    /// command, IAC and an option's negotiation; IAC IAC is the octet 255.
    pub fn strip_telnet(line: &[u8]) -> Vec<u8> {
        let mut stripped = Vec::with_capacity(line.len());
        let mut index = 0;
        while index < line.len() {
            match (line[index], line.get(index + 1)) {
                (255, Some(255)) => {
                    stripped.push(255);
                    index += 2;
                }
                (255, Some(251..=254)) => index += 3,
                (255, Some(240..=250)) => index += 2,
                // An IAC before a byte of no Telnet command (the Synch's DM gone out of band before
                // ABOR, RFC 959 §4.1.3) is dropped alone, the byte kept.
                (255, Some(_)) => index += 1,
                (255, None) => index += 1,
                (byte, _) => {
                    stripped.push(byte);
                    index += 1;
                }
            }
        }
        stripped
    }

    /// Reads the commands that can be read: while none waits for its reply, or ABOR, STAT and
    /// QUIT during a transfer.
    pub fn process(&mut self, now: Instant) {
        while self.greeted && !self.closed && !self.quitting {
            let transferring =
                self.pending.len() == 1 && matches!(self.pending.front(), Some((command, true)) if command.transfers());
            if !self.pending.is_empty() && !transferring {
                break;
            }
            let line = match self.input.line(self.config.maximum_line) {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(_) => {
                    FTPReply::new(500, "Line too long").encode(&mut self.output);
                    continue;
                }
            };
            let line = FTPServer::strip_telnet(&line);
            match FTPCommand::parse(&line) {
                // RFC 959 §4.1.3: during a transfer, STAT is of its progress, QUIT waits for its end, and
                // ABOR is told (the transfer's reply, 426 or its own, comes first, then ABOR's).
                Ok(FTPCommand::Stat(None)) if transferring => {
                    let verb =
                        self.pending.front().map(|(command, _)| String::from(command.verb())).unwrap_or_default();
                    // The verb is one of the commands this module knows: no line break.
                    FTPReply::new(211, &alloc::format!("{verb} in progress")).encode(&mut self.output);
                }
                Ok(FTPCommand::Quit) if transferring => self.quitting = true,
                Ok(FTPCommand::Abor) if transferring => {
                    self.pending.push_back((FTPCommand::Abor, false));
                    self.events.push_back(FTPServerEvent::Command(FTPCommand::Abor));
                }
                Ok(_) if transferring => FTPReply::new(503, "A transfer is in progress").encode(&mut self.output),
                Ok(command) => self.dispatch(command),
                // RFC 2428 §2: a network protocol not supported is 522.
                Err(FTPError::State { .. }) => {
                    FTPReply::new(522, "Network protocol not supported, use (1,2)").encode(&mut self.output);
                }
                // RFC 959 §4.2.1: 500 for a line of no command, 501 for the arguments of one.
                Err(_) => {
                    let verb = line.split(|byte| *byte == b' ').next().unwrap_or_default();
                    let code = match (3..=4).contains(&verb.len()) && verb.iter().all(u8::is_ascii_alphabetic) {
                        true => 501,
                        false => 500,
                    };
                    FTPReply::new(code, "Syntax error").encode(&mut self.output);
                }
            }
        }
        let waiting = self.greeted && !self.closed && self.pending.is_empty();
        self.deadline = waiting.then(|| now.saturating_add(self.config.idle_timeout));
    }

    /// Writes a reply the server makes itself. The text is a constant of the program
    /// (`&'static str`), never text received or made at run time, which would go unchecked into
    /// the reply: such text is sent with [`FTPServer::reply`], which checks it.
    pub fn answer(&mut self, code: u16, text: &'static str) {
        FTPReply::new(code, text).encode(&mut self.output);
    }

    /// Whether the command needs a logged-in user (RFC 959 §5.4: 530 otherwise).
    pub fn needs_login(command: &FTPCommand) -> bool {
        !matches!(
            command,
            FTPCommand::User(_)
                | FTPCommand::Pass(_)
                | FTPCommand::Acct(_)
                | FTPCommand::Quit
                | FTPCommand::Noop
                | FTPCommand::Feat
                | FTPCommand::Syst
                | FTPCommand::Help(_)
                | FTPCommand::Opts(_)
                | FTPCommand::Host(_)
                | FTPCommand::Auth(_)
                | FTPCommand::Pbsz(_)
                | FTPCommand::Prot(_)
                | FTPCommand::Ccc
                | FTPCommand::Lang(_)
                | FTPCommand::Stat(None)
                // RFC 959 §5.4: REIN's replies are 120, 220, 421, 500 and 502, never 530.
                | FTPCommand::Rein
        )
    }

    /// Answers a command the server decides itself, or tells it.
    pub fn dispatch(&mut self, command: FTPCommand) {
        let server = &self.server;
        // A REST marker is for the transfer right after it (RFC 959 §4.1.3).
        if !matches!(command, FTPCommand::Retr(_) | FTPCommand::Stor(_) | FTPCommand::Appe(_) | FTPCommand::Stou) {
            self.restart = None;
        }
        if !matches!(command, FTPCommand::Rnto(_)) {
            self.rename_ready = false;
        }
        if FTPServer::needs_login(&command) && !self.logged_in {
            return self.answer(530, "Not logged in");
        }
        match &command {
            FTPCommand::Noop => return self.answer(200, "NOOP ok"),
            FTPCommand::Feat => {
                let reply = self.features().reply();
                return reply.encode(&mut self.output);
            }
            FTPCommand::Syst => {
                // FTPServerConfig::check refuses a system type with a line break.
                return FTPReply::new(215, &server.system).encode(&mut self.output);
            }
            FTPCommand::Quit => {
                self.answer(221, "Goodbye");
                return self.close(None);
            }
            FTPCommand::Type(kind) => {
                // RFC 959 §5.1: ASCII Non-print; IMAGE; LOCAL 8. Kept for the application.
                let kind = match kind.to_ascii_uppercase().as_str() {
                    "A" | "A N" => "A N",
                    "I" => "I",
                    "L 8" => "L 8",
                    _ => return self.answer(504, "Type not implemented"),
                };
                self.representation = String::from(kind);
                return self.answer(200, "Type set");
            }
            FTPCommand::Mode(mode) => {
                return if mode.eq_ignore_ascii_case(&'S') {
                    self.mode = 'S';
                    self.answer(200, "Mode set")
                } else {
                    self.answer(504, "Mode not implemented")
                };
            }
            FTPCommand::Stru(structure) => {
                let structure = structure.to_ascii_uppercase();
                return if matches!(structure, 'F' | 'R') {
                    self.structure = structure;
                    self.answer(200, "Structure set")
                } else {
                    self.answer(504, "Structure not implemented")
                };
            }
            FTPCommand::User(_) if server.require_tls && !self.secure => {
                return self.answer(530, "TLS is required (AUTH TLS)");
            }
            FTPCommand::Pass(_) | FTPCommand::Acct(_) if self.user.is_none() => {
                return self.answer(503, "Login with USER first");
            }
            FTPCommand::Host(_) if !server.host => return self.answer(502, "HOST not implemented"),
            FTPCommand::Host(_) if self.logged_in || self.user.is_some() => {
                return self.answer(503, "HOST only before USER");
            }
            FTPCommand::Rnto(_) if !self.rename_ready => return self.answer(503, "RNFR first"),
            FTPCommand::Auth(mechanism) => {
                if !server.tls {
                    return self.answer(502, "AUTH not implemented");
                }
                if self.secure {
                    return self.answer(503, "TLS is already in use");
                }
                if mechanism != "TLS" && mechanism != "TLS-C" {
                    return self.answer(504, "Only AUTH TLS");
                }
            }
            FTPCommand::Pbsz(_) => {
                if !self.secure {
                    return self.answer(503, "PBSZ only under TLS");
                }
                // RFC 4217 §8: 0 for TLS; another is answered with PBSZ=0.
                self.buffer_size_set = true;
                return self.answer(200, "PBSZ=0");
            }
            FTPCommand::Prot(level) => {
                if !self.buffer_size_set {
                    return self.answer(503, "PBSZ first");
                }
                return match level {
                    'C' | 'P' => {
                        self.protection = *level;
                        self.answer(200, "Protection level set")
                    }
                    'S' | 'E' => self.answer(536, "Protection level not supported"),
                    _ => self.answer(504, "Not a protection level"),
                };
            }
            FTPCommand::Ccc => {
                if !self.secure {
                    return self.answer(533, "TLS is not in use");
                }
                if !server.allow_ccc {
                    return self.answer(534, "CCC denied by policy");
                }
                self.answer(200, "Command channel cleared");
                self.secure = false;
                self.buffer_size_set = false;
                self.events.push_back(FTPServerEvent::ClearCommandChannel);
                return;
            }
            FTPCommand::Port(address) | FTPCommand::Eprt(address) => {
                if self.epsv_all {
                    return self.answer(503, "Only EPSV after EPSV ALL");
                }
                // Compared as addresses, an IPv4-mapped peer of a dual-stack socket as its IPv4.
                let host = address.host.map(|host| host.to_canonical());
                let foreign = host != Some(self.peer.to_canonical()) || address.port < 1024;
                if foreign && !server.allow_foreign_data {
                    // RFC 2577 §3: no data connections to other hosts, or to their privileged ports.
                    return self.answer(504, "Command not implemented for that parameter");
                }
            }
            FTPCommand::Pasv if self.epsv_all => return self.answer(503, "Only EPSV after EPSV ALL"),
            FTPCommand::Epsv(Some(argument)) => match argument.as_str() {
                "ALL" => {
                    self.epsv_all = true;
                    return self.answer(200, "EPSV ALL ok");
                }
                "1" | "2" => {}
                _ => return self.answer(522, "Network protocol not supported, use (1,2)"),
            },
            FTPCommand::Size(_) if !server.size => return self.answer(502, "SIZE not implemented"),
            FTPCommand::Mdtm(_) if !server.mdtm => return self.answer(502, "MDTM not implemented"),
            FTPCommand::Mlst(_) | FTPCommand::Mlsd(_) if server.mlst_facts.is_empty() => {
                return self.answer(502, "MLST not implemented");
            }
            FTPCommand::Opts(options)
                if options.eq_ignore_ascii_case("UTF8 ON") || options.eq_ignore_ascii_case("UTF8") =>
            {
                return match server.utf8 {
                    true => self.answer(200, "UTF8 on"),
                    false => self.answer(504, "UTF8 not implemented"),
                };
            }
            command if command.transfers() && server.require_protection && self.protection != 'P' => {
                return self.answer(521, "Data connections need PROT P");
            }
            FTPCommand::Other { verb, .. } if !server.commands.iter().any(|known| known.eq_ignore_ascii_case(verb)) => {
                return self.answer(500, "Command not recognized");
            }
            _ => {}
        }
        self.pending.push_back((command.clone(), false));
        self.events.push_back(FTPServerEvent::Command(command));
    }

    /// Answers the oldest command told: a preliminary reply (1xx) of a transfer first, then its
    /// final one; an ABOR told during a transfer is answered after the transfer. The reply moves the session on (RFC 959 §5.4): 331 or 332 to USER keeps the name,
    /// 230 (or 202) logs in, 350 to RNFR lets RNTO follow and to REST keeps the marker, 234 to
    /// AUTH starts TLS, 421 closes the connection.
    pub fn reply(&mut self, reply: FTPReply, now: Instant) -> Result<(), FTPError> {
        reply.check()?;
        let Some((command, preliminary)) = self.pending.front().cloned() else {
            return Err(FTPError::State { reason: "no command to answer" });
        };
        if reply.is_preliminary() {
            if preliminary || !command.transfers() {
                return Err(FTPError::State { reason: "a preliminary reply of no transfer, or a second" });
            }
            reply.encode(&mut self.output);
            if let Some(front) = self.pending.front_mut() {
                front.1 = true;
            }
            self.process(now);
            return Ok(());
        }
        self.pending.pop_front();
        reply.encode(&mut self.output);
        match &command {
            FTPCommand::User(name) => {
                self.logged_in = reply.code == 230;
                self.user = matches!(reply.code, 331 | 332).then(|| name.clone());
            }
            FTPCommand::Pass(_) | FTPCommand::Acct(_) => {
                self.logged_in = matches!(reply.code, 230 | 202);
                if reply.code != 332 {
                    self.user = None;
                }
            }
            // RFC 959 §4.1.1 and RFC 4217 §13: REIN ends the session as after the greeting, TLS
            // of the control connection too.
            FTPCommand::Rein if reply.is_positive() => {
                self.reset_session();
                if self.secure {
                    self.secure = false;
                    self.events.push_back(FTPServerEvent::ClearCommandChannel);
                }
                self.buffer_size_set = false;
                self.protection = 'C';
            }
            FTPCommand::Rnfr(_) => self.rename_ready = reply.code == 350,
            FTPCommand::Rest(marker) if reply.code == 350 => self.restart = Some(marker.clone()),
            FTPCommand::Retr(_) | FTPCommand::Stor(_) | FTPCommand::Appe(_) | FTPCommand::Stou => self.restart = None,
            FTPCommand::Auth(_) if reply.code == 234 => {
                self.input.clear();
                self.secure = true;
                // RFC 4217 §4: the user authorizes again, and the state of the session is reset.
                self.reset_session();
                self.events.push_back(FTPServerEvent::StartTLS);
            }
            _ => {}
        }
        if reply.code == 421 {
            self.close(None);
        }
        if self.quitting && self.pending.is_empty() && !self.closed {
            self.answer(221, "Goodbye");
            self.close(None);
        }
        self.process(now);
        Ok(())
    }

    /// Forgets what the session set: the user and login, a rename or restart begun, TYPE, MODE
    /// and STRU, EPSV ALL (RFC 4217 §4, after AUTH; RFC 959 §4.1.1, after REIN).
    pub fn reset_session(&mut self) {
        self.user = None;
        self.logged_in = false;
        self.rename_ready = false;
        self.restart = None;
        self.representation = String::from("A N");
        self.mode = 'S';
        self.structure = 'F';
        self.epsv_all = false;
    }

    /// Closes the connection with 421 and `text` (RFC 959 §4.2): for shutting down. Fails for a
    /// text that cannot be written, a line break in it.
    pub fn shutdown(&mut self, text: &str) -> Result<(), FTPError> {
        let reply = FTPReply::new(421, text);
        reply.check()?;
        if self.is_open() {
            reply.encode(&mut self.output);
            self.close(None);
        }
        Ok(())
    }

    pub fn transmit(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.output);
    }

    pub fn poll_event(&mut self) -> Option<FTPServerEvent> {
        self.events.pop_front()
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        self.deadline
    }

    /// Closes the connection with 421 if the client was silent past the idle time.
    pub fn expire(&mut self, now: Instant) {
        if self.deadline.is_some_and(|deadline| deadline <= now) && !self.closed {
            self.answer(421, "Timeout, closing the control connection");
            self.close(Some(FTPError::Timeout));
        }
    }

    pub fn close(&mut self, error: Option<FTPError>) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.pending.clear();
        self.deadline = None;
        self.events.push_back(FTPServerEvent::Closed { error });
    }
}
