//! An IMAP server and client over TCP, to try umilib's IMAP against other
//! implementations (`examples/mail.sh` runs them against Dovecot, curl and
//! Python's imaplib).
//!
//! ```text
//! imap server PORT
//! imap client HOST PORT USER PASSWORD [--auth] [--mailbox NAME] [--fetch SET]
//! ```
//!
//! The server keeps a mailbox INBOX of two messages in memory for any user
//! and password (LOGIN, AUTHENTICATE PLAIN), and answers LIST, STATUS,
//! SELECT and EXAMINE, FETCH and UID FETCH (flags, UID, size, internal date,
//! ENVELOPE, BODYSTRUCTURE, sections), SEARCH (all messages), STORE, IDLE,
//! NAMESPACE and CLOSE; it prints a line for each command (`command:
//! LINE`). The client logs in (with `--auth` by AUTHENTICATE PLAIN), lists
//! the mailboxes, selects one (INBOX by default), searches it, fetches
//! `--fetch` (`1:*` by default) and logs out, printing each untagged
//! response (`* ...`) and each completion (`completed: COMMAND CONDITION`).
//! Passwords are taken without TLS here: this is a test tool.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant as Clock};

use umilib::codec::mail::{MIMEEntity, MailConfig, MailFields};
use umilib::protocol::imap::v4::{
    IMAPBody, IMAPClient, IMAPClientEvent, IMAPCommand, IMAPCommandBody, IMAPCondition, IMAPConfig, IMAPDateTime,
    IMAPEnvelope, IMAPFetchAttribute, IMAPFetchItem, IMAPLiteralMode, IMAPMailbox, IMAPNamespace, IMAPResponse,
    IMAPResponseCode, IMAPSearchData, IMAPSequenceSet, IMAPServer, IMAPServerConfig, IMAPServerEvent, IMAPStoreMode,
    IMAPWriter,
};
use umilib::runtime::Instant;

/// The command line: positional arguments and `--name value` options.
pub struct Arguments {
    pub positional: Vec<String>,
    pub options: Vec<(String, Option<String>)>,
}

impl Arguments {
    /// The options that take no value.
    pub const FLAGS: [&'static str; 1] = ["--auth"];

    pub fn parse() -> Arguments {
        let mut positional = Vec::new();
        let mut options = Vec::new();
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            if !argument.starts_with("--") {
                positional.push(argument);
            } else if Arguments::FLAGS.contains(&argument.as_str()) {
                options.push((argument, None));
            } else {
                options.push((argument, arguments.next()));
            }
        }
        Arguments { positional, options }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.options.iter().find(|(option, _)| option == name).and_then(|(_, value)| value.as_deref())
    }

    pub fn has(&self, name: &str) -> bool {
        self.options.iter().any(|(option, _)| option == name)
    }

    pub fn position(&self, index: usize, what: &str) -> &str {
        self.positional.get(index).map(String::as_str).unwrap_or_else(|| Tool::fail(what))
    }
}

/// A message of the server's mailbox.
pub struct Message {
    pub uid: u32,
    pub flags: Vec<String>,
    pub date: IMAPDateTime,
    pub text: Vec<u8>,
}

/// The helpers of the tool.
pub struct Tool;

impl Tool {
    /// How long the client runs at most.
    pub const BUDGET: Duration = Duration::from_secs(30);
    /// The UIDVALIDITY of the mailbox.
    pub const VALIDITY: u32 = 3857529045;

    pub fn fail(message: &str) -> ! {
        eprintln!("error: {message}");
        std::process::exit(2)
    }

    pub fn now(start: Clock) -> Instant {
        Instant::from_nanos(start.elapsed().as_nanos() as u64)
    }

    /// Writes `out` to `stream`, then reads what arrives within `wait`; `None` when the connection closed.
    pub fn exchange(stream: &mut TcpStream, out: &[u8], wait: Duration) -> Option<Vec<u8>> {
        if !out.is_empty() && stream.write_all(out).is_err() {
            return None;
        }
        stream.set_read_timeout(Some(wait.max(Duration::from_millis(1)))).ok()?;
        let mut buffer = vec![0u8; 65536];
        match stream.read(&mut buffer) {
            Ok(0) => None,
            Ok(count) => Some(buffer[..count].to_vec()),
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                Some(Vec::new())
            }
            Err(_) => None,
        }
    }

    pub fn wait(deadline: Option<Instant>, now: Instant) -> Duration {
        deadline.map_or(Duration::from_secs(1), |deadline| {
            Duration::from_nanos(deadline.as_nanos().saturating_sub(now.as_nanos())).min(Duration::from_secs(1))
        })
    }

    /// The logical line of a response, without its last CRLF.
    pub fn line(response: &IMAPResponse) -> String {
        let mut writer = IMAPWriter::new(IMAPLiteralMode::Server, true);
        response.write(&mut writer);
        String::from_utf8_lossy(&writer.out).trim_end().to_string()
    }

    pub fn mailbox() -> Vec<Message> {
        let texts: [&[u8]; 2] = [
            b"From: John Doe <jdoe@machine.example>\r\nTo: Mary Smith <mary@example.net>\r\nSubject: Saying Hello\r\nDate: Fri, 21 Nov 1997 09:55:06 -0600\r\nMessage-ID: <1234@local.machine.example>\r\n\r\nThis is a message just to say hello.\r\n",
            b"From: Mary Smith <mary@example.net>\r\nTo: John Doe <jdoe@machine.example>\r\nSubject: Re: Saying Hello\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThis is a reply.\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAAECAw==\r\n--b--\r\n",
        ];
        texts
            .iter()
            .enumerate()
            .map(|(index, text)| Message {
                uid: index as u32 + 1,
                flags: Vec::new(),
                date: IMAPDateTime::new(880_127_706 + index as i64 * 3600, -360),
                text: text.to_vec(),
            })
            .collect()
    }

    pub fn serve(port: u16) {
        let listener = TcpListener::bind(("0.0.0.0", port)).unwrap_or_else(|error| Tool::fail(&error.to_string()));
        println!("listening: {port}");
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || Tool::session(stream));
        }
    }

    /// One connection of the server.
    pub fn session(mut stream: TcpStream) {
        let start = Clock::now();
        let settings = IMAPServerConfig {
            auth_mechanisms: vec![String::from("PLAIN")],
            passwords_require_tls: false,
            ..IMAPServerConfig::default()
        };
        let mut server = IMAPServer::new(IMAPConfig::default(), settings, false).expect("a server");
        server.greet(IMAPCondition::OK, "umilib IMAP4rev2 server ready", Tool::now(start)).expect("a greeting");
        let mut messages = Tool::mailbox();
        let mut out = Vec::new();
        while server.is_open() {
            out.clear();
            server.transmit(&mut out);
            let now = Tool::now(start);
            let Some(input) = Tool::exchange(&mut stream, &out, Tool::wait(server.poll_timeout(), now)) else { break };
            let now = Tool::now(start);
            server.receive(&input, now);
            if server.poll_timeout().is_some_and(|deadline| deadline <= now) {
                server.expire(now);
            }
            while let Some(event) = server.poll_event() {
                match event {
                    IMAPServerEvent::Command(command) => {
                        let mut writer = IMAPWriter::new(IMAPLiteralMode::Server, true);
                        command.write(&mut writer);
                        println!("command: {}", String::from_utf8_lossy(&writer.out).trim_end());
                        Tool::answer(&mut server, &command.body, &mut messages, now);
                    }
                    IMAPServerEvent::AuthenticateResponse { data, .. } => {
                        let user = data.split(|byte| *byte == 0).nth(1).unwrap_or_default();
                        println!("auth: {}", String::from_utf8_lossy(user));
                        server.complete(IMAPCondition::OK, None, "AUTHENTICATE completed", now).expect("a completion");
                    }
                    IMAPServerEvent::IdleDone { .. } => {
                        server.complete(IMAPCondition::OK, None, "IDLE terminated", now).expect("a completion");
                    }
                    _ => {}
                }
            }
        }
        out.clear();
        server.transmit(&mut out);
        let _ = stream.write_all(&out);
    }

    /// The item of `attribute` of `message`, and whether the message is now \Seen.
    pub fn item(attribute: &IMAPFetchAttribute, message: &Message) -> (IMAPFetchItem, bool) {
        let config = MailConfig::default();
        let entity = MIMEEntity::decode(&message.text, &config).expect("a message");
        let item = match attribute {
            IMAPFetchAttribute::Flags => IMAPFetchItem::Flags(message.flags.clone()),
            IMAPFetchAttribute::UID => IMAPFetchItem::UID(message.uid),
            IMAPFetchAttribute::RFC822Size => IMAPFetchItem::RFC822Size(message.text.len() as u64),
            IMAPFetchAttribute::InternalDate => IMAPFetchItem::InternalDate(message.date),
            IMAPFetchAttribute::Envelope => {
                let (fields, _) = MailFields::decode(&message.text, &config).expect("fields");
                IMAPFetchItem::Envelope(IMAPEnvelope::from_fields(&fields))
            }
            IMAPFetchAttribute::Body => IMAPFetchItem::Body(IMAPBody::from_entity(&entity, &message.text, false)),
            IMAPFetchAttribute::BodyStructure => {
                IMAPFetchItem::BodyStructure(IMAPBody::from_entity(&entity, &message.text, true))
            }
            IMAPFetchAttribute::BodySection { peek, section, partial } => {
                let data = section.extract(&entity, &message.text).map(|data| match partial {
                    Some((origin, count)) => {
                        let start = (*origin as usize).min(data.len());
                        data[start..(start + *count as usize).min(data.len())].to_vec()
                    }
                    None => data,
                });
                let item = IMAPFetchItem::BodySection {
                    section: section.clone(),
                    origin: partial.map(|(origin, _)| origin),
                    data,
                };
                return (item, !peek);
            }
            IMAPFetchAttribute::RFC822 => return (IMAPFetchItem::RFC822(Some(message.text.clone())), true),
            IMAPFetchAttribute::RFC822Header => {
                let end = message.text.windows(4).position(|window| window == b"\r\n\r\n").map_or(0, |at| at + 4);
                IMAPFetchItem::RFC822Header(Some(message.text[..end].to_vec()))
            }
            IMAPFetchAttribute::RFC822Text => {
                let end = message.text.windows(4).position(|window| window == b"\r\n\r\n").map_or(0, |at| at + 4);
                return (IMAPFetchItem::RFC822Text(Some(message.text[end..].to_vec())), true);
            }
            IMAPFetchAttribute::Binary { part, .. } | IMAPFetchAttribute::BinarySize { part } => {
                IMAPFetchItem::BinarySize { part: part.clone(), size: 0 }
            }
        };
        (item, false)
    }

    /// Answers a command of the mailbox.
    pub fn answer(server: &mut IMAPServer, body: &IMAPCommandBody, messages: &mut [Message], now: Instant) {
        let ok = |server: &mut IMAPServer, code: Option<IMAPResponseCode>, text: &str| {
            server.complete(IMAPCondition::OK, code, text, now).expect("a completion");
        };
        let numbers = |set: &IMAPSequenceSet, uid: bool, messages: &[Message]| -> Vec<usize> {
            let last = if uid { messages.last().map_or(0, |message| message.uid) } else { messages.len() as u32 };
            (0..messages.len())
                .filter(|index| set.contains(if uid { messages[*index].uid } else { *index as u32 + 1 }, last))
                .collect()
        };
        let inbox = IMAPMailbox::inbox();
        match body {
            IMAPCommandBody::Login { user, .. } => {
                println!("login: {}", String::from_utf8_lossy(user));
                ok(server, None, "LOGIN completed")
            }
            IMAPCommandBody::Authenticate { initial: Some(data), .. } => {
                let user = data.split(|byte| *byte == 0).nth(1).unwrap_or_default();
                println!("auth: {}", String::from_utf8_lossy(user));
                ok(server, None, "AUTHENTICATE completed")
            }
            IMAPCommandBody::Authenticate { initial: None, .. } => {
                server.authenticate_challenge(b"", now).expect("a challenge")
            }
            IMAPCommandBody::List { .. } | IMAPCommandBody::Lsub { .. } => {
                let response = IMAPResponse::List {
                    lsub: matches!(body, IMAPCommandBody::Lsub { .. }),
                    attributes: vec![String::from("\\HasNoChildren")],
                    delimiter: Some('/'),
                    mailbox: inbox,
                    extended: Vec::new(),
                };
                server.respond(&response).expect("LIST");
                ok(server, None, "LIST completed")
            }
            IMAPCommandBody::Namespace => {
                let personal = vec![IMAPNamespace { prefix: Vec::new(), delimiter: Some('/') }];
                server
                    .respond(&IMAPResponse::Namespace { personal, other: Vec::new(), shared: Vec::new() })
                    .expect("NAMESPACE");
                ok(server, None, "NAMESPACE completed")
            }
            IMAPCommandBody::Status { mailbox, items } => {
                let values = items
                    .iter()
                    .filter_map(|item| {
                        let value = match item.as_str() {
                            "MESSAGES" => messages.len() as u64,
                            "UIDNEXT" => messages.len() as u64 + 1,
                            "UIDVALIDITY" => u64::from(Tool::VALIDITY),
                            "UNSEEN" => messages
                                .iter()
                                .filter(|message| !message.flags.iter().any(|flag| flag == "\\Seen"))
                                .count() as u64,
                            "SIZE" => messages.iter().map(|message| message.text.len() as u64).sum(),
                            _ => return None,
                        };
                        Some((item.clone(), value))
                    })
                    .collect();
                server.respond(&IMAPResponse::StatusData { mailbox: mailbox.clone(), items: values }).expect("STATUS");
                ok(server, None, "STATUS completed")
            }
            IMAPCommandBody::Select(mailbox) | IMAPCommandBody::Examine(mailbox) if mailbox.is_inbox() => {
                server.respond(&IMAPResponse::Exists(messages.len() as u32)).expect("EXISTS");
                let flags: Vec<String> =
                    ["\\Answered", "\\Flagged", "\\Deleted", "\\Seen", "\\Draft"].map(String::from).to_vec();
                server.respond(&IMAPResponse::Flags(flags.clone())).expect("FLAGS");
                for code in [
                    IMAPResponseCode::UIDValidity(Tool::VALIDITY),
                    IMAPResponseCode::UIDNext(messages.len() as u32 + 1),
                    IMAPResponseCode::PermanentFlags(flags),
                ] {
                    server.respond(&IMAPResponse::untagged(IMAPCondition::OK, Some(code), "")).expect("OK");
                }
                let code = match body {
                    IMAPCommandBody::Select(_) => IMAPResponseCode::ReadWrite,
                    _ => IMAPResponseCode::ReadOnly,
                };
                ok(server, Some(code), "SELECT completed")
            }
            IMAPCommandBody::Select(_) | IMAPCommandBody::Examine(_) => {
                server.complete(IMAPCondition::NO, None, "no such mailbox", now).expect("NO")
            }
            IMAPCommandBody::Fetch { uid, set, attributes } => {
                for index in numbers(set, *uid, messages) {
                    let mut items = Vec::new();
                    let mut seen = false;
                    for attribute in attributes {
                        let (item, sets_seen) = Tool::item(attribute, &messages[index]);
                        items.push(item);
                        seen |= sets_seen;
                    }
                    if *uid && !attributes.contains(&IMAPFetchAttribute::UID) {
                        items.insert(0, IMAPFetchItem::UID(messages[index].uid));
                    }
                    if seen && !messages[index].flags.iter().any(|flag| flag == "\\Seen") {
                        messages[index].flags.push(String::from("\\Seen"));
                        items.push(IMAPFetchItem::Flags(messages[index].flags.clone()));
                    }
                    server.respond(&IMAPResponse::Fetch { number: index as u32 + 1, items }).expect("FETCH");
                }
                ok(server, None, "FETCH completed")
            }
            IMAPCommandBody::Store { uid, set, mode, silent, flags } => {
                for index in numbers(set, *uid, messages) {
                    let current = &mut messages[index].flags;
                    match mode {
                        IMAPStoreMode::Replace => *current = flags.clone(),
                        IMAPStoreMode::Add => current
                            .extend(flags.iter().filter(|flag| !current.contains(flag)).cloned().collect::<Vec<_>>()),
                        IMAPStoreMode::Remove => current.retain(|flag| !flags.contains(flag)),
                    }
                    if !silent {
                        let items = vec![IMAPFetchItem::Flags(current.clone())];
                        server.respond(&IMAPResponse::Fetch { number: index as u32 + 1, items }).expect("FETCH");
                    }
                }
                ok(server, None, "STORE completed")
            }
            IMAPCommandBody::Search { uid, search } => {
                let found: Vec<u32> = messages
                    .iter()
                    .enumerate()
                    .map(|(index, message)| if *uid { message.uid } else { index as u32 + 1 })
                    .collect();
                let response = match server.rev2 || search.returns.is_some() {
                    true => IMAPResponse::ESearch {
                        tag: None,
                        uid: *uid,
                        data: vec![
                            IMAPSearchData::All(IMAPSequenceSet::from_numbers(&found)),
                            IMAPSearchData::Count(found.len() as u32),
                        ],
                    },
                    false => IMAPResponse::Search(found),
                };
                server.respond(&response).expect("SEARCH");
                ok(server, None, "SEARCH completed")
            }
            IMAPCommandBody::Idle => server.idle("idling", now).expect("IDLE"),
            _ => ok(server, None, "completed"),
        }
    }

    pub fn client(host: &str, port: u16, user: &str, password: &str, arguments: &Arguments) {
        let mut stream = TcpStream::connect((host, port)).unwrap_or_else(|error| Tool::fail(&error.to_string()));
        let start = Clock::now();
        // Passwords go in the clear here: this is a test tool (a client refuses to by default).
        let config = IMAPConfig { passwords_require_tls: false, ..IMAPConfig::default() };
        let mut client = IMAPClient::new(config, false, "u", Tool::now(start)).expect("a client");
        let mailbox = arguments.get("--mailbox").unwrap_or("INBOX");
        let fetch = arguments.get("--fetch").unwrap_or("1:*");
        let quote = |text: &str| format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""));
        let mut steps: Vec<String> = vec![
            match arguments.has("--auth") {
                true => String::from("AUTHENTICATE PLAIN"),
                false => format!("LOGIN {} {}", quote(user), quote(password)),
            },
            String::from("LIST \"\" \"*\""),
            format!("SELECT {}", quote(mailbox)),
            String::from("SEARCH ALL"),
            format!("FETCH {fetch} (FLAGS UID RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[])"),
            String::from("LOGOUT"),
        ];
        steps.reverse();
        let mut out = Vec::new();
        while client.is_open() && start.elapsed() < Tool::BUDGET {
            out.clear();
            client.transmit(&mut out);
            let now = Tool::now(start);
            let Some(input) = Tool::exchange(&mut stream, &out, Tool::wait(client.poll_timeout(), now)) else { break };
            let now = Tool::now(start);
            client.receive(&input, now).unwrap_or_else(|error| Tool::fail(&error.to_string()));
            if client.poll_timeout().is_some_and(|deadline| deadline <= now) {
                client.expire(now);
            }
            while let Some(event) = client.poll_event() {
                let mut advance = false;
                match event {
                    IMAPClientEvent::Greeting(response) => {
                        println!("greeting: {}", Tool::line(&response));
                        advance = true;
                    }
                    IMAPClientEvent::Untagged(response) => println!("{}", Tool::line(&response)),
                    IMAPClientEvent::Completed { command, condition, text, .. } => {
                        println!("completed: {} {}", command.body.name(), condition.name());
                        if condition != IMAPCondition::OK && !matches!(command.body, IMAPCommandBody::Logout) {
                            Tool::fail(&format!("{}: {text}", command.body.name()));
                        }
                        advance = true;
                    }
                    IMAPClientEvent::AuthenticateChallenge { .. } => client
                        .authenticate_respond(format!("\0{user}\0{password}").as_bytes(), now)
                        .expect("a response"),
                    IMAPClientEvent::Closed { error: Some(error) } => Tool::fail(&error.to_string()),
                    _ => {}
                }
                if advance && let Some(line) = steps.pop() {
                    let body = IMAPCommand::parse(format!("x {line}").as_bytes(), true, 32).expect("a command").body;
                    client.send(body, now).unwrap_or_else(|error| Tool::fail(&error.to_string()));
                }
            }
        }
        if !steps.is_empty() {
            Tool::fail("the session did not end");
        }
    }
}

fn main() {
    let arguments = Arguments::parse();
    let port = |index| arguments.position(index, "a port").parse().unwrap_or_else(|_| Tool::fail("a port"));
    match arguments.position(0, "server or client") {
        "server" => Tool::serve(port(1)),
        "client" => {
            let (host, user, password) =
                (arguments.position(1, "a host"), arguments.position(3, "a user"), arguments.position(4, "a password"));
            Tool::client(host, port(2), user, password, &arguments)
        }
        _ => Tool::fail("server or client"),
    }
}
