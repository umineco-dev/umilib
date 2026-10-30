//! An SMTP server and client over TCP, to try umilib's SMTP against other
//! implementations (`examples/mail.sh` runs them against Postfix, curl and
//! Python's smtplib).
//!
//! ```text
//! smtp server PORT [--domain NAME] [--auth]
//! smtp client HOST PORT --from ADDRESS --to ADDRESS [--name NAME] [--auth USER:PASSWORD] [--chunking] < MESSAGE
//! ```
//!
//! The server takes every recipient and message, and prints a line for each
//! (`mail: FROM`, `rcpt: TO`, `message: OCTETS octets`, `subject: TEXT`), and
//! with `--auth` offers PLAIN, which it takes of any name and password
//! (`auth: NAME`). The client sends the message of its standard input, as
//! mail data or with `--chunking` as one BDAT chunk (RFC 3030), and prints
//! each reply (`reply: COMMAND -> CODE`) and `sent` when the message was
//! taken. Passwords are taken without TLS here: this is a test tool.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant as Clock};

use umilib::codec::base::Encoding;
use umilib::codec::base::base64::Base64;
use umilib::protocol::smtp::{
    SMTPClient, SMTPClientEvent, SMTPCommand, SMTPConfig, SMTPReply, SMTPServer, SMTPServerConfig, SMTPServerEvent,
};
use umilib::runtime::Instant;

/// The command line: positional arguments and `--name value` options.
pub struct Arguments {
    pub positional: Vec<String>,
    pub options: Vec<(String, Option<String>)>,
}

impl Arguments {
    /// The options that take no value.
    pub const FLAGS: [&'static str; 2] = ["--auth-offer", "--chunking"];

    pub fn parse() -> Arguments {
        let mut positional = Vec::new();
        let mut options = Vec::new();
        let mut arguments = std::env::args().skip(1).peekable();
        while let Some(argument) = arguments.next() {
            if !argument.starts_with("--") {
                positional.push(argument);
            } else if Arguments::FLAGS.contains(&argument.as_str())
                || arguments.peek().is_none_or(|next| next.starts_with("--"))
            {
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

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.options.iter().filter(|(option, _)| option == name).filter_map(|(_, value)| value.as_deref()).collect()
    }

    pub fn has(&self, name: &str) -> bool {
        self.options.iter().any(|(option, _)| option == name)
    }

    pub fn position(&self, index: usize, what: &str) -> &str {
        self.positional.get(index).map(String::as_str).unwrap_or_else(|| Tool::fail(what))
    }
}

/// The helpers of the tool.
pub struct Tool;

impl Tool {
    /// How long a connection waits for the other side at most.
    pub const BUDGET: Duration = Duration::from_secs(30);

    pub fn fail(message: &str) -> ! {
        eprintln!("error: {message}");
        std::process::exit(2)
    }

    /// The session's clock: nanoseconds since the tool started.
    pub fn now(start: Clock) -> Instant {
        Instant::from_nanos(start.elapsed().as_nanos() as u64)
    }

    /// Writes `out` to `stream`, then reads what arrives within the time until `deadline`;
    /// `None` when the connection closed.
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

    /// The time until `deadline` from `now`, at most a second.
    pub fn wait(deadline: Option<Instant>, now: Instant) -> Duration {
        deadline.map_or(Duration::from_secs(1), |deadline| {
            Duration::from_nanos(deadline.as_nanos().saturating_sub(now.as_nanos())).min(Duration::from_secs(1))
        })
    }

    pub fn serve(port: u16, arguments: &Arguments) {
        let listener = TcpListener::bind(("0.0.0.0", port)).unwrap_or_else(|error| Tool::fail(&error.to_string()));
        let mut settings = SMTPServerConfig {
            domain: String::from(arguments.get("--domain").unwrap_or("umilib.test")),
            ..SMTPServerConfig::default()
        };
        if arguments.has("--auth") {
            settings.auth_mechanisms = vec![String::from("PLAIN")];
            settings.passwords_require_tls = false;
        }
        println!("listening: {port}");
        for stream in listener.incoming().flatten() {
            let settings = settings.clone();
            std::thread::spawn(move || Tool::session(stream, settings));
        }
    }

    /// The reply to a response of PLAIN (RFC 4616): any name and password are taken.
    pub fn authenticated(response: &[u8]) -> SMTPReply {
        let user = response.split(|byte| *byte == 0).nth(1).unwrap_or_default();
        println!("auth: {}", String::from_utf8_lossy(user));
        SMTPReply::new(235, "2.7.0 Authentication successful")
    }

    /// One connection of the server.
    pub fn session(mut stream: TcpStream, settings: SMTPServerConfig) {
        let start = Clock::now();
        let mut server = match SMTPServer::new(SMTPConfig::default(), settings, false) {
            Ok(server) => server,
            Err(error) => return eprintln!("error: {error}"),
        };
        server.greet(server.greeting(), Tool::now(start)).expect("a greeting");
        let mut message = Vec::new();
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
                let reply = match event {
                    SMTPServerEvent::Command(SMTPCommand::Mail { path, .. }) => {
                        println!("mail: {path}");
                        Some(SMTPReply::new(250, "OK"))
                    }
                    SMTPServerEvent::Command(SMTPCommand::Rcpt { path, .. }) => {
                        println!("rcpt: {path}");
                        Some(SMTPReply::new(250, "OK"))
                    }
                    SMTPServerEvent::Command(SMTPCommand::Data) => {
                        Some(SMTPReply::new(354, "End data with <CR><LF>.<CR><LF>"))
                    }
                    SMTPServerEvent::Command(SMTPCommand::Auth { initial: Some(response), .. }) => {
                        Some(Tool::authenticated(&response))
                    }
                    SMTPServerEvent::Command(SMTPCommand::Auth { initial: None, .. }) => {
                        server.auth_challenge(b"", now).expect("a challenge");
                        None
                    }
                    SMTPServerEvent::Command(SMTPCommand::Ehlo(name) | SMTPCommand::Helo(name)) => {
                        Some(SMTPReply::new(250, &format!("umilib.test greets {name}")))
                    }
                    SMTPServerEvent::Command(command) => {
                        println!("command: {command}");
                        Some(SMTPReply::new(250, "OK"))
                    }
                    SMTPServerEvent::AuthResponse(response) => Some(Tool::authenticated(&response)),
                    SMTPServerEvent::Data(data) => {
                        message.extend_from_slice(&data);
                        None
                    }
                    SMTPServerEvent::DataEnd { last } => {
                        if last {
                            println!("message: {} octets", message.len());
                            let subject = message
                                .split(|byte| *byte == b'\n')
                                .take_while(|line| *line != b"\r")
                                .find_map(|line| line.strip_prefix(b"Subject: "));
                            if let Some(subject) = subject {
                                println!("subject: {}", String::from_utf8_lossy(subject).trim_end());
                            }
                            message.clear();
                        }
                        Some(SMTPReply::new(250, "Queued"))
                    }
                    SMTPServerEvent::DataRejected(error) => {
                        println!("rejected: {error}");
                        message.clear();
                        None
                    }
                    _ => None,
                };
                if let Some(reply) = reply {
                    server.reply(reply, now).expect("a reply");
                }
            }
        }
        out.clear();
        server.transmit(&mut out);
        let _ = stream.write_all(&out);
    }

    pub fn client(host: &str, port: u16, arguments: &Arguments) {
        let mut message = Vec::new();
        std::io::stdin().read_to_end(&mut message).expect("a message");
        // RFC 5321 §2.3.8: lines end in CRLF.
        let message = String::from_utf8_lossy(&message).replace("\r\n", "\n").replace('\n', "\r\n").into_bytes();
        let mut stream = TcpStream::connect((host, port)).unwrap_or_else(|error| Tool::fail(&error.to_string()));
        let start = Clock::now();
        // Passwords go in the clear here: this is a test tool (a client refuses to by default).
        let config = SMTPConfig { passwords_require_tls: false, ..SMTPConfig::default() };
        let mut client = SMTPClient::new(config, false, Tool::now(start)).expect("a client");
        let name = arguments.get("--name").unwrap_or("client.umilib.test");
        let from = arguments.get("--from").unwrap_or_else(|| Tool::fail("--from"));
        let recipients = arguments.all("--to");
        let chunking = arguments.has("--chunking");
        let mut steps: Vec<String> = Vec::new();
        let mut plain = None;
        if let Some(credentials) = arguments.get("--auth") {
            let (user, password) = credentials.split_once(':').unwrap_or_else(|| Tool::fail("--auth USER:PASSWORD"));
            plain = Some(format!("\0{user}\0{password}").into_bytes());
            let response = Base64::STANDARD.encode(plain.as_deref().unwrap_or_default());
            steps.push(format!("AUTH PLAIN {response}"));
        }
        steps.push(format!("MAIL FROM:<{from}>"));
        steps.extend(recipients.iter().map(|to| format!("RCPT TO:<{to}>")));
        steps.reverse();
        let mut greeted = false;
        let mut sent = false;
        let mut out = Vec::new();
        while client.is_open() && start.elapsed() < Tool::BUDGET {
            out.clear();
            client.transmit(&mut out);
            let now = Tool::now(start);
            let Some(input) = Tool::exchange(&mut stream, &out, Tool::wait(client.poll_timeout(), now)) else { break };
            let now = Tool::now(start);
            if let Err(error) = client.receive(&input, now) {
                Tool::fail(&error.to_string());
            }
            if client.poll_timeout().is_some_and(|deadline| deadline <= now) {
                client.expire(now);
            }
            while let Some(event) = client.poll_event() {
                let mut advance = false;
                match event {
                    SMTPClientEvent::Greeting(reply) => {
                        println!("greeting: {}", reply.code);
                        greeted = true;
                        client.send(SMTPCommand::Ehlo(String::from(name)), now).expect("EHLO");
                    }
                    SMTPClientEvent::Reply { command, reply } => {
                        println!("reply: {} -> {}", command.verb(), reply.code);
                        if reply.code == 354 {
                            client.send_data(&message, now).unwrap_or_else(|error| Tool::fail(&error.to_string()));
                        } else if reply.severity() >= 4 && !matches!(command, SMTPCommand::Rcpt { .. }) {
                            Tool::fail(&format!("{} refused: {}", command.verb(), reply.text()));
                        } else if command.verb() == "BDAT" {
                            println!("sent");
                            sent = true;
                            advance = true;
                        } else {
                            advance = command != SMTPCommand::Quit;
                        }
                    }
                    SMTPClientEvent::DataReply(reply) => {
                        println!("reply: DATA end -> {}", reply.code);
                        if reply.is_positive() {
                            println!("sent");
                        }
                        sent = true;
                        advance = true;
                    }
                    // RFC 4954 §4: the initial response waits for an empty challenge if the line is too long.
                    SMTPClientEvent::AuthChallenge(_) => {
                        client.auth_respond(plain.as_deref().unwrap_or_default(), now).expect("a response");
                    }
                    SMTPClientEvent::Closed { error: Some(error) } => Tool::fail(&error.to_string()),
                    _ => {}
                }
                if advance {
                    let command = match steps.pop() {
                        Some(line) => SMTPCommand::parse(line.as_bytes(), true).expect("a command"),
                        None if sent => SMTPCommand::Quit,
                        None if chunking => {
                            client.send_chunk(&message, true, now).expect("a chunk");
                            continue;
                        }
                        None => SMTPCommand::Data,
                    };
                    client.send(command, now).unwrap_or_else(|error| Tool::fail(&error.to_string()));
                }
            }
        }
        if !greeted || !sent {
            Tool::fail("the message was not sent");
        }
    }
}

fn main() {
    let arguments = Arguments::parse();
    match arguments.position(0, "server or client") {
        "server" => {
            Tool::serve(arguments.position(1, "a port").parse().unwrap_or_else(|_| Tool::fail("a port")), &arguments)
        }
        "client" => {
            let host = arguments.position(1, "a host");
            let port = arguments.position(2, "a port").parse().unwrap_or_else(|_| Tool::fail("a port"));
            Tool::client(host, port, &arguments)
        }
        _ => Tool::fail("server or client"),
    }
}
