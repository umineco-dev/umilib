//! A POP3 server and client over TCP, to try umilib's POP3 against other
//! implementations (`examples/mail.sh` runs them against Dovecot, curl and
//! Python's poplib).
//!
//! ```text
//! pop3 server PORT
//! pop3 client HOST PORT USER PASSWORD [--apop] [--auth] [--retr NUMBER] [--delete NUMBER]
//! ```
//!
//! The server keeps a maildrop of two messages in memory for any user and
//! password (USER and PASS, APOP of the secret `tanstaaf`, AUTH PLAIN), and
//! prints a line for each command (`command: LINE`). The client logs in (with
//! `--apop` by APOP, `--auth` by AUTH PLAIN, USER and PASS otherwise), prints
//! `stat: COUNT SIZE` and the scan listing (`list: NUMBER SIZE`), with
//! `--retr` the message, with `--delete` marks one deleted, and quits.
//! Passwords are taken without TLS here: this is a test tool.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant as Clock};

use umilib::protocol::pop::v3::{
    POP3Client, POP3ClientEvent, POP3Command, POP3Config, POP3MultiLineWriter, POP3Response, POP3Server,
    POP3ServerConfig, POP3ServerEvent,
};
use umilib::runtime::Instant;

/// The command line: positional arguments and `--name value` options.
pub struct Arguments {
    pub positional: Vec<String>,
    pub options: Vec<(String, Option<String>)>,
}

impl Arguments {
    /// The options that take no value.
    pub const FLAGS: [&'static str; 2] = ["--apop", "--auth"];

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

/// The helpers of the tool.
pub struct Tool;

impl Tool {
    /// How long the client runs at most.
    pub const BUDGET: Duration = Duration::from_secs(30);
    /// The maildrop of the server.
    pub const MAILDROP: [&'static [u8]; 2] = [
        b"From: John Doe <jdoe@machine.example>\r\nSubject: first\r\n\r\nThis is the first message.\r\n.A line that begins with a period.\r\n",
        b"From: Mary Smith <mary@example.net>\r\nSubject: second\r\n\r\nThe second message.\r\n",
    ];

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
        let settings = POP3ServerConfig {
            sasl_mechanisms: vec![String::from("PLAIN")],
            passwords_require_tls: false,
            ..POP3ServerConfig::default()
        };
        let mut server = POP3Server::new(POP3Config::default(), settings, false).expect("a server");
        let timestamp = format!("<{}.{}@umilib.test>", std::process::id(), start.elapsed().as_nanos());
        server
            .greet(POP3Response::ok(&format!("POP3 server ready {timestamp}")), Tool::now(start))
            .expect("a greeting");
        let mut deleted = [false; Tool::MAILDROP.len()];
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
                    POP3ServerEvent::Command(command) => {
                        println!("command: {command}");
                        Tool::answer(&mut server, &command, &timestamp, &mut deleted, now);
                    }
                    POP3ServerEvent::AuthResponse(response) => {
                        let user = response.split(|byte| *byte == 0).nth(1).unwrap_or_default();
                        println!("auth: {}", String::from_utf8_lossy(user));
                        server.reply(POP3Response::ok("logged in"), now).expect("a reply");
                    }
                    _ => {}
                }
            }
        }
        out.clear();
        server.transmit(&mut out);
        let _ = stream.write_all(&out);
    }

    /// Answers a command of the maildrop.
    pub fn answer(server: &mut POP3Server, command: &POP3Command, timestamp: &str, deleted: &mut [bool], now: Instant) {
        let present = |number: u32| {
            let index = (number as usize).checked_sub(1)?;
            (index < Tool::MAILDROP.len() && !deleted[index]).then_some(index)
        };
        let size = |index: usize| POP3MultiLineWriter::canonical_length(Tool::MAILDROP[index]);
        let indices: Vec<usize> = (0..Tool::MAILDROP.len()).filter(|index| !deleted[*index]).collect();
        let (response, data) = match command {
            POP3Command::User(_) | POP3Command::Pass(_) | POP3Command::Noop | POP3Command::Rset => {
                (POP3Response::ok(""), None)
            }
            POP3Command::Apop { digest, .. } => {
                match POP3Command::apop_matches(digest, timestamp.as_bytes(), b"tanstaaf") {
                    true => (POP3Response::ok("maildrop locked and ready"), None),
                    false => (POP3Response::error_with(&["AUTH"], "permission denied"), None),
                }
            }
            POP3Command::Auth { .. } => {
                server.auth_challenge(b"", now).expect("a challenge");
                return;
            }
            POP3Command::Stat => {
                let total: u64 = indices.iter().map(|index| size(*index)).sum();
                (POP3Response::ok(&format!("{} {total}", indices.len())), None)
            }
            POP3Command::List(None) => {
                let lines: String = indices.iter().map(|index| format!("{} {}\r\n", index + 1, size(*index))).collect();
                (POP3Response::ok(&format!("{} messages", indices.len())), Some(lines.into_bytes()))
            }
            POP3Command::List(Some(number)) => match present(*number) {
                Some(index) => (POP3Response::ok(&format!("{number} {}", size(index))), None),
                None => (POP3Response::error("no such message"), None),
            },
            POP3Command::Uidl(None) => {
                let lines: String =
                    indices.iter().map(|index| format!("{} message-{}\r\n", index + 1, index + 1)).collect();
                (POP3Response::ok(""), Some(lines.into_bytes()))
            }
            POP3Command::Retr(number) => match present(*number) {
                Some(index) => {
                    (POP3Response::ok(&format!("{} octets", size(index))), Some(Tool::MAILDROP[index].to_vec()))
                }
                None => (POP3Response::error("no such message"), None),
            },
            POP3Command::Top { message, lines } => match present(*message) {
                Some(index) => {
                    let text = Tool::MAILDROP[index];
                    let body = text.windows(4).position(|window| window == b"\r\n\r\n").map_or(text.len(), |at| at + 4);
                    let top: Vec<&[u8]> = text[body..].split(|byte| *byte == b'\n').take(*lines as usize).collect();
                    (POP3Response::ok(""), Some([&text[..body], &top.join(&b'\n')[..]].concat()))
                }
                None => (POP3Response::error("no such message"), None),
            },
            POP3Command::Dele(number) => match present(*number) {
                Some(index) => {
                    deleted[index] = true;
                    (POP3Response::ok(&format!("message {number} deleted")), None)
                }
                None => (POP3Response::error("no such message"), None),
            },
            POP3Command::Quit => (POP3Response::ok("umilib POP3 server signing off"), None),
            _ => (POP3Response::error("not implemented"), None),
        };
        let multi = response.ok && command.is_multi_line();
        server.reply(response, now).expect("a reply");
        if multi {
            server.send_data(&data.unwrap_or_default()).expect("the lines");
            server.end_data(now).expect("the end");
        }
    }

    pub fn client(host: &str, port: u16, user: &str, password: &str, arguments: &Arguments) {
        let mut stream = TcpStream::connect((host, port)).unwrap_or_else(|error| Tool::fail(&error.to_string()));
        let start = Clock::now();
        // Passwords go in the clear here: this is a test tool (a client refuses to by default).
        let config = POP3Config { passwords_require_tls: false, ..POP3Config::default() };
        let mut client = POP3Client::new(config, false, Tool::now(start)).expect("a client");
        let mut queue: Vec<POP3Command> = Vec::new();
        let mut data = Vec::new();
        let mut current = None;
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
                match event {
                    POP3ClientEvent::Greeting(greeting) => {
                        println!("greeting: {}", String::from_utf8_lossy(&greeting.text));
                        let mut login = vec![POP3Command::Capa];
                        if arguments.has("--apop") {
                            let timestamp = greeting.timestamp().unwrap_or_else(|| Tool::fail("no APOP timestamp"));
                            login.push(POP3Command::apop(user, timestamp, password.as_bytes()));
                        } else if arguments.has("--auth") {
                            login.push(POP3Command::parse(b"AUTH PLAIN", false).expect("AUTH"));
                        } else {
                            login.push(POP3Command::User(String::from(user)));
                            login.push(POP3Command::Pass(String::from(password)));
                        }
                        login.extend([POP3Command::Stat, POP3Command::List(None)]);
                        if let Some(number) = arguments.get("--retr") {
                            login.push(POP3Command::Retr(
                                number.parse().unwrap_or_else(|_| Tool::fail("--retr NUMBER")),
                            ));
                        }
                        if let Some(number) = arguments.get("--delete") {
                            login.push(POP3Command::Dele(
                                number.parse().unwrap_or_else(|_| Tool::fail("--delete NUMBER")),
                            ));
                        }
                        login.push(POP3Command::Quit);
                        login.reverse();
                        queue = login;
                        client.send(queue.pop().expect("a command"), now).expect("CAPA");
                    }
                    POP3ClientEvent::Response { command, response } => {
                        if !response.ok {
                            Tool::fail(&format!("{command}: {}", String::from_utf8_lossy(&response.text)));
                        }
                        match &command {
                            POP3Command::Stat => println!("stat: {}", String::from_utf8_lossy(&response.text)),
                            POP3Command::Dele(number) => println!("deleted: {number}"),
                            POP3Command::Quit => println!("quit"),
                            _ => {}
                        }
                        match command.is_multi_line() {
                            true => current = Some(command),
                            false => Tool::next(&mut client, &mut queue, now),
                        }
                    }
                    POP3ClientEvent::Data(lines) => data.extend_from_slice(&lines),
                    POP3ClientEvent::DataEnd => {
                        let text = String::from_utf8_lossy(&data).into_owned();
                        match current.take() {
                            Some(POP3Command::List(_)) => text.lines().for_each(|line| println!("list: {line}")),
                            Some(POP3Command::Capa) => text.lines().for_each(|line| println!("capability: {line}")),
                            _ => print!("{text}"),
                        }
                        data.clear();
                        Tool::next(&mut client, &mut queue, now);
                    }
                    POP3ClientEvent::AuthChallenge(_) => {
                        client.auth_respond(format!("\0{user}\0{password}").as_bytes(), now).expect("a response");
                    }
                    POP3ClientEvent::Closed { error: Some(error) } => Tool::fail(&error.to_string()),
                    _ => {}
                }
            }
        }
    }

    /// Sends the next command of the session, if any is left.
    pub fn next(client: &mut POP3Client, queue: &mut Vec<POP3Command>, now: Instant) {
        if let Some(command) = queue.pop() {
            client.send(command, now).unwrap_or_else(|error| Tool::fail(&error.to_string()));
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
