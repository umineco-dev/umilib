//! An FTP server and client over TCP, to try umilib's FTP against other
//! implementations (`examples/ftp.sh` runs them against vsftpd, curl and
//! Python's ftplib).
//!
//! ```text
//! ftp server PORT [--passive FIRST-LAST]
//! ftp client HOST PORT USER PASSWORD [--pasv] [--list] [--get NAME] [--put NAME] [--size NAME]
//! ```
//!
//! The server keeps a directory of files in memory for any user and
//! password, with passive data connections (PASV and EPSV) on the ports
//! `--passive` gives, and answers PWD, CWD, SIZE, MDTM, LIST, NLST, MLSD,
//! MLST, RETR, STOR, DELE and REST; it prints a line for each command
//! (`command: LINE`). The client logs in, and for each of `--list`, `--get`
//! (to its standard output), `--put` (from its standard input) and `--size`
//! opens a data connection with EPSV (`--pasv`: PASV), listing with MLSD
//! where the server has MLST and LIST otherwise, and quits, printing
//! each final reply (`reply: VERB -> CODE`).

use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as Clock};

use umilib::protocol::ftp::{
    FTPClient, FTPClientEvent, FTPCommand, FTPConfig, FTPDataAddress, FTPFacts, FTPReply, FTPServer, FTPServerConfig,
    FTPServerEvent, FTPTime,
};
use umilib::protocol::ip::{IPAddress, IPv4Address, IPv6Address};
use umilib::runtime::Instant;

/// The command line: positional arguments and `--name value` options.
pub struct Arguments {
    pub positional: Vec<String>,
    pub options: Vec<(String, Option<String>)>,
}

impl Arguments {
    /// The options that take no value.
    pub const FLAGS: [&'static str; 2] = ["--pasv", "--list"];

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

/// A file of the server's directory.
pub struct File {
    pub name: String,
    pub data: Vec<u8>,
    pub modified: FTPTime,
}

/// The helpers of the tool.
pub struct Tool;

impl Tool {
    /// How long the client runs, and a data connection waits, at most.
    pub const BUDGET: Duration = Duration::from_secs(30);

    pub fn fail(message: &str) -> ! {
        eprintln!("error: {message}");
        std::process::exit(2)
    }

    pub fn now(start: Clock) -> Instant {
        Instant::from_nanos(start.elapsed().as_nanos() as u64)
    }

    pub fn address(ip: IpAddr) -> IPAddress {
        match ip {
            IpAddr::V4(ip) => IPAddress::V4(IPv4Address(ip.octets())),
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(mapped) => IPAddress::V4(IPv4Address(mapped.octets())),
                None => IPAddress::V6(IPv6Address(ip.octets())),
            },
        }
    }

    pub fn ip(address: IPAddress) -> IpAddr {
        match address {
            IPAddress::V4(address) => IpAddr::from(address.0),
            IPAddress::V6(address) => IpAddr::from(address.0),
        }
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

    pub fn serve(port: u16, passive: (u16, u16)) {
        let listener = TcpListener::bind(("0.0.0.0", port)).unwrap_or_else(|error| Tool::fail(&error.to_string()));
        println!("listening: {port}");
        let files = Arc::new(Mutex::new(vec![
            File {
                name: String::from("hello.txt"),
                data: b"Hello, FTP!\r\n".to_vec(),
                modified: FTPTime::new(897_904_845, 0),
            },
            File {
                name: String::from("data.bin"),
                data: (0..65536u32).map(|index| index as u8).collect(),
                modified: FTPTime::new(1_700_000_000, 0),
            },
        ]));
        for stream in listener.incoming().flatten() {
            let files = Arc::clone(&files);
            std::thread::spawn(move || Tool::session(stream, passive, &files));
        }
    }

    /// A listener of a data connection on a port of `passive`, of the control connection's local address.
    pub fn listen(local: IpAddr, passive: (u16, u16)) -> Option<TcpListener> {
        (passive.0..=passive.1).find_map(|port| TcpListener::bind((local, port)).ok())
    }

    /// The facts of a file, as MLSD and MLST give them (RFC 3659 §7).
    pub fn facts(file: &File) -> FTPFacts {
        let mut facts = FTPFacts::new(&file.name);
        facts.set("type", "file");
        facts.set("size", &file.data.len().to_string());
        facts.set("modify", &file.modified.to_string());
        facts.set("perm", "adfrw");
        facts
    }

    /// One connection of the server.
    pub fn session(mut stream: TcpStream, passive: (u16, u16), files: &Mutex<Vec<File>>) {
        let start = Clock::now();
        let (peer, local) = match (stream.peer_addr(), stream.local_addr()) {
            (Ok(peer), Ok(local)) => (peer.ip(), local.ip()),
            _ => return,
        };
        let mut server = FTPServer::new(FTPConfig::default(), FTPServerConfig::default(), Tool::address(peer), false)
            .expect("a server");
        server.greet(FTPReply::new(220, "umilib FTP server ready"), Tool::now(start)).expect("a greeting");
        let mut data: Option<TcpListener> = None;
        let mut restart = 0usize;
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
                let FTPServerEvent::Command(command) = event else { continue };
                println!("command: {command}");
                let line = command.to_string();
                let argument =
                    line.split_once(' ').map_or("", |(_, argument)| argument).trim_start_matches('/').to_string();
                let mut files = files.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let found = files.iter().position(|file| file.name == argument);
                let reply = |code, text: &str| FTPReply::new(code, text);
                let answer = match command.verb() {
                    "USER" => reply(331, "Password required"),
                    "PASS" => reply(230, "Logged in"),
                    "PWD" => FTPReply::with_pathname("/", "is the current directory"),
                    "CWD" if argument.is_empty() => reply(250, "Directory changed"),
                    "CWD" => reply(550, "No such directory"),
                    "SIZE" => match found {
                        Some(index) => reply(213, &files[index].data.len().to_string()),
                        None => reply(550, "No such file"),
                    },
                    "MDTM" => match found {
                        Some(index) => reply(213, &files[index].modified.to_string()),
                        None => reply(550, "No such file"),
                    },
                    "MLST" => match found {
                        Some(index) => FTPReply {
                            code: 250,
                            lines: vec![
                                b"Listing".to_vec(),
                                format!(" {}", Tool::facts(&files[index])).into_bytes(),
                                b"End".to_vec(),
                            ],
                        },
                        None => reply(550, "No such file"),
                    },
                    "DELE" => match found {
                        Some(index) => {
                            files.remove(index);
                            reply(250, "Deleted")
                        }
                        None => reply(550, "No such file"),
                    },
                    "REST" => {
                        restart = argument.parse().unwrap_or(0);
                        reply(350, "Restarting")
                    }
                    "PASV" | "EPSV" => match Tool::listen(local, passive) {
                        Some(listener) => {
                            let port = listener.local_addr().map(|address| address.port()).unwrap_or(0);
                            data = Some(listener);
                            match command.verb() {
                                "PASV" => FTPDataAddress::new(Some(Tool::address(local)), port)
                                    .pasv_reply()
                                    .unwrap_or_else(|_| reply(425, "No IPv4 address")),
                                _ => FTPDataAddress::new(None, port).epsv_reply(),
                            }
                        }
                        None => reply(425, "No data port free"),
                    },
                    verb if command.transfers() => {
                        let Some(listener) = data.take() else {
                            server.reply(reply(425, "Use PASV or EPSV first"), now).expect("a reply");
                            continue;
                        };
                        if matches!(verb, "RETR") && found.is_none() {
                            server.reply(reply(550, "No such file"), now).expect("a reply");
                            continue;
                        }
                        server.reply(reply(150, "Opening data connection"), now).expect("a reply");
                        out.clear();
                        server.transmit(&mut out);
                        let _ = stream.write_all(&out);
                        let _ = listener.set_nonblocking(false);
                        let Ok((mut connection, _)) = listener.accept() else {
                            server.reply(reply(425, "No data connection"), Tool::now(start)).expect("a reply");
                            continue;
                        };
                        let _ = connection.set_read_timeout(Some(Tool::BUDGET));
                        let sent = match verb {
                            "RETR" => connection.write_all(
                                &files[found.unwrap_or_default()].data
                                    [restart.min(files[found.unwrap_or_default()].data.len())..],
                            ),
                            "LIST" => connection.write_all(
                                files
                                    .iter()
                                    .map(|file| {
                                        format!(
                                            "-rw-r--r-- 1 ftp ftp {} Jan 01 00:00 {}\r\n",
                                            file.data.len(),
                                            file.name
                                        )
                                    })
                                    .collect::<String>()
                                    .as_bytes(),
                            ),
                            "NLST" => connection.write_all(
                                files.iter().map(|file| format!("{}\r\n", file.name)).collect::<String>().as_bytes(),
                            ),
                            "MLSD" => connection.write_all(
                                files
                                    .iter()
                                    .map(|file| format!("{}\r\n", Tool::facts(file)))
                                    .collect::<String>()
                                    .as_bytes(),
                            ),
                            "STOR" | "APPE" => {
                                let mut received = Vec::new();
                                let result = connection.read_to_end(&mut received).map(|_| ());
                                println!("stored: {argument} {} octets", received.len());
                                match files.iter_mut().find(|file| file.name == argument) {
                                    Some(file) if verb == "APPE" => file.data.extend(received),
                                    Some(file) => file.data = received,
                                    None => files.push(File {
                                        name: argument.clone(),
                                        data: received,
                                        modified: FTPTime::new(1_800_000_000, 0),
                                    }),
                                }
                                result
                            }
                            _ => Ok(()),
                        };
                        restart = 0;
                        let _ = connection.shutdown(Shutdown::Both);
                        match sent {
                            Ok(()) => reply(226, "Transfer complete"),
                            Err(_) => reply(426, "Connection closed; transfer aborted"),
                        }
                    }
                    _ => reply(502, "Command not implemented"),
                };
                server.reply(answer, Tool::now(start)).expect("a reply");
            }
        }
        out.clear();
        server.transmit(&mut out);
        let _ = stream.write_all(&out);
    }

    pub fn client(host: &str, port: u16, user: &str, password: &str, arguments: &Arguments) {
        let mut stream = TcpStream::connect((host, port)).unwrap_or_else(|error| Tool::fail(&error.to_string()));
        let server_ip =
            stream.peer_addr().map(|address| address.ip()).unwrap_or_else(|error| Tool::fail(&error.to_string()));
        let start = Clock::now();
        let mut client = FTPClient::new(FTPConfig::default(), false, Tool::now(start)).expect("a client");
        let passive = if arguments.has("--pasv") { "PASV" } else { "EPSV" };
        let mut upload = Vec::new();
        if arguments.get("--put").is_some() {
            std::io::stdin().read_to_end(&mut upload).expect("the file");
        }
        let mut steps: Vec<String> = vec![
            format!("USER {user}"),
            format!("PASS {password}"),
            String::from("TYPE I"),
            String::from("FEAT"),
            String::from("PWD"),
        ];
        if let Some(name) = arguments.get("--size") {
            steps.push(format!("SIZE {name}"));
            steps.push(format!("MDTM {name}"));
        }
        if arguments.has("--list") {
            steps.extend([String::from(passive), String::from("MLSD")]);
        }
        if let Some(name) = arguments.get("--get") {
            steps.extend([String::from(passive), format!("RETR {name}")]);
        }
        if let Some(name) = arguments.get("--put") {
            steps.extend([String::from(passive), format!("STOR {name}")]);
        }
        steps.push(String::from("QUIT"));
        steps.reverse();
        let mut data: Option<TcpStream> = None;
        let connect = |address: SocketAddr| {
            TcpStream::connect_timeout(&address, Tool::BUDGET).unwrap_or_else(|error| Tool::fail(&error.to_string()))
        };
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
                    FTPClientEvent::Greeting(reply) => {
                        println!("greeting: {}", reply.code);
                        advance = true;
                    }
                    FTPClientEvent::Preliminary { command, reply } => {
                        println!("preliminary: {} -> {}", command.verb(), reply.code);
                        let mut connection = data.take().unwrap_or_else(|| Tool::fail("no data connection"));
                        match command.verb() {
                            "STOR" => {
                                connection.write_all(&upload).expect("the upload");
                                let _ = connection.shutdown(Shutdown::Write);
                            }
                            verb => {
                                let mut received = Vec::new();
                                connection.read_to_end(&mut received).expect("the data");
                                match verb {
                                    "RETR" => std::io::stdout().write_all(&received).expect("the output"),
                                    _ => String::from_utf8_lossy(&received)
                                        .lines()
                                        .for_each(|line| println!("entry: {line}")),
                                }
                            }
                        }
                    }
                    FTPClientEvent::Reply { command, reply } => {
                        println!("reply: {} -> {}", command.verb(), reply.code);
                        match command.verb() {
                            "PASV" => {
                                let address = FTPDataAddress::from_pasv(&reply)
                                    .unwrap_or_else(|error| Tool::fail(&error.to_string()));
                                // Connected now: some servers send the transfer's 150 only once it is.
                                data = Some(connect(SocketAddr::new(
                                    Tool::ip(address.host.expect("a host")),
                                    address.port,
                                )));
                            }
                            "EPSV" => {
                                let address = FTPDataAddress::from_epsv(&reply)
                                    .unwrap_or_else(|error| Tool::fail(&error.to_string()));
                                data = Some(connect(SocketAddr::new(server_ip, address.port)));
                            }
                            "PWD" => println!("directory: {}", reply.pathname().unwrap_or_default()),
                            "SIZE" | "MDTM" => println!("{}: {}", command.verb().to_ascii_lowercase(), reply.text()),
                            "FEAT" => {}
                            _ => {}
                        }
                        if reply.is_negative() && !matches!(command.verb(), "FEAT" | "QUIT") {
                            Tool::fail(&format!("{command}: {}", reply.text()));
                        }
                        advance = command.verb() != "QUIT";
                    }
                    FTPClientEvent::Closed { error: Some(error) } => Tool::fail(&error.to_string()),
                    _ => {}
                }
                if advance && let Some(mut line) = steps.pop() {
                    // MLSD where FEAT lists MLST (RFC 3659 §7.1), LIST otherwise.
                    if line == "MLSD" && !client.has_feature("MLST") {
                        line = String::from("LIST");
                    }
                    let command = FTPCommand::parse(line.as_bytes()).expect("a command");
                    client.send(command, now).unwrap_or_else(|error| Tool::fail(&error.to_string()));
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
        "server" => {
            let range = arguments.get("--passive").unwrap_or("30000-30099");
            let (first, last) = range.split_once('-').unwrap_or_else(|| Tool::fail("--passive FIRST-LAST"));
            let parse = |text: &str| text.parse().unwrap_or_else(|_| Tool::fail("--passive FIRST-LAST"));
            Tool::serve(port(1), (parse(first), parse(last)))
        }
        "client" => {
            let (host, user, password) =
                (arguments.position(1, "a host"), arguments.position(3, "a user"), arguments.position(4, "a password"));
            Tool::client(host, port(2), user, password, &arguments)
        }
        _ => Tool::fail("server or client"),
    }
}
