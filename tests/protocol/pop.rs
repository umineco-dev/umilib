//! POP3 (RFC 1939): the session of §10 and the examples of the commands,
//! the CAPA list of RFC 2449 §5, STLS of RFC 2595 §4 and the AUTH
//! exchanges of RFC 5034 §6, run by the client against the server's lines
//! and by the server against the client's; and the rules of each: states,
//! response codes, multi-line responses and their periods, limits.

use std::time::Duration;

use umilib::codec::base::Encoding;
use umilib::codec::base::base64::Base64;
use umilib::protocol::pop::v3::{
    POP3Capabilities, POP3Client, POP3ClientEvent, POP3Command, POP3Config, POP3Error, POP3MultiLineReader,
    POP3MultiLineWriter, POP3Response, POP3Server, POP3ServerConfig, POP3ServerEvent, POP3State,
};
use umilib::runtime::Instant;

use crate::Vectors;

const T0: Instant = Instant::from_nanos(1_000_000_000);

/// A client that sends passwords in the clear, as the examples of the RFCs do: refusing to is
/// the default (RFC 2595 §2.3).
fn clear() -> POP3Config {
    POP3Config { passwords_require_tls: false, ..POP3Config::default() }
}

#[derive(Clone, Debug)]
struct Step {
    client: bool,
    text: String,
}

/// The dialogue of an RFC from the line beginning with `start` to the one
/// beginning with `end`: its lines of `C:` and `S:`, the lines in angle
/// brackets left out, and the lines of base64 wrapped onto the next
/// (RFC 5034 §6, "broken for editorial clarity only") joined.
fn dialogue(path: &str, start: &str, end: &str) -> Vec<Step> {
    let text = Vectors::read(path);
    let lines: Vec<&str> = text.lines().collect();
    let heading = |line: &&str, text: &str| {
        line.trim_start().starts_with(text) && !line.contains(". . .") && !line.contains("....")
    };
    let first = lines.iter().position(|line| heading(line, start)).expect("the start of the dialogue");
    let last = first + 1 + lines[first + 1..].iter().position(|line| heading(line, end)).expect("its end");
    let mut steps: Vec<Step> = Vec::new();
    for line in &lines[first..last] {
        let trimmed = line.trim_start();
        let (client, rest) = match trimmed.split_at_checked(2) {
            Some(("C:", rest)) => (true, rest.trim_start()),
            Some(("S:", rest)) => (false, rest.trim_start()),
            _ => {
                let base64 = !trimmed.is_empty()
                    && trimmed.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte));
                if let Some(previous) = steps.last_mut().filter(|_| base64 && line.starts_with("          ")) {
                    previous.text.push_str(trimmed);
                }
                continue;
            }
        };
        if rest.starts_with('<') && rest.ends_with('>') && !rest.contains('@') {
            continue;
        }
        steps.push(Step { client, text: rest.to_string() });
    }
    steps
}

/// Runs the client's side: it sends the client's lines and checks that
/// what it sends is them, when they are said. The responses and data told.
fn run_client(steps: &[Step]) -> (POP3Client, Vec<POP3ClientEvent>) {
    let mut client = POP3Client::new(clear(), false, T0).unwrap();
    let (mut expected, mut sent, mut told) = (Vec::new(), Vec::new(), Vec::new());
    for step in steps {
        let line = format!("{}\r\n", step.text).into_bytes();
        if step.client {
            expected.extend_from_slice(&line);
            if client.authenticating {
                client.auth_respond(&Base64::STANDARD.decode(step.text.as_bytes()).unwrap(), T0).unwrap();
            } else {
                let command = POP3Command::parse(step.text.as_bytes(), false).unwrap();
                client.send(command, T0).unwrap_or_else(|error| panic!("{}: {error}", step.text));
            }
        } else {
            client.receive(&line, T0).unwrap();
        }
        client.transmit(&mut sent);
        assert_eq!(String::from_utf8_lossy(&sent), String::from_utf8_lossy(&expected), "after {:?}", step.text);
        told.extend(std::iter::from_fn(|| client.poll_event()));
    }
    (client, told)
}

/// Runs the server's side: it feeds the client's lines and answers what
/// the server tells with the dialogue's lines, multi-line responses sent
/// line by line. What the server sends is the dialogue's server lines,
/// status lines compared by their status only (a server writes its own text
/// for what it answers itself).
fn run_server(steps: &[Step], config: POP3ServerConfig) -> POP3Server {
    let server_lines: Vec<&Step> = steps.iter().filter(|step| !step.client).collect();
    let mut server = POP3Server::new(POP3Config::default(), config, false).unwrap();
    server.greet(POP3Response::parse(server_lines[0].text.as_bytes()).unwrap(), T0).unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    let mut next = 1;
    let mut written = 1;
    let count = |out: &[u8]| out.windows(2).filter(|pair| pair == b"\r\n").count();
    for step in steps.iter().filter(|step| step.client) {
        server.receive(format!("{}\r\n", step.text).as_bytes(), T0);
        loop {
            server.transmit(&mut out);
            // The server lines it wrote itself are skipped.
            next = next.max(written).max(count(&out));
            written = count(&out);
            let Some(event) = server.poll_event() else { break };
            let line = |index: usize| server_lines[index].text.clone();
            match event {
                POP3ServerEvent::Command(POP3Command::Auth { .. }) | POP3ServerEvent::AuthResponse(_)
                    if line(next).starts_with('+') && !line(next).starts_with("+OK") =>
                {
                    let challenge =
                        Base64::STANDARD.decode(line(next).trim_start_matches('+').trim_start().as_bytes()).unwrap();
                    server.auth_challenge(&challenge, T0).unwrap();
                }
                POP3ServerEvent::Command(command) => {
                    let response = POP3Response::parse(line(next).as_bytes()).unwrap();
                    let multi = response.ok && command.is_multi_line();
                    server.reply(response, T0).unwrap();
                    if multi {
                        let mut index = next + 1;
                        while line(index) != "." {
                            let text = line(index);
                            server
                                .send_data(format!("{}\r\n", text.strip_prefix('.').unwrap_or(&text)).as_bytes())
                                .unwrap();
                            index += 1;
                        }
                        server.end_data(T0).unwrap();
                    }
                }
                POP3ServerEvent::AuthResponse(_) => {
                    server.reply(POP3Response::parse(line(next).as_bytes()).unwrap(), T0).unwrap()
                }
                _ => {}
            }
        }
    }
    let lines: Vec<&[u8]> = out
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| line.strip_suffix(b"\r").unwrap())
        .collect();
    assert_eq!(lines.len(), server_lines.len(), "{}", String::from_utf8_lossy(&out));
    for (written, expected) in lines.iter().zip(&server_lines) {
        let status = |line: &[u8]| POP3Response::parse(line).ok().map(|response| response.ok);
        match status(expected.text.as_bytes()) {
            Some(ok) => assert_eq!(status(written), Some(ok), "{}", String::from_utf8_lossy(written)),
            None => assert_eq!(*written, expected.text.as_bytes()),
        }
    }
    server
}

#[test]
fn rfc1939_example_session() {
    let steps = dialogue("protocol/pop/rfc1939.txt", "10. Example POP3 Session", "11. Message Format");
    let (client, told) = run_client(&steps);
    assert_eq!(client.state, POP3State::Update);
    assert!(!client.is_open());
    // The lines of the first multi-line response, LIST.
    let listing: Vec<u8> = told
        .iter()
        .skip_while(|event| !matches!(event, POP3ClientEvent::Data(_)))
        .take_while(|event| **event != POP3ClientEvent::DataEnd)
        .flat_map(|event| match event {
            POP3ClientEvent::Data(data) => data.clone(),
            _ => Vec::new(),
        })
        .collect();
    assert_eq!(listing, b"1 120\r\n2 200\r\n");
    let greeting = told
        .iter()
        .find_map(|event| match event {
            POP3ClientEvent::Greeting(greeting) => Some(greeting.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(greeting.timestamp(), Some(&b"<1896.697170952@dbc.mtview.ca.us>"[..]));
    // The server, APOP offered by the timestamp of its greeting.
    let config = POP3ServerConfig { passwords_require_tls: false, ..POP3ServerConfig::default() };
    let server = run_server(&steps, config);
    assert_eq!(server.state, POP3State::Update);
}

#[cfg(umilib_feature = "hash-md-v5")]
#[test]
fn rfc1939_apop_digest() {
    // §7: the digest of the timestamp and the secret "tanstaaf".
    let timestamp = b"<1896.697170952@dbc.mtview.ca.us>";
    assert_eq!(POP3Command::apop_digest(timestamp, b"tanstaaf"), "c4c9334bac560ecc979e58001b3e22fb");
    assert_eq!(
        POP3Command::apop("mrose", timestamp, b"tanstaaf").to_string(),
        "APOP mrose c4c9334bac560ecc979e58001b3e22fb"
    );
    assert!(POP3Command::apop_matches("c4c9334bac560ecc979e58001b3e22fb", timestamp, b"tanstaaf"));
    assert!(!POP3Command::apop_matches("c4c9334bac560ecc979e58001b3e22fa", timestamp, b"tanstaaf"));
}

#[test]
fn rfc1939_commands_and_states() {
    let parse = |line: &[u8]| POP3Command::parse(line, false);
    // §3: keywords in any case, of 3 or 4 characters; message numbers of 1 or more.
    assert_eq!(parse(b"retr 1").unwrap(), POP3Command::Retr(1));
    assert_eq!(parse(b"TOP 1 10").unwrap(), POP3Command::Top { message: 1, lines: 10 });
    assert_eq!(parse(b"TOP 1 0").unwrap(), POP3Command::Top { message: 1, lines: 0 });
    assert_eq!(parse(b"LIST").unwrap(), POP3Command::List(None));
    assert_eq!(parse(b"UIDL 2").unwrap(), POP3Command::Uidl(Some(2)));
    assert!(parse(b"RETR 0").is_err());
    assert!(parse(b"RETR").is_err());
    assert!(parse(b"RETR 1 2").is_err());
    assert!(parse(b"RETR x").is_err());
    assert!(parse(b"QUIT now").is_err());
    assert!(parse(b"RETR  1").is_err(), "parameters separated by a single space");
    // §7: a password may have spaces.
    assert_eq!(parse(b"PASS my secret").unwrap(), POP3Command::Pass("my secret".into()));
    assert!(parse(b"APOP mrose C4C9334BAC560ECC979E58001B3E22FB").is_err(), "a digest of lower-case hexadecimal");
    // §3: +OK and -ERR in upper case; RFC 2449 §8: response codes.
    assert!(POP3Response::parse(b"+ok").is_err());
    let response = POP3Response::parse(b"-ERR [IN-USE] Do you have another POP session running?").unwrap();
    assert!(!response.ok && response.has_code(&["IN-USE"]));
    assert_eq!(response.text, b"Do you have another POP session running?");
    assert!(POP3Response::parse(b"-ERR [SYS/TEMP] try later").unwrap().has_code(&["SYS", "TEMP"]));
    let mut out = Vec::new();
    POP3Response::error_with(&["LOGIN-DELAY"], "wait").encode(&mut out);
    assert_eq!(out, b"-ERR [LOGIN-DELAY] wait\r\n");
    // The server: commands of the other state are -ERR (§3), the UIDL and TOP examples of §7.
    let mut server = POP3Server::new(
        POP3Config::default(),
        POP3ServerConfig { passwords_require_tls: false, ..POP3ServerConfig::default() },
        false,
    )
    .unwrap();
    server.greet(POP3Response::ok("POP3 server ready"), T0).unwrap();
    server.receive(b"STAT\r\nPASS secret\r\nUSER mrose\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert_eq!(out, b"+OK POP3 server ready\r\n-ERR Not in the AUTHORIZATION state\r\n-ERR USER first\r\n");
    assert_eq!(server.poll_event(), Some(POP3ServerEvent::Command(POP3Command::User("mrose".into()))));
    server.reply(POP3Response::ok("mrose is a real hoopy frood"), T0).unwrap();
    server.receive(b"PASS secret\r\n", T0);
    assert_eq!(server.poll_event(), Some(POP3ServerEvent::Command(POP3Command::Pass("secret".into()))));
    server.reply(POP3Response::ok("mrose's maildrop has 2 messages (320 octets)"), T0).unwrap();
    assert_eq!(server.state, POP3State::Transaction);
    server.receive(b"USER x\r\nNOOP\r\nUIDL\r\n", T0);
    assert_eq!(server.poll_event(), Some(POP3ServerEvent::Command(POP3Command::Uidl(None))));
    server.reply(POP3Response::ok(""), T0).unwrap();
    server.send_data(b"1 whqtswO00WBw418f9t5JxYwZ\r\n2 QhdPYR:00WBw1Ph7x7\r\n").unwrap();
    server.end_data(T0).unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    let expected = "-ERR Not in the TRANSACTION state\r\n+OK OK\r\n+OK\r\n1 whqtswO00WBw418f9t5JxYwZ\r\n2 QhdPYR:00WBw1Ph7x7\r\n.\r\n";
    assert!(String::from_utf8_lossy(&out).ends_with(expected), "{}", String::from_utf8_lossy(&out));
    // §6: QUIT in the TRANSACTION state is told (the UPDATE state), then the connection closes.
    server.receive(b"QUIT\r\n", T0);
    assert_eq!(server.poll_event(), Some(POP3ServerEvent::Command(POP3Command::Quit)));
    server.reply(POP3Response::ok("dewey POP3 server signing off (maildrop empty)"), T0).unwrap();
    assert!(!server.is_open());
    assert_eq!(server.state, POP3State::Update);
    // §6: QUIT in the AUTHORIZATION state is answered by the server, without the UPDATE state.
    let mut early = POP3Server::new(POP3Config::default(), POP3ServerConfig::default(), false).unwrap();
    early.greet(POP3Response::ok("ready"), T0).unwrap();
    early.receive(b"QUIT\r\n", T0);
    assert!(!early.is_open());
    assert!(!std::iter::from_fn(|| early.poll_event()).any(|event| matches!(event, POP3ServerEvent::Command(_))));
    // The client sends commands only in their state, PASS only after USER is accepted.
    let mut client = POP3Client::new(clear(), false, T0).unwrap();
    client.receive(b"+OK ready\r\n", T0).unwrap();
    assert!(client.send(POP3Command::Stat, T0).is_err());
    assert!(client.send(POP3Command::Pass("x".into()), T0).is_err());
    client.send(POP3Command::User("mrose".into()), T0).unwrap();
    client.receive(b"-ERR sorry, no mailbox for frated here\r\n", T0).unwrap();
    assert!(client.send(POP3Command::Pass("x".into()), T0).is_err());
}

#[test]
fn multi_lines_of_section_3() {
    // A line beginning with the termination octet is byte-stuffed; the end is CRLF.CRLF.
    let mut writer = POP3MultiLineWriter::new();
    let mut out = Vec::new();
    writer.write(b".hidden\r\nline", &mut out);
    writer.write(b"\r\n..two\r", &mut out);
    writer.write(b"\nlast", &mut out);
    writer.finish(&mut out);
    assert_eq!(out, b"..hidden\r\nline\r\n...two\r\nlast\r\n.\r\n");
    // Line breaks of any form are sent as CRLF; the size LIST gives counts them so.
    let mut out = Vec::new();
    POP3MultiLineWriter::new().write(b"a\nb\rc\r\n", &mut out);
    assert_eq!(out, b"a\r\nb\r\nc\r\n");
    assert_eq!(POP3MultiLineWriter::canonical_length(b"a\nb\rc\r\n"), 9);
    // The reader removes the periods and ends at the line of a period alone, whole or octet by octet.
    let sent = b"..hidden\r\nline\r\n.\r\n+OK next";
    let mut reader = POP3MultiLineReader::new();
    let mut data = Vec::new();
    let read = reader.read(sent, &mut data);
    assert!(reader.is_end());
    assert_eq!(&sent[read..], b"+OK next");
    assert_eq!(data, b".hidden\r\nline\r\n");
    let mut piecewise = POP3MultiLineReader::new();
    let mut pieces = Vec::new();
    let mut total = 0;
    while !piecewise.is_end() {
        total += piecewise.read(&sent[total..total + 1], &mut pieces);
    }
    assert_eq!(pieces, data);
    // Only CRLF ends a line: <LF>.<LF> is data.
    let mut lf = POP3MultiLineReader::new();
    let mut data = Vec::new();
    lf.read(b"a\n.\nb\r\n.\r\n", &mut data);
    assert!(lf.is_end());
    assert_eq!(data, b"a\n.\nb\r\n");
}

#[test]
fn rfc2449_capabilities() {
    let path = "protocol/pop/rfc2449.txt";
    // The example begins after the greeting, which is added.
    let mut steps = dialogue(path, "Examples:", "6.  Initial Set of Capabilities");
    steps.insert(0, Step { client: false, text: "+OK POP3 server ready".into() });
    let (client, _) = run_client(&steps);
    let capabilities = client.capabilities.clone().unwrap();
    for tag in ["TOP", "USER", "RESP-CODES", "PIPELINING", "UIDL"] {
        assert!(capabilities.has(tag), "{tag}");
    }
    assert_eq!(capabilities.sasl_mechanisms(), ["CRAM-MD5", "KERBEROS_V4"]);
    assert_eq!(capabilities.get("login-delay").unwrap().parameters, ["900"]);
    assert_eq!(capabilities.get("EXPIRE").unwrap().parameters, ["60"]);
    assert_eq!(capabilities.get("IMPLEMENTATION").unwrap().parameters, ["Shlemazle-Plotz-v302"]);
    // §6.6: with PIPELINING, commands are sent without waiting.
    let mut client = POP3Client::new(clear(), false, T0).unwrap();
    client.receive(b"+OK ready\r\n", T0).unwrap();
    client.send(POP3Command::Capa, T0).unwrap();
    client.receive(b"+OK\r\nPIPELINING\r\nUSER\r\n.\r\n", T0).unwrap();
    client.send(POP3Command::User("a".into()), T0).unwrap();
    client.receive(b"+OK\r\n", T0).unwrap();
    client.send(POP3Command::Pass("b".into()), T0).unwrap();
    client.receive(b"+OK\r\n", T0).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    for command in [POP3Command::Retr(1), POP3Command::Dele(1), POP3Command::Retr(2)] {
        client.send(command, T0).unwrap();
    }
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert_eq!(out, b"RETR 1\r\nDELE 1\r\nRETR 2\r\n");
    // The server's list: what it is configured with, STLS only before TLS.
    let config = POP3ServerConfig {
        stls: true,
        login_delay: Some(900),
        expire: Some("60".into()),
        ..POP3ServerConfig::default()
    };
    let mut server = POP3Server::new(POP3Config::default(), config, false).unwrap();
    server.greet(POP3Response::ok("ready"), T0).unwrap();
    server.receive(b"CAPA\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    let list = &out[out.windows(2).position(|pair| pair == b"\r\n").unwrap() + 2..];
    let list = &list[out.iter().position(|byte| *byte == b'\n').map(|_| 0).unwrap()..];
    let listed = POP3Capabilities::parse(&list[..list.len() - 3]);
    for tag in ["TOP", "RESP-CODES", "AUTH-RESP-CODE", "PIPELINING", "UIDL", "STLS", "LOGIN-DELAY", "EXPIRE"] {
        assert!(listed.has(tag), "{tag}");
    }
    assert!(!listed.has("USER"), "no plaintext passwords before TLS (RFC 5034 §4)");
}

#[test]
fn rfc2595_stls() {
    // §4: the client forgets the capabilities with TLS, and sends STLS only once.
    let mut client = POP3Client::new(POP3Config::default(), false, T0).unwrap();
    client.receive(b"+OK ready\r\n", T0).unwrap();
    assert!(client.send(POP3Command::Stls, T0).is_err(), "STLS not announced");
    client.send(POP3Command::Capa, T0).unwrap();
    client.receive(b"+OK\r\nSTLS\r\n.\r\n", T0).unwrap();
    client.send(POP3Command::Stls, T0).unwrap();
    client.receive(b"+OK Begin TLS negotiation\r\n+OK injected\r\n", T0).unwrap();
    let events: Vec<POP3ClientEvent> = std::iter::from_fn(|| client.poll_event()).collect();
    assert!(events.contains(&POP3ClientEvent::StartTLS));
    assert!(client.capabilities.is_none() && client.input.is_empty() && client.secure);
    assert!(client.send(POP3Command::Stls, T0).is_err());
    // The server: commands sent with STLS are discarded; under TLS, STLS is -ERR and not announced.
    let config = POP3ServerConfig { stls: true, ..POP3ServerConfig::default() };
    let mut server = POP3Server::new(POP3Config::default(), config, false).unwrap();
    server.greet(POP3Response::ok("ready"), T0).unwrap();
    server.receive(b"STLS\r\nUSER evil\r\n", T0);
    assert_eq!(server.poll_event(), Some(POP3ServerEvent::Command(POP3Command::Stls)));
    server.reply(POP3Response::ok("Begin TLS negotiation"), T0).unwrap();
    assert_eq!(server.poll_event(), Some(POP3ServerEvent::StartTLS));
    assert_eq!(server.poll_event(), None, "the USER sent with STLS is not read");
    assert!(!server.capabilities().has("STLS"));
    assert!(server.capabilities().has("USER"), "passwords under TLS");
    server.receive(b"STLS\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert!(out.ends_with(b"-ERR STLS not taken\r\n"));
}

#[test]
fn rfc5034_auth() {
    let path = "protocol/pop/rfc5034.txt";
    let plain = dialogue(path, "Here is an example of a client attempting AUTH PLAIN", "Here is another client");
    let (client, _) = run_client(&plain);
    assert_eq!(client.state, POP3State::Transaction);
    assert!(client.secure);
    let challenge = dialogue(path, "Here is an example using a mechanism in which", "7.  Security Considerations");
    let (client, told) = run_client(&challenge);
    assert_eq!(client.state, POP3State::Transaction);
    let challenges: Vec<&POP3ClientEvent> =
        told.iter().filter(|event| matches!(event, POP3ClientEvent::AuthChallenge(_))).collect();
    assert_eq!(challenges.len(), 2);
    assert!(
        matches!(challenges[0], POP3ClientEvent::AuthChallenge(data) if data.starts_with(b"realm=\"elwood.innosoft.com\""))
    );
    // The servers of both: PLAIN only under TLS, the other mechanisms before it too.
    let config = POP3ServerConfig {
        user: false,
        top: false,
        uidl: false,
        pipelining: false,
        response_codes: false,
        stls: true,
        sasl_mechanisms: vec!["PLAIN".into(), "DIGEST-MD5".into(), "GSSAPI".into(), "ANONYMOUS".into()],
        implementation: Some("BlurdyBlurp POP3 server".into()),
        ..POP3ServerConfig::default()
    };
    let server = run_server(&plain, config.clone());
    assert_eq!(server.state, POP3State::Transaction);
    let server = run_server(&challenge, config.clone());
    assert_eq!(server.state, POP3State::Transaction);
    // Without the initial response, the empty challenge "+ " is answered.
    let mut client = POP3Client::new(POP3Config::default(), true, T0).unwrap();
    client.receive(b"+OK ready\r\n", T0).unwrap();
    client.send(POP3Command::Capa, T0).unwrap();
    client.receive(b"+OK\r\nSASL PLAIN\r\n.\r\n", T0).unwrap();
    client.send(POP3Command::Auth { mechanism: "PLAIN".into(), initial: None }, T0).unwrap();
    client.receive(b"+ \r\n", T0).unwrap();
    assert!(
        std::iter::from_fn(|| client.poll_event()).any(|event| event == POP3ClientEvent::AuthChallenge(Vec::new()))
    );
    client.auth_respond(b"test\0test\0test", T0).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert!(out.ends_with(b"AUTH PLAIN\r\ndGVzdAB0ZXN0AHRlc3Q=\r\n"));
    // A mechanism not announced is not used; an initial response too long for 255 octets waits.
    assert!(client.check(&POP3Command::Auth { mechanism: "GSSAPI".into(), initial: None }).is_err());
    let mut long = POP3Client::new(POP3Config::default(), true, T0).unwrap();
    long.receive(b"+OK ready\r\n", T0).unwrap();
    long.send(POP3Command::Capa, T0).unwrap();
    long.receive(b"+OK\r\nSASL PLAIN\r\n.\r\n", T0).unwrap();
    long.send(POP3Command::Auth { mechanism: "PLAIN".into(), initial: Some(vec![b'a'; 300]) }, T0).unwrap();
    let mut out = Vec::new();
    long.transmit(&mut out);
    assert!(out.ends_with(b"AUTH PLAIN\r\n"));
    long.receive(b"+ \r\n", T0).unwrap();
    let mut out = Vec::new();
    long.transmit(&mut out);
    assert_eq!(out, format!("{}\r\n", Base64::STANDARD.encode(&[b'a'; 300])).into_bytes());
    // The server: "*" cancels (-ERR), a response not of base64 fails, PLAIN before TLS is refused.
    let mut server = POP3Server::new(POP3Config::default(), config.clone(), false).unwrap();
    server.greet(POP3Response::ok("ready"), T0).unwrap();
    server.receive(b"AUTH PLAIN =\r\nAUTH DIGEST-MD5\r\n", T0);
    assert!(matches!(server.poll_event(), Some(POP3ServerEvent::Command(POP3Command::Auth { .. }))));
    server.auth_challenge(b"challenge", T0).unwrap();
    server.receive(b"*\r\nAUTH DIGEST-MD5\r\n", T0);
    assert_eq!(server.poll_event(), Some(POP3ServerEvent::AuthCancelled));
    assert!(matches!(server.poll_event(), Some(POP3ServerEvent::Command(POP3Command::Auth { .. }))));
    server.auth_challenge(b"challenge", T0).unwrap();
    server.receive(b"=AAA\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("-ERR Plaintext authentication"), "{text}");
    assert!(
        text.contains("-ERR Authentication cancelled") && text.ends_with("-ERR Cannot decode the response\r\n"),
        "{text}"
    );
}

#[test]
fn rfc6856_utf8_and_lang() {
    let config = POP3ServerConfig {
        utf8: true,
        utf8_user: true,
        lang: true,
        stls: true,
        passwords_require_tls: false,
        ..POP3ServerConfig::default()
    };
    let mut server = POP3Server::new(POP3Config::default(), config, false).unwrap();
    server.greet(POP3Response::ok("ready"), T0).unwrap();
    assert_eq!(server.capabilities().get("UTF8").unwrap().parameters, ["USER"]);
    server.receive(b"UTF8\r\n", T0);
    assert_eq!(server.poll_event(), Some(POP3ServerEvent::Command(POP3Command::Utf8)));
    server.reply(POP3Response::ok("UTF8 enabled"), T0).unwrap();
    // §2.1: no STLS after UTF8.
    assert!(!server.capabilities().has("STLS"));
    server.receive("USER \u{7528}\u{6237}\r\nLANG\r\n".as_bytes(), T0);
    assert_eq!(server.poll_event(), Some(POP3ServerEvent::Command(POP3Command::User("\u{7528}\u{6237}".into()))));
    let mut client = POP3Client::new(POP3Config::default(), false, T0).unwrap();
    client.receive(b"+OK ready\r\n", T0).unwrap();
    assert!(client.send(POP3Command::Utf8, T0).is_err(), "UTF8 not announced");
    client.send(POP3Command::Capa, T0).unwrap();
    client.receive(b"+OK\r\nUTF8\r\nSTLS\r\nLANG\r\n.\r\n", T0).unwrap();
    client.send(POP3Command::Utf8, T0).unwrap();
    client.receive(b"+OK\r\n", T0).unwrap();
    assert!(client.send(POP3Command::Stls, T0).is_err(), "§2.1: no STLS after UTF8");
    client.send(POP3Command::Lang(None), T0).unwrap();
    client.receive(b"+OK Language listing follows\r\nen English\r\n.\r\n", T0).unwrap();
    let events: Vec<POP3ClientEvent> = std::iter::from_fn(|| client.poll_event()).collect();
    assert!(events.contains(&POP3ClientEvent::Data(b"en English\r\n".to_vec())));
}

#[test]
fn limits_and_timeouts() {
    // RFC 2449 §4: commands of up to 255 octets; a longer one is -ERR.
    let mut server = POP3Server::new(POP3Config::default(), POP3ServerConfig::default(), false).unwrap();
    server.greet(POP3Response::ok("ready"), T0).unwrap();
    server.receive(format!("USER {}\r\nNOOP\r\n", "x".repeat(300)).as_bytes(), T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert!(out.ends_with(b"-ERR Line too long\r\n-ERR Not in the AUTHORIZATION state\r\n"));
    // RFC 1939 §3: the autologout timer, at least 10 minutes, closes without a response.
    let deadline = server.poll_timeout().unwrap();
    assert_eq!(deadline, T0.saturating_add(Duration::from_secs(600)));
    server.expire(deadline);
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert!(out.is_empty());
    assert!(!server.is_open());
    assert!(POP3Config { autologout: Duration::from_secs(599), ..POP3Config::default() }.check().is_err());
    assert!(POP3Config { maximum_command_line: 254, ..POP3Config::default() }.check().is_err());
    // The client: a response to no command is an error; a response times out.
    let mut client = POP3Client::new(POP3Config::default(), false, T0).unwrap();
    client.receive(b"+OK ready\r\n", T0).unwrap();
    assert!(matches!(client.receive(b"+OK surprise\r\n", T0), Err(POP3Error::Syntax { .. })));
    let mut client = POP3Client::new(POP3Config::default(), false, T0).unwrap();
    client.receive(b"+OK ready\r\n", T0).unwrap();
    client.send(POP3Command::Capa, T0).unwrap();
    client.expire(client.poll_timeout().unwrap());
    assert!(!client.is_open());
}

#[test]
fn rfc2595_clear_text_logins_refused() {
    // §2.3: a client MUST be configurable to refuse clear-text logins without TLS; it does so by
    // default, and takes them under TLS.
    let greeted = |secure: bool| {
        let mut client = POP3Client::new(POP3Config::default(), secure, T0).unwrap();
        client.receive(b"+OK ready <1.2@x>\r\n", T0).unwrap();
        client
    };
    let mut client = greeted(false);
    for command in [
        POP3Command::User(String::from("u")),
        POP3Command::apop("u", b"<1.2@x>", b"secret"),
        POP3Command::parse(b"AUTH PLAIN", false).unwrap(),
    ] {
        assert!(matches!(client.send(command, T0), Err(POP3Error::State { .. })));
    }
    assert!(greeted(true).send(POP3Command::User(String::from("u")), T0).is_ok());
    // A line break in an argument is no second command (RFC 1939 §3: a command is one line).
    let mut client = POP3Client::new(clear(), false, T0).unwrap();
    client.receive(b"+OK ready\r\n", T0).unwrap();
    assert!(matches!(client.send(POP3Command::User(String::from("u\r\nDELE 1")), T0), Err(POP3Error::Syntax { .. })));
}

#[test]
fn rules_of_the_review() {
    // RFC 6856 §2.1: the size LIST gives is what RETR delivers; a last line without its CRLF
    // is sent with one.
    assert_eq!(POP3MultiLineWriter::canonical_length(b"abc"), 5);
    assert_eq!(POP3MultiLineWriter::canonical_length(b""), 0);

    let greeted = || {
        let mut client = POP3Client::new(clear(), false, T0).unwrap();
        client.receive(b"+OK ready\r\n", T0).unwrap();
        client
    };
    // A multi-line response that stops is timed out, from its last octets.
    let mut client = greeted();
    client.send(POP3Command::User(String::from("u")), T0).unwrap();
    client.receive(b"+OK\r\n", T0).unwrap();
    client.send(POP3Command::Pass(String::from("p")), T0).unwrap();
    client.receive(b"+OK\r\n", T0).unwrap();
    client.send(POP3Command::Retr(1), T0).unwrap();
    let later = T0.saturating_add(Duration::from_secs(60));
    client.receive(b"+OK\r\nfirst line\r\n", later).unwrap();
    let deadline = client.poll_timeout().expect("the response is timed");
    assert_eq!(deadline, later.saturating_add(clear().response_timeout));
    client.expire(deadline);
    assert!(!client.is_open());

    // After STLS, an accepted USER is forgotten (RFC 2595 §4).
    let mut client = POP3Client::new(clear(), false, T0).unwrap();
    client.receive(b"+OK ready\r\n", T0).unwrap();
    client.send(POP3Command::Capa, T0).unwrap();
    client.receive(b"+OK\r\nSTLS\r\nUSER\r\n.\r\n", T0).unwrap();
    client.send(POP3Command::User(String::from("u")), T0).unwrap();
    client.receive(b"+OK\r\n", T0).unwrap();
    client.send(POP3Command::Stls, T0).unwrap();
    client.receive(b"+OK begin TLS\r\n", T0).unwrap();
    assert!(client.send(POP3Command::Pass(String::from("p")), T0).is_err());

    // A response of AUTH that is not base64 fails the exchange, and the application is told.
    let config =
        POP3ServerConfig { sasl_mechanisms: vec![String::from("SCRAM-SHA-256")], ..POP3ServerConfig::default() };
    let mut server = POP3Server::new(POP3Config::default(), config, false).unwrap();
    server.greet(POP3Response::ok("ready"), T0).unwrap();
    server.receive(b"AUTH SCRAM-SHA-256\r\n", T0);
    server.poll_event();
    server.auth_challenge(b"", T0).unwrap();
    server.receive(b"!!!\r\n", T0);
    assert_eq!(server.poll_event(), Some(POP3ServerEvent::AuthFailed));
}
