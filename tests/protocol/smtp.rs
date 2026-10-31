//! SMTP (RFC 5321): the scenarios of Appendix D, and the examples of RFC
//! 2920 (PIPELINING), RFC 2034 (ENHANCEDSTATUSCODES), RFC 3207 (STARTTLS),
//! RFC 4954 (AUTH) and RFC 3030 (CHUNKING), run by the client against the
//! server's lines and by the server against the client's; and the rules of
//! each: reply and command syntax, paths, mail data and its end, limits,
//! sequencing, and the choice of mail exchangers (RFC 5321 §5.1, RFC 7505).

use std::time::Duration;

use umilib::bytes::LineBuffer;
use umilib::codec::base::Encoding;
use umilib::codec::base::base64::Base64;
use umilib::protocol::smtp::{
    SMTPClient, SMTPClientEvent, SMTPCommand, SMTPConfig, SMTPData, SMTPDataReader, SMTPEnhancedStatus, SMTPError,
    SMTPExtensions, SMTPMailbox, SMTPParameter, SMTPPath, SMTPReply, SMTPReplyReader, SMTPServer, SMTPServerConfig,
    SMTPServerEvent, SMTPXText,
};
use umilib::runtime::Instant;

use crate::Vectors;

const T0: Instant = Instant::from_nanos(1_000_000_000);

/// A line of a dialogue: who said it (`C` the client, `S` the server) and what.
#[derive(Clone, Debug)]
struct Step {
    client: bool,
    text: String,
}

/// The dialogue of an RFC beginning at the line `start` and ending before
/// the line `end`: its lines of `C:` and `S:` (of RFC 3030, `S:` and `R:`),
/// the page breaks and the lines in angle brackets left out, and a line of
/// the server wrapped onto the next (RFC 4954 §4.1) joined.
fn dialogue(path: &str, start: &str, end: &str) -> Vec<Step> {
    let text = Vectors::read(path);
    let lines: Vec<&str> = text.lines().collect();
    // Not a line of the table of contents, of dot leaders.
    let heading = |line: &&str, text: &str| line.trim_start().starts_with(text) && !line.contains(". . .");
    let first = lines.iter().position(|line| heading(line, start)).expect("the start of the dialogue");
    let last = first + lines[first..].iter().position(|line| heading(line, end)).expect("its end");
    let rfc3030 = path.ends_with("rfc3030.txt");
    let mut steps: Vec<Step> = Vec::new();
    for line in &lines[first..last] {
        let trimmed = line.trim_start();
        let (client, rest) = match trimmed.split_at_checked(3) {
            Some(("C: ", rest)) if !rfc3030 => (true, rest),
            Some(("S: ", rest)) if !rfc3030 => (false, rest),
            Some(("S: ", rest)) => (true, rest),
            Some(("R: ", rest)) => (false, rest),
            _ if trimmed == "C:" => (true, ""),
            _ => {
                let wrapped = line.starts_with("      ") && !trimmed.is_empty() && !trimmed.starts_with("...");
                if let Some(previous) =
                    steps.last_mut().filter(|step| !step.client && wrapped && !trimmed.starts_with('('))
                {
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

/// The replies of the server's lines of a dialogue.
fn replies(steps: &[Step]) -> Vec<SMTPReply> {
    let mut reader = SMTPReplyReader::new();
    steps
        .iter()
        .filter(|step| !step.client)
        .filter_map(|step| reader.push(step.text.as_bytes(), 1000).unwrap())
        .collect()
}

/// The replies written so far by a server, read back.
#[derive(Default)]
struct Transcript {
    buffer: LineBuffer,
    reader: SMTPReplyReader,
    replies: Vec<SMTPReply>,
}

impl Transcript {
    fn take(&mut self, server: &mut SMTPServer) {
        let mut out = Vec::new();
        server.transmit(&mut out);
        self.buffer.push(&out);
        while let Some(line) = self.buffer.line(100_000).unwrap() {
            if let Some(reply) = self.reader.push(&line, 1000).unwrap() {
                self.replies.push(reply);
            }
        }
    }
}

/// Runs the client's side of a dialogue: it sends the client's lines
/// through the client and checks that what it sends is them, at the time
/// they are said, and that it tells the server's replies.
fn run_client(steps: &[Step], secure: bool) -> (SMTPClient, Vec<SMTPReply>) {
    let mut client = SMTPClient::new(SMTPConfig::default(), secure, T0).unwrap();
    let (mut expected, mut sent, mut message) = (Vec::new(), Vec::new(), Vec::<u8>::new());
    let mut told = Vec::new();
    for step in steps {
        let line = format!("{}\r\n", step.text).into_bytes();
        if step.client {
            expected.extend_from_slice(&line);
            if client.data_ready {
                if step.text == "." {
                    client.send_data(&message, T0).unwrap();
                    message.clear();
                } else {
                    message.extend_from_slice(line.strip_prefix(b".").unwrap_or(&line));
                    continue;
                }
            } else if client.authenticating {
                client.auth_respond(&Base64::STANDARD.decode(step.text.as_bytes()).unwrap(), T0).unwrap();
            } else {
                let command = SMTPCommand::parse(step.text.as_bytes(), true).unwrap();
                client.send(command, T0).unwrap_or_else(|error| panic!("{}: {error}", step.text));
            }
        } else {
            client.receive(&line, T0).unwrap();
        }
        client.transmit(&mut sent);
        assert_eq!(String::from_utf8_lossy(&sent), String::from_utf8_lossy(&expected), "after {:?}", step.text);
        while let Some(event) = client.poll_event() {
            match event {
                SMTPClientEvent::Greeting(reply)
                | SMTPClientEvent::Reply { reply, .. }
                | SMTPClientEvent::DataReply(reply) => told.push(reply),
                SMTPClientEvent::AuthChallenge(_) | SMTPClientEvent::StartTLS | SMTPClientEvent::Closed { .. } => {}
            }
        }
    }
    (client, told)
}

/// Runs the server's side of a dialogue: it feeds the client's lines to
/// the server and answers what it tells with the dialogue's replies; the
/// codes it writes are the dialogue's, the replies it decides itself
/// (QUIT, and those that RFC 5321 decides) included. The data told is returned.
fn run_server(steps: &[Step], config: SMTPServerConfig) -> (SMTPServer, Vec<u8>) {
    let expected = replies(steps);
    let mut server = SMTPServer::new(SMTPConfig::default(), config, false).unwrap();
    let mut transcript = Transcript::default();
    server.greet(expected[0].clone(), T0).unwrap();
    transcript.take(&mut server);
    let mut data = Vec::new();
    for step in steps.iter().filter(|step| step.client) {
        server.receive(format!("{}\r\n", step.text).as_bytes(), T0);
        loop {
            transcript.take(&mut server);
            let Some(event) = server.poll_event() else { break };
            let next = || {
                expected
                    .get(transcript.replies.len())
                    .cloned()
                    .expect("a reply of the dialogue for what the server tells")
            };
            match event {
                SMTPServerEvent::Data(bytes) => data.extend_from_slice(&bytes),
                SMTPServerEvent::Command(SMTPCommand::Auth { .. }) | SMTPServerEvent::AuthResponse(_)
                    if next().code == 334 =>
                {
                    let challenge = Base64::STANDARD.decode(next().lines[0].as_slice()).unwrap();
                    server.auth_challenge(&challenge, T0).unwrap();
                }
                SMTPServerEvent::Command(_) | SMTPServerEvent::DataEnd { .. } | SMTPServerEvent::AuthResponse(_) => {
                    server.reply(next(), T0).unwrap();
                }
                _ => {}
            }
        }
    }
    transcript.take(&mut server);
    let codes = |replies: &[SMTPReply]| replies.iter().map(|reply| reply.code).collect::<Vec<_>>();
    assert_eq!(codes(&transcript.replies), codes(&expected));
    (server, data)
}

fn rfc5321(start: &str, end: &str) -> Vec<Step> {
    dialogue("protocol/smtp/rfc5321.txt", start, end)
}

#[test]
fn appendix_d_scenarios_from_the_client() {
    for (start, end) in [
        ("D.1.", "D.2."),
        ("D.2.", "D.3."),
        ("Step 1 -- Source Host to Relay Host", "Step 2 -- Relay Host"),
        ("Step 2 -- Relay Host", "D.4."),
        ("D.4.", "Appendix E."),
    ] {
        let steps = rfc5321(start, end);
        let (client, told) = run_client(&steps, false);
        assert_eq!(told, replies(&steps), "{start}");
        assert!(!client.is_open(), "{start}: closed after QUIT");
    }
    // D.1: the extensions of the reply to EHLO, and SIZE without a number (RFC 1870 §4).
    let steps = rfc5321("D.1.", "D.2.");
    let extensions = SMTPExtensions::from_reply(&replies(&steps)[1]).unwrap();
    assert!(extensions.has("8bitmime") && extensions.has("DSN") && extensions.has("HELP"));
    assert_eq!(extensions.size(), Some(0));
    assert_eq!(extensions.greeting, "foo.com greets bar.com");
}

#[test]
fn appendix_d_scenarios_from_the_server() {
    let config = SMTPServerConfig {
        domain: "foo.com".into(),
        enhanced_status_codes: false,
        dsn: true,
        ..SMTPServerConfig::default()
    };
    let (server, data) = run_server(&rfc5321("D.1.", "D.2."), config.clone());
    // The line "...etc. etc. etc." is as it is sent: the server removes its added period (§4.5.2).
    assert_eq!(data, b"Blah blah blah...\r\n..etc. etc. etc.\r\n");
    assert!(!server.is_open());
    run_server(&rfc5321("D.2.", "D.3."), config.clone());
    let (_, data) = run_server(&rfc5321("Step 1 -- Source Host to Relay Host", "Step 2 -- Relay Host"), config.clone());
    assert!(data.starts_with(b"Date: Thu, 21 May 1998 05:33:29 -0700\r\n"));
    assert!(
        data.ends_with(b"\r\nBill:\r\nThe next meeting of the board of directors will be\r\non Tuesday.\r\nJohn.\r\n")
    );
    run_server(&rfc5321("D.4.", "Appendix E."), config);
}

#[test]
fn rfc2920_pipelining() {
    let path = "protocol/smtp/rfc2920.txt";
    let lockstep = dialogue(path, "Consider the following SMTP dialogue", "The client waits for a server response");
    let pipelined = dialogue(path, "simple example. But if pipelining", "The total number of turnarounds");
    let rejected = dialogue(path, "The next example illustrates", "The client SMTP waits for the server 4 times");
    let accepted = dialogue(path, "server SMTP does not check", "5.  Security Considerations");
    for steps in [&lockstep, &pipelined, &rejected, &accepted] {
        let (_, told) = run_client(steps, false);
        assert_eq!(told, replies(steps));
    }
    // The server answers in order, and refuses DATA without a valid recipient itself (§3.2 (3)).
    let config = SMTPServerConfig { enhanced_status_codes: false, ..SMTPServerConfig::default() };
    for steps in [&lockstep, &pipelined, &rejected] {
        run_server(steps, config.clone());
    }
    // Without PIPELINING, the client sends one command at a time.
    let mut client = SMTPClient::new(SMTPConfig::default(), false, T0).unwrap();
    client.receive(b"220 x\r\n", T0).unwrap();
    client.send(SMTPCommand::parse(b"HELO a.example", false).unwrap(), T0).unwrap();
    client.receive(b"250 x\r\n", T0).unwrap();
    client.send(SMTPCommand::parse(b"MAIL FROM:<a@a.example>", false).unwrap(), T0).unwrap();
    client.send(SMTPCommand::parse(b"RCPT TO:<b@b.example>", false).unwrap(), T0).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert_eq!(out, b"HELO a.example\r\nMAIL FROM:<a@a.example>\r\n");
}

#[test]
fn rfc2034_enhanced_status_codes() {
    let steps = dialogue("protocol/smtp/rfc2034.txt", "6.  Usage Example", "The client that receives these responses");
    let (_, told) = run_client(&steps, false);
    assert_eq!(told[2].status(), Some(SMTPEnhancedStatus::new(2, 1, 0)));
    assert_eq!(told[4].status(), Some(SMTPEnhancedStatus::new(5, 1, 1)));
    assert_eq!(told[5].lines.len(), 2);
    assert_eq!(told[5].status(), Some(SMTPEnhancedStatus::new(5, 7, 1)));
    assert_eq!(told[6].status(), None, "3xx replies have no status code");
    let (_, _) = run_server(&steps, SMTPServerConfig::default());
    // §4: a status of another class than the code is none of it.
    let mismatched = SMTPReply::new(250, "5.1.1 no");
    assert_eq!(mismatched.status(), None);
    assert_eq!(SMTPEnhancedStatus::parse(b"2.1000.0 x"), None);
    assert_eq!(SMTPEnhancedStatus::parse(b"3.0.0 x"), None);
    assert_eq!(SMTPEnhancedStatus::parse(b"4.7.11 x"), Some((SMTPEnhancedStatus::new(4, 7, 11), &b"x"[..])));
    // A server offering the extension puts a status before replies that have none.
    let mut server = SMTPServer::new(SMTPConfig::default(), SMTPServerConfig::default(), false).unwrap();
    server.greet(server.greeting(), T0).unwrap();
    server.receive(b"EHLO a.example\r\nMAIL FROM:<a@a.example>\r\n", T0);
    server.reply(SMTPReply::new(250, "hello"), T0).unwrap();
    server.reply(SMTPReply::new(250, "OK"), T0).unwrap();
    let mut transcript = Transcript::default();
    transcript.take(&mut server);
    assert!(transcript.replies[1].lines.iter().any(|line| line == b"ENHANCEDSTATUSCODES"));
    assert_eq!(transcript.replies[1].status(), None, "nor to EHLO");
    assert_eq!(transcript.replies[2].status(), Some(SMTPEnhancedStatus::new(2, 0, 0)));
}

#[test]
fn rfc3207_starttls() {
    let steps = dialogue("protocol/smtp/rfc3207.txt", "5. Usage Example", "6. Security Considerations");
    let (client, told) = run_client(&steps, false);
    assert_eq!(told, replies(&steps));
    assert!(client.secure);
    // §4.2: under TLS STARTTLS is not sent again.
    assert!(matches!(client.check(&SMTPCommand::StartTLS), Err(SMTPError::State { .. })));
    // The client forgets the extensions with TLS, and believes nothing sent before it.
    let mut client = SMTPClient::new(SMTPConfig::default(), false, T0).unwrap();
    client.receive(b"220 x\r\n", T0).unwrap();
    client.send(SMTPCommand::Ehlo("a.example".into()), T0).unwrap();
    client.receive(b"250-x\r\n250 STARTTLS\r\n", T0).unwrap();
    client.send(SMTPCommand::StartTLS, T0).unwrap();
    client.receive(b"220 go ahead\r\n250-x\r\n250 AUTH PLAIN\r\n", T0).unwrap();
    let events: Vec<SMTPClientEvent> = std::iter::from_fn(|| client.poll_event()).collect();
    assert!(events.contains(&SMTPClientEvent::StartTLS));
    assert!(client.extensions.is_none());
    assert!(client.input.is_empty(), "the injected reply is discarded");
    // Without STARTTLS advertised it is not sent.
    let mut plain = SMTPClient::new(SMTPConfig::default(), false, T0).unwrap();
    plain.receive(b"220 x\r\n", T0).unwrap();
    plain.send(SMTPCommand::Ehlo("a.example".into()), T0).unwrap();
    plain.receive(b"250 x\r\n", T0).unwrap();
    assert!(plain.send(SMTPCommand::StartTLS, T0).is_err());

    // The server: commands sent with STARTTLS are discarded; STARTTLS is not offered under TLS.
    let config = SMTPServerConfig { starttls: true, ..SMTPServerConfig::default() };
    let mut server = SMTPServer::new(SMTPConfig::default(), config, false).unwrap();
    server.greet(server.greeting(), T0).unwrap();
    server.receive(b"EHLO a.example\r\n", T0);
    server.reply(SMTPReply::new(250, "hello"), T0).unwrap();
    server.receive(b"STARTTLS\r\nMAIL FROM:<evil@a.example>\r\n", T0);
    assert_eq!(server.poll_event(), Some(SMTPServerEvent::Command(SMTPCommand::Ehlo("a.example".into()))));
    assert_eq!(server.poll_event(), Some(SMTPServerEvent::Command(SMTPCommand::StartTLS)));
    server.reply(SMTPReply::new(220, "Go ahead"), T0).unwrap();
    assert_eq!(server.poll_event(), Some(SMTPServerEvent::StartTLS));
    assert_eq!(server.poll_event(), None, "the MAIL sent with STARTTLS is not read");
    assert!(server.secure && server.hello.is_none());
    assert!(!server.extensions().has("STARTTLS"));
    server.receive(b"STARTTLS\r\n", T0);
    let mut transcript = Transcript::default();
    transcript.take(&mut server);
    assert_eq!(transcript.replies.last().unwrap().code, 503);
    // §4: a server requiring TLS answers 530 to all but NOOP, EHLO, STARTTLS and QUIT.
    let config = SMTPServerConfig { starttls: true, requires_tls: true, ..SMTPServerConfig::default() };
    let mut server = SMTPServer::new(SMTPConfig::default(), config, false).unwrap();
    server.greet(server.greeting(), T0).unwrap();
    server.receive(b"HELO a.example\r\nNOOP\r\n", T0);
    let mut transcript = Transcript::default();
    transcript.take(&mut server);
    let codes: Vec<u16> = transcript.replies.iter().map(|reply| reply.code).collect();
    assert_eq!(codes, [220, 530, 250]);
}

#[test]
fn rfc4954_auth() {
    let path = "protocol/smtp/rfc4954.txt";
    // The greetings of §4.1 have their continuation lines left out: they are taken as one line.
    let fix = |mut steps: Vec<Step>| {
        for step in &mut steps {
            if step.text.starts_with("220-") {
                step.text.replace_range(3..4, " ");
            }
        }
        steps
    };
    let plain = fix(dialogue(path, "Here is an example of a client attempting AUTH using", "Here is another client"));
    let (client, told) = run_client(&plain, false);
    assert_eq!(told, replies(&plain));
    assert!(client.secure);
    let cram = fix(dialogue(
        path,
        "Here is an example using CRAM-MD5",
        "Here is an example of a client attempting AUTH EXTERNAL",
    ));
    let (_, told) = run_client(&cram, false);
    assert_eq!(told.last().unwrap().code, 235);
    let external =
        fix(dialogue(path, "Here is an example of a client attempting AUTH EXTERNAL", "5.  The AUTH Parameter"));
    run_client(&external, false);
    // The server of each: PLAIN under TLS, CRAM-MD5 offered without it.
    let config = SMTPServerConfig {
        starttls: true,
        auth_mechanisms: vec!["GSSAPI".into(), "DIGEST-MD5".into(), "PLAIN".into()],
        ..SMTPServerConfig::default()
    };
    run_server(&plain, config.clone());
    run_server(
        &external,
        SMTPServerConfig { auth_mechanisms: vec!["EXTERNAL".into(), "PLAIN".into()], ..config.clone() },
    );
    let open = SMTPServerConfig { auth_mechanisms: vec!["DIGEST-MD5".into(), "CRAM-MD5".into()], ..config.clone() };
    run_server(&cram, open);

    // Without an initial response, the 334 of no text ("334 ") is answered (the second example).
    let mut client = SMTPClient::new(SMTPConfig::default(), true, T0).unwrap();
    client.receive(b"220 x\r\n", T0).unwrap();
    client.send(SMTPCommand::Ehlo("client.example.com".into()), T0).unwrap();
    client.receive(b"250-x\r\n250 AUTH GSSAPI DIGEST-MD5 PLAIN\r\n", T0).unwrap();
    client.send(SMTPCommand::Auth { mechanism: "PLAIN".into(), initial: None }, T0).unwrap();
    client.receive(b"334 \r\n", T0).unwrap();
    let events: Vec<SMTPClientEvent> = std::iter::from_fn(|| client.poll_event()).collect();
    assert!(events.contains(&SMTPClientEvent::AuthChallenge(Vec::new())));
    client.auth_respond(b"test\0test\x001234", T0).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert!(out.ends_with(b"AUTH PLAIN\r\ndGVzdAB0ZXN0ADEyMzQ=\r\n"));
    // A mechanism not advertised is not used; a challenge that is not base64 is cancelled.
    assert!(client.check(&SMTPCommand::Auth { mechanism: "CRAM-MD5".into(), initial: None }).is_err());
    // An initial response that would make the line too long waits for the empty challenge (§4).
    let mut long = SMTPClient::new(SMTPConfig::default(), true, T0).unwrap();
    long.receive(b"220 x\r\n", T0).unwrap();
    long.send(SMTPCommand::Ehlo("a.example".into()), T0).unwrap();
    long.receive(b"250-x\r\n250 AUTH PLAIN\r\n", T0).unwrap();
    let response = vec![b'a'; 600];
    long.send(SMTPCommand::Auth { mechanism: "PLAIN".into(), initial: Some(response.clone()) }, T0).unwrap();
    let mut out = Vec::new();
    long.transmit(&mut out);
    assert!(out.ends_with(b"AUTH PLAIN\r\n"));
    long.receive(b"334 \r\n", T0).unwrap();
    let mut out = Vec::new();
    long.transmit(&mut out);
    assert_eq!(out, format!("{}\r\n", Base64::STANDARD.encode(&response)).into_bytes());
    let mut bad = SMTPClient::new(SMTPConfig::default(), true, T0).unwrap();
    bad.receive(b"220 x\r\n", T0).unwrap();
    bad.send(SMTPCommand::Ehlo("a.example".into()), T0).unwrap();
    bad.receive(b"250-x\r\n250 AUTH PLAIN\r\n", T0).unwrap();
    bad.send(SMTPCommand::Auth { mechanism: "PLAIN".into(), initial: None }, T0).unwrap();
    bad.receive(b"334 =AAA\r\n", T0).unwrap();
    let mut out = Vec::new();
    bad.transmit(&mut out);
    assert!(out.ends_with(b"*\r\n"));

    // The server: cancel (501), a response that is not base64 (501), AUTH in a transaction and
    // after success (503), a mechanism not offered (504), and before TLS when it needs it (538).
    let codes = |config: &SMTPServerConfig, secure: bool, lines: &[&[u8]], answers: &[(u16, bool)]| {
        let mut server = SMTPServer::new(SMTPConfig::default(), config.clone(), secure).unwrap();
        server.greet(server.greeting(), T0).unwrap();
        let mut answers = answers.iter();
        for line in lines {
            server.receive(line, T0);
            while let Some(event) = server.poll_event() {
                if matches!(
                    event,
                    SMTPServerEvent::Command(_) | SMTPServerEvent::AuthResponse(_) | SMTPServerEvent::DataEnd { .. }
                ) {
                    let (code, challenge) = answers.next().expect("an answer");
                    match challenge {
                        true => server.auth_challenge(b"", T0).unwrap(),
                        false => server.reply(SMTPReply::new(*code, "x"), T0).unwrap(),
                    }
                }
            }
        }
        let mut transcript = Transcript::default();
        transcript.take(&mut server);
        transcript.replies.iter().map(|reply| reply.code).collect::<Vec<u16>>()
    };
    let config = SMTPServerConfig { auth_mechanisms: vec!["PLAIN".into()], ..SMTPServerConfig::default() };
    let ehlo: &[u8] = b"EHLO a.example\r\n";
    assert_eq!(
        codes(&config, true, &[ehlo, b"AUTH PLAIN\r\n", b"*\r\n"], &[(250, false), (334, true)]),
        [220, 250, 334, 501]
    );
    assert_eq!(
        codes(&config, true, &[ehlo, b"AUTH PLAIN\r\n", b"A=AA\r\n"], &[(250, false), (334, true)]),
        [220, 250, 334, 501]
    );
    assert_eq!(
        codes(&config, true, &[ehlo, b"AUTH PLAIN =\r\n", b"AUTH PLAIN =\r\n"], &[(250, false), (235, false)]),
        [220, 250, 235, 503]
    );
    assert_eq!(
        codes(
            &config,
            true,
            &[ehlo, b"MAIL FROM:<a@a.example>\r\n", b"AUTH PLAIN =\r\n"],
            &[(250, false), (250, false)]
        ),
        [220, 250, 250, 503]
    );
    assert_eq!(codes(&config, true, &[ehlo, b"AUTH LOGIN\r\n"], &[(250, false)]), [220, 250, 504]);
    assert_eq!(codes(&config, false, &[ehlo, b"AUTH PLAIN\r\n"], &[(250, false)]), [220, 250, 538]);
    let required = SMTPServerConfig { requires_auth: true, ..config.clone() };
    assert_eq!(codes(&required, true, &[ehlo, b"MAIL FROM:<a@a.example>\r\n"], &[(250, false)]), [220, 250, 530]);
    // §5: the AUTH parameter of MAIL, xtext or <>.
    let command = SMTPCommand::parse(b"MAIL FROM:<e=mc2@example.com> AUTH=e+3Dmc2@example.com", false).unwrap();
    let SMTPCommand::Mail { parameters, .. } = &command else { panic!() };
    assert_eq!(SMTPXText::decode(parameters[0].value.as_deref().unwrap().as_bytes()).unwrap(), b"e=mc2@example.com");
    assert_eq!(
        codes(&config, true, &[ehlo, b"MAIL FROM:<john+@example.org> AUTH=<>\r\n"], &[(250, false), (250, false)]),
        [220, 250, 250]
    );
}

#[test]
fn rfc3030_chunking() {
    // §4.1: a message of 86 octets in one chunk.
    let message = b"To: Susan@random.com\r\nFrom: Sam@random.com\r\nSubject: This is a bodyless test message\r\n";
    assert_eq!(message.len(), 86);
    let mut client = SMTPClient::new(SMTPConfig::default(), false, T0).unwrap();
    client.receive(b"220 cnri.reston.va.us SMTP service ready\r\n", T0).unwrap();
    client.send(SMTPCommand::Ehlo("ymir.claremont.edu".into()), T0).unwrap();
    client.receive(b"250-cnri.reston.va.us says hello\r\n250 CHUNKING\r\n", T0).unwrap();
    client.send(SMTPCommand::parse(b"MAIL FROM:<Sam@Random.com>", false).unwrap(), T0).unwrap();
    client.receive(b"250 <Sam@Random.com> Sender ok\r\n", T0).unwrap();
    client.send(SMTPCommand::parse(b"RCPT TO:<Susan@Random.com>", false).unwrap(), T0).unwrap();
    client.receive(b"250 <Susan@random.com> Recipient ok\r\n", T0).unwrap();
    client.send_chunk(message, true, T0).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert!(out.ends_with(&[b"BDAT 86 LAST\r\n".as_slice(), message].concat()));
    // The server reads the chunk as it is, its 86 octets.
    let mut server = SMTPServer::new(SMTPConfig::default(), SMTPServerConfig::default(), false).unwrap();
    server.greet(server.greeting(), T0).unwrap();
    server.receive(&out, T0);
    let mut data = Vec::new();
    let mut ends = Vec::new();
    while let Some(event) = server.poll_event() {
        match event {
            SMTPServerEvent::Command(_) => server.reply(SMTPReply::new(250, "OK"), T0).unwrap(),
            SMTPServerEvent::Data(bytes) => data.extend_from_slice(&bytes),
            SMTPServerEvent::DataEnd { last } => {
                ends.push(last);
                server.reply(SMTPReply::new(250, "Message OK, 86 octets received"), T0).unwrap();
            }
            _ => {}
        }
    }
    assert_eq!(data, message);
    assert_eq!(ends, [true]);
    assert!(server.transaction.is_none());

    // §4.2: BINARYMIME in pipelined chunks of 100000, 324 and 0 octets; DATA is not taken.
    let config = SMTPServerConfig { binary_mime: true, ..SMTPServerConfig::default() };
    let mut server = SMTPServer::new(SMTPConfig::default(), config, false).unwrap();
    server.greet(server.greeting(), T0).unwrap();
    let first: Vec<u8> = (0..100_000u32).map(|index| (index * 7 % 256) as u8).collect();
    let second: Vec<u8> = (0..324u32).map(|index| (index % 256) as u8).collect();
    let mut input = b"EHLO ymir.claremont.edu\r\nMAIL FROM:<ned@ymir.claremont.edu> BODY=BINARYMIME\r\nRCPT TO:<gvaudre@cnri.reston.va.us>\r\nRCPT TO:<jstewart@cnri.reston.va.us>\r\nBDAT 100000\r\n".to_vec();
    input.extend_from_slice(&first);
    input.extend_from_slice(b"BDAT 324\r\n");
    input.extend_from_slice(&second);
    input.extend_from_slice(b"BDAT 0 LAST\r\nDATA\r\n");
    let mut data = Vec::new();
    let mut ends = Vec::new();
    for piece in input.chunks(4093) {
        server.receive(piece, T0);
        while let Some(event) = server.poll_event() {
            match event {
                SMTPServerEvent::Command(_) => server.reply(SMTPReply::new(250, "OK"), T0).unwrap(),
                SMTPServerEvent::Data(bytes) => data.extend_from_slice(&bytes),
                SMTPServerEvent::DataEnd { last } => {
                    ends.push(last);
                    server.reply(SMTPReply::new(250, "received"), T0).unwrap();
                }
                _ => {}
            }
        }
    }
    assert_eq!(data, [first, second].concat());
    assert_eq!(ends, [false, false, true]);
    let mut transcript = Transcript::default();
    transcript.take(&mut server);
    assert_eq!(transcript.replies.last().unwrap().code, 503, "DATA without a transaction");
    // The client sends BINARYMIME only in chunks, and only to a server that has it.
    let mut client = SMTPClient::new(SMTPConfig::default(), false, T0).unwrap();
    client.receive(b"220 x\r\n", T0).unwrap();
    client.send(SMTPCommand::Ehlo("a.example".into()), T0).unwrap();
    client.receive(b"250-x\r\n250-PIPELINING\r\n250-BINARYMIME\r\n250 CHUNKING\r\n", T0).unwrap();
    client.send(SMTPCommand::parse(b"MAIL FROM:<a@a.example> BODY=BINARYMIME", false).unwrap(), T0).unwrap();
    client.send(SMTPCommand::parse(b"RCPT TO:<b@b.example>", false).unwrap(), T0).unwrap();
    assert!(client.send(SMTPCommand::Data, T0).is_err());
    client.send_chunk(&[0, 0xff, b'\n'], true, T0).unwrap();
}

#[test]
fn replies_of_section_4_2() {
    let mut reader = SMTPReplyReader::new();
    assert_eq!(reader.push(b"250-first", 10).unwrap(), None);
    let reply = reader.push(b"250 last", 10).unwrap().unwrap();
    assert_eq!(reply.lines, [b"first".to_vec(), b"last".to_vec()]);
    // A code alone, or with a space, is a reply (§4.2: SHOULD be prepared).
    assert_eq!(SMTPReplyReader::new().push(b"250", 10).unwrap().unwrap().lines, [Vec::<u8>::new()]);
    assert_eq!(SMTPReplyReader::new().push(b"334 ", 10).unwrap().unwrap().lines, [Vec::<u8>::new()]);
    // The code: 2-5, 0-5, 0-9; the same on every line.
    for line in [&b"199 x"[..], b"600 x", b"260 x", b"25 x", b"2500 x", b"250x"] {
        assert!(SMTPReplyReader::new().push(line, 10).is_err(), "{}", String::from_utf8_lossy(line));
    }
    let mut mixed = SMTPReplyReader::new();
    mixed.push(b"250-a", 10).unwrap();
    assert!(mixed.push(b"251 b", 10).is_err());
    let mut many = SMTPReplyReader::new();
    many.push(b"250-a", 2).unwrap();
    many.push(b"250-a", 2).unwrap();
    assert!(many.push(b"250 a", 2).is_err());
    let mut out = Vec::new();
    SMTPReply { code: 250, lines: vec![b"a".to_vec(), b"b".to_vec()] }.encode(&mut out);
    assert_eq!(out, b"250-a\r\n250 b\r\n");
    assert!(SMTPReply::new(250, "a\r\nb").check().is_err());
}

#[test]
fn commands_and_paths_of_section_4_1() {
    let parse = |line: &[u8]| SMTPCommand::parse(line, false);
    // Verbs and FROM:/TO: in any case; a space after the colon taken.
    let mail = parse(b"mail from: <Smith@bar.com> SIZE=1000 body=8BITMIME").unwrap();
    assert_eq!(
        mail,
        SMTPCommand::Mail {
            path: SMTPPath::Mailbox(SMTPMailbox::new("Smith", "bar.com")),
            parameters: vec![SMTPParameter::new("SIZE", Some("1000")), SMTPParameter::new("BODY", Some("8BITMIME"))],
        }
    );
    assert_eq!(mail.to_string(), "MAIL FROM:<Smith@bar.com> SIZE=1000 BODY=8BITMIME");
    // §4.1.2: a source route is accepted and ignored.
    assert_eq!(
        parse(b"RCPT TO:<@ONE,@TWO:JOE@THREE>").unwrap(),
        SMTPCommand::Rcpt { path: SMTPPath::Mailbox(SMTPMailbox::new("JOE", "THREE")), parameters: vec![] }
    );
    // §4.1.1.3: <Postmaster> in RCPT only; the null path in MAIL only.
    assert_eq!(
        parse(b"RCPT TO:<Postmaster>").unwrap(),
        SMTPCommand::Rcpt { path: SMTPPath::Postmaster, parameters: vec![] }
    );
    assert!(parse(b"MAIL FROM:<Postmaster>").is_err());
    assert_eq!(parse(b"MAIL FROM:<>").unwrap(), SMTPCommand::Mail { path: SMTPPath::Null, parameters: vec![] });
    assert!(parse(b"RCPT TO:<>").is_err());
    // Quoted local parts, with the least quoting written; address literals.
    let quoted = parse(br#"RCPT TO:<"Joe\,Smith"@example.com>"#).unwrap();
    let SMTPCommand::Rcpt { path: SMTPPath::Mailbox(mailbox), .. } = &quoted else { panic!() };
    assert_eq!(mailbox.local, "Joe,Smith");
    assert_eq!(mailbox.to_string(), "\"Joe,Smith\"@example.com");
    assert_eq!(SMTPMailbox::parse(br#""john"@example.com"#, false).unwrap().to_string(), "john@example.com");
    assert!(SMTPMailbox::parse(b"a@[192.0.2.1]", false).is_ok());
    assert!(SMTPMailbox::parse(b"a@[IPv6:2001:db8::1]", false).is_ok());
    assert!(SMTPMailbox::parse(b"a@[IPv6:2001:db8::192.0.2.1]", false).is_ok());
    assert!(SMTPMailbox::parse(b"a@[256.0.0.1]", false).is_err());
    assert!(SMTPMailbox::parse(b"a@[IPv6:2001:db8:::1]", false).is_err());
    // §4.1.2: no underscore or other character but letters, digits and hyphens in a label.
    assert!(SMTPMailbox::parse(b"a@ex_ample.com", false).is_err());
    assert!(SMTPMailbox::parse(b"a@-example.com", false).is_err());
    assert!(SMTPMailbox::parse(b"a..b@example.com", false).is_err());
    assert!(parse(b"MAIL FROM:Smith@bar.com").is_err(), "a path without angle brackets");
    // RFC 6531 §3.3: UTF-8 only where SMTPUTF8 is in use.
    assert!(SMTPCommand::parse("RCPT TO:<\u{7528}\u{6237}@\u{4f8b}\u{3048}.jp>".as_bytes(), false).is_err());
    let utf8 = SMTPCommand::parse("RCPT TO:<\u{7528}\u{6237}@\u{4f8b}\u{3048}.jp>".as_bytes(), true).unwrap();
    assert!(matches!(utf8, SMTPCommand::Rcpt { path: SMTPPath::Mailbox(ref mailbox), .. } if mailbox.is_utf8()));
    // Commands of no arguments take none; BDAT and AUTH (RFC 3030 §2, RFC 4954 §4).
    assert!(parse(b"DATA x").is_err());
    assert_eq!(parse(b"BDAT 86 LAST").unwrap(), SMTPCommand::Bdat { size: 86, last: true });
    assert!(parse(b"BDAT x").is_err());
    assert_eq!(
        parse(b"AUTH EXTERNAL =").unwrap(),
        SMTPCommand::Auth { mechanism: "EXTERNAL".into(), initial: Some(vec![]) }
    );
    assert_eq!(
        SMTPCommand::Auth { mechanism: "EXTERNAL".into(), initial: Some(vec![]) }.to_string(),
        "AUTH EXTERNAL ="
    );
    assert!(parse(b"AUTH PLAIN A=AA").is_err(), "RFC 4954 §4: padding only at the end");
    assert!(parse(b"MAIL FROM:<a@b.example>\nRCPT TO:<c@d.example>").is_err(), "an LF alone in a command");
    // §4.1.2: esmtp-keyword and esmtp-value.
    assert!(SMTPParameter::parse(b"-X=1", false).is_err());
    assert!(SMTPParameter::parse(b"X=a=b", false).is_err());
    // RFC 3461 §4: xtext.
    assert_eq!(SMTPXText::encode(b"a+b=c d"), "a+2Bb+3Dc+20d");
    assert_eq!(SMTPXText::decode(b"a+2Bb+3Dc+20d").unwrap(), b"a+b=c d");
    assert!(SMTPXText::decode(b"+2b").is_err(), "upper-case hexadecimal digits");
}

#[test]
fn mail_data_of_section_4_5_2() {
    // A line beginning with a period gets another; a final CRLF is added; the end line follows.
    let mut out = Vec::new();
    SMTPData::encode(b".hidden\r\nline\r\n..two", 1000, &mut out).unwrap();
    assert_eq!(out, b"..hidden\r\nline\r\n...two\r\n.\r\n");
    let mut empty = Vec::new();
    SMTPData::encode(b"", 1000, &mut empty).unwrap();
    assert_eq!(empty, b".\r\n");
    // §2.3.8: no CR or LF alone; §4.5.3.1.6: lines of at most 1000 octets with their CRLF.
    assert!(SMTPData::encode(b"a\nb", 1000, &mut Vec::new()).is_err());
    assert!(SMTPData::encode(b"a\rb", 1000, &mut Vec::new()).is_err());
    assert!(SMTPData::check(&[b'x'; 998], 1000).is_ok());
    assert!(SMTPData::check(&[b'x'; 999], 1000).is_err());
    // The reader removes the periods and finds the end, read whole or an octet at a time.
    let sent = b"..hidden\r\n.x\r\nend\r\n.\r\nQUIT\r\n";
    let mut whole = SMTPDataReader::new(u64::MAX, 1000);
    let mut data = Vec::new();
    let read = whole.read(sent, &mut data);
    assert!(whole.is_end() && whole.error().is_none());
    assert_eq!(&sent[read..], b"QUIT\r\n");
    assert_eq!(data, b".hidden\r\nx\r\nend\r\n");
    let mut piecewise = SMTPDataReader::new(u64::MAX, 1000);
    let mut pieces = Vec::new();
    let mut total = 0;
    while !piecewise.is_end() {
        total += piecewise.read(&sent[total..total + 1], &mut pieces);
    }
    assert_eq!(pieces, data);
    // SMTP smuggling: <LF>.<LF> and <CR>.<CR> end nothing, and make the data invalid.
    for smuggled in [&b"a\n.\nMAIL FROM:<x@y>\r\n.\r\n"[..], b"a\r.\rMAIL FROM:<x@y>\r\n.\r\n", b"a\r\n.\nb\r\n.\r\n"] {
        let mut reader = SMTPDataReader::new(u64::MAX, 1000);
        let mut data = Vec::new();
        let read = reader.read(smuggled, &mut data);
        assert_eq!(read, smuggled.len(), "{}", String::from_utf8_lossy(smuggled));
        assert!(reader.is_end());
        assert!(matches!(reader.error(), Some(SMTPError::Content { .. })));
    }
    // Past the maximum size the data is read and not kept.
    let mut small = SMTPDataReader::new(4, 1000);
    let mut data = Vec::new();
    small.read(b"abcdefgh\r\n.\r\n", &mut data);
    assert!(small.is_end());
    assert!(data.len() <= 4);
    assert!(matches!(small.error(), Some(SMTPError::TooLarge { .. })));
    // A line over 1000 octets, the added period not counted.
    let mut long = SMTPDataReader::new(u64::MAX, 1000);
    let line = [b"..".as_slice(), &[b'x'; 997], b"\r\n.\r\n"].concat();
    long.read(&line, &mut Vec::new());
    assert!(long.error().is_none());
    let mut longer = SMTPDataReader::new(u64::MAX, 1000);
    longer.read(&[&[b'x'; 999][..], b"\r\n.\r\n"].concat(), &mut Vec::new());
    assert!(matches!(longer.error(), Some(SMTPError::TooLong { .. })));
}

/// A server greeted, its replies to every command it tells given by `answer`.
fn session(
    config: SMTPServerConfig,
    input: &[u8],
    answer: impl Fn(&SMTPServerEvent) -> Option<SMTPReply>,
) -> (SMTPServer, Vec<SMTPReply>, Vec<SMTPServerEvent>) {
    let mut server = SMTPServer::new(SMTPConfig::default(), config, false).unwrap();
    server.greet(server.greeting(), T0).unwrap();
    server.receive(input, T0);
    let mut events = Vec::new();
    while let Some(event) = server.poll_event() {
        if let Some(reply) = answer(&event) {
            server.reply(reply, T0).unwrap();
        }
        events.push(event);
    }
    let mut transcript = Transcript::default();
    transcript.take(&mut server);
    (server, transcript.replies, events)
}

fn codes(replies: &[SMTPReply]) -> Vec<u16> {
    replies.iter().map(|reply| reply.code).collect()
}

fn accept(event: &SMTPServerEvent) -> Option<SMTPReply> {
    match event {
        SMTPServerEvent::Command(SMTPCommand::Data) => Some(SMTPReply::new(354, "go ahead")),
        SMTPServerEvent::Command(_) | SMTPServerEvent::DataEnd { .. } => Some(SMTPReply::new(250, "OK")),
        _ => None,
    }
}

#[test]
fn server_sequencing_of_section_4_1_4() {
    let config = SMTPServerConfig::default();
    // §4.1.4: MAIL before EHLO, nested MAIL, RCPT and DATA without MAIL: 503.
    let (_, replies, _) =
        session(config.clone(), b"MAIL FROM:<a@a.example>\r\nRCPT TO:<b@b.example>\r\nDATA\r\n", accept);
    assert_eq!(codes(&replies), [220, 503, 503, 503]);
    let (_, replies, _) =
        session(config.clone(), b"EHLO a.example\r\nMAIL FROM:<a@a.example>\r\nMAIL FROM:<a@a.example>\r\n", accept);
    assert_eq!(codes(&replies), [220, 250, 250, 503]);
    // NOOP, HELP, VRFY, RSET at any time; NOOP, RSET and QUIT the server answers itself.
    let (server, replies, events) = session(config.clone(), b"NOOP\r\nRSET\r\nVRFY x\r\nQUIT\r\nNOOP\r\n", accept);
    assert_eq!(codes(&replies), [220, 250, 250, 250, 221]);
    assert_eq!(events.iter().filter(|event| matches!(event, SMTPServerEvent::Command(_))).count(), 1);
    assert!(!server.is_open());
    // DATA with no recipient accepted: 554 (RFC 2920 §3.2 (3)); 100 recipients and then 452 (§4.5.3.1.10).
    let (_, replies, _) = session(config.clone(), b"EHLO a.example\r\nMAIL FROM:<a@a.example>\r\nDATA\r\n", accept);
    assert_eq!(codes(&replies), [220, 250, 250, 554]);
    let mut input = b"EHLO a.example\r\nMAIL FROM:<a@a.example>\r\n".to_vec();
    for index in 0..101 {
        input.extend_from_slice(format!("RCPT TO:<r{index}@b.example>\r\n").as_bytes());
    }
    let (_, replies, _) = session(config.clone(), &input, accept);
    assert_eq!(replies.len(), 104);
    assert_eq!(replies.last().unwrap().code, 452);
    // A refused EHLO leaves the state as it was; an accepted one resets the transaction.
    let reject_ehlo = |event: &SMTPServerEvent| match event {
        SMTPServerEvent::Command(SMTPCommand::Ehlo(domain)) if domain == "bad.example" => {
            Some(SMTPReply::new(550, "no"))
        }
        event => accept(event),
    };
    let (server, _, _) =
        session(config.clone(), b"EHLO a.example\r\nMAIL FROM:<a@a.example>\r\nEHLO bad.example\r\n", reject_ehlo);
    assert!(server.transaction.is_some());
    let (server, _, events) =
        session(config.clone(), b"EHLO a.example\r\nMAIL FROM:<a@a.example>\r\nEHLO b.example\r\n", accept);
    assert!(server.transaction.is_none());
    assert!(events.contains(&SMTPServerEvent::Reset));
    // §3.1: after a 554 greeting only QUIT is taken.
    let mut server = SMTPServer::new(SMTPConfig::default(), config.clone(), false).unwrap();
    server.greet(SMTPReply::new(554, "no service"), T0).unwrap();
    server.receive(b"EHLO a.example\r\nQUIT\r\n", T0);
    let mut transcript = Transcript::default();
    transcript.take(&mut server);
    assert_eq!(codes(&transcript.replies), [554, 503, 221]);
    // Unknown commands (500), bad arguments (501), lines too long (500).
    let long = format!("NOOP {}\r\nNOOP\r\n", "x".repeat(600));
    let (_, replies, _) = session(config.clone(), long.as_bytes(), accept);
    assert_eq!(codes(&replies), [220, 500, 250]);
    let (_, replies, _) = session(config.clone(), b"FROB\r\nMAIL FROM:bad\r\nHELO\r\n", accept);
    assert_eq!(codes(&replies), [220, 500, 501, 501]);
    // Pipelined commands are told one at a time, answered in order (RFC 2920 §3.2 (1)).
    let mut server = SMTPServer::new(SMTPConfig::default(), config.clone(), false).unwrap();
    server.greet(server.greeting(), T0).unwrap();
    server.receive(b"EHLO a.example\r\nMAIL FROM:<a@a.example>\r\nRCPT TO:<b@b.example>\r\n", T0);
    assert!(matches!(server.poll_event(), Some(SMTPServerEvent::Command(SMTPCommand::Ehlo(_)))));
    assert_eq!(server.poll_event(), None);
    server.reply(SMTPReply::new(250, "hi"), T0).unwrap();
    assert!(matches!(server.poll_event(), Some(SMTPServerEvent::Command(SMTPCommand::Mail { .. }))));
}

#[test]
fn server_parameters_and_limits() {
    let config = SMTPServerConfig { maximum_message_size: 1000, ..SMTPServerConfig::default() };
    // RFC 1870 §6: a declared size over the limit, 552; RFC 5321 §4.1.1.11: unknown parameters, 555.
    let (_, replies, _) = session(config.clone(), b"EHLO a.example\r\nMAIL FROM:<a@a.example> SIZE=1001\r\nMAIL FROM:<a@a.example> FROB=1\r\nMAIL FROM:<a@a.example> SIZE=x\r\n", accept);
    assert_eq!(codes(&replies), [220, 250, 552, 555, 501]);
    // Under HELO, no parameters (they are of extensions).
    let (_, replies, _) = session(config.clone(), b"HELO a.example\r\nMAIL FROM:<a@a.example> SIZE=10\r\n", accept);
    assert_eq!(codes(&replies), [220, 250, 555]);
    // RFC 6531 §3.4: an address of UTF-8 needs SMTPUTF8.
    let utf8 = "EHLO a.example\r\nMAIL FROM:<\u{7528}@\u{4f8b}.jp>\r\nMAIL FROM:<\u{7528}@\u{4f8b}.jp> SMTPUTF8\r\nRCPT TO:<\u{4eba}@\u{4f8b}.jp>\r\n";
    let (_, replies, _) = session(config.clone(), utf8.as_bytes(), accept);
    assert_eq!(codes(&replies), [220, 250, 553, 250, 250]);
    // RFC 3461: NOTIFY and ORCPT only with DSN, and of their syntax.
    let dsn = SMTPServerConfig { dsn: true, ..config.clone() };
    let (_, replies, _) = session(dsn, b"EHLO a.example\r\nMAIL FROM:<a@a.example> RET=HDRS ENVID=QQ314159\r\nRCPT TO:<b@b.example> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;b@b.example\r\nRCPT TO:<c@b.example> NOTIFY=NEVER,SUCCESS\r\n", accept);
    assert_eq!(codes(&replies), [220, 250, 250, 250, 501]);
    let (_, replies, _) = session(config.clone(), b"EHLO a.example\r\nMAIL FROM:<a@a.example> RET=HDRS\r\n", accept);
    assert_eq!(codes(&replies), [220, 250, 555]);
    // Data larger than the limit, and data of a bare LF, are refused by the server itself.
    let big = format!(
        "EHLO a.example\r\nMAIL FROM:<a@a.example>\r\nRCPT TO:<b@b.example>\r\nDATA\r\n{}\r\n.\r\nNOOP\r\n",
        "x".repeat(990)
    );
    let (_, replies, events) =
        session(SMTPServerConfig { maximum_message_size: 100, ..config.clone() }, big.as_bytes(), accept);
    assert_eq!(codes(&replies), [220, 250, 250, 250, 354, 552, 250]);
    assert!(events.iter().any(|event| matches!(event, SMTPServerEvent::DataRejected(SMTPError::TooLarge { .. }))));
    let smuggled = b"EHLO a.example\r\nMAIL FROM:<a@a.example>\r\nRCPT TO:<b@b.example>\r\nDATA\r\nhello\n.\nMAIL FROM:<x@x.example>\r\n.\r\nNOOP\r\n";
    let (server, replies, events) = session(config.clone(), smuggled, accept);
    assert_eq!(codes(&replies), [220, 250, 250, 250, 354, 550, 250]);
    assert!(!events.iter().any(|event| matches!(event, SMTPServerEvent::DataEnd { .. })));
    assert!(server.transaction.is_none());
    // A message taken: its data told, the transaction over after the reply to its end.
    let (server, replies, events) = session(
        config.clone(),
        b"EHLO a.example\r\nMAIL FROM:<a@a.example>\r\nRCPT TO:<b@b.example>\r\nDATA\r\n..line\r\n.\r\n",
        accept,
    );
    assert_eq!(codes(&replies), [220, 250, 250, 250, 354, 250]);
    assert!(events.contains(&SMTPServerEvent::Data(b".line\r\n".to_vec())));
    assert!(server.transaction.is_none());
    // BDAT without CHUNKING: its octets are read all the same, then 502.
    let no_chunking = SMTPServerConfig { chunking: false, ..config.clone() };
    let (_, replies, _) = session(
        no_chunking,
        b"EHLO a.example\r\nMAIL FROM:<a@a.example>\r\nRCPT TO:<b@b.example>\r\nBDAT 6\r\nNOOP\r\nNOOP\r\n",
        accept,
    );
    assert_eq!(codes(&replies), [220, 250, 250, 250, 502, 250]);
    // The configuration: at least 100 recipients, SMTPUTF8 with 8BITMIME.
    assert!(SMTPServerConfig { maximum_recipients: 99, ..config.clone() }.check().is_err());
    assert!(SMTPServerConfig { eight_bit_mime: false, ..config.clone() }.check().is_err());
    assert!(SMTPConfig { maximum_command_line: 511, ..SMTPConfig::default() }.check().is_err());
}

#[test]
fn server_timeout_of_section_4_5_3_2_7() {
    let mut server = SMTPServer::new(SMTPConfig::default(), SMTPServerConfig::default(), false).unwrap();
    server.greet(server.greeting(), T0).unwrap();
    let deadline = server.poll_timeout().unwrap();
    assert_eq!(deadline, T0.saturating_add(Duration::from_secs(300)));
    server.expire(deadline);
    let mut transcript = Transcript::default();
    transcript.take(&mut server);
    assert_eq!(transcript.replies.last().unwrap().code, 421);
    assert!(!server.is_open());
}

/// §3.8: a server that must shut down replies 421 and closes; §4.2: a reply's text is of lines
/// without CR or LF, so text of a line break, which would be replies of its own, is refused.
#[test]
fn server_shutdown_of_section_3_8() {
    let mut server = SMTPServer::new(SMTPConfig::default(), SMTPServerConfig::default(), false).unwrap();
    server.greet(server.greeting(), T0).unwrap();
    let mut transcript = Transcript::default();
    transcript.take(&mut server);
    for text in ["bye\r\n250 OK", "bye\n250 OK", "bye\r", "bye\0"] {
        assert!(server.shutdown(text).is_err(), "{text:?}");
        let mut out = Vec::new();
        server.transmit(&mut out);
        assert!(out.is_empty(), "{text:?}");
        assert!(server.is_open());
    }
    server.shutdown("Service not available, closing transmission channel").unwrap();
    transcript.take(&mut server);
    assert_eq!(codes(&transcript.replies), [220, 421]);
    assert!(!server.is_open());
    assert!(matches!(server.poll_event(), Some(SMTPServerEvent::Closed { error: None })));
    // Nothing is written once closed.
    server.shutdown("again").unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert!(out.is_empty());
}

#[test]
fn client_rules() {
    let ready = |extensions: &[u8]| {
        let mut client = SMTPClient::new(SMTPConfig::default(), false, T0).unwrap();
        client.receive(b"220 x\r\n", T0).unwrap();
        client.send(SMTPCommand::Ehlo("a.example".into()), T0).unwrap();
        client.receive(extensions, T0).unwrap();
        client.transmit(&mut Vec::new());
        client
    };
    // Parameters of extensions not advertised are not sent; a size over the server's is not (RFC 1870 §6).
    let mut client = ready(b"250-x\r\n250 SIZE 1000\r\n");
    assert!(client.send(SMTPCommand::parse(b"MAIL FROM:<a@a.example> BODY=8BITMIME", false).unwrap(), T0).is_err());
    assert!(matches!(
        client.send(SMTPCommand::parse(b"MAIL FROM:<a@a.example> SIZE=1001", false).unwrap(), T0),
        Err(SMTPError::TooLarge { .. })
    ));
    assert!(client.send(SMTPCommand::parse("MAIL FROM:<\u{7528}@\u{4f8b}.jp>".as_bytes(), true).unwrap(), T0).is_err());
    // 8-bit data needs BODY=8BITMIME (RFC 6152 §3).
    client.send(SMTPCommand::parse(b"MAIL FROM:<a@a.example> SIZE=10", false).unwrap(), T0).unwrap();
    client.receive(b"250 ok\r\n", T0).unwrap();
    client.send(SMTPCommand::parse(b"RCPT TO:<b@b.example>", false).unwrap(), T0).unwrap();
    client.receive(b"250 ok\r\n", T0).unwrap();
    client.send(SMTPCommand::Data, T0).unwrap();
    client.receive(b"354 go\r\n", T0).unwrap();
    assert!(matches!(client.send_data("caf\u{e9}".as_bytes(), T0), Err(SMTPError::Content { .. })));
    assert!(client.send(SMTPCommand::Noop(None), T0).is_err(), "the data of DATA is next");
    client.send_data(b"ok", T0).unwrap();
    // A 421 at any time closes the connection (§3.8).
    client.receive(b"421 shutting down\r\n", T0).unwrap();
    assert!(!client.is_open());
    // A reply to no command is an error.
    let mut client = ready(b"250 x\r\n");
    assert!(client.receive(b"250 surprise\r\n", T0).is_err());
    assert!(!client.is_open());
    // RCPT and DATA without MAIL are not sent.
    let mut client = ready(b"250 x\r\n");
    assert!(client.send(SMTPCommand::parse(b"RCPT TO:<b@b.example>", false).unwrap(), T0).is_err());
    assert!(client.send(SMTPCommand::Data, T0).is_err());
    // The greeting and replies time out (§4.5.3.2).
    let mut client = SMTPClient::new(SMTPConfig::default(), false, T0).unwrap();
    assert_eq!(client.poll_timeout(), Some(T0.saturating_add(Duration::from_secs(300))));
    client.expire(T0.saturating_add(Duration::from_secs(300)));
    assert!(
        std::iter::from_fn(|| client.poll_event())
            .any(|event| event == SMTPClientEvent::Closed { error: Some(SMTPError::Timeout) })
    );
    let mut client = ready(b"250 x\r\n");
    client.send(SMTPCommand::parse(b"MAIL FROM:<a@a.example>", false).unwrap(), T0).unwrap();
    client.receive(b"250 ok\r\n", T0).unwrap();
    client.send(SMTPCommand::parse(b"RCPT TO:<b@b.example>", false).unwrap(), T0).unwrap();
    client.receive(b"250 ok\r\n", T0).unwrap();
    client.send(SMTPCommand::Data, T0).unwrap();
    assert_eq!(client.poll_timeout(), Some(T0.saturating_add(Duration::from_secs(120))), "DATA initiation: 2 minutes");
    client.receive(b"354 go\r\n", T0).unwrap();
    client.send_data(b"x", T0).unwrap();
    assert_eq!(
        client.poll_timeout(),
        Some(T0.saturating_add(Duration::from_secs(600))),
        "DATA termination: 10 minutes"
    );
    // A refused MAIL ends the transaction; a refused DATA does not (RSET ends it).
    let mut client = ready(b"250 x\r\n");
    client.send(SMTPCommand::parse(b"MAIL FROM:<a@a.example>", false).unwrap(), T0).unwrap();
    client.receive(b"550 no\r\n", T0).unwrap();
    assert!(client.transaction.is_none());
}

#[cfg(umilib_feature = "protocol-dns")]
#[test]
fn mail_exchangers_of_section_5_1() {
    use umilib::crypto::random::{Random, RandomError};
    use umilib::protocol::dns::{DNSClass, DNSData, DNSName, DNSRecord, DNSType};
    use umilib::protocol::smtp::SMTPMailExchanger;

    struct Counter(u64);
    impl Random for Counter {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
            for byte in out {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                *byte = (self.0 >> 56) as u8;
            }
            Ok(())
        }
    }
    let name = |text: &str| DNSName::parse(text, None).unwrap();
    let mx = |owner: &str, preference: u16, exchange: &str| DNSRecord {
        name: name(owner),
        kind: DNSType::MX,
        class: DNSClass::IN,
        ttl: 300,
        data: DNSData::MX { preference, exchange: name(exchange) },
    };
    let domain = name("example.com.");
    let mut random = Counter(1);
    // No MX: the domain itself, an implicit MX of preference 0.
    assert_eq!(
        SMTPMailExchanger::order(&domain, &[], &[], &mut random).unwrap(),
        [SMTPMailExchanger { preference: 0, host: domain.clone() }]
    );
    // By preference, lowest first; records of other owners ignored.
    let records = [
        mx("example.com.", 20, "b.example.com."),
        mx("example.com.", 10, "a.example.com."),
        mx("other.example.", 0, "x.example."),
    ];
    let order = SMTPMailExchanger::order(&domain, &records, &[], &mut random).unwrap();
    assert_eq!(order.iter().map(|exchanger| exchanger.preference).collect::<Vec<_>>(), [10, 20]);
    // Hosts of one preference in a random order: every order seen.
    let same = [
        mx("example.com.", 10, "a.example.com."),
        mx("example.com.", 10, "b.example.com."),
        mx("example.com.", 10, "c.example.com."),
    ];
    let mut firsts = std::collections::BTreeSet::new();
    for _ in 0..200 {
        firsts.insert(SMTPMailExchanger::order(&domain, &same, &[], &mut random).unwrap()[0].host.to_string());
    }
    assert_eq!(firsts.len(), 3);
    // This host and every host of no lower preference are removed.
    let relay =
        [mx("example.com.", 10, "xyz.com."), mx("example.com.", 20, "foo.com."), mx("example.com.", 30, "bar.com.")];
    let order = SMTPMailExchanger::order(&domain, &relay, &[name("foo.com.")], &mut random).unwrap();
    assert_eq!(order, [SMTPMailExchanger { preference: 10, host: name("xyz.com.") }]);
    assert_eq!(SMTPMailExchanger::order(&domain, &relay, &[name("xyz.com.")], &mut random), Err(SMTPError::NoMail));
    // RFC 7505: the null MX means no mail.
    assert_eq!(
        SMTPMailExchanger::order(&domain, &[mx("example.com.", 0, ".")], &[], &mut random),
        Err(SMTPError::NoMail)
    );
}

/// A client greeted and answered EHLO with `extensions`.
fn client_after_ehlo(config: SMTPConfig, extensions: &[&str], now: Instant) -> SMTPClient {
    let mut client = SMTPClient::new(config, false, now).unwrap();
    client.receive(b"220 mx.example ESMTP\r\n", now).unwrap();
    client.send(SMTPCommand::Ehlo(String::from("client.example")), now).unwrap();
    let mut reply = String::from("250-mx.example\r\n");
    for extension in extensions {
        reply.push_str(&format!("250-{extension}\r\n"));
    }
    reply.push_str("250 HELP\r\n");
    client.receive(reply.as_bytes(), now).unwrap();
    client.transmit(&mut Vec::new());
    while client.poll_event().is_some() {}
    client
}

#[test]
fn rules_of_the_review() {
    // A field of a line break is no second command (RFC 5321 §2.3.8: a command is one line).
    let mut client = client_after_ehlo(SMTPConfig::default(), &["PIPELINING"], T0);
    let path = SMTPPath::Mailbox(SMTPMailbox::new("a\r\nRCPT TO:<victim@x>\r\nX", "c.example"));
    assert!(client.send(SMTPCommand::Mail { path, parameters: Vec::new() }, T0).is_err());
    assert!(client.send(SMTPCommand::Ehlo(String::from("x\r\nMAIL FROM:<a@b>")), T0).is_err());
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert!(out.is_empty());

    // RFC 2595 §2.3: a password as it is is not sent without TLS, by default.
    let mut client = client_after_ehlo(SMTPConfig::default(), &["AUTH PLAIN"], T0);
    let auth = SMTPCommand::parse(b"AUTH PLAIN AHRpbQB0YW5zdGFhZg==", false).unwrap();
    assert!(matches!(client.send(auth.clone(), T0), Err(SMTPError::State { .. })));
    let clear = SMTPConfig { passwords_require_tls: false, ..SMTPConfig::default() };
    assert!(client_after_ehlo(clear, &["AUTH PLAIN"], T0).send(auth, T0).is_ok());

    // RFC 4954 §4: the line of AUTH and its initial response is `AUTH`, a space, the mechanism,
    // a space, the base64 and CRLF; one longer than 512 waits for the empty challenge.
    let mut client = client_after_ehlo(clear, &["AUTH PLAIN"], T0);
    let initial = vec![b'a'; 375]; // 500 octets of base64: a line of 513
    client.send(SMTPCommand::Auth { mechanism: String::from("PLAIN"), initial: Some(initial) }, T0).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert_eq!(out, b"AUTH PLAIN\r\n");

    // RFC 5321 §4.1.4: no MAIL before EHLO or HELO.
    let mut client = SMTPClient::new(SMTPConfig::default(), false, T0).unwrap();
    client.receive(b"220 mx.example\r\n", T0).unwrap();
    let mail = SMTPCommand::parse(b"MAIL FROM:<a@b.example>", false).unwrap();
    assert!(client.send(mail.clone(), T0).is_err());

    // §4.1.1.1: the reply of success to EHLO is 250; another 2xx closes the client.
    let mut client = SMTPClient::new(SMTPConfig::default(), false, T0).unwrap();
    client.receive(b"220 mx.example\r\n", T0).unwrap();
    client.send(SMTPCommand::Ehlo(String::from("c.example")), T0).unwrap();
    assert!(client.receive(b"252 mx\r\n", T0).is_err());
    assert!(!client.is_open());

    // §4.5.3.2: each reply is timed from the one before it, not from when its command was sent.
    let start = T0;
    let mut client = client_after_ehlo(SMTPConfig::default(), &["PIPELINING"], start);
    client.send(mail.clone(), start).unwrap();
    for to in 0..12 {
        client.send(SMTPCommand::parse(format!("RCPT TO:<{to}@x.example>").as_bytes(), false).unwrap(), start).unwrap();
    }
    for reply in 0..13u64 {
        let now = start.saturating_add(Duration::from_secs(30 * (reply + 1)));
        client.expire(now);
        assert!(client.is_open(), "reply {reply} came 30 seconds after the one before");
        client.receive(b"250 OK\r\n", now).unwrap();
    }

    // RFC 3030 §2: a BDAT refused (here before TLS) has its chunk read and discarded, never
    // taken as commands.
    let config = SMTPServerConfig { starttls: true, requires_tls: true, ..SMTPServerConfig::default() };
    let mut server = SMTPServer::new(SMTPConfig::default(), config, false).unwrap();
    server.greet(server.greeting(), T0).unwrap();
    server.receive(b"BDAT 16\r\nNOOP\r\nNOOP\r\nxx\r\nNOOP\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    let text = String::from_utf8(out).unwrap();
    let codes: Vec<&str> = text.lines().skip(1).map(|line| &line[..3]).collect();
    assert_eq!(codes, ["530", "250"], "{text}");

    // RFC 5321 §4.1.1.11: parameters are of extensions, which HELO does not open.
    let mut server =
        SMTPServer::new(SMTPConfig::default(), SMTPServerConfig { dsn: true, ..SMTPServerConfig::default() }, false)
            .unwrap();
    server.greet(server.greeting(), T0).unwrap();
    server.receive(b"HELO c.example\r\n", T0);
    server.poll_event();
    server.reply(SMTPReply::new(250, "mx"), T0).unwrap();
    server.receive(b"MAIL FROM:<a@c.example>\r\n", T0);
    server.poll_event();
    server.reply(SMTPReply::new(250, "OK"), T0).unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    out.clear();
    server.receive(b"RCPT TO:<b@x.example> NOTIFY=NEVER\r\n", T0);
    server.transmit(&mut out);
    assert!(out.starts_with(b"555 "), "{}", String::from_utf8_lossy(&out));

    // RFC 2034 §4: the status code begins every line of a reply.
    let mut server = SMTPServer::new(SMTPConfig::default(), SMTPServerConfig::default(), false).unwrap();
    server.greet(server.greeting(), T0).unwrap();
    server.receive(b"HELP\r\n", T0);
    server.poll_event();
    let mut out = Vec::new();
    server.transmit(&mut out);
    out.clear();
    server.reply(SMTPReply { code: 214, lines: vec![b"2.0.0 a".to_vec(), b"b".to_vec()] }, T0).unwrap();
    server.transmit(&mut out);
    assert_eq!(out, b"214-2.0.0 a\r\n214 2.0.0 b\r\n");

    // A response of AUTH that is not base64 fails the exchange, and the application is told.
    let config =
        SMTPServerConfig { auth_mechanisms: vec![String::from("SCRAM-SHA-256")], ..SMTPServerConfig::default() };
    let mut server = SMTPServer::new(SMTPConfig::default(), config, false).unwrap();
    server.greet(server.greeting(), T0).unwrap();
    server.receive(b"EHLO c\r\n", T0);
    server.poll_event();
    server.reply(SMTPReply::new(250, "mx"), T0).unwrap();
    server.receive(b"AUTH SCRAM-SHA-256\r\n", T0);
    server.poll_event();
    server.auth_challenge(b"", T0).unwrap();
    server.receive(b"!!!\r\n", T0);
    assert_eq!(server.poll_event(), Some(SMTPServerEvent::AuthFailed));
}
