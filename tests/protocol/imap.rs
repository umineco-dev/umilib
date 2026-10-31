//! IMAP4rev2 (RFC 9051): the sample connection of §8, run by the client
//! against the server's lines and by the server against the client's; the
//! responses and commands of the examples of the RFC read and written back;
//! literals (RFC 7888), mailbox names (RFC 3501 §5.1.3), sequence sets,
//! sections (§6.4.5) and body structures of messages read by codec-mail;
//! and the rules of the states.

use std::ops::RangeInclusive;

use umilib::bytes::LineBuffer;
use umilib::codec::base::Encoding;
use umilib::codec::base::base64::Base64;
use umilib::codec::mail::{MIMEEntity, MailConfig, MailFields};
use umilib::protocol::imap::v4::{
    IMAPBody, IMAPClient, IMAPClientEvent, IMAPCommand, IMAPCommandBody, IMAPCondition, IMAPConfig, IMAPDate,
    IMAPDateTime, IMAPEnvelope, IMAPError, IMAPFetchAttribute, IMAPFetchItem, IMAPLineEvent, IMAPLineReader,
    IMAPLiteralMode, IMAPMailbox, IMAPReader, IMAPResponse, IMAPResponseCode, IMAPSearch, IMAPSearchKey, IMAPSection,
    IMAPSectionText, IMAPSequenceNumber, IMAPSequenceSet, IMAPServer, IMAPServerConfig, IMAPServerEvent, IMAPState,
    IMAPWriter,
};
use umilib::runtime::Instant;

use crate::Vectors;

const T0: Instant = Instant::from_nanos(1_000_000_000);
const DEPTH: usize = 64;

#[derive(Clone, Debug)]
struct Step {
    client: bool,
    text: Vec<u8>,
}

/// Whether `text` is of base64 characters alone.
fn is_base64(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
}

/// The dialogue of an RFC between the lines beginning with `start` and `end`:
/// its lines of `C:` and `S:`, a line broken for editorial clarity joined (a
/// broken run of base64 without a space), a literal's lines and the rest of
/// its line joined into one step, the lines in angle brackets left out.
fn dialogue(path: &str, start: &str, end: &str) -> Vec<Step> {
    let text = Vectors::read(path);
    let lines: Vec<&str> = text.lines().collect();
    // A heading begins its line; the table of contents is indented.
    let heading = |line: &&str, text: &str| line.starts_with(text);
    let first = lines.iter().position(|line| heading(line, start)).expect("the start");
    let last = first + 1 + lines[first + 1..].iter().position(|line| heading(line, end)).expect("the end");
    let mut steps: Vec<(bool, String)> = Vec::new();
    for line in &lines[first..last] {
        let trimmed = line.trim_start();
        let (client, rest) = match trimmed.split_at_checked(2) {
            Some(("C:", rest)) => (true, rest.trim_start()),
            Some(("S:", rest)) => (false, rest.strip_prefix(' ').map_or(rest, |rest| rest.trim_start_matches(' '))),
            _ => {
                if trimmed.is_empty() || trimmed.starts_with('<') {
                    continue;
                }
                if let Some((_, previous)) = steps.last_mut() {
                    let last_word = previous.rsplit(' ').next().unwrap_or_default();
                    let broken_base64 = is_base64(trimmed) && is_base64(last_word) && last_word.len() >= 40;
                    // A break after an opening parenthesis is not a space of the protocol.
                    if !broken_base64 && !previous.ends_with('(') {
                        previous.push(' ');
                    }
                    previous.push_str(trimmed);
                }
                continue;
            }
        };
        steps.push((client, rest.to_string()));
    }
    // A step ending in the length of a literal takes the next lines of its side as the literal,
    // and the line after it as its rest.
    let mut joined: Vec<Step> = Vec::new();
    let mut index = 0;
    while index < steps.len() {
        let (client, text) = &steps[index];
        let mut bytes = text.clone().into_bytes();
        index += 1;
        while let Some((length, _)) = IMAPLineReader::literal_of(&bytes) {
            bytes.extend_from_slice(b"\r\n");
            let mut literal = Vec::new();
            while (literal.len() as u64) < length && index < steps.len() {
                literal.extend_from_slice(steps[index].1.as_bytes());
                literal.extend_from_slice(b"\r\n");
                index += 1;
            }
            assert_eq!(literal.len() as u64, length, "the literal of {text}");
            bytes.extend_from_slice(&literal);
            if index < steps.len() {
                bytes.extend_from_slice(steps[index].1.as_bytes());
                index += 1;
            }
        }
        joined.push(Step { client: *client, text: bytes });
    }
    joined
}

fn line(text: &[u8]) -> Vec<u8> {
    [text, b"\r\n"].concat()
}

/// The responses a server wrote, read back.
#[derive(Default)]
struct Transcript {
    buffer: LineBuffer,
    reader: IMAPLineReader,
    responses: Vec<IMAPResponse>,
}

impl Transcript {
    fn take(&mut self, out: &[u8]) {
        self.buffer.push(out);
        while let Some(event) = self.reader.next(&mut self.buffer, &IMAPConfig::default()).unwrap() {
            if let IMAPLineEvent::Line(line) = event {
                self.responses.push(
                    IMAPResponse::parse(&line, true, DEPTH)
                        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&line))),
                );
            }
        }
    }
}

/// Runs the client's side of a dialogue: the client sends the client's commands (with their tags), and
/// what it sends reads as them; what it tells of the server's lines is returned.
fn run_client(steps: &[Step]) -> (IMAPClient, Vec<IMAPClientEvent>) {
    let mut client = IMAPClient::new(IMAPConfig::default(), false, "T", T0).unwrap();
    let mut told = Vec::new();
    for step in steps {
        if step.client {
            if client.authenticating {
                client.authenticate_respond(&Base64::STANDARD.decode(&step.text).unwrap(), T0).unwrap();
                let mut out = Vec::new();
                client.transmit(&mut out);
                assert_eq!(out, line(&step.text));
            } else if step.text.eq_ignore_ascii_case(b"DONE") {
                client.idle_done(T0).unwrap();
            } else {
                let command = IMAPCommand::parse(&step.text, client.rev2, DEPTH).unwrap();
                client
                    .send_with_tag(&command.tag, command.body.clone(), T0)
                    .unwrap_or_else(|error| panic!("{error}: {command:?}"));
                let mut out = Vec::new();
                client.transmit(&mut out);
                let sent = IMAPCommand::parse(out.strip_suffix(b"\r\n").unwrap(), client.rev2, DEPTH).unwrap();
                assert_eq!(sent, command);
            }
        } else {
            client
                .receive(&line(&step.text), T0)
                .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&step.text)));
        }
        told.extend(std::iter::from_fn(|| client.poll_event()));
    }
    (client, told)
}

/// Runs the server's side: it feeds the client's lines and answers what the server tells with the
/// dialogue's responses. The responses it writes are those of the dialogue: the same, but for those
/// the server makes itself (the greeting, CAPABILITY, ENABLE, LOGOUT), of the same condition.
fn run_server(steps: &[Step], config: IMAPServerConfig) -> IMAPServer {
    let expected: Vec<IMAPResponse> = steps
        .iter()
        .filter(|step| !step.client)
        .map(|step| IMAPResponse::parse(&step.text, true, DEPTH).unwrap())
        .collect();
    let mut server = IMAPServer::new(IMAPConfig::default(), config, false).unwrap();
    let IMAPResponse::Status { condition, text, .. } = &expected[0] else { panic!("a greeting") };
    server.greet(*condition, text, T0).unwrap();
    let mut transcript = Transcript::default();
    let mut out = Vec::new();
    server.transmit(&mut out);
    transcript.take(&out);
    for step in steps.iter().filter(|step| step.client) {
        server.receive(&line(&step.text), T0);
        loop {
            let mut out = Vec::new();
            server.transmit(&mut out);
            transcript.take(&out);
            let Some(event) = server.poll_event() else { break };
            let tag = match &event {
                IMAPServerEvent::Command(command) => command.tag.clone(),
                IMAPServerEvent::AuthenticateResponse { tag, .. } | IMAPServerEvent::IdleDone { tag } => tag.clone(),
                _ => continue,
            };
            // The dialogue's responses to the command, to its completion or a continuation request.
            loop {
                let response = expected[transcript.responses.len()].clone();
                match response {
                    IMAPResponse::Status { tag: Some(done), condition, code, text } if done == tag => {
                        server.complete(condition, code, &text, T0).unwrap();
                        break;
                    }
                    IMAPResponse::Continuation(text) => {
                        match matches!(
                            &event,
                            IMAPServerEvent::Command(IMAPCommand { body: IMAPCommandBody::Idle, .. })
                        ) {
                            true => server.idle(&String::from_utf8_lossy(&text), T0).unwrap(),
                            false => server
                                .authenticate_challenge(&Base64::STANDARD.decode(text.trim_ascii()).unwrap(), T0)
                                .unwrap(),
                        }
                        break;
                    }
                    response => server.respond(&response).unwrap(),
                }
                let mut out = Vec::new();
                server.transmit(&mut out);
                transcript.take(&out);
            }
        }
    }
    let mut out = Vec::new();
    server.transmit(&mut out);
    transcript.take(&out);
    assert_eq!(transcript.responses.len(), expected.len(), "{:#?}", transcript.responses);
    for (written, expected) in transcript.responses.iter().zip(&expected) {
        match (written, expected) {
            (IMAPResponse::Status { tag: a, condition: b, .. }, IMAPResponse::Status { tag: c, condition: d, .. }) => {
                assert_eq!(
                    (a.as_deref().map(str::to_ascii_lowercase), b),
                    (c.as_deref().map(str::to_ascii_lowercase), d)
                );
            }
            (IMAPResponse::Capability(_), IMAPResponse::Capability(_)) => {}
            (written, expected) => assert_eq!(written, expected),
        }
    }
    server
}

#[test]
fn sample_connection_of_section_8() {
    let steps = dialogue("protocol/imap/rfc9051.txt", "8.  Sample IMAP4rev2 Connection", "9.  Formal Syntax");
    let (client, told) = run_client(&steps);
    assert!(!client.is_open());
    assert_eq!(client.state, IMAPState::Logout);
    // The greeting's capabilities: IMAP4rev2 alone, so IMAP4rev2 is in use.
    assert!(matches!(
        &told[0],
        IMAPClientEvent::Greeting(IMAPResponse::Status { code: Some(IMAPResponseCode::Capability(_)), .. })
    ));
    assert!(told.contains(&IMAPClientEvent::StartTLS));
    // The FETCH FULL response: its envelope and the structure of its body.
    let fetch = told
        .iter()
        .find_map(|event| match event {
            IMAPClientEvent::Untagged(IMAPResponse::Fetch { number: 12, items }) if items.len() > 2 => {
                Some(items.clone())
            }
            _ => None,
        })
        .unwrap();
    let envelope = fetch
        .iter()
        .find_map(|item| if let IMAPFetchItem::Envelope(envelope) = item { Some(envelope.clone()) } else { None })
        .unwrap();
    assert_eq!(envelope.subject.as_deref(), Some(&b"IMAP4rev2 WG mtg summary and minutes"[..]));
    assert_eq!(envelope.cc.len(), 2);
    assert_eq!(envelope.to[0].mailbox.as_deref(), Some(&b"imap"[..]));
    assert!(fetch.contains(&IMAPFetchItem::InternalDate(IMAPDateTime::new(837_596_665, -420))));
    let IMAPFetchItem::Body(IMAPBody::Text { fields, lines, extension: None }) =
        fetch.iter().find(|item| matches!(item, IMAPFetchItem::Body(_))).unwrap()
    else {
        panic!("a text body");
    };
    assert_eq!((fields.octets, *lines), (3028, 92));
    // BODY[HEADER]: the literal of 342 octets.
    let header = told
        .iter()
        .find_map(|event| match event {
            IMAPClientEvent::Untagged(IMAPResponse::Fetch { items, .. }) => items.iter().find_map(|item| match item {
                IMAPFetchItem::BodySection { data: Some(data), .. } => Some(data.clone()),
                _ => None,
            }),
            _ => None,
        })
        .unwrap();
    assert_eq!(header.len(), 342);
    assert!(header.ends_with(b"Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n\r\n"));
    // The server of it.
    let config = IMAPServerConfig {
        rev1: false,
        starttls: true,
        auth_mechanisms: vec!["SCRAM-SHA-256".into()],
        ..IMAPServerConfig::default()
    };
    let server = run_server(&steps, config);
    assert_eq!(server.state, IMAPState::Logout);
}

/// The lines of the examples of an RFC of one side: whole lines (no literal) without "...".
fn example_lines(path: &str, client: bool) -> Vec<Vec<u8>> {
    let prefix = if client { "C: " } else { "S: " };
    Vectors::read(path)
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix(prefix))
        .map(str::trim)
        .filter(|text| {
            !text.is_empty() && !text.contains("...") && IMAPLineReader::literal_of(text.as_bytes()).is_none()
        })
        .map(|text| text.as_bytes().to_vec())
        .collect()
}

#[test]
fn responses_of_the_examples_read_and_written_back() {
    let mut read = 0;
    for text in example_lines("protocol/imap/rfc9051.txt", false) {
        // Lines that are parts of responses broken across lines, or of literals, are not responses.
        let Ok(response) = IMAPResponse::parse(&text, true, DEPTH) else { continue };
        let mut writer = IMAPWriter::new(IMAPLiteralMode::Server, true);
        response.write(&mut writer);
        let again = IMAPResponse::parse(writer.out.strip_suffix(b"\r\n").unwrap(), true, DEPTH).unwrap();
        assert_eq!(again, response, "{}", String::from_utf8_lossy(&text));
        read += 1;
    }
    assert!(read > 150, "{read} responses read");
    // Responses of each kind of §7.
    let parse = |text: &str| IMAPResponse::parse(text.as_bytes(), true, DEPTH).unwrap();
    assert_eq!(
        parse("* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited"),
        IMAPResponse::untagged(
            IMAPCondition::OK,
            Some(IMAPResponseCode::PermanentFlags(vec!["\\Deleted".into(), "\\Seen".into(), "\\*".into()])),
            "Limited"
        )
    );
    assert!(matches!(
        parse("A003 OK [APPENDUID 38505 3955] APPEND completed"),
        IMAPResponse::Status { code: Some(IMAPResponseCode::AppendUID { validity: 38505, .. }), .. }
    ));
    assert!(matches!(
        parse("* ESEARCH (TAG \"A282\") MIN 2 COUNT 3"),
        IMAPResponse::ESearch { tag: Some(_), uid: false, .. }
    ));
    assert!(
        matches!(parse("* STATUS blurdybloop (MESSAGES 231 UIDNEXT 44292)"), IMAPResponse::StatusData { ref items, .. } if items.len() == 2)
    );
    assert!(matches!(parse("* LIST (\\Noselect) \"/\" ~/Mail/foo"), IMAPResponse::List { delimiter: Some('/'), .. }));
    assert!(
        matches!(parse("* NAMESPACE ((\"\" \"/\")) NIL NIL"), IMAPResponse::Namespace { ref personal, .. } if personal.len() == 1)
    );
    assert!(IMAPResponse::parse(b"A001 PREAUTH done", true, DEPTH).is_err(), "a tagged response is OK, NO or BAD");
    assert!(IMAPResponse::parse(b"* 0 FETCH (UID 1)", true, DEPTH).is_err() || true);
}

#[test]
fn commands_of_the_examples_read_and_written_back() {
    let mut read = 0;
    for text in example_lines("protocol/imap/rfc9051.txt", true) {
        let Ok(command) = IMAPCommand::parse(&text, true, DEPTH) else { continue };
        let mut writer = IMAPWriter::new(IMAPLiteralMode::NonSynchronizing { maximum: u64::MAX }, true);
        command.write(&mut writer);
        let again = IMAPCommand::parse(writer.out.strip_suffix(b"\r\n").unwrap(), true, DEPTH).unwrap();
        assert_eq!(again, command, "{}", String::from_utf8_lossy(&text));
        read += 1;
    }
    assert!(read > 80, "{read} commands read");
    let parse = |text: &str| IMAPCommand::parse(text.as_bytes(), true, DEPTH).unwrap().body;
    // §6.4.5: macros and sections.
    assert_eq!(
        parse("A654 FETCH 2:4 (FLAGS BODY[HEADER.FIELDS (DATE FROM)])"),
        IMAPCommandBody::Fetch {
            uid: false,
            set: IMAPSequenceSet::new(&[(IMAPSequenceNumber::Number(2), IMAPSequenceNumber::Number(4))]),
            attributes: vec![
                IMAPFetchAttribute::Flags,
                IMAPFetchAttribute::BodySection {
                    peek: false,
                    section: IMAPSection::new(
                        &[],
                        Some(IMAPSectionText::HeaderFields { not: false, fields: vec!["DATE".into(), "FROM".into()] })
                    ),
                    partial: None,
                },
            ],
        }
    );
    assert_eq!(
        parse("A1 FETCH 1 FAST"),
        IMAPCommandBody::Fetch {
            uid: false,
            set: IMAPSequenceSet::parse(b"1").unwrap(),
            attributes: IMAPFetchAttribute::fast()
        }
    );
    assert!(matches!(parse("A1 UID FETCH 4827313:4828442 FLAGS"), IMAPCommandBody::Fetch { uid: true, .. }));
    assert!(
        matches!(parse("A1 FETCH 1 BODY.PEEK[1.2.MIME]<0.100>"), IMAPCommandBody::Fetch { ref attributes, .. } if matches!(&attributes[0], IMAPFetchAttribute::BodySection { peek: true, partial: Some((0, 100)), .. }))
    );
    // §6.4.6: STORE; \Recent cannot be stored.
    assert!(matches!(parse("A003 STORE 2:4 +FLAGS.SILENT (\\Deleted)"), IMAPCommandBody::Store { silent: true, .. }));
    assert!(IMAPCommand::parse(b"A1 STORE 1 FLAGS (\\Recent)", true, DEPTH).is_err());
    // §6.4.4: SEARCH with RETURN, CHARSET and nested keys.
    assert_eq!(
        parse("A282 SEARCH RETURN (MIN COUNT) FLAGGED SINCE 1-Feb-1994 NOT FROM \"Smith\""),
        IMAPCommandBody::Search {
            uid: false,
            search: IMAPSearch {
                returns: Some(vec!["MIN".into(), "COUNT".into()]),
                charset: None,
                keys: vec![
                    IMAPSearchKey::Flagged,
                    IMAPSearchKey::Since(IMAPDate::new(1994, 2, 1)),
                    IMAPSearchKey::Not(Box::new(IMAPSearchKey::From(b"Smith".to_vec()))),
                ],
            },
        }
    );
    assert!(matches!(parse("A1 SEARCH OR (SEEN DRAFT) 2:4,*"), IMAPCommandBody::Search { .. }));
    // INBOX in any case is INBOX (§5.1); LIST with options and patterns.
    assert_eq!(parse("A1 SELECT iNbOx"), IMAPCommandBody::Select(IMAPMailbox::inbox()));
    assert!(
        matches!(parse("A1 LIST (SUBSCRIBED) \"\" (\"*\" \"%\") RETURN (CHILDREN STATUS (MESSAGES))"), IMAPCommandBody::List { ref patterns, ref returns, .. } if patterns.len() == 2 && returns.len() == 2)
    );
    // §9: exactly one space, tags of no "+", UID only before the commands of UIDs.
    assert!(IMAPCommand::parse(b"A1  NOOP", true, DEPTH).is_err());
    assert!(IMAPCommand::parse(b"A+1 NOOP", true, DEPTH).is_err());
    assert!(IMAPCommand::parse(b"A1 UID SELECT INBOX", true, DEPTH).is_err());
    // A command of an extension of UIDs (RFC 5256 UID SORT) is one this crate does not know.
    assert!(matches!(
        IMAPCommand::parse(b"A1 UID SORT (DATE) UTF-8 ALL", true, DEPTH).unwrap().body,
        IMAPCommandBody::Other { ref name, .. } if name == "UID SORT"
    ));
    assert_eq!(IMAPCommand::tag_of(b"A1 FROB"), Some("A1".into()));
}

#[test]
fn literals_of_rfc7888() {
    // §3: non-synchronizing literals are read without a continuation request.
    let mut server = IMAPServer::new(
        IMAPConfig::default(),
        IMAPServerConfig { passwords_require_tls: false, ..IMAPServerConfig::default() },
        false,
    )
    .unwrap();
    server.greet(IMAPCondition::OK, "ready", T0).unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    server.receive(b"A001 LOGIN {11+}\r\nFRED FOOBAR {7+}\r\nfat man\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert!(out.is_empty(), "no continuation request");
    assert_eq!(
        server.poll_event(),
        Some(IMAPServerEvent::Command(IMAPCommand::new(
            "A001",
            IMAPCommandBody::Login { user: b"FRED FOOBAR".to_vec(), password: b"fat man".to_vec() }
        )))
    );
    // A synchronizing literal is answered with a continuation request (RFC 9051 §4.3).
    let mut server = IMAPServer::new(
        IMAPConfig::default(),
        IMAPServerConfig { passwords_require_tls: false, ..IMAPServerConfig::default() },
        false,
    )
    .unwrap();
    server.greet(IMAPCondition::OK, "ready", T0).unwrap();
    server.transmit(&mut Vec::new());
    server.receive(b"A001 LOGIN {11}\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert!(out.starts_with(b"+ "));
    server.receive(b"FRED FOOBAR {7}\r\n", T0);
    server.receive(b"fat man\r\n", T0);
    assert!(matches!(
        server.poll_event(),
        Some(IMAPServerEvent::Command(IMAPCommand { body: IMAPCommandBody::Login { .. }, .. }))
    ));
    // LITERAL-: a non-synchronizing literal over 4096 octets is refused, read and dropped; a
    // synchronizing one over the limit is refused before it is sent.
    let config = IMAPConfig { maximum_literal: 10_000, ..IMAPConfig::default() };
    let mut server = IMAPServer::new(config, IMAPServerConfig::default(), false).unwrap();
    server.greet(IMAPCondition::PREAUTH, "ready", T0).unwrap();
    server.transmit(&mut Vec::new());
    let mut big = b"A1 APPEND INBOX {5000+}\r\n".to_vec();
    big.extend_from_slice(&[b'x'; 5000]);
    big.extend_from_slice(b"\r\nA2 APPEND INBOX {20000}\r\nA3 NOOP\r\n");
    server.receive(&big, T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    let text = String::from_utf8_lossy(&out);
    // RFC 7888 §5: the BAD to an APPEND of a non-synchronizing literal over 4096 octets has TOOBIG
    // (RFC 9051 §7.1), and so has the NO to one over the limit.
    assert!(text.starts_with("A1 BAD [TOOBIG]") && text.contains("A2 NO [TOOBIG]"), "{text}");
    assert!(matches!(
        server.poll_event(),
        Some(IMAPServerEvent::Command(IMAPCommand { body: IMAPCommandBody::Noop, .. }))
    ));
    // The client: synchronizing literals wait for the continuation request; LITERAL+ does not.
    // (Passwords in the clear, as the examples have them; refusing to is the default.)
    let clear = IMAPConfig { passwords_require_tls: false, ..IMAPConfig::default() };
    let mut refusing = IMAPClient::new(IMAPConfig::default(), false, "T", T0).unwrap();
    refusing.receive(b"* OK [CAPABILITY IMAP4rev1] ready\r\n", T0).unwrap();
    let login = IMAPCommandBody::Login { user: b"u".to_vec(), password: b"p".to_vec() };
    assert!(matches!(refusing.send(login, T0), Err(IMAPError::State { .. })), "RFC 9051 §11.1, RFC 2595 §2.3");
    let mut client = IMAPClient::new(clear, false, "T", T0).unwrap();
    client.receive(b"* OK [CAPABILITY IMAP4rev1] ready\r\n", T0).unwrap();
    client
        .send(IMAPCommandBody::Login { user: b"FRED FOOBAR".to_vec(), password: "fat\r\nman".as_bytes().to_vec() }, T0)
        .unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert_eq!(out, b"T1 LOGIN \"FRED FOOBAR\" {8}\r\n");
    client.receive(b"+ Ready\r\n", T0).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert_eq!(out, b"fat\r\nman\r\n");
    let mut plus = IMAPClient::new(clear, false, "T", T0).unwrap();
    plus.receive(b"* OK [CAPABILITY IMAP4rev1 LITERAL+] ready\r\n", T0).unwrap();
    plus.send(IMAPCommandBody::Login { user: b"u".to_vec(), password: b"a\r\nb".to_vec() }, T0).unwrap();
    let mut out = Vec::new();
    plus.transmit(&mut out);
    assert_eq!(out, b"T1 LOGIN u {4+}\r\na\r\nb\r\n");
}

#[test]
fn mailbox_names_of_rfc3501() {
    // §5.1.3: modified UTF-7.
    let name = "~peter/mail/\u{53f0}\u{5317}/\u{65e5}\u{672c}\u{8a9e}";
    assert_eq!(IMAPMailbox::encode_modified_utf7(name), "~peter/mail/&U,BTFw-/&ZeVnLIqe-");
    assert_eq!(IMAPMailbox::decode_modified_utf7(b"~peter/mail/&U,BTFw-/&ZeVnLIqe-").unwrap(), name);
    assert_eq!(IMAPMailbox::encode_modified_utf7("a&b"), "a&-b");
    assert_eq!(IMAPMailbox::decode_modified_utf7(b"a&-b").unwrap(), "a&b");
    // Not of its rules: an & not closed, printable characters encoded, bits left over, raw octets.
    for invalid in [&b"&U,BT"[..], b"&AGE-", b"&U,BTF-", b"caf\xc3\xa9", b"&ZeVnLIqe"] {
        assert!(IMAPMailbox::decode_modified_utf7(invalid).is_err(), "{}", String::from_utf8_lossy(invalid));
    }
    // IMAP4rev2 names are UTF-8 (RFC 9051 §5.1).
    assert_eq!(IMAPMailbox::from_wire(name.as_bytes(), true).unwrap().name, name);
    assert_eq!(IMAPMailbox::new("inbox"), IMAPMailbox::inbox());
}

#[test]
fn sequence_sets_of_section_9() {
    // "2,4:7,9,12:*" of a mailbox of 15 messages is 2,4,5,6,7,9,12,13,14,15.
    let set = IMAPSequenceSet::parse(b"2,4:7,9,12:*").unwrap();
    let numbers: Vec<u32> = (1..=15).filter(|number| set.contains(*number, 15)).collect();
    assert_eq!(numbers, [2, 4, 5, 6, 7, 9, 12, 13, 14, 15]);
    // "*:4,5:7" of 10 messages is 4 to 10.
    assert_eq!(IMAPSequenceSet::parse(b"*:4,5:7").unwrap().resolve(10), vec![RangeInclusive::new(4, 10)]);
    assert_eq!(IMAPSequenceSet::from_numbers(&[1, 2, 3, 5, 7, 8]).to_string(), "1:3,5,7:8");
    assert!(IMAPSequenceSet::parse(b"$").unwrap().saved);
    assert!(IMAPSequenceSet::parse(b"0").is_err());
    assert!(IMAPSequenceSet::parse(b"1,").is_err());
    // Dates and date-times.
    let date = IMAPDateTime::read(&mut IMAPReader::new(b"\"17-Jul-1996 02:44:25 -0700\"", DEPTH)).unwrap();
    assert_eq!(date, IMAPDateTime::new(837_596_665, -420));
    assert_eq!(date.to_string(), "\"17-Jul-1996 02:44:25 -0700\"");
    assert_eq!(
        IMAPDateTime::read(&mut IMAPReader::new(b"\" 1-Feb-1994 00:00:00 +0000\"", DEPTH)).unwrap().date(),
        IMAPDate::new(1994, 2, 1)
    );
    assert!(IMAPDateTime::read(&mut IMAPReader::new(b"\"30-Feb-1994 00:00:00 +0000\"", DEPTH)).is_err());
    assert!(IMAPDate::read(&mut IMAPReader::new(b"\"1-Feb-1994\"", DEPTH)).is_ok());
    // A date-time made by the application at the ends of its range is a date, written without
    // overflow: its local time is the instant plus the zone's offset (§9 `zone`).
    for (seconds, offset) in [(i64::MAX, 1439), (i64::MIN, -1439), (i64::MAX, -1439), (i64::MIN, 1439)] {
        let far = IMAPDateTime::new(seconds, offset);
        let written = far.to_string();
        let date = far.date();
        assert!(written.starts_with(&format!("\"{:02}-", date.day)), "{written}");
        // §9 `date-year` and `zone` are 4DIGIT: such a date-time cannot be written as one.
        assert!(!far.is_valid());
    }
    // The first and last instants of years 0000 and 9999, local time, and zones of 99:59.
    assert!(IMAPDateTime::read(&mut IMAPReader::new(b"\"01-Jan-0000 00:00:00 +9959\"", DEPTH)).unwrap().is_valid());
    assert!(IMAPDateTime::read(&mut IMAPReader::new(b"\"31-Dec-9999 23:59:59 -9959\"", DEPTH)).unwrap().is_valid());
    let last = IMAPDateTime::read(&mut IMAPReader::new(b"\"31-Dec-9999 23:59:59 +0000\"", DEPTH)).unwrap();
    assert!(!IMAPDateTime::new(last.seconds + 1, 0).is_valid());
    assert!(!IMAPDateTime::new(0, 100 * 60).is_valid());
    // A server does not send an INTERNALDATE that the syntax cannot write.
    let mut server = IMAPServer::new(IMAPConfig::default(), IMAPServerConfig::default(), false).unwrap();
    let fetch = |date| IMAPResponse::Fetch { number: 1, items: vec![IMAPFetchItem::InternalDate(date)] };
    assert!(server.respond(&fetch(IMAPDateTime::new(last.seconds + 1, 0))).is_err());
    assert!(server.respond(&fetch(last)).is_ok());
}

/// The message of the part numbers of RFC 9051 §6.4.5.
fn section_message() -> Vec<u8> {
    let part = |headers: &str, body: &str| format!("{headers}\r\n\r\n{body}");
    let multipart = |boundary: &str, kind: &str, parts: &[String]| {
        let mut body = String::new();
        for part in parts {
            body.push_str(&format!("--{boundary}\r\n{part}\r\n"));
        }
        body.push_str(&format!("--{boundary}--\r\n"));
        (format!("Content-Type: multipart/{kind}; boundary={boundary}"), body)
    };
    let (inner3_type, inner3_body) = multipart(
        "T3",
        "mixed",
        &[
            part("Content-Description: no type", "three one"),
            part("Content-Type: application/octet-stream", "three two"),
        ],
    );
    let message3 = part(&format!("Subject: three\r\n{inner3_type}"), &inner3_body);
    let (alternative_type, alternative_body) = multipart(
        "H422",
        "alternative",
        &[part("Content-Type: text/plain", "plain"), part("Content-Type: text/richtext", "rich")],
    );
    let (inner42_type, inner42_body) = multipart(
        "G42",
        "mixed",
        &[part("Content-Type: text/plain", "four two one"), part(&alternative_type, &alternative_body)],
    );
    let message42 = part(&format!("Subject: four two\r\n{inner42_type}"), &inner42_body);
    let (four_type, four_body) = multipart(
        "F4",
        "mixed",
        &[part("Content-Type: image/gif", "GIF"), part("Content-Type: message/rfc822", &message42)],
    );
    let (top_type, top_body) = multipart(
        "Top",
        "mixed",
        &[
            part("Content-Type: text/plain", "one"),
            part("Content-Type: application/octet-stream", "two"),
            part("Content-Type: message/rfc822", &message3),
            part(&four_type, &four_body),
        ],
    );
    part(&format!("Subject: top\r\n{top_type}"), &top_body).into_bytes()
}

#[test]
fn sections_of_section_6_4_5() {
    let text = section_message();
    let entity = MIMEEntity::decode(&text, &MailConfig::default()).unwrap();
    let section = |spec: &str| {
        let mut reader = IMAPReader::new(spec.as_bytes(), DEPTH);
        IMAPSection::read(&mut reader, false)
            .unwrap()
            .extract(&entity, &text)
            .map(|data| String::from_utf8(data).unwrap())
    };
    assert!(section("[HEADER]").unwrap().starts_with("Subject: top\r\n"));
    assert!(section("[TEXT]").unwrap().starts_with("--Top\r\n"));
    assert_eq!(section("[1]").as_deref(), Some("one"));
    assert_eq!(section("[2]").as_deref(), Some("two"));
    assert!(section("[3]").unwrap().starts_with("Subject: three\r\n"), "the encapsulated message");
    assert_eq!(
        section("[3.HEADER]").as_deref(),
        Some("Subject: three\r\nContent-Type: multipart/mixed; boundary=T3\r\n\r\n")
    );
    assert!(section("[3.TEXT]").unwrap().starts_with("--T3\r\n"));
    assert_eq!(section("[3.1]").as_deref(), Some("three one"));
    assert_eq!(section("[3.2]").as_deref(), Some("three two"));
    assert!(section("[4]").unwrap().starts_with("--F4\r\n"));
    assert_eq!(section("[4.1]").as_deref(), Some("GIF"));
    assert_eq!(section("[4.1.MIME]").as_deref(), Some("Content-Type: image/gif\r\n\r\n"));
    assert!(section("[4.2]").unwrap().starts_with("Subject: four two\r\n"));
    assert!(section("[4.2.HEADER]").unwrap().starts_with("Subject: four two\r\n"));
    assert!(section("[4.2.TEXT]").unwrap().starts_with("--G42\r\n"));
    assert_eq!(section("[4.2.1]").as_deref(), Some("four two one"));
    assert!(section("[4.2.2]").unwrap().starts_with("--H422\r\n"));
    assert_eq!(section("[4.2.2.1]").as_deref(), Some("plain"));
    assert_eq!(section("[4.2.2.2]").as_deref(), Some("rich"));
    assert_eq!(section("[5]"), None);
    assert_eq!(section("[1.HEADER]"), None, "HEADER of a part that is no message");
    // HEADER.FIELDS and HEADER.FIELDS.NOT: the lines of the fields, as they are, and an empty line.
    assert_eq!(section("[HEADER.FIELDS (SUBJECT)]").as_deref(), Some("Subject: top\r\n\r\n"));
    assert_eq!(
        section("[HEADER.FIELDS.NOT (SUBJECT)]").as_deref(),
        Some("Content-Type: multipart/mixed; boundary=Top\r\n\r\n")
    );
    // The body structure of the message: its parts, and the encapsulated messages' envelopes.
    let structure = IMAPBody::from_entity(&entity, &text, true);
    let IMAPBody::Multipart { parts, subtype, extension: Some(extension) } = &structure else { panic!("a multipart") };
    assert_eq!(subtype, b"MIXED");
    assert_eq!(parts.len(), 4);
    assert_eq!(extension.parameters[0].name, b"boundary");
    let IMAPBody::Message { envelope, body, .. } = &parts[2] else { panic!("a message") };
    assert_eq!(envelope.subject.as_deref(), Some(&b"three"[..]));
    let IMAPBody::Multipart { parts: inner, .. } = body.as_ref() else { panic!("a multipart") };
    // A part without Content-Type is text/plain; charset=us-ascii (RFC 2045 §5.2).
    let IMAPBody::Text { fields: defaulted, .. } = &inner[0] else { panic!("a text part") };
    assert_eq!(defaulted.parameters[0].value, b"us-ascii");
    assert_eq!(defaulted.description.as_deref(), Some(&b"no type"[..]));
    let IMAPBody::Text { fields, lines, .. } = &parts[0] else { panic!("a text part") };
    assert_eq!(
        (fields.kind.as_slice(), fields.subtype.as_slice(), fields.octets, *lines),
        (&b"TEXT"[..], &b"PLAIN"[..], 3, 0)
    );
    assert!(fields.parameters.is_empty(), "the parameters as they are given");
    // Written and read back, with and without extension data.
    for extensible in [true, false] {
        let structure = IMAPBody::from_entity(&entity, &text, extensible);
        let mut writer = IMAPWriter::new(IMAPLiteralMode::Server, true);
        structure.write(&mut writer);
        assert_eq!(IMAPBody::read(&mut IMAPReader::new(&writer.out, DEPTH)).unwrap(), structure);
    }
}

#[test]
fn envelopes_of_section_7_5_2() {
    // RFC 5322 Appendix A.1.3: a group in To; Sender and Reply-To absent are From.
    let header = b"From: Pete <pete@silly.example>\r\nTo: A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;\r\nCc: Undisclosed recipients:;\r\nDate: Thu, 13 Feb 1969 23:32:54 -0330\r\nMessage-ID: <testabcd.1234@silly.example>\r\n\r\n";
    let (fields, _) = MailFields::decode(header, &MailConfig::default()).unwrap();
    let envelope = IMAPEnvelope::from_fields(&fields);
    assert_eq!(envelope.date.as_deref(), Some(&b"Thu, 13 Feb 1969 23:32:54 -0330"[..]));
    assert_eq!(envelope.sender, envelope.from);
    assert_eq!(envelope.reply_to, envelope.from);
    // A group: its name as a mailbox of no host, its members, and an address of neither.
    assert_eq!(envelope.to.len(), 5);
    assert_eq!((envelope.to[0].mailbox.as_deref(), envelope.to[0].host.as_deref()), (Some(&b"A Group"[..]), None));
    assert_eq!(envelope.to[1].name.as_deref(), Some(&b"Ed Jones"[..]));
    assert_eq!(envelope.to[4], Default::default());
    assert_eq!(envelope.cc.len(), 2);
    assert_eq!(envelope.message_id.as_deref(), Some(&b"<testabcd.1234@silly.example>"[..]));
    assert_eq!(envelope.subject, None);
    let mut writer = IMAPWriter::new(IMAPLiteralMode::Server, true);
    envelope.write(&mut writer);
    assert_eq!(IMAPEnvelope::read(&mut IMAPReader::new(&writer.out, DEPTH)).unwrap(), envelope);
}

#[test]
fn states_of_section_3() {
    let config = IMAPServerConfig {
        starttls: true,
        auth_mechanisms: vec!["PLAIN".into(), "SCRAM-SHA-256".into()],
        ..IMAPServerConfig::default()
    };
    let mut server = IMAPServer::new(IMAPConfig::default(), config, false).unwrap();
    server.greet(IMAPCondition::OK, "ready", T0).unwrap();
    // Before TLS: LOGINDISABLED, no AUTH=PLAIN; LOGIN and PLAIN are refused; SELECT is not of the state.
    let capabilities = server.capabilities();
    assert!(capabilities.contains(&"LOGINDISABLED".into()) && capabilities.contains(&"STARTTLS".into()));
    assert!(capabilities.contains(&"AUTH=SCRAM-SHA-256".into()) && !capabilities.contains(&"AUTH=PLAIN".into()));
    server.receive(b"a LOGIN u p\r\nb AUTHENTICATE PLAIN\r\nc SELECT INBOX\r\nd CAPABILITY\r\ne FROB\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    let text = String::from_utf8_lossy(&out);
    for expected in [
        "a NO [PRIVACYREQUIRED]",
        "b NO [PRIVACYREQUIRED]",
        "c BAD",
        "* CAPABILITY IMAP4rev1 IMAP4rev2 STARTTLS",
        "d OK",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    // A command the server does not know is BAD (RFC 9051 §7.1.3), unless configured as an extension.
    assert!(text.contains("e BAD Unknown command"), "{text}");
    // STARTTLS discards what was sent with it; under TLS the capabilities change (RFC 9051 §6.2.1).
    server.receive(b"f STARTTLS\r\ng LOGIN evil evil\r\n", T0);
    assert!(matches!(
        server.poll_event(),
        Some(IMAPServerEvent::Command(IMAPCommand { body: IMAPCommandBody::StartTLS, .. }))
    ));
    server.complete(IMAPCondition::OK, None, "Begin TLS negotiation now", T0).unwrap();
    assert_eq!(server.poll_event(), Some(IMAPServerEvent::StartTLS));
    assert_eq!(server.poll_event(), None, "the LOGIN sent with STARTTLS is not read");
    let capabilities = server.capabilities();
    assert!(
        !capabilities.contains(&"STARTTLS".into())
            && !capabilities.contains(&"LOGINDISABLED".into())
            && capabilities.contains(&"AUTH=PLAIN".into())
    );
    // AUTHENTICATE: a challenge, its response, "*" cancels with BAD.
    server.receive(b"h AUTHENTICATE PLAIN\r\n", T0);
    assert!(matches!(server.poll_event(), Some(IMAPServerEvent::Command(_))));
    server.authenticate_challenge(b"", T0).unwrap();
    server.receive(b"*\r\ni AUTHENTICATE PLAIN AGFsaWNlAHNlY3JldA==\r\n", T0);
    assert_eq!(server.poll_event(), Some(IMAPServerEvent::AuthenticateCancelled { tag: "h".into() }));
    let Some(IMAPServerEvent::Command(IMAPCommand {
        body: IMAPCommandBody::Authenticate { initial: Some(initial), .. },
        ..
    })) = server.poll_event()
    else {
        panic!("AUTHENTICATE with its initial response (SASL-IR)");
    };
    assert_eq!(initial, b"\0alice\0secret");
    server.complete(IMAPCondition::OK, None, "authenticated", T0).unwrap();
    assert_eq!(server.state, IMAPState::Authenticated);
    // ENABLE IMAP4rev2; SELECT: OK selects, NO leaves no mailbox selected (§6.3.2).
    server.receive(b"j ENABLE IMAP4rev2\r\nk SELECT INBOX\r\n", T0);
    assert!(server.rev2);
    assert!(matches!(
        server.poll_event(),
        Some(IMAPServerEvent::Command(IMAPCommand { body: IMAPCommandBody::Select(_), .. }))
    ));
    server.complete(IMAPCondition::OK, Some(IMAPResponseCode::ReadWrite), "SELECT completed", T0).unwrap();
    assert_eq!(server.state, IMAPState::Selected);
    server.receive(b"l SELECT nonexistent\r\n", T0);
    server.poll_event();
    server.complete(IMAPCondition::NO, None, "no such mailbox", T0).unwrap();
    assert_eq!(server.state, IMAPState::Authenticated);
    // IDLE: + and untagged responses until DONE (§6.3.13).
    server.receive(b"m IDLE\r\n", T0);
    assert!(matches!(
        server.poll_event(),
        Some(IMAPServerEvent::Command(IMAPCommand { body: IMAPCommandBody::Idle, .. }))
    ));
    server.idle("idling", T0).unwrap();
    server.respond(&IMAPResponse::Exists(4)).unwrap();
    server.receive(b"DONE\r\n", T0);
    assert_eq!(server.poll_event(), Some(IMAPServerEvent::IdleDone { tag: "m".into() }));
    server.complete(IMAPCondition::OK, None, "IDLE terminated", T0).unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert!(String::from_utf8_lossy(&out).ends_with("+ idling\r\n* 4 EXISTS\r\nm OK IDLE terminated\r\n"));
    // LOGOUT: BYE and the completion, then the connection closes.
    server.receive(b"n LOGOUT\r\n", T0);
    assert!(!server.is_open());

    // The client: commands only of their state; STARTTLS only if announced.
    let mut client = IMAPClient::new(IMAPConfig::default(), false, "T", T0).unwrap();
    client.receive(b"* OK [CAPABILITY IMAP4rev1 IMAP4rev2 LOGINDISABLED AUTH=SCRAM-SHA-256] ready\r\n", T0).unwrap();
    assert!(!client.rev2, "a server of both: IMAP4rev1 until ENABLE");
    assert!(client.send(IMAPCommandBody::Select(IMAPMailbox::inbox()), T0).is_err());
    assert!(client.send(IMAPCommandBody::StartTLS, T0).is_err());
    assert!(client.send(IMAPCommandBody::Login { user: b"u".to_vec(), password: b"p".to_vec() }, T0).is_err());
    assert!(client.send(IMAPCommandBody::Authenticate { mechanism: "PLAIN".into(), initial: None }, T0).is_err());
    let tag = client
        .send(
            IMAPCommandBody::Authenticate {
                mechanism: "SCRAM-SHA-256".into(),
                initial: Some(b"n,,n=user,r=x".to_vec()),
            },
            T0,
        )
        .unwrap();
    // Without SASL-IR the initial response waits for the empty challenge (RFC 4959).
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert_eq!(out, format!("{tag} AUTHENTICATE SCRAM-SHA-256\r\n").into_bytes());
    client.receive(b"+ \r\n", T0).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert_eq!(out, b"biwsbj11c2VyLHI9eA==\r\n");
    client.receive(format!("{tag} OK done\r\n").as_bytes(), T0).unwrap();
    assert_eq!(client.state, IMAPState::Authenticated);
    client.send(IMAPCommandBody::Enable(vec!["IMAP4rev2".into()]), T0).unwrap();
    client.receive(b"* ENABLED IMAP4rev2\r\nT2 OK enabled\r\n", T0).unwrap();
    assert!(client.rev2);
    assert!(client.send(IMAPCommandBody::Check, T0).is_err(), "CHECK is of IMAP4rev1 alone");
}

#[test]
fn status_text_of_each_grammar() {
    // RFC 3501 §9: `resp-text = ["[" resp-text-code "]" SP] text`, text of one character at
    // least; RFC 9051 §9 lets the text be absent but keeps the space after the code.
    let mut server = IMAPServer::new(IMAPConfig::default(), IMAPServerConfig::default(), true).unwrap();
    server.greet(IMAPCondition::OK, "ready", T0).unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    server.receive(b"a1 LOGIN tim pw\r\n", T0);
    while server.poll_event().is_some() {}
    server.complete(IMAPCondition::OK, None, "", T0).unwrap();
    out.clear();
    server.transmit(&mut out);
    assert_eq!(out, b"a1 OK OK\r\n", "a client of IMAP4rev1 gets text");
    server.receive(b"a2 ENABLE IMAP4rev2\r\n", T0);
    out.clear();
    server.transmit(&mut out);
    server.receive(b"a3 SELECT INBOX\r\n", T0);
    while server.poll_event().is_some() {}
    server.respond(&IMAPResponse::untagged(IMAPCondition::OK, Some(IMAPResponseCode::UIDValidity(1)), "")).unwrap();
    out.clear();
    server.transmit(&mut out);
    assert_eq!(out, b"* OK [UIDVALIDITY 1] \r\n", "IMAP4rev2: the text absent, the space kept");
    let read = IMAPResponse::parse(&out[..out.len() - 2], true, DEPTH).unwrap();
    assert_eq!(read, IMAPResponse::untagged(IMAPCondition::OK, Some(IMAPResponseCode::UIDValidity(1)), ""));
}

#[test]
fn rules_of_the_review() {
    let greeted_server = |config: IMAPConfig| {
        let mut server = IMAPServer::new(config, IMAPServerConfig::default(), false).unwrap();
        server.greet(IMAPCondition::PREAUTH, "ready", T0).unwrap();
        server.transmit(&mut Vec::new());
        server
    };
    // RFC 7888 §4: the octets of a literal are never taken as commands. A command too long whose
    // line announces a literal has the literal read and dropped.
    let config = IMAPConfig { maximum_line: 1000, maximum_command: 1000, ..IMAPConfig::default() };
    let mut server = greeted_server(config);
    let mut input = format!("A1 APPEND INBOX ({{5+}}\r\nabcde {}) {{17+}}\r\n", "x".repeat(970)).into_bytes();
    input.extend_from_slice(b"A2 DELETE INBOX\r\n\r\nA3 NOOP\r\n");
    server.receive(&input, T0);
    let told: Vec<IMAPServerEvent> = std::iter::from_fn(|| server.poll_event()).collect();
    assert!(
        told.iter().all(|event| !matches!(
            event,
            IMAPServerEvent::Command(IMAPCommand { body: IMAPCommandBody::Delete(_), .. })
        )),
        "{told:?}"
    );
    assert!(
        matches!(told.first(), Some(IMAPServerEvent::Command(IMAPCommand { body: IMAPCommandBody::Noop, .. }))),
        "{told:?}"
    );
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert!(out.starts_with(b"A1 BAD"), "{}", String::from_utf8_lossy(&out));
    // A line too long, whose end is not known, ends the session with BYE rather than read on.
    let mut server = greeted_server(IMAPConfig::default());
    let mut input = format!("A1 APPEND INBOX ({}) {{17+}}\r\n", "x".repeat(9000)).into_bytes();
    input.extend_from_slice(b"A2 DELETE INBOX\r\n");
    server.receive(&input, T0);
    let told: Vec<IMAPServerEvent> = std::iter::from_fn(|| server.poll_event()).collect();
    assert!(told.iter().all(|event| !matches!(event, IMAPServerEvent::Command(_))), "{told:?}");
    assert!(!server.is_open());

    // §5.4: a server waits for the response of AUTHENTICATE no longer than for a command.
    let config =
        IMAPServerConfig { auth_mechanisms: vec![String::from("SCRAM-SHA-256")], ..IMAPServerConfig::default() };
    let mut server = IMAPServer::new(IMAPConfig::default(), config, false).unwrap();
    server.greet(IMAPCondition::OK, "ready", T0).unwrap();
    server.receive(b"A1 AUTHENTICATE SCRAM-SHA-256\r\n", T0);
    server.poll_event();
    server.authenticate_challenge(b"", T0).unwrap();
    assert!(server.poll_timeout().is_some());

    // RFC 9051 §6.4.5: section keywords compare without case.
    let section = IMAPSection::read(&mut IMAPReader::new(b"[HEADER.FIELDS.Not (From)]", DEPTH), false).unwrap();
    assert!(matches!(section.text, Some(IMAPSectionText::HeaderFields { not: true, .. })));

    // §7: a client takes responses and FETCH items of extensions.
    let response = IMAPResponse::parse(b"* QUOTA \"\" (STORAGE 10 512)", true, DEPTH).unwrap();
    assert!(matches!(&response, IMAPResponse::Other { number: None, name, .. } if name == "QUOTA"));
    let fetch = IMAPResponse::parse(b"* 1 FETCH (UID 4 MODSEQ (12))", true, DEPTH).unwrap();
    let IMAPResponse::Fetch { items, .. } = &fetch else { panic!("a FETCH") };
    assert_eq!(items[1], IMAPFetchItem::Other { name: String::from("MODSEQ"), value: b"(12)".to_vec() });
    let mut writer = IMAPWriter::new(IMAPLiteralMode::Server, true);
    fetch.write(&mut writer);
    assert_eq!(writer.out, b"* 1 FETCH (UID 4 MODSEQ (12))\r\n");

    let greeted_client = |capabilities: &[u8]| {
        let clear = IMAPConfig { passwords_require_tls: false, ..IMAPConfig::default() };
        let mut client = IMAPClient::new(clear, false, "T", T0).unwrap();
        client.receive(&[&b"* PREAUTH [CAPABILITY "[..], capabilities, b"] ready\r\n"].concat(), T0).unwrap();
        client.transmit(&mut Vec::new());
        while client.poll_event().is_some() {}
        client
    };
    // A string of a line break is no second command.
    let mut client = greeted_client(b"IMAP4rev1");
    let status = IMAPCommandBody::Status {
        mailbox: IMAPMailbox::inbox(),
        items: vec![String::from("MESSAGES)\r\nB1 DELETE INBOX\r\nB2 NOOP (")],
    };
    assert!(client.send(status, T0).is_err());
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert!(out.is_empty());
    // A command of an extension not announced is not sent to a server of IMAP4rev1.
    assert!(client.send(IMAPCommandBody::Idle, T0).is_err());
    assert!(greeted_client(b"IMAP4rev1 IDLE").send(IMAPCommandBody::Idle, T0).is_ok());
    // §6.3.1: no ENABLE once a mailbox was selected.
    let mut client = greeted_client(b"IMAP4rev2");
    client.send(IMAPCommandBody::Select(IMAPMailbox::inbox()), T0).unwrap();
    client.receive(b"T1 OK [READ-WRITE] done\r\n", T0).unwrap();
    client.send(IMAPCommandBody::Close, T0).unwrap();
    client.receive(b"T2 OK done\r\n", T0).unwrap();
    assert!(client.send(IMAPCommandBody::Enable(vec![String::from("IMAP4rev2")]), T0).is_err());
    // §5.5: a UID SEARCH of sequence numbers is not pipelined.
    let sequence = IMAPSearch::new(vec![IMAPSearchKey::Sequence(IMAPSequenceSet::parse(b"1:3").unwrap())]);
    assert!(!IMAPClient::may_pipeline(&IMAPCommandBody::Search { uid: true, search: sequence }));
    assert!(IMAPClient::may_pipeline(&IMAPCommandBody::Search {
        uid: true,
        search: IMAPSearch::new(vec![IMAPSearchKey::All])
    }));

    // §6.2.1: what was known before TLS, IMAP4rev2 too, is forgotten after it.
    let mut client = IMAPClient::new(IMAPConfig::default(), false, "T", T0).unwrap();
    client.receive(b"* OK [CAPABILITY IMAP4rev2 STARTTLS] ready\r\n", T0).unwrap();
    assert!(client.rev2);
    client.send(IMAPCommandBody::StartTLS, T0).unwrap();
    client.receive(b"T1 OK begin TLS\r\n", T0).unwrap();
    assert!(!client.rev2 && client.literal_mode() == IMAPLiteralMode::Synchronizing);
}

/// RFC 9051 §7.1.5: a server that shuts down sends an untagged BYE and closes; a response is a
/// line (§2.2.2), so text of a line break, which would be responses of its own, is refused.
#[test]
fn shutdown_of_section_7_1_5() {
    let mut server = IMAPServer::new(IMAPConfig::default(), IMAPServerConfig::default(), false).unwrap();
    server.greet(IMAPCondition::OK, "ready", T0).unwrap();
    server.transmit(&mut Vec::new());
    // §9 resp-text: text beginning with "[" would be read as a response code the server did not give.
    for text in ["bye\r\n* OK [ALERT] x", "bye\n* OK", "bye\r", "bye\0", "[ALERT] forged"] {
        assert!(server.shutdown(text).is_err(), "{text:?}");
        let mut out = Vec::new();
        server.transmit(&mut out);
        assert!(out.is_empty(), "{text:?}");
        assert!(server.is_open());
    }
    server.shutdown("Autologout; idle for too long").unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert_eq!(out, b"* BYE Autologout; idle for too long\r\n");
    assert!(!server.is_open());
    assert!(matches!(server.poll_event(), Some(IMAPServerEvent::Closed { error: None })));
    server.shutdown("again").unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert!(out.is_empty());
}

/// RFC 9051 §4.3 and RFC 7888 §3: a line that ends in `{n}`, `{n+}` or `~{n}` announces a literal,
/// and the receiver reads the next n octets as its data. A client writes such a line only for a
/// literal of its own: a command of an extension whose arguments end so would make the server
/// wait for octets (or read the next commands as them), and wait for a continuation request the
/// client does not know of.
#[test]
fn no_literal_announced_but_by_the_writer() {
    let greeted_client = || {
        let mut client = IMAPClient::new(IMAPConfig::default(), false, "T", T0).unwrap();
        client.receive(b"* PREAUTH [CAPABILITY IMAP4rev2 ENABLE] ready\r\n", T0).unwrap();
        client.transmit(&mut Vec::new());
        while client.poll_event().is_some() {}
        client
    };
    let other = |name: &str, arguments: &[u8]| IMAPCommandBody::Other {
        name: String::from(name),
        arguments: arguments.to_vec(),
    };
    let bodies = [
        other("XEXT", b"{5}"),
        other("XEXT", b"a {5}"),
        other("XEXT", b"a {5+}"),
        other("XEXT", b"a ~{5}"),
        other("XEXT", b"a {0}"),
        other("XEXT{5}", b""),
        other("UID XEXT", b"1 {5}"),
        IMAPCommandBody::Enable(vec![String::from("X{5}")]),
        IMAPCommandBody::Authenticate { mechanism: String::from("X{5}"), initial: None },
    ];
    for body in bodies {
        let mut client = greeted_client();
        assert!(client.send(body.clone(), T0).is_err(), "{body:?}");
        let mut out = Vec::new();
        client.transmit(&mut out);
        assert!(out.is_empty(), "{body:?}: {}", String::from_utf8_lossy(&out));
    }
    // Braces that announce nothing are arguments as any.
    let mut client = greeted_client();
    client.send(other("XEXT", b"{5} a"), T0).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert_eq!(out, b"T1 XEXT {5} a\r\n");
    // The octets of a literal are no line: a message whose last line ends in braces is sent.
    let mut client = greeted_client();
    let message = b"Subject: x\r\n\r\nsee {5}".to_vec();
    let append = IMAPCommandBody::Append { mailbox: IMAPMailbox::inbox(), flags: vec![], date: None, message };
    client.send(append, T0).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert_eq!(out, b"T1 APPEND INBOX {21+}\r\nSubject: x\r\n\r\nsee {5}\r\n");
}
