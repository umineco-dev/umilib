//! The Internet Message Format and MIME: the example messages of RFC 5322
//! Appendix A, RFC 2046 §5.1 and RFC 2049 Appendix A read, the encoded
//! words of RFC 2047 §8, the parameters of RFC 2231 and RFC 2183, the
//! group syntax of RFC 6854, UTF-8 of RFC 6532, and the rules of each
//! (folding, dates, Quoted-Printable, Base64, boundaries).

use umilib::codec::mail::{
    MIMECharset, MIMEContentType, MIMEDisposition, MIMEEncodedWord, MIMEEntity, MIMEMultipart, MIMEParameter,
    MIMEParameters, MIMEQuotedPrintable, MIMETransferEncoding, MIMEWordEncoding, MailAddress, MailConfig, MailDate,
    MailError, MailField, MailFields, MailMailbox, MailMessage, MailMessageID, MailReader,
};

use crate::Vectors;

/// The lines of an RFC, its page breaks removed: the footer, the form
/// feed, the header, and the blank lines around them, which are of no
/// example.
fn lines(path: &str) -> Vec<String> {
    let text = Vectors::read(path);
    let raw: Vec<&str> = text.lines().collect();
    let mut lines: Vec<String> = Vec::new();
    let mut index = 0;
    while index < raw.len() {
        let line = raw[index];
        if line.trim_end().ends_with(']') && line.contains("[Page ") {
            while lines.last().is_some_and(|last| last.trim().is_empty()) {
                lines.pop();
            }
            index += 1;
            while index < raw.len()
                && (raw[index].trim().is_empty() || raw[index].starts_with('\u{c}') || raw[index].starts_with("RFC "))
            {
                index += 1;
            }
            continue;
        }
        lines.push(line.to_string());
        index += 1;
    }
    lines
}

/// The message of `block` lines, `indent` removed from each, each ending in CRLF.
fn message(block: &[String], indent: usize) -> Vec<u8> {
    let mut text = Vec::new();
    for line in block {
        text.extend_from_slice(line.get(indent..).unwrap_or("").as_bytes());
        text.extend_from_slice(b"\r\n");
    }
    text
}

/// The messages of RFC 5322 Appendix A: between lines of `----`.
fn appendix_a() -> Vec<Vec<u8>> {
    let lines = lines("codec/mail/rfc5322.txt");
    let start = lines.iter().position(|line| line.starts_with("Appendix A.1.1.")).expect("Appendix A");
    let mut messages = Vec::new();
    let mut open: Option<usize> = None;
    for (index, line) in lines.iter().enumerate().skip(start) {
        if line.trim() == "----" {
            match open.take() {
                Some(first) => {
                    // A.6.3: "__" stands for two spaces.
                    let block: Vec<String> = lines[first..index].iter().map(|line| line.replace("__", "  ")).collect();
                    messages.push(message(&block, 3));
                }
                None => open = Some(index + 1),
            }
        }
    }
    messages
}

/// The example of an RFC beginning with the line `first` and ending with `last`.
fn example(path: &str, first: &str, last: &str, indent: usize) -> Vec<u8> {
    let lines = lines(path);
    let start = lines.iter().position(|line| line == first).expect("first line of the example");
    let end = start + lines[start..].iter().position(|line| line == last).expect("last line of the example");
    message(&lines[start..=end], indent)
}

fn config() -> MailConfig {
    MailConfig::default()
}

fn mailbox(name: Option<&str>, local: &str, domain: &str) -> MailMailbox {
    MailMailbox::new(name, local, domain)
}

#[test]
fn appendix_a_messages_are_read_and_valid() {
    let messages = appendix_a();
    assert_eq!(messages.len(), 14, "RFC 5322 Appendix A has fourteen messages");
    for text in &messages {
        let message = MailMessage::decode(text, &config())
            .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(text)));
        message.validate().unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(text)));
        assert_eq!(MailMessage::decode(&message.encode(), &config()).unwrap(), message, "written and read back");
        let entity = MIMEEntity::decode(text, &config()).unwrap();
        assert!(entity.content_type.is("text", "plain"));
        assert_eq!(&text[entity.body.clone()], message.body.as_slice());
    }
}

#[test]
fn appendix_a_1_1_simple_addressing() {
    let message = MailMessage::decode(&appendix_a()[0], &config()).unwrap();
    let fields = &message.fields;
    assert_eq!(fields.mailboxes("From").unwrap().unwrap(), [mailbox(Some("John Doe"), "jdoe", "machine.example")]);
    let to = fields.addresses("To").unwrap().unwrap();
    assert_eq!(to, [MailAddress::Mailbox(mailbox(Some("Mary Smith"), "mary", "example.net"))]);
    assert_eq!(fields.text("Subject").unwrap().as_deref(), Some("Saying Hello"));
    assert_eq!(fields.date("Date").unwrap(), Some(MailDate::new(880127706, -360)));
    assert_eq!(
        fields.message_ids("Message-ID").unwrap().unwrap(),
        [MailMessageID::new("1234", "local.machine.example")]
    );
    assert_eq!(message.body, b"This is a message just to say hello.\r\nSo, \"Hello\".\r\n");

    let message = MailMessage::decode(&appendix_a()[1], &config()).unwrap();
    assert_eq!(
        message.fields.mailbox("Sender").unwrap(),
        Some(mailbox(Some("Michael Jones"), "mjones", "machine.example"))
    );
}

#[test]
fn appendix_a_1_2_types_of_mailboxes() {
    let message = MailMessage::decode(&appendix_a()[2], &config()).unwrap();
    let fields = &message.fields;
    assert_eq!(
        fields.mailboxes("From").unwrap().unwrap(),
        [mailbox(Some("Joe Q. Public"), "john.q.public", "example.com")]
    );
    let to = fields.addresses("To").unwrap().unwrap();
    assert_eq!(
        to,
        [
            MailAddress::Mailbox(mailbox(Some("Mary Smith"), "mary", "x.test")),
            MailAddress::Mailbox(mailbox(None, "jdoe", "example.org")),
            MailAddress::Mailbox(mailbox(Some("Who?"), "one", "y.test")),
        ]
    );
    let cc = fields.addresses("Cc").unwrap().unwrap();
    assert_eq!(
        cc,
        [
            MailAddress::Mailbox(mailbox(None, "boss", "nil.test")),
            MailAddress::Mailbox(mailbox(Some("Giant; \"Big\" Box"), "sysservices", "example.net")),
        ]
    );
    assert_eq!(fields.date("Date").unwrap(), Some(MailDate::new(1057049557, 120)));
    // The names are written back quoted where §3.4 needs it.
    assert_eq!(cc[1].to_string(), "\"Giant; \\\"Big\\\" Box\" <sysservices@example.net>");
    assert_eq!(to[2].to_string(), "Who? <one@y.test>");
    assert_eq!(MailAddress::parse_list(MailAddress::format_list(&to).as_bytes(), false).unwrap(), to);
}

#[test]
fn appendix_a_1_3_groups() {
    let message = MailMessage::decode(&appendix_a()[3], &config()).unwrap();
    let to = message.fields.addresses("To").unwrap().unwrap();
    assert_eq!(
        to,
        [MailAddress::Group {
            name: "A Group".into(),
            members: vec![
                mailbox(Some("Ed Jones"), "c", "a.test"),
                mailbox(None, "joe", "where.test"),
                mailbox(Some("John"), "jdoe", "one.test"),
            ],
        }]
    );
    let cc = message.fields.addresses("Cc").unwrap().unwrap();
    assert_eq!(cc, [MailAddress::Group { name: "Undisclosed recipients".into(), members: vec![] }]);
    assert_eq!(cc[0].to_string(), "\"Undisclosed recipients\":;".replace('"', ""));
    assert_eq!(message.fields.date("Date").unwrap(), Some(MailDate::new(-27723426, -210)));
}

#[test]
fn appendix_a_2_replies() {
    let messages = appendix_a();
    let reply = MailMessage::decode(&messages[5], &config()).unwrap();
    assert_eq!(
        reply.fields.addresses("Reply-To").unwrap().unwrap(),
        [MailAddress::Mailbox(mailbox(Some("Mary Smith: Personal Account"), "smith", "home.example"))]
    );
    assert_eq!(
        reply.fields.message_ids("In-Reply-To").unwrap().unwrap(),
        [MailMessageID::new("1234", "local.machine.example")]
    );
    let second = MailMessage::decode(&messages[6], &config()).unwrap();
    assert_eq!(
        second.fields.message_ids("References").unwrap().unwrap(),
        [MailMessageID::new("1234", "local.machine.example"), MailMessageID::new("3456", "example.net")]
    );
    assert_eq!(second.fields.text("Subject").unwrap().as_deref(), Some("Re: Saying Hello"));
}

#[test]
fn appendix_a_3_resent_fields() {
    let message = MailMessage::decode(&appendix_a()[8], &config()).unwrap();
    assert_eq!(message.fields.entries[0].name, "Resent-From");
    assert_eq!(message.fields.date("Resent-Date").unwrap(), Some(MailDate::new(880410121, -480)));
    assert_eq!(
        message.fields.message_ids("Resent-Message-ID").unwrap().unwrap(),
        [MailMessageID::new("78910", "example.net")]
    );
}

#[test]
fn appendix_a_4_trace_fields_are_unfolded() {
    let message = MailMessage::decode(&appendix_a()[9], &config()).unwrap();
    let received: Vec<&MailField> = message.fields.all("Received").collect();
    assert_eq!(received.len(), 2);
    let unfolded = String::from_utf8(received[0].unfolded()).unwrap();
    assert_eq!(
        unfolded,
        "from x.y.test   by example.net   via TCP   with ESMTP   id ABC12345   for <mary@example.net>;  21 Nov 1997 10:05:43 -0600"
    );
}

#[test]
fn appendix_a_5_white_space_and_comments() {
    let message = MailMessage::decode(&appendix_a()[10], &config()).unwrap();
    let fields = &message.fields;
    assert_eq!(fields.mailboxes("From").unwrap().unwrap(), [mailbox(Some("Pete"), "pete", "silly.test")]);
    assert_eq!(
        fields.addresses("To").unwrap().unwrap(),
        [MailAddress::Group {
            name: "A Group".into(),
            members: vec![
                mailbox(Some("Chris Jones"), "c", "public.example"),
                mailbox(None, "joe", "example.org"),
                mailbox(Some("John"), "jdoe", "one.test"),
            ],
        }]
    );
    assert_eq!(
        fields.addresses("Cc").unwrap().unwrap(),
        [MailAddress::Group { name: "Hidden recipients".into(), members: vec![] }]
    );
    assert_eq!(fields.date("Date").unwrap(), Some(MailDate::new(-27723480, -210)));
    assert_eq!(fields.message_ids("Message-ID").unwrap().unwrap(), [MailMessageID::new("testabcd.1234", "silly.test")]);
}

#[test]
fn appendix_a_6_obsolete_forms() {
    let messages = appendix_a();
    let addressing = MailMessage::decode(&messages[11], &config()).unwrap();
    assert_eq!(
        addressing.fields.mailboxes("From").unwrap().unwrap(),
        [mailbox(Some("Joe Q. Public"), "john.q.public", "example.com")]
    );
    // The route is ignored (§4.4), the empty elements skipped, the spaces about "." removed.
    assert_eq!(
        addressing.fields.addresses("To").unwrap().unwrap(),
        [
            MailAddress::Mailbox(mailbox(Some("Mary Smith"), "mary", "example.net")),
            MailAddress::Mailbox(mailbox(None, "jdoe", "test.example")),
        ]
    );
    let dates = MailMessage::decode(&messages[12], &config()).unwrap();
    assert_eq!(dates.fields.date("Date").unwrap(), Some(MailDate::new(880106106, 0)));
    let white_space = MailMessage::decode(&messages[13], &config()).unwrap();
    let fields = &white_space.fields;
    assert_eq!(fields.mailboxes("From").unwrap().unwrap(), [mailbox(Some("John Doe"), "jdoe", "machine.example")]);
    assert_eq!(
        fields.addresses("To").unwrap().unwrap(),
        [MailAddress::Mailbox(mailbox(Some("Mary Smith"), "mary", "example.net"))]
    );
    assert_eq!(fields.text("Subject").unwrap().as_deref(), Some("Saying Hello"));
    assert_eq!(fields.date("Date").unwrap(), Some(MailDate::new(880127706, -360)));
    assert_eq!(
        fields.message_ids("Message-ID").unwrap().unwrap(),
        [MailMessageID::new("1234", "local.machine.example")]
    );
}

#[test]
fn field_names_and_values() {
    // §2.2: printable US-ASCII but the colon; §3.6.8.
    assert!(MailField::is_name("X-Mailer"));
    assert!(!MailField::is_name("Bad Name"));
    assert!(!MailField::is_name("a:b"));
    assert!(!MailField::is_name(""));
    assert!(!MailField::is_name("Caf\u{e9}"));
    assert!(MailField::new("Subject", b"a\r\nb").is_err());
    assert!(MailField::new("Subject", b"a\nb").is_err());
    let text = b"Subject: x\r\n\r\n";
    let (fields, body) = MailFields::decode(text, &config()).unwrap();
    assert_eq!(fields.get("subject"), Some(&b"x"[..]), "names compare without case");
    assert_eq!(body, text.len());
    // A line that is no field, or a folded line first, is not a header section.
    assert!(MailFields::decode(b"no colon here\r\n\r\n", &config()).is_err());
    assert!(MailFields::decode(b" Subject: x\r\n\r\n", &config()).is_err());
    // Fields kept in order, all of a name found (§3.6).
    let (fields, _) = MailFields::decode(b"Received: a\r\nX: 1\r\nReceived: b\r\n\r\n", &config()).unwrap();
    let received: Vec<&[u8]> = fields.all("received").map(|field| field.value.as_slice()).collect();
    assert_eq!(received, [&b"a"[..], &b"b"[..]]);
}

#[test]
fn folding_keeps_lines_short_and_unfolds_to_the_value() {
    // §2.2.3: folding is a CRLF before white space; unfolding removes the CRLF.
    let value = "word ".repeat(60);
    let value = value.trim_end();
    let field = MailField::new("Subject", value.as_bytes()).unwrap();
    let mut out = Vec::new();
    field.encode(&mut out);
    for line in out.split(|byte| *byte == b'\n') {
        assert!(line.len() <= MailField::LINE + 1, "a line of {} characters", line.len());
    }
    let (fields, _) = MailFields::decode(&[out.as_slice(), b"\r\n"].concat(), &config()).unwrap();
    assert_eq!(fields.entries[0].unfolded(), value.as_bytes());
}

#[test]
fn dates_of_section_3_3() {
    let date = MailDate::parse(b"Fri, 21 Nov 1997 09:55:06 -0600").unwrap();
    assert_eq!(date.to_string(), "Fri, 21 Nov 1997 09:55:06 -0600");
    assert_eq!(MailDate::parse(date.to_string().as_bytes()).unwrap(), date);
    // The day of the week is optional, the seconds too.
    assert_eq!(MailDate::parse(b"21 Nov 1997 09:55 -0600").unwrap(), MailDate::new(880127700, -360));
    // A day of the week not of the date, a day not of the month, a year before 1900.
    assert!(MailDate::parse(b"Sat, 21 Nov 1997 09:55:06 -0600").is_err());
    assert!(MailDate::parse(b"30 Feb 2001 00:00:00 +0000").is_err());
    assert!(MailDate::parse(b"29 Feb 2000 00:00:00 +0000").is_ok());
    assert!(MailDate::parse(b"1 Jan 1899 00:00:00 +0000").is_err());
    assert!(MailDate::parse(b"21 Nov 1997 24:00:00 +0000").is_err());
    // A leap second (§3.3: 60).
    assert!(MailDate::parse(b"31 Dec 2016 23:59:60 +0000").is_ok());
    // The zone: four digits, the minutes at most 59.
    assert!(MailDate::parse(b"21 Nov 1997 09:55:06 -06").is_err());
    assert!(MailDate::parse(b"21 Nov 1997 09:55:06 +0060").is_err());
    assert_eq!(MailDate::parse(b"21 Nov 1997 09:55:06 +9959").unwrap().offset, 99 * 60 + 59);
    // §4.3: obsolete years and zones.
    assert_eq!(
        MailDate::parse(b"21 Nov 49 00:00:00 GMT").unwrap(),
        MailDate::parse(b"21 Nov 2049 00:00:00 +0000").unwrap()
    );
    assert_eq!(
        MailDate::parse(b"21 Nov 50 00:00:00 GMT").unwrap(),
        MailDate::parse(b"21 Nov 1950 00:00:00 +0000").unwrap()
    );
    assert_eq!(
        MailDate::parse(b"21 Nov 100 00:00:00 GMT").unwrap(),
        MailDate::parse(b"21 Nov 2000 00:00:00 +0000").unwrap()
    );
    assert_eq!(MailDate::parse(b"1 Jan 2000 00:00:00 EST").unwrap().offset, -300);
    assert_eq!(MailDate::parse(b"1 Jan 2000 00:00:00 PDT").unwrap().offset, -420);
    assert_eq!(MailDate::parse(b"1 Jan 2000 00:00:00 A").unwrap().offset, 0, "military zones as -0000");
}

#[test]
fn addresses_of_section_3_4() {
    // A quoted local part, quoted again when written (§3.4.1).
    let mailbox = MailMailbox::parse(b"\"john doe\"@example.com", false).unwrap();
    assert_eq!(mailbox.local, "john doe");
    assert_eq!(mailbox.address(), "\"john doe\"@example.com");
    let literal = MailMailbox::parse(b"<postmaster@[192.0.2.1]>", false).unwrap();
    assert_eq!(literal.domain, "[192.0.2.1]");
    // A name of atoms only is written as it is.
    assert_eq!(MailMailbox::new(Some("Mary Smith"), "mary", "x.test").to_string(), "Mary Smith <mary@x.test>");
    assert!(MailMailbox::parse(b"no-at-sign", false).is_err());
    assert!(MailMailbox::parse(b"<a@b", false).is_err());
    assert!(MailMailbox::parse(b"a@b c", false).is_err());
    assert!(MailAddress::parse_list(b"Group: a@b", false).is_err(), "a group not ended by ;");
    assert!(MailMailbox::parse_list(b"", false).is_err(), "a mailbox list has one mailbox or more");
}

#[test]
fn rfc6854_groups_in_from_and_sender() {
    let text = b"From: Managing Partners:ben@example.com,carol@example.com;\r\nSender: dave@example.com\r\nDate: 1 Jan 2013 00:00:00 +0000\r\n\r\n";
    let message = MailMessage::decode(text, &config()).unwrap();
    message.validate().unwrap();
    let robot = b"From: Nightly Monitor Robot:;\r\nDate: 1 Jan 2013 00:00:00 +0000\r\n\r\n";
    MailMessage::decode(robot, &config()).unwrap().validate().unwrap();
    // Two authors need a Sender, which is of one mailbox at most.
    let no_sender = b"From: ben@example.com,carol@example.com\r\nDate: 1 Jan 2013 00:00:00 +0000\r\n\r\n";
    assert!(MailMessage::decode(no_sender, &config()).unwrap().validate().is_err());
    let group_sender = b"From: a@example.com,b@example.com\r\nSender: S:c@example.com,d@example.com;\r\nDate: 1 Jan 2013 00:00:00 +0000\r\n\r\n";
    assert!(MailMessage::decode(group_sender, &config()).unwrap().validate().is_err());
}

#[test]
fn validation_of_messages() {
    let valid = b"From: a@example.com\r\nDate: 1 Jan 2013 00:00:00 +0000\r\n\r\nbody\r\n".to_vec();
    MailMessage::decode(&valid, &config()).unwrap().validate().unwrap();
    let check = |text: &[u8]| MailMessage::decode(text, &config()).unwrap().validate();
    assert!(check(b"From: a@example.com\r\n\r\n").is_err(), "no Date");
    assert!(check(b"Date: 1 Jan 2013 00:00:00 +0000\r\n\r\n").is_err(), "no From");
    assert!(check(b"From: a@example.com\r\nFrom: b@example.com\r\nDate: 1 Jan 2013 00:00:00 +0000\r\n\r\n").is_err());
    assert!(
        check(b"From: a@example.com\r\nDate: 1 Jan 2013 00:00:00 +0000\r\nSubject: a\r\nSubject: b\r\n\r\n").is_err()
    );
    let mut lone_lf = valid.clone();
    lone_lf.extend_from_slice(b"line\n");
    assert!(check(&lone_lf).is_err(), "§2.3: CR and LF only together");
    let mut long = valid.clone();
    long.extend_from_slice(&[b'x'; 999]);
    assert!(check(&long).is_err(), "§2.1.1: lines of at most 998 characters");
    let mut longest = valid;
    longest.extend_from_slice(&[b'x'; 998]);
    assert!(check(&longest).is_ok());
}

#[test]
fn rfc6532_utf8_headers() {
    let text = "From: \u{65e5}\u{672c} <\u{30e6}\u{30fc}\u{30b6}\u{30fc}@\u{4f8b}\u{3048}.jp>\r\nSubject: \u{3053}\u{3093}\u{306b}\u{3061}\u{306f}\r\n\r\n";
    let message = MailMessage::decode(text.as_bytes(), &config()).unwrap();
    let from = message.fields.mailboxes("From").unwrap().unwrap();
    assert_eq!(from, [mailbox(Some("\u{65e5}\u{672c}"), "\u{30e6}\u{30fc}\u{30b6}\u{30fc}", "\u{4f8b}\u{3048}.jp")]);
    assert_eq!(message.fields.text("Subject").unwrap().as_deref(), Some("\u{3053}\u{3093}\u{306b}\u{3061}\u{306f}"));
    // Without UTF-8, a header is US-ASCII (RFC 5322 §2.2).
    let ascii = MailConfig { utf8: false, ..MailConfig::default() };
    assert!(MailMessage::decode(text.as_bytes(), &ascii).is_err());
    // §3.2: invalid UTF-8 is not text.
    assert!(MailMailbox::parse(b"\xff@example.com", true).is_err());
}

#[test]
fn rfc2047_examples_of_section_8() {
    let lines = lines("codec/mail/rfc2047.txt");
    let start = lines.iter().position(|line| line == "8. Examples").unwrap();
    let headers: Vec<&String> = lines[start..].iter().take_while(|line| !line.starts_with("9. References")).collect();
    let field = |prefix: &str| {
        let index = headers.iter().position(|line| line.starts_with(prefix)).unwrap();
        let line = headers[index];
        let mut value = line[line.find(": ").unwrap() + 2..].to_string();
        for line in &headers[index + 1..] {
            if !line.starts_with("    ") || line.trim().is_empty() {
                break;
            }
            value.push_str("\r\n");
            value.push_str(&line[3..]);
        }
        value
    };
    let name = |value: String| MailMailbox::parse(value.as_bytes(), false).unwrap().name.unwrap();
    let decode = |text: String| MIMEEncodedWord::decode_text(text.as_bytes()).unwrap();
    assert_eq!(decode(name(field("   From: =?US-ASCII"))), "Keith Moore");
    assert_eq!(decode(name(field("   To: =?ISO-8859-1"))), "Keld J\u{f8}rn Simonsen");
    assert_eq!(decode(name(field("   CC: "))), "Andr\u{e9} Pirard");
    assert_eq!(decode(field("   Subject: =?ISO-8859-1?B")), "If you can read this you understand the example.");
    assert_eq!(decode(name(field("   From: =?ISO-8859-1?Q?Olle"))), "Olle J\u{e4}rnefors");
    assert_eq!(decode(name(field("   From: =?ISO-8859-1?Q?Patrik"))), "Patrik F\u{e4}ltstr\u{f6}m");
    // The table: the text of each comment, its parentheses removed, as displayed.
    let table = lines.iter().position(|line| line.starts_with("   encoded form")).unwrap();
    let mut cases = 0;
    let mut index = table;
    while index < lines.len() && !lines[index].starts_with("9. References") {
        let line = &lines[index];
        if line.starts_with("   (") {
            let (mut encoded, displayed) = match line.get(47..) {
                Some(displayed) => (line[3..47].trim_end().to_string(), displayed.trim().to_string()),
                None => (line[3..].trim_end().to_string(), String::new()),
            };
            if !encoded.ends_with(')') {
                index += 1;
                encoded.push_str("\r\n");
                encoded.push_str(lines[index].trim_end());
            }
            let encoded = &encoded[1..encoded.len() - 1];
            let displayed = &displayed[1..displayed.len() - 1];
            assert_eq!(MIMEEncodedWord::decode_text(encoded.as_bytes()).unwrap(), displayed, "{encoded}");
            cases += 1;
        }
        index += 1;
    }
    assert_eq!(cases, 7);
}

#[test]
fn rfc2047_encoded_words() {
    let word = MIMEEncodedWord::parse(b"=?US-ASCII*EN?Q?Keith_Moore?=").unwrap();
    assert_eq!(word.charset, "US-ASCII");
    assert_eq!(word.language.as_deref(), Some("EN"), "RFC 2231 §5");
    assert_eq!(word.text().unwrap(), "Keith Moore");
    assert_eq!(word.encode(), "=?US-ASCII*EN?Q?Keith_Moore?=");
    // §2: at most 75 characters; no space or ? in the text.
    let long = format!("=?UTF-8?Q?{}?=", "a".repeat(64));
    assert!(MIMEEncodedWord::parse(long.as_bytes()).is_err());
    assert!(MIMEEncodedWord::parse(b"=?UTF-8?Q?a b?=").is_err());
    assert!(MIMEEncodedWord::parse(b"=?UTF-8?X?a?=").is_err());
    // §6.2: a character set not converted is left as it is.
    assert_eq!(MIMEEncodedWord::decode_text(b"=?x-unknown?Q?a?= b").unwrap(), "=?x-unknown?Q?a?= b");
    // §5 (1): an encoded word is a whole word.
    assert_eq!(MIMEEncodedWord::decode_text(b"x=?UTF-8?Q?a?=").unwrap(), "x=?UTF-8?Q?a?=");
    // Encoding: plain text stays, other text becomes words of at most 75 characters.
    assert_eq!(MIMEEncodedWord::encode_text("Saying Hello"), "Saying Hello");
    for text in ["Caf\u{e9}", &"\u{65e5}\u{672c}\u{8a9e}".repeat(20), &"r\u{e9}sum\u{e9} ".repeat(15), "a =?b?= c"] {
        let encoded = MIMEEncodedWord::encode_text(text);
        assert!(encoded.is_ascii());
        for word in encoded.split(' ') {
            assert!(word.len() <= MIMEEncodedWord::MAXIMUM_LENGTH, "{word}");
            MIMEEncodedWord::parse(word.as_bytes()).unwrap();
        }
        assert_eq!(MIMEEncodedWord::decode_text(encoded.as_bytes()).unwrap(), text);
    }
    let word = MIMEEncodedWord {
        charset: "UTF-8".into(),
        language: None,
        encoding: MIMEWordEncoding::B,
        data: b"\xe2\x82\xac".to_vec(),
    };
    assert_eq!(word.encode(), "=?UTF-8?B?4oKs?=");
}

#[test]
fn charsets() {
    assert_eq!(MIMECharset::from_name("utf-8"), Some(MIMECharset::UTF8));
    assert_eq!(MIMECharset::from_name("LATIN1"), Some(MIMECharset::ISO88591));
    assert_eq!(MIMECharset::ISO88591.decode(b"\xe9").unwrap(), "\u{e9}");
    assert_eq!(MIMECharset::Windows1252.decode(b"\x80").unwrap(), "\u{20ac}");
    assert!(MIMECharset::Windows1252.decode(b"\x81").is_err());
    assert!(MIMECharset::USASCII.decode(b"\x80").is_err());
    assert_eq!(MIMECharset::Windows1252.encode("\u{20ac}").unwrap(), b"\x80");
    assert!(MIMECharset::ISO88591.encode("\u{20ac}").is_err());
    assert_eq!(MIMECharset::decode_named("ISO-8859-2", b"abc").unwrap(), "abc");
    assert_eq!(MIMECharset::decode_named("ISO-8859-2", b"\xb1"), Err(MailError::Charset));
    assert_eq!(MIMECharset::decode_named("Shift_JIS", b"abc"), Err(MailError::Charset));
}

#[test]
fn rfc2045_content_type() {
    // §5.1: types, subtypes and parameter names without case; comments; quoted values.
    let content_type = MIMEContentType::parse(b"TEXT/Plain; CHARSET=\"us-ascii\" (Plain text)").unwrap();
    assert!(content_type.is("text", "plain"));
    assert_eq!(content_type.parameters.text("charset"), Some("us-ascii"));
    assert_eq!(
        MIMEContentType::parse(b"text/plain; charset=us-ascii").unwrap(),
        MIMEContentType::parse(b"text/plain; charset=\"us-ascii\"").unwrap()
    );
    assert!(MIMEContentType::parse(b"text").is_err());
    assert!(MIMEContentType::parse(b"text/plain; charset").is_err());
    assert!(MIMEContentType::parse(b"text/plain; a=1; a=2").is_err(), "a parameter twice is in doubt");
    let mut built = MIMEContentType::new("multipart", "mixed");
    built.parameters.set(MIMEParameter::new("boundary", b"simple boundary"));
    assert_eq!(built.to_string(), "multipart/mixed; boundary=\"simple boundary\"");
    // §5.2: no Content-Type, or one that cannot be read, is text/plain; charset=us-ascii.
    let entity = MIMEEntity::decode(b"Content-Type: text\r\n\r\nx", &config()).unwrap();
    assert_eq!(entity.content_type, MIMEContentType::default_text());
    let entity = MIMEEntity::decode(b"Subject: x\r\n\r\nx", &config()).unwrap();
    assert_eq!(entity.content_type, MIMEContentType::default_text());
}

#[test]
fn rfc2045_transfer_encodings() {
    // §6.1: names without case, 7bit by default.
    assert_eq!(MIMETransferEncoding::parse(b" Quoted-Printable ").unwrap(), MIMETransferEncoding::QuotedPrintable);
    assert_eq!(MIMETransferEncoding::parse(b"BASE64").unwrap(), MIMETransferEncoding::Base64);
    assert_eq!(MIMETransferEncoding::parse(b"x-uuencode").unwrap(), MIMETransferEncoding::Other("x-uuencode".into()));
    assert_eq!(MIMETransferEncoding::Other("x-uuencode".into()).decode(b"x"), Err(MailError::Encoding));
    let entity = MIMEEntity::decode(b"Subject: x\r\n\r\nx", &config()).unwrap();
    assert_eq!(entity.encoding, MIMETransferEncoding::SevenBit);
    // §6.8: Base64 in lines of at most 76 characters, other characters ignored when decoding.
    let data: Vec<u8> = (0..=255).collect();
    let mut encoded = Vec::new();
    MIMETransferEncoding::Base64.encode(&data, &mut encoded).unwrap();
    for line in encoded.split(|byte| *byte == b'\n') {
        assert!(line.len() <= 77);
    }
    assert_eq!(MIMETransferEncoding::Base64.decode(&encoded).unwrap(), data);
    assert_eq!(MIMETransferEncoding::Base64.decode(b"aGVs\r\nbG8=\r\n").unwrap(), b"hello");
    assert_eq!(MIMETransferEncoding::Base64.decode(b"aGVs!bG8").unwrap(), b"hello");
    assert_eq!(MIMETransferEncoding::Base64.decode(b"aGk=").unwrap(), b"hi");
}

#[test]
fn rfc2045_quoted_printable() {
    let text = MIMEQuotedPrintable::new(false);
    // §6.7 (1), (2): =XX for other octets; literal printable characters.
    assert_eq!(text.decode(b"caf=E9"), b"caf\xe9");
    assert_eq!(text.decode(b"caf=e9"), b"caf\xe9", "note (2): lower case taken");
    // (3): white space at the end of a line removed; (5): soft line breaks.
    assert_eq!(text.decode(b"a  \r\nb"), b"a\r\nb");
    assert_eq!(text.decode(b"a=\r\nb"), b"ab");
    assert_eq!(text.decode(b"a= \r\nb"), b"ab", "white space after a soft line break");
    // Note (1): an = not of an octet is taken as it is.
    assert_eq!(text.decode(b"a=Gb"), b"a=Gb");
    // Encoding: lines of at most 76 characters, white space before a line break encoded.
    let mut out = Vec::new();
    text.encode(b"trailing \r\nx", &mut out);
    assert_eq!(out, b"trailing=20\r\nx");
    let long: Vec<u8> = (0..500).map(|index| b"ab\xe9 ="[index % 5]).collect();
    let mut out = Vec::new();
    text.encode(&long, &mut out);
    for line in out.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        assert!(line.len() <= MIMEQuotedPrintable::LINE, "{}", line.len());
        assert!(line.iter().all(|byte| (32..=126).contains(byte)));
    }
    assert_eq!(text.decode(&out), long);
    // (4): line breaks of binary data are encoded.
    let binary = MIMEQuotedPrintable::new(true);
    let data: Vec<u8> = (0..=255).cycle().take(1000).collect();
    let mut out = Vec::new();
    binary.encode(&data, &mut out);
    assert_eq!(binary.decode(&out), data);
}

#[test]
fn rfc2046_simple_multipart() {
    let text = example(
        "codec/mail/rfc2046.txt",
        "     From: Nathaniel Borenstein <nsb@bellcore.com>",
        "     This is the epilogue.  It is also to be ignored.",
        5,
    );
    let entity = MIMEEntity::decode(&text, &config()).unwrap();
    assert!(entity.content_type.is("multipart", "mixed"));
    assert_eq!(entity.content_type.boundary(), Some(&b"simple boundary"[..]));
    assert_eq!(entity.parts.len(), 2);
    // The first part has no header: implicitly text/plain; its CRLF before the delimiter is not of it.
    let first = &entity.parts[0];
    assert!(first.fields.entries.is_empty());
    assert_eq!(first.content_type, MIMEContentType::default_text());
    assert_eq!(
        &text[first.body.clone()],
        b"This is implicitly typed plain US-ASCII text.\r\nIt does NOT end with a linebreak."
    );
    let second = &entity.parts[1];
    assert_eq!(second.content_type.parameters.text("charset"), Some("us-ascii"));
    assert_eq!(
        &text[second.body.clone()],
        b"This is explicitly typed plain US-ASCII text.\r\nIt DOES end with a linebreak.\r\n"
    );
    let multipart = MIMEMultipart::split(&text, entity.body.clone(), b"simple boundary");
    assert!(multipart.closed);
    assert!(text[multipart.preamble.clone()].starts_with(b"This is the preamble."));
    assert_eq!(&text[multipart.epilogue.clone()], b"\r\nThis is the epilogue.  It is also to be ignored.\r\n");
}

#[test]
fn rfc2049_complex_multipart() {
    let text = example("codec/mail/rfc2049.txt", "     MIME-Version: 1.0", "     --unique-boundary-1--", 5);
    let entity = MIMEEntity::decode(&text, &config()).unwrap();
    assert_eq!(entity.parts.len(), 5);
    let kinds: Vec<(&str, &str)> =
        entity.parts.iter().map(|part| (part.content_type.kind.as_str(), part.content_type.subtype.as_str())).collect();
    assert_eq!(
        kinds,
        [("text", "plain"), ("text", "plain"), ("multipart", "parallel"), ("text", "enriched"), ("message", "rfc822")]
    );
    let parallel = &entity.parts[2];
    assert_eq!(parallel.parts.len(), 2);
    assert!(parallel.parts[0].content_type.is("audio", "basic"));
    assert_eq!(parallel.parts[0].encoding, MIMETransferEncoding::Base64);
    assert!(parallel.parts[1].content_type.is("image", "jpeg"));
    let encapsulated = entity.parts[4].message.as_ref().expect("an encapsulated message");
    assert!(encapsulated.content_type.is("text", "plain"));
    assert_eq!(encapsulated.content_type.parameters.text("charset"), Some("ISO-8859-1"));
    assert_eq!(encapsulated.encoding, MIMETransferEncoding::QuotedPrintable);
    assert_eq!(encapsulated.fields.get("Subject"), Some(&b"(subject in US-ASCII)"[..]));
}

#[test]
fn rfc2046_boundaries() {
    // §5.1.1: 1 to 70 characters of bchars, not ending in a space.
    let boundary = |value: &str| {
        let mut content_type = MIMEContentType::new("multipart", "mixed");
        content_type.parameters.set(MIMEParameter::new("boundary", value.as_bytes()));
        content_type.boundary().map(<[u8]>::to_vec)
    };
    assert!(boundary(&"a".repeat(70)).is_some());
    assert!(boundary(&"a".repeat(71)).is_none());
    assert!(boundary("").is_none());
    assert!(boundary("ends with space ").is_none());
    assert!(boundary("bad\"quote").is_none());
    // A delimiter: a line that begins with -- and the boundary; it MUST NOT appear in a part "as
    // the prefix of any line", and it is sufficient that the boundary appear in its entirety.
    assert_eq!(MIMEMultipart::delimiter(b"--b  \r\n", b"b"), Some(false));
    assert_eq!(MIMEMultipart::delimiter(b"--b--\r\n", b"b"), Some(true));
    assert_eq!(MIMEMultipart::delimiter(b"--bc\r\n", b"b"), Some(false));
    assert_eq!(MIMEMultipart::delimiter(b"--b--garbage\r\n", b"b"), Some(true));
    assert_eq!(MIMEMultipart::delimiter(b" --b\r\n", b"b"), None);
    assert_eq!(MIMEMultipart::delimiter(b"-b\r\n", b"b"), None);
    // So a part with a line that begins with the boundary ends there, as every reader sees it.
    let text = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\none\r\n--bX\r\nhidden\r\n--b--\r\n";
    assert_eq!(MIMEEntity::decode(text, &config()).unwrap().parts.len(), 2);
    // Writing refuses a part with the boundary in it, as a line or as its prefix.
    let mut out = Vec::new();
    assert!(MIMEMultipart::encode(b"b", &[b"x\r\n--b\r\ny"], &mut out).is_err());
    assert!(MIMEMultipart::encode(b"b", &[b"x\r\n--bX\r\ny"], &mut out).is_err());
    assert!(MIMEMultipart::encode(b"b", &[b"x\r\n --b\r\ny"], &mut Vec::new()).is_ok());
    let mut out = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n".to_vec();
    MIMEMultipart::encode(b"b", &[b"\r\none", b"Content-Type: text/html\r\n\r\n<p>two</p>"], &mut out).unwrap();
    let entity = MIMEEntity::decode(&out, &config()).unwrap();
    assert_eq!(entity.parts.len(), 2);
    assert_eq!(&out[entity.parts[0].body.clone()], b"one");
    assert!(entity.parts[1].content_type.is("text", "html"));
    assert_eq!(entity.parts[1].data(&out).unwrap(), b"<p>two</p>");
}

#[test]
fn rfc2046_digest_default_type() {
    // §5.1.5: a part of multipart/digest without a type is message/rfc822.
    let text = b"Content-Type: multipart/digest; boundary=d\r\n\r\n--d\r\n\r\nSubject: inner\r\n\r\nbody\r\n--d--\r\n";
    let entity = MIMEEntity::decode(text, &config()).unwrap();
    assert!(entity.parts[0].content_type.is("message", "rfc822"));
    let inner = entity.parts[0].message.as_ref().unwrap();
    assert_eq!(inner.fields.get("Subject"), Some(&b"inner"[..]));
}

#[test]
fn limits_of_the_configuration() {
    let nested = |depth: usize| {
        let mut text = Vec::new();
        for level in 0..depth {
            text.extend_from_slice(
                format!("Content-Type: multipart/mixed; boundary=b{level}\r\n\r\n--b{level}\r\n").as_bytes(),
            );
        }
        text.extend_from_slice(b"\r\nx");
        text
    };
    let config = MailConfig { maximum_depth: 4, ..MailConfig::default() };
    assert!(MIMEEntity::decode(&nested(4), &config).is_ok());
    assert_eq!(MIMEEntity::decode(&nested(5), &config), Err(MailError::TooMany { maximum: 4 }));
    let config = MailConfig { maximum_parts: 3, ..MailConfig::default() };
    let parts =
        b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\n1\r\n--b\r\n\r\n2\r\n--b\r\n\r\n3\r\n--b--\r\n";
    assert_eq!(MIMEEntity::decode(parts, &config), Err(MailError::TooMany { maximum: 3 }));
    let config = MailConfig { maximum_fields: 2, ..MailConfig::default() };
    assert_eq!(MailFields::decode(b"A: 1\r\nB: 2\r\nC: 3\r\n\r\n", &config), Err(MailError::TooMany { maximum: 2 }));
    let config = MailConfig { maximum_length: 4, ..MailConfig::default() };
    assert!(MailMessage::decode(b"A: 1\r\n\r\n", &config).is_err());
}

#[test]
fn rfc2231_continuations_charsets_and_languages() {
    // §3: sections joined in order, quoted or not.
    let content_type = MIMEContentType::parse(
        b"message/external-body; access-type=URL;\r\n URL*0=\"ftp://\";\r\n URL*1=\"cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar\"",
    )
    .unwrap();
    assert_eq!(content_type.parameters.text("url"), Some("ftp://cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar"));
    // §4: the character set and the language, octets percent-encoded.
    let content_type =
        MIMEContentType::parse(b"application/x-stuff;\r\n title*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A")
            .unwrap();
    let title = content_type.parameters.get("title").unwrap();
    assert_eq!(title.charset.as_deref(), Some("us-ascii"));
    assert_eq!(title.language.as_deref(), Some("en-us"));
    assert_eq!(title.text().unwrap(), "This is ***fun***");
    // §4.1, with the semicolons the grammar of §7 puts between parameters.
    let content_type = MIMEContentType::parse(
        b"application/x-stuff;\r\n title*0*=us-ascii'en'This%20is%20even%20more%20;\r\n title*1*=%2A%2A%2Afun%2A%2A%2A%20;\r\n title*2=\"isn't it!\"",
    )
    .unwrap();
    assert_eq!(content_type.parameters.get("title").unwrap().text().unwrap(), "This is even more ***fun*** isn't it!");
    // Neither gaps nor leading zeros (§3).
    assert!(MIMEContentType::parse(b"a/b; t*0=x; t*2=y").is_err());
    assert!(MIMEContentType::parse(b"a/b; t*0=x; t*01=y").is_err());
    assert!(MIMEContentType::parse(b"a/b; t*1=x").is_err());
    assert!(MIMEContentType::parse(b"a/b; t=x; t*0=y").is_err());
    // The delimiters must be there (§4.1 (5)).
    assert!(MIMEContentType::parse(b"a/b; t*=x").is_err());
    // Writing: text of other octets extended, in sections of at most 78 characters.
    let name = "\u{65e5}\u{672c}\u{8a9e}\u{306e}\u{30d5}\u{30a1}\u{30a4}\u{30eb}\u{540d}".repeat(3) + ".txt";
    let mut parameters = MIMEParameters::new();
    parameters.set(MIMEParameter::new("filename", name.as_bytes()));
    let mut written = String::new();
    parameters.encode(&mut written);
    assert!(written.is_ascii());
    assert!(written.contains("filename*0*=UTF-8''%E6%97%A5"));
    for section in written.split("; ").skip(1) {
        assert!(section.len() <= MailField::LINE, "{section}");
    }
    let disposition = MIMEDisposition::parse(format!("attachment{written}").as_bytes()).unwrap();
    assert_eq!(disposition.filename().as_deref(), Some(name.as_str()));
}

#[test]
fn rfc2183_disposition() {
    let lines = lines("codec/mail/rfc2183.txt");
    let index = lines
        .iter()
        .position(|line| line.trim_start().starts_with("Content-Disposition: attachment; filename=genome.jpeg;"))
        .unwrap();
    let value = format!("{}\r\n{}", &lines[index].trim_start()["Content-Disposition: ".len()..], lines[index + 1]);
    let disposition = MIMEDisposition::parse(value.as_bytes()).unwrap();
    assert_eq!(disposition.kind, "attachment");
    assert!(!disposition.is_inline());
    assert_eq!(disposition.filename().as_deref(), Some("genome.jpeg"));
    let date = disposition.parameters.text("modification-date").unwrap();
    assert_eq!(MailDate::parse(date.as_bytes()).unwrap().to_string(), "Wed, 12 Feb 1997 16:29:51 -0500");
    // §2.3: only the last component of a path is taken, nothing of . or ...
    assert_eq!(
        MIMEDisposition::parse(b"attachment; filename=\"../../etc/passwd\"").unwrap().filename().as_deref(),
        Some("passwd")
    );
    assert_eq!(
        MIMEDisposition::parse(b"attachment; filename=\"C:\\\\x\\\\y.txt\"").unwrap().filename().as_deref(),
        Some("y.txt")
    );
    assert_eq!(MIMEDisposition::parse(b"attachment; filename=\"..\"").unwrap().filename(), None);
    assert!(MIMEDisposition::parse(b"INLINE").unwrap().is_inline());
}

#[test]
fn reader_tokens() {
    // RFC 2045 §5.1: tspecials end a token.
    let mut reader = MailReader::new(b" text/plain", false);
    assert_eq!(reader.token().unwrap(), b"text");
    assert!(!MailReader::is_token(b'/'));
    assert!(MailReader::is_token(b'*'));
    // RFC 5322 §3.2.2: comments nest.
    let mut reader = MailReader::new(b"(a (b) c) atom", false);
    assert_eq!(reader.atom().unwrap(), b"atom");
    assert!(MailReader::new(b"(a (b c) atom", false).atom().is_err());
}

#[test]
fn rules_of_the_review() {
    // RFC 5322 §3.6.4: a msg-id of a quoted local part is written as it reads back.
    let id = MailMessageID::parse(b"<\"a b\"@x.example>", true).unwrap();
    assert_eq!(MailMessageID::parse(id.to_string().as_bytes(), true).unwrap(), id);
    // §3.4: the mailboxes of a group are separated by commas.
    assert!(MailAddress::parse(b"g: a@b.example c@d.example;", true).is_err());
    assert!(MailAddress::parse(b"g: a@b.example, c@d.example;", true).is_ok());
    // §3.2.2: a comment closed that was not open is no comment.
    assert!(MailReader::new(b")", true).comment().is_err());
    // §3.2.2: no line of white space alone; §2.1.1: no line over 998 characters.
    let field = MailField::new("Subject", format!("{} ", "x".repeat(76)).as_bytes()).unwrap();
    let mut out = Vec::new();
    field.encode(&mut out);
    let blank = |line: &[u8]| line.iter().all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'));
    assert!(!out.split_inclusive(|byte| *byte == b'\n').any(blank), "{:?}", String::from_utf8_lossy(&out));
    assert!(MailField::new("Subject", "y".repeat(1200).as_bytes()).is_err());
    // RFC 2231 §3: a long value is written in sections a reader takes back, however long.
    let mut parameters = MIMEParameters::new();
    let mut filename = MIMEParameter::new("filename", "\u{65e5}".repeat(10_000).as_bytes());
    filename.charset = Some(String::from("UTF-8"));
    parameters.set(filename.clone());
    let mut text = String::from("attachment");
    parameters.encode(&mut text);
    let read = MIMEDisposition::parse(text.as_bytes()).unwrap();
    assert_eq!(read.parameters.get("filename").map(|parameter| &parameter.value), Some(&filename.value));
    // Reading many sections stays fast (no quadratic grouping): 8,000 parameters in well under a second.
    let mut many = String::from("text/plain");
    for index in 0..8000 {
        many.push_str(&format!("; p{index}=v"));
    }
    let start = std::time::Instant::now();
    assert_eq!(MIMEContentType::parse(many.as_bytes()).unwrap().parameters.entries.len(), 8000);
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn local_time_unknown() {
    // RFC 5322 §3.3: -0000 is a time of UTC of a local time unknown; §4.3: the military zones
    // SHOULD be taken as -0000. Both are written back as -0000.
    let unknown = MailDate::parse(b"Fri, 21 Nov 1997 09:55:06 -0000").unwrap();
    assert!(unknown.zone_unknown && unknown.offset == 0);
    assert_eq!(unknown.format(), "Fri, 21 Nov 1997 09:55:06 -0000");
    let military = MailDate::parse(b"Fri, 21 Nov 1997 09:55:06 A").unwrap();
    assert!(military.zone_unknown);
    assert_eq!(military.format(), "Fri, 21 Nov 1997 09:55:06 -0000");
    let utc = MailDate::parse(b"Fri, 21 Nov 1997 09:55:06 +0000").unwrap();
    assert!(!utc.zone_unknown);
    assert_eq!(utc.format(), "Fri, 21 Nov 1997 09:55:06 +0000");
    assert_eq!(MailDate::parse(b"Fri, 21 Nov 1997 09:55:06 GMT").unwrap(), utc);
}
