//! The C ABI of `umilib::protocol::smtp` against the rules and examples of
//! RFC 5321, RFC 2034, RFC 3461 and RFC 3030, through the functions C calls.

use std::ffi::CString;
use std::ptr;

use umilib::ffi::protocol::smtp::*;
use umilib::ffi::{Buffer, Status};
use umilib::protocol::smtp::{SMTPClient, SMTPDataReader, SMTPServer};

use super::super::Check;

/// A second in the nanoseconds of `now`.
const SECOND: u64 = 1_000_000_000;

/// The contents of an event of the C ABI.
#[derive(Debug, PartialEq, Eq)]
struct Event {
    kind: u8,
    command: Vec<u8>,
    reply: Vec<u8>,
    data: Vec<u8>,
    last: bool,
    error: *const Status,
}

impl Event {
    /// The events pending of a client, in order.
    fn client(client: *mut SMTPClient) -> Vec<Event> {
        Event::all(|found, kind, command, reply, data, last, error| unsafe {
            umilib_protocol_smtp_smtp_client_poll_event(client, found, kind, command, reply, data, last, error)
        })
    }

    /// The events pending of a server, in order.
    fn server(server: *mut SMTPServer) -> Vec<Event> {
        Event::all(|found, kind, command, reply, data, last, error| unsafe {
            umilib_protocol_smtp_smtp_server_poll_event(server, found, kind, command, reply, data, last, error)
        })
    }

    #[allow(clippy::type_complexity)]
    fn all(
        mut poll: impl FnMut(
            *mut bool,
            *mut u8,
            *mut Buffer,
            *mut Buffer,
            *mut Buffer,
            *mut bool,
            *mut *const Status,
        ) -> *const Status,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        loop {
            let (mut found, mut kind, mut last, mut error) = (false, 0u8, false, ptr::null());
            let (mut command, mut reply, mut data) = (Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY);
            Check::ok(poll(&mut found, &mut kind, &mut command, &mut reply, &mut data, &mut last, &mut error));
            let (command, reply, data) = unsafe { (command.take(), reply.take(), data.take()) };
            if !found {
                assert!(command.is_empty() && reply.is_empty() && data.is_empty() && error.is_null());
                return events;
            }
            events.push(Event { kind, command, reply, data, last, error });
        }
    }
}

/// Moves what each side has to send to the other.
fn exchange(client: *mut SMTPClient, server: *mut SMTPServer, now: u64) {
    unsafe {
        loop {
            let (mut to_server, mut to_client) = (Buffer::EMPTY, Buffer::EMPTY);
            Check::ok(umilib_protocol_smtp_smtp_client_transmit(client, &mut to_server));
            Check::ok(umilib_protocol_smtp_smtp_server_transmit(server, &mut to_client));
            let (to_server, to_client) = (to_server.take(), to_client.take());
            if to_server.is_empty() && to_client.is_empty() {
                return;
            }
            Check::ok(umilib_protocol_smtp_smtp_server_receive(server, to_server.as_ptr(), to_server.len(), now));
            Check::ok(umilib_protocol_smtp_smtp_client_receive(client, to_client.as_ptr(), to_client.len(), now));
        }
    }
}

fn send(client: *mut SMTPClient, line: &str, now: u64) {
    Check::ok(unsafe { umilib_protocol_smtp_smtp_client_send(client, line.as_ptr(), line.len(), false, now) });
}

fn reply(server: *mut SMTPServer, wire: &str, now: u64) {
    Check::ok(unsafe { umilib_protocol_smtp_smtp_server_reply(server, wire.as_ptr(), wire.len(), now) });
}

/// The one command the server tells.
fn command(server: *mut SMTPServer) -> String {
    let events = Event::server(server);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].kind, 0);
    String::from_utf8(events[0].command.clone()).unwrap()
}

/// The one reply the client tells, to the command `line`.
fn replied(client: *mut SMTPClient, line: &str) -> Vec<u8> {
    let events = Event::client(client);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!((events[0].kind, events[0].command.as_slice()), (1, line.as_bytes()));
    events[0].reply.clone()
}

fn server_config() -> FFISMTPServerConfig {
    let mut config = FFISMTPServerConfig::default();
    Check::ok(unsafe { umilib_protocol_smtp_smtp_server_config_default(&mut config) });
    config
}

fn config() -> FFISMTPConfig {
    let mut config = FFISMTPConfig::default();
    Check::ok(unsafe { umilib_protocol_smtp_smtp_config_default(&mut config) });
    config
}

#[test]
fn smtp_configurations_are_of_rfc_5321() {
    let config = config();
    // RFC 5321 §4.5.3.1: the lengths at least, §4.5.3.2: the timeouts at least.
    assert!(config.maximum_command_line >= 512);
    assert!(config.maximum_reply_line >= 512);
    assert!(config.maximum_text_line >= 1000);
    assert!(config.greeting_timeout >= 5 * 60 * SECOND);
    assert!(config.command_timeout >= 5 * 60 * SECOND);
    assert!(config.data_initiation_timeout >= 2 * 60 * SECOND);
    assert!(config.data_termination_timeout >= 10 * 60 * SECOND);
    assert!(config.server_timeout >= 5 * 60 * SECOND);
    // §4.5.3.1.8: a server takes at least 100 recipients.
    assert!(server_config().maximum_recipients >= 100);
}

#[test]
fn smtp_replies_commands_and_parts_through_the_c_abi() {
    unsafe {
        // RFC 5321 §4.2.1: a multiline reply, its code on every line, a hyphen on all but the last.
        let wire = b"250-foo.com greets bar.com\r\n250-8BITMIME\r\n250-SIZE 1000\r\n250 HELP\r\n";
        let (mut code, mut lines) = (0u16, Buffer::EMPTY);
        Check::ok(umilib_protocol_smtp_smtp_reply_decode(wire.as_ptr(), wire.len(), &mut code, &mut lines));
        assert_eq!((code, lines.take()), (250, b"foo.com greets bar.com\n8BITMIME\nSIZE 1000\nHELP".to_vec()));
        let text = b"foo.com greets bar.com\n8BITMIME\nSIZE 1000\nHELP";
        let mut encoded = Buffer::EMPTY;
        Check::ok(umilib_protocol_smtp_smtp_reply_encode(250, text.as_ptr(), text.len(), &mut encoded));
        assert_eq!(encoded.take(), wire.to_vec());
        // §4.2: a code of three digits, of 2 to 5 first.
        Check::fails(
            umilib_protocol_smtp_smtp_reply_encode(650, text.as_ptr(), 4, &mut encoded),
            "protocol.smtp",
            "Syntax",
        );
        for bad in [&b"250 OK\n"[..], b"250-OK\r\n", b"25 OK\r\n", b"250 OK\r\n250 again\r\n", b"250-a\r\n251 b\r\n"] {
            Check::fails(
                umilib_protocol_smtp_smtp_reply_decode(bad.as_ptr(), bad.len(), &mut code, &mut lines),
                "protocol.smtp",
                "Syntax",
            );
        }

        // RFC 5321 §4.1.4: extensions of the reply to EHLO; keywords compare without case.
        let (mut greeting, mut entries) = (Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_protocol_smtp_smtp_extensions_decode(wire.as_ptr(), wire.len(), &mut greeting, &mut entries));
        assert_eq!(greeting.take(), b"foo.com greets bar.com".to_vec());
        assert_eq!(entries.take(), b"8BITMIME\nSIZE 1000\nHELP".to_vec());

        // RFC 2034 §4: the enhanced status code after the reply code.
        let wire = b"550 5.1.1 Mailbox \"nosuchuser\" does not exist\r\n";
        let (mut found, mut class, mut subject, mut detail) = (false, 0u8, 0u16, 0u16);
        Check::ok(umilib_protocol_smtp_smtp_reply_status(
            wire.as_ptr(),
            wire.len(),
            &mut found,
            &mut class,
            &mut subject,
            &mut detail,
        ));
        assert_eq!((found, class, subject, detail), (true, 5, 1, 1));
        // The class of the status is that of the reply (§3).
        let wire = b"250 5.1.1 not of its class\r\n";
        Check::ok(umilib_protocol_smtp_smtp_reply_status(
            wire.as_ptr(),
            wire.len(),
            &mut found,
            &mut class,
            &mut subject,
            &mut detail,
        ));
        assert!(!found);

        // RFC 5321 §4.1.1.2: a command line, its verb in any case.
        let line = b"mail from:<Smith@bar.com> SIZE=500";
        let mut normal = Buffer::EMPTY;
        Check::ok(umilib_protocol_smtp_smtp_command_normalize(line.as_ptr(), line.len(), false, &mut normal));
        assert_eq!(normal.take(), b"MAIL FROM:<Smith@bar.com> SIZE=500".to_vec());
        for bad in [&b"MAIL FROM: Smith@bar.com"[..], b"RCPT TO:<>", b"HELO", b"DATA x"] {
            Check::fails(
                umilib_protocol_smtp_smtp_command_normalize(bad.as_ptr(), bad.len(), false, &mut normal),
                "protocol.smtp",
                "Syntax",
            );
        }
        // RFC 6531 §3.3: UTF-8 in a path only of SMTPUTF8.
        let line = "RCPT TO:<用户@例子.广告>";
        Check::fails(
            umilib_protocol_smtp_smtp_command_normalize(line.as_ptr(), line.len(), false, &mut normal),
            "protocol.smtp",
            "Syntax",
        );
        Check::ok(umilib_protocol_smtp_smtp_command_normalize(line.as_ptr(), line.len(), true, &mut normal));
        assert_eq!(normal.take(), line.as_bytes().to_vec());

        // §4.1.2: a mailbox of a quoted local part.
        let text = b"\"John Doe\"@example.com";
        let (mut local, mut domain) = (Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_protocol_smtp_smtp_mailbox_parse(text.as_ptr(), text.len(), false, &mut local, &mut domain));
        assert_eq!((local.take(), domain.take()), (b"John Doe".to_vec(), b"example.com".to_vec()));
        let mut formatted = Buffer::EMPTY;
        Check::ok(umilib_protocol_smtp_smtp_mailbox_format(
            b"John Doe".as_ptr(),
            8,
            b"example.com".as_ptr(),
            11,
            &mut formatted,
        ));
        assert_eq!(formatted.take(), text.to_vec());

        // RFC 3461 §4: xtext, "+" and "=" and the octets outside 33 to 126 as "+" and two hex digits.
        let data = b"a+b=c d";
        let mut xtext = Buffer::EMPTY;
        Check::ok(umilib_protocol_smtp_smtp_xtext_encode(data.as_ptr(), data.len(), &mut xtext));
        let xtext = xtext.take();
        assert_eq!(xtext, b"a+2Bb+3Dc+20d".to_vec());
        let mut decoded = Buffer::EMPTY;
        Check::ok(umilib_protocol_smtp_smtp_xtext_decode(xtext.as_ptr(), xtext.len(), &mut decoded));
        assert_eq!(decoded.take(), data.to_vec());
        Check::fails(
            umilib_protocol_smtp_smtp_xtext_decode(b"a+2".as_ptr(), 3, &mut decoded),
            "protocol.smtp",
            "Syntax",
        );

        // §4.5.2: a period at the start of a line is doubled, and CRLF.CRLF ends the data.
        let message = b"Subject: x\r\n\r\n.hidden\r\nlast";
        let mut data = Buffer::EMPTY;
        let mut rejected = Buffer::EMPTY;
        Check::ok(umilib_protocol_smtp_smtp_data_encode(message.as_ptr(), message.len(), 1000, &mut data));
        let data = data.take();
        assert_eq!(data, b"Subject: x\r\n\r\n..hidden\r\nlast\r\n.\r\n".to_vec());
        // A CR or an LF alone is not of the data (§2.3.8).
        Check::fails(
            umilib_protocol_smtp_smtp_data_encode(b"a\nb".as_ptr(), 3, 1000, &mut rejected),
            "protocol.smtp",
            "Content",
        );

        // The reader takes the data back, and stops at its end.
        let mut reader: *mut SMTPDataReader = ptr::null_mut();
        Check::ok(umilib_protocol_smtp_smtp_data_reader_new(1 << 20, 1000, &mut reader));
        let input = [&data[..], b"QUIT\r\n"].concat();
        let (mut read, mut out, mut end) = (0usize, Buffer::EMPTY, false);
        Check::ok(umilib_protocol_smtp_smtp_data_reader_read(
            reader,
            input.as_ptr(),
            10,
            &mut read,
            &mut out,
            &mut end,
        ));
        let mut taken = out.take();
        assert_eq!((read, end), (10, false));
        Check::ok(umilib_protocol_smtp_smtp_data_reader_read(
            reader,
            input[10..].as_ptr(),
            input.len() - 10,
            &mut read,
            &mut out,
            &mut end,
        ));
        taken.extend(out.take());
        assert_eq!((10 + read, end), (data.len(), true));
        assert_eq!(taken, b"Subject: x\r\n\r\n.hidden\r\nlast\r\n".to_vec());
        let mut error = ptr::null();
        Check::ok(umilib_protocol_smtp_smtp_data_reader_error(reader, &mut error));
        assert!(error.is_null());
        umilib_protocol_smtp_smtp_data_reader_free(reader);

        // A bare LF is told after the end, so the server can answer 550.
        Check::ok(umilib_protocol_smtp_smtp_data_reader_new(1 << 20, 1000, &mut reader));
        let input = b"a\nb\r\n.\r\n";
        Check::ok(umilib_protocol_smtp_smtp_data_reader_read(
            reader,
            input.as_ptr(),
            input.len(),
            &mut read,
            &mut out,
            &mut end,
        ));
        drop(out.take());
        assert!(end);
        Check::ok(umilib_protocol_smtp_smtp_data_reader_error(reader, &mut error));
        Check::fails(error, "protocol.smtp", "Content");
        umilib_protocol_smtp_smtp_data_reader_free(reader);
        umilib_protocol_smtp_smtp_data_reader_free(ptr::null_mut());
    }
}

#[test]
fn smtp_sessions_through_the_c_abi() {
    unsafe {
        let domain = b"foo.com";
        let mechanisms = [CString::new("PLAIN").unwrap()];
        let mechanism_pointers: Vec<_> = mechanisms.iter().map(|name| name.as_ptr().cast()).collect();
        let mut settings = server_config();
        settings.passwords_require_tls = false;
        let mut server: *mut SMTPServer = ptr::null_mut();
        Check::ok(umilib_protocol_smtp_smtp_server_new(
            config(),
            settings,
            domain.as_ptr(),
            domain.len(),
            mechanism_pointers.as_ptr(),
            mechanism_pointers.len(),
            mechanism_pointers.as_ptr(),
            mechanism_pointers.len(),
            ptr::null(),
            0,
            false,
            &mut server,
        ));
        let mut client: *mut SMTPClient = ptr::null_mut();
        // The passwords of the examples go in the clear; refusing to is the default (RFC 2595 §2.3).
        let mut clear = config();
        assert!(clear.passwords_require_tls);
        clear.passwords_require_tls = false;
        Check::ok(umilib_protocol_smtp_smtp_client_new(clear, false, 0, &mut client));
        // The client waits for the greeting (RFC 5321 §4.5.3.2.1).
        let (mut found, mut deadline) = (false, 0u64);
        Check::ok(umilib_protocol_smtp_smtp_client_poll_timeout(client, &mut found, &mut deadline));
        assert!(found && deadline >= 5 * 60 * SECOND);

        // RFC 5321 appendix D.1, the server foo.com and the client bar.com.
        let mut greeting = Buffer::EMPTY;
        Check::ok(umilib_protocol_smtp_smtp_server_greeting(server, &mut greeting));
        let greeting = greeting.take();
        assert!(greeting.starts_with(b"220 foo.com"));
        Check::ok(umilib_protocol_smtp_smtp_server_greet(server, greeting.as_ptr(), greeting.len(), 0));
        exchange(client, server, 0);
        let events = Event::client(client);
        assert_eq!((events.len(), events[0].kind, &events[0].reply), (1, 0, &greeting));

        send(client, "EHLO bar.com", 0);
        exchange(client, server, 0);
        assert_eq!(command(server), "EHLO bar.com");
        reply(server, "250 foo.com greets bar.com\r\n", 0);
        exchange(client, server, 0);
        // The server lists its extensions after the line given.
        let wire = replied(client, "EHLO bar.com");
        assert!(wire.starts_with(b"250-foo.com greets bar.com\r\n"));
        let mut extensions = Buffer::EMPTY;
        Check::ok(umilib_protocol_smtp_smtp_server_extensions(server, &mut extensions));
        let extensions = extensions.take();
        assert!(extensions.ends_with(&wire[wire.iter().position(|byte| *byte == b'\n').unwrap() + 1..]));
        for (keyword, advertised) in
            [("8bitmime", true), ("PIPELINING", true), ("AUTH", true), ("STARTTLS", false), ("X-NONE", false)]
        {
            let mut has = false;
            Check::ok(umilib_protocol_smtp_smtp_client_has_extension(
                client,
                keyword.as_ptr(),
                keyword.len(),
                &mut has,
            ));
            assert_eq!(has, advertised, "{keyword}");
        }

        // An unadvertised extension is not sent (RFC 5321 §2.2.1).
        let line = "STARTTLS";
        Check::fails(
            umilib_protocol_smtp_smtp_client_send(client, line.as_ptr(), line.len(), false, 0),
            "protocol.smtp",
            "State",
        );

        // RFC 4954 §4: an initial response, its challenge and the answer.
        send(client, "AUTH PLAIN", 0);
        exchange(client, server, 0);
        assert_eq!(command(server), "AUTH PLAIN");
        Check::ok(umilib_protocol_smtp_smtp_server_auth_challenge(server, ptr::null(), 0, 0));
        exchange(client, server, 0);
        let events = Event::client(client);
        assert_eq!((events.len(), events[0].kind, events[0].data.as_slice()), (1, 3, &b""[..]));
        let response = b"\0tim\0tanstaaftanstaaf";
        Check::ok(umilib_protocol_smtp_smtp_client_auth_respond(client, response.as_ptr(), response.len(), 0));
        exchange(client, server, 0);
        let events = Event::server(server);
        assert_eq!((events.len(), events[0].kind, events[0].data.as_slice()), (1, 4, &response[..]));
        reply(server, "235 2.7.0 Authentication successful\r\n", 0);
        exchange(client, server, 0);
        assert!(replied(client, "AUTH PLAIN").starts_with(b"235 "));

        for (line, wire) in [
            ("MAIL FROM:<Smith@bar.com>", "250 OK\r\n"),
            ("RCPT TO:<Jones@foo.com>", "250 OK\r\n"),
            ("RCPT TO:<Green@foo.com>", "550 No such user here\r\n"),
            ("RCPT TO:<Brown@foo.com>", "250 OK\r\n"),
            ("DATA", "354 Start mail input; end with <CRLF>.<CRLF>\r\n"),
        ] {
            send(client, line, 0);
            exchange(client, server, 0);
            assert_eq!(command(server), line);
            reply(server, wire, 0);
            exchange(client, server, 0);
            let told = replied(client, line);
            // RFC 2034 §3: the server writes a status code of its class where the reply has none.
            assert_eq!(told[..4], wire.as_bytes()[..4]);
            if !wire.starts_with('3') {
                assert_eq!(told[4..10], *format!("{}.0.0 ", &wire[..1]).as_bytes(), "{line}");
            }
        }
        let message = b"Blah blah blah...\r\n...etc. etc. etc.";
        Check::ok(umilib_protocol_smtp_smtp_client_send_data(client, message.as_ptr(), message.len(), 0));
        exchange(client, server, 0);
        let events = Event::server(server);
        let data: Vec<u8> =
            events.iter().filter(|event| event.kind == 1).flat_map(|event| event.data.clone()).collect();
        assert_eq!(data, b"Blah blah blah...\r\n...etc. etc. etc.\r\n".to_vec());
        assert_eq!(events.last().map(|event| (event.kind, event.last)), Some((2, true)));
        reply(server, "250 OK\r\n", 0);
        exchange(client, server, 0);
        let events = Event::client(client);
        assert_eq!((events.len(), events[0].kind), (1, 2));
        assert!(events[0].reply.starts_with(b"250 2.0.0 OK"));

        // QUIT is answered by the server itself (§4.1.1.10), and both close.
        send(client, "QUIT", 0);
        exchange(client, server, 0);
        let events = Event::server(server);
        assert_eq!(events.last().map(|event| (event.kind, event.error)), Some((8, ptr::null())));
        let events = Event::client(client);
        assert!(events[0].reply.starts_with(b"221 "));
        assert_eq!(events.last().map(|event| (event.kind, event.error)), Some((5, ptr::null())));
        let mut open = true;
        Check::ok(umilib_protocol_smtp_smtp_client_is_open(client, &mut open));
        assert!(!open);
        Check::ok(umilib_protocol_smtp_smtp_server_is_open(server, &mut open));
        assert!(!open);
        Check::fails(
            umilib_protocol_smtp_smtp_client_send(client, "NOOP".as_ptr(), 4, false, 0),
            "protocol.smtp",
            "Closed",
        );
        umilib_protocol_smtp_smtp_client_free(client);
        umilib_protocol_smtp_smtp_server_free(server);
        umilib_protocol_smtp_smtp_client_free(ptr::null_mut());
        umilib_protocol_smtp_smtp_server_free(ptr::null_mut());
    }
}

#[test]
fn smtp_timeouts_and_shutdowns_through_the_c_abi() {
    unsafe {
        let mut client: *mut SMTPClient = ptr::null_mut();
        let mut config = config();
        config.greeting_timeout = 10 * SECOND;
        Check::ok(umilib_protocol_smtp_smtp_client_new(config, false, 0, &mut client));
        Check::ok(umilib_protocol_smtp_smtp_client_expire(client, 9 * SECOND));
        assert!(Event::client(client).is_empty());
        // RFC 5321 §4.5.3.2: no greeting in its time closes the connection with a timeout.
        Check::ok(umilib_protocol_smtp_smtp_client_expire(client, 10 * SECOND));
        let events = Event::client(client);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, 5);
        Check::fails(events[0].error, "protocol.smtp", "Timeout");
        umilib_protocol_smtp_smtp_client_free(client);

        // A server shuts down with 421 (§3.8).
        let mut server: *mut SMTPServer = ptr::null_mut();
        Check::ok(umilib_protocol_smtp_smtp_server_new(
            config,
            server_config(),
            b"foo.com".as_ptr(),
            7,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            false,
            &mut server,
        ));
        // RFC 5321 §4.2: text of a line break would be a reply of its own.
        let injected = "bye\r\n250 OK";
        Check::fails(
            umilib_protocol_smtp_smtp_server_shutdown(server, injected.as_ptr(), injected.len()),
            "protocol.smtp",
            "Syntax",
        );
        let text = "Service not available";
        Check::ok(umilib_protocol_smtp_smtp_server_shutdown(server, text.as_ptr(), text.len()));
        let mut out = Buffer::EMPTY;
        Check::ok(umilib_protocol_smtp_smtp_server_transmit(server, &mut out));
        assert!(out.take().starts_with(b"421 "));
        let mut open = true;
        Check::ok(umilib_protocol_smtp_smtp_server_is_open(server, &mut open));
        assert!(!open);
        umilib_protocol_smtp_smtp_server_free(server);

        // An array of text must not be null where it has strings.
        Check::fails(
            umilib_protocol_smtp_smtp_server_new(
                config,
                server_config(),
                b"foo.com".as_ptr(),
                7,
                ptr::null(),
                1,
                ptr::null(),
                0,
                ptr::null(),
                0,
                false,
                &mut server,
            ),
            "ffi",
            "NullPointer",
        );
    }
}

#[cfg(all(umilib_feature = "protocol-dns", umilib_feature = "hash-sha-v2"))]
#[test]
fn smtp_mail_exchangers_through_the_c_abi() {
    use umilib::ffi::crypto::random::hmac_drbg;
    use umilib::ffi::protocol::smtp::route::umilib_protocol_smtp_smtp_mail_exchanger_order;

    unsafe {
        let hash = b"umilib_hash_sha_v2_SHA256";
        let kind = b"umilib_crypto_random_HMACDRBG";
        let mut state = ptr::null_mut();
        Check::ok(hmac_drbg::new(
            hash.as_ptr(),
            hash.len(),
            [7u8; 32].as_ptr(),
            32,
            [8u8; 16].as_ptr(),
            16,
            ptr::null(),
            0,
            &mut state,
        ));
        let order = |domain: &str, records: &str, local: &[&str]| -> Result<Vec<String>, *const Status> {
            let local: Vec<CString> = local.iter().map(|name| CString::new(*name).unwrap()).collect();
            let pointers: Vec<_> = local.iter().map(|name| name.as_ptr().cast()).collect();
            let mut out = Buffer::EMPTY;
            let status = umilib_protocol_smtp_smtp_mail_exchanger_order(
                domain.as_ptr(),
                domain.len(),
                records.as_ptr(),
                records.len(),
                pointers.as_ptr(),
                pointers.len(),
                state.cast(),
                kind.as_ptr(),
                kind.len(),
                &mut out,
            );
            let text = String::from_utf8(out.take()).unwrap();
            match status.is_null() {
                true => Ok(text.lines().map(String::from).collect()),
                false => Err(status),
            }
        };
        let records = "example.com. 300 IN MX 20 b.example.com.\n\
                       example.com. 300 IN MX 10 a1.example.com.\n\
                       example.com. 300 IN MX 10 a2.example.com.\n\
                       example.com. 300 IN MX 30 c.example.com.\n\
                       other.com. 300 IN MX 5 x.other.com.\n";
        // RFC 5321 §5.1: the lowest preference first, one preference in a random order.
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..32 {
            let hosts = order("example.com.", records, &[]).unwrap();
            assert_eq!(hosts.len(), 4);
            let mut first: Vec<&str> = hosts[..2].iter().map(String::as_str).collect();
            seen.insert(first.join(","));
            first.sort();
            assert_eq!(first, ["10 a1.example.com.", "10 a2.example.com."]);
            assert_eq!(hosts[2..], ["20 b.example.com.", "30 c.example.com."]);
        }
        assert_eq!(seen.len(), 2, "both orders of one preference are drawn");
        // This host as an MX: it and every host not of a lower preference are removed.
        assert_eq!(order("example.com.", records, &["b.example.com."]).unwrap().len(), 2);
        Check::fails(order("example.com.", records, &["a2.example.com."]).unwrap_err(), "protocol.smtp", "NoMail");
        // No MX: the domain itself, of preference 0.
        assert_eq!(order("none.com.", records, &[]).unwrap(), ["0 none.com."]);
        // RFC 7505: the null MX alone means the domain takes no mail.
        Check::fails(order("null.com.", "null.com. 300 IN MX 0 .\n", &[]).unwrap_err(), "protocol.smtp", "NoMail");
        hmac_drbg::free(state);
    }
}

#[test]
fn smtp_flow_control_and_auth_failures_through_the_c_abi() {
    unsafe {
        let mechanisms = [CString::new("SCRAM-SHA-256").unwrap()];
        let pointers: Vec<_> = mechanisms.iter().map(|name| name.as_ptr().cast()).collect();
        let mut server: *mut SMTPServer = ptr::null_mut();
        Check::ok(umilib_protocol_smtp_smtp_server_new(
            config(),
            server_config(),
            b"mx".as_ptr(),
            2,
            pointers.as_ptr(),
            1,
            ptr::null(),
            0,
            ptr::null(),
            0,
            false,
            &mut server,
        ));
        let mut greeting = Buffer::EMPTY;
        Check::ok(umilib_protocol_smtp_smtp_server_greeting(server, &mut greeting));
        let greeting = greeting.take();
        Check::ok(umilib_protocol_smtp_smtp_server_greet(server, greeting.as_ptr(), greeting.len(), 0));
        let mut wants = false;
        Check::ok(umilib_protocol_smtp_smtp_server_wants_receive(server, &mut wants));
        assert!(wants);
        let input = b"EHLO c\r\n";
        Check::ok(umilib_protocol_smtp_smtp_server_receive(server, input.as_ptr(), input.len(), 0));
        Event::server(server);
        reply(server, "250 mx\r\n", 0);
        // A command waits for its answer: what is pipelined behind it is held, up to maximum_buffered.
        let input = b"AUTH SCRAM-SHA-256\r\n";
        Check::ok(umilib_protocol_smtp_smtp_server_receive(server, input.as_ptr(), input.len(), 0));
        Event::server(server);
        let flood = vec![b'x'; config().maximum_buffered];
        Check::ok(umilib_protocol_smtp_smtp_server_receive(server, flood.as_ptr(), flood.len(), 0));
        Check::ok(umilib_protocol_smtp_smtp_server_wants_receive(server, &mut wants));
        assert!(!wants);
        umilib_protocol_smtp_smtp_server_free(server);

        // A response of AUTH that is not base64 is told as kind 9, AuthFailed.
        let mut server: *mut SMTPServer = ptr::null_mut();
        Check::ok(umilib_protocol_smtp_smtp_server_new(
            config(),
            server_config(),
            b"mx".as_ptr(),
            2,
            pointers.as_ptr(),
            1,
            ptr::null(),
            0,
            ptr::null(),
            0,
            false,
            &mut server,
        ));
        Check::ok(umilib_protocol_smtp_smtp_server_greet(server, greeting.as_ptr(), greeting.len(), 0));
        let input = b"EHLO c\r\n";
        Check::ok(umilib_protocol_smtp_smtp_server_receive(server, input.as_ptr(), input.len(), 0));
        Event::server(server);
        reply(server, "250 mx\r\n", 0);
        let input = b"AUTH SCRAM-SHA-256\r\n";
        Check::ok(umilib_protocol_smtp_smtp_server_receive(server, input.as_ptr(), input.len(), 0));
        Event::server(server);
        Check::ok(umilib_protocol_smtp_smtp_server_auth_challenge(server, ptr::null(), 0, 0));
        let input = b"!!!\r\n";
        Check::ok(umilib_protocol_smtp_smtp_server_receive(server, input.as_ptr(), input.len(), 0));
        assert_eq!(Event::server(server).iter().map(|event| event.kind).collect::<Vec<_>>(), [9]);
        // A null output loses no event: the call fails before taking it.
        let input = b"VRFY tim\r\n";
        Check::ok(umilib_protocol_smtp_smtp_server_receive(server, input.as_ptr(), input.len(), 0));
        let (mut found, mut kind, mut last, mut error) = (false, 0u8, false, ptr::null());
        let (mut reply_buffer, mut data) = (Buffer::EMPTY, Buffer::EMPTY);
        Check::fails(
            umilib_protocol_smtp_smtp_server_poll_event(
                server,
                &mut found,
                &mut kind,
                ptr::null_mut(),
                &mut reply_buffer,
                &mut data,
                &mut last,
                &mut error,
            ),
            "ffi",
            "NullPointer",
        );
        let events = Event::server(server);
        assert_eq!((events.len(), events[0].kind, events[0].command.as_slice()), (1, 0, &b"VRFY tim"[..]));
        umilib_protocol_smtp_smtp_server_free(server);
    }
}
