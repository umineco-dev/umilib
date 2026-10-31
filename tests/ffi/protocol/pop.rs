//! The C ABI of `umilib::protocol::pop::v3` against the example session of
//! RFC 1939 §10 and the rules of RFC 1939, RFC 2449 and RFC 6856, through the
//! functions C calls.

use std::ptr;

use umilib::ffi::protocol::pop::v3::*;
use umilib::ffi::{Buffer, Status};
use umilib::protocol::pop::v3::{POP3Client, POP3MultiLineReader, POP3MultiLineWriter, POP3Server};

use super::super::Check;

/// A second in the nanoseconds of `now`.
const SECOND: u64 = 1_000_000_000;

/// The contents of an event of the C ABI.
#[derive(Debug)]
struct Event {
    kind: u8,
    command: Vec<u8>,
    response: Vec<u8>,
    data: Vec<u8>,
    error: *const Status,
}

impl Event {
    #[allow(clippy::type_complexity)]
    fn all(
        mut poll: impl FnMut(*mut bool, *mut u8, *mut Buffer, *mut Buffer, *mut Buffer, *mut *const Status) -> *const Status,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        loop {
            let (mut found, mut kind, mut error) = (false, 0u8, ptr::null());
            let (mut command, mut response, mut data) = (Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY);
            Check::ok(poll(&mut found, &mut kind, &mut command, &mut response, &mut data, &mut error));
            let (command, response, data) = unsafe { (command.take(), response.take(), data.take()) };
            if !found {
                return events;
            }
            events.push(Event { kind, command, response, data, error });
        }
    }

    fn client(client: *mut POP3Client) -> Vec<Event> {
        Event::all(|found, kind, command, response, data, error| unsafe {
            umilib_protocol_pop_v3_pop3_client_poll_event(client, found, kind, command, response, data, error)
        })
    }

    fn server(server: *mut POP3Server) -> Vec<Event> {
        Event::all(|found, kind, command, response, data, error| unsafe {
            umilib_protocol_pop_v3_pop3_server_poll_event(server, found, kind, command, response, data, error)
        })
    }
}

fn exchange(client: *mut POP3Client, server: *mut POP3Server) {
    unsafe {
        loop {
            let (mut to_server, mut to_client) = (Buffer::EMPTY, Buffer::EMPTY);
            Check::ok(umilib_protocol_pop_v3_pop3_client_transmit(client, &mut to_server));
            Check::ok(umilib_protocol_pop_v3_pop3_server_transmit(server, &mut to_client));
            let (to_server, to_client) = (to_server.take(), to_client.take());
            if to_server.is_empty() && to_client.is_empty() {
                return;
            }
            Check::ok(umilib_protocol_pop_v3_pop3_server_receive(server, to_server.as_ptr(), to_server.len(), 0));
            Check::ok(umilib_protocol_pop_v3_pop3_client_receive(client, to_client.as_ptr(), to_client.len(), 0));
        }
    }
}

fn config() -> FFIPOP3Config {
    let mut config = FFIPOP3Config::default();
    Check::ok(unsafe { umilib_protocol_pop_v3_pop3_config_default(&mut config) });
    config
}

fn server_config() -> FFIPOP3ServerConfig {
    let mut config = FFIPOP3ServerConfig::default();
    Check::ok(unsafe { umilib_protocol_pop_v3_pop3_server_config_default(&mut config) });
    config
}

fn new_server(settings: FFIPOP3ServerConfig) -> *mut POP3Server {
    let mut server = ptr::null_mut();
    Check::ok(unsafe {
        umilib_protocol_pop_v3_pop3_server_new(
            config(),
            settings,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            false,
            &mut server,
        )
    });
    server
}

/// Sends `line`, and the server tells it; answers it with `answer` and the lines of `data`.
fn round(
    client: *mut POP3Client,
    server: *mut POP3Server,
    line: &str,
    answer: &str,
    data: Option<&[u8]>,
) -> Vec<Event> {
    unsafe {
        Check::ok(umilib_protocol_pop_v3_pop3_client_send(client, line.as_ptr(), line.len(), false, 0));
        exchange(client, server);
        let told = Event::server(server);
        assert_eq!(told.len(), 1, "{line}: {told:?}");
        assert_eq!((told[0].kind, told[0].command.as_slice()), (0, line.as_bytes()));
        Check::ok(umilib_protocol_pop_v3_pop3_server_reply(server, answer.as_ptr(), answer.len(), 0));
        if let Some(data) = data {
            Check::ok(umilib_protocol_pop_v3_pop3_server_send_data(server, data.as_ptr(), data.len()));
            Check::ok(umilib_protocol_pop_v3_pop3_server_end_data(server, 0));
        }
        exchange(client, server);
        let events = Event::client(client);
        assert_eq!(
            (events[0].kind, events[0].command.as_slice(), events[0].response.as_slice()),
            (1, line.as_bytes(), answer.as_bytes())
        );
        events
    }
}

#[test]
fn pop3_lines_and_parts_through_the_c_abi() {
    unsafe {
        // RFC 1939 §3: the default times, an autologout timer of at least 10 minutes.
        assert!(config().autologout >= 600 * SECOND);

        // RFC 2449 §8: a response code of levels after the status.
        let line = b"-ERR [SYS/TEMP] try again";
        let (mut ok, mut code, mut text) = (true, Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_protocol_pop_v3_pop3_response_decode(
            line.as_ptr(),
            line.len(),
            &mut ok,
            &mut code,
            &mut text,
        ));
        assert_eq!((ok, code.take(), text.take()), (false, b"SYS/TEMP".to_vec(), b"try again".to_vec()));
        let mut encoded = Buffer::EMPTY;
        Check::ok(umilib_protocol_pop_v3_pop3_response_encode(
            false,
            b"SYS/TEMP".as_ptr(),
            8,
            b"try again".as_ptr(),
            9,
            &mut encoded,
        ));
        assert_eq!(encoded.take(), line.to_vec());
        Check::ok(umilib_protocol_pop_v3_pop3_response_encode(true, ptr::null(), 0, ptr::null(), 0, &mut encoded));
        assert_eq!(encoded.take(), b"+OK".to_vec());
        // §3: +OK and -ERR in upper case, a space before the text.
        for bad in [&b"+ok fine"[..], b"OK", b"+OKfine", b"-ERR a\rb"] {
            Check::fails(
                umilib_protocol_pop_v3_pop3_response_decode(bad.as_ptr(), bad.len(), &mut ok, &mut code, &mut text),
                "protocol.pop.v3",
                "Syntax",
            );
        }
        Check::fails(
            umilib_protocol_pop_v3_pop3_response_encode(false, b"A]B".as_ptr(), 3, ptr::null(), 0, &mut encoded),
            "protocol.pop.v3",
            "Syntax",
        );

        // §7: the timestamp of a greeting, its angle brackets included.
        let greeting = b"+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>";
        let (mut found, mut timestamp) = (false, Buffer::EMPTY);
        Check::ok(umilib_protocol_pop_v3_pop3_response_timestamp(
            greeting.as_ptr(),
            greeting.len(),
            &mut found,
            &mut timestamp,
        ));
        assert_eq!((found, timestamp.take()), (true, b"<1896.697170952@dbc.mtview.ca.us>".to_vec()));
        Check::ok(umilib_protocol_pop_v3_pop3_response_timestamp(b"+OK ready".as_ptr(), 9, &mut found, &mut timestamp));
        assert!(!found);
        assert!(timestamp.take().is_empty());

        // Commands: keywords of any case, arguments as given (§3).
        let mut normal = Buffer::EMPTY;
        Check::ok(umilib_protocol_pop_v3_pop3_command_normalize(b"retr 1".as_ptr(), 6, false, &mut normal));
        assert_eq!(normal.take(), b"RETR 1".to_vec());
        let mut multi = false;
        for (line, expected) in [
            ("RETR 1", true),
            ("LIST", true),
            ("LIST 1", false),
            ("TOP 1 10", true),
            ("UIDL", true),
            ("STAT", false),
            ("CAPA", true),
        ] {
            Check::ok(umilib_protocol_pop_v3_pop3_command_is_multi_line(line.as_ptr(), line.len(), &mut multi));
            assert_eq!(multi, expected, "{line}");
        }
        for bad in ["RETR", "RETR x", "RETR 0", "DELE -1", "STAT 1"] {
            Check::fails(
                umilib_protocol_pop_v3_pop3_command_normalize(bad.as_ptr(), bad.len(), false, &mut normal),
                "protocol.pop.v3",
                "Syntax",
            );
        }

        // RFC 2449 §6: the CAPA list of its example.
        let list = b"TOP\r\nUSER\r\nSASL CRAM-MD5 KERBEROS_V4\r\nRESP-CODES\r\nLOGIN-DELAY 900\r\nPIPELINING\r\nEXPIRE 60\r\nUIDL\r\nIMPLEMENTATION Shlemazle-Plotz-v302\r\n";
        let mut capabilities = Buffer::EMPTY;
        Check::ok(umilib_protocol_pop_v3_pop3_capabilities_decode(list.as_ptr(), list.len(), &mut capabilities));
        let capabilities = String::from_utf8(capabilities.take()).unwrap();
        assert_eq!(capabilities.lines().nth(2), Some("SASL CRAM-MD5 KERBEROS_V4"));
        assert_eq!(capabilities.lines().count(), 9);

        // §3: multi-line responses, a period added to a line that begins with one.
        let mut writer: *mut POP3MultiLineWriter = ptr::null_mut();
        Check::ok(umilib_protocol_pop_v3_pop3_multi_line_writer_new(&mut writer));
        let (mut first, mut rest) = (Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_protocol_pop_v3_pop3_multi_line_writer_write(writer, b"a\n.b\r".as_ptr(), 5, &mut first));
        Check::ok(umilib_protocol_pop_v3_pop3_multi_line_writer_finish(writer, &mut rest));
        let written = [first.take(), rest.take()].concat();
        assert_eq!(written, b"a\r\n..b\r\n.\r\n".to_vec());
        umilib_protocol_pop_v3_pop3_multi_line_writer_free(writer);
        let mut length = 0u64;
        Check::ok(umilib_protocol_pop_v3_pop3_multi_line_canonical_length(b"a\n.b\r".as_ptr(), 5, &mut length));
        // a CR LF . b CR LF: the added period is not of the message.
        assert_eq!(length, 7);
        let mut reader: *mut POP3MultiLineReader = ptr::null_mut();
        Check::ok(umilib_protocol_pop_v3_pop3_multi_line_reader_new(&mut reader));
        let input = [&written[..], b"+OK next\r\n"].concat();
        let (mut read, mut out, mut end) = (0usize, Buffer::EMPTY, false);
        Check::ok(umilib_protocol_pop_v3_pop3_multi_line_reader_read(
            reader,
            input.as_ptr(),
            input.len(),
            &mut read,
            &mut out,
            &mut end,
        ));
        assert_eq!((read, out.take(), end), (written.len(), b"a\r\n.b\r\n".to_vec(), true));
        umilib_protocol_pop_v3_pop3_multi_line_reader_free(reader);
        umilib_protocol_pop_v3_pop3_multi_line_reader_free(ptr::null_mut());
        umilib_protocol_pop_v3_pop3_multi_line_writer_free(ptr::null_mut());
    }
}

#[cfg(all(umilib_feature = "hash-md-v5", umilib_feature = "secret"))]
#[test]
fn pop3_apop_through_the_c_abi() {
    unsafe {
        // RFC 1939 §7: the example digest of the secret "tanstaaf".
        let timestamp = b"<1896.697170952@dbc.mtview.ca.us>";
        let mut digest = Buffer::EMPTY;
        Check::ok(umilib_protocol_pop_v3_pop3_command_apop_digest(
            timestamp.as_ptr(),
            timestamp.len(),
            b"tanstaaf".as_ptr(),
            8,
            &mut digest,
        ));
        let digest = digest.take();
        assert_eq!(digest, b"c4c9334bac560ecc979e58001b3e22fb".to_vec());
        let mut matches = false;
        Check::ok(umilib_protocol_pop_v3_pop3_command_apop_matches(
            digest.as_ptr(),
            digest.len(),
            timestamp.as_ptr(),
            timestamp.len(),
            b"tanstaaf".as_ptr(),
            8,
            &mut matches,
        ));
        assert!(matches);
        Check::ok(umilib_protocol_pop_v3_pop3_command_apop_matches(
            digest.as_ptr(),
            digest.len(),
            timestamp.as_ptr(),
            timestamp.len(),
            b"tanstaag".as_ptr(),
            8,
            &mut matches,
        ));
        assert!(!matches);
    }
}

#[test]
fn pop3_sessions_of_rfc_1939_section_10_through_the_c_abi() {
    unsafe {
        let mut settings = server_config();
        settings.passwords_require_tls = false;
        let server = new_server(settings);
        let mut client: *mut POP3Client = ptr::null_mut();
        // The passwords of the examples go in the clear; refusing to is the default (RFC 2595 §2.3).
        let mut clear = config();
        assert!(clear.passwords_require_tls);
        clear.passwords_require_tls = false;
        Check::ok(umilib_protocol_pop_v3_pop3_client_new(clear, false, 0, &mut client));

        let greeting = "+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>";
        Check::ok(umilib_protocol_pop_v3_pop3_server_greet(server, greeting.as_ptr(), greeting.len(), 0));
        exchange(client, server);
        let events = Event::client(client);
        assert_eq!((events.len(), events[0].kind, events[0].response.as_slice()), (1, 0, greeting.as_bytes()));
        let mut state = 9u8;
        Check::ok(umilib_protocol_pop_v3_pop3_client_state(client, &mut state));
        assert_eq!(state, 0);

        round(
            client,
            server,
            "APOP mrose c4c9334bac560ecc979e58001b3e22fb",
            "+OK mrose's maildrop has 2 messages (320 octets)",
            None,
        );
        Check::ok(umilib_protocol_pop_v3_pop3_client_state(client, &mut state));
        assert_eq!(state, 1);
        round(client, server, "STAT", "+OK 2 320", None);
        let events = round(client, server, "LIST", "+OK 2 messages (320 octets)", Some(b"1 120\r\n2 200\r\n"));
        let data: Vec<u8> =
            events.iter().filter(|event| event.kind == 2).flat_map(|event| event.data.clone()).collect();
        assert_eq!(data, b"1 120\r\n2 200\r\n".to_vec());
        assert_eq!(events.last().map(|event| event.kind), Some(3));
        let message = b"Subject: x\r\n\r\n.a line of a period\r\n";
        let events = round(client, server, "RETR 1", "+OK 120 octets", Some(message));
        let data: Vec<u8> =
            events.iter().filter(|event| event.kind == 2).flat_map(|event| event.data.clone()).collect();
        assert_eq!(data, message.to_vec());
        round(client, server, "DELE 1", "+OK message 1 deleted", None);
        // A negative response to a multi-line command has no lines.
        let events = round(client, server, "RETR 9", "-ERR no such message", None);
        assert_eq!(events.len(), 1);

        // QUIT in TRANSACTION is told: the server enters UPDATE and answers (§6).
        let events = round(client, server, "QUIT", "+OK dewey POP3 server signing off (maildrop empty)", None);
        assert_eq!(events.last().map(|event| (event.kind, event.error)), Some((6, ptr::null())));
        Check::ok(umilib_protocol_pop_v3_pop3_client_state(client, &mut state));
        assert_eq!(state, 2);
        let mut open = true;
        Check::ok(umilib_protocol_pop_v3_pop3_client_is_open(client, &mut open));
        assert!(!open);
        Check::fails(
            umilib_protocol_pop_v3_pop3_client_send(client, b"NOOP".as_ptr(), 4, false, 0),
            "protocol.pop.v3",
            "Closed",
        );
        umilib_protocol_pop_v3_pop3_client_free(client);
        umilib_protocol_pop_v3_pop3_server_free(server);
        umilib_protocol_pop_v3_pop3_client_free(ptr::null_mut());
        umilib_protocol_pop_v3_pop3_server_free(ptr::null_mut());
    }
}

#[test]
fn pop3_capabilities_rules_and_timeouts_through_the_c_abi() {
    unsafe {
        // Passwords as they are are not taken without TLS by default (RFC 5034 §4).
        let server = new_server(server_config());
        let mut taken = true;
        Check::ok(umilib_protocol_pop_v3_pop3_server_passwords_taken(server, &mut taken));
        assert!(!taken);
        let mut client: *mut POP3Client = ptr::null_mut();
        Check::ok(umilib_protocol_pop_v3_pop3_client_new(config(), false, 0, &mut client));
        Check::ok(umilib_protocol_pop_v3_pop3_server_greet(server, b"+OK ready".as_ptr(), 9, 0));
        exchange(client, server);
        Event::client(client);

        // CAPA is answered by the server itself (RFC 2449 §5).
        let line = "CAPA";
        Check::ok(umilib_protocol_pop_v3_pop3_client_send(client, line.as_ptr(), line.len(), false, 0));
        exchange(client, server);
        assert!(Event::server(server).is_empty());
        let events = Event::client(client);
        assert!(events[0].response.starts_with(b"+OK"));
        let list: Vec<u8> =
            events.iter().filter(|event| event.kind == 2).flat_map(|event| event.data.clone()).collect();
        let mut announced = Buffer::EMPTY;
        Check::ok(umilib_protocol_pop_v3_pop3_server_capabilities(server, &mut announced));
        assert_eq!(list, announced.take());
        for (tag, expected) in [("pipelining", true), ("UIDL", true), ("TOP", true), ("STLS", false), ("SASL", false)] {
            let mut has = false;
            Check::ok(umilib_protocol_pop_v3_pop3_client_has_capability(client, tag.as_ptr(), tag.len(), &mut has));
            assert_eq!(has, expected, "{tag}");
        }
        // STLS was not announced: not sent (RFC 2595 §4).
        Check::fails(
            umilib_protocol_pop_v3_pop3_client_send(client, b"STLS".as_ptr(), 4, false, 0),
            "protocol.pop.v3",
            "State",
        );
        // A command of the TRANSACTION state in AUTHORIZATION is refused by the server itself.
        Check::ok(umilib_protocol_pop_v3_pop3_server_receive(server, b"STAT\r\n".as_ptr(), 6, 0));
        assert!(Event::server(server).is_empty());
        let mut out = Buffer::EMPTY;
        Check::ok(umilib_protocol_pop_v3_pop3_server_transmit(server, &mut out));
        assert!(out.take().starts_with(b"-ERR"));
        umilib_protocol_pop_v3_pop3_client_free(client);

        // §3: the autologout timer closes the connection without a response.
        let (mut found, mut deadline) = (false, 0u64);
        Check::ok(umilib_protocol_pop_v3_pop3_server_poll_timeout(server, &mut found, &mut deadline));
        assert!(found && deadline >= 600 * SECOND);
        Check::ok(umilib_protocol_pop_v3_pop3_server_expire(server, deadline));
        let events = Event::server(server);
        assert_eq!(events.last().map(|event| event.kind), Some(4));
        Check::ok(umilib_protocol_pop_v3_pop3_server_transmit(server, &mut out));
        assert!(out.take().is_empty());
        umilib_protocol_pop_v3_pop3_server_free(server);

        // No response in time closes a client with Timeout.
        let mut client: *mut POP3Client = ptr::null_mut();
        Check::ok(umilib_protocol_pop_v3_pop3_client_new(config(), false, 0, &mut client));
        Check::ok(umilib_protocol_pop_v3_pop3_client_poll_timeout(client, &mut found, &mut deadline));
        Check::ok(umilib_protocol_pop_v3_pop3_client_expire(client, deadline));
        let events = Event::client(client);
        assert_eq!(events.last().map(|event| event.kind), Some(6));
        Check::fails(events.last().unwrap().error, "protocol.pop.v3", "Timeout");
        umilib_protocol_pop_v3_pop3_client_free(client);
    }
}

/// Shutting down: -ERR, of SYS/TEMP where response codes are announced (RFC 3206 §4), then closed;
/// a status line is one line (RFC 1939 §3), so text of a line break is refused.
#[test]
fn pop3_shutdown_through_the_c_abi() {
    unsafe {
        let server = new_server(server_config());
        Check::ok(umilib_protocol_pop_v3_pop3_server_greet(server, b"+OK ready".as_ptr(), 9, 0));
        let mut out = Buffer::EMPTY;
        Check::ok(umilib_protocol_pop_v3_pop3_server_transmit(server, &mut out));
        out.take();
        let injected = b"bye\r\n+OK";
        Check::fails(
            umilib_protocol_pop_v3_pop3_server_shutdown(server, injected.as_ptr(), injected.len()),
            "protocol.pop.v3",
            "Syntax",
        );
        Check::ok(umilib_protocol_pop_v3_pop3_server_transmit(server, &mut out));
        assert!(out.take().is_empty());
        let text = b"shutting down";
        Check::ok(umilib_protocol_pop_v3_pop3_server_shutdown(server, text.as_ptr(), text.len()));
        Check::ok(umilib_protocol_pop_v3_pop3_server_transmit(server, &mut out));
        assert_eq!(out.take(), b"-ERR [SYS/TEMP] shutting down\r\n");
        let mut open = true;
        Check::ok(umilib_protocol_pop_v3_pop3_server_is_open(server, &mut open));
        assert!(!open);
        assert_eq!(Event::server(server).last().map(|event| event.kind), Some(4));
        umilib_protocol_pop_v3_pop3_server_free(server);
    }
}

#[test]
fn pop3_flow_control_through_the_c_abi() {
    unsafe {
        let server = new_server(server_config());
        let mut wants = false;
        Check::ok(umilib_protocol_pop_v3_pop3_server_wants_receive(server, &mut wants));
        assert!(wants);
        Check::fails(umilib_protocol_pop_v3_pop3_server_wants_receive(server, ptr::null_mut()), "ffi", "NullPointer");
        umilib_protocol_pop_v3_pop3_server_free(server);
    }
}
