//! The C ABI of `umilib::protocol::imap::v4` against the examples and rules
//! of RFC 9051, RFC 3501 §5.1.3 and RFC 7888, through the functions C calls.

use std::ffi::CString;
use std::ptr;

use umilib::codec::mail::MailConfig;
use umilib::ffi::protocol::imap::v4::*;
use umilib::ffi::{Buffer, Status};
use umilib::protocol::imap::v4::{IMAPClient, IMAPServer};

use super::super::Check;

/// The conditions of the C ABI.
const OK: u8 = 0;
const NO: u8 = 1;
const BAD: u8 = 2;
const BYE: u8 = 4;

/// The contents of an event of the C ABI.
#[derive(Debug)]
struct Event {
    kind: u8,
    tag: String,
    command: Vec<u8>,
    response: Vec<u8>,
    data: Vec<u8>,
    error: *const Status,
}

impl Event {
    #[allow(clippy::type_complexity)]
    fn all(
        mut poll: impl FnMut(
            *mut bool,
            *mut u8,
            *mut Buffer,
            *mut Buffer,
            *mut Buffer,
            *mut Buffer,
            *mut *const Status,
        ) -> *const Status,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        loop {
            let (mut found, mut kind, mut error) = (false, 0u8, ptr::null());
            let (mut tag, mut command, mut response, mut data) =
                (Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY);
            Check::ok(poll(&mut found, &mut kind, &mut tag, &mut command, &mut response, &mut data, &mut error));
            let (tag, command, response, data) = unsafe { (tag.take(), command.take(), response.take(), data.take()) };
            if !found {
                return events;
            }
            events.push(Event { kind, tag: String::from_utf8(tag).unwrap(), command, response, data, error });
        }
    }

    fn client(client: *mut IMAPClient) -> Vec<Event> {
        Event::all(|found, kind, tag, command, response, data, error| unsafe {
            umilib_protocol_imap_v4_imap_client_poll_event(client, found, kind, tag, command, response, data, error)
        })
    }

    fn server(server: *mut IMAPServer) -> Vec<Event> {
        Event::all(|found, kind, tag, command, response, data, error| unsafe {
            umilib_protocol_imap_v4_imap_server_poll_event(server, found, kind, tag, command, response, data, error)
        })
    }
}

fn exchange(client: *mut IMAPClient, server: *mut IMAPServer) {
    unsafe {
        loop {
            let (mut to_server, mut to_client) = (Buffer::EMPTY, Buffer::EMPTY);
            Check::ok(umilib_protocol_imap_v4_imap_client_transmit(client, &mut to_server));
            Check::ok(umilib_protocol_imap_v4_imap_server_transmit(server, &mut to_client));
            let (to_server, to_client) = (to_server.take(), to_client.take());
            if to_server.is_empty() && to_client.is_empty() {
                return;
            }
            Check::ok(umilib_protocol_imap_v4_imap_server_receive(server, to_server.as_ptr(), to_server.len(), 0));
            Check::ok(umilib_protocol_imap_v4_imap_client_receive(client, to_client.as_ptr(), to_client.len(), 0));
        }
    }
}

fn config() -> FFIIMAPConfig {
    let mut config = FFIIMAPConfig::default();
    Check::ok(unsafe { umilib_protocol_imap_v4_imap_config_default(&mut config) });
    config
}

fn new_server(settings: FFIIMAPServerConfig, mechanisms: &[&str]) -> *mut IMAPServer {
    let names: Vec<CString> = mechanisms.iter().map(|name| CString::new(*name).unwrap()).collect();
    let pointers: Vec<_> = names.iter().map(|name| name.as_ptr().cast()).collect();
    let mut server = ptr::null_mut();
    Check::ok(unsafe {
        umilib_protocol_imap_v4_imap_server_new(
            config(),
            settings,
            pointers.as_ptr(),
            pointers.len(),
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

fn send(client: *mut IMAPClient, body: &[u8]) -> String {
    let mut tag = Buffer::EMPTY;
    Check::ok(unsafe { umilib_protocol_imap_v4_imap_client_send(client, body.as_ptr(), body.len(), 0, &mut tag) });
    String::from_utf8(unsafe { tag.take() }).unwrap()
}

fn respond(server: *mut IMAPServer, line: &[u8]) {
    Check::ok(unsafe { umilib_protocol_imap_v4_imap_server_respond(server, line.as_ptr(), line.len()) });
}

fn complete(server: *mut IMAPServer, condition: u8, code: &str, text: &str) {
    Check::ok(unsafe {
        umilib_protocol_imap_v4_imap_server_complete(
            server,
            condition,
            code.as_ptr(),
            code.len(),
            text.as_ptr(),
            text.len(),
            0,
        )
    });
}

/// The status of the response at `line`: whether tagged, its tag, condition, code and text.
fn status(line: &[u8]) -> Option<(bool, String, u8, String, String)> {
    let (mut is_status, mut tagged, mut condition) = (false, false, 9u8);
    let (mut tag, mut code, mut text) = (Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY);
    Check::ok(unsafe {
        umilib_protocol_imap_v4_imap_response_status(
            line.as_ptr(),
            line.len(),
            &mut is_status,
            &mut tagged,
            &mut tag,
            &mut condition,
            &mut code,
            &mut text,
        )
    });
    let text_of = |mut buffer: Buffer| String::from_utf8(unsafe { buffer.take() }).unwrap();
    let (tag, code, text) = (text_of(tag), text_of(code), text_of(text));
    is_status.then_some((tagged, tag, condition, code, text))
}

#[test]
fn imap_lines_and_parts_through_the_c_abi() {
    unsafe {
        // RFC 9051 §5.4: an autologout timer of at least 30 minutes.
        assert!(config().autologout >= 30 * 60 * 1_000_000_000);

        // Commands: the verb in any case, the tag kept; `UID` and its command are its name (§6.4.9).
        let line = b"a003 uid fetch 1:* (FLAGS UID)";
        let (mut tag, mut name, mut normal) = (Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_protocol_imap_v4_imap_command_normalize(
            line.as_ptr(),
            line.len(),
            &mut tag,
            &mut name,
            &mut normal,
        ));
        assert_eq!(
            (tag.take(), name.take(), normal.take()),
            (b"a003".to_vec(), b"UID FETCH".to_vec(), b"a003 UID FETCH 1:* (FLAGS UID)".to_vec())
        );
        // A literal is part of the logical line (§4.3), as RFC 7888 LITERAL+ writes it too.
        for line in [&b"A1 LOGIN {5}\r\nSMITH {6}\r\nSESAME"[..], b"A1 LOGIN {5+}\r\nSMITH \"SESAME\""] {
            Check::ok(umilib_protocol_imap_v4_imap_command_normalize(
                line.as_ptr(),
                line.len(),
                &mut tag,
                &mut name,
                &mut normal,
            ));
            drop(tag.take());
            assert_eq!(name.take(), b"LOGIN".to_vec());
            assert_eq!(normal.take(), b"A1 LOGIN SMITH SESAME".to_vec());
        }
        for bad in [
            &b"a001"[..],
            b"a+1 NOOP",
            b"a001 LOGIN SMITH",
            b"a001 SELECT",
            b"a001 FETCH x FLAGS",
            b"a001 LOGIN {9}\r\nSMITH SESAME",
        ] {
            Check::fails(
                umilib_protocol_imap_v4_imap_command_normalize(
                    bad.as_ptr(),
                    bad.len(),
                    &mut tag,
                    &mut name,
                    &mut normal,
                ),
                "protocol.imap.v4",
                "Syntax",
            );
        }

        // Responses of RFC 9051 §7.
        for line in [
            &b"* OK [UIDVALIDITY 3857529045] UIDs valid"[..],
            b"* 18 EXISTS",
            b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
            b"* LIST (\\Noselect) \"/\" foo",
            b"* STATUS blurdybloop (MESSAGES 231 UIDNEXT 44292)",
            b"* 12 FETCH (FLAGS (\\Seen) UID 4827313)",
            b"A142 OK [READ-WRITE] SELECT completed",
        ] {
            let mut normal = Buffer::EMPTY;
            Check::ok(umilib_protocol_imap_v4_imap_response_normalize(line.as_ptr(), line.len(), &mut normal));
            assert_eq!(normal.take(), line.to_vec(), "{}", String::from_utf8_lossy(line));
        }
        assert_eq!(
            status(b"A142 OK [READ-WRITE] SELECT completed"),
            Some((true, String::from("A142"), OK, String::from("[READ-WRITE]"), String::from("SELECT completed")))
        );
        assert_eq!(
            status(b"* BYE Autologout; idle for too long"),
            Some((false, String::new(), BYE, String::new(), String::from("Autologout; idle for too long")))
        );
        assert_eq!(status(b"* 18 EXISTS"), None);
        let mut encoded = Buffer::EMPTY;
        Check::ok(umilib_protocol_imap_v4_imap_response_status_encode(
            b"a1".as_ptr(),
            2,
            NO,
            b"[TRYCREATE]".as_ptr(),
            11,
            b"no".as_ptr(),
            2,
            &mut encoded,
        ));
        assert_eq!(encoded.take(), b"a1 NO [TRYCREATE] no".to_vec());
        // §7.1: a tagged response is OK, NO or BAD.
        Check::fails(
            umilib_protocol_imap_v4_imap_response_status_encode(
                b"a1".as_ptr(),
                2,
                BYE,
                ptr::null(),
                0,
                b"x".as_ptr(),
                1,
                &mut encoded,
            ),
            "protocol.imap.v4",
            "Syntax",
        );
        Check::fails(
            umilib_protocol_imap_v4_imap_response_status_encode(
                ptr::null(),
                0,
                9,
                ptr::null(),
                0,
                ptr::null(),
                0,
                &mut encoded,
            ),
            "protocol.imap.v4",
            "UnknownValue",
        );

        // RFC 3501 §5.1.3: the example of modified UTF-7.
        let text = "~peter/mail/台北/日本語";
        let mut utf7 = Buffer::EMPTY;
        Check::ok(umilib_protocol_imap_v4_imap_mailbox_encode_modified_utf7(text.as_ptr(), text.len(), &mut utf7));
        let utf7 = utf7.take();
        assert_eq!(utf7, b"~peter/mail/&U,BTFw-/&ZeVnLIqe-".to_vec());
        let mut decoded = Buffer::EMPTY;
        Check::ok(umilib_protocol_imap_v4_imap_mailbox_decode_modified_utf7(utf7.as_ptr(), utf7.len(), &mut decoded));
        assert_eq!(decoded.take(), text.as_bytes().to_vec());
        Check::fails(
            umilib_protocol_imap_v4_imap_mailbox_decode_modified_utf7(b"&Jjo!".as_ptr(), 5, &mut decoded),
            "protocol.imap.v4",
            "Syntax",
        );

        // §9: sequence sets; `*` is the highest number, the order of a range does not matter.
        let mut resolved = Buffer::EMPTY;
        Check::ok(umilib_protocol_imap_v4_imap_sequence_set_resolve(b"4:2,*,9:7".as_ptr(), 9, 10, &mut resolved));
        assert_eq!(resolved.take(), b"2:4,7:10".to_vec());
        let mut contains = false;
        Check::ok(umilib_protocol_imap_v4_imap_sequence_set_contains(b"2:4".as_ptr(), 3, 3, 10, &mut contains));
        assert!(contains);
        Check::ok(umilib_protocol_imap_v4_imap_sequence_set_contains(b"2:4".as_ptr(), 3, 5, 10, &mut contains));
        assert!(!contains);
        Check::fails(
            umilib_protocol_imap_v4_imap_sequence_set_resolve(b"0".as_ptr(), 1, 10, &mut resolved),
            "protocol.imap.v4",
            "Syntax",
        );

        // §9 date-time: the example of §7.5.2.
        let (mut seconds, mut offset) = (0i64, 0i16);
        let date = b"\"17-Jul-1996 02:44:25 -0700\"";
        Check::ok(umilib_protocol_imap_v4_imap_date_time_parse(date.as_ptr(), date.len(), &mut seconds, &mut offset));
        assert_eq!((seconds, offset), (837_596_665, -420));
        let mut formatted = Buffer::EMPTY;
        Check::ok(umilib_protocol_imap_v4_imap_date_time_format(seconds, offset, &mut formatted));
        assert_eq!(formatted.take(), date.to_vec());

        // The parts of a message a server answers FETCH with (§6.4.5, §7.5.2).
        let message = b"From: Pete <pete@silly.example>\r\nSubject: hi\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nabc\r\n";
        let mail = MailConfig::default();
        let mut envelope = Buffer::EMPTY;
        Check::ok(umilib_protocol_imap_v4_imap_envelope_of_message(
            message.as_ptr(),
            message.len(),
            mail,
            &mut envelope,
        ));
        assert_eq!(envelope.take(), b"(NIL \"hi\" ((\"Pete\" NIL \"pete\" \"silly.example\")) ((\"Pete\" NIL \"pete\" \"silly.example\")) ((\"Pete\" NIL \"pete\" \"silly.example\")) NIL NIL NIL NIL NIL)".to_vec());
        let mut body = Buffer::EMPTY;
        Check::ok(umilib_protocol_imap_v4_imap_body_of_message(
            message.as_ptr(),
            message.len(),
            mail,
            false,
            &mut body,
        ));
        let body = String::from_utf8(body.take()).unwrap();
        assert!(body.starts_with("(\"TEXT\" \"PLAIN\" (\"charset\" \"us-ascii\") NIL NIL \"7BIT\" 5 1"), "{body}");
        let (mut found, mut section) = (false, Buffer::EMPTY);
        let fields = b"[HEADER.FIELDS (SUBJECT)]";
        Check::ok(umilib_protocol_imap_v4_imap_section_extract(
            fields.as_ptr(),
            fields.len(),
            message.as_ptr(),
            message.len(),
            mail,
            &mut found,
            &mut section,
        ));
        assert_eq!((found, section.take()), (true, b"Subject: hi\r\n\r\n".to_vec()));
        Check::ok(umilib_protocol_imap_v4_imap_section_extract(
            b"[2]".as_ptr(),
            3,
            message.as_ptr(),
            message.len(),
            mail,
            &mut found,
            &mut section,
        ));
        assert!(!found);
        drop(section.take());
    }
}

#[test]
fn imap_sessions_through_the_c_abi() {
    unsafe {
        let mut settings = FFIIMAPServerConfig::default();
        Check::ok(umilib_protocol_imap_v4_imap_server_config_default(&mut settings));
        settings.passwords_require_tls = false;
        let server = new_server(settings, &["PLAIN"]);
        let mut client: *mut IMAPClient = ptr::null_mut();
        // The passwords of the examples go in the clear; refusing to is the default (RFC 2595 §2.3).
        let mut clear = config();
        assert!(clear.passwords_require_tls);
        clear.passwords_require_tls = false;
        Check::ok(umilib_protocol_imap_v4_imap_client_new(clear, false, b"a".as_ptr(), 1, 0, &mut client));
        let text = "IMAP4rev2 Service Ready";
        Check::ok(umilib_protocol_imap_v4_imap_server_greet(server, OK, text.as_ptr(), text.len(), 0));
        exchange(client, server);
        let events = Event::client(client);
        assert_eq!((events.len(), events[0].kind), (1, 0));
        // The greeting carries the capabilities (§7.1), which the client takes.
        let mut capabilities = Buffer::EMPTY;
        Check::ok(umilib_protocol_imap_v4_imap_server_capabilities(server, &mut capabilities));
        let capabilities = String::from_utf8(capabilities.take()).unwrap();
        assert!(capabilities.contains("IMAP4rev2") && capabilities.contains("AUTH=PLAIN"));
        // Capability names compare without case (§7.2.2).
        assert_eq!(
            status(&events[0].response).unwrap().3.to_ascii_uppercase(),
            format!("[CAPABILITY {capabilities}]").to_ascii_uppercase()
        );
        let mut has = false;
        Check::ok(umilib_protocol_imap_v4_imap_client_has_capability(client, b"imap4rev2".as_ptr(), 9, &mut has));
        assert!(has);

        // LOGIN of literals (§6.2.3): the client waits for the continuation of each.
        let tag = send(client, b"LOGIN {5}\r\nSMITH {6}\r\nSESAME");
        assert_eq!(tag, "a1");
        exchange(client, server);
        let events = Event::server(server);
        assert_eq!((events.len(), events[0].kind, events[0].tag.as_str()), (1, 0, "a1"));
        assert_eq!(events[0].command, b"a1 LOGIN SMITH SESAME".to_vec());
        complete(server, OK, "", "LOGIN completed");
        exchange(client, server);
        let events = Event::client(client);
        assert_eq!((events[0].kind, events[0].command.as_slice()), (2, &b"a1 LOGIN SMITH SESAME"[..]));
        assert_eq!(status(&events[0].response).map(|status| status.2), Some(OK));
        let mut state = 9u8;
        Check::ok(umilib_protocol_imap_v4_imap_client_state(client, &mut state));
        assert_eq!(state, 1);

        // SELECT (§6.3.2): its untagged responses, then OK, which selects.
        send(client, b"SELECT inbox");
        exchange(client, server);
        assert_eq!(Event::server(server)[0].command, b"a2 SELECT INBOX".to_vec());
        for line in [
            &b"* 18 EXISTS"[..],
            b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
            b"* OK [UIDVALIDITY 3857529045] UIDs valid",
        ] {
            respond(server, line);
        }
        complete(server, OK, "[READ-WRITE]", "SELECT completed");
        exchange(client, server);
        let events = Event::client(client);
        assert_eq!(events.iter().map(|event| event.kind).collect::<Vec<_>>(), [1, 1, 1, 2]);
        assert_eq!(events[0].response, b"* 18 EXISTS".to_vec());
        Check::ok(umilib_protocol_imap_v4_imap_server_state(server, &mut state));
        assert_eq!(state, 2);

        // FETCH of a section: the server sends it as a literal (§7.5.2), the client reads it whole.
        send(client, b"FETCH 12 (BODY[HEADER])");
        exchange(client, server);
        assert_eq!(Event::server(server)[0].command, b"a3 FETCH 12 BODY[HEADER]".to_vec());
        respond(server, b"* 12 FETCH (BODY[HEADER] {14}\r\nSubject: x\r\n\r\n)");
        complete(server, OK, "", "FETCH completed");
        exchange(client, server);
        let events = Event::client(client);
        assert_eq!(events[0].response, b"* 12 FETCH (BODY[HEADER] {14}\r\nSubject: x\r\n\r\n)".to_vec());

        // A command of another state is answered BAD by the server itself (§3).
        send(client, b"NOOP");
        exchange(client, server);
        Event::server(server);
        complete(server, OK, "", "NOOP completed");
        Check::fails(
            umilib_protocol_imap_v4_imap_server_complete(server, OK, ptr::null(), 0, ptr::null(), 0, 0),
            "protocol.imap.v4",
            "State",
        );
        exchange(client, server);
        Event::client(client);

        // LOGOUT is answered by the server itself: BYE, then OK (§6.1.3).
        send(client, b"LOGOUT");
        exchange(client, server);
        assert_eq!(Event::server(server).last().map(|event| event.kind), Some(5));
        let events = Event::client(client);
        assert_eq!(status(&events[0].response).map(|status| status.2), Some(BYE));
        assert!(events.iter().any(|event| event.kind == 2 && event.command == b"a5 LOGOUT"));
        assert_eq!(events.last().map(|event| (event.kind, event.error)), Some((6, ptr::null())));
        let mut open = true;
        Check::ok(umilib_protocol_imap_v4_imap_client_is_open(client, &mut open));
        assert!(!open);
        umilib_protocol_imap_v4_imap_client_free(client);
        umilib_protocol_imap_v4_imap_server_free(server);
        umilib_protocol_imap_v4_imap_client_free(ptr::null_mut());
        umilib_protocol_imap_v4_imap_server_free(ptr::null_mut());
    }
}

#[test]
fn imap_authenticate_idle_and_rules_through_the_c_abi() {
    unsafe {
        let mut settings = FFIIMAPServerConfig::default();
        Check::ok(umilib_protocol_imap_v4_imap_server_config_default(&mut settings));
        let server = new_server(settings, &["PLAIN", "SCRAM-SHA-256"]);
        // RFC 9051 §6.2.3: no password without TLS by default; LOGINDISABLED is announced.
        let mut taken = true;
        Check::ok(umilib_protocol_imap_v4_imap_server_passwords_taken(server, &mut taken));
        assert!(!taken);
        let mut capabilities = Buffer::EMPTY;
        Check::ok(umilib_protocol_imap_v4_imap_server_capabilities(server, &mut capabilities));
        let capabilities = String::from_utf8(capabilities.take()).unwrap();
        assert!(capabilities.contains("LOGINDISABLED"));
        assert!(!capabilities.contains("AUTH=PLAIN") && capabilities.contains("AUTH=SCRAM-SHA-256"));
        let mut client: *mut IMAPClient = ptr::null_mut();
        Check::ok(umilib_protocol_imap_v4_imap_client_new(config(), false, b"t".as_ptr(), 1, 0, &mut client));
        Check::ok(umilib_protocol_imap_v4_imap_server_greet(server, OK, b"ready".as_ptr(), 5, 0));
        exchange(client, server);
        Event::client(client);

        // AUTHENTICATE (§6.2.2): a challenge, a response, cancelled with `*`.
        Check::ok(umilib_protocol_imap_v4_imap_client_send_with_tag(
            client,
            b"x1".as_ptr(),
            2,
            b"AUTHENTICATE SCRAM-SHA-256".as_ptr(),
            26,
            0,
        ));
        exchange(client, server);
        assert_eq!(Event::server(server)[0].tag, "x1");
        Check::ok(umilib_protocol_imap_v4_imap_server_authenticate_challenge(server, ptr::null(), 0, 0));
        exchange(client, server);
        let events = Event::client(client);
        assert_eq!((events[0].kind, events[0].tag.as_str(), events[0].data.as_slice()), (3, "x1", &b""[..]));
        let first = b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
        Check::ok(umilib_protocol_imap_v4_imap_client_authenticate_respond(client, first.as_ptr(), first.len(), 0));
        exchange(client, server);
        let events = Event::server(server);
        assert_eq!((events[0].kind, events[0].data.as_slice()), (1, &first[..]));
        Check::ok(umilib_protocol_imap_v4_imap_server_authenticate_challenge(server, b"r=x".as_ptr(), 3, 0));
        exchange(client, server);
        Event::client(client);
        Check::ok(umilib_protocol_imap_v4_imap_client_authenticate_cancel(client, 0));
        exchange(client, server);
        assert_eq!(Event::server(server)[0].kind, 2);
        let events = Event::client(client);
        assert_eq!(status(&events[0].response).map(|status| status.2), Some(BAD));

        // A plaintext mechanism is not announced without TLS, so the client does not send it, and
        // the server answers it NO [PRIVACYREQUIRED] itself.
        let mut tag = Buffer::EMPTY;
        Check::fails(
            umilib_protocol_imap_v4_imap_client_send(client, b"AUTHENTICATE PLAIN".as_ptr(), 18, 0, &mut tag),
            "protocol.imap.v4",
            "State",
        );
        let line = b"t9 AUTHENTICATE PLAIN\r\n";
        Check::ok(umilib_protocol_imap_v4_imap_server_receive(server, line.as_ptr(), line.len(), 0));
        assert!(Event::server(server).is_empty());
        let mut out = Buffer::EMPTY;
        Check::ok(umilib_protocol_imap_v4_imap_server_transmit(server, &mut out));
        let out = out.take();
        let completed = status(&out[..out.len() - 2]).unwrap();
        assert_eq!((completed.1.as_str(), completed.2, completed.3.as_str()), ("t9", NO, "[PRIVACYREQUIRED]"));
        // Nothing was told, so nothing is to complete.
        Check::fails(
            umilib_protocol_imap_v4_imap_server_complete(server, OK, ptr::null(), 0, ptr::null(), 0, 0),
            "protocol.imap.v4",
            "State",
        );
        umilib_protocol_imap_v4_imap_client_free(client);
        umilib_protocol_imap_v4_imap_server_free(server);

        // §5.4: the autologout timer ends a silent session with BYE.
        let server = new_server(settings, &[]);
        Check::ok(umilib_protocol_imap_v4_imap_server_greet(server, OK, b"ready".as_ptr(), 5, 0));
        let mut out = Buffer::EMPTY;
        Check::ok(umilib_protocol_imap_v4_imap_server_transmit(server, &mut out));
        drop(out.take());
        let (mut found, mut deadline) = (false, 0u64);
        Check::ok(umilib_protocol_imap_v4_imap_server_poll_timeout(server, &mut found, &mut deadline));
        assert!(found);
        Check::ok(umilib_protocol_imap_v4_imap_server_expire(server, deadline));
        Check::ok(umilib_protocol_imap_v4_imap_server_transmit(server, &mut out));
        assert!(out.take().starts_with(b"* BYE"));
        umilib_protocol_imap_v4_imap_server_free(server);
    }
}

#[test]
fn imap_server_state_through_the_c_abi() {
    unsafe {
        let mut settings = FFIIMAPServerConfig::default();
        Check::ok(umilib_protocol_imap_v4_imap_server_config_default(&mut settings));
        let server = new_server(settings, &[]);
        let mut rev2 = true;
        Check::ok(umilib_protocol_imap_v4_imap_server_rev2(server, &mut rev2));
        assert!(!rev2, "IMAP4rev1 is offered too: IMAP4rev2 only once enabled");
        Check::ok(umilib_protocol_imap_v4_imap_server_greet(server, 3, b"ready".as_ptr(), 5, 0));
        let input = b"a1 ENABLE IMAP4rev2\r\n";
        Check::ok(umilib_protocol_imap_v4_imap_server_receive(server, input.as_ptr(), input.len(), 0));
        Check::ok(umilib_protocol_imap_v4_imap_server_rev2(server, &mut rev2));
        assert!(rev2);
        let mut wants = false;
        Check::ok(umilib_protocol_imap_v4_imap_server_wants_receive(server, &mut wants));
        assert!(wants);
        umilib_protocol_imap_v4_imap_server_free(server);
    }
}
