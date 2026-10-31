//! The C ABI of `umilib::protocol::ftp` against the examples and rules of
//! RFC 959, RFC 2389, RFC 2428, RFC 2577 and RFC 3659, through the functions
//! C calls.

use std::ptr;

use umilib::ffi::protocol::ftp::*;
use umilib::ffi::{Buffer, Status};
use umilib::protocol::ftp::{FTPClient, FTPServer};

use super::super::Check;

/// The contents of an event of the C ABI.
#[derive(Debug)]
struct Event {
    kind: u8,
    command: Vec<u8>,
    reply: Vec<u8>,
    error: *const Status,
}

impl Event {
    #[allow(clippy::type_complexity)]
    fn all(
        mut poll: impl FnMut(*mut bool, *mut u8, *mut Buffer, *mut Buffer, *mut *const Status) -> *const Status,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        loop {
            let (mut found, mut kind, mut error) = (false, 0u8, ptr::null());
            let (mut command, mut reply) = (Buffer::EMPTY, Buffer::EMPTY);
            Check::ok(poll(&mut found, &mut kind, &mut command, &mut reply, &mut error));
            let (command, reply) = unsafe { (command.take(), reply.take()) };
            if !found {
                return events;
            }
            events.push(Event { kind, command, reply, error });
        }
    }

    fn client(client: *mut FTPClient) -> Vec<Event> {
        Event::all(|found, kind, command, reply, error| unsafe {
            umilib_protocol_ftp_ftp_client_poll_event(client, found, kind, command, reply, error)
        })
    }

    fn server(server: *mut FTPServer) -> Vec<Event> {
        Event::all(|found, kind, command, reply, error| unsafe {
            umilib_protocol_ftp_ftp_server_poll_event(server, found, kind, command, reply, error)
        })
    }
}

fn exchange(client: *mut FTPClient, server: *mut FTPServer) {
    unsafe {
        loop {
            let (mut to_server, mut to_client) = (Buffer::EMPTY, Buffer::EMPTY);
            Check::ok(umilib_protocol_ftp_ftp_client_transmit(client, &mut to_server));
            Check::ok(umilib_protocol_ftp_ftp_server_transmit(server, &mut to_client));
            let (to_server, to_client) = (to_server.take(), to_client.take());
            if to_server.is_empty() && to_client.is_empty() {
                return;
            }
            Check::ok(umilib_protocol_ftp_ftp_server_receive(server, to_server.as_ptr(), to_server.len(), 0));
            Check::ok(umilib_protocol_ftp_ftp_client_receive(client, to_client.as_ptr(), to_client.len(), 0));
        }
    }
}

fn config() -> FFIFTPConfig {
    let mut config = FFIFTPConfig::default();
    Check::ok(unsafe { umilib_protocol_ftp_ftp_config_default(&mut config) });
    config
}

fn new_server(peer: &[u8]) -> *mut FTPServer {
    let mut settings = FFIFTPServerConfig::default();
    Check::ok(unsafe { umilib_protocol_ftp_ftp_server_config_default(&mut settings) });
    let system = "UNIX Type: L8";
    let mut server = ptr::null_mut();
    Check::ok(unsafe {
        umilib_protocol_ftp_ftp_server_new(
            config(),
            settings,
            system.as_ptr(),
            system.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            peer.as_ptr(),
            peer.len(),
            false,
            &mut server,
        )
    });
    server
}

fn address(octets: &[u8], port: u16) -> FFIFTPDataAddress {
    let mut address = FFIFTPDataAddress { port, length: octets.len() as u8, ..FFIFTPDataAddress::default() };
    address.octets[..octets.len()].copy_from_slice(octets);
    address
}

/// Sends `line`; the server tells it and answers with `replies`; the client's events.
fn round(client: *mut FTPClient, server: *mut FTPServer, line: &str, replies: &[&str]) -> Vec<Event> {
    unsafe {
        Check::ok(umilib_protocol_ftp_ftp_client_send(client, line.as_ptr(), line.len(), 0));
        exchange(client, server);
        let told = Event::server(server);
        assert_eq!(told.len(), 1, "{line}: {told:?}");
        assert_eq!((told[0].kind, told[0].command.as_slice()), (0, line.as_bytes()));
        for reply in replies {
            Check::ok(umilib_protocol_ftp_ftp_server_reply(server, reply.as_ptr(), reply.len(), 0));
        }
        exchange(client, server);
        Event::client(client)
    }
}

#[test]
fn ftp_lines_and_parts_through_the_c_abi() {
    unsafe {
        // RFC 959 §4.2: a multi-line reply; a line of the text beginning with digits is padded.
        let wire = b"211-Features:\r\n MDTM\r\n SIZE\r\n REST STREAM\r\n211 End\r\n";
        let (mut code, mut lines) = (0u16, Buffer::EMPTY);
        Check::ok(umilib_protocol_ftp_ftp_reply_decode(wire.as_ptr(), wire.len(), &mut code, &mut lines));
        assert_eq!((code, lines.take()), (211, b"Features:\n MDTM\n SIZE\n REST STREAM\nEnd".to_vec()));
        let mut encoded = Buffer::EMPTY;
        let text = b"a\n123 b\nc";
        Check::ok(umilib_protocol_ftp_ftp_reply_encode(214, text.as_ptr(), text.len(), &mut encoded));
        assert_eq!(encoded.take(), b"214-a\r\n 123 b\r\n214 c\r\n".to_vec());
        // §4.2.1: a code of a first digit of 1 to 5 and a second of 0 to 5.
        Check::fails(
            umilib_protocol_ftp_ftp_reply_encode(260, b"x".as_ptr(), 1, &mut encoded),
            "protocol.ftp",
            "Syntax",
        );
        // RFC 2389 §3.2: the features of the reply to FEAT.
        let mut features = Buffer::EMPTY;
        Check::ok(umilib_protocol_ftp_ftp_features_decode(wire.as_ptr(), wire.len(), &mut features));
        assert_eq!(features.take(), b"MDTM\nSIZE\nREST STREAM".to_vec());

        // RFC 959 Appendix II: the pathname of 257, its quotes doubled.
        let mut reply = Buffer::EMPTY;
        Check::ok(umilib_protocol_ftp_ftp_reply_with_pathname(
            b"/usr/dm/\"q\"".as_ptr(),
            11,
            b"created".as_ptr(),
            7,
            &mut reply,
        ));
        let reply = reply.take();
        assert_eq!(reply, b"257 \"/usr/dm/\"\"q\"\"\" created\r\n".to_vec());
        let (mut found, mut pathname) = (false, Buffer::EMPTY);
        Check::ok(umilib_protocol_ftp_ftp_reply_pathname(reply.as_ptr(), reply.len(), &mut found, &mut pathname));
        assert_eq!((found, pathname.take()), (true, b"/usr/dm/\"q\"".to_vec()));

        // Commands: the verb in any case (§5.3.1); RETR, STOR, LIST and the like transfer.
        let (mut transfers, mut normal) = (false, Buffer::EMPTY);
        for (line, expected, transferring) in [
            ("retr a.txt", "RETR a.txt", true),
            ("type I", "TYPE I", false),
            ("LIST", "LIST", true),
            ("cwd /pub", "CWD /pub", false),
        ] {
            Check::ok(umilib_protocol_ftp_ftp_command_normalize(
                line.as_ptr(),
                line.len(),
                &mut transfers,
                &mut normal,
            ));
            assert_eq!((normal.take(), transfers), (expected.as_bytes().to_vec(), transferring), "{line}");
        }
        Check::fails(
            umilib_protocol_ftp_ftp_command_normalize(b"PORT 1,2,3".as_ptr(), 10, &mut transfers, &mut normal),
            "protocol.ftp",
            "Syntax",
        );

        // §4.1.2: PORT and the reply to PASV, h1,h2,h3,h4,p1,p2.
        let mut parsed = FFIFTPDataAddress::default();
        Check::ok(umilib_protocol_ftp_ftp_data_address_parse_port(b"192,168,1,2,7,138".as_ptr(), 17, &mut parsed));
        assert_eq!(parsed, address(&[192, 168, 1, 2], 1930));
        let mut text = Buffer::EMPTY;
        Check::ok(umilib_protocol_ftp_ftp_data_address_format_port(parsed, &mut text));
        assert_eq!(text.take(), b"192,168,1,2,7,138".to_vec());
        let pasv = b"227 Entering Passive Mode (192,168,1,2,7,138)\r\n";
        Check::ok(umilib_protocol_ftp_ftp_data_address_from_pasv(pasv.as_ptr(), pasv.len(), &mut parsed));
        assert_eq!(parsed, address(&[192, 168, 1, 2], 1930));
        let mut wire = Buffer::EMPTY;
        Check::ok(umilib_protocol_ftp_ftp_data_address_pasv_reply(parsed, &mut wire));
        assert!(wire.take().starts_with(b"227 "));
        // RFC 2428 §2 and §3: EPRT of IPv6 and the reply to EPSV of a port alone.
        let eprt = b"|2|1080::8:800:200C:417A|5282|";
        Check::ok(umilib_protocol_ftp_ftp_data_address_parse_eprt(eprt.as_ptr(), eprt.len(), &mut parsed));
        assert_eq!(parsed, address(&[0x10, 0x80, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0, 0x20, 0x0c, 0x41, 0x7a], 5282));
        Check::ok(umilib_protocol_ftp_ftp_data_address_format_eprt(parsed, &mut text));
        assert_eq!(text.take().to_ascii_lowercase(), b"|2|1080::8:800:200c:417a|5282|".to_vec());
        let epsv = b"229 Entering Extended Passive Mode (|||6446|)\r\n";
        Check::ok(umilib_protocol_ftp_ftp_data_address_from_epsv(epsv.as_ptr(), epsv.len(), &mut parsed));
        assert_eq!(parsed, FFIFTPDataAddress { port: 6446, ..FFIFTPDataAddress::default() });
        Check::ok(umilib_protocol_ftp_ftp_data_address_epsv_reply(parsed, &mut wire));
        assert_eq!(wire.take(), b"229 Entering Extended Passive Mode (|||6446|)\r\n".to_vec());
        Check::fails(
            umilib_protocol_ftp_ftp_data_address_parse_eprt(b"|1|1.2.3.4|".as_ptr(), 11, &mut parsed),
            "protocol.ftp",
            "Syntax",
        );
        // A network protocol not supported is answered 522 (§2): not of this state of the server.
        Check::fails(
            umilib_protocol_ftp_ftp_data_address_parse_eprt(b"|3|x|1|".as_ptr(), 7, &mut parsed),
            "protocol.ftp",
            "State",
        );

        // RFC 3659 §2.3: a time-val, of UTC, its fraction kept.
        let (mut seconds, mut nanoseconds) = (0i64, 0u32);
        Check::ok(umilib_protocol_ftp_ftp_time_parse(
            b"19980615100045.014".as_ptr(),
            18,
            &mut seconds,
            &mut nanoseconds,
        ));
        assert_eq!((seconds, nanoseconds), (897_904_845, 14_000_000));
        Check::ok(umilib_protocol_ftp_ftp_time_format(seconds, nanoseconds, &mut text));
        assert_eq!(text.take(), b"19980615100045.014".to_vec());
        Check::fails(
            umilib_protocol_ftp_ftp_time_parse(b"19980230100045".as_ptr(), 14, &mut seconds, &mut nanoseconds),
            "protocol.ftp",
            "Syntax",
        );
        // §7.2: facts, their names compared without case.
        let line = "Type=file;Size=1024990;Perm=r; /tmp/cap60.pcap";
        Check::ok(umilib_protocol_ftp_ftp_facts_normalize(line.as_ptr(), line.len(), &mut text));
        assert_eq!(text.take(), b"type=file;size=1024990;perm=r; /tmp/cap60.pcap".to_vec());
        Check::fails(
            umilib_protocol_ftp_ftp_facts_normalize(b"type=file /x".as_ptr(), 12, &mut text),
            "protocol.ftp",
            "Syntax",
        );
    }
}

#[test]
fn ftp_sessions_through_the_c_abi() {
    unsafe {
        let server = new_server(&[127, 0, 0, 1]);
        let mut client: *mut FTPClient = ptr::null_mut();
        Check::ok(umilib_protocol_ftp_ftp_client_new(config(), false, 0, &mut client));
        let greeting = b"220 Service ready for new user.\r\n";
        Check::ok(umilib_protocol_ftp_ftp_server_greet(server, greeting.as_ptr(), greeting.len(), 0));
        exchange(client, server);
        let events = Event::client(client);
        assert_eq!((events.len(), events[0].kind, events[0].reply.as_slice()), (1, 0, &greeting[..]));

        // RFC 959 §7: USER and PASS, then a retrieval with its preliminary and final replies.
        let events = round(client, server, "USER anonymous", &["331 User name okay, need password.\r\n"]);
        assert_eq!((events[0].kind, events[0].command.as_slice()), (2, &b"USER anonymous"[..]));
        round(client, server, "PASS guest", &["230 User logged in, proceed.\r\n"]);
        // FEAT is answered by the server itself (RFC 2389 §3), as is TYPE (RFC 959 §5.1).
        let line = "FEAT";
        Check::ok(umilib_protocol_ftp_ftp_client_send(client, line.as_ptr(), line.len(), 0));
        exchange(client, server);
        assert!(Event::server(server).is_empty());
        let mut features = Buffer::EMPTY;
        Check::ok(umilib_protocol_ftp_ftp_server_features(server, &mut features));
        assert_eq!(Event::client(client)[0].reply, features.take());
        let mut has = false;
        Check::ok(umilib_protocol_ftp_ftp_client_has_feature(client, b"mdtm".as_ptr(), 4, &mut has));
        assert!(has);
        Check::ok(umilib_protocol_ftp_ftp_client_send(client, b"TYPE I".as_ptr(), 6, 0));
        exchange(client, server);
        assert!(Event::server(server).is_empty());
        assert!(Event::client(client)[0].reply.starts_with(b"200 "));

        let mut reply = Buffer::EMPTY;
        Check::ok(umilib_protocol_ftp_ftp_data_address_epsv_reply(address(&[], 6446), &mut reply));
        let reply = String::from_utf8(reply.take()).unwrap();
        let events = round(client, server, "EPSV", &[&reply]);
        let mut data = FFIFTPDataAddress::default();
        Check::ok(umilib_protocol_ftp_ftp_data_address_from_epsv(
            events[0].reply.as_ptr(),
            events[0].reply.len(),
            &mut data,
        ));
        assert_eq!(data.port, 6446);
        let events = round(
            client,
            server,
            "RETR a.txt",
            &["150 File status okay; about to open data connection.\r\n", "226 Closing data connection.\r\n"],
        );
        assert_eq!(events.iter().map(|event| event.kind).collect::<Vec<_>>(), [1, 2]);
        assert!(events[1].reply.starts_with(b"226 "));

        // RFC 2577 §3: PORT to another host than the client's is refused by the server itself.
        Check::ok(umilib_protocol_ftp_ftp_client_send(client, b"PORT 10,0,0,9,7,138".as_ptr(), 19, 0));
        exchange(client, server);
        assert!(Event::server(server).is_empty());
        assert!(Event::client(client)[0].reply.starts_with(b"504 "));

        // QUIT: 221 from the server itself, and both close.
        Check::ok(umilib_protocol_ftp_ftp_client_send(client, b"QUIT".as_ptr(), 4, 0));
        exchange(client, server);
        assert_eq!(Event::server(server).last().map(|event| (event.kind, event.error)), Some((3, ptr::null())));
        let events = Event::client(client);
        assert!(events[0].reply.starts_with(b"221 "));
        assert_eq!(events.last().map(|event| (event.kind, event.error)), Some((5, ptr::null())));
        let mut open = true;
        Check::ok(umilib_protocol_ftp_ftp_client_is_open(client, &mut open));
        assert!(!open);
        Check::fails(umilib_protocol_ftp_ftp_client_send(client, b"NOOP".as_ptr(), 4, 0), "protocol.ftp", "Closed");
        umilib_protocol_ftp_ftp_client_free(client);
        umilib_protocol_ftp_ftp_server_free(server);
        umilib_protocol_ftp_ftp_client_free(ptr::null_mut());
        umilib_protocol_ftp_ftp_server_free(ptr::null_mut());
    }
}

#[test]
fn ftp_rules_and_timeouts_through_the_c_abi() {
    unsafe {
        let server = new_server(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        Check::ok(umilib_protocol_ftp_ftp_server_greet(server, b"220 ready\r\n".as_ptr(), 11, 0));
        // RFC 959 §5.4: a command needing a login is refused before one, with 530.
        Check::ok(umilib_protocol_ftp_ftp_server_receive(server, b"RETR x\r\n".as_ptr(), 8, 0));
        assert!(Event::server(server).is_empty());
        let mut out = Buffer::EMPTY;
        Check::ok(umilib_protocol_ftp_ftp_server_transmit(server, &mut out));
        let out_bytes = out.take();
        assert!(out_bytes.starts_with(b"220 ready\r\n530 "), "{}", String::from_utf8_lossy(&out_bytes));
        // The idle time ends the session with 421.
        let (mut found, mut deadline) = (false, 0u64);
        Check::ok(umilib_protocol_ftp_ftp_server_poll_timeout(server, &mut found, &mut deadline));
        assert!(found);
        Check::ok(umilib_protocol_ftp_ftp_server_expire(server, deadline));
        Check::ok(umilib_protocol_ftp_ftp_server_transmit(server, &mut out));
        assert!(out.take().starts_with(b"421 "));
        umilib_protocol_ftp_ftp_server_free(server);

        // A server's peer is an address of 4 or 16 octets.
        let mut server = ptr::null_mut();
        let settings = FFIFTPServerConfig::default();
        Check::fails(
            umilib_protocol_ftp_ftp_server_new(
                config(),
                settings,
                b"UNIX".as_ptr(),
                4,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                [1u8; 5].as_ptr(),
                5,
                false,
                &mut server,
            ),
            "ffi",
            "InvalidArgument",
        );

        // No reply in its time closes a client with Timeout.
        let mut client: *mut FTPClient = ptr::null_mut();
        Check::ok(umilib_protocol_ftp_ftp_client_new(config(), false, 0, &mut client));
        Check::ok(umilib_protocol_ftp_ftp_client_poll_timeout(client, &mut found, &mut deadline));
        Check::ok(umilib_protocol_ftp_ftp_client_expire(client, deadline));
        let events = Event::client(client);
        assert_eq!(events.last().map(|event| event.kind), Some(5));
        Check::fails(events.last().unwrap().error, "protocol.ftp", "Timeout");
        umilib_protocol_ftp_ftp_client_free(client);
    }
}

#[test]
fn ftp_session_state_through_the_c_abi() {
    unsafe {
        let server = new_server(&[127, 0, 0, 1]);
        Check::ok(umilib_protocol_ftp_ftp_server_greet(server, b"220 ready\r\n".as_ptr(), 11, 0));
        let input = b"USER u\r\n";
        Check::ok(umilib_protocol_ftp_ftp_server_receive(server, input.as_ptr(), input.len(), 0));
        Event::server(server);
        Check::ok(umilib_protocol_ftp_ftp_server_reply(server, b"230 in\r\n".as_ptr(), 8, 0));
        let input = b"TYPE I\r\nSTRU R\r\nREST 100\r\n";
        Check::ok(umilib_protocol_ftp_ftp_server_receive(server, input.as_ptr(), input.len(), 0));
        Event::server(server);
        Check::ok(umilib_protocol_ftp_ftp_server_reply(server, b"350 restarting\r\n".as_ptr(), 16, 0));
        let (mut logged_in, mut mode, mut structure, mut protection, mut has_restart) = (false, 0u8, 0u8, 0u8, false);
        let (mut representation, mut restart) = (Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_protocol_ftp_ftp_server_session(
            server,
            &mut logged_in,
            &mut representation,
            &mut mode,
            &mut structure,
            &mut protection,
            &mut has_restart,
            &mut restart,
        ));
        assert_eq!(
            (logged_in, representation.take(), mode, structure, protection),
            (true, b"I".to_vec(), b'S', b'R', b'C')
        );
        assert_eq!((has_restart, restart.take()), (true, b"100".to_vec()));
        let mut wants = false;
        Check::ok(umilib_protocol_ftp_ftp_server_wants_receive(server, &mut wants));
        assert!(wants);
        umilib_protocol_ftp_ftp_server_free(server);
    }
}
