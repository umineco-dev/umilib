//! FTP (RFC 959): the scenario of §7, the dialogues of RFC 3659 (MDTM,
//! SIZE, REST STREAM, MLST, MLSD), RFC 7151 (HOST) and RFC 2389 (FEAT) run
//! by the client against the server's lines and by the server against the
//! client's; the addresses of RFC 2428; FTPS of RFC 4217; and the rules:
//! multi-line replies (§4.2), sequences (§5.4), the bounce attack (RFC 2577).

use umilib::protocol::ftp::{
    FTPClient, FTPClientEvent, FTPCommand, FTPConfig, FTPDataAddress, FTPError, FTPFacts, FTPFeatures, FTPReply,
    FTPReplyReader, FTPServer, FTPServerConfig, FTPServerEvent, FTPTime,
};
use umilib::protocol::ip::IPAddress;
use umilib::runtime::Instant;

use crate::Vectors;

const T0: Instant = Instant::from_nanos(1_000_000_000);

#[derive(Clone, Debug)]
struct Step {
    client: bool,
    text: String,
}

/// The dialogue of RFC 3659 or RFC 7151 between the lines beginning with `start` and `end`: its lines
/// of `C>` and `S>` (those of the data connection, `D>`, and the elided ones left out).
fn dialogue(path: &str, start: &str, end: &str) -> Vec<Step> {
    let text = Vectors::read(path);
    let lines: Vec<&str> = text.lines().collect();
    let first = lines.iter().position(|line| line.trim_start().starts_with(start)).expect("the start");
    let last =
        first + 1 + lines[first + 1..].iter().position(|line| line.trim_start().starts_with(end)).expect("the end");
    lines[first..last]
        .iter()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let (client, rest) = match trimmed.split_at_checked(3) {
                Some(("C> ", rest)) => (true, rest),
                Some(("S> ", rest)) => (false, rest),
                _ => return None,
            };
            (!rest.contains("...") && !rest.contains("<any")).then(|| Step { client, text: rest.to_string() })
        })
        .collect()
}

/// The replies of the server's lines.
fn replies(steps: &[Step]) -> Vec<FTPReply> {
    let mut reader = FTPReplyReader::new();
    steps
        .iter()
        .filter(|step| !step.client)
        .filter_map(|step| reader.push(step.text.as_bytes(), 100).unwrap())
        .collect()
}

fn logged_in_client() -> FTPClient {
    let mut client = FTPClient::new(FTPConfig::default(), false, T0).unwrap();
    client.receive(b"220 ready\r\n", T0).unwrap();
    client.send(FTPCommand::User("anonymous".into()), T0).unwrap();
    client.receive(b"331 password\r\n", T0).unwrap();
    client.send(FTPCommand::Pass("guest".into()), T0).unwrap();
    client.receive(b"230 logged in\r\n", T0).unwrap();
    client.transmit(&mut Vec::new());
    while client.poll_event().is_some() {}
    client
}

/// Runs the client's side of a dialogue after login: it sends the client's commands, what it sends
/// reads as them, and it tells the server's replies.
fn run_client(steps: &[Step]) -> Vec<FTPClientEvent> {
    let mut client = logged_in_client();
    let mut told = Vec::new();
    for step in steps {
        if step.client {
            let command = FTPCommand::parse(step.text.as_bytes()).unwrap();
            client.send(command.clone(), T0).unwrap_or_else(|error| panic!("{error}: {}", step.text));
            let mut out = Vec::new();
            client.transmit(&mut out);
            assert_eq!(FTPCommand::parse(out.strip_suffix(b"\r\n").unwrap()).unwrap(), command);
        } else {
            client.receive(format!("{}\r\n", step.text).as_bytes(), T0).unwrap();
        }
        told.extend(std::iter::from_fn(|| client.poll_event()));
    }
    told
}

fn peer() -> IPAddress {
    "192.0.2.10".parse().unwrap()
}

/// A server of a client at `peer`, greeted and logged in.
fn logged_in_server(config: FTPServerConfig, peer: IPAddress) -> FTPServer {
    let mut server = FTPServer::new(FTPConfig::default(), config, peer, false).unwrap();
    server.greet(FTPReply::new(220, "ready"), T0).unwrap();
    server.receive(b"USER anonymous\r\n", T0);
    server.poll_event();
    server.reply(FTPReply::new(331, "password"), T0).unwrap();
    server.receive(b"PASS guest\r\n", T0);
    server.poll_event();
    server.reply(FTPReply::new(230, "logged in"), T0).unwrap();
    server.transmit(&mut Vec::new());
    server
}

/// Runs the server's side of a dialogue: it feeds the client's lines and answers what it tells with
/// the dialogue's replies; the codes it writes are the dialogue's.
fn run_server(steps: &[Step], mut server: FTPServer) -> FTPServer {
    let expected = replies(steps);
    let mut written = Vec::new();
    let mut reader = FTPReplyReader::new();
    let mut take = |server: &mut FTPServer, written: &mut Vec<FTPReply>| {
        let mut out = Vec::new();
        server.transmit(&mut out);
        for line in out.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
            if let Some(reply) = reader.push(line.strip_suffix(b"\r").unwrap(), 100).unwrap() {
                written.push(reply);
            }
        }
    };
    for step in steps.iter().filter(|step| step.client) {
        server.receive(format!("{}\r\n", step.text).as_bytes(), T0);
        loop {
            take(&mut server, &mut written);
            match server.poll_event() {
                Some(FTPServerEvent::Command(command)) => loop {
                    let reply = expected[written.len()].clone();
                    let preliminary = reply.is_preliminary();
                    server.reply(reply, T0).unwrap();
                    take(&mut server, &mut written);
                    if !preliminary || !command.transfers() {
                        break;
                    }
                },
                Some(_) => {}
                None => break,
            }
        }
    }
    let codes = |replies: &[FTPReply]| replies.iter().map(|reply| reply.code).collect::<Vec<_>>();
    assert_eq!(codes(&written), codes(&expected));
    server
}

#[test]
fn rfc959_typical_scenario() {
    // §7: login, RETR in ASCII, TYPE I, a STOR refused, QUIT.
    let mut client = FTPClient::new(FTPConfig::default(), false, T0).unwrap();
    let mut server = FTPServer::new(FTPConfig::default(), FTPServerConfig::default(), peer(), false).unwrap();
    server.greet(FTPReply::new(220, "Service ready"), T0).unwrap();
    let mut wire = Vec::new();
    let mut exchange = |client: &mut FTPClient, server: &mut FTPServer| {
        loop {
            server.transmit(&mut wire);
            if !wire.is_empty() {
                client.receive(&wire, T0).unwrap();
                wire.clear();
            }
            client.transmit(&mut wire);
            if wire.is_empty() {
                break;
            }
            server.receive(&wire, T0);
            wire.clear();
            while let Some(event) = server.poll_event() {
                let FTPServerEvent::Command(command) = event else { continue };
                let reply = match command {
                    FTPCommand::User(_) => FTPReply::new(331, "User name ok, need password"),
                    FTPCommand::Pass(_) => FTPReply::new(230, "User logged in"),
                    FTPCommand::Retr(_) => {
                        server
                            .reply(FTPReply::new(150, "File status okay; about to open data connection"), T0)
                            .unwrap();
                        FTPReply::new(226, "Closing data connection, file transfer successful")
                    }
                    FTPCommand::Stor(_) => FTPReply::new(550, "Access denied"),
                    _ => FTPReply::new(502, "Not implemented"),
                };
                server.reply(reply, T0).unwrap();
            }
        }
    };
    exchange(&mut client, &mut server);
    for command in [
        FTPCommand::User("Doe".into()),
        FTPCommand::Pass("mumble".into()),
        FTPCommand::Retr("test.pl1".into()),
        FTPCommand::Type("I".into()),
        FTPCommand::Stor(">udd>cn>fd".into()),
        FTPCommand::Quit,
    ] {
        client.send(command, T0).unwrap();
        exchange(&mut client, &mut server);
    }
    let told: Vec<FTPClientEvent> = std::iter::from_fn(|| client.poll_event()).collect();
    let codes: Vec<u16> = told
        .iter()
        .filter_map(|event| match event {
            FTPClientEvent::Greeting(reply)
            | FTPClientEvent::Preliminary { reply, .. }
            | FTPClientEvent::Reply { reply, .. } => Some(reply.code),
            _ => None,
        })
        .collect();
    assert_eq!(codes, [220, 331, 230, 150, 226, 200, 550, 221]);
    assert!(!client.is_open() && !server.is_open());
}

#[test]
fn rfc959_replies_of_section_4_2() {
    // A multi-line reply: lines between its first and last of any text, one of digits too.
    let mut reader = FTPReplyReader::new();
    assert_eq!(reader.push(b"123-First line", 10).unwrap(), None);
    assert_eq!(reader.push(b"Second line", 10).unwrap(), None);
    assert_eq!(reader.push(b"  234 A line beginning with numbers", 10).unwrap(), None);
    let reply = reader.push(b"123 The last line", 10).unwrap().unwrap();
    assert_eq!(reply.code, 123);
    assert_eq!(reply.lines.len(), 4);
    // A line between of three digits is written after a space, so that it ends nothing.
    let mut out = Vec::new();
    FTPReply { code: 211, lines: vec![b"Status".to_vec(), b"211 not the end".to_vec(), b"End".to_vec()] }
        .encode(&mut out);
    assert_eq!(out, b"211-Status\r\n 211 not the end\r\n211 End\r\n");
    assert!(FTPReplyReader::new().push(b"600 x", 10).is_err());
    assert!(FTPReplyReader::new().push(b"270 x", 10).is_err());
    // Appendix II: the pathname of 257, a quote in it written twice.
    assert_eq!(
        FTPReply::new(257, "\"/usr/dm/foo\"\"bar\" directory created").pathname().as_deref(),
        Some("/usr/dm/foo\"bar")
    );
    assert_eq!(
        FTPReply::with_pathname("/usr/dm/foo\"bar", "directory created").lines[0],
        b"\"/usr/dm/foo\"\"bar\" directory created"
    );
    // §5.3: verbs in any case; arguments after one space.
    assert_eq!(FTPCommand::parse(b"MdTm file6").unwrap(), FTPCommand::Mdtm("file6".into()));
    assert!(FTPCommand::parse(b"NOOP x").is_err());
    assert!(FTPCommand::parse(b"RETR").is_err());
}

#[test]
fn rfc3659_mdtm_size_rest_and_mlst() {
    let path = "protocol/ftp/rfc3659.txt";
    // §3.4 MDTM, §4.4 SIZE, §5.5 REST STREAM, §7.7 MLST.
    for (start, end) in [
        ("C> MDTM A", "4.  File SIZE"),
        ("C> TYPE I", "5.  Restart"),
        ("C> PORT 127,0,0,1,15,107", "6.  A Trivial"),
        ("7.7.1.  Simple MLST", "7.7.2."),
        ("7.7.2.  MLST of a directory", "7.7.3."),
    ] {
        let steps = dialogue(path, start, end);
        let told = run_client(&steps);
        let finals: Vec<FTPReply> = told
            .iter()
            .filter_map(|event| match event {
                FTPClientEvent::Reply { reply, .. } | FTPClientEvent::Preliminary { reply, .. } => Some(reply.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(finals, replies(&steps), "{start}");
        let config = FTPServerConfig { mlst_facts: vec!["type*".into()], ..FTPServerConfig::default() };
        run_server(&steps, logged_in_server(config, "127.0.0.1".parse().unwrap()));
    }
    // §2.3: times; the fraction kept.
    assert_eq!(FTPTime::parse("19980615100045.014").unwrap(), FTPTime::new(897_904_845, 14_000_000));
    assert_eq!(FTPTime::new(897_904_845, 14_000_000).to_string(), "19980615100045.014");
    assert_eq!(FTPTime::parse("19990929003355").unwrap().to_string(), "19990929003355");
    assert!(FTPTime::parse("1999092900335").is_err());
    assert!(FTPTime::parse("19990230003355").is_err());
    // §7.7.1: the fact line of MLST, after its leading space.
    let facts = FTPFacts::parse("Type=file;Size=1024990;Perm=r; /tmp/cap60.pl198.tar.gz").unwrap();
    assert_eq!((facts.get("type"), facts.size(), facts.get("PERM")), (Some("file"), Some(1_024_990), Some("r")));
    assert_eq!(facts.pathname, "/tmp/cap60.pl198.tar.gz");
    // §7.7.3: the lines of MLSD, an empty value too.
    let text = Vectors::read(path);
    let lines: Vec<&str> = text.lines().filter_map(|line| line.strip_prefix("D> ")).collect();
    let listing: Vec<FTPFacts> = lines.iter().take(13).map(|line| FTPFacts::parse(line).unwrap()).collect();
    assert_eq!(listing[2].get("type"), Some("pdir"));
    assert_eq!(listing[3].get("perm"), Some(""));
    assert_eq!(listing[3].modify(), Some(FTPTime::parse("19940728095854").unwrap()));
    assert_eq!(listing[12].to_string(), "type=file;size=1024990;modify=19980130010322;perm=r; cap60.pl198.tar.gz");
    // §7.7.4 writes "Unique=keVO1+ZF4 test" without the ";" that ends each fact (§7.2): not an entry.
    assert!(FTPFacts::parse("Type=dir;Perm=el;Unique=keVO1+ZF4 test").is_err());
}

#[test]
fn rfc2389_features() {
    let reply = FTPReply {
        code: 211,
        lines: vec![
            b"Extensions supported:".to_vec(),
            b" MLST size*;create;modify*;perm;media-type".to_vec(),
            b" SIZE".to_vec(),
            b" COMPRESSION".to_vec(),
            b" MDTM".to_vec(),
            b"END".to_vec(),
        ],
    };
    let features = FTPFeatures::from_reply(&reply).unwrap();
    assert!(features.has("size") && features.has("COMPRESSION"));
    assert_eq!(features.get("MLST").unwrap().parameters, "size*;create;modify*;perm;media-type");
    // A client lists nothing it was not offered: SIZE not listed is not sent.
    let mut client = logged_in_client();
    client.send(FTPCommand::Feat, T0).unwrap();
    client.receive(b"211-Extensions supported:\r\n MDTM\r\n211 End\r\n", T0).unwrap();
    assert!(client.send(FTPCommand::Size("a".into()), T0).is_err());
    client.send(FTPCommand::Mdtm("a".into()), T0).unwrap();
    // The server's reply to FEAT: what it offers.
    let mut server = logged_in_server(FTPServerConfig { tls: true, ..FTPServerConfig::default() }, peer());
    server.receive(b"FEAT\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    let mut reader = FTPReplyReader::new();
    let mut reply = None;
    for line in out.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
        reply = reader.push(line.strip_suffix(b"\r").unwrap(), 100).unwrap().or(reply);
    }
    let features = FTPFeatures::from_reply(&reply.unwrap()).unwrap();
    for name in ["AUTH", "PBSZ", "PROT", "EPRT", "EPSV", "SIZE", "MDTM", "REST", "MLST", "UTF8"] {
        assert!(features.has(name), "{name}");
    }
    assert!(features.has_auth("TLS"));
}

#[test]
fn rfc7151_host() {
    let path = "protocol/ftp/rfc7151.txt";
    let steps = dialogue(path, "C> HOST foo.example.com", "C> HOST ftp.example.com");
    let config = FTPServerConfig { host: true, ..FTPServerConfig::default() };
    let mut server = FTPServer::new(FTPConfig::default(), config.clone(), peer(), false).unwrap();
    server.greet(FTPReply::new(220, "ready"), T0).unwrap();
    server.transmit(&mut Vec::new());
    let server = run_server(&steps, server);
    assert!(server.logged_in);
    // After login HOST is out of sequence (§3.3).
    let mut late = logged_in_server(config, peer());
    late.receive(b"HOST ftp.example.com\r\n", T0);
    let mut out = Vec::new();
    late.transmit(&mut out);
    assert!(out.starts_with(b"503 "));
}

#[test]
fn rfc2428_addresses() {
    // §2: EPRT of IPv4 and IPv6.
    let v4 = FTPDataAddress::parse_eprt("|1|132.235.1.2|6275|").unwrap();
    assert_eq!((v4.host, v4.port), (Some("132.235.1.2".parse().unwrap()), 6275));
    let v6 = FTPDataAddress::parse_eprt("|2|1080::8:800:200C:417A|5282|").unwrap();
    assert_eq!(v6.host, Some("1080::8:800:200C:417A".parse().unwrap()));
    assert_eq!(FTPDataAddress::parse_eprt(&v6.format_eprt().unwrap()).unwrap(), v6);
    assert!(matches!(FTPDataAddress::parse_eprt("|3|x|1|"), Err(FTPError::State { .. })));
    assert!(FTPDataAddress::parse_eprt("|1|132.235.1.2|0|").is_err());
    // §3: the reply to EPSV, of no host.
    let epsv = FTPDataAddress::from_epsv(&FTPReply::new(229, "Entering Extended Passive Mode (|||6446|)")).unwrap();
    assert_eq!((epsv.host, epsv.port), (None, 6446));
    assert_eq!(epsv.epsv_reply().lines[0], b"Entering Extended Passive Mode (|||6446|)");
    // RFC 959: PORT and the reply to PASV.
    let port = FTPDataAddress::parse_port("127,0,0,1,15,107").unwrap();
    assert_eq!(port.port, 15 * 256 + 107);
    assert_eq!(port.format_port().unwrap(), "127,0,0,1,15,107");
    assert_eq!(
        FTPDataAddress::from_pasv(&FTPReply::new(227, "Entering Passive Mode (127,0,0,1,15,107).")).unwrap(),
        port
    );
    assert!(FTPDataAddress::parse_port("127,0,0,256,1,1").is_err());
    // §4: after EPSV ALL only EPSV sets up data connections; another protocol is 522.
    let mut server = logged_in_server(FTPServerConfig::default(), peer());
    server.receive(b"EPSV 3\r\nEPSV ALL\r\nPASV\r\nEPRT |1|192.0.2.10|5000|\r\nEPSV\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert_eq!(out, b"522 Network protocol not supported, use (1,2)\r\n200 EPSV ALL ok\r\n503 Only EPSV after EPSV ALL\r\n503 Only EPSV after EPSV ALL\r\n");
    assert_eq!(server.poll_event(), Some(FTPServerEvent::Command(FTPCommand::Epsv(None))));
}

#[test]
fn rfc2577_bounce_attack() {
    // §3: PORT and EPRT to another host, or to a privileged port, are refused.
    let mut server = logged_in_server(FTPServerConfig::default(), peer());
    server.receive(
        b"PORT 198,51,100,7,0,25\r\nPORT 192,0,2,10,0,25\r\nEPRT |1|198.51.100.7|5000|\r\nPORT 192,0,2,10,19,136\r\n",
        T0,
    );
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert_eq!(out.windows(4).filter(|window| window == b"504 ").count(), 3);
    assert_eq!(
        server.poll_event(),
        Some(FTPServerEvent::Command(FTPCommand::Port(FTPDataAddress::parse_port("192,0,2,10,19,136").unwrap())))
    );
}

#[test]
fn rfc4217_ftps() {
    let config = FTPServerConfig {
        tls: true,
        require_tls: true,
        require_protection: true,
        allow_ccc: true,
        ..FTPServerConfig::default()
    };
    let mut server = FTPServer::new(FTPConfig::default(), config, peer(), false).unwrap();
    server.greet(FTPReply::new(220, "ready"), T0).unwrap();
    // Before TLS: USER refused (§11), PBSZ and PROT out of order (§8, §9).
    server.receive(b"USER a\r\nPBSZ 0\r\nPROT P\r\nAUTH SSL\r\nAUTH TLS\r\nUSER evil\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("530 ") && text.contains("503 PBSZ") && text.contains("503 PBSZ first") && text.contains("504 "),
        "{text}"
    );
    assert_eq!(server.poll_event(), Some(FTPServerEvent::Command(FTPCommand::Auth("TLS".into()))));
    server.reply(FTPReply::new(234, "AUTH TLS successful"), T0).unwrap();
    assert_eq!(server.poll_event(), Some(FTPServerEvent::StartTLS));
    assert_eq!(server.poll_event(), None, "the USER sent with AUTH is not read");
    assert!(!server.features().has("AUTH"));
    // Under TLS: login, then transfers only with PROT P.
    server.receive(b"USER a\r\n", T0);
    server.poll_event();
    server.reply(FTPReply::new(331, "password"), T0).unwrap();
    server.receive(b"PASS b\r\n", T0);
    server.poll_event();
    server.reply(FTPReply::new(230, "in"), T0).unwrap();
    server.transmit(&mut Vec::new());
    server.receive(b"RETR a\r\nPBSZ 0\r\nPROT S\r\nPROT P\r\nRETR a\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert_eq!(out, b"521 Data connections need PROT P\r\n200 PBSZ=0\r\n536 Protection level not supported\r\n200 Protection level set\r\n");
    assert_eq!(server.poll_event(), Some(FTPServerEvent::Command(FTPCommand::Retr("a".into()))));
    // During a transfer, ABOR is read; the transfer's final reply comes first.
    server.reply(FTPReply::new(150, "Opening"), T0).unwrap();
    // ABOR comes after the Telnet IP and Synch of RFC 959 §4.1.3, which are removed.
    server.receive(b"STAT\r\n\xff\xf4\xff\xf2ABOR\r\nCWD x\r\n", T0);
    assert_eq!(server.poll_event(), Some(FTPServerEvent::Command(FTPCommand::Abor)));
    server.reply(FTPReply::new(426, "Transfer aborted"), T0).unwrap();
    server.reply(FTPReply::new(226, "ABOR ok"), T0).unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert!(out.starts_with(b"150 Opening\r\n211 RETR in progress\r\n426 "), "{}", String::from_utf8_lossy(&out));
    assert_eq!(server.poll_event(), Some(FTPServerEvent::Command(FTPCommand::Cwd("x".into()))));
    server.reply(FTPReply::new(250, "ok"), T0).unwrap();
    // CCC clears the command connection (§6).
    server.receive(b"CCC\r\n", T0);
    assert_eq!(server.poll_event(), Some(FTPServerEvent::ClearCommandChannel));

    // The client: AUTH TLS forgets the features and believes nothing sent before TLS.
    let mut client = FTPClient::new(FTPConfig::default(), false, T0).unwrap();
    client.receive(b"220 ready\r\n", T0).unwrap();
    assert!(client.send(FTPCommand::Pbsz(0), T0).is_err());
    client.send(FTPCommand::Feat, T0).unwrap();
    client.receive(b"211-Features\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n211 End\r\n", T0).unwrap();
    client.send(FTPCommand::Auth("TLS".into()), T0).unwrap();
    client.receive(b"234 go\r\n230 injected\r\n", T0).unwrap();
    let told: Vec<FTPClientEvent> = std::iter::from_fn(|| client.poll_event()).collect();
    assert!(told.contains(&FTPClientEvent::StartTLS));
    assert!(client.features.is_none() && client.input.is_empty());
    assert!(client.send(FTPCommand::Prot('P'), T0).is_err(), "PROT before PBSZ");
    client.send(FTPCommand::Pbsz(0), T0).unwrap();
    client.send(FTPCommand::Prot('P'), T0).unwrap();
    assert!(client.send(FTPCommand::Auth("TLS".into()), T0).is_err(), "TLS in use");
}

/// §4.2 and §5.4: 421 when the server must close the control connection, for shutting down; a
/// reply's lines are ended by CRLF, so text of a line break, which would be replies of its own,
/// is refused.
#[test]
fn shutdown_of_section_4_2() {
    let mut server = logged_in_server(FTPServerConfig::default(), peer());
    for text in ["bye\r\n226 done", "bye\n226 done", "bye\r", "bye\0"] {
        assert!(server.shutdown(text).is_err(), "{text:?}");
        let mut out = Vec::new();
        server.transmit(&mut out);
        assert!(out.is_empty(), "{text:?}");
        assert!(server.is_open());
    }
    server.shutdown("Service not available, closing control connection").unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert_eq!(out, b"421 Service not available, closing control connection\r\n");
    assert!(!server.is_open());
    assert!(matches!(server.poll_event(), Some(FTPServerEvent::Closed { error: None })));
    server.shutdown("again").unwrap();
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert!(out.is_empty());
}

#[test]
fn sequences_of_section_5_4() {
    let mut server = FTPServer::new(FTPConfig::default(), FTPServerConfig::default(), peer(), false).unwrap();
    server.greet(FTPReply::new(220, "ready"), T0).unwrap();
    server.transmit(&mut Vec::new());
    // Before login: 530; PASS before USER: 503; QUIT is answered.
    server.receive(b"RETR a\r\nPASS b\r\nSYST\r\nNOOP\r\nFROB\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert_eq!(
        out,
        b"530 Not logged in\r\n503 Login with USER first\r\n215 UNIX Type: L8\r\n200 NOOP ok\r\n530 Not logged in\r\n"
    );
    // RNTO only after an RNFR answered 350; REST for the next transfer only.
    let mut server = logged_in_server(FTPServerConfig::default(), peer());
    server.receive(b"RNTO b\r\nRNFR a\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert_eq!(out, b"503 RNFR first\r\n");
    server.poll_event();
    server.reply(FTPReply::new(350, "ready for RNTO"), T0).unwrap();
    server.receive(b"RNTO b\r\nREST 100\r\n", T0);
    assert_eq!(server.poll_event(), Some(FTPServerEvent::Command(FTPCommand::Rnto("b".into()))));
    server.reply(FTPReply::new(250, "renamed"), T0).unwrap();
    server.poll_event();
    server.reply(FTPReply::new(350, "restarting"), T0).unwrap();
    assert_eq!(server.restart.as_deref(), Some("100"));
    server.receive(b"NOOP\r\nFROB\r\n", T0);
    assert_eq!(server.restart, None);
    let mut out = Vec::new();
    server.transmit(&mut out);
    assert!(out.ends_with(b"500 Command not recognized\r\n"));
    // TYPE, MODE and STRU of RFC 959 §5.1, answered by the server.
    server.receive(b"TYPE I\r\nTYPE E\r\nMODE S\r\nMODE B\r\nSTRU F\r\nSTRU P\r\n", T0);
    let mut out = Vec::new();
    server.transmit(&mut out);
    let codes: Vec<&[u8]> =
        out.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).map(|line| &line[..3]).collect();
    assert_eq!(codes, [&b"200"[..], b"504", b"200", b"504", b"200", b"504"]);
    // The client: PASS only after USER is accepted; one command at a time.
    let mut client = FTPClient::new(FTPConfig::default(), false, T0).unwrap();
    client.receive(b"120 wait\r\n220 ready\r\n", T0).unwrap();
    assert!(client.send(FTPCommand::Pass("x".into()), T0).is_err());
    client.send(FTPCommand::User("a".into()), T0).unwrap();
    client.send(FTPCommand::Pass("b".into()), T0).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert_eq!(out, b"USER a\r\n");
    client.receive(b"331 password\r\n", T0).unwrap();
    let mut out = Vec::new();
    client.transmit(&mut out);
    assert_eq!(out, b"PASS b\r\n");
}

#[test]
fn rules_of_the_review() {
    // RFC 959 §4.1.3: STAT during a transfer is answered during it, before the transfer's reply.
    let mut client = logged_in_client();
    client.send(FTPCommand::parse(b"RETR a").unwrap(), T0).unwrap();
    client.receive(b"150 opening\r\n", T0).unwrap();
    client.send(FTPCommand::Stat(None), T0).unwrap();
    client.receive(b"211 RETR in progress\r\n226 done\r\n", T0).unwrap();
    let replies: Vec<(String, u16)> = std::iter::from_fn(|| client.poll_event())
        .filter_map(|event| match event {
            FTPClientEvent::Reply { command, reply } => Some((String::from(command.verb()), reply.code)),
            _ => None,
        })
        .collect();
    assert_eq!(replies, [(String::from("STAT"), 211), (String::from("RETR"), 226)]);

    // §4.1.3: ABOR after Telnet IP and Synch, its DM gone out of band: IAC IP IAC "ABOR".
    let mut server = logged_in_server(FTPServerConfig::default(), peer());
    server.receive(b"RETR a\r\n", T0);
    server.poll_event();
    server.reply(FTPReply::new(150, "opening"), T0).unwrap();
    server.receive(b"\xff\xf4\xffABOR\r\n", T0);
    assert!(matches!(server.poll_event(), Some(FTPServerEvent::Command(FTPCommand::Abor))));

    // RFC 2428 §2: a network protocol not supported is 522.
    let mut server = logged_in_server(FTPServerConfig::default(), peer());
    let mut out = Vec::new();
    server.receive(b"EPRT |3|x|5282|\r\n", T0);
    server.transmit(&mut out);
    assert!(out.starts_with(b"522 "), "{}", String::from_utf8_lossy(&out));
    // RFC 959 §4.2.1: a line of no command is 500.
    out.clear();
    server.receive(b"(nothing)\r\n", T0);
    server.transmit(&mut out);
    assert!(out.starts_with(b"500 "), "{}", String::from_utf8_lossy(&out));

    // RFC 2577 §3: a peer of a dual-stack socket, an IPv4-mapped address, is its IPv4 address.
    let mapped: IPAddress = "::ffff:192.0.2.10".parse().unwrap();
    let mut server = logged_in_server(FTPServerConfig::default(), mapped);
    server.receive(b"PORT 192,0,2,10,7,138\r\n", T0);
    assert!(matches!(server.poll_event(), Some(FTPServerEvent::Command(FTPCommand::Port(_)))));

    // RFC 959 §5.1: TYPE, MODE and STRU are kept for the application.
    let mut server = logged_in_server(FTPServerConfig::default(), peer());
    assert_eq!((server.representation.as_str(), server.mode, server.structure), ("A N", 'S', 'F'));
    server.receive(b"TYPE I\r\nSTRU R\r\n", T0);
    assert_eq!((server.representation.as_str(), server.structure), ("I", 'R'));

    // RFC 4217 §4: after AUTH TLS the user authorizes again; §13: REIN clears TLS.
    let tls = FTPServerConfig { tls: true, ..FTPServerConfig::default() };
    let mut server = logged_in_server(tls, peer());
    server.receive(b"AUTH TLS\r\n", T0);
    server.poll_event();
    server.reply(FTPReply::new(234, "go"), T0).unwrap();
    assert!(!server.logged_in && server.secure && server.representation == "A N");
    server.receive(b"REIN\r\n", T0);
    while server.poll_event().is_some() {}
    server.reply(FTPReply::new(220, "ready"), T0).unwrap();
    assert!(!server.secure);
    assert!(std::iter::from_fn(|| server.poll_event()).any(|event| event == FTPServerEvent::ClearCommandChannel));

    // A line break in an argument is no second command.
    let mut client = logged_in_client();
    assert!(client.send(FTPCommand::Cwd(String::from("a\r\nDELE b")), T0).is_err());
}
