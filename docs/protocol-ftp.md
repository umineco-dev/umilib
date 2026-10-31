# FTP: `umilib::protocol::ftp`

`protocol-ftp` (no `std`) is the control connection of the File Transfer
Protocol (RFC 959) without doing any I/O, with FEAT and OPTS (RFC 2389),
EPRT and EPSV (RFC 2428), SIZE, MDTM, REST STREAM, MLST and MLSD (RFC
3659), HOST (RFC 7151), UTF-8 pathnames (RFC 2640) and FTPS (RFC 4217).
The data connections are the application's.

| Type | What it is |
| --- | --- |
| `FTPCommand` | A command; `transfers` for those that use a data connection |
| `FTPReply`, `FTPReplyReader` | A reply and its lines, read line by line; the pathname of 257 |
| `FTPFeatures`, `FTPFeature` | The reply to FEAT |
| `FTPDataAddress` | The address of a data connection: of PORT and PASV, of EPRT and EPSV |
| `FTPFacts`, `FTPTime` | An entry of MLST and MLSD, and the time-val of MDTM and the modify fact |
| `FTPClient`, `FTPClientEvent` | A client of the control connection |
| `FTPServer`, `FTPServerEvent` | A server of the control connection |
| `FTPConfig`, `FTPServerConfig` | The limits and times, and what a server offers |

## A client

```rust
use umilib::protocol::ftp::{FTPClient, FTPClientEvent, FTPCommand, FTPConfig, FTPDataAddress};

let mut client = FTPClient::new(FTPConfig::default(), false, now)?;
client.send(FTPCommand::parse(b"USER anonymous")?, now)?;
client.send(FTPCommand::parse(b"EPSV")?, now)?;
while let Some(event) = client.poll_event() {
    match event {
        FTPClientEvent::Reply { command, reply } if command.verb() == "EPSV" => {
            let address = FTPDataAddress::from_epsv(&reply)?; // connect to the server's host at address.port
        }
        FTPClientEvent::Preliminary { command, reply } => { /* 150: the transfer starts on the data connection */ }
        FTPClientEvent::Reply { command, reply } => { /* the final reply */ }
        _ => {}
    }
}
```

- Commands are sent one at a time (RFC 959 §5.4), except ABOR, STAT and
  QUIT, which go during a transfer. A transfer's preliminary reply (1xx) is
  told, then its final one; ABOR's 426 and 226 both come to ABOR's turn.
- A command of a feature the server did not list in FEAT is refused, once
  the features are known.
- Connect the data connection as soon as the reply to PASV or EPSV comes,
  before the transfer's preliminary reply: RFC 959 sets no order, and some
  servers (vsftpd) send the 150 only once the data connection is open.
- `StartTLS` (the 234 to AUTH TLS) and `ClearCommandChannel` (the 200 to
  CCC, or a positive reply to REIN under TLS, RFC 4217 §13) tell when to
  start and end TLS on the control connection; PROT P asks for it on the
  data connections, which the application opens. After AUTH TLS the user
  logs in again (RFC 4217 §4).
- During a transfer, the reply to STAT (211 to 213) is STAT's, before the
  transfer's final one (RFC 959 §4.1.3).
- A command of a line break in an argument is refused (`Syntax`). FTP has
  no clear-text refusal: anonymous FTP sends its password in the clear by
  design; use AUTH TLS (or implicit TLS) where it matters.

## A server

```rust
use umilib::protocol::ftp::{FTPConfig, FTPReply, FTPServer, FTPServerConfig, FTPServerEvent};

let mut server = FTPServer::new(FTPConfig::default(), FTPServerConfig::default(), client_address, false)?;
server.greet(FTPReply::new(220, "Service ready"), now)?;
while let Some(event) = server.poll_event() {
    if let FTPServerEvent::Command(command) = event {
        if command.transfers() {
            server.reply(FTPReply::new(150, "Opening data connection"), now)?;
            // transfer on the data connection
            server.reply(FTPReply::new(226, "Transfer complete"), now)?;
        } else {
            server.reply(FTPReply::new(250, "OK"), now)?;
        }
    }
}
```

The server answers what the RFCs decide and tells the rest:

- NOOP, FEAT, SYST, QUIT, TYPE, MODE, STRU (the minimum of RFC 959 §5.1:
  A, I, L 8; S; F, R), PBSZ, PROT and CCC; a command before login (530) or
  out of sequence (503); one of a feature not offered (502); an unknown
  command (500) unless it is in `commands`.
- PORT and EPRT naming a host other than the client, or a port below 1024,
  are refused with 504 (RFC 2577 §3, the bounce attack) unless
  `allow_foreign_data`; an IPv4-mapped peer (a dual-stack socket) is its
  IPv4 address. EPRT of a network protocol not supported is 522 (RFC 2428
  §2), a line of no command 500, bad arguments 501. After EPSV ALL only EPSV sets up data connections
  (RFC 2428 §4).
- During a transfer, STAT is answered 211 by the server, QUIT waits for the
  transfer's final reply, ABOR is told after it.
- With FTPS, USER before TLS is refused with 530 if `require_tls`, and a
  transfer without PROT P with 521 if `require_protection` (RFC 4217 §9,
  §11). After the 234 to AUTH TLS, what came before TLS is discarded
  (CVE-2011-0411).
- Telnet commands (IAC sequences) are removed from command lines (RFC 959
  §4.1.3, used by ABOR); an IAC before a byte of no Telnet command (the
  Synch's DM sent out of band) is dropped alone.
- What the session set is kept for the application: `representation`
  (TYPE), `mode`, `structure` (STRU), `protection` (PROT), `restart` (REST)
  and `logged_in` (in C and Python, `ftp_server_session` and
  `FTPServer.session()`). AUTH TLS and REIN reset them (RFC 4217 §4, RFC
  959 §4.1.1). REIN needs no login. Stop reading the connection while
  `wants_receive` is false.
- `shutdown(text)` replies 421 and closes (§4.2), for a server shutting
  down; text of a CR, an LF or a NUL is refused (`Syntax`) and nothing is
  written.

## Python and C

`umilib.protocol.ftp` and `include/umilib/protocol/ftp.h` mirror the types
above. Commands cross the C ABI as their lines without CRLF, replies with
their CRLFs. A data address is a structure of 16 octets, a length (4, 16,
or 0 for no host) and a port, as the IP endpoints of `protocol-ip`; Python
gives the host as text.

## Trying it

`examples/ftp.rs` is a server of a directory in memory and a client;
`examples/ftp.sh` runs them against vsftpd and against curl and Python's
ftplib.

## Not implemented

The modes and structures beyond the minimum of RFC 959 §5.1 (block and
compressed modes, page structure); the language negotiation of RFC 2640
(LANG) is told to the application.
