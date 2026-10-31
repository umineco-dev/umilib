# SMTP: `umilib::protocol::smtp`

`protocol-smtp` (no `std`) is the Simple Mail Transfer Protocol (RFC 5321)
without doing any I/O: replies, commands, paths and mail data, and a client
and a server of one connection, with the extensions SIZE (RFC 1870),
PIPELINING (RFC 2920), STARTTLS (RFC 3207), AUTH (RFC 4954), 8BITMIME (RFC
6152), ENHANCEDSTATUSCODES (RFC 2034, RFC 3463), CHUNKING and BINARYMIME
(RFC 3030), SMTPUTF8 (RFC 6531) and DSN (RFC 3461). Submission (RFC 6409)
and implicit TLS (RFC 8314) are the same protocol on another port.

| Type | What it is |
| --- | --- |
| `SMTPReply`, `SMTPReplyReader`, `SMTPEnhancedStatus` | A reply: its code and lines; read line by line; the status code of RFC 3463 |
| `SMTPCommand`, `SMTPParameter` | A command and the parameters of MAIL and RCPT |
| `SMTPPath`, `SMTPMailbox`, `SMTPXText` | A reverse or forward path, a mailbox, and the xtext of DSN |
| `SMTPData`, `SMTPDataReader` | Mail data written with its periods added and read back with them removed (§4.5.2) |
| `SMTPExtensions`, `SMTPExtension` | The reply to EHLO: the greeting and the extensions advertised |
| `SMTPClient`, `SMTPClientEvent` | A client of one connection |
| `SMTPServer`, `SMTPServerEvent` | A server of one connection |
| `SMTPConfig`, `SMTPServerConfig` | The limits and times, and what a server offers |
| `SMTPMailExchanger` | The hosts to deliver a domain's mail to, of its MX records (with `protocol-dns`) |

## A client

```rust
use umilib::protocol::smtp::{SMTPClient, SMTPClientEvent, SMTPCommand, SMTPConfig};

let mut client = SMTPClient::new(SMTPConfig::default(), false, now)?;
// for what arrives: client.receive(&bytes, now)?; send what client.transmit(&mut out) gives
client.send(SMTPCommand::Ehlo(String::from("client.example")), now)?;
client.send(SMTPCommand::parse(b"MAIL FROM:<a@client.example>", false)?, now)?;
client.send(SMTPCommand::parse(b"RCPT TO:<b@server.example>", false)?, now)?;
client.send(SMTPCommand::Data, now)?;
while let Some(event) = client.poll_event() {
    match event {
        SMTPClientEvent::Reply { command: SMTPCommand::Data, reply } if reply.code == 354 => client.send_data(message, now)?,
        SMTPClientEvent::DataReply(reply) => { /* the server took the message, or not */ }
        SMTPClientEvent::AuthChallenge(data) => client.auth_respond(&response, now)?,
        SMTPClientEvent::StartTLS => { /* start TLS on the connection before anything else */ }
        _ => {}
    }
}
```

- A command is checked against the state and the extensions the server
  advertised: an extension, or a parameter of one, that was not advertised
  is not sent (RFC 5321 §2.2.1), and is a `State` error.
- Commands are sent one at a time, or pipelined where PIPELINING allows
  (RFC 2920 §3.1: a command that changes the state ends a group).
- The client keeps each mail transaction by a number: a refused MAIL ends
  it, a refused DATA or chunk keeps it until RSET.
- An initial response of AUTH that would make the line too long is sent
  after the server's empty 334 instead (RFC 4954 §4).
- The mail data is sent with CRLF as its only line break and a period
  added to each line that begins with one. A CR or an LF alone is refused
  (`Content`), as is a line longer than `maximum_text_line`.
- Each reply is waited for as long as RFC 5321 §4.5.3.2 says (5 minutes, 2
  for DATA, 10 for the end of the data), from the reply before it, so that
  pipelined commands do not share one time; then the connection closes with
  `Timeout`.
- A command whose fields cannot be written as its one line (a line break in
  a path or a domain) is refused (`Syntax`), so that no value adds a command.
- MAIL is sent only after EHLO or HELO (§4.1.4), and a 2xx to EHLO other
  than 250 closes the client.
- AUTH PLAIN and LOGIN, which send a password as it is, are sent only
  under TLS while `SMTPConfig::passwords_require_tls` (true by default; RFC
  2595 §2.3 requires a client be able to refuse them).

## A server

```rust
use umilib::protocol::smtp::{SMTPConfig, SMTPReply, SMTPServer, SMTPServerConfig, SMTPServerEvent};

let mut settings = SMTPServerConfig::default();
settings.domain = String::from("mx.example");
let mut server = SMTPServer::new(SMTPConfig::default(), settings, false)?;
server.greet(server.greeting(), now)?;
// for what arrives: server.receive(&bytes, now); send what server.transmit(&mut out) gives
while let Some(event) = server.poll_event() {
    match event {
        SMTPServerEvent::Command(command) => server.reply(SMTPReply::new(250, "OK"), now)?,
        SMTPServerEvent::Data(octets) => { /* part of the message, its periods removed */ }
        SMTPServerEvent::DataEnd { last } => server.reply(SMTPReply::new(250, "Queued"), now)?,
        _ => {}
    }
}
```

The server answers what the RFCs decide and tells the rest, one command at
a time, to be answered with `reply`:

- NOOP, RSET and QUIT; a command out of sequence (503); one of an
  extension not advertised (555 or 502); an unknown command (500) unless
  its verb is in `commands`; a message larger than SIZE (552); too many
  recipients (452); DATA without a recipient taken (554); anything but
  EHLO, STARTTLS, NOOP and QUIT before TLS when `requires_tls` (530); MAIL
  before AUTH when `requires_auth` (530).
- For EHLO, the reply given is the first line, and the server adds the
  extensions it advertises.
- Where ENHANCEDSTATUSCODES is advertised, a reply without a status code
  gets `c.0.0` of its class (RFC 2034 §3).
- A BDAT refused (before TLS, after a 554 greeting, or of a transaction
  refused) has its chunk read and discarded first (RFC 3030 §2), so that its
  octets are never taken as commands.
- An AUTH exchange that fails on the server's side (a response not base64,
  a line too long) is told as `AuthFailed`, for the application to drop its
  SASL state.
- RCPT parameters are taken only after EHLO (§4.1.1.11). With
  ENHANCEDSTATUSCODES, every line of a reply carries the status code (RFC
  2034 §4).
- While a command waits for its answer the server reads nothing more;
  stop reading the connection while `wants_receive` is false, so that a peer
  that pipelines cannot make it hold more than `maximum_buffered`.
- Mail data ends only at CRLF.CRLF. Data with a CR or an LF alone is not
  taken: the server answers 550 itself and tells `DataRejected`. This is
  the defence against SMTP smuggling, where two servers disagree on where a
  message ends.

AUTH and STARTTLS carry what SASL and TLS need and no more:

- `AuthChallenge` and `AuthResponse` are the decoded data of 334 lines;
  the mechanism is the application's (see [auth-sasl.md](auth-sasl.md)).
- The mechanisms that send a password as it is (PLAIN always, and those in
  `plaintext_mechanisms`) are advertised and taken only under TLS while
  `passwords_require_tls` (RFC 4954 §4).
- After the 220 to STARTTLS, whatever was received before TLS is
  discarded on both sides (RFC 3207 §4.2, CVE-2011-0411), and the session
  begins again. Start TLS on the connection at `StartTLS`.
- `shutdown(text)` replies 421 and closes (§3.8), for a server shutting
  down; text of a CR, an LF or a NUL is refused (`Syntax`) and nothing is
  written.

## Delivery

`SMTPMailExchanger::order` (with `protocol-dns`) turns the MX records of a
domain into the hosts to try (RFC 5321 §5.1): by preference, those of one
preference in a random order, the domain itself if it has no MX, without
this host and those not preferred to it. A null MX (RFC 7505) means the
domain takes no mail: `NoMail`.

## Python and C

`umilib.protocol.smtp` and `include/umilib/protocol/smtp.h` mirror the
types above. Commands and replies cross the C ABI as their text on the
wire: a command line without its CRLF, a reply with its CRLFs. The
configurations are structures, and the lists of a server's configuration
arrays of text. An event is the number of its kind and its contents. The
MX records of `SMTPMailExchanger.order` are zone-file text, as
`umilib.protocol.dns` writes them.

## Trying it

`examples/smtp.rs` is a server and a client; `examples/mail.sh` runs them
against Postfix and against curl and Python's smtplib.

## Not implemented

The security layers of SASL (none of the mechanisms in use has one);
ETRN, ATRN and the other extensions of relaying; VRFY and EXPN are told to
the application, which may refuse them (RFC 5321 §7.3).
