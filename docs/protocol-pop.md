# POP3: `umilib::protocol::pop::v3`

`protocol-pop` is the Post Office Protocol by version; its only one,
`protocol-pop-v3` (alias `protocol-pop3`, no `std`), is POP3 (RFC 1939)
without doing any I/O, with CAPA (RFC 2449), STLS (RFC 2595), AUTH (RFC
5034) and UTF8 and LANG (RFC 6856).

| Type | What it is |
| --- | --- |
| `POP3Command` | A command; `apop` and `apop_digest` make APOP (with `hash-md-v5` and `secret`) |
| `POP3Response` | A status line: +OK or -ERR, the levels of a response code (RFC 2449 §8), text |
| `POP3Capabilities`, `POP3Capability` | The CAPA list |
| `POP3MultiLineReader`, `POP3MultiLineWriter` | The lines of a multi-line response, their periods removed and added |
| `POP3Client`, `POP3ClientEvent`, `POP3State` | A client of one connection, and the state of its session |
| `POP3Server`, `POP3ServerEvent` | A server of one connection |
| `POP3Config`, `POP3ServerConfig` | The limits and times, and what a server offers |

## A client

```rust
use umilib::protocol::pop::v3::{POP3Client, POP3ClientEvent, POP3Command, POP3Config};

let mut client = POP3Client::new(POP3Config::default(), false, now)?;
client.send(POP3Command::Capa, now)?;
client.send(POP3Command::User(String::from("mrose")), now)?;
client.send(POP3Command::Pass(String::from("secret")), now)?;
client.send(POP3Command::Retr(1), now)?;
while let Some(event) = client.poll_event() {
    match event {
        POP3ClientEvent::Response { command, response } => { /* +OK or -ERR */ }
        POP3ClientEvent::Data(lines) => { /* lines of the message, CRLF kept, periods removed */ }
        POP3ClientEvent::DataEnd => { /* the end of the multi-line response */ }
        _ => {}
    }
}
```

- A command is checked against the state (AUTHORIZATION, TRANSACTION,
  UPDATE, RFC 1939 §3) and the capabilities: STLS and AUTH only when
  announced, TOP and UIDL where the server has them.
- Commands are pipelined when the server announces PIPELINING (RFC 2449
  §6.6), one at a time otherwise.
- Only CRLF ends a line of a multi-line response.
- Each response is timed from the one before it; a multi-line response is
  timed from its last octets, so a long RETR that keeps coming is not cut and
  one that stops is.
- USER and PASS, APOP and AUTH PLAIN or LOGIN are sent only under TLS while
  `POP3Config::passwords_require_tls` (true by default, RFC 2595 §2.3); an
  argument of a line break is refused (`Syntax`). After STLS, an accepted
  USER is forgotten (RFC 2595 §4).

## A server

```rust
use umilib::protocol::pop::v3::{POP3Config, POP3Response, POP3Server, POP3ServerConfig, POP3ServerEvent};

let mut server = POP3Server::new(POP3Config::default(), POP3ServerConfig::default(), false)?;
server.greet(POP3Response::ok("POP3 server ready <1896.697170952@dbc.mtview.ca.us>"), now)?;
while let Some(event) = server.poll_event() {
    if let POP3ServerEvent::Command(command) = event {
        server.reply(POP3Response::ok(""), now)?;
        if command.is_multi_line() {
            server.send_data(&message)?;
            server.end_data(now)?;
        }
    }
}
```

- The server answers CAPA, NOOP, QUIT in AUTHORIZATION and the commands
  the state does not take itself, and tells the rest one at a time. A
  command it does not know is answered -ERR unless it is in `commands`.
- QUIT in TRANSACTION is told: the application removes the messages marked
  deleted (the UPDATE state) and answers.
- `send_data` writes every line break as CRLF and adds a period before a
  line that begins with one, so a maildrop stored with LF alone is sent
  right. `POP3MultiLineWriter::canonical_length` is the size of a message
  as LIST must give it (RFC 6856 §2.1): the octets RETR delivers, a CRLF
  after a last line without one counted, the added periods not.
- An AUTH exchange that fails on the server's side (a response not base64,
  a line too long) is told as `AuthFailed`. Stop reading the connection
  while `wants_receive` is false.
- Response codes (`[IN-USE]`, `[SYS/TEMP]`) are sent only when RESP-CODES
  is announced; the server leaves them out otherwise.
- USER and PASS, APOP and the mechanisms that send a password as it is
  (PLAIN always, and `plaintext_mechanisms`) are taken only under TLS while
  `passwords_require_tls` (RFC 5034 §4). The other mechanisms are announced
  before TLS too.
- The autologout timer (10 minutes at least, §3) closes a silent session
  without a response.
- `shutdown(text)` answers -ERR, of `[SYS/TEMP]` where response codes are
  announced (RFC 3206 §4), and closes, for a server shutting down, without
  the UPDATE state. While a multi-line response is being sent it closes
  without a response, so that the client does not take the part sent as the
  whole. Text of a CR, an LF or a NUL is refused (`Syntax`) and nothing is
  written.
- After the +OK to STLS, what was received before TLS is discarded (RFC
  2595 §4, CVE-2011-0411). Start TLS at `StartTLS`.

APOP (RFC 1939 §7) is MD5 of the greeting's timestamp and a shared secret.
`POP3Command::apop_matches` compares a digest in constant time. MD5 no
longer protects the secret: offer APOP only under TLS, where there is
nothing better.

## Python and C

`umilib.protocol.pop.v3` and `include/umilib/protocol/pop/v3.h` mirror
the types above. Commands and status lines cross the C ABI as their lines
without CRLF. In Python, `POP3Response.positive` and `negative` are the
Rust `ok`, `error` and `error_with`, because `ok` is the name of the field.

## Trying it

`examples/pop3.rs` is a server of a maildrop in memory and a client;
`examples/mail.sh` runs them against Dovecot and against curl and
Python's poplib.

## Not implemented

The security layers of SASL; the maildrop itself, and its locking (RFC
1939 §8), are the application's.
