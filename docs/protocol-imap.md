# IMAP: `umilib::protocol::imap::v4`

`protocol-imap` is the Internet Message Access Protocol by version; its
only one, `protocol-imap-v4` (alias `protocol-imap4`, no `std`), is
IMAP4rev2 (RFC 9051), and IMAP4rev1 (RFC 3501) for clients that do not
enable it (RFC 9051 appendix E), without doing any I/O.

| Type | What it is |
| --- | --- |
| `IMAPCommand`, `IMAPCommandBody`, `IMAPState` | A command (its tag and body) and the states of RFC 9051 §3 |
| `IMAPResponse`, `IMAPCondition`, `IMAPResponseCode` | A response, the conditions of status responses, response codes |
| `IMAPReader`, `IMAPWriter`, `IMAPLiteralMode` | The productions of RFC 9051 §9 read and written; how literals are sent |
| `IMAPLineReader`, `IMAPLineEvent` | Logical lines: a line and the literals in it (§4.3, RFC 7888) |
| `IMAPMailbox` | A mailbox name, and modified UTF-7 (RFC 3501 §5.1.3) |
| `IMAPSequenceSet`, `IMAPSequenceNumber` | Sequence sets (`2:4,7,*`, `$`) |
| `IMAPFetchAttribute`, `IMAPFetchItem` | What FETCH asks for and what it returns |
| `IMAPSection`, `IMAPSectionText` | A section of `BODY[...]`, taken out of a message |
| `IMAPEnvelope`, `IMAPAddress` | ENVELOPE, made from the fields of a message |
| `IMAPBody` and its parts | BODY and BODYSTRUCTURE, made from a message's MIME structure |
| `IMAPSearch`, `IMAPSearchKey`, `IMAPSearchData` | SEARCH and ESEARCH |
| `IMAPDate`, `IMAPDateTime` | The dates of SEARCH and the date-time of INTERNALDATE and APPEND |
| `IMAPClient`, `IMAPClientEvent` | A client of one connection |
| `IMAPServer`, `IMAPServerEvent` | A server of one connection |
| `IMAPConfig`, `IMAPServerConfig` | The limits and times, and what a server offers |

## A client

```rust
use umilib::protocol::imap::v4::{IMAPClient, IMAPClientEvent, IMAPCommand, IMAPConfig};

let mut client = IMAPClient::new(IMAPConfig::default(), false, "a", now)?;
let login = IMAPCommand::parse(b"x LOGIN SMITH SESAME", true, 32)?.body;
let tag = client.send(login, now)?; // "a1"
while let Some(event) = client.poll_event() {
    match event {
        IMAPClientEvent::Untagged(response) => { /* EXISTS, FETCH, LIST, ... */ }
        IMAPClientEvent::Completed { command, condition, code, text } => { /* the command's tagged response */ }
        IMAPClientEvent::AuthenticateChallenge { data, .. } => client.authenticate_respond(&response, now)?,
        _ => {}
    }
}
```

- A command is checked against the state and the capabilities: STARTTLS
  only when announced, AUTHENTICATE of a mechanism announced (or of any
  while the capabilities are unknown), ENABLE in the Authenticated state
  only and never after a SELECT (RFC 9051 §6.3.1, RFC 5161 §3.1). To a
  server of IMAP4rev1, IDLE, MOVE, UNSELECT, UID EXPUNGE, NAMESPACE, SEARCH
  RETURN and LIST-EXTENDED go only when announced (IMAP4rev2 announced
  implies them all).
- What a command writes must read back as that one command: a flag, a
  capability or another field of a line break is refused (`Syntax`). A
  command this type does not know (`Other`) is sent as its line, so it
  cannot carry a literal.
- LOGIN and AUTHENTICATE PLAIN or LOGIN are sent only under TLS while
  `IMAPConfig::passwords_require_tls` (true by default; RFC 9051 §11.1).
- After STARTTLS the capabilities and IMAP4rev2 are forgotten (§6.2.1)
  until announced again, so literals go synchronizing and mailbox names in
  modified UTF-7 meanwhile.
- A response or a FETCH item of an extension (QUOTA, MODSEQ) is kept as
  `IMAPResponse::Other` and `IMAPFetchItem::Other`, its text as it is
  (§7: a client MUST be ready for any response).
- A string that cannot be quoted is a literal: synchronizing (the client
  waits for the server's `+`), or non-synchronizing (`{n+}`) where LITERAL+
  or LITERAL- (4096 octets) allows (RFC 7888).
- A command that changes the state waits for the commands before it; the
  others are pipelined unless an EXPUNGE could change the numbers they use
  (§5.5).
- The client takes the capabilities from the greeting's code, the
  CAPABILITY response and OK codes. IMAP4rev2 is in use when the server
  offers it and not IMAP4rev1, or after ENABLE IMAP4rev2. Mailbox names are
  then UTF-8, modified UTF-7 otherwise.
- An initial response of AUTHENTICATE goes on its line where SASL-IR or
  IMAP4rev2 allows it, and after the server's empty challenge otherwise.

## A server

```rust
use umilib::protocol::imap::v4::{IMAPCondition, IMAPConfig, IMAPResponse, IMAPServer, IMAPServerConfig, IMAPServerEvent};

let mut server = IMAPServer::new(IMAPConfig::default(), IMAPServerConfig::default(), false)?;
server.greet(IMAPCondition::OK, "IMAP4rev2 Service Ready", now)?;
while let Some(event) = server.poll_event() {
    if let IMAPServerEvent::Command(command) = event {
        server.respond(&IMAPResponse::Exists(18))?;
        server.complete(IMAPCondition::OK, None, "done", now)?;
    }
}
```

The server answers what RFC 9051 decides and tells the rest, one command
at a time, to be answered with `respond` and `complete`:

- CAPABILITY, LOGOUT (BYE and OK), ENABLE, and a command of another state
  (BAD); an unknown command (BAD) unless its name is in `commands`.
- LOGIN and the mechanisms that send a password as it is (PLAIN always,
  and `plaintext_mechanisms`) are refused with NO [PRIVACYREQUIRED] before
  TLS while `passwords_require_tls`, and LOGINDISABLED is announced (§6.2.3).
- A literal larger than `maximum_literal` is refused before it is sent if
  synchronizing (NO [LIMIT]) and read and dropped if not (BAD [LIMIT]);
  [TOOBIG] for APPEND (RFC 7888 §5). A command over `maximum_command` has
  the literal its line announces read and dropped too, and gets a tagged
  BAD. A line over `maximum_line`, whose end (and so whether a literal
  follows) is not read, ends the session with BYE (RFC 7888 §4), so that no
  literal octets are ever taken as commands.
- A command of an extension of UIDs (`UID SORT`) is `Other` named with its
  UID. `rev2` tells whether IMAP4rev2 is in use (ESEARCH, no RECENT).
- The response of AUTHENTICATE is timed like a command (§5.4). Stop
  reading the connection while `wants_receive` is false.
- `complete` moves the state: OK to LOGIN or AUTHENTICATE authenticates,
  SELECT and EXAMINE select a mailbox (and leave none if refused), CLOSE
  and UNSELECT leave it, OK to STARTTLS starts TLS (and what came before it
  is discarded, CVE-2011-0411).
- With `rev1`, a client that does not ENABLE IMAP4rev2 is answered as RFC
  3501 has it: modified UTF-7 names, LSUB and CHECK, ESEARCH only when it
  asks for RETURN.
- IDLE is accepted with `idle` and ended by the client's DONE
  (`IdleDone`); the autologout timer (30 minutes at least, §5.4) ends a
  silent session with BYE.

The mailboxes are the application's. To answer FETCH,
`IMAPEnvelope::from_fields`, `IMAPBody::from_entity` and
`IMAPSection::extract` make ENVELOPE, BODYSTRUCTURE and the sections of a
message from its [codec-mail](codec-mail.md) structure; the line count of a
text part is the number of its LF.

## Python and C

`umilib.protocol.imap.v4` and `include/umilib/protocol/imap/v4.h` mirror
the client, the server and the parts above. Commands and responses cross
the C ABI as their logical lines: a line with its literals in it
(`{n}`, CRLF, the octets), without the last CRLF, mailbox names of UTF-8;
the client and the server write them for the session. A command given to a
client is its body without a tag. ENVELOPE, BODYSTRUCTURE and sections are
made from the message's bytes (`IMAPEnvelope.of_message`,
`IMAPBody.of_message`, `IMAPSection.extract`).

## Trying it

`examples/imap.rs` is a server of a mailbox in memory and a client;
`examples/mail.sh` runs them against Dovecot and against curl and Python's
imaplib.

## Not implemented

The extensions beyond IMAP4rev2 and those it includes (QRESYNC, CONDSTORE,
METADATA, NOTIFY, COMPRESS, ...) are the application's, as `commands` and
`capabilities` let it add them; MESSAGELIMIT (RFC 9738) is Experimental.
The security layers of SASL. ENABLE enables IMAP4rev2 alone: the
extensions a server adds with `capabilities` cannot be enabled through it
yet.
