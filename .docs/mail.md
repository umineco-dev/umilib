# Mail and file transfer

How `codec::mail`, `protocol::smtp`, `protocol::pop::v3`,
`protocol::imap::v4` and `protocol::ftp` are built and why. The user's
view is `docs/codec-mail.md` and `docs/protocol-{smtp,pop,imap,ftp}.md`.

## Standards

- SMTP is RFC 5321 and the message format RFC 5322. Their revisions
  (draft-ietf-emailcore-rfc5321bis and -rfc5322bis) were approved but not
  yet published when this was written, so the published RFCs are
  implemented. The revisions mostly clarify. Each rule lives in the type it
  is about, so that one can be changed when they are published.
- IMAP is RFC 9051 (IMAP4rev2, which obsoletes RFC 3501), with IMAP4rev1
  kept for clients that do not enable IMAP4rev2 (its appendix E).
  MESSAGELIMIT (RFC 9738) is Experimental and not implemented.
- POP3 (RFC 1939) and FTP (RFC 959) have no revision.

## Shape: the same for the four protocols

- **No I/O, one connection.** Each protocol has a client and a server of
  one connection: `receive`, `transmit`, `poll_event`, `poll_timeout`,
  `expire`, with `runtime::Instant`. TLS, SASL, mailboxes, maildrops, files
  and data connections are the application's.
- **The server answers what the RFCs decide, and tells the rest one at a
  time.** NOOP, QUIT, CAPA/CAPABILITY/FEAT, commands of the wrong state,
  extensions not offered, limits, and the refusals of security (passwords
  before TLS, the FTP bounce attack) are answered by the server itself.
  Every other command is an event, and the server reads nothing more until
  it is answered (pipelined commands wait in the input). An application
  that answers nothing therefore stops the session, which is visible, rather
  than having the server guess.
- **Unknown commands are answered negatively** (500, -ERR, BAD) unless
  their name is in the configuration's `commands`, which the application
  adds when it implements an extension. Telling every unknown command was
  considered and rejected: an application that does not know a command
  would have had to answer it itself, and one that forgot would stop the
  session.
- **Lines are CRLF only.** `bytes::LineBuffer` is shared by the four (it
  was SMTP's and was made a part of `bytes` for them, with
  `BytesError::LineTooLong`). A CR or an LF alone is part of a line, and
  each protocol decides what to do with it: SMTP refuses it in mail data
  (550), POP3 and FTP take it as text. A line too long fails once and its
  rest is skipped, so a peer cannot make a buffer grow.
- **TLS is an event, and what came before it is discarded.** After the
  positive reply to STARTTLS, STLS or AUTH TLS, the input received in the
  clear is dropped on both sides (RFC 3207 §4.2, RFC 2595 §3.1, RFC 9051
  §6.2.1, RFC 4217; CVE-2011-0411, where plaintext pipelined after
  STARTTLS was executed as if it came under TLS).
- **Capabilities are checked before use.** A client sends an extension
  only when the server announced it (EHLO, CAPA, CAPABILITY, FEAT), and
  never assumes one from another: IMAP4rev2 is in use only when announced
  and IMAP4rev1 is not, or after ENABLE.

## Passwords before TLS

The clients refuse to send a password as it is (USER and PASS, APOP,
LOGIN, AUTH PLAIN or LOGIN) without TLS while their configuration's
`passwords_require_tls` (true by default): RFC 2595 §2.3 says a client MUST
be configurable to refuse them, and a default that a forgotten setting turns
unsafe is no default. The field is of `SMTPConfig`, `POP3Config` and
`IMAPConfig`, which a client and a server share; a server's own is of its
server configuration. A client knows PLAIN and LOGIN as such mechanisms; a
list like the server's was not added, as a client chooses the mechanism it
sends. FTP has no such setting: anonymous FTP sends its password in the
clear by design.

For the servers:

`passwords_require_tls` (true by default) keeps the mechanisms that send a
password as it is from being offered or taken without TLS, with LOGIN,
USER and PASS and APOP. PLAIN (RFC 4616) is always such a mechanism;
`plaintext_mechanisms` lists others (LOGIN, say). PLAIN was first the
default content of that list. It was made unconditional when the C ABI
came: the lists of a configuration are arrays there, and a C program
that passed none would have offered PLAIN without TLS. A default that a
caller can lose by omission is not a safe default.

Mechanisms that do not send the password (SCRAM, EXTERNAL) are announced
before TLS too. POP3's RFC 5034 §6 example does so; RFC 9051 §6.2.3 only
requires LOGINDISABLED when LOGIN is refused.

## Messages: `codec::mail`

- **Fields are kept as written.** A `MailField` holds its value as it is in
  the message, folds included, and the typed accessors of `MailFields`
  read it when asked. A message with one bad field is still read, and
  writing a message read gives the same field values, folds and body; the
  name's spelling and the space after the colon are written as
  `Name: value` (`Subject:hi` becomes `Subject: hi`), which reads back the
  same.
- **Folding is done once, by `MailField::new`.** A field made by the
  application is folded at its spaces when made (lines of at most 78
  characters where the words allow, RFC 5322 §2.2.3), and `encode` writes
  every value as it is. `encode` used to fold a value without line breaks,
  taking such a value to be one the application made. A long value read
  from a message without folds is not one, and was folded when written:
  the fuzz target `codec-mail` found it, as a message that did not read
  back the same. Keeping a flag of where a value came from was considered
  and rejected: folding when made keeps one form, with nothing to keep in
  step. A fold is made only before a word, so that no line is of white
  space alone (§3.2.2), and a word too long for 998 characters is refused
  (§2.1.1).
- **Delimiters are found by prefix.** A line that begins with `--` and the
  boundary is a delimiter, whatever follows (RFC 2046 §5.1.1). Matching a
  whole line of the boundary and white space was the first reading; a
  review showed that a part with `--bX` was one part here and two in a
  reader that matches by prefix, the difference a filter is bypassed by.
- **RFC 2231 sections are grouped once.** Sorting the sections by name and
  number makes reading O(n log n); grouping by searching the list for each
  took 114 ms for one Content-Type of 8,000 parameters. The writer makes
  its sections longer than a line where a line each would number more than
  the 999 the reader takes.
- **`-0000` is kept.** `MailDate::zone_unknown` holds a local time not
  known (§3.3), and the military zones that §4.3 says SHOULD be taken so;
  it is written back as `-0000`, not `+0000`.
- **From is an address-list, Sender an address** (RFC 6854), so an empty
  group is a valid From.
- **Ambiguity is refused.** A parameter given twice, an RFC 2231
  continuation with a number missing or a leading zero, a boundary not of
  `bchars`: any of these could be read two ways, and two readers taking
  them differently is how filters are bypassed.
- **A Content-Type that cannot be read is text/plain** (RFC 2045 §5.2). A
  header section that cannot be read is no message to `MailMessage`, and
  an entity of no fields whose text is its body to `MIMEEntity`. A limit
  exceeded is an error to both.
- **Character sets.** US-ASCII, UTF-8, ISO-8859-1 and Windows-1252 are
  converted. The other ISO-8859 and Windows-125x sets are converted when
  the text is ASCII, because the example of RFC 2047 §8 is ISO-8859-2 of
  ASCII; their other bytes are `Charset`. A table for every set was left
  out as size for little use: mail of today is UTF-8.

## SMTP

- **What a client sends is checked as a line.** `SMTPCommand::check` and
  `POP3Command::check` refuse a command whose written line has a CR, an LF
  or a NUL, or does not read back; IMAP's client reads what it wrote back;
  FTP's encode refuses line breaks. A review found that a path or a domain
  of a line break, from a web form, became commands of its own.
- **Replies are timed from the one before.** A command's deadline is set
  when it becomes the oldest waiting, not when it is sent; with pipelining,
  13 replies 30 seconds apart closed the session at 300 seconds before.
- **A BDAT refused is read first** (RFC 3030 §2), in every refusing path,
  through `SMTPServer::refuse`.
- **`AuthFailed`** tells a failure the server answered itself; only `*` was
  told before, which left the application's SASL state stale.

- **Mail data ends at CRLF.CRLF only.** Data with a bare CR or LF is not
  taken (550, `DataRejected`): SMTP smuggling makes one server see the end
  of a message where the next does not.
- **The client keeps transactions by number.** A refused MAIL ends its
  transaction; a refused DATA or chunk does not, until RSET, so the client
  never pairs a reply with the wrong message when pipelining.
- **Replies the server writes carry status codes** where
  ENHANCEDSTATUSCODES is advertised: a reply given without one gets `c.0.0`
  of its class, so the application need not know RFC 3463 to be right.
- **An AUTH initial response too long for the line** waits for the server's
  empty 334 (RFC 4954 §4).
- **MX ordering** shuffles each preference with the caller's generator, and
  a null MX alone or no host left is `NoMail` (RFC 7505).

## POP3

- **A multi-line response is timed from its last octets,** and the next
  command from the end of it; before, a stalled RETR was never timed out,
  and a pipelined command timed out behind a long one.
- **`maximum_data_line` was removed:** the lines of a response are streamed,
  so a limit of them bounds nothing, and the field was never used.

- **Multi-line responses are normalized to CRLF** by the server's writer,
  periods added; a maildrop stored with LF alone is sent right.
  `canonical_length` gives the size LIST must report for such a message
  (RFC 6856 §2.1). The added periods are not counted: they are not of the
  message.
- **Response codes only with RESP-CODES**: the server drops them otherwise,
  so a client of RFC 1939 alone never sees one.
- **The autologout timer closes without a response** (RFC 1939 §3).
- **APOP is behind `hash-md-v5` and `secret`** and compares in constant
  time. It is MD5, so it is for servers that have nothing better, under TLS.

## IMAP

- **No literal octets are taken as commands.** A command over
  `maximum_command` keeps its line, so the literal it announces is read and
  dropped. A line over `maximum_line` is skipped by `LineBuffer`, so its
  end, and so a literal it may announce, is not known (`IMAPLineReader::
  lost`): the session ends with BYE, which RFC 7888 §4 allows. Keeping the
  tail of a skipped line to find a literal was considered; it would make
  `LineBuffer` keep part of what it skips for one protocol.
- **Extensions are read as they are.** `IMAPResponse::Other` and
  `IMAPFetchItem::Other` keep what an extension sends (RFC 9051 §7); a
  client closed on `* QUOTA` before.
- **STARTTLS forgets IMAP4rev2.** A man in the middle that announced
  IMAP4rev2 before TLS made the client send non-synchronizing literals and
  UTF-8 names to a server of IMAP4rev1. While capabilities are unknown
  after TLS, AUTHENTICATE and its initial response and ENABLE are not
  stopped, as in the sample of RFC 9051 §8, whose client sends them without
  CAPABILITY.
- **IMAP4rev1 needs text.** A status response of no text gets its
  condition's name as text for a client of IMAP4rev1 (RFC 3501 §9 `text`);
  IMAP4rev2 lets it be absent.

- **Productions, not a tree.** IMAP's grammar is contextual (an atom here
  is a string there, `]` ends a section but not an atom elsewhere), so
  `IMAPReader` and `IMAPWriter` have a method per production of RFC 9051
  §9 rather than one generic parse tree that every user would interpret.
- **Logical lines.** `IMAPLineReader` joins a line and its literals; a
  literal too large is refused before it is sent if synchronizing (NO
  [LIMIT]) and dropped if not (BAD [LIMIT]), so its octets are never taken
  as commands.
- **The client waits for commands that change the state**, and pipelines
  only those whose results an EXPUNGE cannot change (§5.5).
- **IMAP4rev1 compatibility** is a configuration of the server (`rev1`):
  modified UTF-7, LSUB and CHECK, and ESEARCH only on RETURN, until the
  client enables IMAP4rev2.
- **BODYSTRUCTURE** is made from `codec::mail::MIMEEntity`; its line count
  is the number of LF of a text part. RFC 2231 parameters with a character
  set are returned in the `name*` form.

## FTP

- **The session's settings are kept,** TYPE, MODE, STRU, PROT and REST, for
  the application to transfer by, and reset by AUTH TLS and REIN; REIN
  clears TLS (RFC 4217 §13), told as `ClearCommandChannel`.
- **STAT during a transfer** has its reply before the transfer's; the
  client paired them in order before.
- **Telnet IAC** before a byte of no Telnet command is dropped alone, so that
  ABOR after IP and an out-of-band DM is ABOR.

- **The control connection only.** The data connections are sockets of the
  application, at the `FTPDataAddress` of PORT, PASV, EPRT and EPSV; a
  connection of its own would have needed I/O.
- **The bounce attack is refused by default** (RFC 2577 §3): PORT and EPRT
  may name only the client's host and a port of 1024 or more.
- **TYPE, MODE and STRU** are the minimum of RFC 959 §5.1, answered by the
  server.
- **A middle line of a reply that begins with three digits is padded** when
  written (RFC 959 §4.2: the server must). The reader takes an unpadded one
  as text, so writing what was read is not always the bytes read: the fuzz
  target checks that the written form is a fixed point instead.

## The C ABI and Python

- **Commands and replies cross as their text on the wire**, as DNS records
  cross as presentation text: SMTP and FTP replies with their CRLFs,
  command and status lines without, IMAP's as logical lines with their
  literals and UTF-8 mailbox names. A structure per command and response
  was the alternative: the four protocols have well over a hundred
  variants, which would have made a large C ABI to keep in step with Rust
  for no gain, since the text is the canonical form and the Rust side
  checks it (`*_normalize`).
- **Events are a kind number and buffers** (command, reply or response,
  data, an error status), the same shape in the four, so that a binding
  writes one loop.
- **Configurations are structures of their scalars**, and their lists and
  texts are arguments beside them, as arrays of strings.
- **Helpers that are not about one protocol moved to the FFI core**:
  `Pointer::write_optional` (a value and whether it is there) replaces the
  copies the modules had, TLS, HTTP and CoAP included.
- **`poll_event` checks every output before it takes the event,** so a null
  output fails without losing it. `*_server_wants_receive` is exported for
  the four servers: without it a C or Python application could not apply
  back-pressure, and the input held would grow without bound.
- **FTP's session state** is one call, `ftp_server_session`, and in Python
  `FTPServer.session()`, a value of its fields (`FTPSession`), since a
  binding cannot read Rust fields.
- **Python names that differ:** `POP3Response.positive` and `negative`
  (the Rust `ok`, `error`, `error_with`: `ok` is a field), `MIMECharset.
  preferred_name` (the Rust `name`, which an `Enum` member cannot have),
  `SMTPEnhancedStatus.class_` (`class` is a keyword). The defaults of the
  lists of a server's configuration are repeated in Python, because a C
  structure cannot carry them.

## Testing

The Rust tests take the dialogues and examples of the RFCs from their text
in `tests/vectors/protocol/<protocol>/` (RFC 5321 appendix D, RFC 1939
§10, RFC 9051 §8 and its examples, RFC 959 §7, RFC 3659). The FFI tests
and pytest run sessions through the C ABI; pytest also runs the servers
against Python's smtplib, poplib, imaplib and ftplib over sockets.
`examples/mail.sh` and `examples/ftp.sh` run the examples against Postfix,
Dovecot, vsftpd and curl in Docker.

## Open points

- An IMAP server cannot ENABLE the extensions it adds with `capabilities`.
- The protocol C ABIs (of this phase and the earlier ones) do not check
  that a scalar output does not overlap an input range, which docs/ffi.md
  promises (`Pointer::check_ranges`).
