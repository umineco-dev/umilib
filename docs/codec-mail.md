# Internet messages and MIME: `umilib::codec::mail`

`codec-mail` (no `std`) reads and writes Internet messages (RFC 5322, with
UTF-8 by RFC 6532) and MIME (RFC 2045, RFC 2046, RFC 2047, RFC 2183, RFC
2231). IMAP builds its ENVELOPE and BODYSTRUCTURE from it.

| Type | What it is |
| --- | --- |
| `MailMessage` | A message: its fields and its body; `validate` checks RFC 5322 §3.6 |
| `MailFields`, `MailField` | The header fields in order, each with its name and its value as written (folds kept) |
| `MailAddress`, `MailMailbox` | An address (a mailbox or a group) and a mailbox (a display name and an addr-spec) |
| `MailDate` | A date-time: seconds since 1970 and the zone's offset |
| `MailMessageID` | A msg-id |
| `MIMEEntity`, `MIMEMultipart` | An entity and its parts, as ranges of the text read; a multipart body split and written |
| `MIMEContentType`, `MIMEParameters`, `MIMEParameter` | Content-Type and its parameters, RFC 2231 continuations and charsets included |
| `MIMEDisposition` | Content-Disposition (RFC 2183) |
| `MIMETransferEncoding`, `MIMEQuotedPrintable` | Content-Transfer-Encoding: 7bit, 8bit, binary, quoted-printable, base64 |
| `MIMEEncodedWord`, `MIMEWordEncoding` | The encoded words of RFC 2047 (`=?charset?Q?...?=`) |
| `MIMECharset` | The character sets converted: US-ASCII, UTF-8, ISO-8859-1 and Windows-1252 (the other ISO-8859 and Windows-125x sets when the text is ASCII) |
| `MailConfig` | The limits of reading: a message's length, a field's length, the fields, parts and nesting |
| `MailReader` | The lexical tokens of RFC 5322 §3.2 (atoms, quoted strings, comments, folding white space) |

## Messages

```rust
use umilib::codec::mail::{MailConfig, MailMessage};

let message = MailMessage::decode(text, &MailConfig::default())?;
message.validate()?; // a Date and a From, the single fields at most once
let from = message.fields.addresses("From")?; // None if there is no From
let subject = message.fields.text("Subject")?; // encoded words decoded
let bytes = message.encode();
```

- A field is kept as it was written. The typed accessors of `MailFields`
  (`date`, `addresses`, `mailboxes`, `mailbox`, `address`, `message_ids`,
  `text`, each by the field's name) read its value when asked, so a field that cannot be read does not stop
  the rest of the message from being read.
- From is an address-list and Sender an address, as RFC 6854 has them: an
  empty group (`Undisclosed recipients:;`) is a valid From. Read From with
  `addresses` (`mailboxes` fails on a group). The mailboxes of a group are
  separated by commas (§3.4).
- `MailField::new` folds a value at its spaces (lines of at most 78
  characters where the words allow, never a line of white space alone) and
  refuses a word too long for a line of 998 characters (§2.1.1); a field
  read is written as it was read, its folds kept.
- A message whose header section cannot be read is no message to
  `MailMessage::decode`; `MIMEEntity::decode` reads it as an entity of no
  fields whose whole text is its body. A limit exceeded is an error either
  way.

## MIME

`MIMEEntity::decode` reads an entity and, for a multipart or a
`message/rfc822`, its parts, to `maximum_parts` and `maximum_depth`. The
parts are ranges of the text read, so nothing is copied until `data`
decodes a part's body (base64 or quoted-printable).

- A Content-Type that cannot be read is `text/plain; charset=us-ascii`
  (RFC 2045 §5.2).
- A boundary is 1 to 70 characters of `bchars` (RFC 2046 §5.1.1). A line
  that begins with `--` and the boundary is a delimiter, whatever follows
  it (§5.1.1: the boundary MUST NOT be the prefix of a line of a part), so
  that `--bX` ends a part of the boundary `b` here as in every other reader.
  `MIMEMultipart::encode` refuses a part with a line that begins so.
- A parameter given twice, or an RFC 2231 continuation with a number
  missing or a leading zero, is refused: its value would be ambiguous.
- Encoded words (RFC 2047) are decoded by `MailFields::text` and
  `MIMEEncodedWord::decode_text`, in unstructured text; white space between
  two encoded words is dropped (§6.2). A display name is kept as written:
  decode it with `decode_text` where it is a phrase, not a quoted string
  (§5 (3)).
- A date of `-0000`, or of a military zone (which §4.3 says SHOULD be taken
  so), has `zone_unknown`: its local time is not known, and it is written
  back as `-0000`. ISO-8859
  and Windows-125x text is decoded when it is ASCII alone (the example of
  §8 is ISO-8859-2 of ASCII); other bytes of those sets are `Charset`.

## Python and C

`umilib.codec.mail` mirrors the types above (`MIMECharset.preferred_name`
is the Rust `name`, which an `Enum` member cannot have). `MailReader` and
`MIMEParameterSection` borrow the text they read, so they are not in the C
ABI; the rest is, in `include/umilib/codec/mail.h`.

## Not implemented

The obsolete syntax of RFC 5322 §4 is read where the grammar allows it but
never written. Character sets beyond those above: decode them with a
character set library from the `charset` parameter.
