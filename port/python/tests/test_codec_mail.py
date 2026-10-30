"""Tests of umilib.codec.mail against the examples of RFC 5322 Appendix A, RFC 2046, RFC 2047 §8,
RFC 2231 and RFC 2183, RFC 6854, and the rules of each."""

import email.utils

import pytest

from umilib.codec.mail import (
    MIMECharset,
    MIMEContentType,
    MIMEDisposition,
    MIMEEncodedWord,
    MIMEEntity,
    MIMEMultipart,
    MIMEParameter,
    MIMEParameters,
    MIMEQuotedPrintable,
    MIMETransferEncoding,
    MIMEWordEncoding,
    MailAddress,
    MailConfig,
    MailDate,
    MailError,
    MailField,
    MailFields,
    MailMailbox,
    MailMessage,
    MailMessageID,
)

# RFC 5322 Appendix A.1.2 and A.1.3.
A_1_2 = (
    b"From: \"Joe Q. Public\" <john.q.public@example.com>\r\n"
    b"To: Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>\r\n"
    b"Cc: <boss@nil.test>, \"Giant; \\\"Big\\\" Box\" <sysservices@example.net>\r\n"
    b"Date: Tue, 1 Jul 2003 10:52:37 +0200\r\n"
    b"Message-ID: <5678.21-Nov-1997@example.com>\r\n"
    b"\r\n"
    b"Hi everyone.\r\n"
)
A_1_3_TO = b"A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;"

# RFC 2046 §5.1.1.
SIMPLE = (
    b"From: Nathaniel Borenstein <nsb@bellcore.com>\r\n"
    b"To: Ned Freed <ned@innosoft.com>\r\n"
    b"Date: Sun, 21 Mar 1993 23:56:48 -0800 (PST)\r\n"
    b"Subject: Sample message\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-type: multipart/mixed; boundary=\"simple boundary\"\r\n"
    b"\r\n"
    b"This is the preamble.\r\n"
    b"\r\n"
    b"--simple boundary\r\n"
    b"\r\n"
    b"This is implicitly typed plain US-ASCII text.\r\n"
    b"It does NOT end with a linebreak.\r\n"
    b"--simple boundary\r\n"
    b"Content-type: text/plain; charset=us-ascii\r\n"
    b"\r\n"
    b"This is explicitly typed plain US-ASCII text.\r\n"
    b"It DOES end with a linebreak.\r\n"
    b"\r\n"
    b"--simple boundary--\r\n"
    b"\r\n"
    b"This is the epilogue.  It is also to be ignored.\r\n"
)


def test_appendix_a_1_2_mailboxes():
    message = MailMessage.decode(A_1_2)
    message.validate()
    fields = message.fields
    assert fields.mailboxes("From") == [MailMailbox("Joe Q. Public", "john.q.public", "example.com")]
    assert fields.addresses("To") == [
        MailAddress.Mailbox(MailMailbox("Mary Smith", "mary", "x.test")),
        MailAddress.Mailbox(MailMailbox(None, "jdoe", "example.org")),
        MailAddress.Mailbox(MailMailbox("Who?", "one", "y.test")),
    ]
    cc = fields.addresses("Cc")
    assert cc[1] == MailAddress.Mailbox(MailMailbox('Giant; "Big" Box', "sysservices", "example.net"))
    assert str(cc[1]) == '"Giant; \\"Big\\" Box" <sysservices@example.net>'
    assert fields.date("Date") == MailDate(1057049557, 120)
    assert fields.message_ids("Message-ID") == [MailMessageID("5678.21-Nov-1997", "example.com")]
    assert message.body == b"Hi everyone.\r\n"
    assert MailMessage.decode(message.encode()).fields.entries == fields.entries


def test_appendix_a_1_3_groups_and_dates_against_the_standard_library():
    to = MailAddress.parse_list(A_1_3_TO)
    assert to == [
        MailAddress.Group("A Group", (MailMailbox("Ed Jones", "c", "a.test"), MailMailbox(None, "joe", "where.test"), MailMailbox("John", "jdoe", "one.test")))
    ]
    assert MailAddress.parse_list(MailAddress.format_list(to).encode()) == to
    assert MailAddress.parse_list(b"Undisclosed recipients:;") == [MailAddress.Group("Undisclosed recipients")]
    # The instant agrees with Python's own reading of the date.
    text = "Thu, 13 Feb 1969 23:32:54 -0330"
    date = MailDate.parse(text.encode())
    assert date.seconds == int(email.utils.parsedate_to_datetime(text).timestamp())
    assert date.offset == -210
    assert str(date) == text


def test_rfc6854_groups_in_from():
    robot = MailMessage.decode(b"From: Nightly Monitor Robot:;\r\nDate: 1 Jan 2013 00:00:00 +0000\r\n\r\n")
    robot.validate()
    partners = MailMessage.decode(b"From: ben@example.com,carol@example.com\r\nDate: 1 Jan 2013 00:00:00 +0000\r\n\r\n")
    with pytest.raises(MailError) as error:
        partners.validate()
    assert error.value.name == "Syntax"


def test_fields_and_folding():
    fields = MailFields()
    fields.push("Subject", b" ".join([b"word"] * 60))
    fields.push("X-Mailer", b"umilib")
    fields.set("subject", b"short")
    assert [field.name for field in fields.entries] == ["subject", "X-Mailer"], "replaced where the first was, by the name given"
    assert fields.get("SUBJECT") == b"short"
    with pytest.raises(MailError):
        fields.push("Bad Name", b"x")
    with pytest.raises(MailError):
        fields.push("Subject", b"a\r\nb")
    long = MailFields()
    long.push("Subject", b" ".join([b"word"] * 60))
    encoded = long.encode()
    assert all(len(line) <= MailField.LINE + 1 for line in encoded.split(b"\n"))
    decoded, body = MailFields.decode(encoded + b"\r\n")
    assert body == len(encoded) + 2
    assert decoded.entries[0].unfolded() == b" ".join([b"word"] * 60)
    assert MailField.is_name("Received") and not MailField.is_name("a:b")


def test_limits():
    with pytest.raises(MailError) as error:
        MailFields.decode(b"A: 1\r\nB: 2\r\nC: 3\r\n\r\n", MailConfig(maximum_fields=2))
    assert error.value.name == "TooMany"
    with pytest.raises(MailError):
        MailMessage.decode("From: é@example.com\r\n\r\n".encode(), MailConfig(utf8=False))


def test_rfc2047_encoded_words():
    assert MIMEEncodedWord.decode_text(b"=?US-ASCII?Q?Keith_Moore?=") == "Keith Moore"
    assert MIMEEncodedWord.decode_text(b"=?ISO-8859-1?Q?Keld_J=F8rn_Simonsen?=") == "Keld Jørn Simonsen"
    subject = b"=?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?=\r\n =?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?="
    assert MIMEEncodedWord.decode_text(subject) == "If you can read this you understand the example."
    assert MIMEEncodedWord.decode_text(b"=?ISO-8859-1?Q?a?= =?ISO-8859-2?Q?_b?=") == "a b"
    word = MIMEEncodedWord.parse(b"=?US-ASCII*EN?Q?Keith_Moore?=")
    assert (word.charset, word.language, word.encoding, word.data) == ("US-ASCII", "EN", MIMEWordEncoding.Q, b"Keith Moore")
    assert word.text() == "Keith Moore"
    assert word.encode() == "=?US-ASCII*EN?Q?Keith_Moore?="
    text = "日本語の件名" * 10
    encoded = MIMEEncodedWord.encode_text(text)
    assert all(len(part) <= MIMEEncodedWord.MAXIMUM_LENGTH for part in encoded.split(" "))
    assert MIMEEncodedWord.decode_text(encoded.encode()) == text
    assert MIMEEncodedWord.decode_q(b"a_b=3F") == b"a b?"


def test_charsets():
    assert MIMECharset.from_name("latin1") is MIMECharset.ISO88591
    assert MIMECharset.from_name("x-unknown") is None
    assert MIMECharset.UTF8.preferred_name() == "UTF-8"
    assert MIMECharset.Windows1252.decode(b"\x80") == "€"
    assert MIMECharset.ISO88591.encode("é") == b"\xe9"
    assert MIMECharset.decode_named("ISO-8859-2", b"abc") == "abc"
    with pytest.raises(MailError) as error:
        MIMECharset.decode_named("Shift_JIS", b"abc")
    assert error.value.name == "Charset"


def test_quoted_printable_and_base64():
    text = MIMEQuotedPrintable()
    assert text.decode(b"caf=E9 =\r\nau lait  \r\n") == b"caf\xe9 au lait\r\n"
    data = bytes(range(256)) * 3
    binary = MIMEQuotedPrintable(binary=True)
    assert binary.decode(binary.encode(data)) == data
    assert all(len(line.rstrip(b"\r")) <= MIMEQuotedPrintable.LINE for line in binary.encode(data).split(b"\n"))
    assert MIMETransferEncoding.parse(b" BASE64 ") == MIMETransferEncoding.Base64
    assert MIMETransferEncoding.Base64.decode(b"aGVs\r\nbG8=") == b"hello"
    assert MIMETransferEncoding.decode_base64(b"aGVs bG8") == b"hello"
    assert MIMETransferEncoding.Base64.decode(MIMETransferEncoding.Base64.encode(data)) == data
    assert MIMETransferEncoding.SevenBit.is_identity()
    with pytest.raises(MailError) as error:
        MIMETransferEncoding.Other("x-uuencode").decode(b"x")
    assert error.value.name == "Encoding"


def test_content_types_and_rfc2231_parameters():
    content_type = MIMEContentType.parse(b"TEXT/Plain; CHARSET=\"us-ascii\" (Plain text)")
    assert content_type.is_("text", "plain")
    assert content_type.parameters.text("charset") == "us-ascii"
    stuff = MIMEContentType.parse(b"application/x-stuff;\r\n title*0*=us-ascii'en'This%20is%20even%20more%20;\r\n title*1*=%2A%2A%2Afun%2A%2A%2A%20;\r\n title*2=\"isn't it!\"")
    title = stuff.parameters.get("title")
    assert (title.charset, title.language, title.text()) == ("us-ascii", "en", "This is even more ***fun*** isn't it!")
    with pytest.raises(MailError):
        MIMEContentType.parse(b"a/b; t*0=x; t*2=y")
    built = MIMEContentType("multipart", "mixed")
    parameters = MIMEParameters()
    parameters.set(MIMEParameter("boundary", b"simple boundary"))
    built.parameters = parameters
    assert str(built) == 'multipart/mixed; boundary="simple boundary"'
    assert built.boundary() == b"simple boundary"
    assert MIMEContentType.default_text().format() == "text/plain; charset=us-ascii"
    assert MIMEContentType.default_digest().is_message()


def test_rfc2183_dispositions():
    disposition = MIMEDisposition.parse(b"attachment; filename=genome.jpeg;\r\n  modification-date=\"Wed, 12 Feb 1997 16:29:51 -0500\";")
    assert disposition.kind == "attachment" and not disposition.is_inline()
    assert disposition.filename() == "genome.jpeg"
    assert MIMEDisposition.parse(b"attachment; filename=\"../../etc/passwd\"").filename() == "passwd"
    name = "日本語.txt"
    built = MIMEDisposition("attachment")
    parameters = MIMEParameters()
    parameters.set(MIMEParameter("filename", name.encode()))
    built.parameters = parameters
    assert built.format().isascii()
    assert MIMEDisposition.parse(built.format().encode()).filename() == name


def test_rfc2046_multipart():
    entity = MIMEEntity.decode(SIMPLE)
    assert entity.content_type.is_multipart()
    first, second = entity.parts
    assert first.fields.entries == []
    assert SIMPLE[first.body.start : first.body.stop] == b"This is implicitly typed plain US-ASCII text.\r\nIt does NOT end with a linebreak."
    assert second.content_type.parameters.text("charset") == "us-ascii"
    assert second.data(SIMPLE) == b"This is explicitly typed plain US-ASCII text.\r\nIt DOES end with a linebreak.\r\n"
    multipart = MIMEMultipart.split(SIMPLE, entity.body, b"simple boundary")
    assert multipart.closed
    assert len(multipart.parts) == 2
    assert SIMPLE[multipart.epilogue.start : multipart.epilogue.stop] == b"\r\nThis is the epilogue.  It is also to be ignored.\r\n"
    assert MIMEMultipart.delimiter(b"--b--\r\n", b"b") is True
    # RFC 2046 §5.1.1: a line that begins with the boundary is a delimiter, whatever follows.
    assert MIMEMultipart.delimiter(b"--bc\r\n", b"b") is False
    assert MIMEMultipart.delimiter(b" --b\r\n", b"b") is None
    with pytest.raises(MailError):
        MIMEMultipart.encode(b"b", [b"x\r\n--b\r\ny"])


def test_nested_messages_and_their_parts():
    inner = b"Subject: inner\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=C3=A9"
    attachment = b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=x.bin\r\n\r\naGVsbG8="
    head = b"From: a@example.com\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n"
    text = head + MIMEMultipart.encode(b"outer", [b"Content-Type: message/rfc822\r\n\r\n" + inner, attachment])
    entity = MIMEEntity.decode(text)
    message = entity.parts[0].message
    assert message is not None
    assert message.fields.text("Subject") == "inner"
    assert message.encoding == MIMETransferEncoding.QuotedPrintable
    assert message.data(text).decode("utf-8") == "café"
    assert entity.parts[1].disposition().filename() == "x.bin"
    assert entity.parts[1].data(text) == b"hello"
    with pytest.raises(MailError) as error:
        MIMEEntity.decode(text, MailConfig(maximum_depth=1))
    assert error.value.name == "TooMany"
