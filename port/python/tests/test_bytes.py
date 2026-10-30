"""Tests of umilib.bytes, mirroring the Rust tests: network byte order is
most significant byte first, little-endian is least significant byte first,
and failed operations change nothing."""

import pytest

from umilib.bytes import Buffer, BytesError, Integer, LineBuffer, Reader, SliceWriter

DATA = bytes(range(1, 17))


def test_reads_big_endian_integers():
    assert Reader(DATA).read_be(Integer.U8) == 0x01
    assert Reader(DATA).read_be(Integer.U16) == 0x0102
    assert Reader(DATA).read_be(Integer.U32) == 0x01020304
    assert Reader(DATA).read_be(Integer.U64) == 0x0102030405060708
    assert Reader(DATA).read_be(Integer.U128) == 0x0102030405060708090A0B0C0D0E0F10


def test_reads_little_endian_integers():
    assert Reader(DATA).read_le(Integer.U16) == 0x0201
    assert Reader(DATA).read_le(Integer.U32) == 0x04030201
    assert Reader(DATA).read_le(Integer.U128) == 0x100F0E0D0C0B0A090807060504030201


def test_reads_signed_integers_in_twos_complement():
    assert Reader(b"\xff").read_be(Integer.I8) == -1
    assert Reader(b"\x80\x00").read_be(Integer.I16) == -32768
    assert Reader(b"\xfe\xff\xff\xff").read_le(Integer.I32) == -2
    assert Reader(b"\xff" * 16).read_be(Integer.I128) == -1


def test_sized_reads_and_sign_extension():
    reader = Reader(b"\x01\x00\x00\xaa")
    assert reader.read_be_sized(Integer.U32, 3) == 0x010000
    assert reader.position() == 3
    assert Reader(b"\xff\xfe").read_be_sized(Integer.I32, 2) == -2
    assert Reader(b"\xfe\xff").read_le_sized(Integer.I64, 2) == -2
    assert Reader(b"\xff\xff").read_be_sized(Integer.U32, 2) == 0xFFFF
    for length in (0, 5):
        with pytest.raises(BytesError) as error:
            Reader(bytes(16)).read_be_sized(Integer.U32, length)
        assert error.value.name == "InvalidLength"
    with pytest.raises(BytesError):
        Reader.check_length(Integer.U8, 2)
    Reader.check_length(Integer.U128, 16)


def test_failed_reads_do_not_move_the_cursor():
    reader = Reader(b"\x01\x02\x03")
    reader.read_u8()
    for operation in (lambda: reader.read_be(Integer.U32), lambda: reader.read_slice(3), lambda: reader.skip(3),
                      lambda: reader.read_array(3), lambda: reader.read_reader(3)):
        with pytest.raises(BytesError) as error:
            operation()
        assert error.value.name == "UnexpectedEnd"
    assert (reader.position(), reader.remaining()) == (1, 2)
    assert reader.read_be(Integer.U16) == 0x0203
    assert reader.is_empty()


def test_slices_and_nested_readers():
    reader = Reader(b"\x00\x02\xab\xcd\xef")
    length = reader.read_be(Integer.U16)
    inner = reader.read_reader(length)
    assert inner.remaining() == 2
    assert inner.peek(1) == b"\xab"
    assert inner.read_le(Integer.U16) == 0xCDAB
    assert reader.read_rest() == b"\xef"
    assert reader.read_rest() == b""
    assert Reader(b"").read_slice(0) == b""
    assert Reader(b"\x0a\x14").read_array(2) == b"\x0a\x14"


def test_writes_and_round_trips():
    buffer = Buffer.new()
    buffer.write_be(Integer.U32, 0x01020304)
    buffer.write_le(Integer.U32, 0x01020304)
    buffer.write_be(Integer.I16, -2)
    buffer.write_u8(0xAA)
    buffer.write_be(Integer.U128, (1 << 128) - 2)
    buffer.write_le(Integer.I128, -(1 << 127) + 1)
    assert buffer.as_slice()[:11] == bytes([1, 2, 3, 4, 4, 3, 2, 1, 0xFF, 0xFE, 0xAA])
    reader = Reader(buffer.as_slice())
    reader.skip(11)
    assert reader.read_be(Integer.U128) == (1 << 128) - 2
    assert reader.read_le(Integer.I128) == -(1 << 127) + 1
    assert len(buffer) == buffer.len() == 43
    with pytest.raises(OverflowError):
        buffer.write_be(Integer.U8, 256)


def test_sized_writes_must_fit():
    for value in (0, 1, 0xFF, 0x1234, 0xFFFFFF, 0x100000000):
        for length in range(1, 9):
            buffer = Buffer()
            fits = length == 8 or value < 1 << (8 * length)
            if fits:
                buffer.write_be_sized(Integer.U64, value, length)
                assert Reader(buffer.as_slice()).read_be_sized(Integer.U64, length) == value
                little = Buffer()
                little.write_le_sized(Integer.U64, value, length)
                assert Reader(little.as_slice()).read_le_sized(Integer.U64, length) == value
            else:
                with pytest.raises(BytesError) as error:
                    buffer.write_be_sized(Integer.U64, value, length)
                assert error.value.name == "ValueTooLarge"
                assert buffer.is_empty()
    for value, length, fits in ((-1, 1, True), (-128, 1, True), (-129, 1, False), (128, 1, False), (0x7FFFFF, 3, True)):
        buffer = Buffer()
        if fits:
            buffer.write_be_sized(Integer.I32, value, length)
            assert Reader(buffer.as_slice()).read_be_sized(Integer.I32, length) == value
        else:
            with pytest.raises(BytesError):
                buffer.write_be_sized(Integer.I32, value, length)


def test_limits():
    buffer = Buffer.with_limit(4)
    assert buffer.limit() == 4
    buffer.write(b"\x01\x02\x03")
    with pytest.raises(BytesError) as error:
        buffer.write(b"\x04\x05")
    assert error.value.name == "CapacityExceeded"
    assert buffer.as_slice() == b"\x01\x02\x03"
    buffer.write_u8(4)
    with pytest.raises(BytesError):
        buffer.set_limit(2)
    buffer.set_limit(None)
    assert buffer.limit() is None
    buffer.write_u8(5)
    buffer.truncate(2)
    assert buffer.as_slice() == b"\x01\x02"
    buffer.clear()
    assert buffer.is_empty()
    assert Buffer.from_bytes(b"\x09\x08").into_vec() == b"\x09\x08"
    assert Buffer.with_capacity(16).is_empty()


def test_slice_writer_fills_a_bytearray():
    storage = bytearray(6)
    writer = SliceWriter(storage)
    writer.write_be(Integer.U16, 0x0102)
    writer.write_le(Integer.U16, 0x0304)
    assert (writer.position(), writer.remaining()) == (4, 2)
    assert writer.written() == b"\x01\x02\x04\x03"
    with pytest.raises(BytesError):
        writer.write_be(Integer.U32, 1)
    assert writer.into_written() == b"\x01\x02\x04\x03"
    assert storage == bytearray(b"\x01\x02\x04\x03\x00\x00")


def test_capacities():
    buffer = Buffer.try_with_capacity(64)
    assert buffer.capacity() >= 64
    with pytest.raises(BytesError) as error:
        Buffer.with_capacity((1 << 63) - 1)
    assert error.value.name == "CapacityExceeded"
    storage = bytearray(5)
    writer = SliceWriter(storage)
    assert writer.capacity() == 5
    writer.close()
    storage.extend(b"resizable again")
    assert Integer.maximum_size() == 16


def test_line_buffers_read_lines_of_crlf():
    lines = LineBuffer()
    lines.push(b"EHLO a\r\nNO")
    assert lines.line(1000) == b"EHLO a"
    assert lines.line(1000) is None and lines.unread() == b"NO"
    # A CR or an LF alone ends no line.
    lines.push(b"OP\nx\ry\r")
    assert lines.line(1000) is None
    lines.push(b"\n")
    assert lines.line(1000) == b"NOOP\nx\ry"
    assert lines.is_empty() and len(lines) == 0


def test_line_buffers_skip_a_line_too_long_once():
    lines = LineBuffer()
    # The limit counts the CRLF: 4 octets and CRLF are 6.
    lines.push(b"abcd\r\nok\r\n")
    with pytest.raises(BytesError) as raised:
        lines.line(5)
    assert raised.value.name == "LineTooLong"
    assert lines.line(5) == b"ok"
    # A line that is too long before its end fails once, and its rest is skipped as it comes.
    lines.push(b"0123456789")
    with pytest.raises(BytesError):
        lines.line(5)
    lines.push(b"more\r")
    assert lines.line(5) is None
    lines.push(b"\nnext\r\n")
    assert lines.line(10) == b"next"


def test_line_buffers_read_counted_bytes():
    lines = LineBuffer()
    lines.push(b"{5}\r\nhello world")
    assert lines.line(100) == b"{5}"
    assert lines.take(5) == b"hello"
    lines.consume(1)
    assert lines.unread() == b"world" and lines.len() == 5
    lines.clear()
    assert lines.is_empty()
