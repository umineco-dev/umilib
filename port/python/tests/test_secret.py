"""Tests of umilib.secret: constant-time operations agree with ordinary ones,
and zeroization leaves only zeros."""

import pytest

from umilib.ffi import FFIError
from umilib.secret import Choice, ConditionallySelectable, ConstantTimeEq, Secret, Zeroize


def test_choice_follows_boolean_logic():
    for a in (False, True):
        for b in (False, True):
            x, y = Choice.from_bool(a), Choice.from_bool(b)
            assert (x & y).into_bool() == (a and b)
            assert (x | y).into_bool() == (a or b)
            assert (x ^ y).into_bool() == (a != b)
        assert (~Choice.from_bool(a)).into_bool() == (not a)
    assert Choice.from_bit(0xFE).bit() == 0
    assert Choice.from_bit(0x03).bit() == 1
    assert Choice.TRUE.into_bool() and not Choice.FALSE.into_bool()
    assert repr(Choice.TRUE) == "Choice(..)"


def test_equality_matches_ordinary_equality():
    assert ConstantTimeEq.ct_eq(b"secret value", b"secret value").into_bool()
    assert not ConstantTimeEq.ct_eq(b"secret value", b"secret valuE").into_bool()
    assert not ConstantTimeEq.ct_eq(b"secret value", b"secret valu").into_bool()
    assert ConstantTimeEq.ct_eq(b"", b"").into_bool()
    assert ConstantTimeEq.ct_ne(b"a", b"b").into_bool()


def test_selection():
    assert ConditionallySelectable.select(b"abcd", b"abce", Choice.TRUE) == b"abce"
    assert ConditionallySelectable.select(b"abcd", b"abce", Choice.FALSE) == b"abcd"
    target = bytearray(b"xx")
    ConditionallySelectable.conditional_assign(target, b"yy", Choice.FALSE)
    assert target == b"xx"
    ConditionallySelectable.conditional_assign(target, b"yy", Choice.TRUE)
    assert target == b"yy"
    a, b = bytearray(b"12"), bytearray(b"34")
    ConditionallySelectable.conditional_swap(a, b, Choice.TRUE)
    assert (a, b) == (bytearray(b"34"), bytearray(b"12"))
    with pytest.raises(FFIError):
        ConditionallySelectable.select(b"a", b"bc", Choice.TRUE)
    ConditionallySelectable.conditional_swap(a, a, Choice.TRUE)
    assert a == bytearray(b"34"), "swapping a sequence with itself changes nothing"


def test_zeroize_and_secret():
    data = bytearray(b"\xaa" * 32)
    Zeroize.zeroize(data)
    assert data == bytearray(32)
    Zeroize.zeroize(bytearray())

    source = bytearray(b"key")
    secret = Secret(source)
    assert source == bytearray(3), "the source copy is zeroized"
    assert repr(secret) == "Secret(..)"
    view = secret.expose_mut()
    view[0] = ord("K")
    assert secret.expose() == b"Key"
    assert secret.ct_eq(Secret(b"Key")).into_bool()
    assert not secret.ct_eq(Secret(b"key")).into_bool()
    with pytest.raises(FFIError) as error:
        secret.close()
    assert error.value.name == "Borrowed"
    del view
    secret.close()
    with pytest.raises(FFIError) as error:
        secret.expose_mut()
    assert error.value.name == "Closed"


def test_exposed_views_keep_the_secret_alive():
    import gc

    view = Secret(bytearray(b"A" * 64)).expose_mut()
    gc.collect()
    assert bytes(view) == b"A" * 64


def test_secret_helpers_accept_bytearrays_without_copying():
    secret = bytearray(b"abcd")
    assert ConstantTimeEq.ct_eq(secret, b"abcd").into_bool()
    assert ConstantTimeEq.ct_ne(memoryview(secret), b"abce").into_bool()
    assert ConditionallySelectable.select(secret, bytearray(b"wxyz"), Choice.TRUE) == bytearray(b"wxyz")
    assert repr(Choice.FALSE) == "Choice(..)"


def test_constant_time_tables_read_write_and_pack_their_entries():
    from umilib.secret import ConstantTimeTable32_8

    entries = bytes((index * 167 + 13) % 256 for index in range(256))
    table = ConstantTimeTable32_8(entries)
    assert [table.get(index) for index in range(256)] == list(entries)
    # The index is taken modulo the 256 entries; entry i is bits 8 × (i mod 8) of word i / 8.
    assert table.get(256 + 5) == entries[5]
    words = table.words()
    assert all((words[index // 8] >> (8 * (index % 8))) & 0xFF == entries[index] for index in range(256))
    copy = table.clone()
    table.set(77, 0x1AB)
    table.swap(3, 200)
    assert (table.get(77), table.get(3), table.get(200)) == (0xAB, entries[200], entries[3])
    assert copy.get(77) == entries[77]
    assert ConstantTimeTable32_8().get(9) == 0
    assert (ConstantTimeTable32_8.mask(5, 5), ConstantTimeTable32_8.mask(5, 6)) == (2**64 - 1, 0)
    with pytest.raises(Exception):
        ConstantTimeTable32_8(bytes(255))
