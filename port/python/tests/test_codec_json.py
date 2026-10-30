"""Tests of umilib.codec.json: JSONTestSuite, and agreement with Python's ``json`` module."""

import json
from pathlib import Path

import pytest

from umilib.codec.json import (
    DuplicateKeys,
    JSONConfig,
    JSONEncoder,
    JSONError,
    JSONEventKind,
    JSONNumber,
    JSONReader,
    JSONValue,
    JSONValueKind,
)

SUITE = Path(__file__).resolve().parents[3] / "tests" / "vectors" / "codec" / "json" / "test_parsing"


def test_json_test_suite():
    grammar = JSONConfig(duplicate_keys=DuplicateKeys.KeepAll)
    files = sorted(SUITE.iterdir())
    assert len(files) == 318
    for path in files:
        data = path.read_bytes()
        if path.name.startswith("y_"):
            JSONValue.decode(data, grammar)
        elif path.name.startswith("n_"):
            with pytest.raises(JSONError):
                JSONValue.decode(data, grammar)


def test_values_agree_with_the_standard_library():
    for path in sorted(SUITE.glob("y_*")):
        text = path.read_bytes()
        try:
            expected = json.loads(text)
        except (ValueError, RecursionError):
            continue
        if "duplicated_key" in path.name:
            continue
        assert JSONValue.decode(text).to_python() == expected, path.name


def test_round_trips_through_python_objects():
    data = {"name": "umilib", "list": [1, -2, 3.5, None, True, False], "nested": {"é": "😀"}, "big": 10**30}
    value = JSONValue.from_python(data)
    assert value.to_python() == data
    assert json.loads(value.encode()) == data
    assert JSONValue.parse(JSONEncoder.PRETTY.encode(value)) == value
    ascii = JSONEncoder(ascii_only=True).encode(value)
    assert ascii.isascii() and json.loads(ascii) == data
    with pytest.raises(JSONError):
        JSONValue.from_python(float("nan"))


def test_values_are_built_and_queried():
    value = JSONValue.object()
    value.insert("a", JSONValue.from_string("x"))
    array = JSONValue.array()
    array.push(JSONValue.from_bool(True))
    array.push(array)
    value.insert("b", array)
    assert value.encode() == '{"a":"x","b":[true,[true]]}'
    assert value.kind == JSONValueKind.Object and len(value) == 2
    assert value.get("a").as_str() == "x"
    assert value.get("missing") is None
    assert value.get("b").index(1).index(0).as_bool() is True
    assert value.remove("a") and not value.remove("a")
    assert [key for key, _ in value.members()] == ["b"]
    assert value.clone() == value
    assert JSONValue.null().is_null()


def test_numbers_are_exact():
    number = JSONNumber("12345678901234567890123")
    assert number.as_str() == "12345678901234567890123" and number.is_integer()
    assert number.as_i128() == 12345678901234567890123
    with pytest.raises(JSONError) as error:
        number.as_i64()
    assert error.value.name == "OutOfRange"
    assert JSONNumber("1e400").as_f64() is None
    assert JSONNumber.from_f64(0.1).as_f64() == 0.1
    assert JSONNumber.from_f64(float("inf")) is None
    assert JSONNumber.from_int(-(1 << 100)).as_str() == str(-(1 << 100))
    with pytest.raises(JSONError):
        JSONNumber("01")


def test_limits_and_policies():
    config = JSONConfig(maximum_depth=2)
    assert config.maximum_depth == 2
    with pytest.raises(JSONError) as error:
        JSONValue.decode(b"[[[1]]]", config)
    assert error.value.name == "TooDeep"
    with pytest.raises(JSONError) as error:
        JSONValue.parse('{"a": 1, "a": 2}')
    assert error.value.name == "DuplicateKey"
    assert JSONValue.decode(b'{"a": 1, "a": 2}', JSONConfig(duplicate_keys=DuplicateKeys.KeepLast)).encode() == '{"a":2}'
    assert JSONValue.decode(b"\xef\xbb\xbf1", JSONConfig(allow_byte_order_mark=True)).to_python() == 1


def test_reader_events():
    events = list(JSONReader(b'{"k\\u0041": [1, "s", false, null]}'))
    assert [event.kind for event in events] == [
        JSONEventKind.BeginObject, JSONEventKind.Key, JSONEventKind.BeginArray, JSONEventKind.Number,
        JSONEventKind.String, JSONEventKind.Bool, JSONEventKind.Null, JSONEventKind.EndArray, JSONEventKind.EndObject,
    ]
    key = events[1].value
    assert key.raw() == "k\\u0041" and key.is_escaped() and key.as_str() is None and key.decode() == "kA"
    assert events[3].value == "1" and events[5].value is False
    reader = JSONReader(b"[1, 2")
    with pytest.raises(JSONError):
        reader.validate()
    assert JSONEncoder.COMPACT.write_string('a"b') == '"a\\"b"'


def test_python_conversions_report_what_python_cannot_hold():
    with pytest.raises(JSONError) as error:
        JSONValue.parse("1" * 5000).to_python()
    assert error.value.name == "OutOfRange"
    with pytest.raises(JSONError) as error:
        JSONValue.parse("1e400").to_python()
    assert error.value.name == "OutOfRange"
    assert JSONValue.parse("-0").to_python() == 0
    with pytest.raises(TypeError):
        JSONValue.from_python({True: 1})
    with pytest.raises(OverflowError):
        JSONEncoder(indent=-1)
    with pytest.raises(OverflowError):
        JSONEncoder(indent=256)
    assert JSONEncoder(indent=255).indent == 255
