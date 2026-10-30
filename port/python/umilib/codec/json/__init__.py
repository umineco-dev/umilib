"""JSON, RFC 8259. Mirrors ``umilib::codec::json``.

``JSONValue.to_python()`` and ``JSONValue.from_python()`` convert to and from
Python objects; numbers become ``int`` when written as integers and
``float`` otherwise (use :class:`JSONNumber` to keep the exact text).
"""

from __future__ import annotations

import ctypes
import enum
from dataclasses import dataclass
from typing import Any, Iterator

from umilib.ffi import Bytes, FFIError, Handle, I128, Library, Preset, Text


class JSONError(FFIError):
    """An error of JSON parsing or conversion; ``name`` is the variant, such as ``DuplicateKey``."""


Library.register_error("codec.json", JSONError)


class DuplicateKeys(enum.IntEnum):
    Reject = 0
    KeepFirst = 1
    KeepLast = 2
    KeepAll = 3


class JSONValueKind(enum.IntEnum):
    """The kinds of :class:`JSONValue` (the variants of the Rust enum)."""

    Null = 0
    Bool = 1
    Number = 2
    String = 3
    Array = 4
    Object = 5


class JSONEventKind(enum.IntEnum):
    BeginObject = 0
    EndObject = 1
    BeginArray = 2
    EndArray = 3
    Key = 4
    String = 5
    Number = 6
    Bool = 7
    Null = 8


class JSONContainer(enum.Enum):
    Array = "array"
    Object = "object"


class JSONState(enum.Enum):
    Value = "value"
    ArrayStart = "array-start"
    ObjectStart = "object-start"
    Key = "key"
    Colon = "colon"
    AfterValue = "after-value"
    Done = "done"


class JSONConfig(Handle):
    """Limits and options of parsing."""

    FREE = "umilib_codec_json_json_config_free"

    def __init__(self, **fields: Any) -> None:
        super().__init__(Handle.create("umilib_codec_json_json_config_new"))
        for name, value in fields.items():
            if not hasattr(type(self), name):
                raise TypeError(f"JSONConfig has no field {name!r}")
            setattr(self, name, value)

    def get(self, name: str, ctype: Any) -> Any:
        return self.library.value(f"umilib_codec_json_json_config_{name}", ctype, self.handle)

    def set(self, name: str, value: Any) -> None:
        self.library.call(f"umilib_codec_json_json_config_set_{name}", self.handle, value)

    maximum_depth = property(lambda self: self.get("maximum_depth", ctypes.c_size_t), lambda self, value: self.set("maximum_depth", value))
    maximum_length = property(lambda self: self.get("maximum_length", ctypes.c_size_t), lambda self, value: self.set("maximum_length", value))
    allow_byte_order_mark = property(
        lambda self: self.get("allow_byte_order_mark", ctypes.c_bool), lambda self, value: self.set("allow_byte_order_mark", value)
    )
    duplicate_keys = property(
        lambda self: DuplicateKeys(self.get("duplicate_keys", ctypes.c_uint8)), lambda self, value: self.set("duplicate_keys", int(value))
    )


class JSONNumber(Handle):
    """A JSON number, kept exactly as written."""

    FREE = "umilib_codec_json_json_number_free"

    def __init__(self, text: str | None = None, pointer: int | None = None) -> None:
        if pointer is None:
            data, length = Text.encode(text)
            pointer = Handle.create("umilib_codec_json_json_number_new", data, length)
        super().__init__(pointer)

    @classmethod
    def new(cls, text: str) -> JSONNumber:
        return cls(text)

    @classmethod
    def from_f64(cls, value: float) -> JSONNumber | None:
        try:
            return cls(pointer=Handle.create("umilib_codec_json_json_number_from_f64", float(value)))
        except JSONError:
            return None

    @classmethod
    def from_int(cls, value: int) -> JSONNumber:
        """Mirrors ``JSONNumber::from`` for ``i64``, ``u64`` and ``i128``."""
        if -(1 << 63) <= value < 1 << 63:
            return cls(pointer=Handle.create("umilib_codec_json_json_number_from_i64", value))
        if 0 <= value < 1 << 64:
            return cls(pointer=Handle.create("umilib_codec_json_json_number_from_u64", value))
        return cls(pointer=Handle.create("umilib_codec_json_json_number_from_i128", I128.from_int(value)))

    def as_str(self) -> str:
        return self.library.output("umilib_codec_json_json_number_as_str", self.handle).decode("utf-8")

    def is_integer(self) -> bool:
        return self.library.value("umilib_codec_json_json_number_is_integer", ctypes.c_bool, self.handle)

    def as_f64(self) -> float | None:
        try:
            return self.library.value("umilib_codec_json_json_number_as_f64", ctypes.c_double, self.handle)
        except JSONError:
            return None

    def as_i64(self) -> int:
        return self.library.value("umilib_codec_json_json_number_as_i64", ctypes.c_int64, self.handle)

    def as_u64(self) -> int:
        return self.library.value("umilib_codec_json_json_number_as_u64", ctypes.c_uint64, self.handle)

    def as_i128(self) -> int:
        return self.library.value("umilib_codec_json_json_number_as_i128", I128, self.handle).to_int()

    def __repr__(self) -> str:
        return f"JSONNumber({self.as_str()!r})"


class JSONValue(Handle):
    """A JSON value. Children read from a value or added to it are copies."""

    FREE = "umilib_codec_json_json_value_free"

    @classmethod
    def decode(cls, data: bytes, config: JSONConfig | None = None) -> JSONValue:
        data, length = Bytes.readable(data)
        return cls(Handle.create("umilib_codec_json_json_value_decode", data, length, config.handle if config else None))

    @classmethod
    def parse(cls, text: str) -> JSONValue:
        data, length = Text.encode(text)
        return cls(Handle.create("umilib_codec_json_json_value_parse", data, length))

    @classmethod
    def null(cls) -> JSONValue:
        return cls(Handle.create("umilib_codec_json_json_value_null"))

    @classmethod
    def from_bool(cls, value: bool) -> JSONValue:
        return cls(Handle.create("umilib_codec_json_json_value_from_bool", bool(value)))

    @classmethod
    def from_number(cls, number: JSONNumber) -> JSONValue:
        return cls(Handle.create("umilib_codec_json_json_value_from_number", number.handle))

    @classmethod
    def from_string(cls, text: str) -> JSONValue:
        data, length = Text.encode(text)
        return cls(Handle.create("umilib_codec_json_json_value_from_string", data, length))

    @classmethod
    def array(cls) -> JSONValue:
        return cls(Handle.create("umilib_codec_json_json_value_array"))

    @classmethod
    def object(cls) -> JSONValue:
        return cls(Handle.create("umilib_codec_json_json_value_object"))

    @property
    def kind(self) -> JSONValueKind:
        return JSONValueKind(self.library.value("umilib_codec_json_json_value_kind", ctypes.c_uint8, self.handle))

    def is_null(self) -> bool:
        return self.kind == JSONValueKind.Null

    def as_bool(self) -> bool | None:
        return self.library.value("umilib_codec_json_json_value_as_bool", ctypes.c_bool, self.handle) if self.kind == JSONValueKind.Bool else None

    def as_number(self) -> JSONNumber | None:
        if self.kind != JSONValueKind.Number:
            return None
        return JSONNumber(pointer=Handle.create("umilib_codec_json_json_value_as_number", self.handle))

    def as_str(self) -> str | None:
        if self.kind != JSONValueKind.String:
            return None
        return self.library.output("umilib_codec_json_json_value_as_str", self.handle).decode("utf-8")

    def __len__(self) -> int:
        return self.library.value("umilib_codec_json_json_value_len", ctypes.c_size_t, self.handle)

    def index(self, position: int) -> JSONValue | None:
        if self.kind != JSONValueKind.Array or not 0 <= position < len(self):
            return None
        return JSONValue(Handle.create("umilib_codec_json_json_value_index", self.handle, position))

    def push(self, element: JSONValue) -> None:
        self.library.call("umilib_codec_json_json_value_push", self.handle, element.handle)

    def get(self, key: str) -> JSONValue | None:
        if self.kind != JSONValueKind.Object:
            return None
        data, length = Text.encode(key)
        found, out = ctypes.c_bool(), ctypes.c_void_p()
        self.library.call("umilib_codec_json_json_value_get", self.handle, data, length, ctypes.byref(found), ctypes.byref(out))
        return JSONValue(out.value) if found.value else None

    def insert(self, key: str, value: JSONValue) -> None:
        data, length = Text.encode(key)
        self.library.call("umilib_codec_json_json_value_insert", self.handle, data, length, value.handle)

    def remove(self, key: str) -> bool:
        data, length = Text.encode(key)
        return self.library.value("umilib_codec_json_json_value_remove", ctypes.c_bool, self.handle, data, length)

    def members(self) -> Iterator[tuple[str, JSONValue]]:
        """The members of an object, in order."""
        for position in range(len(self)):
            key = self.library.output("umilib_codec_json_json_value_member_key", self.handle, position).decode("utf-8")
            yield key, JSONValue(Handle.create("umilib_codec_json_json_value_member_value", self.handle, position))

    def encode(self) -> str:
        return self.library.output("umilib_codec_json_json_value_encode", self.handle).decode("utf-8")

    def clone(self) -> JSONValue:
        return JSONValue(Handle.create("umilib_codec_json_json_value_clone", self.handle))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, JSONValue):
            return NotImplemented
        return self.library.value("umilib_codec_json_json_value_equal", ctypes.c_bool, self.handle, other.handle)

    def to_python(self) -> Any:
        """The value as Python objects: ``None``, ``bool``, ``int``/``float``, ``str``, ``list``, ``dict``.

        Numbers that Python cannot hold (integers beyond its digit limit,
        non-integers beyond ``float``) raise :class:`JSONError` (``OutOfRange``),
        as ``JSONNumber.as_f64`` does in Rust."""
        kind = self.kind
        if kind == JSONValueKind.Null:
            return None
        if kind == JSONValueKind.Bool:
            return self.as_bool()
        if kind == JSONValueKind.Number:
            number = self.as_number()
            if number.is_integer():
                try:
                    return int(number.as_str())
                except ValueError:
                    # Python limits the digits of integers read from text.
                    raise JSONError("codec.json", "OutOfRange", "the integer has too many digits for Python") from None
            value = number.as_f64()
            if value is None:
                raise JSONError("codec.json", "OutOfRange", "the number does not fit a float")
            return value
        if kind == JSONValueKind.String:
            return self.as_str()
        if kind == JSONValueKind.Array:
            return [self.index(position).to_python() for position in range(len(self))]
        return {key: value.to_python() for key, value in self.members()}

    @classmethod
    def from_python(cls, value: Any) -> JSONValue:
        """A value from Python objects; ``float`` NaN and infinities are rejected."""
        if value is None:
            return cls.null()
        if isinstance(value, bool):
            return cls.from_bool(value)
        if isinstance(value, int):
            return cls.from_number(JSONNumber.from_int(value))
        if isinstance(value, float):
            number = JSONNumber.from_f64(value)
            if number is None:
                raise JSONError("codec.json", "OutOfRange", "JSON cannot represent NaN or infinities")
            return cls.from_number(number)
        if isinstance(value, str):
            return cls.from_string(value)
        if isinstance(value, (list, tuple)):
            array = cls.array()
            for element in value:
                array.push(cls.from_python(element))
            return array
        if isinstance(value, dict):
            object = cls.object()  # noqa: A001
            for key, member in value.items():
                if not isinstance(key, str):
                    raise TypeError(f"JSON object keys must be str, not {type(key).__name__}")
                object.insert(key, cls.from_python(member))
            return object
        raise TypeError(f"cannot convert {type(value).__name__} to JSON")

    def __repr__(self) -> str:
        return f"JSONValue({self.encode()})"


class JSONEncoder(Handle):
    """How values are written as text."""

    FREE = "umilib_codec_json_json_encoder_free"
    COMPACT = Preset(lambda: JSONEncoder(pointer=Handle.create("umilib_codec_json_json_encoder_compact")))
    PRETTY = Preset(lambda: JSONEncoder(pointer=Handle.create("umilib_codec_json_json_encoder_pretty")))

    def __init__(self, indent: int | None = None, ascii_only: bool = False, pointer: int | None = None) -> None:
        if pointer is None:
            pointer = Handle.create("umilib_codec_json_json_encoder_new", indent is not None, indent or 0, ascii_only)
        super().__init__(pointer)

    def settings(self) -> tuple[int | None, bool]:
        has_indent, indent, ascii_only = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_bool()
        self.library.call("umilib_codec_json_json_encoder_settings", self.handle, ctypes.byref(has_indent), ctypes.byref(indent), ctypes.byref(ascii_only))
        return (indent.value if has_indent.value else None), ascii_only.value

    @property
    def indent(self) -> int | None:
        return self.settings()[0]

    @property
    def ascii_only(self) -> bool:
        return self.settings()[1]

    def encode(self, value: JSONValue) -> str:
        return self.library.output("umilib_codec_json_json_encoder_encode", self.handle, value.handle).decode("utf-8")

    def write_string(self, text: str) -> str:
        data, length = Text.encode(text)
        return self.library.output("umilib_codec_json_json_encoder_write_string", self.handle, data, length).decode("utf-8")


@dataclass(frozen=True)
class JSONString:
    """A string as written in JSON text (without quotes, with escapes)."""

    raw_text: str
    escaped: bool

    def raw(self) -> str:
        return self.raw_text

    def is_escaped(self) -> bool:
        return self.escaped

    def as_str(self) -> str | None:
        return None if self.escaped else self.raw_text

    def decode(self) -> str:
        data, length = Text.encode(self.raw_text)
        return Library.default().output("umilib_codec_json_json_string_decode", data, length).decode("utf-8")


@dataclass(frozen=True)
class JSONEvent:
    """One step of a JSON text: ``kind``, and the string, number text or boolean it carries."""

    kind: JSONEventKind
    value: JSONString | str | bool | None = None


class JSONReader(Handle):
    """A pull parser yielding :class:`JSONEvent` objects; iterate over it."""

    FREE = "umilib_codec_json_json_reader_free"
    BYTE_ORDER_MARK = b"\xef\xbb\xbf"

    def __init__(self, data: bytes, config: JSONConfig | None = None) -> None:
        self.data = bytes(data)
        super().__init__(Handle.create("umilib_codec_json_json_reader_new", self.data, len(self.data), config.handle if config else None))

    @staticmethod
    def is_whitespace(byte: int) -> bool:
        return byte in b" \t\n\r"

    def next_event(self) -> JSONEvent | None:
        has, kind, data, length, flag = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_void_p(), ctypes.c_size_t(), ctypes.c_bool()
        self.library.call("umilib_codec_json_json_reader_next_event", self.handle, *(ctypes.byref(item) for item in (has, kind, data, length, flag)))
        if not has.value:
            return None
        kind = JSONEventKind(kind.value)
        text = ctypes.string_at(data.value, length.value).decode("utf-8") if length.value else ""
        if kind in (JSONEventKind.Key, JSONEventKind.String):
            return JSONEvent(kind, JSONString(text, flag.value))
        if kind == JSONEventKind.Number:
            return JSONEvent(kind, text)
        if kind == JSONEventKind.Bool:
            return JSONEvent(kind, flag.value)
        return JSONEvent(kind)

    def __iter__(self) -> Iterator[JSONEvent]:
        while (event := self.next_event()) is not None:
            yield event

    def position(self) -> int:
        return self.library.value("umilib_codec_json_json_reader_position", ctypes.c_size_t, self.handle)

    def depth(self) -> int:
        return self.library.value("umilib_codec_json_json_reader_depth", ctypes.c_size_t, self.handle)

    def validate(self) -> None:
        self.library.call("umilib_codec_json_json_reader_validate", self.handle)




__all__ = [
    "DuplicateKeys",
    "JSONConfig",
    "JSONContainer",
    "JSONEncoder",
    "JSONError",
    "JSONEvent",
    "JSONEventKind",
    "JSONNumber",
    "JSONReader",
    "JSONState",
    "JSONString",
    "JSONValue",
    "JSONValueKind",
]
