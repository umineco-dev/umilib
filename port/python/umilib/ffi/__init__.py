"""The C ABI of umilib, loaded with ctypes. Mirrors ``umilib::ffi``.

Every other Python module calls umilib through :class:`Library`, which loads
the shared library and declares every function from the manifest the library
exports, so signatures never have to be repeated in Python.

The library is searched for in this order:

1. the path in the ``UMILIB_LIBRARY_PATH`` environment variable (a file, or a
   directory containing the library);
2. the library bundled in this package directory;
3. the shared libraries of the system (``ctypes.util.find_library``).
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import dataclasses
import datetime
import json
import os
import sys
import threading
import typing
from pathlib import Path
from typing import Any, Callable, ClassVar, Iterator


class FFIError(Exception):
    """An error reported by umilib through a status.

    ``domain`` is the module of the error, such as ``bytes``; ``name`` is the
    variant of the Rust error type, such as ``UnexpectedEnd``.
    """

    def __init__(self, domain: str, name: str, message: str) -> None:
        super().__init__(f"{domain}: {name}: {message}")
        self.domain = domain
        self.name = name
        self.message = message


class Status(ctypes.Structure):
    """``umilib_ffi_Status``: the error returned by a fallible function."""

    _fields_ = [("domain", ctypes.c_char_p), ("name", ctypes.c_char_p), ("message", ctypes.c_char_p)]


class Buffer(ctypes.Structure):
    """``umilib_ffi_Buffer``: bytes owned by umilib, released with ``umilib_ffi_buffer_free``."""

    _fields_ = [("data", ctypes.c_void_p), ("length", ctypes.c_size_t), ("capacity", ctypes.c_size_t)]


class U128(ctypes.Structure):
    """``umilib_ffi_U128``: an unsigned 128-bit integer, ``(high << 64) | low``."""

    _fields_ = [("high", ctypes.c_uint64), ("low", ctypes.c_uint64)]

    @classmethod
    def from_int(cls, value: int) -> U128:
        if not 0 <= value < 1 << 128:
            raise OverflowError("value does not fit in u128")
        return cls(value >> 64, value & 0xFFFF_FFFF_FFFF_FFFF)

    def to_int(self) -> int:
        return (self.high << 64) | self.low


class I128(ctypes.Structure):
    """``umilib_ffi_I128``: a signed 128-bit integer in two's complement."""

    _fields_ = [("high", ctypes.c_int64), ("low", ctypes.c_uint64)]

    @classmethod
    def from_int(cls, value: int) -> I128:
        if not -(1 << 127) <= value < 1 << 127:
            raise OverflowError("value does not fit in i128")
        return cls(value >> 64, value & 0xFFFF_FFFF_FFFF_FFFF)

    def to_int(self) -> int:
        return (self.high << 64) | self.low


class Function:
    """A C function declared from the manifest.

    Integer arguments are checked against the range of their C type before the
    call, because ctypes would silently wrap them (``-1`` would become
    ``SIZE_MAX``).
    """

    BITS: ClassVar[dict[str, tuple[int, bool]]] = {
        "u8": (8, False),
        "u16": (16, False),
        "u32": (32, False),
        "u64": (64, False),
        "usize": (8 * ctypes.sizeof(ctypes.c_size_t), False),
        "i8": (8, True),
        "i16": (16, True),
        "i32": (32, True),
        "i64": (64, True),
        "isize": (8 * ctypes.sizeof(ctypes.c_ssize_t), True),
    }

    def __init__(self, name: str, symbol: Any, kinds: list[str]) -> None:
        self.name = name
        self.symbol = symbol
        self.kinds = kinds

    def __call__(self, *arguments: Any) -> Any:
        for position, (kind, value) in enumerate(zip(self.kinds, arguments)):
            if kind in Function.BITS and isinstance(value, int):
                bits, signed = Function.BITS[kind]
                low, high = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
                if not low <= value <= high:
                    raise OverflowError(f"{self.name}: argument {position} ({value}) does not fit in {kind}")
        # ctypes releases the GIL during the call: every handle passed is
        # locked so that no other thread uses or releases it meanwhile. Locks
        # are taken in a fixed order (by id) so that two calls never deadlock.
        handles = sorted({id(value): value for value in arguments if isinstance(value, Handle)}.values(), key=id)
        entered: list[Handle] = []
        try:
            for handle in handles:
                handle.enter_call()
                entered.append(handle)
            return self.symbol(*arguments)
        finally:
            for handle in reversed(entered):
                handle.exit_call()


class Library:
    """The loaded umilib shared library.

    ``Library.default()`` returns the library shared by every module. Each
    function declared in the manifest is available through :meth:`function`
    and :meth:`call`; functions of features that were not compiled in are
    missing and raise :class:`FFIError` with the name ``Unavailable``.
    """

    ENVIRONMENT: ClassVar[str] = "UMILIB_LIBRARY_PATH"
    PRIMITIVES: ClassVar[dict[str, Any]] = {
        "bool": ctypes.c_bool,
        "char": ctypes.c_char,
        "u8": ctypes.c_uint8,
        "u16": ctypes.c_uint16,
        "u32": ctypes.c_uint32,
        "u64": ctypes.c_uint64,
        "usize": ctypes.c_size_t,
        "i8": ctypes.c_int8,
        "i16": ctypes.c_int16,
        "i32": ctypes.c_int32,
        "i64": ctypes.c_int64,
        "isize": ctypes.c_ssize_t,
        "f32": ctypes.c_float,
        "f64": ctypes.c_double,
    }
    STRUCTURES: ClassVar[dict[str, type]] = {
        "umilib_ffi_Status": Status,
        "umilib_ffi_Buffer": Buffer,
        "umilib_ffi_U128": U128,
        "umilib_ffi_I128": I128,
    }
    errors: ClassVar[dict[str, type[Exception]]] = {}
    instance: ClassVar[Library | None] = None
    lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, path: str) -> None:
        self.path = path
        self.handle = ctypes.CDLL(path)
        self.types: dict[str, Any] = dict(Library.STRUCTURES)
        self.functions: dict[str, Any] = {}
        manifest = self.handle.umilib_ffi_manifest
        manifest.argtypes = [ctypes.c_void_p]
        manifest.restype = ctypes.c_void_p
        free = self.handle.umilib_ffi_buffer_free
        free.argtypes = [ctypes.c_void_p]
        free.restype = None
        buffer = Buffer()
        self.check(manifest(ctypes.byref(buffer)))
        try:
            self.manifest = json.loads(ctypes.string_at(buffer.data, buffer.length).decode("utf-8"))
        finally:
            free(ctypes.byref(buffer))
        self.declare(self.manifest)

    @staticmethod
    def file_names() -> list[str]:
        """The file names of the shared library on this platform."""
        if sys.platform == "win32":
            return ["umilib.dll"]
        if sys.platform == "darwin" or sys.platform == "ios":
            return ["libumilib.dylib"]
        return ["libumilib.so"]

    @staticmethod
    def find() -> str:
        """The path of the library to load, searched in the documented order."""
        configured = os.environ.get(Library.ENVIRONMENT)
        if configured:
            path = Path(configured)
            if path.is_dir():
                for name in Library.file_names():
                    if (path / name).is_file():
                        return str(path / name)
                raise FFIError("ffi", "NotFound", f"{Library.ENVIRONMENT} names a directory without the library: {path}")
            if path.is_file():
                return str(path)
            raise FFIError("ffi", "NotFound", f"{Library.ENVIRONMENT} names a missing file: {path}")
        bundled = Path(__file__).resolve().parent
        for name in Library.file_names():
            if (bundled / name).is_file():
                return str(bundled / name)
        system = ctypes.util.find_library("umilib")
        if system:
            return system
        raise FFIError("ffi", "NotFound", f"the umilib shared library was not found; set {Library.ENVIRONMENT}")

    @classmethod
    def default(cls) -> Library:
        """The library shared by every module, loaded on first use."""
        with cls.lock:
            if cls.instance is None:
                cls.instance = Library(Library.find())
            return cls.instance

    @classmethod
    def register_error(cls, domain: str, error: type[Exception]) -> None:
        """Makes statuses of ``domain`` raise ``error`` (called with domain, name, message)."""
        cls.errors[domain] = error

    def ctype(self, value: dict, definitions: dict[str, dict] | None = None) -> Any:
        """The ctypes type of a manifest type; every pointer is ``c_void_p``. A named type of
        ``definitions`` that is not declared yet is declared first."""
        kind = value["kind"]
        if kind == "void":
            return None
        if kind == "pointer":
            return ctypes.c_void_p
        if kind == "named":
            if definitions is not None and value["name"] not in self.types and value["name"] in definitions:
                self.declare_type(definitions[value["name"]], definitions)
            return self.types.get(value["name"], ctypes.c_void_p)
        if kind == "array":
            return self.ctype(value["element"], definitions) * value["length"]
        return Library.PRIMITIVES[kind]

    @staticmethod
    def definitions(module: dict, found: dict[str, dict]) -> dict[str, dict]:
        """The definitions of ``module`` and its descendants, by name, added to ``found``."""
        for definition in module["definitions"]:
            found[definition["name"]] = definition
        for child in module["modules"]:
            Library.definitions(child, found)
        return found

    def declare_type(self, definition: dict, definitions: dict[str, dict]) -> None:
        """Declares the structure or callback ``definition`` and the types it uses."""
        name = definition["name"]
        if name in self.types:
            return
        if definition["kind"] == "structure":
            fields = [(field["name"], self.ctype(field["type"], definitions)) for field in definition["fields"]]
            self.types[name] = type(name, (ctypes.Structure,), {"_fields_": fields})
        elif definition["kind"] == "callback":
            parameters = [self.ctype(parameter["type"], definitions) for parameter in definition["parameters"]]
            self.types[name] = ctypes.CFUNCTYPE(self.ctype(definition["returns"], definitions), *parameters)

    def declare(self, module: dict) -> None:
        """Declares the types of ``module`` and its descendants, then their functions: a module may
        use the types of a module declared after it."""
        definitions = Library.definitions(module, {})
        for definition in definitions.values():
            self.declare_type(definition, definitions)
        self.declare_functions(module)

    def declare_functions(self, module: dict) -> None:
        """Declares the functions of ``module`` and its descendants."""
        for function in module["functions"]:
            symbol = getattr(self.handle, function["name"])
            symbol.argtypes = [self.ctype(parameter["type"]) for parameter in function["parameters"]]
            symbol.restype = self.ctype(function["returns"])
            kinds = [parameter["type"]["kind"] for parameter in function["parameters"]]
            self.functions[function["name"]] = Function(function["name"], symbol, kinds)
        for child in module["modules"]:
            self.declare_functions(child)

    def function(self, name: str) -> Any:
        """The declared function ``name``."""
        try:
            return self.functions[name]
        except KeyError:
            raise FFIError("ffi", "Unavailable", f"{name} is not exported; the feature is not compiled in") from None

    def type(self, name: str) -> Any:
        """The ctypes type declared as ``name`` (structures and callbacks)."""
        return self.types[name]

    def check(self, status: int | None) -> None:
        """Raises the error described by a returned status pointer, if any."""
        if not status:
            return
        described = Status.from_address(status)
        domain = described.domain.decode("utf-8")
        name = described.name.decode("utf-8")
        message = described.message.decode("utf-8")
        raise Library.errors.get(domain, FFIError)(domain, name, message)

    def error(self, status: int | None) -> FFIError | None:
        """The error described by a status pointer, or ``None`` for success: :meth:`check` for a
        status that is a value, such as the error of an event."""
        try:
            self.check(status)
        except FFIError as error:
            return error
        return None

    def call(self, name: str, *arguments: Any) -> None:
        """Calls the fallible function ``name`` and raises its error, if any."""
        self.check(self.function(name)(*arguments))

    def take(self, buffer: Buffer) -> bytes:
        """Copies the bytes of ``buffer`` and releases it."""
        try:
            return ctypes.string_at(buffer.data, buffer.length) if buffer.data else b""
        finally:
            self.function("umilib_ffi_buffer_free")(ctypes.byref(buffer))

    def take_optional_text(self, has: ctypes.c_bool, buffer: Buffer) -> str | None:
        """The UTF-8 text of ``buffer`` if ``has`` is set, else ``None``; releases the buffer either way:
        the C form of an optional string as an output."""
        data = self.take(buffer)
        return data.decode("utf-8") if has.value else None

    def take_secret(self, buffer: Buffer) -> bytearray:
        """Moves the bytes of ``buffer`` into a ``bytearray`` without an immutable copy, and releases
        the buffer, which zeroizes it: the result is the only copy, for the caller to zeroize."""
        try:
            out = bytearray(buffer.length)
            if buffer.length:
                ctypes.memmove((ctypes.c_uint8 * buffer.length).from_buffer(out), buffer.data, buffer.length)
            return out
        finally:
            self.function("umilib_ffi_buffer_free")(ctypes.byref(buffer))

    def output_secret(self, name: str, *arguments: Any) -> bytearray:
        """:meth:`output` for a secret: the bytes are returned as a ``bytearray`` (see :meth:`take_secret`)."""
        buffer = Buffer()
        self.call(name, *arguments, ctypes.byref(buffer))
        return self.take_secret(buffer)

    def output(self, name: str, *arguments: Any) -> bytes:
        """Calls ``name`` with a trailing ``umilib_ffi_Buffer`` output and returns its bytes."""
        buffer = Buffer()
        self.call(name, *arguments, ctypes.byref(buffer))
        return self.take(buffer)

    def value(self, name: str, ctype: Any, *arguments: Any) -> Any:
        """Calls ``name`` with a trailing output of type ``ctype`` and returns the output."""
        out = ctype()
        self.call(name, *arguments, ctypes.byref(out))
        return out.value if hasattr(out, "value") else out

    def optional(self, name: str, ctype: Any, *arguments: Any) -> Any:
        """Calls ``name`` with ``bool`` and ``ctype`` outputs and returns the value or ``None``."""
        has_value = ctypes.c_bool()
        if ctype is Buffer:
            buffer = Buffer()
            self.call(name, *arguments, ctypes.byref(has_value), ctypes.byref(buffer))
            data = self.take(buffer)
            return data if has_value.value else None
        out = ctype()
        self.call(name, *arguments, ctypes.byref(has_value), ctypes.byref(out))
        return out.value if has_value.value else None


class Handle:
    """A Python owner of an object created by umilib, released by ``FREE``.

    Handles are released when garbage collected, by :meth:`free`, or at the
    end of a ``with`` block; :meth:`close` releases them too, unless a type
    overrides it with an operation of its protocol. A handle is passed to C functions as it is (see
    :attr:`handle`): :class:`Function` locks it for the duration of the call,
    so one object can be shared by threads, which the C ABI alone does not
    allow. Using a handle again from a callback that runs inside a call on
    the same handle raises :class:`FFIError` (``Reentrant``) instead of
    deadlocking.
    """

    FREE: ClassVar[str] = ""

    def __init__(self, pointer: int | None) -> None:
        if not pointer:
            raise FFIError("ffi", "NullPointer", "umilib returned a null handle")
        self.library = Library.default()
        self.pointer: int | None = pointer
        self.lock = threading.Lock()
        #: The thread holding the lock, how many times it entered, and
        #: whether a C function is running on the object.
        self.locked_by: int | None = None
        self.depth = 0
        self.calling = False
        self.previous_calling = False

    @property
    def handle(self) -> Handle:
        """The argument passed to C functions: the handle itself, which ctypes
        converts through :attr:`_as_parameter_`."""
        return self

    @property
    def _as_parameter_(self) -> int:
        """The pointer, read by ctypes when the handle is an argument."""
        self.check_open()
        return self.pointer

    def check_open(self) -> None:
        """Raises :class:`FFIError` (``Closed``) if the object was released."""
        if self.pointer is None:
            raise FFIError("ffi", "Closed", f"the {type(self).__name__} was already released")

    def acquire(self) -> None:
        """Takes the lock of the handle, waiting for other threads. The thread
        that holds it may take it again, except from a callback running
        inside a C function on this object, which raises ``Reentrant``."""
        if self.locked_by == threading.get_ident():
            if self.calling:
                raise FFIError("ffi", "Reentrant", f"the {type(self).__name__} is already in use by this thread")
            self.depth += 1
            return
        self.lock.acquire()
        self.locked_by = threading.get_ident()
        self.depth = 1

    def release(self) -> None:
        """Gives back one acquisition; does nothing if this thread does not hold the lock."""
        if self.locked_by != threading.get_ident():
            return
        self.depth -= 1
        if self.depth == 0:
            self.locked_by = None
            self.lock.release()

    @contextlib.contextmanager
    def locked(self) -> Iterator[Handle]:
        """Holds the lock for a block, so that memory the object owns can be
        read, or the object consumed, before another thread uses it. Inside
        the block, pass no other handle to a C function: its lock would be
        taken out of the fixed order and could deadlock with another thread.
        Use :meth:`locked_all` to hold several handles."""
        self.acquire()
        try:
            self.check_open()
            yield self
        finally:
            self.release()

    @staticmethod
    @contextlib.contextmanager
    def locked_all(*handles: Handle) -> Iterator[None]:
        """Holds the locks of several handles for a block, taken in the same
        order as :class:`Function` takes them so that no two threads deadlock."""
        with contextlib.ExitStack() as stack:
            for handle in sorted({id(handle): handle for handle in handles}.values(), key=id):
                stack.enter_context(handle.locked())
            yield

    def enter_call(self) -> None:
        """Locks the handle for a C function that receives it."""
        self.acquire()
        self.previous_calling, self.calling = self.calling, True
        try:
            self.check_open()
        except BaseException:
            self.exit_call()
            raise

    def exit_call(self) -> None:
        if self.locked_by != threading.get_ident():
            return
        self.calling = self.previous_calling
        self.release()

    def consumed(self) -> None:
        """Marks the object as released by a C function that consumed it; call it while holding the lock."""
        self.pointer = None

    def free(self) -> None:
        """Releases the object; using it afterwards raises :class:`FFIError`.
        Garbage collection and the end of a ``with`` block call this method."""
        self.acquire()
        try:
            pointer, self.pointer = self.pointer, None
        finally:
            self.release()
        if pointer is not None:
            self.library.function(self.FREE)(pointer)

    def close(self) -> None:
        """Releases the object (:meth:`free`). Types whose Rust ``close`` is an
        operation of a protocol, such as sending a FIN, override this method
        with it and are released only by :meth:`free`."""
        self.free()

    def detach(self) -> int:
        """Gives up ownership without releasing the object and returns the pointer."""
        with self.locked():
            pointer = self.pointer
            self.pointer = None
        return pointer

    def __enter__(self) -> Handle:
        return self

    def __exit__(self, *exception: object) -> None:
        self.free()

    def __del__(self) -> None:
        if getattr(self, "lock", None) is None:
            return  # construction failed before the handle existed
        try:
            self.free()
        except Exception:
            pass

    @classmethod
    def create(cls, name: str, *arguments: Any) -> int:
        """Calls the constructor ``name``, whose last parameter is a handle output, and returns the handle."""
        out = ctypes.c_void_p()
        Library.default().call(name, *arguments, ctypes.byref(out))
        return out.value


class Fields:
    """Assignments to the fields of ctypes structures, checked like the
    integer arguments of :class:`Function`, because ctypes would wrap them."""

    @staticmethod
    def assign(structure: ctypes.Structure, name: str, value: Any) -> None:
        """Sets field ``name`` of ``structure`` to ``value``; raises ``OverflowError``
        if an integer does not fit its C type."""
        ctype = dict(structure._fields_)[name]
        code = getattr(ctype, "_type_", None)
        if isinstance(value, int) and not isinstance(value, bool) and isinstance(code, str) and code in "bBhHiIlLqQnN":
            bits = 8 * ctypes.sizeof(ctype)
            signed = code.islower()
            low, high = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
            if not low <= value <= high:
                raise OverflowError(f"{name} ({value}) does not fit in {bits} bits")
        setattr(structure, name, value)


class Structures:
    """Conversions between dataclasses and the C structures of the same fields, which name their
    structure in ``C_TYPE``; a field of a dataclass that has one is a nested structure."""

    @staticmethod
    def to_structure(value: Any, name: str | None = None) -> Any:
        """The C structure of the dataclass ``value`` (``name``, or its ``C_TYPE``), checked like :meth:`Fields.assign`."""
        structure = Library.default().type(name or type(value).C_TYPE)()
        for field in dataclasses.fields(value):
            item = getattr(value, field.name)
            if dataclasses.is_dataclass(item):
                setattr(structure, field.name, Structures.to_structure(item))
            else:
                Fields.assign(structure, field.name, item)
        return structure

    @staticmethod
    def from_structure(cls: type, structure: Any) -> Any:
        """The dataclass ``cls`` of the C structure ``structure``."""
        hints = typing.get_type_hints(cls)
        values = {}
        for field in dataclasses.fields(cls):
            item = getattr(structure, field.name)
            kind = hints.get(field.name)
            values[field.name] = Structures.from_structure(kind, item) if dataclasses.is_dataclass(kind) else item
        return cls(**values)


class Words:
    """Arrays of unsigned integers for the C ABI, checked like the integer
    arguments of :class:`Function`, because ctypes would wrap them."""

    @staticmethod
    def array(ctype: Any, values: list[int], count: int) -> Any:
        """A ctypes array of the ``count`` integers of ``values`` of the unsigned type ``ctype``; raises
        ``ValueError`` for another count and ``OverflowError`` if a value does not fit."""
        if len(values) != count:
            raise ValueError(f"{count} words are needed, not {len(values)}")
        bits = 8 * ctypes.sizeof(ctype)
        for value in values:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << bits:
                raise OverflowError(f"{value!r} is not an unsigned {bits}-bit integer")
        return (ctype * count)(*values)


class Text:
    """Conversions of Python text to the UTF-8 ``(data, length)`` pairs of the C ABI."""

    @staticmethod
    def encode(text: str | None) -> tuple[bytes | None, int]:
        if text is None:
            return None, 0
        data = text.encode("utf-8")
        return data, len(data)

    @staticmethod
    def array(texts: list[str]) -> tuple[Any, int, list[bytes]]:
        """An array of NUL-terminated strings, its length and the objects that keep it alive."""
        encoded = [text.encode("utf-8") for text in texts]
        array = (ctypes.c_char_p * len(encoded))(*encoded)
        return array, len(encoded), encoded


class Bytes:
    """Conversions of Python byte objects to the pointers of the C ABI."""

    @staticmethod
    def readable(data: bytes | bytearray | memoryview) -> tuple[Any, int]:
        """A pointer to the contents of ``data`` without copying them, and their length in bytes.

        ``bytes`` are passed as they are; a ``bytearray`` or a writable
        ``memoryview`` is exported in place, which matters for secrets. A
        ``memoryview`` of wider items (such as an ``array('I')``) is read as
        its bytes.
        """
        if isinstance(data, bytes):
            return data, len(data)
        if isinstance(data, memoryview):
            if data.readonly:
                data = data.tobytes()
                return data, len(data)
            data = data.cast("B")
        if len(data) == 0:
            return None, 0
        return (ctypes.c_uint8 * len(data)).from_buffer(data), len(data)

    @staticmethod
    def mutable(data: bytearray | memoryview) -> Any:
        """A pointer to the contents of ``data``, which ctypes keeps alive while it is used.

        ``data`` is changed in place, so it must be a ``bytearray`` or a writable,
        contiguous ``memoryview`` of bytes, whose ``len`` is its length in bytes.
        """
        if isinstance(data, memoryview):
            if data.readonly or data.itemsize != 1 or not data.c_contiguous:
                raise TypeError("an operation in place needs a writable, contiguous buffer of bytes")
        elif not isinstance(data, bytearray):
            raise TypeError(f"an operation in place needs a bytearray, not {type(data).__name__}")
        if len(data) == 0:
            return None
        return (ctypes.c_uint8 * len(data)).from_buffer(data)

    @staticmethod
    def array(inputs: list[bytes]) -> tuple[Any, Any, int, list[bytes]]:
        """Arrays of pointers and lengths, the count and the objects that keep them alive."""
        kept = [bytes(item) for item in inputs]
        pointers = (ctypes.c_char_p * len(kept))(*kept)
        lengths = (ctypes.c_size_t * len(kept))(*[len(item) for item in kept])
        return pointers, lengths, len(kept), kept


class Nanoseconds:
    """Conversions between :class:`datetime.timedelta`, which stands for Rust's
    ``Duration``, and the nanosecond integers of the C ABI."""

    @staticmethod
    def from_timedelta(duration: datetime.timedelta) -> int:
        """The duration in whole nanoseconds; Rust durations cannot be negative."""
        nanoseconds = (duration.days * 86_400 + duration.seconds) * 1_000_000_000 + duration.microseconds * 1_000
        if nanoseconds < 0:
            raise ValueError("a duration cannot be negative")
        return nanoseconds

    @staticmethod
    def to_timedelta(nanoseconds: int) -> datetime.timedelta:
        """The duration, truncated to the microsecond resolution of ``timedelta``."""
        return datetime.timedelta(microseconds=nanoseconds // 1_000)


class Marker:
    """A type of no value of the Rust API that the C ABI names by the C type name ``C_TYPE``, such as a
    curve or a group: ``umilib.crypto.curve.p256.P256`` is ``umilib_crypto_curve_p256_P256``. A class
    declared with ``abstract=True`` is a kind of markers and has no name."""

    C_TYPE: ClassVar[str] = ""

    def __init_subclass__(cls, abstract: bool = False, **options: Any) -> None:
        super().__init_subclass__(**options)
        cls.C_TYPE = "" if abstract else f"{cls.__module__.replace('.', '_')}_{cls.__name__}"

    @classmethod
    def require(cls, value: Any, user: str) -> Any:
        """``value`` if it is a named class of this kind; raises ``TypeError`` otherwise."""
        if not (isinstance(value, type) and issubclass(value, cls) and value.C_TYPE):
            raise TypeError(f"{user} needs a {cls.__name__} class")
        return value


class Preset:
    """A class attribute holding a preset object, created on first use so that
    importing a module does not load the library."""

    def __init__(self, create: Callable[[], Any]) -> None:
        self.create = create
        self.value: Any = None

    def __get__(self, instance: object, owner: type) -> Any:
        if self.value is None:
            self.value = self.create()
        return self.value


class Callback:
    """Python functions called back from C."""

    @staticmethod
    def guard(function: Callable[..., Any], failure: Any) -> tuple[Callable[..., Any], list[BaseException]]:
        """Wraps ``function`` so that an exception is recorded, and ``failure``
        returned to C, instead of the exception crossing into C. The caller
        re-raises the first recorded exception after the C call returns."""
        raised: list[BaseException] = []

        def guarded(*arguments: Any) -> Any:
            if any(not isinstance(error, Exception) for error in raised):
                return failure  # interrupted: do no more work until C returns
            try:
                return function(*arguments)
            except BaseException as error:  # noqa: BLE001 - recorded and re-raised by the caller
                if len(raised) < 1 or not isinstance(error, Exception):
                    raised.append(error)
                return failure

        return guarded, raised

    @staticmethod
    def reraise_interrupts(raised: list[BaseException]) -> None:
        """Re-raises a ``KeyboardInterrupt``, ``SystemExit`` or other non-``Exception``
        recorded by :meth:`guard`; ordinary exceptions are left to the caller."""
        for error in raised:
            if not isinstance(error, Exception):
                raise error


Library.register_error("ffi", FFIError)

__all__ = [
    "Buffer",
    "Bytes",
    "Callback",
    "FFIError",
    "Fields",
    "Handle",
    "I128",
    "Library",
    "Marker",
    "Nanoseconds",
    "Preset",
    "Status",
    "Structures",
    "Text",
    "U128",
    "Words",
]
