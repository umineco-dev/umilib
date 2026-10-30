"""Fuzzing: running code on many generated inputs to find inputs that make it fail.
Mirrors ``umilib::platform::fuzz``.

A Python :class:`FuzzTarget` fails by raising an exception, as a Rust target
fails by panicking. libFuzzer needs an instrumented Rust build and is not
available from Python.
"""

from __future__ import annotations

import abc
import ctypes
import datetime
import enum
from typing import Any, Callable

from umilib.ffi import Buffer as FFIBuffer
from umilib.ffi import Bytes, Callback, FFIError, Handle, Library, Nanoseconds, Text


class FuzzError(FFIError):
    """An error of ``platform.fuzz``, such as ``IO`` or ``InvalidArguments``."""


Library.register_error("platform.fuzz", FuzzError)


class FuzzTarget(abc.ABC):
    """Code under test. It fails by raising an exception."""

    @abc.abstractmethod
    def name(self) -> str:
        """The name, used for corpus and crash directories."""

    @abc.abstractmethod
    def run(self, data: bytes) -> None:
        """Runs the code under test on ``data``."""

    def callback(self) -> tuple[Any, list[BaseException]]:
        """The C callback that runs this target, and the list where it records exceptions."""

        def run(context: int, data: int, length: int) -> bool:
            self.run(ctypes.string_at(data, length) if length else b"")
            return True

        guarded, raised = Callback.guard(run, False)
        return Library.default().type("umilib_platform_fuzz_Target")(guarded), raised



class FuzzFunction(FuzzTarget):
    """A :class:`FuzzTarget` made of a name and a function."""

    def __init__(self, name: str, function: Callable[[bytes], object]) -> None:
        self.target_name = name
        self.function = function

    @classmethod
    def new(cls, name: str, function: Callable[[bytes], object]) -> FuzzFunction:
        return cls(name, function)

    def name(self) -> str:
        return self.target_name

    def run(self, data: bytes) -> None:
        self.function(data)


class FuzzEngine(enum.IntEnum):
    """The engine that generates inputs."""

    Builtin = 0
    LibFuzzer = 1


class FuzzConfig(Handle):
    """How :class:`Fuzzer` generates inputs and when it stops."""

    FREE = "umilib_platform_fuzz_fuzz_config_free"

    def __init__(self, pointer: int | None = None, **fields: Any) -> None:
        super().__init__(pointer if pointer is not None else Handle.create("umilib_platform_fuzz_fuzz_config_new"))
        for name, value in fields.items():
            if not hasattr(type(self), name):
                raise TypeError(f"FuzzConfig has no field {name!r}")
            setattr(self, name, value)

    @property
    def seed(self) -> int:
        return self.library.value("umilib_platform_fuzz_fuzz_config_seed", ctypes.c_uint64, self.handle)

    @seed.setter
    def seed(self, value: int) -> None:
        self.library.call("umilib_platform_fuzz_fuzz_config_set_seed", self.handle, value)

    @property
    def maximum_length(self) -> int:
        return self.library.value("umilib_platform_fuzz_fuzz_config_maximum_length", ctypes.c_size_t, self.handle)

    @maximum_length.setter
    def maximum_length(self, value: int) -> None:
        self.library.call("umilib_platform_fuzz_fuzz_config_set_maximum_length", self.handle, value)

    @property
    def iterations(self) -> int | None:
        return self.library.optional("umilib_platform_fuzz_fuzz_config_iterations", ctypes.c_uint64, self.handle)

    @iterations.setter
    def iterations(self, value: int | None) -> None:
        self.library.call("umilib_platform_fuzz_fuzz_config_set_iterations", self.handle, value is not None, value or 0)

    @property
    def duration(self) -> datetime.timedelta | None:
        value = self.library.optional("umilib_platform_fuzz_fuzz_config_duration", ctypes.c_uint64, self.handle)
        return Nanoseconds.to_timedelta(value) if value is not None else None

    @duration.setter
    def duration(self, value: datetime.timedelta | None) -> None:
        nanoseconds = Nanoseconds.from_timedelta(value) if value is not None else 0
        self.library.call("umilib_platform_fuzz_fuzz_config_set_duration", self.handle, value is not None, nanoseconds)

    @property
    def corpus(self) -> str | None:
        value = self.library.optional("umilib_platform_fuzz_fuzz_config_corpus", FFIBuffer, self.handle)
        return value.decode("utf-8") if value is not None else None

    @corpus.setter
    def corpus(self, value: str | None) -> None:
        data, length = Text.encode(None if value is None else str(value))
        self.library.call("umilib_platform_fuzz_fuzz_config_set_corpus", self.handle, data, length)

    @property
    def crashes(self) -> str | None:
        value = self.library.optional("umilib_platform_fuzz_fuzz_config_crashes", FFIBuffer, self.handle)
        return value.decode("utf-8") if value is not None else None

    @crashes.setter
    def crashes(self, value: str | None) -> None:
        data, length = Text.encode(None if value is None else str(value))
        self.library.call("umilib_platform_fuzz_fuzz_config_set_crashes", self.handle, data, length)


class FuzzReport(Handle):
    """The outcome of a fuzzing or replay run."""

    FREE = "umilib_platform_fuzz_fuzz_report_free"

    @property
    def iterations(self) -> int:
        return self.library.value("umilib_platform_fuzz_fuzz_report_iterations", ctypes.c_uint64, self.handle)

    @property
    def failures(self) -> list[bytes]:
        count = self.library.value("umilib_platform_fuzz_fuzz_report_failure_count", ctypes.c_size_t, self.handle)
        return [self.library.output("umilib_platform_fuzz_fuzz_report_failure", self.handle, index) for index in range(count)]

    @property
    def saved(self) -> list[str]:
        """The files the failing inputs were saved to; a failure that could not be saved is missing."""
        count = self.library.value("umilib_platform_fuzz_fuzz_report_saved_count", ctypes.c_size_t, self.handle)
        return [self.library.output("umilib_platform_fuzz_fuzz_report_saved", self.handle, index).decode("utf-8") for index in range(count)]

    @property
    def elapsed(self) -> datetime.timedelta:
        return Nanoseconds.to_timedelta(self.library.value("umilib_platform_fuzz_fuzz_report_elapsed", ctypes.c_uint64, self.handle))

    def is_success(self) -> bool:
        return not self.failures


class Corpus:
    """A set of inputs stored as files in a directory, one input per file."""

    def __init__(self, inputs: list[bytes] | None = None) -> None:
        self.inputs: list[bytes] = list(inputs or [])

    @classmethod
    def load(cls, directory: str) -> Corpus:
        """Reads every file in ``directory``, sorted by name. A missing directory is an empty corpus."""
        library = Library.default()
        data, length = Text.encode(str(directory))
        handle = Handle.create("umilib_platform_fuzz_corpus_load", data, length)
        try:
            count = library.value("umilib_platform_fuzz_corpus_input_count", ctypes.c_size_t, handle)
            return cls([library.output("umilib_platform_fuzz_corpus_inputs", handle, index) for index in range(count)])
        finally:
            library.function("umilib_platform_fuzz_corpus_free")(handle)

    @staticmethod
    def file_name(data: bytes) -> str:
        data = bytes(data)
        return Library.default().output("umilib_platform_fuzz_corpus_file_name", data, len(data)).decode("utf-8")

    @staticmethod
    def save(directory: str, data: bytes) -> str:
        """Writes ``data`` into ``directory``, creating it if needed, and returns the file path."""
        name, length = Text.encode(str(directory))
        data = bytes(data)
        return Library.default().output("umilib_platform_fuzz_corpus_save", name, length, data, len(data)).decode("utf-8")

    def to_handle(self) -> int:
        """A new umilib corpus with the same inputs; the caller releases it."""
        library = Library.default()
        handle = Handle.create("umilib_platform_fuzz_corpus_new")
        for item in self.inputs:
            item = bytes(item)
            library.call("umilib_platform_fuzz_corpus_push_input", handle, item, len(item))
        return handle


class Mutator(Handle):
    """A deterministic generator of input mutations."""

    FREE = "umilib_platform_fuzz_mutator_free"

    def __init__(self, seed: int) -> None:
        super().__init__(Handle.create("umilib_platform_fuzz_mutator_new", seed))

    @classmethod
    def new(cls, seed: int) -> Mutator:
        return cls(seed)

    def next_u64(self) -> int:
        return self.library.value("umilib_platform_fuzz_mutator_next_u64", ctypes.c_uint64, self.handle)

    def below(self, bound: int) -> int:
        return self.library.value("umilib_platform_fuzz_mutator_below", ctypes.c_size_t, self.handle, bound)

    def mutate(self, data: bytearray, maximum_length: int, corpus: list[bytes]) -> None:
        """Applies random mutations to ``data`` in place, keeping it at most ``maximum_length`` bytes long."""
        pointers, lengths, count, kept = Bytes.array(corpus)
        source = bytes(data)
        result = self.library.output("umilib_platform_fuzz_mutator_mutate", self.handle, source, len(source), maximum_length, pointers, lengths, count)
        del kept
        data[:] = result


class Fuzzer(Handle):
    """Runs a :class:`FuzzTarget` with the built-in mutation engine."""

    FREE = "umilib_platform_fuzz_fuzzer_free"

    def __init__(self, config: FuzzConfig | None = None) -> None:
        config = config if config is not None else FuzzConfig()
        super().__init__(Handle.create("umilib_platform_fuzz_fuzzer_new", config.handle))

    @classmethod
    def new(cls, config: FuzzConfig) -> Fuzzer:
        return cls(config)

    def config(self) -> FuzzConfig:
        return FuzzConfig(pointer=Handle.create("umilib_platform_fuzz_fuzzer_config", self.handle))

    @staticmethod
    def is_valid_name(name: str) -> bool:
        """Whether ``name`` can name a directory: ASCII letters, digits, ``-``, ``_`` and ``.``, not starting with ``.``."""
        data, length = Text.encode(name)
        return Library.default().value("umilib_platform_fuzz_fuzzer_is_valid_name", ctypes.c_bool, data, length)

    @staticmethod
    def check(target: FuzzTarget, data: bytes) -> bool:
        """Runs ``target`` on ``data`` and reports whether it returned without failing."""
        data = bytes(data)
        name, length = Text.encode(target.name())
        callback, raised = target.callback()
        passed = Library.default().value("umilib_platform_fuzz_fuzzer_check", ctypes.c_bool, name, length, callback, None, data, len(data))
        Callback.reraise_interrupts(raised)
        return passed

    def run(self, target: FuzzTarget) -> FuzzReport:
        """Fuzzes ``target`` until the configured limits (both apply) or the first failure.
        ``KeyboardInterrupt`` and ``SystemExit`` stop fuzzing and are raised again."""
        name, length = Text.encode(target.name())
        callback, raised = target.callback()
        report = Handle.create("umilib_platform_fuzz_fuzzer_run", self.handle, name, length, callback, None)
        Callback.reraise_interrupts(raised)
        return FuzzReport(report)

    def replay(self, target: FuzzTarget, corpus: Corpus) -> FuzzReport:
        """Runs ``target`` on every input of ``corpus``."""
        name, length = Text.encode(target.name())
        callback, raised = target.callback()
        handle = corpus.to_handle()
        try:
            report = Handle.create("umilib_platform_fuzz_fuzzer_replay_corpus", self.handle, name, length, callback, None, handle)
        finally:
            self.library.function("umilib_platform_fuzz_corpus_free")(handle)
        Callback.reraise_interrupts(raised)
        return FuzzReport(report)


class FuzzArguments:
    """Command-line arguments of a fuzzing program."""

    FIELDS = ("filter", "skip", "list", "fuzz", "engine", "duration", "iterations", "seed", "maximum_length", "engine_arguments")

    def __init__(self, **fields: Any) -> None:
        self.filter: str | None = fields.get("filter")
        self.skip: list[str] = list(fields.get("skip", []))
        self.list: bool = fields.get("list", False)
        self.fuzz: str | None = fields.get("fuzz")
        self.engine: FuzzEngine = fields.get("engine", FuzzEngine.Builtin)
        self.duration: datetime.timedelta | None = fields.get("duration")
        self.iterations: int | None = fields.get("iterations")
        self.seed: int | None = fields.get("seed")
        self.maximum_length: int | None = fields.get("maximum_length")
        self.engine_arguments: list[str] = list(fields.get("engine_arguments", []))

    @classmethod
    def parse(cls, arguments: list[str]) -> FuzzArguments:
        """Parses ``arguments``, which do not include the program name."""
        library = Library.default()
        array, count, kept = Text.array(arguments)
        parsed = Handle.create("umilib_platform_fuzz_fuzz_arguments_parse", array, count)
        del kept
        try:
            text = lambda name: library.optional(name, FFIBuffer, parsed)  # noqa: E731
            filter, fuzz = text("umilib_platform_fuzz_fuzz_arguments_filter"), text("umilib_platform_fuzz_fuzz_arguments_fuzz")  # noqa: A001
            duration = library.optional("umilib_platform_fuzz_fuzz_arguments_duration", ctypes.c_uint64, parsed)
            engine_count = library.value("umilib_platform_fuzz_fuzz_arguments_engine_argument_count", ctypes.c_size_t, parsed)
            skip_count = library.value("umilib_platform_fuzz_fuzz_arguments_skip_count", ctypes.c_size_t, parsed)
            return cls(
                filter=filter.decode("utf-8") if filter is not None else None,
                skip=[library.output("umilib_platform_fuzz_fuzz_arguments_skip", parsed, index).decode("utf-8") for index in range(skip_count)],
                list=library.value("umilib_platform_fuzz_fuzz_arguments_list", ctypes.c_bool, parsed),
                fuzz=fuzz.decode("utf-8") if fuzz is not None else None,
                engine=FuzzEngine(library.value("umilib_platform_fuzz_fuzz_arguments_engine", ctypes.c_uint8, parsed)),
                duration=Nanoseconds.to_timedelta(duration) if duration is not None else None,
                iterations=library.optional("umilib_platform_fuzz_fuzz_arguments_iterations", ctypes.c_uint64, parsed),
                seed=library.optional("umilib_platform_fuzz_fuzz_arguments_seed", ctypes.c_uint64, parsed),
                maximum_length=library.optional("umilib_platform_fuzz_fuzz_arguments_maximum_length", ctypes.c_size_t, parsed),
                engine_arguments=[
                    library.output("umilib_platform_fuzz_fuzz_arguments_engine_arguments", parsed, index).decode("utf-8")
                    for index in range(engine_count)
                ],
            )
        finally:
            library.function("umilib_platform_fuzz_fuzz_arguments_free")(parsed)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, FuzzArguments) and all(getattr(self, name) == getattr(other, name) for name in FuzzArguments.FIELDS)


__all__ = [
    "Corpus",
    "FuzzArguments",
    "FuzzConfig",
    "FuzzEngine",
    "FuzzError",
    "FuzzFunction",
    "FuzzReport",
    "FuzzTarget",
    "Fuzzer",
    "Mutator",
]
