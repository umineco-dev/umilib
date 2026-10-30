"""Measuring how long code takes to run. Mirrors ``umilib::platform::bench``.

Durations are :class:`datetime.timedelta` where Rust uses ``Duration``;
statistics are in nanoseconds per iteration, as in Rust.
"""

from __future__ import annotations

import ctypes
import datetime
from dataclasses import dataclass
from typing import Callable

from umilib.ffi import Buffer as FFIBuffer
from umilib.ffi import Callback, FFIError, Handle, Library, Nanoseconds, Text


class BenchError(FFIError):
    """An error of ``platform.bench``, such as ``InvalidArguments``."""


Library.register_error("platform.bench", BenchError)


@dataclass(frozen=True)
class Throughput:
    """The amount of work done by one iteration: ``Throughput.Bytes(n)`` or ``Throughput.Elements(n)``."""

    kind: int
    count: int

    BYTES = 1
    ELEMENTS = 2

    @classmethod
    def Bytes(cls, amount: int) -> Throughput:  # noqa: N802 - mirrors the Rust variant
        return cls(cls.BYTES, amount)

    @classmethod
    def Elements(cls, amount: int) -> Throughput:  # noqa: N802 - mirrors the Rust variant
        return cls(cls.ELEMENTS, amount)

    def amount(self) -> int:
        return self.count

    def unit(self) -> str:
        return "bytes" if self.kind == Throughput.BYTES else "elements"


@dataclass(frozen=True)
class Statistics:
    """A summary of samples, in nanoseconds per iteration."""

    mean: float = 0.0
    median: float = 0.0
    median_absolute_deviation: float = 0.0
    standard_deviation: float = 0.0
    minimum: float = 0.0
    maximum: float = 0.0

    @classmethod
    def from_c(cls, value: ctypes.Structure) -> Statistics:
        return cls(*(getattr(value, name) for name, _ in value._fields_))

    @classmethod
    def from_samples(cls, samples: list[float]) -> Statistics:
        """Summarizes ``samples``, which are reordered (sorted) in place."""
        library = Library.default()
        array = (ctypes.c_double * len(samples))(*samples)
        out = library.type("umilib_platform_bench_Statistics")()
        library.call("umilib_platform_bench_statistics_from_samples", array if samples else None, len(samples), ctypes.byref(out))
        samples[:] = list(array)
        return cls.from_c(out)

    @staticmethod
    def median_of_sorted(values: list[float]) -> float:
        """The median of sorted, non-empty ``values``."""
        array = (ctypes.c_double * len(values))(*values)
        return Library.default().value("umilib_platform_bench_statistics_median_of_sorted", ctypes.c_double, array, len(values))


class BenchConfig(Handle):
    """How long and how often :class:`Bench` measures each routine."""

    FREE = "umilib_platform_bench_bench_config_free"
    MAXIMUM_SAMPLES = 1_000_000

    def __init__(self, warmup: datetime.timedelta | None = None, measurement: datetime.timedelta | None = None,
                 samples: int | None = None, pointer: int | None = None) -> None:
        super().__init__(pointer if pointer is not None else Handle.create("umilib_platform_bench_bench_config_new"))
        if warmup is not None:
            self.warmup = warmup
        if measurement is not None:
            self.measurement = measurement
        if samples is not None:
            self.samples = samples

    @classmethod
    def quick(cls) -> BenchConfig:
        return cls(pointer=Handle.create("umilib_platform_bench_bench_config_quick"))

    @property
    def warmup(self) -> datetime.timedelta:
        return Nanoseconds.to_timedelta(self.library.value("umilib_platform_bench_bench_config_warmup", ctypes.c_uint64, self.handle))

    @warmup.setter
    def warmup(self, value: datetime.timedelta) -> None:
        self.library.call("umilib_platform_bench_bench_config_set_warmup", self.handle, Nanoseconds.from_timedelta(value))

    @property
    def measurement(self) -> datetime.timedelta:
        return Nanoseconds.to_timedelta(self.library.value("umilib_platform_bench_bench_config_measurement", ctypes.c_uint64, self.handle))

    @measurement.setter
    def measurement(self, value: datetime.timedelta) -> None:
        self.library.call("umilib_platform_bench_bench_config_set_measurement", self.handle, Nanoseconds.from_timedelta(value))

    @property
    def samples(self) -> int:
        return self.library.value("umilib_platform_bench_bench_config_samples", ctypes.c_size_t, self.handle)

    @samples.setter
    def samples(self, value: int) -> None:
        self.library.call("umilib_platform_bench_bench_config_set_samples", self.handle, value)


class BenchResult(Handle):
    """The measurement of one routine."""

    FREE = "umilib_platform_bench_bench_result_free"

    @property
    def name(self) -> str:
        return self.library.output("umilib_platform_bench_bench_result_name", self.handle).decode("utf-8")

    @property
    def iterations(self) -> int:
        return self.library.value("umilib_platform_bench_bench_result_iterations", ctypes.c_uint64, self.handle)

    @property
    def samples(self) -> int:
        return self.library.value("umilib_platform_bench_bench_result_samples", ctypes.c_size_t, self.handle)

    @property
    def statistics(self) -> Statistics:
        out = self.library.type("umilib_platform_bench_Statistics")()
        self.library.call("umilib_platform_bench_bench_result_statistics", self.handle, ctypes.byref(out))
        return Statistics.from_c(out)

    @property
    def throughput(self) -> Throughput | None:
        kind = self.library.value("umilib_platform_bench_bench_result_throughput_kind", ctypes.c_uint8, self.handle)
        amount = self.library.value("umilib_platform_bench_bench_result_throughput_amount", ctypes.c_uint64, self.handle)
        return Throughput(kind, amount) if kind else None

    def throughput_per_second(self) -> float | None:
        if self.throughput is None:
            return None
        rate = self.library.value("umilib_platform_bench_bench_result_throughput_per_second", ctypes.c_double, self.handle)
        return rate if rate > 0 else None


class Bench(Handle):
    """Runs routines and collects their :class:`BenchResult` objects."""

    FREE = "umilib_platform_bench_bench_free"

    def __init__(self, config: BenchConfig | None = None) -> None:
        config = config if config is not None else BenchConfig()
        super().__init__(Handle.create("umilib_platform_bench_bench_new", config.handle))

    def config(self) -> BenchConfig:
        return BenchConfig(pointer=Handle.create("umilib_platform_bench_bench_config", self.handle))

    def set_filter(self, filter: str | None) -> None:  # noqa: A002 - mirrors the Rust parameter
        data, length = Text.encode(filter)
        self.library.call("umilib_platform_bench_bench_set_filter", self.handle, data, length)

    def results(self) -> list[BenchResult]:
        count = self.library.value("umilib_platform_bench_bench_result_count", ctypes.c_size_t, self.handle)
        return [BenchResult(Handle.create("umilib_platform_bench_bench_results", self.handle, index)) for index in range(count)]

    def run(self, name: str, throughput: Throughput | None, routine: Callable[[], object]) -> BenchResult | None:
        """Measures ``routine`` under ``name`` unless the filter excludes it.

        If the routine raises, it is not called again, and the exception is
        raised once measuring ends; the routine is called once before measuring
        so that a routine that always fails is reported at once.
        """
        routine()
        guarded, raised = Callback.guard(lambda context: None if raised else routine(), None)
        callback = self.library.type("umilib_platform_bench_Routine")(guarded)
        data, length = Text.encode(name)
        kind, amount = (throughput.kind, throughput.count) if throughput else (0, 0)
        out = ctypes.c_void_p()
        self.library.call("umilib_platform_bench_bench_run", self.handle, data, length, kind, amount, callback, None, ctypes.byref(out))
        if raised:
            raise raised[0]
        return BenchResult(out.value) if out.value else None

    @staticmethod
    def format_duration(nanoseconds: float) -> str:
        return Library.default().output("umilib_platform_bench_bench_format_duration", float(nanoseconds)).decode("utf-8")

    @staticmethod
    def format_result(result: BenchResult) -> str:
        return Library.default().output("umilib_platform_bench_bench_format_result", result.handle).decode("utf-8")

    def report_text(self) -> str:
        return self.library.output("umilib_platform_bench_bench_report_text", self.handle).decode("utf-8")

    def report_json(self) -> str:
        return self.library.output("umilib_platform_bench_bench_report_json", self.handle).decode("utf-8")


class BenchArguments:
    """Command-line arguments of a benchmark program."""

    def __init__(self, quick: bool = False, json: str | None = None, filter: str | None = None) -> None:  # noqa: A002
        self.quick = quick
        self.json = json
        self.filter = filter

    @classmethod
    def parse(cls, arguments: list[str]) -> BenchArguments:
        """Parses ``arguments``, which do not include the program name."""
        library = Library.default()
        array, count, kept = Text.array(arguments)
        parsed = Handle.create("umilib_platform_bench_bench_arguments_parse", array, count)
        try:
            quick = library.value("umilib_platform_bench_bench_arguments_quick", ctypes.c_bool, parsed)
            json = library.optional("umilib_platform_bench_bench_arguments_json", FFIBuffer, parsed)
            filter = library.optional("umilib_platform_bench_bench_arguments_filter", FFIBuffer, parsed)  # noqa: A001
        finally:
            library.function("umilib_platform_bench_bench_arguments_free")(parsed)
        del kept
        return cls(quick, json.decode("utf-8") if json is not None else None, filter.decode("utf-8") if filter is not None else None)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, BenchArguments) and (self.quick, self.json, self.filter) == (other.quick, other.json, other.filter)


__all__ = ["Bench", "BenchArguments", "BenchConfig", "BenchError", "BenchResult", "Statistics", "Throughput"]
