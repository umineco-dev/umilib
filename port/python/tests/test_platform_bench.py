"""Tests of umilib.platform.bench, mirroring the Rust tests."""

import datetime
import json
import math

import pytest

from umilib.platform.bench import Bench, BenchArguments, BenchConfig, BenchError, Statistics, Throughput


def test_statistics_follow_their_definitions():
    samples = [4.0, 1.0, 100.0, 3.0, 2.0]
    statistics = Statistics.from_samples(samples)
    assert samples == [1.0, 2.0, 3.0, 4.0, 100.0]
    assert (statistics.mean, statistics.median, statistics.median_absolute_deviation) == (22.0, 3.0, 1.0)
    assert (statistics.minimum, statistics.maximum) == (1.0, 100.0)
    expected = math.sqrt((21**2 + 20**2 + 19**2 + 18**2 + 78**2) / 5)
    assert abs(statistics.standard_deviation - expected) < 1e-9
    assert Statistics.from_samples([1.0, 2.0, 3.0, 4.0]).median == 2.5
    assert Statistics.from_samples([]) == Statistics()
    assert Statistics.median_of_sorted([1.0, 3.0]) == 2.0


def test_config_round_trips():
    config = BenchConfig(warmup=datetime.timedelta(milliseconds=1), measurement=datetime.timedelta(milliseconds=5), samples=5)
    assert config.warmup == datetime.timedelta(milliseconds=1)
    assert config.measurement == datetime.timedelta(milliseconds=5)
    assert config.samples == 5
    assert BenchConfig.quick().samples == 10


def test_bench_measures_and_reports():
    config = BenchConfig(warmup=datetime.timedelta(milliseconds=1), measurement=datetime.timedelta(milliseconds=5), samples=5)
    bench = Bench(config)
    assert bench.config().samples == 5
    calls = []
    result = bench.run("count", Throughput.Bytes(1024), lambda: calls.append(None))
    assert result.name == "count" and result.samples == 5 and result.iterations >= 1
    statistics = result.statistics
    assert statistics.minimum <= statistics.median <= statistics.maximum
    assert result.throughput == Throughput.Bytes(1024)
    assert result.throughput_per_second() > 0
    assert len(calls) >= result.iterations * 5
    bench.set_filter("hash")
    assert bench.run("count", None, lambda: None) is None
    assert bench.run("hash-sha", None, lambda: None).throughput is None
    assert [item.name for item in bench.results()] == ["count", "hash-sha"]
    assert len(bench.report_text().splitlines()) == 2
    report = json.loads(bench.report_json())
    assert report[0]["throughput"] == {"unit": "bytes", "amount": 1024}
    assert report[1]["throughput"] is None
    assert Bench.format_result(result).startswith("count")


def test_exceptions_in_routines_propagate():
    bench = Bench(BenchConfig.quick())

    def failing():
        raise ValueError("boom")

    with pytest.raises(ValueError):
        bench.run("failing", None, failing)

    calls = []

    def fails_later():
        calls.append(None)
        if len(calls) > 3:
            raise RuntimeError("late")

    with pytest.raises(RuntimeError):
        bench.run("fails-later", None, fails_later)
    assert len(calls) == 4, "a routine is not called again after it raised"


def test_durations_are_formatted_with_units():
    assert Bench.format_duration(12.345) == "12.35 ns"
    assert Bench.format_duration(1_500.0) == "1.50 µs"
    assert Bench.format_duration(2_500_000.0) == "2.50 ms"
    assert Bench.format_duration(3e9) == "3.00 s"


def test_throughput_units():
    assert Throughput.Elements(2).unit() == "elements"
    assert Throughput.Bytes(3).amount() == 3


def test_arguments_are_parsed():
    assert BenchArguments.parse(["--bench"]) == BenchArguments()
    parsed = BenchArguments.parse(["--bench", "--quick", "sha", "--json", "out.json"])
    assert (parsed.quick, parsed.filter, parsed.json) == (True, "sha", "out.json")
    for invalid in (["--json"], ["--unknown"], ["a", "b"]):
        with pytest.raises(BenchError) as error:
            BenchArguments.parse(invalid)
        assert error.value.name == "InvalidArguments"


def test_sample_bound():
    assert BenchConfig.MAXIMUM_SAMPLES == 1_000_000
