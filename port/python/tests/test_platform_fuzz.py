"""Tests of umilib.platform.fuzz, mirroring the Rust tests."""

import datetime

import pytest

from umilib.platform.fuzz import Corpus, FuzzArguments, FuzzConfig, FuzzEngine, FuzzError, FuzzFunction, Fuzzer, Mutator


def test_mutator_is_deterministic_and_bounded():
    a, b = Mutator(42), Mutator(42)
    assert [a.next_u64() for _ in range(50)] == [b.next_u64() for _ in range(50)]
    assert Mutator(0).next_u64() == 0xE220A8397B1DCDAF
    mutator = Mutator(7)
    data = bytearray(8)
    for _ in range(2000):
        mutator.mutate(data, 16, [b"\x01" * 32])
        assert len(data) <= 16
    assert all(mutator.below(3) < 3 for _ in range(200))
    with pytest.raises(Exception):
        mutator.below(0)


def test_fuzzer_finds_a_failing_input_and_saves_it(tmp_path):
    def target(data: bytes) -> None:
        assert b"\xff\xff" not in data

    config = FuzzConfig(seed=3, iterations=1_000_000, crashes=str(tmp_path))
    report = Fuzzer(config).run(FuzzFunction("finds-magic", target))
    assert not report.is_success()
    assert len(report.failures) == 1
    assert Corpus.load(str(tmp_path / "finds-magic")).inputs == report.failures


def test_fuzzer_stops_at_its_limits():
    passes = FuzzFunction.new("passes", lambda data: None)
    report = Fuzzer(FuzzConfig(iterations=500)).run(passes)
    assert report.is_success() and report.iterations == 500
    report = Fuzzer(FuzzConfig(iterations=None, duration=datetime.timedelta(milliseconds=20))).run(passes)
    assert report.elapsed >= datetime.timedelta(milliseconds=20)


def test_config_fields_round_trip(tmp_path):
    config = FuzzConfig(seed=9, maximum_length=10, iterations=None, duration=datetime.timedelta(seconds=2), corpus=str(tmp_path))
    assert (config.seed, config.maximum_length, config.iterations) == (9, 10, None)
    assert config.duration == datetime.timedelta(seconds=2)
    assert config.corpus == str(tmp_path) and config.crashes is None
    assert Fuzzer(config).config().seed == 9
    assert (config.maximum_corpus_inputs, config.sample_interval) == (1024, 64)
    config.maximum_corpus_inputs, config.sample_interval = 16, 0
    assert (config.maximum_corpus_inputs, config.sample_interval) == (16, 0)
    assert Fuzzer(config).config().sample_interval == 0
    with pytest.raises(TypeError):
        FuzzConfig(unknown=1)


def test_corpus_round_trips_and_replay_reports_failures(tmp_path):
    assert Corpus.load(str(tmp_path / "missing")).inputs == []
    first = Corpus.save(str(tmp_path), b"pass")
    Corpus.save(str(tmp_path), b"fail")
    assert Corpus.save(str(tmp_path), b"pass") == first
    assert first.endswith(Corpus.file_name(b"pass"))
    corpus = Corpus.load(str(tmp_path))
    assert len(corpus.inputs) == 2

    def target(data: bytes) -> None:
        assert data != b"fail"

    report = Fuzzer().replay(FuzzFunction("replay", target), corpus)
    assert report.iterations == 2 and report.failures == [b"fail"]
    assert Fuzzer.check(FuzzFunction("replay", target), b"pass")
    assert not Fuzzer.check(FuzzFunction("replay", target), b"fail")


def test_arguments_are_parsed():
    assert FuzzArguments.parse(["--quiet", "--test-threads=1"]) == FuzzArguments()
    parsed = FuzzArguments.parse(["--fuzz", "bytes-reader", "--engine", "libfuzzer", "--time", "5", "--seed", "9", "--", "-runs=10"])
    assert parsed.fuzz == "bytes-reader" and parsed.engine == FuzzEngine.LibFuzzer
    assert parsed.duration == datetime.timedelta(seconds=5) and parsed.seed == 9
    assert parsed.engine_arguments == ["-runs=10"]
    assert FuzzArguments.parse(["bytes"]).filter == "bytes"
    assert FuzzArguments.parse(["--test-threads", "1", "--format", "terse"]) == FuzzArguments()
    listed = FuzzArguments.parse(["--list", "--skip", "secret"])
    assert listed.list and listed.skip == ["secret"]
    for invalid in (["--engine", "other"], ["--time", "x"], ["--bogus"]):
        with pytest.raises(FuzzError) as error:
            FuzzArguments.parse(invalid)
        assert error.value.name == "InvalidArguments"


def test_interrupts_stop_fuzzing_and_propagate():
    calls = []

    def interrupted(data: bytes) -> None:
        calls.append(None)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        Fuzzer(FuzzConfig(iterations=1000)).run(FuzzFunction("interrupted", interrupted))
    assert len(calls) == 1


def test_names_and_saved_failures(tmp_path):
    assert Fuzzer.is_valid_name("bytes-reader")
    assert not Fuzzer.is_valid_name("../escape")
    with pytest.raises(FuzzError) as error:
        Fuzzer().run(FuzzFunction("../escape", lambda data: None))
    assert error.value.name == "InvalidName"

    def fails(data: bytes) -> None:
        raise AssertionError

    report = Fuzzer(FuzzConfig(crashes=str(tmp_path))).run(FuzzFunction("fails", fails))
    assert len(report.saved) == 1 and report.saved[0].startswith(str(tmp_path))
