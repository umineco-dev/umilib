"""Tests of umilib.ffi: loading, the manifest and status handling."""

import ctypes
import json
import os
from pathlib import Path

import pytest

import umilib
from umilib.ffi import FFIError, Handle, I128, Library, Nanoseconds, U128


def test_library_is_found_from_the_environment():
    assert Path(Library.find()) == Path(os.environ[Library.ENVIRONMENT]).resolve() or Path(Library.find()).is_file()


def test_missing_environment_path_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setenv(Library.ENVIRONMENT, str(tmp_path / "missing.so"))
    with pytest.raises(FFIError) as error:
        Library.find()
    assert error.value.name == "NotFound"
    monkeypatch.setenv(Library.ENVIRONMENT, str(tmp_path))
    with pytest.raises(FFIError):
        Library.find()


def test_directory_in_the_environment_is_searched(monkeypatch):
    library = Path(Library.default().path)
    monkeypatch.setenv(Library.ENVIRONMENT, str(library.parent))
    assert Path(Library.find()).name in Library.file_names()


def test_manifest_lists_every_module_and_is_declared():
    library = Library.default()
    names = [module["name"] for module in library.manifest["modules"]]
    assert names[0] == "ffi"
    assert {"bytes", "secret", "platform"} <= set(names)
    assert library.function("umilib_ffi_buffer_free") is not None
    with pytest.raises(FFIError) as error:
        library.function("umilib_does_not_exist")
    assert error.value.name == "Unavailable"


def test_version_is_the_crate_version():
    version = umilib.VERSION
    assert version.count(".") == 2
    with pytest.raises(AttributeError):
        umilib.DOES_NOT_EXIST  # noqa: B018


def test_manifest_json_is_valid():
    library = Library.default()
    text = library.output("umilib_ffi_manifest").decode("utf-8")
    assert json.loads(text) == library.manifest


def test_null_output_is_reported():
    with pytest.raises(FFIError) as error:
        Library.default().call("umilib_ffi_manifest", None)
    assert (error.value.domain, error.value.name) == ("ffi", "NullPointer")


def test_128_bit_integers_split_into_halves():
    value = 0x0102030405060708090A0B0C0D0E0F10
    assert U128.from_int(value).high == 0x0102030405060708
    assert U128.from_int(value).to_int() == value
    assert I128.from_int(-1).to_int() == -1
    assert I128.from_int(-(1 << 127)).to_int() == -(1 << 127)
    with pytest.raises(OverflowError):
        U128.from_int(-1)
    with pytest.raises(OverflowError):
        I128.from_int(1 << 127)


def test_nanoseconds_convert_timedeltas():
    import datetime

    assert Nanoseconds.from_timedelta(datetime.timedelta(seconds=1, microseconds=5)) == 1_000_005_000
    assert Nanoseconds.to_timedelta(2_000_000) == datetime.timedelta(milliseconds=2)


def test_handles_reject_null_and_use_after_close():
    with pytest.raises(FFIError):
        Handle(None)
    from umilib.bytes import Buffer

    buffer = Buffer()
    buffer.close()
    buffer.close()
    with pytest.raises(FFIError) as error:
        buffer.len()
    assert error.value.name == "Closed"
    with Buffer() as scoped:
        assert scoped.is_empty()
    assert scoped.pointer is None
    assert isinstance(ctypes.sizeof(U128), int)


def test_collection_and_with_blocks_free_handles_whose_close_is_an_operation():
    """``__del__`` and ``__exit__`` release a handle with ``free()``; a ``close()``
    of a protocol, such as sending a FIN, is never what releases it."""
    import gc

    from umilib.runtime import Channel

    _, receiver = Channel.bounded(1)
    closes = []
    receiver.close = lambda: closes.append(True)  # type: ignore[method-assign]
    with receiver:
        pass
    assert receiver.pointer is None and closes == []
    sender, receiver = Channel.bounded(1)
    freed = []

    class Recorded(type(receiver)):
        def close(self) -> None:
            closes.append(True)

        def free(self) -> None:
            freed.append(True)
            super().free()

    recorded = Recorded(receiver.detach())
    del recorded
    gc.collect()
    assert freed == [True] and closes == []
    # The receiver is gone, so the channel is closed for the sender.
    with pytest.raises(FFIError) as error:
        sender.try_send(b"a")
    assert error.value.name == "Closed"


def test_handles_are_locked_for_each_call():
    import threading

    from umilib.bytes import Buffer

    buffer = Buffer()
    threads = [threading.Thread(target=lambda: [buffer.write(b"ab") for _ in range(500)]) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert buffer.len() == 8 * 500 * 2
    # A callback running inside a C call on the handle (simulated by
    # entering the call) cannot use it again: it raises instead of deadlocking.
    buffer.enter_call()
    try:
        with pytest.raises(FFIError) as error:
            buffer.len()
        assert error.value.name == "Reentrant"
        with pytest.raises(FFIError):
            buffer.close()
    finally:
        buffer.exit_call()
    # Holding the lock for a block allows calls from the same thread.
    with buffer.locked():
        assert buffer.len() == 8000
    # Borrowed bytes are read while the lock is held, even while other threads write.
    readers_ok = []

    def read() -> None:
        for _ in range(300):
            data = buffer.as_slice()
            readers_ok.append(len(data) % 2 == 0 and set(data) <= {ord("a"), ord("b")})

    writers = [threading.Thread(target=lambda: [buffer.write(b"ab") for _ in range(300)]) for _ in range(4)]
    readers = [threading.Thread(target=read) for _ in range(4)]
    for thread in writers + readers:
        thread.start()
    for thread in writers + readers:
        thread.join()
    assert all(readers_ok) and buffer.len() == 8000 + 4 * 300 * 2
    buffer.close()


def test_integer_arguments_are_range_checked():
    from umilib.bytes import Buffer

    with pytest.raises(OverflowError):
        Buffer.with_limit(-1)
    with pytest.raises(OverflowError):
        Buffer.with_limit(1 << 64)


def test_negative_durations_are_rejected():
    import datetime

    with pytest.raises(ValueError):
        Nanoseconds.from_timedelta(datetime.timedelta(seconds=-1))
    # Integer arithmetic: no precision is lost for large values.
    assert Nanoseconds.to_timedelta((1 << 63) + 1_999) == datetime.timedelta(microseconds=((1 << 63) + 1_999) // 1_000)
