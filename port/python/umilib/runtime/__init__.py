"""The asynchronous runtime. Mirrors ``umilib::runtime``.

Python has no Rust futures to give the runtime, so a task is a function
``poll(waker) -> bool`` that does what it can and returns ``True`` once it
is done, keeping ``waker.clone()`` to wake it when it can do more (as the C
ABI's tasks). A :class:`LocalExecutor` runs them in :meth:`LocalExecutor.run_until_idle`.
Channels carry byte messages. Errors are :class:`RuntimeStatusError`.
"""

from __future__ import annotations

import ctypes
import itertools
from typing import Callable

from umilib.ffi import Buffer, Bytes, FFIError, Handle, Library


class RuntimeStatusError(FFIError):
    """An error of the runtime; ``name`` is ``Closed``, ``Full``, ``Empty``, ``Cancelled`` or ``Pending``."""


Library.register_error("runtime", RuntimeStatusError)


class Waker(Handle):
    """The waker of a task. The one given to a poll function is valid only during the call;
    :meth:`clone` gives one to keep."""

    FREE = "umilib_runtime_waker_free"

    def wake(self) -> None:
        """Makes the executor poll the task again."""
        self.library.call("umilib_runtime_waker_wake", self.handle)

    def clone(self) -> Waker:
        """A waker of the same task to keep."""
        return Waker(Handle.create("umilib_runtime_waker_clone", self.handle))


class BorrowedWaker(Waker):
    """The waker given to a poll function: valid only during the call and owned by the executor.
    Closing it (or dropping it) only gives it up; :meth:`clone` gives a waker to keep."""

    def close(self) -> None:
        if self.pointer is not None:
            self.detach()


class JoinHandle(Handle):
    """The handle of a spawned task."""

    FREE = "umilib_runtime_join_handle_free"

    def abort(self) -> None:
        """Stops the task at its next poll."""
        self.library.call("umilib_runtime_join_handle_abort", self.handle)

    def result(self) -> None:
        """Returns once the task is done; raises ``Pending`` before, ``Cancelled`` if it was aborted or dropped."""
        self.library.call("umilib_runtime_join_handle_result", self.handle)

    @property
    def finished(self) -> bool:
        """Whether the task is done or cancelled (without taking its result)."""
        try:
            self.library.call("umilib_runtime_join_handle_result", self.handle)
        except RuntimeStatusError as error:
            return error.name != "Pending"
        return True


class LocalExecutor(Handle):
    """An executor that runs its tasks in :meth:`run_until_idle`. A task spawns others through a
    :meth:`clone` of the executor (a handle is not used again from inside a call on it). A poll
    function that raises ends its task; :meth:`run_until_idle` raises the exception afterwards."""

    FREE = "umilib_runtime_local_executor_free"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer or Handle.create("umilib_runtime_local_executor_new"))
        #: The callbacks of the tasks alive, kept until their drop callback, and the exceptions raised.
        self.callbacks: dict[int, tuple] = {}
        self.raised: list[BaseException] = []
        #: The keys of the tasks' contexts, shared by the clones (``next`` is atomic).
        self.keys = itertools.count(1)

    def clone(self) -> LocalExecutor:
        """Another handle of the same executor."""
        clone = LocalExecutor(Handle.create("umilib_runtime_local_executor_clone", self.handle))
        clone.callbacks, clone.raised, clone.keys = self.callbacks, self.raised, self.keys
        return clone

    def spawn(self, poll: Callable[[Waker], bool], drop: Callable[[], None] | None = None) -> JoinHandle:
        """Spawns the task of ``poll`` (and ``drop``, called once when it is dropped)."""
        callbacks, raised = self.callbacks, self.raised
        key = next(self.keys)

        def poll_task(context: int, waker: int) -> bool:
            borrowed = BorrowedWaker(waker)
            try:
                return bool(poll(borrowed))
            except BaseException as error:  # noqa: BLE001 - re-raised by run_until_idle
                raised.append(error)
                return True
            finally:
                borrowed.close()

        def drop_task(context: int) -> None:
            entry = callbacks.pop(context, None)
            try:
                if drop is not None:
                    drop()
            except BaseException as error:  # noqa: BLE001 - re-raised by run_until_idle
                raised.append(error)
            del entry

        entry = (self.library.type("umilib_runtime_TaskPoll")(poll_task), self.library.type("umilib_runtime_TaskDrop")(drop_task))
        callbacks[key] = entry
        return JoinHandle(Handle.create("umilib_runtime_local_executor_spawn", self.handle, entry[0], entry[1], key))

    def run_until_idle(self) -> int:
        """Runs the tasks in the run queue until it is empty; returns the polls made."""
        # The exceptions are taken under the lock, so that another thread's run does not take them.
        with self.locked():
            polls = self.library.value("umilib_runtime_local_executor_run_until_idle", ctypes.c_size_t, self.handle)
            if self.raised:
                error = self.raised[0]
                self.raised.clear()
                raise error
        return polls

    @property
    def queued(self) -> int:
        """The tasks waiting to run."""
        return self.library.value("umilib_runtime_local_executor_queued", ctypes.c_size_t, self.handle)


class TimerQueue(Handle):
    """Timers by deadline (nanoseconds of the caller's clock), each with a waker."""

    FREE = "umilib_runtime_timer_queue_free"

    def __init__(self) -> None:
        super().__init__(Handle.create("umilib_runtime_timer_queue_new"))

    def insert(self, deadline: int, waker: Waker | None = None) -> int:
        """Adds a timer of ``deadline`` whose expiry wakes ``waker``; returns its key."""
        return self.library.value("umilib_runtime_timer_queue_insert", ctypes.c_uint64, self.handle, deadline, waker)

    def remove(self, key: int) -> bool:
        """Removes the timer ``key``; whether it was waiting."""
        return self.library.value("umilib_runtime_timer_queue_remove", ctypes.c_bool, self.handle, key)

    def next_deadline(self) -> int | None:
        """The earliest deadline of the timers waiting."""
        has, deadline = ctypes.c_bool(), ctypes.c_uint64()
        self.library.call("umilib_runtime_timer_queue_next_deadline", self.handle, ctypes.byref(has), ctypes.byref(deadline))
        return deadline.value if has.value else None

    def fire(self, now: int) -> int:
        """Wakes the timers of a deadline of ``now`` or earlier; returns how many expired."""
        return self.library.value("umilib_runtime_timer_queue_fire", ctypes.c_size_t, self.handle, now)


class Sender(Handle):
    """A sending side of a bounded channel of byte messages."""

    FREE = "umilib_runtime_sender_free"

    def clone(self) -> Sender:
        return Sender(Handle.create("umilib_runtime_sender_clone", self.handle))

    def try_send(self, message: bytes | bytearray | memoryview) -> None:
        """Sends ``message``; raises ``Full`` or ``Closed``."""
        data, length = Bytes.readable(message)
        self.library.call("umilib_runtime_sender_try_send", self.handle, data, length)

    def poll_send(self, waker: Waker, message: bytes | bytearray | memoryview) -> bool:
        """Sends ``message`` if there is room; otherwise returns ``False`` and ``waker`` is woken when there may be."""
        data, length = Bytes.readable(message)
        return self.library.value("umilib_runtime_sender_poll_send", ctypes.c_bool, self.handle, waker, data, length)


class Receiver(Handle):
    """The receiving side of a bounded channel of byte messages."""

    FREE = "umilib_runtime_receiver_free"

    def try_receive(self) -> bytes:
        """The next message; raises ``Empty``, or ``Closed`` once every sender is gone and it is empty."""
        return self.library.output("umilib_runtime_receiver_try_receive", self.handle)

    def poll_receive(self, waker: Waker) -> bytes | None:
        """The next message, or ``None`` (and ``waker`` is woken when one comes); raises ``Closed``."""
        ready, buffer = ctypes.c_bool(), Buffer()
        self.library.call("umilib_runtime_receiver_poll_receive", self.handle, waker, ctypes.byref(ready), ctypes.byref(buffer))
        return self.library.take(buffer) if ready.value else None

    def close(self) -> None:
        """Closes the channel: sends fail from now on."""
        self.library.call("umilib_runtime_receiver_close", self.handle)

    def __len__(self) -> int:
        return self.library.value("umilib_runtime_receiver_len", ctypes.c_size_t, self.handle)


class Channel:
    """The constructors of the channels."""

    @staticmethod
    def bounded(capacity: int) -> tuple[Sender, Receiver]:
        """A channel of at most ``capacity`` messages in flight."""
        sender, receiver = ctypes.c_void_p(), ctypes.c_void_p()
        Library.default().call("umilib_runtime_channel_bounded", capacity, ctypes.byref(sender), ctypes.byref(receiver))
        return Sender(sender.value), Receiver(receiver.value)


__all__ = [
    "BorrowedWaker","Channel", "JoinHandle", "LocalExecutor", "Receiver", "RuntimeStatusError", "Sender", "TimerQueue", "Waker"]
