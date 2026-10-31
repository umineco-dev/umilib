"""The runtime of the platform. Mirrors ``umilib::platform::runtime``.

A :class:`ThreadPool` runs tasks of poll functions (as :mod:`umilib.runtime`
describes them) on its threads, and a :class:`Reactor` wakes them at
deadlines of the :class:`MonotonicClock`. The poll functions run on the
pool's threads, one at a time per task.

Each call on a handle locks it (see :class:`umilib.ffi.Handle`), so:

- a task spawns others through a :class:`PoolSpawner`, never through the
  :class:`ThreadPool`, whose :meth:`ThreadPool.shutdown` holds the pool
  while it waits for the threads that run the tasks;
- a task waited for with :meth:`ThreadPool.block_on` cannot be aborted
  from another thread through the same :class:`JoinHandle` meanwhile.

Pools still alive when the interpreter exits are stopped first. The
asynchronous sockets and the supervisor are not in the Python package yet.
"""

from __future__ import annotations

import atexit
import ctypes
import itertools
import weakref
from typing import Callable, ClassVar

from umilib.ffi import Handle, Library
from umilib.runtime import BorrowedWaker, JoinHandle, Waker


class MonotonicClock:
    """The system's monotonic clock."""

    @staticmethod
    def now() -> int:
        """The nanoseconds since the process first read the clock."""
        return Library.default().value("umilib_platform_runtime_monotonic_clock_now", ctypes.c_uint64)


class Reactor(Handle):
    """A thread that waits on the system's I/O and wakes timers."""

    FREE = "umilib_platform_runtime_reactor_free"

    def __init__(self) -> None:
        super().__init__(Handle.create("umilib_platform_runtime_reactor_new"))

    def now(self) -> int:
        """The nanoseconds of the reactor's clock (the :class:`MonotonicClock`)."""
        return self.library.value("umilib_platform_runtime_reactor_now", ctypes.c_uint64, self.handle)

    def wake_at(self, deadline: int, waker: Waker) -> int:
        """Wakes ``waker`` once the clock reaches ``deadline`` (at once if it has); returns the key
        of the timer, which a task that stops waiting gives to :meth:`remove`."""
        return self.library.value("umilib_platform_runtime_reactor_wake_at", ctypes.c_uint64, self.handle, deadline, waker)

    def remove(self, key: int) -> bool:
        """Removes the timer ``key``; whether it was waiting."""
        return self.library.value("umilib_platform_runtime_reactor_remove", ctypes.c_bool, self.handle, key)


class PoolTasks:
    """The callbacks of the tasks of a pool, kept until their drop callback, and the exceptions they raised."""

    def __init__(self) -> None:
        self.callbacks: dict[int, tuple] = {}
        self.raised: list[BaseException] = []
        #: The keys of the tasks' contexts (``next`` is atomic).
        self.keys = itertools.count(1)

    def entry(self, library: Library, poll: Callable[[Waker], bool], drop: Callable[[], None] | None) -> tuple[tuple, int]:
        """The C callbacks of a task of ``poll`` and ``drop``, and the key of its context."""
        callbacks, raised = self.callbacks, self.raised

        def poll_task(context: int, waker: int) -> bool:
            borrowed = BorrowedWaker(waker)
            try:
                return bool(poll(borrowed))
            except BaseException as error:  # noqa: BLE001 - re-raised by ThreadPool.block_on
                raised.append(error)
                return True
            finally:
                borrowed.close()

        def drop_task(context: int) -> None:
            entry = callbacks.pop(context, None)
            try:
                if drop is not None:
                    drop()
            except BaseException as error:  # noqa: BLE001 - re-raised by ThreadPool.block_on
                raised.append(error)
            del entry

        key = next(self.keys)
        entry = (library.type("umilib_runtime_TaskPoll")(poll_task), library.type("umilib_runtime_TaskDrop")(drop_task))
        callbacks[key] = entry
        return entry, key

    def raise_first(self) -> None:
        """Raises the first exception a callback raised, if any."""
        if self.raised:
            error = self.raised[0]
            self.raised.clear()
            raise error


class PoolSpawner(Handle):
    """A handle that spawns tasks on a :class:`ThreadPool` while it exists; tasks keep one to spawn more."""

    FREE = "umilib_platform_runtime_pool_spawner_free"

    def __init__(self, pointer: int, tasks: PoolTasks) -> None:
        super().__init__(pointer)
        self.tasks = tasks

    def spawn(self, poll: Callable[[Waker], bool], drop: Callable[[], None] | None = None) -> JoinHandle:
        """Spawns the task of ``poll`` (and ``drop``, called once when it is dropped); once the pool
        is gone or stopped, the task is dropped at once."""
        entry, key = self.tasks.entry(self.library, poll, drop)
        try:
            return JoinHandle(Handle.create("umilib_platform_runtime_pool_spawner_spawn", self.handle, entry[0], entry[1], key))
        except BaseException:
            # Not spawned: the pool never calls its drop callback.
            self.tasks.callbacks.pop(key, None)
            raise


class ThreadPool(Handle):
    """A pool of threads that run tasks of poll functions. A poll function that raises ends its
    task; :meth:`block_on` raises the exception afterwards."""

    FREE = "umilib_platform_runtime_thread_pool_free"
    #: The pools alive, stopped when the interpreter exits (their threads must not call into it then).
    alive: ClassVar[weakref.WeakSet] = weakref.WeakSet()

    def __init__(self, threads: int = 0) -> None:
        """A pool of ``threads`` threads (0 for as many as the system's parallelism)."""
        super().__init__(Handle.create("umilib_platform_runtime_thread_pool_new", threads))
        self.tasks = PoolTasks()
        ThreadPool.alive.add(self)

    @staticmethod
    def close_all() -> None:
        """Releases every pool alive (registered with :mod:`atexit`)."""
        for pool in list(ThreadPool.alive):
            pool.close()

    @property
    def threads(self) -> int:
        return self.library.value("umilib_platform_runtime_thread_pool_threads", ctypes.c_size_t, self.handle)

    def spawner(self) -> PoolSpawner:
        """A spawner of the pool, for tasks to spawn more."""
        return PoolSpawner(Handle.create("umilib_platform_runtime_thread_pool_spawner", self.handle), self.tasks)

    def spawn(self, poll: Callable[[Waker], bool], drop: Callable[[], None] | None = None) -> JoinHandle:
        """Spawns the task of ``poll`` (and ``drop``, called once when it is dropped)."""
        with self.spawner() as spawner:
            return spawner.spawn(poll, drop)

    def block_on(self, handle: JoinHandle) -> None:
        """Waits until the task of ``handle`` is done; raises ``Cancelled`` if it was aborted or
        dropped, and first the exception of a poll or drop function of the pool, if one raised."""
        try:
            ThreadPool.block_on_thread(handle)
        finally:
            self.tasks.raise_first()

    @staticmethod
    def block_on_thread(handle: JoinHandle) -> None:
        """Waits until the task of ``handle`` is done; raises ``Cancelled`` if it was aborted or dropped."""
        Library.default().call("umilib_platform_runtime_thread_pool_block_on_thread", handle)

    def shutdown(self) -> None:
        """Stops the threads (after the polls they are making) and drops the tasks left, calling
        their drop functions; tasks spawned afterwards are dropped at once."""
        self.library.call("umilib_platform_runtime_thread_pool_shutdown", self.handle)


atexit.register(ThreadPool.close_all)

__all__ = ["MonotonicClock", "PoolSpawner", "PoolTasks", "Reactor", "ThreadPool"]
