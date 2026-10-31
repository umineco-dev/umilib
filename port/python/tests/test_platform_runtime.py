"""Tests of umilib.platform.runtime: tasks on a thread pool, sleeping on a reactor's timer."""

import threading

import pytest

from umilib.ffi import FFIError
from umilib.platform.native import System
from umilib.platform.runtime import MonotonicClock, Reactor, ThreadPool
from umilib.runtime import RuntimeStatusError

pytestmark = pytest.mark.skipif(System.name() == "other", reason="the system has no platform runtime")


def test_the_monotonic_clock_goes_forward():
    first = MonotonicClock.now()
    second = MonotonicClock.now()
    assert second >= first


def test_tasks_sleep_on_the_reactor_and_run_on_the_pool_threads():
    reactor = Reactor()
    pool = ThreadPool(3)
    assert pool.threads == 3
    deadline = reactor.now() + 20_000_000
    threads = set()
    dropped = []

    def sleep(waker):
        threads.add(threading.current_thread().ident)
        if reactor.now() >= deadline:
            return True
        reactor.wake_at(deadline, waker)
        return False

    handles = [pool.spawn(sleep, lambda: dropped.append(True)) for _ in range(8)]
    for handle in handles:
        pool.block_on(handle)
    assert reactor.now() >= deadline
    assert threading.current_thread().ident not in threads
    pool.shutdown()
    assert len(dropped) == 8


def test_tasks_spawn_tasks_through_a_spawner():
    pool = ThreadPool(2)
    spawner = pool.spawner()
    children = []

    def parent(waker):
        children.extend(spawner.spawn(lambda waker: True) for _ in range(5))
        return True

    pool.block_on(pool.spawn(parent))
    assert len(children) == 5
    for child in children:
        pool.block_on(child)


def test_a_failed_spawn_keeps_no_callbacks():
    pool = ThreadPool(1)
    spawner = pool.spawner()
    spawner.free()
    with pytest.raises(FFIError) as error:
        spawner.spawn(lambda waker: True)
    assert error.value.name == "Closed"
    assert pool.tasks.callbacks == {}


def test_a_raising_task_ends_and_block_on_raises():
    pool = ThreadPool(1)

    def fail(waker):
        raise ValueError("a task fails")

    with pytest.raises(ValueError, match="a task fails"):
        pool.block_on(pool.spawn(fail))
    pool.block_on(pool.spawn(lambda waker: True))


def test_tasks_of_a_stopped_pool_are_cancelled():
    pool = ThreadPool(1)
    spawner = pool.spawner()
    pool.shutdown()
    dropped = []
    handle = spawner.spawn(lambda waker: True, lambda: dropped.append(True))
    with pytest.raises(RuntimeStatusError) as error:
        pool.block_on(handle)
    assert error.value.name == "Cancelled"
    assert dropped == [True]
    pool.close()
    other = spawner.spawn(lambda waker: True)
    with pytest.raises(RuntimeStatusError):
        ThreadPool.block_on_thread(other)


def test_borrowed_wakers_are_only_given_up_and_timers_are_removed():
    reactor = Reactor()
    pool = ThreadPool(1)
    keys = []

    def poll(waker):
        # Closing the waker of a poll gives it up; it is not released (it belongs to the pool).
        clone = waker.clone()
        with waker:
            pass
        keys.append(reactor.wake_at(reactor.now() + 10**12, clone))
        assert reactor.remove(keys[-1])
        assert not reactor.remove(keys[-1])
        clone.wake()
        return len(keys) == 3

    pool.block_on(pool.spawn(poll))
    assert len(keys) == 3
