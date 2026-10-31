"""Tests of umilib.runtime: tasks of poll functions, wakers, timers and channels."""

import threading

import pytest

from umilib.ffi import FFIError
from umilib.runtime import Channel, LocalExecutor, RuntimeStatusError, TimerQueue


def test_tasks_run_until_done_and_wake_from_other_threads():
    executor = LocalExecutor()
    sender, receiver = Channel.bounded(2)
    received = []
    dropped = []

    def consume(waker):
        while True:
            try:
                message = receiver.poll_receive(waker)
            except RuntimeStatusError as error:
                assert error.name == "Closed"
                return True
            if message is None:
                return False
            received.append(message)

    handle = executor.spawn(consume, lambda: dropped.append(True))
    assert executor.queued == 1
    executor.run_until_idle()
    assert not handle.finished

    def produce():
        for index in range(20):
            while True:
                try:
                    sender.try_send(b"message %d" % index)
                    break
                except RuntimeStatusError as error:
                    assert error.name == "Full"
                    threading.Event().wait(0.001)

    thread = threading.Thread(target=produce)
    thread.start()
    while thread.is_alive() or len(received) < 20:
        executor.run_until_idle()
        threading.Event().wait(0.001)
    thread.join()
    sender.close()
    executor.run_until_idle()
    assert received == [b"message %d" % index for index in range(20)]
    handle.result()
    assert dropped == [True]


def test_tasks_are_aborted_and_exceptions_raised():
    executor = LocalExecutor()
    kept = []

    def wait(waker):
        kept.append(waker.clone())
        return False

    handle = executor.spawn(wait)
    executor.run_until_idle()
    with pytest.raises(RuntimeStatusError) as error:
        handle.result()
    assert error.value.name == "Pending"
    kept[0].wake()
    assert executor.run_until_idle() == 1
    handle.abort()
    executor.run_until_idle()
    with pytest.raises(RuntimeStatusError) as error:
        handle.result()
    assert error.value.name == "Cancelled"

    def fail(waker):
        raise ValueError("bad task")

    executor.spawn(fail)
    with pytest.raises(ValueError):
        executor.run_until_idle()
    # A task spawns another through a clone of the executor.
    spawner = executor.clone()
    order = []
    executor.spawn(lambda waker: order.append("first") or bool(spawner.spawn(lambda w: order.append("second") or True)))
    executor.run_until_idle()
    assert order == ["first", "second"]


def test_timer_queues_wake_in_deadline_order():
    executor = LocalExecutor()
    queue = TimerQueue()
    fired = []

    def timer(name, deadline):
        state = {}

        def poll(waker):
            if "key" not in state:
                state["key"] = queue.insert(deadline, waker)
                return False
            fired.append(name)
            return True

        return poll

    executor.spawn(timer("late", 300))
    executor.spawn(timer("early", 100))
    executor.run_until_idle()
    assert queue.next_deadline() == 100
    assert queue.fire(99) == 0
    assert queue.fire(100) == 1
    executor.run_until_idle()
    assert fired == ["early"]
    key = queue.insert(200)
    assert queue.remove(key) and not queue.remove(key)
    assert queue.fire(1000) == 1
    executor.run_until_idle()
    assert fired == ["early", "late"] and queue.next_deadline() is None


def test_channels_report_full_empty_and_closed():
    sender, receiver = Channel.bounded(1)
    sender.try_send(b"a")
    with pytest.raises(RuntimeStatusError) as error:
        sender.try_send(b"b")
    assert error.value.name == "Full"
    assert len(receiver) == 1 and receiver.try_receive() == b"a"
    with pytest.raises(RuntimeStatusError) as error:
        receiver.try_receive()
    assert error.value.name == "Empty"
    second = sender.clone()
    sender.close()
    second.try_send(b"c")
    second.close()
    assert receiver.try_receive() == b"c"
    with pytest.raises(RuntimeStatusError) as error:
        receiver.try_receive()
    assert error.value.name == "Closed"


def test_tasks_spawned_through_clones_keep_their_callbacks():
    import gc

    executor = LocalExecutor()
    clone = executor.clone()
    wakers = []
    finished = []

    def waiting(waker):
        if wakers:
            finished.append("first")
            return True
        wakers.append(waker.clone())
        return False

    def other(waker):
        finished.append("second")
        return True

    first = executor.spawn(waiting)
    executor.run_until_idle()
    second = clone.spawn(other)
    clone.run_until_idle()
    # The callbacks of the first task must still be alive: collect, then wake and run it.
    gc.collect()
    wakers[0].wake()
    executor.run_until_idle()
    assert finished == ["second", "first"]
    first.result()
    second.result()
    assert executor.callbacks == {}


def test_closing_a_receiver_closes_the_channel_and_keeps_the_receiver():
    sender, receiver = Channel.bounded(1)
    receiver.close()
    with pytest.raises(RuntimeStatusError) as error:
        sender.try_send(b"a")
    assert error.value.name == "Closed"
    assert len(receiver) == 0
    receiver.free()
    with pytest.raises(FFIError) as error:
        len(receiver)
    assert error.value.name == "Closed"


def test_a_failed_spawn_keeps_no_callbacks():
    executor = LocalExecutor()
    clone = executor.clone()
    executor.free()
    with pytest.raises(FFIError) as error:
        executor.spawn(lambda waker: True)
    assert error.value.name == "Closed"
    assert clone.callbacks == {}
