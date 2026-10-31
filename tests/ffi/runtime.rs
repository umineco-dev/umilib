use std::ffi::c_void;
use std::ptr;
use std::task::Waker;

use umilib::ffi::Buffer;
use umilib::ffi::runtime::*;
use umilib::runtime::{JoinHandle, LocalExecutor, Receiver, Sender, TimerQueue};

use super::Check;

/// The context of the C task of the test: polls until `remaining` wakes have been made, keeping its waker.
struct Countdown {
    remaining: u32,
    polls: u32,
    waker: *mut Waker,
    dropped: bool,
}

unsafe extern "C" fn poll_countdown(context: *mut c_void, waker: *const Waker) -> bool {
    // SAFETY: the test passes a Countdown that outlives the task.
    let countdown = unsafe { &mut *(context as *mut Countdown) };
    countdown.polls += 1;
    if countdown.remaining == 0 {
        return true;
    }
    countdown.remaining -= 1;
    unsafe {
        umilib_runtime_waker_free(countdown.waker);
        countdown.waker = ptr::null_mut();
        Check::ok(umilib_runtime_waker_clone(waker, &mut countdown.waker));
    }
    false
}

unsafe extern "C" fn drop_countdown(context: *mut c_void) {
    // SAFETY: as above.
    let countdown = unsafe { &mut *(context as *mut Countdown) };
    countdown.dropped = true;
    unsafe { umilib_runtime_waker_free(countdown.waker) };
    countdown.waker = ptr::null_mut();
}

#[test]
fn callback_tasks_run_and_wake_through_the_c_abi() {
    unsafe {
        let mut executor: *mut LocalExecutor = ptr::null_mut();
        Check::ok(umilib_runtime_local_executor_new(&mut executor));
        let mut countdown = Countdown { remaining: 3, polls: 0, waker: ptr::null_mut(), dropped: false };
        let context = &mut countdown as *mut Countdown as *mut c_void;
        let mut handle: *mut JoinHandle<()> = ptr::null_mut();
        let drop = TaskDrop(Some(drop_countdown));
        Check::ok(umilib_runtime_local_executor_spawn(executor, Some(poll_countdown), drop, context, &mut handle));
        let mut polls = 0usize;
        Check::ok(umilib_runtime_local_executor_run_until_idle(executor, &mut polls));
        assert_eq!((polls, countdown.polls), (1, 1));
        Check::fails(umilib_runtime_join_handle_result(handle), "runtime", "Pending");
        for _ in 0..3 {
            Check::ok(umilib_runtime_waker_wake(countdown.waker));
            Check::ok(umilib_runtime_local_executor_run_until_idle(executor, &mut polls));
        }
        assert_eq!(countdown.polls, 4);
        assert!(countdown.dropped);
        Check::ok(umilib_runtime_join_handle_result(handle));
        umilib_runtime_join_handle_free(handle);
        // An aborted task is dropped and reports Cancelled.
        let mut second = Countdown { remaining: 10, polls: 0, waker: ptr::null_mut(), dropped: false };
        let context = &mut second as *mut Countdown as *mut c_void;
        Check::ok(umilib_runtime_local_executor_spawn(executor, Some(poll_countdown), drop, context, &mut handle));
        Check::ok(umilib_runtime_local_executor_run_until_idle(executor, &mut polls));
        Check::ok(umilib_runtime_join_handle_abort(handle));
        Check::ok(umilib_runtime_local_executor_run_until_idle(executor, &mut polls));
        assert!(second.dropped);
        Check::fails(umilib_runtime_join_handle_result(handle), "runtime", "Cancelled");
        umilib_runtime_join_handle_free(handle);
        Check::fails(
            umilib_runtime_local_executor_spawn(executor, None, drop, context, &mut handle),
            "ffi",
            "InvalidArgument",
        );
        umilib_runtime_local_executor_free(executor);
    }
}

#[test]
fn timer_queues_and_channels_through_the_c_abi() {
    unsafe {
        let mut queue: *mut TimerQueue = ptr::null_mut();
        Check::ok(umilib_runtime_timer_queue_new(&mut queue));
        let (mut first, mut second) = (0u64, 0u64);
        Check::ok(umilib_runtime_timer_queue_insert(queue, 200, ptr::null(), &mut first));
        Check::ok(umilib_runtime_timer_queue_insert(queue, 100, ptr::null(), &mut second));
        let (mut has, mut deadline) = (false, 0u64);
        Check::ok(umilib_runtime_timer_queue_next_deadline(queue, &mut has, &mut deadline));
        assert_eq!((has, deadline), (true, 100));
        let mut removed = false;
        Check::ok(umilib_runtime_timer_queue_remove(queue, second, &mut removed));
        assert!(removed);
        let mut expired = 0usize;
        Check::ok(umilib_runtime_timer_queue_fire(queue, 1000, &mut expired));
        assert_eq!(expired, 1);
        Check::ok(umilib_runtime_timer_queue_next_deadline(queue, &mut has, &mut deadline));
        assert!(!has);
        // Both outputs are checked before either is written.
        has = true;
        Check::fails(umilib_runtime_timer_queue_next_deadline(queue, &mut has, ptr::null_mut()), "ffi", "NullPointer");
        assert!(has);
        let mut shared = 7u64;
        let shared_pointer: *mut u64 = &mut shared;
        Check::fails(
            umilib_runtime_timer_queue_next_deadline(queue, shared_pointer.cast(), shared_pointer),
            "ffi",
            "InvalidArgument",
        );
        assert_eq!(shared, 7);
        umilib_runtime_timer_queue_free(queue);

        let (mut sender, mut receiver): (*mut Sender<Vec<u8>>, *mut Receiver<Vec<u8>>) =
            (ptr::null_mut(), ptr::null_mut());
        Check::ok(umilib_runtime_channel_bounded(1, &mut sender, &mut receiver));
        Check::ok(umilib_runtime_sender_try_send(sender, b"one".as_ptr(), 3));
        Check::fails(umilib_runtime_sender_try_send(sender, b"two".as_ptr(), 3), "runtime", "Full");
        let waker = Waker::noop();
        let mut sent = true;
        Check::ok(umilib_runtime_sender_poll_send(sender, waker, b"two".as_ptr(), 3, &mut sent));
        assert!(!sent);
        let mut length = 0usize;
        Check::ok(umilib_runtime_receiver_len(receiver, &mut length));
        assert_eq!(length, 1);
        let mut message = Buffer::EMPTY;
        Check::ok(umilib_runtime_receiver_try_receive(receiver, &mut message));
        assert_eq!(message.as_slice(), b"one");
        umilib::ffi::umilib_ffi_buffer_free(&mut message);
        let mut ready = true;
        Check::ok(umilib_runtime_receiver_poll_receive(receiver, waker, &mut ready, &mut message));
        assert!(!ready);
        Check::fails(umilib_runtime_receiver_try_receive(receiver, &mut message), "runtime", "Empty");
        umilib_runtime_sender_free(sender);
        Check::fails(umilib_runtime_receiver_try_receive(receiver, &mut message), "runtime", "Closed");
        Check::fails(
            umilib_runtime_receiver_poll_receive(receiver, waker, &mut ready, &mut message),
            "runtime",
            "Closed",
        );
        umilib_runtime_receiver_free(receiver);
    }
}
