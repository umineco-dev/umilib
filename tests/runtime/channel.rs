use umilib::runtime::{Channel, ChannelError, Executor, LocalExecutor};

#[test]
fn bounded_channels_keep_order_and_capacity() {
    let (sender, mut receiver) = Channel::bounded::<u32>(3);
    for value in 0..3 {
        sender.try_send(value).unwrap();
    }
    let full = sender.try_send(3).unwrap_err();
    assert_eq!((full.error, full.value), (ChannelError::Full, 3));
    assert_eq!(receiver.len(), 3);
    assert_eq!(receiver.try_receive(), Ok(0));
    sender.try_send(3).unwrap();
    assert_eq!((1..4).map(|_| receiver.try_receive().unwrap()).collect::<Vec<_>>(), [1, 2, 3]);
    assert_eq!(receiver.try_receive(), Err(ChannelError::Empty));
    // The receiver sees the end once every sender is gone and the channel is drained.
    let second = sender.clone();
    drop(sender);
    second.try_send(9).unwrap();
    drop(second);
    assert_eq!(receiver.try_receive(), Ok(9));
    assert_eq!(receiver.try_receive(), Err(ChannelError::Closed));
}

#[test]
fn senders_wait_for_room_and_see_closing() {
    let executor = LocalExecutor::new();
    let (sender, mut receiver) = Channel::bounded::<u32>(1);
    let producer = executor.spawn(async move {
        for value in 0..10 {
            sender.send(value).await.unwrap();
        }
        sender
    });
    let consumer = executor.spawn(async move {
        let mut values = Vec::new();
        for _ in 0..10 {
            values.push(receiver.receive().await.unwrap());
        }
        (values, receiver)
    });
    let sender = executor.block_on(producer).unwrap();
    let (values, mut receiver) = executor.block_on(consumer).unwrap();
    assert_eq!(values, (0..10).collect::<Vec<_>>());
    // A closed receiver refuses values; a dropped one too.
    receiver.close();
    assert!(sender.is_closed());
    let error = executor.block_on(sender.send(1)).unwrap_err();
    assert_eq!((error.error, error.value), (ChannelError::Closed, 1));
    drop(receiver);
    assert_eq!(sender.try_send(2).unwrap_err().error, ChannelError::Closed);
    // A receiver waiting when the last sender leaves gets None.
    let (sender, mut receiver) = Channel::bounded::<u32>(1);
    let waiting = executor.spawn(async move { receiver.receive().await });
    executor.run_until_idle();
    drop(sender);
    assert_eq!(executor.block_on(waiting), Ok(None));
}

#[test]
fn oneshot_channels_deliver_one_value() {
    let executor = LocalExecutor::new();
    let (sender, mut receiver) = Channel::oneshot::<String>();
    assert_eq!(receiver.try_receive(), Err(ChannelError::Empty));
    sender.send("value".into()).unwrap();
    assert_eq!(receiver.try_receive(), Ok("value".into()));
    let (sender, receiver) = Channel::oneshot::<u8>();
    drop(sender);
    assert_eq!(executor.block_on(receiver), Err(ChannelError::Closed));
    let (sender, receiver) = Channel::oneshot::<u8>();
    drop(receiver);
    assert!(sender.is_closed());
    assert_eq!(sender.send(4), Err(4));
}

/// A waker that drops a sender of the channel it waits on when woken, as a
/// task whose pool is stopping drops its future (and the sender in it) inside
/// the wake.
struct DroppingWaker {
    sender: std::sync::Mutex<Option<umilib::runtime::Sender<u32>>>,
}

impl std::task::Wake for DroppingWaker {
    fn wake(self: std::sync::Arc<DroppingWaker>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &std::sync::Arc<DroppingWaker>) {
        drop(self.sender.lock().unwrap().take());
    }
}

/// Runs `body` on a thread of its own and fails if it does not end within a
/// minute (a waker woken under the channel's lock spins forever on it).
fn finishes(body: impl FnOnce() + Send + 'static) {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        body();
        let _ = done.send(());
    });
    finished.recv_timeout(std::time::Duration::from_secs(60)).expect("the channel operation never returned");
}

/// A full channel with a sender waiting for room, whose waker drops another sender of the channel.
fn waiting_sender() -> (umilib::runtime::Sender<u32>, umilib::runtime::Receiver<u32>) {
    use std::future::Future;
    let (sender, receiver) = Channel::bounded::<u32>(1);
    sender.try_send(0).unwrap();
    let waker = std::sync::Arc::new(DroppingWaker { sender: std::sync::Mutex::new(Some(sender.clone())) });
    let waker = std::task::Waker::from(waker);
    assert!(std::pin::Pin::new(&mut sender.send(1)).poll(&mut std::task::Context::from_waker(&waker)).is_pending());
    (sender, receiver)
}

#[test]
fn senders_are_woken_outside_the_channel() {
    finishes(|| {
        let (_sender, mut receiver) = waiting_sender();
        assert_eq!(receiver.try_receive(), Ok(0));
    });
    finishes(|| {
        let (_sender, mut receiver) = waiting_sender();
        let executor = LocalExecutor::new();
        assert_eq!(executor.block_on(receiver.receive()), Some(0));
    });
    finishes(|| {
        let (_sender, mut receiver) = waiting_sender();
        receiver.close();
    });
    finishes(|| {
        let (_sender, receiver) = waiting_sender();
        drop(receiver);
    });
}

/// A waker that counts its wakes.
#[derive(Default)]
struct CountingWaker(std::sync::atomic::AtomicUsize);

impl std::task::Wake for CountingWaker {
    fn wake(self: std::sync::Arc<CountingWaker>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &std::sync::Arc<CountingWaker>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn a_task_polling_again_is_kept_once() {
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    // `Waker::will_wake` is best effort: it may say false for wakers of one
    // task, and does under Miri, where each use of a waker's vtable has its
    // own address. The count of kept wakers is checked only where it is exact.
    let exact = !cfg!(miri);
    let counter = Arc::new(CountingWaker::default());
    let waker = std::task::Waker::from(counter.clone());
    let mut context = std::task::Context::from_waker(&waker);
    // A sender polled many times while the channel is full keeps one waker, and is woken once.
    let (sender, mut receiver) = Channel::bounded::<u32>(1);
    sender.try_send(0).unwrap();
    for value in 1..100 {
        let mut send = sender.send(value);
        assert!(std::pin::Pin::new(&mut send).poll(&mut context).is_pending());
    }
    if exact {
        assert_eq!(Arc::strong_count(&counter), 3);
    }
    assert_eq!(receiver.try_receive(), Ok(0));
    assert!(counter.0.load(Ordering::SeqCst) >= 1);
    if exact {
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    }
    // Every waker kept is given back by the wake.
    assert_eq!(Arc::strong_count(&counter), 2);
    // So does a receiver polled many times while the channel is empty.
    let woken = counter.0.load(Ordering::SeqCst);
    for _ in 0..100 {
        assert!(std::pin::Pin::new(&mut receiver.receive()).poll(&mut context).is_pending());
    }
    assert_eq!(Arc::strong_count(&counter), 3);
    sender.try_send(1).unwrap();
    assert_eq!(counter.0.load(Ordering::SeqCst), woken + 1);
    assert_eq!(Arc::strong_count(&counter), 2);
}
