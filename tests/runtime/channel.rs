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
