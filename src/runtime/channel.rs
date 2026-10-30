use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use super::sync::SpinLock;

/// Why a channel operation did not take or give a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelError {
    /// The other side is gone (or the channel was closed).
    Closed,
    /// The channel holds as many values as its capacity.
    Full,
    /// The channel holds no value.
    Empty,
}

/// A value a channel did not take, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendError<T> {
    pub error: ChannelError,
    pub value: T,
}

/// The constructors of the channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel;

impl Channel {
    /// A channel of at most `capacity` values (at least 1) in flight, of any
    /// number of senders and one receiver; senders wait while it is full.
    pub fn bounded<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
        let shared = Arc::new(SpinLock::new(ChannelState {
            queue: VecDeque::new(),
            capacity: capacity.max(1),
            senders: 1,
            receiver: true,
            receiver_waker: None,
            sender_wakers: VecDeque::new(),
        }));
        (Sender { shared: shared.clone() }, Receiver { shared })
    }

    /// A channel of one value from one sender to one receiver.
    pub fn oneshot<T>() -> (OneshotSender<T>, OneshotReceiver<T>) {
        let shared = Arc::new(SpinLock::new(OneshotState { value: None, sender: true, receiver: true, waker: None }));
        (OneshotSender { shared: shared.clone() }, OneshotReceiver { shared })
    }
}

/// What the sides of a bounded channel share.
#[derive(Debug)]
pub struct ChannelState<T> {
    queue: VecDeque<T>,
    capacity: usize,
    senders: usize,
    receiver: bool,
    receiver_waker: Option<Waker>,
    sender_wakers: VecDeque<Waker>,
}

impl<T> ChannelState<T> {
    /// Wakes every sender waiting for room (they retry, and wait again if needed).
    pub fn wake_senders(&mut self) {
        for waker in self.sender_wakers.drain(..) {
            waker.wake();
        }
    }
}

/// A sending side of a bounded channel; clones send into the same channel.
#[derive(Debug)]
pub struct Sender<T> {
    shared: Arc<SpinLock<ChannelState<T>>>,
}

impl<T> Sender<T> {
    /// Sends `value` if the channel has room.
    pub fn try_send(&self, value: T) -> Result<(), SendError<T>> {
        let mut state = self.shared.lock();
        if !state.receiver {
            return Err(SendError { error: ChannelError::Closed, value });
        }
        if state.queue.len() >= state.capacity {
            return Err(SendError { error: ChannelError::Full, value });
        }
        state.queue.push_back(value);
        let waker = state.receiver_waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }

    /// Sends `value`, waiting for room; fails with `Closed` (giving the value back) once the receiver is gone.
    pub fn send(&self, value: T) -> SendFuture<'_, T> {
        SendFuture { sender: self, value: Some(value) }
    }

    /// Whether the receiver is gone.
    pub fn is_closed(&self) -> bool {
        !self.shared.lock().receiver
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Sender<T> {
        self.shared.lock().senders += 1;
        Sender { shared: self.shared.clone() }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.senders -= 1;
        if state.senders == 0 {
            let waker = state.receiver_waker.take();
            drop(state);
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }
}

/// The future of [`Sender::send`].
#[derive(Debug)]
pub struct SendFuture<'a, T> {
    sender: &'a Sender<T>,
    value: Option<T>,
}

impl<T> Unpin for SendFuture<'_, T> {}

impl<T> Future for SendFuture<'_, T> {
    type Output = Result<(), SendError<T>>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), SendError<T>>> {
        let value = self.value.take().expect("a send future polled after it finished");
        match self.sender.try_send(value) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(SendError { error: ChannelError::Full, value }) => {
                let mut state = self.sender.shared.lock();
                // The receiver may have taken a value between the attempt and the lock.
                if state.queue.len() < state.capacity || !state.receiver {
                    drop(state);
                    self.value = Some(value);
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
                state.sender_wakers.push_back(context.waker().clone());
                drop(state);
                self.value = Some(value);
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

/// The receiving side of a bounded channel.
#[derive(Debug)]
pub struct Receiver<T> {
    shared: Arc<SpinLock<ChannelState<T>>>,
}

impl<T> Receiver<T> {
    /// The next value if one is there; `Closed` once every sender is gone and the channel is empty.
    pub fn try_receive(&mut self) -> Result<T, ChannelError> {
        let mut state = self.shared.lock();
        match state.queue.pop_front() {
            Some(value) => {
                state.wake_senders();
                Ok(value)
            }
            None if state.senders == 0 => Err(ChannelError::Closed),
            None => Err(ChannelError::Empty),
        }
    }

    /// The next value, waiting for one; `None` once every sender is gone and the channel is empty.
    pub fn receive(&mut self) -> ReceiveFuture<'_, T> {
        ReceiveFuture { receiver: self }
    }

    /// Stops the channel: sends fail from now on; the values in it can still be received.
    pub fn close(&mut self) {
        let mut state = self.shared.lock();
        state.receiver = false;
        state.wake_senders();
    }

    /// The values in the channel.
    pub fn len(&self) -> usize {
        self.shared.lock().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.close();
    }
}

/// The future of [`Receiver::receive`].
#[derive(Debug)]
pub struct ReceiveFuture<'a, T> {
    receiver: &'a mut Receiver<T>,
}

impl<T> Future for ReceiveFuture<'_, T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<T>> {
        let mut state = self.receiver.shared.lock();
        if let Some(value) = state.queue.pop_front() {
            state.wake_senders();
            return Poll::Ready(Some(value));
        }
        if state.senders == 0 {
            return Poll::Ready(None);
        }
        state.receiver_waker = Some(context.waker().clone());
        Poll::Pending
    }
}

/// What the sides of a oneshot channel share.
#[derive(Debug)]
pub struct OneshotState<T> {
    value: Option<T>,
    sender: bool,
    receiver: bool,
    waker: Option<Waker>,
}

/// The sending side of a oneshot channel.
#[derive(Debug)]
pub struct OneshotSender<T> {
    shared: Arc<SpinLock<OneshotState<T>>>,
}

impl<T> OneshotSender<T> {
    /// Sends `value`; gives it back if the receiver is gone.
    pub fn send(self, value: T) -> Result<(), T> {
        let mut state = self.shared.lock();
        if !state.receiver {
            return Err(value);
        }
        state.value = Some(value);
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }

    /// Whether the receiver is gone.
    pub fn is_closed(&self) -> bool {
        !self.shared.lock().receiver
    }
}

impl<T> Drop for OneshotSender<T> {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.sender = false;
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// The receiving side of a oneshot channel: a future of the value, or
/// `Closed` if the sender is gone without sending.
#[derive(Debug)]
pub struct OneshotReceiver<T> {
    shared: Arc<SpinLock<OneshotState<T>>>,
}

impl<T> OneshotReceiver<T> {
    /// The value if it was sent; `Empty` while it may still be, `Closed` once it cannot.
    pub fn try_receive(&mut self) -> Result<T, ChannelError> {
        let mut state = self.shared.lock();
        match state.value.take() {
            Some(value) => Ok(value),
            None if state.sender => Err(ChannelError::Empty),
            None => Err(ChannelError::Closed),
        }
    }
}

impl<T> Future for OneshotReceiver<T> {
    type Output = Result<T, ChannelError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<T, ChannelError>> {
        let mut state = self.shared.lock();
        match state.value.take() {
            Some(value) => Poll::Ready(Ok(value)),
            None if !state.sender => Poll::Ready(Err(ChannelError::Closed)),
            None => {
                state.waker = Some(context.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl<T> Drop for OneshotReceiver<T> {
    fn drop(&mut self) {
        self.shared.lock().receiver = false;
    }
}
