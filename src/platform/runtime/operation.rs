use core::cell::UnsafeCell;
use core::pin::Pin;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::vec::Vec;

use super::{PoolShared, Reactor};
use crate::platform::windows::sys::{self, Overlapped, RawSocket, WSABuffer, Windows};
use crate::platform::windows::{RawSocketAddress, Socket};
use crate::runtime::AtomicWaker;

/// An overlapped operation on a socket associated with a [`Reactor`].
///
/// It holds what the system reads and writes while the operation runs:
/// - the `OVERLAPPED`, first, so that the address the completion port
///   reports is the operation's;
/// - the buffer;
/// - the address;
/// - the flags;
/// - the socket an accept fills.
///
/// From [`Operation::start`] until the reactor receives the completion, the
/// system holds a reference to the operation (and through it to the
/// reactor). So a [`PendingOperation`] dropped early leaves the memory
/// valid: it cancels the operation, and the completion still comes.
#[repr(C)]
pub struct Operation {
    overlapped: UnsafeCell<Overlapped>,
    address: UnsafeCell<RawSocketAddress>,
    flags: UnsafeCell<u32>,
    done: AtomicBool,
    waker: AtomicWaker,
    socket: RawSocket,
    buffer: Mutex<Vec<u8>>,
    accepted: Mutex<Option<Socket>>,
    reactor: Reactor,
}

// SAFETY: the cells are written only by the system, while the operation
// runs. They are read only after `done` (Acquire), when the system no longer
// writes them.
unsafe impl Send for Operation {}
// SAFETY: as above.
unsafe impl Sync for Operation {}

impl Operation {
    /// An operation on `socket` (associated with `reactor`) with `buffer`
    /// (empty for none).
    pub fn new(reactor: &Reactor, socket: RawSocket, buffer: Vec<u8>) -> Operation {
        Operation {
            overlapped: UnsafeCell::new(Overlapped::default()),
            address: UnsafeCell::new(RawSocketAddress::empty()),
            flags: UnsafeCell::new(0),
            done: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            socket,
            buffer: Mutex::new(buffer),
            accepted: Mutex::new(None),
            reactor: reactor.clone(),
        }
    }

    /// The operation with the address `address`: the destination of a send
    /// or a connect. Without it, the address is empty, for a receive to fill.
    pub fn with_address(mut self, address: RawSocketAddress) -> Operation {
        *self.address.get_mut() = address;
        self
    }

    /// The operation with the socket `socket`, for an accept to fill.
    pub fn with_accepted(mut self, socket: Socket) -> Operation {
        self.accepted = Mutex::new(Some(socket));
        self
    }

    /// The `OVERLAPPED` to give the system.
    pub fn overlapped(&self) -> *mut Overlapped {
        self.overlapped.get()
    }

    /// The address to give the system: it is read by a send, and written by a receive.
    pub fn address(&self) -> *mut RawSocketAddress {
        self.address.get()
    }

    /// The flags to give the system (in and out for a receive).
    pub fn flags(&self) -> *mut u32 {
        self.flags.get()
    }

    /// The `WSABUF` of the bytes of the buffer from `start` to its length.
    /// The bytes stay where they are until the buffer is taken back with
    /// [`Operation::take_buffer`], which waits for the end of the operation.
    pub fn buffer(&self, start: usize) -> WSABuffer {
        let mut buffer = PoolShared::lock(&self.buffer);
        let start = start.min(buffer.len());
        let bytes = &mut buffer[start..];
        WSABuffer { length: u32::try_from(bytes.len()).unwrap_or(u32::MAX), data: bytes.as_mut_ptr() }
    }

    /// Starts the operation with `issue`, the Winsock call, given the
    /// operation; it returns true if the call succeeded or is pending. The
    /// system then holds a reference to the operation until the completion.
    /// The future gives the bytes transferred, or the call's error at once
    /// if it neither succeeded nor is pending (the operation is then done).
    pub fn start(self: &Arc<Operation>, issue: impl FnOnce(&Operation) -> bool) -> PendingOperation {
        let raw = Arc::into_raw(self.clone());
        let mut failure = None;
        if !issue(self) {
            let error = Socket::last_error();
            if error.raw_os_error() != Some(Windows::WSA_IO_PENDING) {
                // SAFETY: the call failed, so no completion will come and the reference is ours again.
                drop(unsafe { Arc::from_raw(raw) });
                self.done.store(true, Ordering::Release);
                failure = Some(error);
            }
        }
        PendingOperation { operation: self.clone(), failure }
    }

    /// Marks the operation at `address` done and wakes its task.
    ///
    /// # Safety
    /// `address` is the `OVERLAPPED` of an operation started with
    /// [`Operation::start`], reported by the completion port (once).
    pub unsafe fn complete(address: usize) {
        // SAFETY: the caller's promise: this is the reference `start` gave the system.
        let operation = unsafe { Arc::from_raw(address as *const Operation) };
        operation.done.store(true, Ordering::Release);
        operation.waker.wake();
    }

    /// Whether the system is done with the operation.
    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// The result of the operation once it is done: the bytes transferred.
    pub fn poll(&self, context: &mut Context<'_>) -> Poll<io::Result<u32>> {
        if !self.is_done() {
            self.waker.register(context.waker());
            if !self.is_done() {
                return Poll::Pending;
            }
        }
        let (mut transferred, mut flags) = (0u32, 0u32);
        // SAFETY: the operation is done; its OVERLAPPED is no longer written.
        let succeeded =
            unsafe { sys::WSAGetOverlappedResult(self.socket, self.overlapped(), &mut transferred, 0, &mut flags) };
        Poll::Ready(if succeeded != 0 { Ok(transferred) } else { Err(Socket::last_error()) })
    }

    /// Asks the system to stop the operation; its completion still comes.
    pub fn cancel(&self) {
        if !self.is_done() {
            // SAFETY: the socket and the OVERLAPPED of an operation; a failure means it already ended.
            unsafe { sys::CancelIoEx(self.socket as sys::Handle, self.overlapped()) };
        }
    }

    /// The buffer, once the system is done with it.
    pub fn take_buffer(&self) -> Option<Vec<u8>> {
        self.is_done().then(|| core::mem::take(&mut *PoolShared::lock(&self.buffer)))
    }

    /// The address, once the system is done with it.
    pub fn received_address(&self) -> Option<RawSocketAddress> {
        // SAFETY: the operation is done, so the system no longer writes the address.
        self.is_done().then(|| unsafe { *self.address.get() })
    }

    /// The socket an accept filled, once the system is done with it.
    pub fn take_accepted(&self) -> Option<Socket> {
        if self.is_done() { PoolShared::lock(&self.accepted).take() } else { None }
    }

    /// The reactor of the operation.
    pub fn reactor(&self) -> &Reactor {
        &self.reactor
    }
}

/// A started [`Operation`], as a future of its result (the bytes
/// transferred). Dropping it before the end cancels the operation.
pub struct PendingOperation {
    operation: Arc<Operation>,
    failure: Option<io::Error>,
}

impl PendingOperation {
    pub fn operation(&self) -> &Arc<Operation> {
        &self.operation
    }
}

impl Future for PendingOperation {
    type Output = io::Result<u32>;

    fn poll(mut self: Pin<&mut PendingOperation>, context: &mut Context<'_>) -> Poll<io::Result<u32>> {
        match self.failure.take() {
            Some(error) => Poll::Ready(Err(error)),
            None => self.operation.poll(context),
        }
    }
}

impl Drop for PendingOperation {
    fn drop(&mut self) {
        self.operation.cancel();
    }
}
