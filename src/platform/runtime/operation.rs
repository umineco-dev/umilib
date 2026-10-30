use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::pin::Pin;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::vec::Vec;

use super::{PoolShared, Reactor};
use crate::platform::windows::sys::{self, Overlapped, RawSocket, WSABuffer, Windows};
use crate::platform::windows::{RawSocketAddress, Socket};
use crate::runtime::AtomicWaker;

/// How the completions of a socket's operations reach the reactor's
/// completion port ([`Reactor::register`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompletionRoute {
    /// The socket is associated with the port, which the system queues the
    /// completions to.
    Port,
    /// The socket is not associated with the port: it shares its underlying
    /// socket with another process ([`Socket::is_duplicate`]), and a socket
    /// may be associated with only one port. Each operation signals an event
    /// instead (with the low bit of `OVERLAPPED.hEvent` set, so that the
    /// system queues it to no port), and a wait of the system's thread pool
    /// queues the completion to the reactor's port.
    Event,
}

/// An overlapped operation on a socket registered with a [`Reactor`].
///
/// It holds what the system reads and writes while the operation runs:
/// - the `OVERLAPPED`, first, so that the address the completion port
///   reports is the operation's;
/// - the buffer;
/// - the address;
/// - the flags;
/// - the socket an accept fills;
/// - on [`CompletionRoute::Event`], the event and its wait.
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
    route: CompletionRoute,
    buffer: Mutex<Vec<u8>>,
    accepted: Mutex<Option<Socket>>,
    /// The event the operation signals, on [`CompletionRoute::Event`].
    event: OnceLock<OwnedHandle>,
    /// The thread-pool wait for the event, once registered.
    wait: AtomicPtr<c_void>,
    reactor: Reactor,
}

// SAFETY: the cells are written only by the system, while the operation
// runs. They are read only after `done` (Acquire), when the system no longer
// writes them.
unsafe impl Send for Operation {}
// SAFETY: as above.
unsafe impl Sync for Operation {}

impl Operation {
    /// An operation on `socket` (registered with `reactor` by `route`) with
    /// `buffer` (empty for none).
    pub fn new(reactor: &Reactor, socket: RawSocket, route: CompletionRoute, buffer: Vec<u8>) -> Operation {
        Operation {
            overlapped: UnsafeCell::new(Overlapped::default()),
            address: UnsafeCell::new(RawSocketAddress::empty()),
            flags: UnsafeCell::new(0),
            done: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            socket,
            route,
            buffer: Mutex::new(buffer),
            accepted: Mutex::new(None),
            event: OnceLock::new(),
            wait: AtomicPtr::new(core::ptr::null_mut()),
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
        let event = match self.route {
            CompletionRoute::Port => None,
            CompletionRoute::Event => match self.prepare_event() {
                Ok(event) => Some(event),
                Err(error) => {
                    self.done.store(true, Ordering::Release);
                    return PendingOperation { operation: self.clone(), failure: Some(error) };
                }
            },
        };
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
        if failure.is_none()
            && let Some(event) = event
            && let Err(error) = self.watch_event(raw, event)
        {
            failure = Some(error);
        }
        PendingOperation { operation: self.clone(), failure }
    }

    /// Makes the event of [`CompletionRoute::Event`], puts it in the
    /// `OVERLAPPED` before the operation is issued, and returns its handle
    /// (owned by the operation).
    fn prepare_event(&self) -> io::Result<sys::Handle> {
        // SAFETY: a manual-reset event, not signaled, without a name or attributes; the result is checked.
        let event = unsafe { sys::CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the handle was just created and is owned by nothing else.
        let event = unsafe { OwnedHandle::from_raw_handle(event as RawHandle) };
        // The low bit keeps the completion off every completion port (GetQueuedCompletionStatus).
        let tagged = (event.as_raw_handle() as usize | 1) as sys::Handle;
        // SAFETY: the operation has not been issued, so nothing else reads or writes the OVERLAPPED.
        unsafe { (*self.overlapped.get()).event = tagged };
        let handle = event.as_raw_handle() as sys::Handle;
        // `start` runs once per operation, so the cell is empty.
        self.event.set(event).map_err(|_| io::Error::from(io::ErrorKind::AlreadyExists))?;
        Ok(handle)
    }

    /// Waits on the thread pool for `event`, the event of the issued
    /// operation, whose reference given to the system is `raw`. If the wait
    /// cannot be registered, the operation is cancelled and waited for here,
    /// and the reference taken back.
    fn watch_event(&self, raw: *const Operation, event: sys::Handle) -> io::Result<()> {
        let mut wait: sys::Handle = core::ptr::null_mut();
        let flags = Windows::WT_EXECUTEINWAITTHREAD | Windows::WT_EXECUTEONLYONCE;
        // SAFETY: the event lives as long as the operation, which the reference `raw` keeps
        // alive until the callback posts its completion; the result is checked.
        let registered = unsafe {
            sys::RegisterWaitForSingleObject(
                &mut wait,
                event,
                Operation::signaled,
                raw as *mut c_void,
                Windows::INFINITE,
                flags,
            )
        };
        if registered != 0 {
            self.wait.store(wait, Ordering::Release);
            return Ok(());
        }
        let error = io::Error::last_os_error();
        self.cancel();
        // SAFETY: the event of this operation, which the cancelled call signals when it ends.
        unsafe { sys::WaitForSingleObject(event, Windows::INFINITE) };
        // SAFETY: the operation has ended and nothing will post its completion, so the reference is ours again.
        drop(unsafe { Arc::from_raw(raw) });
        self.done.store(true, Ordering::Release);
        Err(error)
    }

    /// The callback of the wait of [`Operation::watch_event`]: it queues the
    /// completion of the operation `context` to its reactor's port.
    ///
    /// # Safety
    /// `context` is the reference [`Operation::start`] gave the system.
    unsafe extern "system" fn signaled(context: *mut c_void, _timed_out: u8) {
        // SAFETY: the reference keeps the operation alive until its completion is posted.
        let port = unsafe { &*(context as *const Operation) }.reactor.shared().driver.raw();
        // The reactor may free the operation once this is posted: it is not touched after.
        // SAFETY: the port of the reactor and the operation's OVERLAPPED (its address).
        if unsafe { sys::PostQueuedCompletionStatus(port, 0, 0, context) } == 0 {
            // The port could not queue it: completed here, so that the task still wakes.
            // SAFETY: the reference of `start`, given back once, as the port would have.
            unsafe { Operation::complete(context as usize) };
        }
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

impl Drop for Operation {
    /// Ends the wait of [`CompletionRoute::Event`], whose callback has posted
    /// the completion (the last reference was given back after it), before the
    /// event closes. It does not wait for the callback to return, so it may
    /// run on the wait's own thread.
    fn drop(&mut self) {
        let wait = *self.wait.get_mut();
        if !wait.is_null() {
            // SAFETY: the wait `watch_event` registered, unregistered once; a null completion event does not block.
            unsafe { sys::UnregisterWaitEx(wait, core::ptr::null_mut()) };
        }
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
