use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::future::{Future, poll_fn};
use core::task::{Poll, Waker};

use super::sync::SpinLock;

/// The kinds of I/O errors (those of the operating systems and of the streams of the runtime).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IOErrorKind {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NotConnected,
    AddressInUse,
    AddressNotAvailable,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    Interrupted,
    Unsupported,
    UnexpectedEnd,
    OutOfMemory,
    Other,
}

/// An I/O error: its kind and, from an operating system, its error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IOError {
    pub kind: IOErrorKind,
    pub code: Option<i32>,
}

impl IOError {
    pub const fn new(kind: IOErrorKind) -> IOError {
        IOError { kind, code: None }
    }
}

impl fmt::Display for IOError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(code) => write!(formatter, "{:?} (error {code})", self.kind),
            None => write!(formatter, "{:?}", self.kind),
        }
    }
}

impl core::error::Error for IOError {}

/// An IP socket address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SocketAddress {
    V4 { address: [u8; 4], port: u16 },
    V6 { address: [u8; 16], port: u16, flow: u32, scope: u32 },
}

impl SocketAddress {
    pub const fn port(&self) -> u16 {
        match self {
            SocketAddress::V4 { port, .. } | SocketAddress::V6 { port, .. } => *port,
        }
    }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketAddress::V4 { address, port } => {
                write!(formatter, "{}.{}.{}.{}:{port}", address[0], address[1], address[2], address[3])
            }
            SocketAddress::V6 { address, port, scope, .. } => {
                formatter.write_str("[")?;
                for (index, pair) in address.chunks(2).enumerate() {
                    if index > 0 {
                        formatter.write_str(":")?;
                    }
                    write!(formatter, "{:x}", u16::from_be_bytes([pair[0], pair[1]]))?;
                }
                if *scope != 0 {
                    write!(formatter, "%{scope}")?;
                }
                write!(formatter, "]:{port}")
            }
        }
    }
}

/// A byte stream that reads into owned buffers (the I/O of completion-based
/// systems such as IOCP and io_uring, which hold the buffer while the
/// operation runs, as well as of readiness-based ones).
pub trait AsyncRead {
    /// Reads at most `buffer.capacity() - buffer.len()` bytes (at least one
    /// byte of room is needed) after the bytes of `buffer`; gives the buffer
    /// back with the count, 0 at the end of the stream.
    fn read(&mut self, buffer: Vec<u8>) -> impl Future<Output = (Result<usize, IOError>, Vec<u8>)>;
}

/// A byte stream that writes from owned buffers.
pub trait AsyncWrite {
    /// Writes a prefix of `buffer` (at least one byte unless it is empty);
    /// gives the buffer back with the count.
    fn write(&mut self, buffer: Vec<u8>) -> impl Future<Output = (Result<usize, IOError>, Vec<u8>)>;

    /// Writes all of `buffer`, writing again after partial writes.
    fn write_all(&mut self, buffer: Vec<u8>) -> impl Future<Output = (Result<(), IOError>, Vec<u8>)> {
        async move {
            let mut buffer = buffer;
            let mut done = 0;
            while done < buffer.len() {
                let rest = buffer.split_off(done);
                let (result, rest) = self.write(rest).await;
                buffer.extend_from_slice(&rest);
                match result {
                    Ok(0) => return (Err(IOError::new(IOErrorKind::WriteZero)), buffer),
                    Ok(count) => done += count,
                    Err(error) => return (Err(error), buffer),
                }
            }
            (Ok(()), buffer)
        }
    }

    /// Delivers what was written to its destination.
    fn flush(&mut self) -> impl Future<Output = Result<(), IOError>>;

    /// Ends the writing side: the reader sees the end of the stream after what was written.
    fn shutdown(&mut self) -> impl Future<Output = Result<(), IOError>>;
}

/// A socket of datagrams that sends and receives owned buffers.
pub trait AsyncDatagram {
    /// Sends `buffer` to `address`; gives it back with the bytes sent.
    fn send_to(
        &mut self,
        buffer: Vec<u8>,
        address: SocketAddress,
    ) -> impl Future<Output = (Result<usize, IOError>, Vec<u8>)>;

    /// Receives a datagram after the bytes of `buffer` (into its spare
    /// capacity, the rest of a longer datagram dropped); gives the buffer
    /// back with the count and the sender's address.
    fn receive_from(
        &mut self,
        buffer: Vec<u8>,
    ) -> impl Future<Output = (Result<(usize, SocketAddress), IOError>, Vec<u8>)>;
}

/// One direction of a [`DuplexStream`]: bytes in flight, the waiters and whether the writer ended it.
#[derive(Debug, Default)]
pub struct DuplexPipe {
    bytes: VecDeque<u8>,
    capacity: usize,
    closed: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

/// An in-memory byte stream, one end of a pair ([`DuplexStream::pair`]):
/// what one end writes, the other reads, at most `capacity` bytes in flight
/// each way. It is what tests and in-process pipelines run protocols over.
#[derive(Debug)]
pub struct DuplexStream {
    incoming: Arc<SpinLock<DuplexPipe>>,
    outgoing: Arc<SpinLock<DuplexPipe>>,
}

impl DuplexStream {
    /// Two connected ends of `capacity` bytes (at least 1) in flight each way.
    pub fn pair(capacity: usize) -> (DuplexStream, DuplexStream) {
        let pipe = || Arc::new(SpinLock::new(DuplexPipe { capacity: capacity.max(1), ..DuplexPipe::default() }));
        let (a, b) = (pipe(), pipe());
        (DuplexStream { incoming: a.clone(), outgoing: b.clone() }, DuplexStream { incoming: b, outgoing: a })
    }
}

impl Drop for DuplexStream {
    fn drop(&mut self) {
        for pipe in [&self.incoming, &self.outgoing] {
            let mut pipe = pipe.lock();
            pipe.closed = true;
            let wakers = (pipe.reader.take(), pipe.writer.take());
            drop(pipe);
            wakers.0.into_iter().chain(wakers.1).for_each(Waker::wake);
        }
    }
}

impl AsyncRead for DuplexStream {
    fn read(&mut self, buffer: Vec<u8>) -> impl Future<Output = (Result<usize, IOError>, Vec<u8>)> {
        let mut buffer = Some(buffer);
        poll_fn(move |context| {
            let mut pipe = self.incoming.lock();
            let room = buffer.as_ref().map_or(0, |buffer| buffer.capacity() - buffer.len());
            if pipe.bytes.is_empty() && !pipe.closed && room > 0 {
                pipe.reader = Some(context.waker().clone());
                return Poll::Pending;
            }
            let mut buffer = buffer.take().expect("a read polled after it finished");
            let count = room.min(pipe.bytes.len());
            buffer.extend(pipe.bytes.drain(..count));
            let writer = pipe.writer.take();
            drop(pipe);
            if let Some(writer) = writer {
                writer.wake();
            }
            Poll::Ready((Ok(count), buffer))
        })
    }
}

impl AsyncWrite for DuplexStream {
    fn write(&mut self, buffer: Vec<u8>) -> impl Future<Output = (Result<usize, IOError>, Vec<u8>)> {
        let mut buffer = Some(buffer);
        poll_fn(move |context| {
            let mut pipe = self.outgoing.lock();
            if pipe.closed {
                let buffer = buffer.take().expect("a write polled after it finished");
                return Poll::Ready((Err(IOError::new(IOErrorKind::BrokenPipe)), buffer));
            }
            let room = pipe.capacity - pipe.bytes.len();
            let length = buffer.as_ref().map_or(0, Vec::len);
            if room == 0 && length > 0 {
                pipe.writer = Some(context.waker().clone());
                return Poll::Pending;
            }
            let buffer = buffer.take().expect("a write polled after it finished");
            let count = room.min(length);
            pipe.bytes.extend(&buffer[..count]);
            let reader = pipe.reader.take();
            drop(pipe);
            if let Some(reader) = reader {
                reader.wake();
            }
            Poll::Ready((Ok(count), buffer))
        })
    }

    fn flush(&mut self) -> impl Future<Output = Result<(), IOError>> {
        core::future::ready(Ok(()))
    }

    fn shutdown(&mut self) -> impl Future<Output = Result<(), IOError>> {
        let mut pipe = self.outgoing.lock();
        pipe.closed = true;
        let reader = pipe.reader.take();
        drop(pipe);
        if let Some(reader) = reader {
            reader.wake();
        }
        core::future::ready(Ok(()))
    }
}
