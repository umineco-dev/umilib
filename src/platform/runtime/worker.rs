use std::io::{self, Read};
use std::thread::JoinHandle;
use std::vec::Vec;

use crate::platform::native::Socket;

/// What a [`Supervisor`](super::Supervisor) writes on the standard input of
/// a worker it starts: the listening sockets the worker shares, each as the
/// bytes [`WorkerHandshake::share`] makes of it for that process.
///
/// The encoding, in little-endian:
/// 1. the magic `UMWH`;
/// 2. the version (u32, 1);
/// 3. the number of listeners (u32);
/// 4. for each listener, its length (u32) and its bytes.
///
/// A worker rejects another version: a supervisor and its workers are the
/// same program, so they agree on it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkerHandshake {
    pub listeners: Vec<Vec<u8>>,
}

impl WorkerHandshake {
    pub const MAGIC: [u8; 4] = *b"UMWH";
    pub const VERSION: u32 = 1;
    /// The listeners of a handshake at most.
    pub const MAXIMUM_LISTENERS: usize = 1024;
    /// The length of a listener's bytes at most.
    pub const MAXIMUM_LENGTH: usize = 4096;

    pub fn encode(&self) -> Vec<u8> {
        let length = self.listeners.iter().map(|listener| 4 + listener.len()).sum::<usize>();
        let mut bytes = Vec::with_capacity(12 + length);
        bytes.extend_from_slice(&WorkerHandshake::MAGIC);
        bytes.extend_from_slice(&WorkerHandshake::VERSION.to_le_bytes());
        bytes.extend_from_slice(&(self.listeners.len() as u32).to_le_bytes());
        for listener in &self.listeners {
            bytes.extend_from_slice(&(listener.len() as u32).to_le_bytes());
            bytes.extend_from_slice(listener);
        }
        bytes
    }

    /// The handshake read from `reader`, which is left just after it.
    /// Rejects (with `InvalidData`) another magic or version, more listeners
    /// or longer bytes than the maxima, and a listener given twice.
    pub fn decode(reader: &mut impl Read) -> io::Result<WorkerHandshake> {
        let invalid = || io::Error::from(io::ErrorKind::InvalidData);
        let mut word = [0u8; 4];
        reader.read_exact(&mut word)?;
        if word != WorkerHandshake::MAGIC {
            return Err(invalid());
        }
        reader.read_exact(&mut word)?;
        if u32::from_le_bytes(word) != WorkerHandshake::VERSION {
            return Err(invalid());
        }
        reader.read_exact(&mut word)?;
        let count = u32::from_le_bytes(word) as usize;
        if count > WorkerHandshake::MAXIMUM_LISTENERS {
            return Err(invalid());
        }
        let mut listeners: Vec<Vec<u8>> = Vec::with_capacity(count);
        for _ in 0..count {
            reader.read_exact(&mut word)?;
            let length = u32::from_le_bytes(word) as usize;
            if length > WorkerHandshake::MAXIMUM_LENGTH {
                return Err(invalid());
            }
            let mut listener = std::vec![0; length];
            reader.read_exact(&mut listener)?;
            if listeners.contains(&listener) {
                return Err(invalid());
            }
            listeners.push(listener);
        }
        Ok(WorkerHandshake { listeners })
    }

    /// The bytes of `socket` for the worker of process ID `process`: the
    /// descriptor, which the worker inherits (as a little-endian i32).
    #[cfg(unix)]
    pub fn share(socket: &Socket, _process: u32) -> io::Result<Vec<u8>> {
        use std::os::fd::AsRawFd;
        Ok(socket.as_raw_fd().to_le_bytes().to_vec())
    }

    /// The bytes of `socket` for the worker of process ID `process`: its
    /// protocol information from `WSADuplicateSocketW`.
    #[cfg(windows)]
    pub fn share(socket: &Socket, process: u32) -> io::Result<Vec<u8>> {
        Ok(socket.duplicate(process)?.bytes.to_vec())
    }

    /// The socket of `bytes` from [`WorkerHandshake::share`], in the worker.
    /// The descriptor is checked to be a socket (it is left open otherwise),
    /// owned by the worker, and made close-on-exec again.
    #[cfg(unix)]
    pub fn adopt(bytes: &[u8]) -> io::Result<Socket> {
        use std::os::fd::{FromRawFd, RawFd};
        let invalid = || io::Error::from(io::ErrorKind::InvalidData);
        let descriptor = RawFd::from_le_bytes(bytes.try_into().map_err(|_| invalid())?);
        if descriptor < 0 {
            return Err(invalid());
        }
        // SAFETY: the supervisor gave the descriptor to this process to own (it was
        // inherited across exec); `decode` rejects one given twice.
        let socket = core::mem::ManuallyDrop::new(unsafe { Socket::from_raw_fd(descriptor) });
        if socket.local_address().is_err() {
            return Err(invalid());
        }
        let socket = core::mem::ManuallyDrop::into_inner(socket);
        socket.set_close_on_exec()?;
        Ok(socket)
    }

    /// The socket of `bytes` from [`WorkerHandshake::share`], in the worker.
    #[cfg(windows)]
    pub fn adopt(bytes: &[u8]) -> io::Result<Socket> {
        use crate::platform::windows::SocketDuplicate;
        let bytes = bytes.try_into().map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        Socket::from_duplicate(&SocketDuplicate { bytes })
    }
}

/// The view of a worker process from inside: its index among the workers of
/// its [`Supervisor`](super::Supervisor) and the listening sockets it
/// shares with the other workers.
#[derive(Debug)]
pub struct Worker {
    index: usize,
    listeners: Vec<Socket>,
}

impl Worker {
    /// The environment variable that marks a worker: its index.
    pub const ENVIRONMENT: &'static str = "UMILIB_WORKER";

    /// The worker this process is, if a supervisor started it. It reads the
    /// handshake from standard input, so call it once, before anything else
    /// reads standard input.
    pub fn current() -> io::Result<Option<Worker>> {
        let Some(value) = std::env::var_os(Worker::ENVIRONMENT) else {
            return Ok(None);
        };
        let index = value.to_str().and_then(|value| value.parse().ok());
        let index = index.ok_or(io::Error::from(io::ErrorKind::InvalidData))?;
        let handshake = WorkerHandshake::decode(&mut io::stdin().lock())?;
        // Every listener is adopted even if one fails, so that none is left
        // open (and inheritable) unowned; the first failure is reported.
        let adopted: Vec<io::Result<Socket>> =
            handshake.listeners.iter().map(|bytes| WorkerHandshake::adopt(bytes)).collect();
        Ok(Some(Worker { index, listeners: adopted.into_iter().collect::<io::Result<Vec<Socket>>>()? }))
    }

    pub fn index(&self) -> usize {
        self.index
    }

    /// The listening sockets, in the order the supervisor was given them.
    pub fn listeners(&self) -> &[Socket] {
        &self.listeners
    }

    pub fn take_listeners(&mut self) -> Vec<Socket> {
        core::mem::take(&mut self.listeners)
    }

    /// Calls `stop` on a thread of its own when the supervisor asks the
    /// worker to stop. The supervisor asks by closing the worker's standard
    /// input; it also closes when the supervisor exits.
    pub fn watch(stop: impl FnOnce() + Send + 'static) -> io::Result<JoinHandle<()>> {
        std::thread::Builder::new().name(std::string::String::from("umilib-worker-watch")).spawn(move || {
            let mut input = io::stdin().lock();
            let mut buffer = [0u8; 64];
            loop {
                match input.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(_) => continue,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            stop();
        })
    }
}
