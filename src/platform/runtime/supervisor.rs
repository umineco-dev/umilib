use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::string::ToString;
use std::time::{Duration, Instant};
use std::vec::Vec;

use super::{Worker, WorkerHandshake};
use crate::platform::native::Socket;

/// When a [`Supervisor`] starts a worker again after it exits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RestartPolicy {
    /// Never.
    Never,
    /// When it exits unsuccessfully (or is killed).
    #[default]
    OnFailure,
    /// Whenever it exits.
    Always,
}

impl RestartPolicy {
    /// Whether a worker that exited with `status` is started again.
    pub fn restarts(&self, status: ExitStatus) -> bool {
        match self {
            RestartPolicy::Never => false,
            RestartPolicy::OnFailure => !status.success(),
            RestartPolicy::Always => true,
        }
    }
}

/// The parameters of a [`Supervisor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisorConfig {
    /// The workers; 0 for as many as the system's parallelism.
    pub workers: usize,
    /// The program of the workers; `None` for the executable of this process.
    pub program: Option<PathBuf>,
    /// The arguments of the workers (by default, those of this process).
    pub arguments: Vec<OsString>,
    /// Environment variables set for the workers, besides [`Worker::ENVIRONMENT`].
    pub environment: Vec<(OsString, OsString)>,
    pub restart: RestartPolicy,
    /// The time between the exit of a worker and its restart.
    pub restart_delay: Duration,
    /// The time workers are given to exit after they are asked to stop, before they are killed.
    pub stop_timeout: Duration,
    /// The interval at which [`Supervisor::run`] checks the workers.
    pub check_interval: Duration,
}

impl Default for SupervisorConfig {
    fn default() -> SupervisorConfig {
        SupervisorConfig {
            workers: 0,
            program: None,
            arguments: std::env::args_os().skip(1).collect(),
            environment: Vec::new(),
            restart: RestartPolicy::default(),
            restart_delay: Duration::from_secs(1),
            stop_timeout: Duration::from_secs(10),
            check_interval: Duration::from_millis(100),
        }
    }
}

/// A worker process of a [`Supervisor`]: running, or the status of its last exit.
#[derive(Debug)]
pub struct WorkerProcess {
    index: usize,
    child: Option<Child>,
    input: Option<ChildStdin>,
    exit: Option<(ExitStatus, Instant)>,
    restarts: u64,
}

impl WorkerProcess {
    pub fn new(index: usize) -> WorkerProcess {
        WorkerProcess { index, child: None, input: None, exit: None, restarts: 0 }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    /// The process ID, while it runs.
    pub fn id(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }

    /// The status of its last exit.
    pub fn exit(&self) -> Option<ExitStatus> {
        self.exit.map(|(status, _)| status)
    }

    /// The times it was started again.
    pub fn restarts(&self) -> u64 {
        self.restarts
    }

    /// Records the exit of the process if it exited.
    pub fn reap(&mut self) -> io::Result<()> {
        if let Some(child) = &mut self.child
            && let Some(status) = child.try_wait()?
        {
            self.child = None;
            self.input = None;
            self.exit = Some((status, Instant::now()));
        }
        Ok(())
    }

    /// Asks the process to stop: closes its standard input.
    pub fn stop(&mut self) {
        self.input = None;
    }

    /// Kills the process and waits for it.
    pub fn kill(&mut self) -> io::Result<()> {
        if let Some(mut child) = self.child.take() {
            self.input = None;
            let _ = child.kill();
            self.exit = Some((child.wait()?, Instant::now()));
        }
        Ok(())
    }
}

/// The supervisor of worker processes: it starts the workers (by default,
/// the program of this process again), shares listening sockets with them,
/// starts them again when they exit as its [`RestartPolicy`] says, and
/// stops them.
///
/// A worker knows itself with [`Worker::current`], which reads from its
/// standard input the sockets the supervisor shares ([`WorkerHandshake`]):
/// - on Unix, the descriptors, inherited across exec;
/// - on Windows, sockets duplicated for the worker's process with
///   `WSADuplicateSocketW`.
///
/// The supervisor asks a worker to stop by closing its standard input,
/// which also happens when the supervisor exits; [`Worker::watch`] waits for it.
#[derive(Debug)]
pub struct Supervisor {
    config: SupervisorConfig,
    listeners: Vec<Socket>,
    workers: Vec<WorkerProcess>,
    stopped: bool,
}

impl Supervisor {
    /// A supervisor of the parameters `config` sharing `listeners` (none started yet).
    pub fn new(config: SupervisorConfig, listeners: Vec<Socket>) -> Supervisor {
        let workers = match config.workers {
            0 => std::thread::available_parallelism().map_or(1, usize::from),
            workers => workers,
        };
        Supervisor { config, listeners, workers: (0..workers).map(WorkerProcess::new).collect(), stopped: true }
    }

    pub fn config(&self) -> &SupervisorConfig {
        &self.config
    }

    pub fn listeners(&self) -> &[Socket] {
        &self.listeners
    }

    pub fn workers(&self) -> &[WorkerProcess] {
        &self.workers
    }

    /// Starts the workers not running.
    pub fn start(&mut self) -> io::Result<()> {
        self.stopped = false;
        for index in 0..self.workers.len() {
            if !self.workers[index].is_running() {
                self.launch(index)?;
            }
        }
        Ok(())
    }

    /// Starts the worker `index`, and gives it the handshake.
    pub fn launch(&mut self, index: usize) -> io::Result<()> {
        let program = match &self.config.program {
            Some(program) => program.clone(),
            None => std::env::current_exe()?,
        };
        let mut command = Command::new(program);
        command.args(&self.config.arguments);
        command.envs(self.config.environment.iter().map(|(name, value)| (name, value)));
        command.env(Worker::ENVIRONMENT, index.to_string());
        command.stdin(Stdio::piped());
        #[cfg(unix)]
        self.inherit(&mut command)?;
        let mut child = command.spawn()?;
        let given = child.stdin.take().ok_or(io::Error::from(io::ErrorKind::BrokenPipe)).and_then(|mut input| {
            input.write_all(&self.handshake(child.id())?.encode())?;
            input.flush()?;
            Ok(input)
        });
        let worker = &mut self.workers[index];
        match given {
            Ok(input) => {
                worker.child = Some(child);
                worker.input = Some(input);
                Ok(())
            }
            Err(error) => {
                let _ = child.kill();
                worker.exit = Some((child.wait()?, Instant::now()));
                Err(error)
            }
        }
    }

    /// The handshake for the worker of process ID `process`.
    pub fn handshake(&self, process: u32) -> io::Result<WorkerHandshake> {
        let listeners = self.listeners.iter().map(|listener| WorkerHandshake::share(listener, process));
        Ok(WorkerHandshake { listeners: listeners.collect::<io::Result<Vec<Vec<u8>>>>()? })
    }

    /// Makes `command` keep the listeners open across exec (they are
    /// close-on-exec). Fails with `InvalidInput` if a listener is a standard
    /// descriptor (0 to 2, possible when this process started without them):
    /// the child's standard streams replace those before exec.
    #[cfg(unix)]
    pub fn inherit(&self, command: &mut Command) -> io::Result<()> {
        use crate::platform::unix::sys::{self, POSIX};
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let descriptors: Vec<i32> = self.listeners.iter().map(AsRawFd::as_raw_fd).collect();
        if descriptors.iter().any(|descriptor| (0..=2).contains(descriptor)) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let clear = move || {
            for &descriptor in &descriptors {
                // SAFETY: a descriptor of this process (the child's copy of the supervisor's).
                if unsafe { sys::fcntl(descriptor, POSIX::F_SETFD, 0) } == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        };
        // SAFETY: the closure runs in the child between fork and exec; it
        // calls only fcntl, which is async-signal-safe, and allocates nothing.
        unsafe { command.pre_exec(clear) };
        Ok(())
    }

    /// Records the workers that exited and starts again those the restart
    /// policy says to, once the restart delay has passed. Returns the
    /// workers running.
    pub fn check(&mut self) -> io::Result<usize> {
        for index in 0..self.workers.len() {
            self.workers[index].reap()?;
            if self.is_restarting(&self.workers[index])
                && self.workers[index].exit.is_some_and(|(_, at)| at.elapsed() >= self.config.restart_delay)
            {
                self.workers[index].restarts += 1;
                self.launch(index)?;
            }
        }
        Ok(self.workers.iter().filter(|worker| worker.is_running()).count())
    }

    /// Whether `worker` exited and is to be started again.
    pub fn is_restarting(&self, worker: &WorkerProcess) -> bool {
        !self.stopped
            && !worker.is_running()
            && worker.exit().is_some_and(|status| self.config.restart.restarts(status))
    }

    /// Starts the workers and checks them every check interval until `stop`
    /// says to stop or no worker runs nor is to be started again; then
    /// stops them.
    pub fn run(&mut self, stop: impl Fn() -> bool) -> io::Result<()> {
        let result = self.start().and_then(|()| {
            while !stop() {
                let running = self.check()?;
                if running == 0 && !self.workers.iter().any(|worker| self.is_restarting(worker)) {
                    break;
                }
                std::thread::sleep(self.config.check_interval);
            }
            Ok(())
        });
        let stopped = self.stop();
        result.and(stopped)
    }

    /// Asks every worker to stop, waits for them up to the stop timeout and
    /// kills those still running.
    pub fn stop(&mut self) -> io::Result<()> {
        self.stopped = true;
        self.workers.iter_mut().for_each(WorkerProcess::stop);
        let deadline = Instant::now() + self.config.stop_timeout;
        loop {
            for worker in &mut self.workers {
                worker.reap()?;
            }
            if !self.workers.iter().any(WorkerProcess::is_running) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(self.config.check_interval.min(Duration::from_millis(10)));
        }
        // Every worker is killed even if one fails; the first failure is reported.
        let killed: Vec<io::Result<()>> = self.workers.iter_mut().map(WorkerProcess::kill).collect();
        killed.into_iter().collect()
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
