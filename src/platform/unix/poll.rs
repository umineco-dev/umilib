/// What a poller (`Poller` of `platform-linux` and `platform-darwin`) watches a descriptor for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Interest {
    pub readable: bool,
    pub writable: bool,
}

impl Interest {
    pub const READABLE: Interest = Interest { readable: true, writable: false };
    pub const WRITABLE: Interest = Interest { readable: false, writable: true };
    pub const BOTH: Interest = Interest { readable: true, writable: true };
}

/// A readiness event of a poller: the token the descriptor was registered
/// with and what it is ready for. An error or hang-up also makes it
/// readable and writable, so that the next operation reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PollEvent {
    pub token: usize,
    pub readable: bool,
    pub writable: bool,
    /// The peer closed its side, or the descriptor failed.
    pub hangup: bool,
    pub error: bool,
}

impl PollEvent {
    /// The token of the poller's own notification (`Poller::notify`), an
    /// event that is only readable; not usable for descriptors.
    pub const NOTIFY: usize = usize::MAX;
}

/// How a poller reports a descriptor that stays ready.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum PollMode {
    /// Every wait while it is ready (`epoll` level-triggered, `kqueue` default).
    #[default]
    Level,
    /// Once each time it becomes ready (`EPOLLET`, `EV_CLEAR`): read or write until `WouldBlock`.
    Edge,
    /// Once, then not until it is modified again (`EPOLLONESHOT`, `EV_ONESHOT` with `EV_DISPATCH` semantics).
    Oneshot,
}
