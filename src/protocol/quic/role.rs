/// Which end of a connection this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QUICRole {
    Client,
    Server,
}

impl QUICRole {
    /// The other end.
    pub const fn peer(self) -> QUICRole {
        match self {
            QUICRole::Client => QUICRole::Server,
            QUICRole::Server => QUICRole::Client,
        }
    }
}
