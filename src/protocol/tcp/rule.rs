use crate::protocol::ip::{IPEndpointPattern, IPEndpoints};
use crate::service::Rule;

/// The rule of a [`Router`](crate::service::Router) that routes connections
/// by their local and remote endpoints, as `UDPRule` of `protocol::udp`
/// routes datagrams; [`TCPConnection`](super::TCPConnection) implements
/// `IPEndpoints`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TCPRule {
    pub local: IPEndpointPattern,
    pub remote: IPEndpointPattern,
}

impl TCPRule {
    /// The connections to the endpoints of `local`, from any endpoint.
    pub const fn new(local: IPEndpointPattern) -> TCPRule {
        TCPRule { local, remote: IPEndpointPattern::ANY }
    }

    /// These connections, from the endpoints of `remote` only.
    pub const fn with_remote(self, remote: IPEndpointPattern) -> TCPRule {
        TCPRule { remote, ..self }
    }
}

impl<R: IPEndpoints> Rule<R> for TCPRule {
    fn matches(&self, request: &R) -> bool {
        self.local.matches(&request.local()) && self.remote.matches(&request.remote())
    }
}
