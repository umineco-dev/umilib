use alloc::vec::Vec;

use crate::protocol::ip::{IPEndpoint, IPEndpointPattern, IPEndpoints};
use crate::service::Rule;

/// A datagram as a UDP service receives it: the local endpoint it came to,
/// the remote endpoint it came from, and its data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UDPRequest {
    pub local: IPEndpoint,
    pub remote: IPEndpoint,
    pub payload: Vec<u8>,
}

impl IPEndpoints for UDPRequest {
    fn local(&self) -> IPEndpoint {
        self.local
    }

    fn remote(&self) -> IPEndpoint {
        self.remote
    }
}

/// The rule of a [`Router`](crate::service::Router) that routes datagrams by
/// their local and remote endpoints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct UDPRule {
    pub local: IPEndpointPattern,
    pub remote: IPEndpointPattern,
}

impl UDPRule {
    /// The datagrams to the endpoints of `local`, from any endpoint.
    pub const fn new(local: IPEndpointPattern) -> UDPRule {
        UDPRule { local, remote: IPEndpointPattern::ANY }
    }

    /// These datagrams, from the endpoints of `remote` only.
    pub const fn with_remote(self, remote: IPEndpointPattern) -> UDPRule {
        UDPRule { remote, ..self }
    }
}

impl<R: IPEndpoints> Rule<R> for UDPRule {
    fn matches(&self, request: &R) -> bool {
        self.local.matches(&request.local()) && self.remote.matches(&request.remote())
    }
}
