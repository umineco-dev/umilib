use crate::protocol::tls::{TLSNamePattern, TLSRule};
use crate::service::Rule;

use super::{QUICConnection, QUICVersion};

/// The rule of a [`Router`](crate::service::Router) that routes QUIC
/// connections by the server name and application protocol of their
/// handshake (RFC 9001 §8.1) and, if given, their version: HTTP/3 to one
/// service and DNS over QUIC to another on one port, say. A connection is
/// routed once its handshake completed and its protocol is known.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct QUICRule {
    pub tls: TLSRule,
    /// The version the connection must use; any if `None`.
    pub version: Option<QUICVersion>,
}

impl QUICRule {
    /// The connections whose server name `server_name` matches, of any protocol and version.
    pub fn new(server_name: TLSNamePattern) -> QUICRule {
        QUICRule { tls: TLSRule::new(server_name), version: None }
    }

    /// These connections, of `protocol` only (ALPN, RFC 7301).
    pub fn with_protocol(self, protocol: &[u8]) -> QUICRule {
        QUICRule { tls: self.tls.with_protocol(protocol), ..self }
    }

    /// These connections, of `version` only.
    pub fn with_version(self, version: QUICVersion) -> QUICRule {
        QUICRule { version: Some(version), ..self }
    }
}

impl Rule<QUICConnection> for QUICRule {
    fn matches(&self, connection: &QUICConnection) -> bool {
        self.version.is_none_or(|version| version == connection.version) && self.tls.matches(&connection.tls.session)
    }
}
