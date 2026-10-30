use alloc::string::String;
use alloc::vec::Vec;

use crate::service::Rule;

use super::{TLSClientHello, TLSExtensionType, TLSProtocolNames, TLSServerNames, TLSSession};

/// What a [`TLSRule`] routes by: the server name a client asks for and the
/// application protocols (ALPN) it offers or negotiated. A ClientHello
/// routes before the handshake; a session after it.
pub trait TLSRoute {
    /// The host name asked for (`server_name`, RFC 6066 §3), if any.
    fn server_name(&self) -> Option<String>;

    /// Whether `protocol` is offered (a ClientHello) or was negotiated (a session).
    fn has_protocol(&self, protocol: &[u8]) -> bool;
}

impl TLSRoute for TLSClientHello {
    fn server_name(&self) -> Option<String> {
        let names = TLSServerNames::decode(self.extension(TLSExtensionType::SERVER_NAME)?).ok()?;
        String::from_utf8(names.host_name()?.to_vec()).ok()
    }

    fn has_protocol(&self, protocol: &[u8]) -> bool {
        self.extension(TLSExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
            .and_then(|data| TLSProtocolNames::decode(data).ok())
            .is_some_and(|names| names.names.iter().any(|name| name == protocol))
    }
}

impl TLSRoute for TLSSession {
    fn server_name(&self) -> Option<String> {
        self.server_name.clone()
    }

    fn has_protocol(&self, protocol: &[u8]) -> bool {
        self.protocol.as_deref() == Some(protocol)
    }
}

/// The server names a [`TLSRule`] matches, compared without case.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum TLSNamePattern {
    /// Any name, and none.
    #[default]
    Any,
    /// No name: a client that sent no `server_name`.
    None,
    /// This name.
    Exact(String),
    /// Any name of one more label in this domain: `*.example.com` is
    /// `Wildcard("example.com")`, which matches `a.example.com` but neither
    /// `example.com` nor `a.b.example.com` (as RFC 9525 §6.3 matches
    /// wildcard certificates).
    Wildcard(String),
}

impl TLSNamePattern {
    /// The pattern of `text`: `*` is any name, `*.domain` a wildcard, and
    /// anything else that name, without a trailing dot.
    pub fn parse(text: &str) -> TLSNamePattern {
        let text = text.strip_suffix('.').unwrap_or(text).to_ascii_lowercase();
        match text.strip_prefix("*.") {
            _ if text == "*" => TLSNamePattern::Any,
            Some(domain) => TLSNamePattern::Wildcard(String::from(domain)),
            None => TLSNamePattern::Exact(text),
        }
    }

    pub fn matches(&self, name: Option<&str>) -> bool {
        let name = name.map(|name| name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase());
        match (self, name) {
            (TLSNamePattern::Any, _) => true,
            (TLSNamePattern::None, name) => name.is_none(),
            (TLSNamePattern::Exact(exact), Some(name)) => *exact == name,
            (TLSNamePattern::Wildcard(domain), Some(name)) => name
                .strip_suffix(domain.as_str())
                .and_then(|label| label.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.')),
            _ => false,
        }
    }
}

/// The rule of a [`Router`](crate::service::Router) that routes TLS
/// connections by the server name and, if given, an application protocol:
/// the virtual hosts of a server, or the services of one port (RFC 7301).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLSRule {
    pub server_name: TLSNamePattern,
    /// The protocol that must be offered or negotiated; any if `None`.
    pub protocol: Option<Vec<u8>>,
}

impl TLSRule {
    /// The connections whose server name `server_name` matches, of any protocol.
    pub fn new(server_name: TLSNamePattern) -> TLSRule {
        TLSRule { server_name, protocol: None }
    }

    /// These connections, of `protocol` only.
    pub fn with_protocol(self, protocol: &[u8]) -> TLSRule {
        TLSRule { protocol: Some(protocol.to_vec()), ..self }
    }
}

impl<R: TLSRoute> Rule<R> for TLSRule {
    fn matches(&self, request: &R) -> bool {
        self.server_name.matches(request.server_name().as_deref())
            && self.protocol.as_deref().is_none_or(|protocol| request.has_protocol(protocol))
    }
}
