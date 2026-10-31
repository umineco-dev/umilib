use alloc::string::String;
use alloc::vec::Vec;

use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::crypto::random::Random;
use crate::hash::Digest;
use crate::hash::sha::v1::SHA1;
use crate::protocol::http::{
    HTTPError, HTTPFields, HTTPMethod, HTTPRequest, HTTPResponse, HTTPStatus, HTTPSyntax, HTTPVersion,
};
use crate::protocol::websocket::WebSocketDeflateParameters;

/// What a client's opening handshake asks for (RFC 6455 §4.1, §4.2.1):
/// its key (HTTP/1.1 only), the subprotocols it offers, and its offers of
/// permessage-deflate (RFC 7692 §5) that are valid, in its order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct WebSocketOffer {
    pub key: Option<Vec<u8>>,
    pub protocols: Vec<String>,
    pub deflate: Vec<WebSocketDeflateParameters>,
}

/// What the opening handshake agreed: the subprotocol and permessage-deflate's parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct WebSocketAgreement {
    pub protocol: Option<String>,
    pub deflate: Option<WebSocketDeflateParameters>,
}

/// An extension of a Sec-WebSocket-Extensions field (RFC 6455 §9.1): its
/// name and its parameters, quoted values unquoted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct WebSocketExtension {
    pub name: String,
    pub parameters: Vec<(String, Option<String>)>,
}

/// The opening handshake of WebSocket over HTTP: HTTP/1.1's Upgrade (RFC
/// 6455 §4), and the extended CONNECT of HTTP/2 (RFC 8441) and HTTP/3
/// (RFC 9220), whose stream then carries the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WebSocketHandshake;

impl WebSocketHandshake {
    /// The GUID that the accept value hashes with the key (RFC 6455 §1.3).
    pub const GUID: &'static [u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    /// The only version: 13 (RFC 6455 §4.1).
    pub const VERSION: &'static [u8] = b"13";
    /// The protocol of an extended CONNECT (RFC 8441 §4).
    pub const PROTOCOL: &'static [u8] = b"websocket";

    /// Sec-WebSocket-Accept of `key`: base64 of SHA-1 of the key and the GUID (RFC 6455 §4.2.2).
    pub fn accept(key: &[u8]) -> Vec<u8> {
        let mut hash = SHA1::new();
        hash.update(key);
        hash.update(WebSocketHandshake::GUID);
        Base64::STANDARD.encode(hash.finalize().as_ref()).into_bytes()
    }

    /// The fields both forms of the request carry: the version, the subprotocols, the extensions.
    pub fn offer_fields(
        fields: &mut HTTPFields,
        protocols: &[&str],
        deflate: Option<WebSocketDeflateParameters>,
    ) -> Result<(), HTTPError> {
        fields.append(b"sec-websocket-version", WebSocketHandshake::VERSION)?;
        if !protocols.is_empty() {
            fields.append(b"sec-websocket-protocol", protocols.join(", ").as_bytes())?;
        }
        if let Some(deflate) = deflate {
            let offer = WebSocketHandshake::write_extension(WebSocketDeflateParameters::NAME, &deflate.pairs());
            fields.append(b"sec-websocket-extensions", &offer)?;
        }
        Ok(())
    }

    /// A client's request over HTTP/1.1 (RFC 6455 §4.1): GET with Upgrade,
    /// and a key of 16 random bytes, which it returns.
    pub fn request(
        scheme: &[u8],
        authority: &[u8],
        path: &[u8],
        protocols: &[&str],
        deflate: Option<WebSocketDeflateParameters>,
        random: &mut (dyn Random + Send),
    ) -> Result<(HTTPRequest, Vec<u8>), HTTPError> {
        let mut nonce = [0u8; 16];
        random.fill(&mut nonce).map_err(|_| HTTPError::Config)?;
        let key = Base64::STANDARD.encode(&nonce).into_bytes();
        let mut request = HTTPRequest::new(HTTPMethod::GET, scheme, authority, path);
        request.fields.append(b"upgrade", b"websocket")?;
        request.fields.append(b"connection", b"Upgrade")?;
        request.fields.append(b"sec-websocket-key", &key)?;
        WebSocketHandshake::offer_fields(&mut request.fields, protocols, deflate)?;
        Ok((request, key))
    }

    /// A client's extended CONNECT over HTTP/2 or HTTP/3 (RFC 8441 §4, §5,
    /// RFC 9220 §3): no key, no accept.
    pub fn connect_request(
        scheme: &[u8],
        authority: &[u8],
        path: &[u8],
        protocols: &[&str],
        deflate: Option<WebSocketDeflateParameters>,
    ) -> Result<HTTPRequest, HTTPError> {
        let mut request = HTTPRequest::new(HTTPMethod::CONNECT, scheme, authority, path);
        request.protocol = Some(WebSocketHandshake::PROTOCOL.to_vec());
        WebSocketHandshake::offer_fields(&mut request.fields, protocols, deflate)?;
        Ok(request)
    }

    /// A server's check of a request of `version` (RFC 6455 §4.2.1, RFC 8441
    /// §5, RFC 9220 §3). Fails with the response to send: 400 for a request
    /// that is not a handshake (one over HTTP/1.0 included), 426 with the
    /// WebSocket version for another WebSocket version (§4.4), and 505 for
    /// a version of HTTP other than 1.0, 1.1, 2 and 3, whose handshake is
    /// not known.
    pub fn check_request(request: &HTTPRequest, version: HTTPVersion) -> Result<WebSocketOffer, HTTPResponse> {
        let bad = || HTTPResponse::new(HTTPStatus::BAD_REQUEST);
        let fields = &request.fields;
        let key = if version == HTTPVersion::HTTP1_0 {
            return Err(bad());
        } else if version == HTTPVersion::HTTP1_1 {
            if request.method != HTTPMethod::GET || request.host().is_none() {
                return Err(bad());
            }
            if !fields.contains_token(b"upgrade", b"websocket") || !fields.contains_token(b"connection", b"upgrade") {
                return Err(bad());
            }
            let key = fields.get(b"sec-websocket-key").ok_or_else(bad)?;
            // A key is 16 bytes in base64 (§4.2.1 item 5).
            match Base64::STANDARD.decode(key) {
                Ok(nonce) if nonce.len() == 16 => Some(key.to_vec()),
                _ => return Err(bad()),
            }
        } else if version == HTTPVersion::HTTP2 || version == HTTPVersion::HTTP3 {
            if request.method != HTTPMethod::CONNECT
                || request.protocol.as_deref() != Some(WebSocketHandshake::PROTOCOL)
            {
                return Err(bad());
            }
            None
        } else {
            return Err(HTTPResponse::new(HTTPStatus::HTTP_VERSION_NOT_SUPPORTED));
        };
        if fields.get(b"sec-websocket-version") != Some(WebSocketHandshake::VERSION) {
            let mut response = HTTPResponse::new(HTTPStatus::UPGRADE_REQUIRED);
            let _ = response.fields.append(b"sec-websocket-version", WebSocketHandshake::VERSION);
            return Err(response);
        }
        let protocols = fields
            .get_all(b"sec-websocket-protocol")
            .flat_map(HTTPSyntax::list)
            .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
            .collect();
        let mut deflate = Vec::new();
        for value in fields.get_all(b"sec-websocket-extensions") {
            let extensions = WebSocketHandshake::parse_extensions(value).map_err(|_| bad())?;
            for WebSocketExtension { name, parameters } in extensions {
                // An offer of invalid parameters is declined, not an error (RFC 7692 §5).
                if name.eq_ignore_ascii_case(WebSocketDeflateParameters::NAME)
                    && let Ok(offer) = WebSocketDeflateParameters::parse(&parameters)
                {
                    deflate.push(offer);
                }
            }
        }
        Ok(WebSocketOffer { key, protocols, deflate })
    }

    /// A server's response to `offer` with the `agreement` it chose: 101
    /// with Upgrade and the accept value over HTTP/1.1 (RFC 6455 §4.2.2),
    /// 200 over HTTP/2 and HTTP/3 (RFC 8441 §5).
    pub fn response(offer: &WebSocketOffer, agreement: &WebSocketAgreement) -> Result<HTTPResponse, HTTPError> {
        let mut response = match &offer.key {
            Some(key) => {
                let mut response = HTTPResponse::new(HTTPStatus::SWITCHING_PROTOCOLS);
                response.fields.append(b"upgrade", b"websocket")?;
                response.fields.append(b"connection", b"Upgrade")?;
                response.fields.append(b"sec-websocket-accept", &WebSocketHandshake::accept(key))?;
                response
            }
            None => HTTPResponse::new(HTTPStatus::OK),
        };
        if let Some(protocol) = &agreement.protocol {
            if !offer.protocols.contains(protocol) {
                return Err(HTTPError::Malformed("a subprotocol the client did not offer"));
            }
            response.fields.append(b"sec-websocket-protocol", protocol.as_bytes())?;
        }
        if let Some(deflate) = &agreement.deflate {
            let value = WebSocketHandshake::write_extension(WebSocketDeflateParameters::NAME, &deflate.pairs());
            response.fields.append(b"sec-websocket-extensions", &value)?;
        }
        Ok(response)
    }

    /// The agreement of a server that takes the first subprotocol of
    /// `supported` the client offered, and the client's first offer of
    /// permessage-deflate if `deflate`.
    pub fn agree(offer: &WebSocketOffer, supported: &[&str], deflate: bool) -> WebSocketAgreement {
        WebSocketAgreement {
            protocol: offer.protocols.iter().find(|protocol| supported.contains(&protocol.as_str())).cloned(),
            deflate: offer.deflate.first().filter(|_| deflate).map(WebSocketDeflateParameters::accept),
        }
    }

    /// A client's check of the response (RFC 6455 §4.1, RFC 8441 §5): 101
    /// with the accept value of its `key` over HTTP/1.1, a 2xx otherwise; a
    /// subprotocol and extensions of those offered only.
    pub fn check_response(
        response: &HTTPResponse,
        key: Option<&[u8]>,
        protocols: &[&str],
        deflate: Option<&WebSocketDeflateParameters>,
    ) -> Result<WebSocketAgreement, &'static str> {
        let fields = &response.fields;
        match key {
            Some(key) => {
                if response.status != HTTPStatus::SWITCHING_PROTOCOLS {
                    return Err("a response other than 101");
                }
                if !fields.contains_token(b"upgrade", b"websocket") || !fields.contains_token(b"connection", b"upgrade")
                {
                    return Err("a 101 without Upgrade: websocket");
                }
                if fields.get(b"sec-websocket-accept") != Some(&WebSocketHandshake::accept(key)[..]) {
                    return Err("a Sec-WebSocket-Accept of another key");
                }
            }
            None if !response.status.is_successful() => return Err("a response other than 2xx"),
            None => {}
        }
        let protocol = match fields.get(b"sec-websocket-protocol") {
            Some(protocol) => {
                let protocol = String::from_utf8_lossy(protocol).into_owned();
                if !protocols.contains(&protocol.as_str()) {
                    return Err("a subprotocol not offered");
                }
                Some(protocol)
            }
            None => None,
        };
        let mut agreed = None;
        for value in fields.get_all(b"sec-websocket-extensions") {
            for WebSocketExtension { name, parameters } in WebSocketHandshake::parse_extensions(value)? {
                let offer = deflate.filter(|_| name.eq_ignore_ascii_case(WebSocketDeflateParameters::NAME));
                let (Some(offer), None) = (offer, agreed) else { return Err("an extension not offered") };
                let parameters = WebSocketDeflateParameters::parse(&parameters)?;
                WebSocketDeflateParameters::check_response(offer, &parameters)?;
                agreed = Some(parameters.with_hints(offer));
            }
        }
        Ok(WebSocketAgreement { protocol, deflate: agreed })
    }

    /// The extensions of a Sec-WebSocket-Extensions value (RFC 6455 §9.1).
    pub fn parse_extensions(value: &[u8]) -> Result<Vec<WebSocketExtension>, &'static str> {
        let invalid = "an invalid Sec-WebSocket-Extensions";
        let mut extensions = Vec::new();
        for element in HTTPSyntax::list(value) {
            let mut parts = element.split(|byte| *byte == b';').map(HTTPSyntax::trim);
            let name = parts.next().filter(|name| HTTPSyntax::is_token(name)).ok_or(invalid)?;
            let mut parameters = Vec::new();
            for part in parts {
                let (key, value) = match part.iter().position(|byte| *byte == b'=') {
                    Some(equals) => (HTTPSyntax::trim(&part[..equals]), Some(HTTPSyntax::trim(&part[equals + 1..]))),
                    None => (part, None),
                };
                if !HTTPSyntax::is_token(key) {
                    return Err(invalid);
                }
                let value = match value {
                    Some([b'"', inner @ .., b'"']) => Some(inner.to_vec()),
                    Some(value) if HTTPSyntax::is_token(value) => Some(value.to_vec()),
                    Some(_) => return Err(invalid),
                    None => None,
                };
                let text = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).map_err(|_| invalid);
                parameters.push((text(key)?, value.map(|value| text(&value)).transpose()?));
            }
            extensions.push(WebSocketExtension { name: String::from_utf8_lossy(name).into_owned(), parameters });
        }
        Ok(extensions)
    }

    /// An extension of Sec-WebSocket-Extensions: its name and parameters.
    pub fn write_extension(name: &str, parameters: &[(String, Option<String>)]) -> Vec<u8> {
        let mut out = String::from(name);
        for (key, value) in parameters {
            out.push_str("; ");
            out.push_str(key);
            if let Some(value) = value {
                out.push('=');
                out.push_str(value);
            }
        }
        out.into_bytes()
    }
}
