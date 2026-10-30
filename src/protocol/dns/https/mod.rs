//! DNS: `https` — DNS queries over HTTPS (RFC 8484): a query a request,
//! by GET with the message in the "dns" variable as base64url without
//! padding, or by POST as the content; the response the content of a 2xx
//! response, of the media type "application/dns-message" (§6), fresh for
//! no longer than its least TTL (§5.1). The HTTP exchange is the HTTP
//! connection's (HTTP/2 or later is RECOMMENDED, §5.2).

use alloc::format;
use alloc::vec::Vec;

use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;
use crate::protocol::http::{HTTPFields, HTTPMethod, HTTPRequest, HTTPResponse, HTTPStatus};

use super::{DNSCache, DNSError, DNSMessage};

/// The rules of DNS over HTTPS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DNSHTTPS;

impl DNSHTTPS {
    /// The media type of DNS messages (RFC 8484 §6).
    pub const MEDIA_TYPE: &'static [u8] = b"application/dns-message";
    /// The path of the examples of RFC 8484 §4.1.1, which servers commonly use.
    pub const PATH: &'static [u8] = b"/dns-query";

    /// The GET request of `query` (whose ID should be 0, §4.1) to `path`
    /// of `authority`: the message in the "dns" variable (§4.1).
    pub fn get(query: &DNSMessage, authority: &[u8], path: &[u8]) -> Result<HTTPRequest, DNSError> {
        let bytes = query.encode(DNSMessage::MAXIMUM_SIZE)?;
        let separator = if path.contains(&b'?') { "&" } else { "?" };
        let target = format!(
            "{}{separator}dns={}",
            core::str::from_utf8(path).map_err(|_| DNSError::Config)?,
            Base64::URL_SAFE_NO_PADDING.encode(&bytes)
        );
        let fields = HTTPFields::new().with(b"accept", DNSHTTPS::MEDIA_TYPE).map_err(|_| DNSError::Config)?;
        Ok(HTTPRequest::new(HTTPMethod::GET, b"https", authority, target.as_bytes()).with_fields(fields))
    }

    /// The POST request of `query` to `path` of `authority`, and its content (§4.1).
    pub fn post(query: &DNSMessage, authority: &[u8], path: &[u8]) -> Result<(HTTPRequest, Vec<u8>), DNSError> {
        let bytes = query.encode(DNSMessage::MAXIMUM_SIZE)?;
        let length = format!("{}", bytes.len());
        let fields = HTTPFields::new()
            .with(b"accept", DNSHTTPS::MEDIA_TYPE)
            .and_then(|fields| fields.with(b"content-type", DNSHTTPS::MEDIA_TYPE))
            .and_then(|fields| fields.with(b"content-length", length.as_bytes()))
            .map_err(|_| DNSError::Config)?;
        Ok((HTTPRequest::new(HTTPMethod::POST, b"https", authority, path).with_fields(fields), bytes))
    }

    /// The query of `request` with its `content`, or the status to answer
    /// it with: 405 for another method, 415 for content of another type,
    /// 413 for a message above 65535 bytes, 400 for one that cannot be read.
    pub fn query(request: &HTTPRequest, content: &[u8]) -> Result<Vec<u8>, HTTPStatus> {
        let message = match request.method {
            HTTPMethod::GET => {
                let (_, query) = request
                    .path
                    .split_at(request.path.iter().position(|byte| *byte == b'?').ok_or(HTTPStatus::BAD_REQUEST)? + 1);
                let value = query
                    .split(|byte| *byte == b'&')
                    .find_map(|pair| pair.strip_prefix(b"dns="))
                    .ok_or(HTTPStatus::BAD_REQUEST)?;
                if value.len() > DNSMessage::MAXIMUM_SIZE.div_ceil(3) * 4 {
                    return Err(HTTPStatus::URI_TOO_LONG);
                }
                Base64::URL_SAFE_NO_PADDING.decode(value).map_err(|_| HTTPStatus::BAD_REQUEST)?
            }
            HTTPMethod::POST => {
                let media = request.fields.get(b"content-type").map(DNSHTTPS::media_type);
                if media != Some(DNSHTTPS::MEDIA_TYPE.to_vec()) {
                    return Err(HTTPStatus::UNSUPPORTED_MEDIA_TYPE);
                }
                content.to_vec()
            }
            _ => return Err(HTTPStatus::METHOD_NOT_ALLOWED),
        };
        if message.len() > DNSMessage::MAXIMUM_SIZE {
            return Err(HTTPStatus::CONTENT_TOO_LARGE);
        }
        DNSMessage::decode(&message).map_err(|_| HTTPStatus::BAD_REQUEST)?;
        Ok(message)
    }

    /// The media type of a Content-Type value: before its parameters,
    /// lowercased, without spaces (RFC 9110 §8.3.1).
    pub fn media_type(value: &[u8]) -> Vec<u8> {
        let media = value.split(|byte| *byte == b';').next().unwrap_or_default();
        media.iter().filter(|byte| !byte.is_ascii_whitespace()).map(u8::to_ascii_lowercase).collect()
    }

    /// The 200 response of the DNS response `message` (§4.2.1), fresh for
    /// its cache lifetime (§5.1, RFC 2308 §5); no-cache if it has none.
    pub fn response(message: &[u8]) -> Result<HTTPResponse, DNSError> {
        let decoded = DNSMessage::decode(message)?;
        let control = match DNSCache::default().lifetime(&decoded) {
            Some(lifetime) => format!("max-age={}", lifetime.as_secs()),
            None => "no-cache".into(),
        };
        let length = format!("{}", message.len());
        let fields = HTTPFields::new()
            .with(b"content-type", DNSHTTPS::MEDIA_TYPE)
            .and_then(|fields| fields.with(b"content-length", length.as_bytes()))
            .and_then(|fields| fields.with(b"cache-control", control.as_bytes()))
            .map_err(|_| DNSError::Config)?;
        Ok(HTTPResponse::new(HTTPStatus::OK).with_fields(fields))
    }

    /// The DNS response of `response` and its `content`: a 2xx of the
    /// media type "application/dns-message" (§4.2.1).
    pub fn decode_response(response: &HTTPResponse, content: &[u8]) -> Result<DNSMessage, DNSError> {
        if !(200..300).contains(&response.status.0) {
            return Err(DNSError::Malformed("an HTTP response of an error"));
        }
        let media = response.fields.get(b"content-type").map(DNSHTTPS::media_type);
        if media != Some(DNSHTTPS::MEDIA_TYPE.to_vec()) {
            return Err(DNSError::Malformed("an HTTP response not of a DNS message"));
        }
        DNSMessage::decode(content)
    }
}
