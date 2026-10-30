use alloc::vec;
use alloc::vec::Vec;

use super::{HTTPError, HTTPField, HTTPFields, HTTPMethod, HTTPRequest, HTTPResponse, HTTPStatus};

/// The field sections of HTTP/2 and HTTP/3, which carry the start line of
/// a message in pseudo-header fields (RFC 9113 §8.3, RFC 9114 §4.3), and
/// share their rules of fields (RFC 9113 §8.2, RFC 9114 §4.2): the
/// messages of decoded field lines, and the field lines of messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HTTPPseudoField;

impl HTTPPseudoField {
    /// Whether `name` is of a field specific to a connection, which neither
    /// version carries (RFC 9113 §8.2.2, RFC 9114 §4.2).
    pub fn is_connection_specific(name: &[u8]) -> bool {
        matches!(name, b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding" | b"upgrade")
    }

    /// The regular fields of decoded field lines: lowercase tokens, valid
    /// values, none specific to a connection, TE only "trailers";
    /// pseudo-header fields only before them, and only if `pseudo` allows.
    pub fn fields(lines: Vec<HTTPField>, pseudo: bool) -> Result<HTTPFields, &'static str> {
        let mut out = HTTPFields::new();
        for line in lines {
            if line.name.first() == Some(&b':') {
                if !pseudo || !out.is_empty() {
                    return Err("a pseudo-header field out of place");
                }
                continue;
            }
            if line.name.iter().any(u8::is_ascii_uppercase) {
                return Err("a field name with uppercase letters");
            }
            if HTTPPseudoField::is_connection_specific(&line.name) {
                return Err("a field specific to a connection");
            }
            if line.name == b"te" && line.value != b"trailers" {
                return Err("TE other than trailers");
            }
            let mut field = HTTPField::new(&line.name, &line.value).map_err(|_| "an invalid field")?;
            field.sensitive = line.sensitive;
            out.fields.push(field);
        }
        Ok(out)
    }

    /// The pseudo-header fields at the start of `lines`, each once, of the names `allowed`.
    pub fn pseudo<'a>(lines: &'a [HTTPField], allowed: &[&[u8]]) -> Result<Vec<&'a HTTPField>, &'static str> {
        let mut pseudo: Vec<&HTTPField> = Vec::new();
        for line in lines.iter().take_while(|line| line.name.first() == Some(&b':')) {
            if !allowed.contains(&line.name.as_slice()) {
                return Err("an unknown pseudo-header field");
            }
            if pseudo.iter().any(|field| field.name == line.name) {
                return Err("a pseudo-header field repeated");
            }
            pseudo.push(line);
        }
        Ok(pseudo)
    }

    /// The request of decoded field lines (RFC 9113 §8.3.1, RFC 9114
    /// §4.3.1, RFC 8441 §4, RFC 9220 §3); `extended_connect` if this end
    /// allows :protocol. Host, if any, names what :authority does.
    pub fn request(lines: Vec<HTTPField>, extended_connect: bool) -> Result<HTTPRequest, &'static str> {
        let pseudo = HTTPPseudoField::pseudo(&lines, &[b":method", b":scheme", b":authority", b":path", b":protocol"])?;
        let get = |name: &[u8]| pseudo.iter().find(|field| field.name == name).map(|field| field.value.clone());
        let method = HTTPMethod::parse(&get(b":method").ok_or("a request without :method")?)
            .map_err(|_| "an invalid :method")?;
        let protocol = get(b":protocol");
        if protocol.is_some() && (!extended_connect || method != HTTPMethod::CONNECT) {
            return Err("a :protocol not allowed");
        }
        let (scheme, path, mut authority) = (get(b":scheme"), get(b":path"), get(b":authority"));
        if method == HTTPMethod::CONNECT && protocol.is_none() {
            if scheme.is_some() || path.is_some() {
                return Err("CONNECT with :scheme or :path");
            }
        } else if scheme.is_none() || path.as_ref().is_none_or(Vec::is_empty) {
            return Err("a request without :scheme or :path");
        }
        let regular = HTTPPseudoField::fields(lines, true)?;
        if let Some(host) = regular.get(b"host") {
            match &authority {
                Some(authority) if !authority.eq_ignore_ascii_case(host) => return Err("Host other than :authority"),
                None => authority = Some(host.to_vec()),
                _ => {}
            }
        }
        let request = HTTPRequest {
            method,
            scheme: scheme.map(|scheme| scheme.to_ascii_lowercase()),
            authority,
            path: path.unwrap_or_default(),
            protocol,
            fields: regular,
        };
        request.check().map_err(|_| "an invalid request target")?;
        Ok(request)
    }

    /// The response of decoded field lines (RFC 9113 §8.3.2, RFC 9114 §4.3.2).
    pub fn response(lines: Vec<HTTPField>) -> Result<HTTPResponse, &'static str> {
        let pseudo = HTTPPseudoField::pseudo(&lines, &[b":status"])?;
        let status = pseudo.first().map(|field| field.value.as_slice()).ok_or("a response without :status")?;
        let status = HTTPStatus::parse(status).ok_or("an invalid :status")?;
        Ok(HTTPResponse { status, fields: HTTPPseudoField::fields(lines, true)? })
    }

    /// The field lines of a request: pseudo-header fields, then its fields
    /// without Host (RFC 9113 §8.3.1, RFC 9114 §4.3.1).
    pub fn request_lines(request: &HTTPRequest) -> Vec<HTTPField> {
        let line =
            |name: &[u8], value: &[u8]| HTTPField { name: name.to_vec(), value: value.to_vec(), sensitive: false };
        let mut lines = vec![line(b":method", request.method.as_bytes())];
        let connect = request.method == HTTPMethod::CONNECT && request.protocol.is_none();
        if !connect {
            lines.push(line(b":scheme", request.scheme.as_deref().unwrap_or(b"https")));
        }
        if let Some(authority) = request.host() {
            lines.push(line(b":authority", authority));
        }
        if !connect {
            lines.push(line(b":path", if request.path.is_empty() { b"/" } else { &request.path }));
        }
        if let Some(protocol) = &request.protocol {
            lines.push(line(b":protocol", protocol));
        }
        lines.extend(request.fields.iter().filter(|field| field.name != b"host").cloned());
        lines
    }

    /// The field lines of a response: :status, then its fields.
    pub fn response_lines(response: &HTTPResponse) -> Vec<HTTPField> {
        let mut status = Vec::new();
        response.status.write(&mut status);
        let mut lines = vec![HTTPField { name: b":status".to_vec(), value: status, sensitive: false }];
        lines.extend(response.fields.iter().cloned());
        lines
    }

    /// Checks fields to send: none specific to a connection, TE only "trailers".
    pub fn check(fields: &HTTPFields) -> Result<(), HTTPError> {
        for field in fields {
            if HTTPPseudoField::is_connection_specific(&field.name) || field.name == b"te" && field.value != b"trailers"
            {
                return Err(HTTPError::Malformed("a field specific to a connection"));
            }
        }
        Ok(())
    }

    /// Checks a request to send the rules of both versions put on it.
    pub fn check_request(request: &HTTPRequest) -> Result<(), HTTPError> {
        request.check()?;
        HTTPPseudoField::check(&request.fields)?;
        if let (Some(authority), Some(host)) = (&request.authority, request.fields.get(b"host"))
            && !authority.eq_ignore_ascii_case(host)
        {
            return Err(HTTPError::Malformed("Host other than the authority"));
        }
        Ok(())
    }
}
