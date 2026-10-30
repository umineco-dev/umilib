use alloc::vec::Vec;

use crate::protocol::http::{HTTPFields, HTTPMethod, HTTPStatus, HTTPVersion};

/// The writing of HTTP/1.1's message heads and chunks (RFC 9112).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H1Writer;

impl H1Writer {
    /// A request line and header fields, `extra` lines after them, and the empty line.
    pub fn request_head(
        method: &HTTPMethod,
        target: &[u8],
        fields: &HTTPFields,
        extra: &[(&[u8], &[u8])],
        out: &mut Vec<u8>,
    ) {
        out.extend_from_slice(method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(target);
        out.push(b' ');
        HTTPVersion::HTTP1_1.write(out);
        out.extend_from_slice(b"\r\n");
        H1Writer::fields(fields, extra, out);
    }

    /// A status line, with the reason phrase of the status, and the fields.
    pub fn response_head(status: HTTPStatus, fields: &HTTPFields, extra: &[(&[u8], &[u8])], out: &mut Vec<u8>) {
        HTTPVersion::HTTP1_1.write(out);
        out.push(b' ');
        status.write(out);
        out.push(b' ');
        out.extend_from_slice(status.reason().as_bytes());
        out.extend_from_slice(b"\r\n");
        H1Writer::fields(fields, extra, out);
    }

    /// Field lines, then the empty line that ends a head or trailer section.
    pub fn fields(fields: &HTTPFields, extra: &[(&[u8], &[u8])], out: &mut Vec<u8>) {
        for field in fields {
            H1Writer::field(&field.name, &field.value, out);
        }
        for (name, value) in extra {
            H1Writer::field(name, value, out);
        }
        out.extend_from_slice(b"\r\n");
    }

    pub fn field(name: &[u8], value: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }

    /// A chunk of `data`, not empty (RFC 9112 §7.1).
    pub fn chunk(data: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(alloc::format!("{:x}\r\n", data.len()).as_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
    }

    /// The last chunk and the trailer section (RFC 9112 §7.1.2).
    pub fn last_chunk(trailers: &HTTPFields, out: &mut Vec<u8>) {
        out.extend_from_slice(b"0\r\n");
        H1Writer::fields(trailers, &[], out);
    }
}
