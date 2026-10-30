//! URIs: the generic syntax of RFC 3986 and the form encoding of
//! `application/x-www-form-urlencoded`.
//!
//! [`URIReference`] reads and writes a URI reference (§4.1) as its
//! components, each as written (percent-encoded), resolves a reference
//! against a base (§5) and normalizes one by its syntax (§6.2.2).
//! [`URIPercent`] encodes and decodes octets (§2.1); [`URIForm`] reads and
//! writes the name and value pairs of the form encoding (WHATWG URL Standard
//! §5, which RFC 6749 Appendix B uses).

mod error;
mod form;
mod percent;
mod reference;

pub use error::URIError;
pub use form::URIForm;
pub use percent::URIPercent;
pub use reference::{URIAuthority, URIHostKind, URIReference};
