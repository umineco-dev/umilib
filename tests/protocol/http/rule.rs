//! HTTPRule: routing by host (RFC 9110 §4.2: without case or port, from the
//! authority or the Host field), path, method and fields.

use umilib::protocol::http::{HTTPMethod, HTTPRequest, HTTPRule};
use umilib::service::{Pattern, Rule};

fn request(authority: Option<&[u8]>, host: Option<&[u8]>, path: &[u8]) -> HTTPRequest {
    let mut request = HTTPRequest::new(HTTPMethod::GET, b"https", b"x", path);
    request.authority = authority.map(<[u8]>::to_vec);
    if let Some(host) = host {
        request.fields.append(b"host", host).unwrap();
    }
    request
}

#[test]
fn hosts() {
    let rule = HTTPRule::new(Pattern::exact(b"Auth.Example.com"), Pattern::prefix(b"/oauth/"));
    assert!(rule.matches(&request(Some(b"auth.example.com"), None, b"/oauth/token")));
    assert!(rule.matches(&request(Some(b"AUTH.example.COM:8443"), None, b"/oauth/token?x=1")));
    assert!(rule.matches(&request(None, Some(b"auth.example.com"), b"/oauth/")), "the Host field");
    assert!(!rule.matches(&request(Some(b"example.com"), None, b"/oauth/token")));
    assert!(!rule.matches(&request(Some(b"auth.example.com"), None, b"/OAuth/token")), "paths keep case");
    assert!(!rule.matches(&request(Some(b"auth.example.com"), None, b"/oauth%2Ftoken")), "paths are not decoded");
    assert!(!rule.matches(&request(None, None, b"/oauth/token")), "no host");
    assert!(!rule.matches(&request(Some(b"user@auth.example.com"), None, b"/oauth/token")), "not an authority");
    let suffix = HTTPRule::new(Pattern::suffix(b".example.com"), Pattern::any());
    assert!(suffix.matches(&request(Some(b"a.b.example.com"), None, b"/")));
    assert!(!suffix.matches(&request(Some(b"[::1]"), None, b"/")));
    let any = HTTPRule::default();
    assert!(any.matches(&request(None, None, b"*")), "any host includes none");
}

#[test]
fn methods_and_fields() {
    let rule = HTTPRule::new(Pattern::any(), Pattern::exact(b"/api"))
        .with_method(HTTPMethod::POST)
        .with_field(b"Content-Type", Pattern::prefix(b"application/json"));
    let mut post = HTTPRequest::new(HTTPMethod::POST, b"https", b"a", b"/api");
    assert!(!rule.matches(&post), "the field is required");
    post.fields.append(b"content-type", b"text/plain").unwrap();
    post.fields.append(b"content-type", b"application/json; charset=utf-8").unwrap();
    assert!(rule.matches(&post), "any of the field's lines");
    let mut get = post.clone();
    get.method = HTTPMethod::GET;
    assert!(!rule.matches(&get));
}
