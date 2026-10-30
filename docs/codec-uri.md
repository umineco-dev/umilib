# `umilib::codec::uri`

URI references (RFC 3986) and the form encoding
`application/x-www-form-urlencoded` (WHATWG URL Standard §5, which RFC 6749
Appendix B uses). Feature: `codec-uri` (no dependencies).

```rust
use umilib::codec::uri::{URIForm, URIPercent, URIReference};

let base = URIReference::parse("http://a/b/c/d;p?q")?;
let target = URIReference::parse("../g?y")?.resolve(&base)?;   // http://a/b/g?y
assert_eq!(target.to_string(), "http://a/b/g?y");
let same = URIReference::parse("HTTP://a/./b/%7e")?.normalize(); // http://a/b/~
let pairs = URIForm::parse(b"grant_type=authorization_code&code=xyz")?;
let body = URIForm::encode(&[("redirect_uri", "https://client.example.com/cb")]);
let segment = URIPercent::encode_component("a b/c".as_bytes()); // a%20b%2Fc
```

## References

- `URIReference` has the five components of RFC 3986 §3 as public fields,
  each **as written**, percent-encodings included. An absent component is
  `None`; a present and empty one is `Some("")`. `http://h/?` (empty query)
  and `http://h/` (no query) differ, as §5.3 says they do. The path is
  always present and may be empty.
- `parse` checks the whole grammar of Appendix A: the scheme, the userinfo,
  the host (IPv6 and IPvFuture literals in brackets, IPv4 addresses, and
  registered names), the port (digits only, any number of them), the path,
  the query, the fragment, and every percent-encoding. It accepts only ASCII:
  a URI with non-ASCII characters is an IRI (RFC 3987) and must be converted
  first. IPv6 zone identifiers are not accepted.
- `URIAuthority::host` keeps an IP literal with its brackets; `host_kind`
  tells the four forms apart. A dotted name that is not an IPv4 address in
  the strict sense of §3.2.2 (`256.1.1.1`, `01.2.3.4`) is a registered name.
- `Display` writes the components back (§5.3). For a value built field by
  field, `check` tells whether it is valid: it fails if a component is not of
  its grammar or would read back as part of another (a path `b?c`, or a path
  `//b` without an authority).
- `is_relative` is §4.2 (no scheme); `is_absolute` is §4.3 (a scheme and
  **no fragment**), the form that RFC 6749 requires of a redirect URI.
- `resolve(&base)` is the strict algorithm of §5.2.2: a reference with a
  scheme is never taken as relative (`http:g` stays `http:g`). The base must
  have a scheme (`NotAbsolute`); its fragment is not used. When a target
  without an authority would get a path beginning with `//`, `/.` is put
  before the path so that it does not read back as an authority, as the WHATWG
  URL Standard does; the path is the same once dot-segments are removed.
- `normalize` is the syntax-based normalization of §6.2.2: the scheme and
  host in lower case, the digits of percent-encodings in upper case,
  percent-encoded unreserved characters decoded, and dot-segments removed.
  An empty port is dropped with its `:` (§6.2.3). Dot-segments of a
  **relative** reference are kept, because removing them changes its target.
  Normalizations that depend on the scheme (a default port, an empty path
  for `http`) are yours to apply.
- To compare two URIs, compare their normalized forms. A security check such
  as the redirect URI of OAuth is better served by comparing the exact
  strings (RFC 9700 §4.1.3).

## Percent-encoding

- `URIPercent::encode(data, keep)` encodes every octet that `keep` rejects,
  with upper-case digits (§2.1); `encode_component` keeps only the unreserved
  characters, which is right for a value put into any component.
- `decode` fails on a `%` without two hexadecimal digits; `decode_text` also
  fails on octets that are not UTF-8. Decode a component only after splitting
  the reference: a decoded `/` or `?` is data, not a delimiter (§2.4).

## Form encoding

- `URIForm::parse` follows the parser of the WHATWG URL Standard §5.1:
  sequences split at `&`, empty ones skipped, each split at its first `=` (a
  name without `=` has an empty value), `+` read as a space, and a `%` without
  two hexadecimal digits kept as it is. The one difference: octets that are
  not UTF-8 fail with `UTF8` instead of becoming U+FFFD, so that two
  different bodies never read as the same value.
- `URIForm::encode` and `encode_text` follow the serializer of §5.2: the
  alphanumerics and `*-._` kept, a space as `+`, every other octet of the
  UTF-8 percent-encoded. The result reads back as the same pairs with both
  `URIForm::parse` and the older HTML 4.01 rules.
- A name may appear more than once; `parse` returns the pairs in order and
  leaves it to you to refuse repeats (RFC 6749 §3.1 does for OAuth).

## C and Python

The C ABI (`include/umilib/codec/uri.h`) holds a reference as a handle whose
components are read and set one at a time, an absent component passed as a
null pointer. `URIPercent::encode` takes the octets to keep as a list of
bytes. Python (`umilib.codec.uri`) has the same classes; `URIReference` and
`URIAuthority` are dataclasses with the fields of Rust, and
`URIForm.parse` returns a list of `(name, value)` tuples.
