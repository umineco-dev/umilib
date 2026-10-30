# URIs (`codec-uri`)

Why the URI codec is built as it is. The user's view is in
`docs/codec-uri.md`.

## Why a URI codec of its own

OAuth needs to compare redirect URIs, add parameters to a query, and read and
write form bodies (RFC 6749 §3.1, §3.1.2, §4.1.2, Appendix B). HTTP already
had targets and authorities of its own (`protocol-http`), and the IP endpoint
text of `protocol-ip` is RFC 3986 text for one host. Neither is the generic
syntax: HTTP's types are about request targets (RFC 9112 §3.2) and the IP
endpoint about one address. A codec of the generic syntax, with no
dependency, is a part that any of them can use.

## Components as written

The components are kept percent-encoded, as written. Decoding while parsing
loses the difference between a `/` that is a delimiter and a `%2F` that is
data (§2.4), and a decoded value cannot be written back exactly. A user who
needs decoded text decodes one component with `URIPercent`.

The fields are public, as for the other value types of the codecs, so a
reference can be built field by field. `check` is the price: it writes the
components back and parses them again, so it is exactly as strict as
`parse`, with no second copy of the grammar. Considered: private fields with
setters that check each component. Rejected: a component's grammar depends
on the others (a path without an authority may not begin with `//`; the
first segment of a relative path may not hold `:`), so a setter could not
check it alone, and the order of the calls would matter.

`Option<String>` tells an absent component from an empty one, as §5.3
requires. The port is kept as text: RFC 3986 allows any number of digits, so
a number type would refuse valid references or need its own error.

## Choices of RFC 3986 left open

- `resolve` is the strict algorithm. The non-strict one (a scheme equal to
  the base's treated as relative) is a loophole of earlier specifications that
  §5.4.2 asks to avoid.
- A target without an authority whose path begins with `//` gets `/.` before
  the path. Without it, `a:/b` and `/..//g` resolve to the path `//g`, which
  written back reads as the authority `g`: the value would not survive
  `Display` and `parse`. The WHATWG URL Standard serializes such paths the
  same way. Considered: leaving the path as §5.2 computes it. Rejected: a
  value that changes meaning when written is a security hazard, and the two
  paths are equal after dot-segment removal.
- `normalize` removes dot-segments only from references with a scheme.
  §6.2.2.3 speaks of URIs; for a relative reference `../a`, removal gives `a`,
  a different target.
- IPv6 zone identifiers (RFC 6874) are not accepted; RFC 9844 withdrew them
  from URIs.
- Non-ASCII text is refused. Converting an IRI (RFC 3987) needs IDNA for the
  host, which is a separate codec.

## Form encoding

RFC 6749 Appendix B points to HTML 4.01 §17.13.4.1, which keeps only the
alphanumerics and leaves non-ASCII text undefined. The WHATWG URL Standard
§5 is the current definition, and what browsers send. The serializer keeps
`*-._` as WHATWG does; both readers accept the result.

The reader differs from WHATWG in one point: WHATWG decodes bytes that are
not UTF-8 to U+FFFD, so `a=%FF` and `a=%FE` read as the same value. For a
token or a code that is a collision an attacker may choose; the reader fails
with `UTF8` instead. Considered: returning bytes. Rejected: every use in
OAuth is text, and each caller would repeat the UTF-8 check.
