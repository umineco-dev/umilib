# OAuth (`auth-oauth`)

How OAuth is built, and why. The user's view is in `docs/auth-oauth.md`.

## Which specifications

OAuth 2.1 (draft-ietf-oauth-v2-1) is not an RFC. As with the other drafts
this library leaves out until they are published, it is not implemented as a
version of its own. Its substance is RFC 6749 with the practices of RFC 9700
(BCP 240, published), and those practices are the defaults here: PKCE with
S256 for every client, no implicit and no password grant, exact redirect URI
matching, refresh tokens rotated or sender-constrained, `iss` in responses.
When OAuth 2.1 is published, what changes is mostly what may be configured
off.

Left out, as drafts or not asked for: client ID metadata documents,
attestation-based client authentication, transaction tokens, first-party
applications, identity chaining, token status lists, the JWT bearer grant at
the server (RFC 7523 §2.1 needs a trust policy for assertion issuers), dynamic
client registration (RFC 7591; the registry names of its methods are used),
JAR (RFC 9101) and OpenID Connect. RFC 7523bis (in the RFC Editor queue)
narrows the `aud` of client assertions to the issuer: the client already
sends the issuer; the server also takes the token endpoint URL, as RFC 7523
allows, until the update is published.

## No I/O, no HTTP types

Like the protocols, OAuth works without I/O. Unlike them it is not a state
machine over bytes: its messages ride on HTTP. The endpoints take an
`OAuthEndpointRequest` (method, URI, the three header fields OAuth reads,
body) and return an `OAuthHTTPResponse`; the client returns
`OAuthHTTPRequest`s. Considered: taking and returning the request and
response types of `protocol-http`. Rejected: OAuth would depend on the HTTP
implementation and on one way of carrying it, while users may send OAuth
over another HTTP library, and a server may sit behind a proxy whose external
URI differs from the one it sees. The integrated example shows the glue with
`protocol-http` and `service::Router<HTTPRule, _>`; it is a few lines.

## Messages as values

Each message is a type with `from_parameters`/`to_parameters` or
`decode`/`encode`. Parameters (`OAuthParameters`) apply RFC 6749 §3.1/§3.2
once for all: an empty value is omitted, and a parameter given twice is an
error unless it is repeatable (`resource`, RFC 8707). Members a type does not
know are kept (`other`), so that extensions pass through.

The JSON documents of the server (metadata) are kept as a JSON object read by
name (`OAuthMetadata::string`, `strings`, `boolean`), with the registered
names as constants. Considered: a struct with a field per member. Rejected:
RFC 8414 and RFC 9728 have dozens of registered members and more are added;
the documents are read for a few members and passed on as they are.

## The authorization server

- **Tables, not a storage trait.** The server keeps clients, codes, tokens,
  pushed requests, device authorizations and assertion identifiers in bounded
  in-memory tables. Considered: a storage trait for the user to implement.
  Rejected for now: the checks (code reuse, refresh rotation, family
  revocation, replay) depend on how the records relate, and a trait would
  move that logic out of the place where it is tested. A server restarted
  loses its grants; clients go through the flow again. Persistent storage can
  be added later as export and import of the tables without changing the
  checks.
- **Digests.** Codes and tokens are kept as their SHA-256 digests; secrets of
  clients too. A memory disclosure of the tables gives nothing to present.
  Tokens are random (256 bits), so a digest needs no salt and the lookup by
  digest leaks nothing useful by its timing.
- **Families.** Every grant (a code, a client credentials request, a device
  authorization) starts a family; refresh tokens keep it. A code used twice
  (RFC 6749 §4.1.2) and a replaced refresh token used again (RFC 9700
  §4.14.2) revoke the family. A failed exchange still marks the code used: an
  attacker who tries a stolen code with a wrong verifier burns it, which is
  the safe outcome.
- **Full tables refuse.** When a table is full the endpoint answers 503
  `temporarily_unavailable` (500 is for failures of the server itself).
  Considered: evicting the oldest entries. Rejected: that would revoke live
  grants of other users, or forget a used code, which reopens replay.
- **`OAuthTable`.** Every table is one: a map, an index by expiry, and a count
  per client. The per-client limit keeps one client from filling a table for
  the others (a review found that a public client refreshing in a loop could
  fill the token table for everyone); expiry pops from the front of the
  index instead of scanning every record on every request. The tables first
  were plain maps with one global limit and a full scan in `expire`.
- **The last replaced refresh token.** A family keeps only the refresh token it
  replaced last, so rotation does not grow the table. A thief and the client
  both holding a token is still caught: whoever presents it second presents
  the last replaced one. An older one is refused without revoking the family;
  its holder gets nothing either way. Considered: keeping every replaced token
  until the family's expiry (RFC 9700 §4.14.2 catches every reuse). Rejected:
  a client refreshing often would hold thousands of records for 30 days.
- **Replacement after issuance.** A refresh token is marked replaced only once
  the new tokens are issued; marking it first made a refusal (a full table)
  look like reuse at the retry and revoked the user's grant.
- **Revocation of another client's token** is refused with
  `unauthorized_client`, as RFC 7009 §2.1 says. It was first answered 200
  silently, so as not to reveal that a token exists; the client must already
  hold the token to ask, and tokens are 256 random bits, so nothing is
  revealed that the asker does not know.
- **Errors at the authorization endpoint.** An unknown client or redirect URI
  gives `OAuthAuthorizationFailure::Local` (RFC 6749 §4.1.2.1: never redirect
  to an unverified URI); everything after goes back to the client's redirect
  URI with `state` and `iss`.
- **PAR.** A pushed request is checked as the authorization endpoint would
  check it, answered as JSON (RFC 9126 §2.3), and kept under a one-time
  `request_uri` that only the client that pushed it can use; another client
  naming it does not consume it.
- **User codes.** Eight characters of the twenty consonants of RFC 8628 §6.1,
  chosen by rejection sampling so that each is uniform.
- **Client credentials.** Confidential clients only (RFC 6749 §4.4), and no
  refresh token (§4.4.3: SHOULD NOT).

## DPoP

- The proof's `htu` at the token endpoint is compared with the configured
  token endpoint, not with the URI the server saw: behind a proxy the two
  differ, and the configured one is what the client was told (metadata). The
  resource server compares with `OAuthEndpointRequest::uri`, which the user
  fills with the external URI.
- Both sides of a comparison are normalized (RFC 3986 §6.2.2 and the default
  ports and empty path of §6.2.3), as RFC 9449 §4.3 advises.
- Only the refresh tokens of public clients are bound to the key (§5); a
  confidential client authenticates when it refreshes.
- The replay check keeps each `jti` until its `iat` is too old to be taken;
  when the table is full, proofs are refused rather than forgotten.
- Nonces: the current and the previous one are taken, so a rotation does not
  fail the requests in flight. A verifier that requires nonces but has made
  none answers `server_error`: `use_dpop_nonce` without a nonce to send would
  refuse every client for good, silently.
- The PAR endpoint checks a proof too and binds the code to its key
  (RFC 9449 §10.1); an assertion may name the PAR endpoint as its audience
  (RFC 9126 §2).

## The resource server

- Tokens are read from the `Authorization` header only. RFC 6750 §2.3 (query)
  is not recommended and RFC 9700 §4.3.2 says not to use it; the form body
  method (§2.2) mixes the token into application data and needs the body
  before authorization. Considered: supporting both behind options. Rejected:
  options that weaken the default are rarely needed and easily misused.
- Introspection is two steps: the user sends the introspection request
  (with any HTTP client) and hands the answer back. A resource server does
  not own an HTTP client, by the no-I/O rule.
- A request without credentials gets one challenge per scheme and no error
  code (RFC 6750 §3.1); a bound token sent as Bearer is refused with a DPoP
  challenge (RFC 9449 §7.2).

## `WWW-Authenticate`

`OAuthChallenge::parse` follows RFC 9110 §11.6.1, and refuses control
characters in quoted-strings (qdtext and quoted-pair, §5.6.4); `encode`
returns an error for a challenge that is not of the grammar, as a value with
CR or LF would inject header fields. The grammar is ambiguous
after a comma: a token may start a new challenge or be a parameter of the
current one. A token followed by `=` and a value is a parameter; anything
else starts a challenge, as browsers and curl read it. `realm=` alone after a
scheme is a token68, which is what the grammar says, though it looks like an
empty parameter. Values are always written as quoted-strings, as RFC 6750
§3 writes them.

## The C ABI and Python

Messages cross as their text on the wire, as for mail: the Rust types check
them and give back canonical text, so the C side never builds a message the
Rust side would refuse. An error response of the other side is a normal
outcome of a client, not a failure of the library; it fails with the status
`Response` and its JSON goes into an `out_error` buffer, which Python turns
into `OAuthError.response`. Refusals of a resource server are values
(`OAuthResourceError` handles); Python raises them as exceptions, as its
idiom for a `Result`. The server's scalar settings are one structure
(`OAuthServerLimits`), because the configuration is fixed when a server is
made.
