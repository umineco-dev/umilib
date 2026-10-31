# `umilib::auth::oauth`

OAuth 2.0 (RFC 6749) with the security practices of RFC 9700 (BCP 240), for
clients, authorization servers and protected resources. Feature: `auth-oauth`
(uses `codec-uri`, `codec-json`, `codec-base-base64`, `protocol-jwt`,
`crypto-random`, `hash-sha-v2` and `secret`).

| Specification | What it adds |
| --- | --- |
| RFC 6749 | authorization code, client credentials and refresh token grants |
| RFC 6750 | Bearer tokens and their `WWW-Authenticate` challenges |
| RFC 7636 | PKCE, `S256` only |
| RFC 8414, RFC 9728 | metadata of authorization servers and of protected resources |
| RFC 9207 | the `iss` parameter of authorization responses |
| RFC 8707 | resource indicators |
| RFC 7523 | `private_key_jwt` client authentication |
| RFC 7662, RFC 7009 | introspection and revocation |
| RFC 9126 | pushed authorization requests |
| RFC 8628 | device authorization |
| RFC 9068 | JWT access tokens |
| RFC 9449 | DPoP: tokens bound to a client's key |
| RFC 9470 | step-up authentication challenges |

OAuth 2.1 is still a draft, so it is not implemented as such; its rules are
the defaults here anyway (see *Security defaults*). Browser-based applications
should follow RFC 10017 (OAuth 2.0 for Browser-Based Applications); native
applications RFC 8252.

Nothing does I/O. The client, the server and the resource server take what
arrived and return what to send: the HTTP requests a client makes are
`OAuthHTTPRequest` values, the requests an endpoint receives are
`OAuthEndpointRequest` values, and the responses are `OAuthHTTPResponse`
values. Send them with any HTTP version (`protocol-http`, or another
library). Times are seconds since 1970 (`now: i64`).

## Client

```rust
use umilib::auth::oauth::*;

// The server's metadata, fetched from OAuthMetadata::location(Server, issuer).
let metadata = OAuthMetadata::decode(OAuthMetadataKind::Server, &body)?;
metadata.check("https://as.example")?;                     // RFC 8414 §3.3
let authentication = OAuthClientAuthentication::None { client_id: "app".into() };
let mut client = OAuthClient::new(OAuthClientConfig::from_metadata(&metadata, authentication, "https://app.example/cb")?);

let url = client.authorize(Some(&OAuthScope::parse("read")?), &[], now, &mut random)?;
// ... send the browser to `url`; it comes back to the redirect URI ...
let request = client.callback(&URIReference::parse(&came_back)?, now)?;
let http = client.token_request(&request, now, &mut random)?; // send it
let tokens = OAuthTokenResponse::decode(status, &response_body)?;
```

- `authorize` makes a random `state` and an S256 code challenge for every
  request, and keeps them (at most `maximum_pending`, for
  `pending_lifetime` seconds).
- `callback` takes only a response whose `state` matches a pending request,
  once (RFC 6749 §10.12). It checks `iss` when the response has one, and
  requires it when the metadata says the server sends it (RFC 9207 §2.4). An
  error response becomes `OAuthError::Response`, after the same checks.
- `token_request` and `endpoint_request` add the client's authentication:
  `None` (a public client), `SecretBasic` (the identifier and secret
  form-encoded, then base64, RFC 6749 §2.3.1), `SecretPost`, or
  `PrivateKeyJWT` (an assertion with a random `jti` and a lifetime of a
  minute, whose audience is the issuer).
- Refresh with `OAuthTokenRequest::new(OAuthGrant::RefreshToken { .. })`,
  client credentials with `OAuthGrant::ClientCredentials`. Keep the new
  refresh token of every response: the server rotates them.
- For DPoP, send a proof made by `DPoPProof::create` in the `DPoP` header of
  the token request and of every resource request (with the access token, so
  that the proof carries its hash). When a server answers `use_dpop_nonce`,
  make a new proof with the nonce of its `DPoP-Nonce` header.

## Authorization server

```rust
let mut server = OAuthServer::new(OAuthServerConfig::new("https://as.example"));
server.register(OAuthClientRegistration::public("app", &["https://app.example/cb"], OAuthScope::parse("read write")?));

// GET /authorize?...
match server.authorize(&OAuthParameters::from_query(&target)?, now) {
    Ok(authorization) => {
        // Authenticate the user and ask for consent, then:
        let grant = OAuthGrantRecord { client_id: authorization.client_id.clone(), subject: Some(user), scope, ..Default::default() };
        let redirect = server.approve(&authorization, grant, now, &mut random)?; // 302 to `redirect`
    }
    Err(OAuthAuthorizationFailure::Local(error)) => { /* show the error; do not redirect */ }
    Err(OAuthAuthorizationFailure::Redirect(uri)) => { /* 302 to `uri` */ }
}
// POST /token, /introspect, /revoke, /par, /device
let response = server.token(&request, now, &mut random);
```

- Routes: the paths of `OAuthServerConfig::new` are `/authorize`, `/token`,
  `/introspect`, `/revoke`, `/par` and `/device` under the issuer; change
  them in the configuration. Serve `server.metadata().encode()` at
  `OAuthMetadata::location(Server, issuer)` and, with JWT access tokens,
  `server.jwks()` at `jwks_uri`. With `protocol-http`, route them with a
  `service::Router<HTTPRule, _>` (see `examples/integrated.rs`).
- A client is registered with its authentication method, its redirect URIs,
  its grant types, the scope it may be granted, the resources it may ask for,
  and whether it may introspect. A secret is kept as its SHA-256 digest only.
- Codes, tokens and device codes are random (32 octets by default) and kept
  as their SHA-256 digests. Every table has a limit in all and a limit per
  client (`maximum_tokens` and `maximum_tokens_per_client`, ...), so that one
  client cannot fill a table for the others; when a table is full, the
  endpoint answers 503 `temporarily_unavailable` rather than forgetting live
  grants, and a refused refresh leaves the refresh token valid. A public
  client's identifier is public, so its share can still be filled by anyone
  who names it: limit the rate of requests in front of the server. Expired
  records are dropped by the endpoints, in order of expiry, without a scan;
  `expire(now)` does it at any time.
- `register` refuses redirect URIs that are not absolute or have a fragment
  (RFC 6749 §3.1.2). `approve` and `deny` check the authorization against the
  registration again, so an authorization carried through the consent page
  cannot be changed on the way (redirect URI, PKCE challenge).
- The server does not authenticate users or keep consent: do that between
  `authorize` and `approve`, and give `approve` the user (`subject`), the
  scope and resources granted (at most those asked for), and, for step-up
  authentication, when and how the user authenticated (`auth_time`, `acr`).
- Access tokens are opaque by default; with
  `OAuthAccessTokenFormat::JWT`, they are JWTs of RFC 9068 signed with your
  key, whose `aud` is the resource asked for or `default_audience`.
- The device grant: `device_authorize` answers the device; show the user code
  on your verification page, look it up with `device(user_code)`, and call
  `device_approve` or `device_deny`. User codes are eight consonants (about
  34 bits, RFC 8628 §6.1): limit the attempts at your verification page.
- DPoP: a token request with a valid proof gets tokens bound to its key
  (`token_type` `DPoP`), and a proof at the PAR endpoint binds the code as
  `dpop_jkt` does (RFC 9449 §10.1). The proof's `htu` is compared with the
  configured endpoint. Set `config.dpop.require_nonce` and call
  `server.dpop().rotate_nonce(random)` before serving and regularly after:
  without a nonce made, proofs are refused with `server_error`. The
  `config.dpop.previous_nonces` nonces made before the current one (1 by
  default) are still taken, so that a rotation does not refuse the requests
  in flight.
- Revocation (RFC 7009): a token of another client is refused with
  `unauthorized_client` (§2.1); an unknown token is answered 200 (§2.2).

## Protected resource

```rust
let mut resource = OAuthResourceServer::new(OAuthResourceConfig {
    resource: "https://api.example".into(),
    realm: Some("api".into()),
    resource_metadata: Some(OAuthMetadata::location(OAuthMetadataKind::Resource, "https://api.example")?),
    validation: OAuthTokenValidation::JWT { issuer: "https://as.example".into(), keys, algorithms: vec![JWSAlgorithm::ES256] },
    require_dpop: false,
    dpop: DPoPConfig::default(),
    leeway: 0,
});
match resource.accept_jwt(&request, now) {
    Ok(info) => resource.require_scope(&info, &OAuthScope::parse("read")?, OAuthTokenScheme::Bearer)?,
    Err(refusal) => return refusal.to_response(), // 401/403 with WWW-Authenticate
}
```

- Tokens are read from the `Authorization` header only (`Bearer` or `DPoP`).
  RFC 6750 §2.3 advises against tokens in the query, and the form body
  method mixes the token with application data; neither is supported.
- JWT access tokens are checked as RFC 9068 §4 says: the type `at+jwt`, the
  issuer, this resource in `aud`, the signature with one of `keys` and
  `algorithms`, and the lifetime. With `OAuthTokenValidation::Introspection`,
  introspect the token yourself (an `OAuthClient::endpoint_request` to the
  introspection endpoint) and hand the answer to `accept_introspection`.
- A DPoP-bound token must come with the `DPoP` scheme and a proof of its key
  for this request (method, URI without query and fragment, the hash of the
  token); a bound token sent as `Bearer` is refused. Give the request's
  absolute URI in `OAuthEndpointRequest::uri`, as the client sees it.
- A token whose `cnf` (RFC 7800) has no `jkt`, such as one bound to a client
  certificate (`x5t#S256`, RFC 8705), is refused with `invalid_token`: this
  resource cannot check that binding, and taking the token as a Bearer token
  would undo it. A malformed `cnf` is refused too. Members of `cnf` beside
  `jkt` are ignored, as RFC 7800 §3.1 says. An introspection response with
  such a `cnf` fails to decode (`OAuthMembers::confirmation` reads `cnf` for
  both), so the token is not taken either.
- Refusals carry the challenges of RFC 6750 §3 (and `algs` for DPoP,
  `resource_metadata` of RFC 9728 §5.1): a request without credentials gets
  one challenge per scheme and no error code, `insufficient_scope` names the
  scope needed (403), and `require_authentication` asks for a more recent or
  stronger login (`insufficient_user_authentication`, RFC 9470).
- `OAuthChallenge::parse` reads `WWW-Authenticate` on the client side, for
  `resource_metadata` and step-up requests. It refuses control characters in
  values, and `encode` refuses a challenge whose scheme or names are not
  tokens or whose values hold a control character (CR and LF would inject
  header fields); `OAuthResourceServer::new` refuses a realm that could not
  be quoted.

## Security defaults

| Rule | Where |
| --- | --- |
| PKCE with S256 required for every authorization request; `plain` refused | RFC 9700 §2.1.1 |
| no implicit grant (`response_type=token`), no password grant | RFC 9700 §2.1.2, §2.4 |
| redirect URIs compared exactly; a loopback `http` URI may change its port | RFC 9700 §2.1, RFC 8252 §7.3 |
| errors about the client or redirect URI are shown, never redirected | RFC 6749 §4.1.2.1 |
| codes are used once; a second use revokes what the first gave | RFC 6749 §4.1.2 |
| refresh tokens rotate; a replaced one used again revokes the grant | RFC 9700 §4.14.2 |
| the code is bound to the redirect URI, the PKCE verifier and the client | RFC 6749 §4.1.3, RFC 7636 §4.6 |
| `iss` in every authorization response | RFC 9207 |
| client assertions used once, for a lifetime of at most 5 minutes | RFC 7523 §3 |
| errors in a request's syntax go back to a known redirect URI | RFC 6749 §4.1.2.1 |
| refresh tokens of public clients bound to their DPoP key | RFC 9449 §5 |
| client credentials only for confidential clients, without refresh tokens | RFC 6749 §4.4 |
| one client authentication method per request | RFC 6749 §2.3 |

All of these are configurable where the specifications allow a choice
(`require_pkce`, `rotate_refresh_tokens`, lifetimes, limits).

## C and Python

The C ABI (`include/umilib/auth/oauth.h`) passes messages as their text on
the wire: parameters through `umilib_auth_oauth_OAuthParameters`, documents
as JSON that the library checks and writes back canonical. The client,
server, resource server, DPoP verifier, endpoint requests and responses are
handles. When the other side answered with an OAuth error, a function fails
with the status `Response` and writes the error response's JSON into its
`out_error` buffer. Python (`umilib.auth.oauth`) has the same classes; an
error response is `OAuthError.response`, a refused authorization request
raises `OAuthAuthorizationFailure`, and a refusal of a resource server raises
`OAuthResourceError`.
