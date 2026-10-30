# SASL: `umilib::auth::sasl`

`auth-sasl` (no `std`) implements the messages of the SASL mechanisms of
RFC 4422 that protocols such as SMTP, IMAP and LDAP negotiate. It does no
I/O: the application carries the messages in its protocol (often in
base64), looks up credentials, and decides the outcome.

| Feature | Mechanism | Types | Specification |
| --- | --- | --- | --- |
| `auth-sasl-plain` | `PLAIN` | `PLAINMessage` | RFC 4616 |
| `auth-sasl-external` | `EXTERNAL` | `EXTERNALMessage` | RFC 4422 appendix A |
| `auth-sasl-anonymous` | `ANONYMOUS` | `ANONYMOUSMessage` | RFC 4505 |
| `auth-sasl-scram` | `SCRAM-SHA-1`, `SCRAM-SHA-256` and their `-PLUS` variants | `SCRAMClient<H>`, `SCRAMServer<H>`, `SCRAMCredentials<H>`, ... | RFC 5802, RFC 7677 |
| `auth-sasl-oauthbearer` | `OAUTHBEARER` | `OAUTHBEARERMessage`, `OAUTHBEARERErrorResult` | RFC 7628 |

Shared by all: `SASLMechanism` (the names, compared exactly, and
`SASLMechanism::is_name` for the syntax of RFC 4422 §3.1), `GS2Header`
(RFC 5801 §4, which SCRAM and OAUTHBEARER begin with) and `SASLError`.
`SCRAM-SHA-512` is not implemented: it is still a draft, not registered.

## SCRAM

```rust
use umilib::auth::sasl::scram::{SCRAMClient, SCRAMCredentials, SCRAMNonce, SCRAMSecret, SCRAMServer};
use umilib::hash::sha::v2::SHA256;
use umilib::secret::Secret;

// The client.
let secret = SCRAMSecret::Password(Secret::new(String::from("pencil")));
let mut client = SCRAMClient::<SHA256>::new("user", secret, &SCRAMNonce::random(&mut random)?);
let client_first = client.client_first()?;

// The server: it reads the first message, looks up the user, answers.
let mut server = SCRAMServer::<SHA256>::new(false);
server.receive_client_first(&client_first)?;
let credentials: SCRAMCredentials<SHA256> = lookup(server.username().unwrap());
let server_first = server.server_first(&credentials, &SCRAMNonce::random(&mut random)?)?;

let client_final = client.receive_server_first(&server_first)?;
let server_final = server.receive_client_final(&client_final)?;
client.receive_server_final(&server_final)?;
```

- **Credentials.** A server keeps `SCRAMCredentials` (salt, iteration
  count, StoredKey, ServerKey; never the password): make them with
  `SCRAMCredentials::new(password, salt, iterations)` from a random salt of
  `SCRAMCredentials::SALT_SIZE` bytes or more and 4096 iterations or more
  (RFC 7677 §4), and read them back with `from_parts`. StoredKey is as
  secret as ServerKey: with one observed exchange it gives the ClientKey
  (RFC 5802 §9), so both are kept in `Secret`.
- **Identities.** `server.username()` and `server.authzid()` hold from the
  client-first-message to the end of a successful exchange: once
  `receive_client_final` succeeds, the application checks that the
  authenticated user may act as the authorization identity (RFC 5802 §5).
- **Preparation.** Usernames are prepared with SASLprep as queries, and
  passwords as stored strings (RFC 5802 §2.2, §5.1); `server.username()` is
  the prepared name to look up. `,` and `=` in names are sent as `=2C` and
  `=3D`.
- **Errors.** A server step fails with `SCRAMError::Server(error)`, one of
  the `server-error-value`s of RFC 5802 §7; the server may send
  `server.reject(error)` (`e=...`) or end the exchange without it. A client
  receiving `e=` fails with the same error. The other client errors are
  `Format`, `Extension` (`m=`), `Nonce` (the server's nonce must extend the
  client's), `Iterations`, `ServerSignature`, `Salt`, `Prepare`, `Random`,
  `State`. After a failure, the object refuses further steps.
- **Iteration counts.** `SCRAMConfig` bounds what a client accepts: at
  least 4096 (RFC 5802 §5.1, RFC 7677 §3) and at most 1 000 000 by default,
  so that a server cannot make the client work without bound.
- **Channel binding.** A client sets `channel_binding` (`n`, `y`, or
  `Required(type)`) and `channel_binding_data` (the TLS value of that type,
  present exactly when required); `mechanism()` is then the `-PLUS`
  variant. A server is created for the mechanism the client chose
  (`plus`) and given the types it supports with their data
  (`add_channel_binding`): it refuses `y` when it supports channel binding
  (a downgrade, RFC 5802 §6), types it does not support, and data that does
  not match. Use `tls-exporter` (RFC 9266) with TLS 1.3, where
  `tls-unique` is not defined.
- **Caching.** After a successful exchange, `client.salted_secret()` gives
  the SaltedPassword with its salt and iteration count, which a client may
  keep to log in again without the cost of the key derivation
  (`SCRAMSecret::SaltedPassword`).

## PLAIN, EXTERNAL, ANONYMOUS

- `PLAINMessage::decode` reads `[authzid] NUL authcid NUL password`;
  `verify_password(stored)` compares the presented password (SASLprep as a
  query) with the stored one (SASLprep as a stored string) in constant
  time, and `prepared_authcid()` is the identity to look up (RFC 4616 §2).
  PLAIN sends the password in the clear: accept it only over TLS.
- `EXTERNALMessage` is the authorization identity the client asks to act
  as, empty to act as the identity of its external credentials.
- `ANONYMOUSMessage` holds optional trace information of at most 255
  characters, prepared with the "trace" profile
  (`StringPrepProfile::TRACE`).

## OAUTHBEARER

`OAUTHBEARERMessage::new(authzid, token, host, port)` makes the initial
client response; `decode` reads one, and `encode` writes one, under the
same rules (`OAUTHBEARERMessage::check`): `auth` is present, `auth`,
`host` and `port` occur once, `port` is a positive integer without leading
zeros, and unknown keys are kept. `bearer_token()` is the token of
`auth=Bearer <token>`. On failure the server sends an
`OAUTHBEARERErrorResult` (JSON with `status`, `scope` and
`openid-configuration`), the client answers with
`OAUTHBEARERMessage::DUMMY`, and the server fails the exchange. The bearer
token must travel over TLS (RFC 7628 §3).

## C and Python

The C ABI exports the messages and the SCRAM objects as handles; SCRAM
takes its hash function by the C type name (`umilib_hash_sha_v1_SHA1`,
`umilib_hash_sha_v2_SHA256`). The Python package mirrors it in
`umilib.auth.sasl`, as `SCRAMClient[SHA256]("user", "pencil", nonce)`.
