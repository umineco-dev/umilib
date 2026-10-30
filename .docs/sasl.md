# SASL

How `umilib::auth::sasl` is built. The user-facing description is
`docs/auth-sasl.md`.

- **Messages and state machines, no callbacks.** Each mechanism is its
  messages (`encode`/`decode`); SCRAM, the only one with several steps,
  adds a client and a server whose methods take a message and return the
  next. The server does not call back to look up credentials: the
  application reads `server.username()` after the first message and passes
  the credentials to `server_first`, which keeps lookups that are
  asynchronous (a database) outside the module.
- **Names.** The type prefixes are the registered mechanism names (`PLAIN`,
  `EXTERNAL`, `ANONYMOUS`, `SCRAM`, `OAUTHBEARER`), upper case as the
  registry writes them.
- **Errors by role.** The decoders of the client messages (which servers
  read) fail with `SCRAMError::Server(value)`, the value the server reports
  in `e=`; the decoders of the server messages (which clients read) fail
  with the client errors. A received `e=` gives the same
  `SCRAMError::Server(value)`, so both sides speak of one error the same way.
- **Text as received.** The AuthMessage and the channel binding check use
  the client-first-message-bare and the GS2 header as the server received
  them (RFC 5802 §5.1: the username is used as received in the hash), not
  as the decoded fields would encode again.
- **Choices where RFC 5802 is silent.** A server nonce that does not add to
  the client nonce is refused (`Nonce`): the server must contribute. A
  `p` flag with a non-PLUS mechanism is `channel-binding-not-supported`;
  `n` or `y` with a `-PLUS` mechanism and a changed nonce in the
  client-final-message are `other-error`. Extensions may not reuse the
  letters RFC 5802 defines.
- **Secrets.** Passwords, SaltedPassword, ClientKey, StoredKey and
  ServerKey are kept in `Secret` and the digests and HMAC outputs derived
  from them are zeroized. Stringprep zeroizes its intermediate strings, and
  sizes its buffers from the largest expansion (16 bytes per byte for a
  mapping, 18 code points per code point for NFKD, checked against every
  code point by a test) so that they do not move while they grow.
- **SCRAM-SHA-512** is a draft (draft-melnikov-scram-sha-512, expired) and
  is not in the IANA registry; `SCRAMHash` is implemented for SHA-1 and
  SHA-256 only. Adding a hash is one `impl SCRAMHash`.
- **OAUTHBEARER** accepts any GS2 channel binding flag (RFC 7628 defines no
  channel binding; the application decides), refuses a repeated `auth`,
  `host` or `port`, and keeps unknown keys, which the server must ignore.
- **FFI.** A handle output is the last parameter of a function, which the
  Python bindings rely on (`Handle.create` appends it): `gs2_header_decode`
  writes the header's length before the handle for that reason.

## Vectors and their errors

- RFC 5802 §5 and RFC 7677 §3 give a full exchange each; the tests run both
  sides of this module against every message. RFC 7677 separates the
  messages with blank lines, RFC 5802 does not: the extraction in
  `tests/auth/sasl/mod.rs` joins wrapped lines by their indentation.
- RFC 7628 §4.4 writes the authorization identity as `user=`, which the
  GS2 header does not have (erratum 8564, reported); the test checks that
  it is refused and that the corrected message reads.
- The server errors of RFC 5802 §7 are read from the grammar in the RFC
  text, so that `SCRAMServerError::ALL` cannot drift from it.
- The Python tests recompute SCRAM with `hashlib` and `hmac`, an oracle
  that shares no code with this library.
