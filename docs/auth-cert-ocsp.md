# OCSP: `umilib::auth::cert::ocsp`

`auth-cert-ocsp` (no `std`) reads, writes, signs and checks the messages of
the Online Certificate Status Protocol (RFC 6960), with the nonce of RFC
8954. It does no I/O: the requests and responses are bytes the caller sends
and receives (by HTTP, or stapled to a TLS handshake).

```rust
use umilib::auth::cert::key::HashAlgorithm;
use umilib::auth::cert::ocsp::{CertID, CertStatus, OCSPConfig, OCSPNonce, OCSPRequest, OCSPResponse, Request, TBSRequest};
use umilib::auth::cert::x509::{Extension, Extensions};

// A request for `certificate`, issued by `issuer`, with a nonce.
let cert_id = CertID::new(&certificate, issuer.public_key()?.key(), HashAlgorithm::SHA256);
let nonce = OCSPNonce::random(&mut random)?;
let mut extensions = Extensions::new();
extensions.push(Extension::new(&nonce, false)?)?;
let tbs = TBSRequest {
    requestor_name: None,
    requests: vec![Request { cert_id: cert_id.clone(), extensions: Extensions::new() }],
    extensions,
};
let request = OCSPRequest::new(tbs)?.to_der()?;

// The response: its signer, its time and its nonce are checked.
let response = OCSPResponse::from_der(&bytes)?;
let config = OCSPConfig { nonce: Some(nonce.nonce.to_vec()), ..OCSPConfig::new(now) };
let single = response.basic()?.verify(&cert_id, &issuer.tbs_certificate().subject, &issuer.public_key()?, &config)?;
match single.status {
    CertStatus::Good => {}
    CertStatus::Revoked { time, reason } => {}
    CertStatus::Unknown => {}
}
```

## Requests

- `CertID::new(certificate, issuer_key, hash)` names a certificate by the
  hash of its issuer's name (the DER of the `issuer` field of the
  certificate), the hash of its issuer's key (the bits of the
  `subjectPublicKey`) and its serial number. `matches` compares two
  identifiers: the same hash function, whatever the encoding of its
  parameters, the same hashes and the same serial number.
  `identifies(certificate, issuer_key)` computes the identifier with the
  identifier's own hash function and compares.
- `TBSRequest` holds the requests, the optional requestor's name and the
  extensions. `OCSPRequest::new` makes an unsigned request;
  `OCSPRequest::sign` signs it (RFC 6960 §4.1.2), with the certificates
  that help verify the signature. `verify(key)` checks a signed request.
- `OCSPNonce` is the nonce extension: 1 to 32 octets (RFC 8954 §2.1).
  `OCSPNonce::random` draws 32, as RFC 8954 asks of new clients.
- The version is v1, the only one RFC 6960 defines. Another version is
  refused (`OCSPError::Version`).

## Responses

- `OCSPResponse` is a status (`OCSPResponseStatus`) and, when the status is
  `Successful`, a basic response. A successful status without one, another
  status with one, or a response type other than `id-pkix-ocsp-basic` are
  refused (`OCSPError::ResponseType`). `basic()` fails with
  `OCSPError::Status` for a status that is not successful (`TryLater`, for
  one).
- `BasicOCSPResponse` holds the signed `ResponseData`: the responder
  (`ResponderID::ByName` or `ResponderID::ByKey`, the SHA-1 hash of its
  key), the time it was produced, the `SingleResponse`s and the
  extensions. It keeps the signed bytes as read.
- `ResponseData::sign(key, algorithm, certificates, random)` makes a basic
  response. A delegated responder includes its certificate.

## Checks (RFC 6960 §3.2)

`BasicOCSPResponse::verify(cert_id, issuer_name, issuer_key, config)`
returns the status of the certificate `cert_id` names after these checks:

1. A status for that certificate exists (`OCSPError::NotFound`).
2. No critical extension that this module does not process is present in
   the response or in that status (`UnknownCriticalExtension`). The nonce
   is the one processed.
3. The signature algorithm is accepted: SHA-1 only with
   `config.accept_sha1` (`Algorithm`).
4. The signer may answer for the CA (§4.2.2.2), checked by
   `BasicOCSPResponse::signer`. Otherwise `Signer`. The signer is one of:
   - the CA's own key;
   - the key of a certificate in the response that
     `BasicOCSPResponse::authorizes`: issued by the CA (same issuer name,
     signature verifying under the CA's key, in an accepted algorithm),
     valid at `config.time`, whose extended key usage has
     `id-kp-OCSPSigning`, whose key usage (if any) has
     `digitalSignature`, and without critical extensions other than
     `RESPONDER_EXTENSIONS` (RFC 5280 §4.2).

   The responder identifier must name the signer: by name or by the hash
   of its key.
5. With `config.nonce`, the response repeats that nonce (`Nonce`).
6. The status is current: `thisUpdate` not after `config.time`, and
   `nextUpdate`, if present, not before it (`Time`). Without `nextUpdate`
   newer information is available at any time (§4.2.2.1), so the status
   must be recent (§3.2): it is current for
   `config.lifetime_without_next_update` seconds after `thisUpdate` (one
   day by default).

The search of the signer verifies at most `config.maximum_signatures`
signatures (9 by default: the CA's key and four delegated responders, two
signatures each), so a response with many certificates costs little.

Times are compared in whole seconds. The times of a response are
GeneralizedTime without a fraction (§4.2.2.1 refers to RFC 5280
§4.1.2.5.2), and a fraction is refused when read.

A delegated responder's own certificate is not checked for revocation, as
if it had `id-pkix-ocsp-nocheck` (§4.2.2.2.1). Responders are configured to
include it, and the alternative, checking the responder with OCSP, loops.
Trusting a responder by local configuration (the first case of §4.2.2.2) is
the caller's choice: verify the response's signature with the trusted key
(`signer` or `verifies`) instead of calling `verify`.

## With path validation

With `auth-cert-path`, `OCSPResponse` and `BasicOCSPResponse` are
revocation sources of `PathValidator` (see
[auth-cert-path.md](auth-cert-path.md)):

```rust
let validator = PathValidator::new(&config, &anchors, &intermediates, &crls).with_sources(&[&response]);
```

For each certificate of the path, a response that names it gives its
status, checked as above without a nonce. A status that is not current is
undetermined. A response that names the certificate but fails another
check fails the path with `PathErrorReason::InvalidResponse`. A response
that does not name it, or is not successful, says nothing.

## C and Python

`include/umilib/auth/cert/ocsp.h` and the Python package
`umilib.auth.cert.ocsp` give the same objects as handles. Requests and
responses are built with `tbs_request_*` and `response_data_*`, read with
the accessors of `ocsp_request_*`, `basic_ocsp_response_*` and
`single_response_*`, and checked with `basic_ocsp_response_verify` under an
`OCSPConfig`. A status is a kind (0 good, 1 revoked, 2 unknown), the
revocation time and the reason code (255 for none). In Python,
`CertStatus`, `OCSPConfig` and `ResponderID` are data classes, and
`OCSPResponse.add_to` adds a response to the sources of a `PathValidator`.
