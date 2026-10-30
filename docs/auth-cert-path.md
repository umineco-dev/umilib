# Certification path validation: `umilib::auth::cert::path`

`auth-cert-path` (no `std`) builds a certification path from a target
certificate to a trust anchor and validates it:

- the algorithm of RFC 5280 §6.1, with the policy graph of RFC 9618 in
  place of the policy tree;
- name constraints of every name form of RFC 5280, with names compared as
  §7.1 requires;
- revocation by CRLs (§6.3: distribution points, indirect CRLs, delta
  CRLs, reason codes) and by other sources such as OCSP;
- the identity the target must name (RFC 9525), its key usage and its
  extended key usage;
- the profile of RFC 5280 §4 and the rules of the Web PKI, as options.

It does no I/O: the caller gives the intermediates, CRLs and responses it
has (from a TLS handshake, a directory, a cache).

```rust
use umilib::auth::cert::key::KeyLimits;
use umilib::auth::cert::path::{PathConfig, PathValidator, ServiceIdentity, TrustAnchor};

let anchors = roots.into_iter().map(|root| TrustAnchor::from_certificate(root, &KeyLimits::default())).collect::<Result<Vec<_>, _>>()?;
let config = PathConfig::web_pki_server(now, ServiceIdentity::DNS("www.example.com".into()));
let path = PathValidator::new(&config, &anchors, &intermediates, &crls).validate(&leaf)?;
// path.certificates: from the leaf to the certificate the anchor issued; path.anchor; path.policies.
```

## Configuration

`PathConfig::new(time)` gives the defaults; every field can be changed.

| Field | Default | Meaning |
| --- | --- | --- |
| `time` | | The time at which the path must be valid. A fraction of a second is dropped. |
| `profile` | `PathProfile::RFC5280` | The requirements beyond the algorithm (below). |
| `initial_policy_set` | `None` (any-policy) | `user-initial-policy-set` (§6.1.1 (c)). |
| `initial_explicit_policy`, `initial_policy_mapping_inhibit`, `initial_any_policy_inhibit` | `false` | The initial policy flags (§6.1.1 (e), (f), (g)). |
| `initial_name_constraints` | `None` | Permitted and excluded subtrees of every path (§6.1.1 (h), (i)). |
| `maximum_intermediates` | 8 | The most intermediates, not counting self-issued ones. |
| `maximum_signatures` | 100 | The most signatures a validation verifies (certificates, CRLs, the paths of CRL issuers). |
| `maximum_name_checks` | 2^20 | The most comparisons of names with name constraints. |
| `key_limits` | 16384-bit RSA, 64-bit exponents | The largest keys accepted. |
| `accept_sha1` | `false` | Whether signatures that hash with SHA-1 are accepted. |
| `revocation` | `RevocationConfig::NONE` | Revocation checking (below). |
| `key_usage` | `None` | Key usages the target's key must allow, if it has the extension. |
| `extended_key_usage` | `None` | A purpose the target's extended key usage must allow, if it has the extension. |
| `identity` | `None` | The identity the target must name. |

`PathConfig::web_pki_server(time, identity)` is the validation of a TLS
server: the Web PKI profile, the purpose `id-kp-serverAuth`, and the
identity.

## Trust anchors

A `TrustAnchor` is a trusted name and key (§6.1.1 (d)), with optional name
constraints. `TrustAnchor::from_certificate` takes them from a certificate,
usually self-signed, including its name constraints extension, which RFC
5280 §6.2 lets relying parties honour. A path ends at the first certificate
an anchor issued: the anchor's own certificate is never part of the path.
With a profile beyond the algorithm, the anchor's certificate (if any) is
checked too: valid at the time, a CA, allowed to sign certificates, and
without critical extensions this module does not process.

## Path building

`validate(target)` tries the candidate issuers of each certificate, depth
first, backtracking when a path fails (RFC 4158):

- candidates are the trust anchors and intermediates whose subject matches
  the issuer (§7.1). Those whose subject key identifier is the
  certificate's authority key identifier come first;
- a certificate that is already in the path, or another certificate of the
  same CA (same subject and key), is not added again;
- the search stops after `maximum_signatures` signatures (`Work`) or
  `maximum_name_checks` name comparisons, so that hostile certificates
  cannot make it run long. Both budgets are for the whole validation:
  they also pay for the signatures of CRLs and delta CRLs, the checks of
  self-signed certificates, and the paths of CRL issuers.

The error returned is that of the longest path tried. `PathError` gives
the index of the certificate (0 for the target, the length of the path for
the trust anchor) and the `PathErrorReason`.

## Validation (RFC 5280 §6.1)

Each certificate, from the one the anchor issued to the target, is checked
for:

- its signature, under the key of the previous certificate (or the
  anchor's);
- its validity period;
- its revocation status;
- the chaining of names;
- its name constraints;
- its policies;
- its extensions: an unknown critical extension fails the path;
- for intermediates, `cA` and `keyCertSign`, and path length constraints.

The policies are processed with the valid policy graph of RFC 9618, which
grows linearly with the policies and mappings of the path: the policy tree
of RFC 5280 can grow exponentially. The result is the same. `ValidatedPath`
gives the user-constrained policy set (RFC 9618 §5.5), which contains
anyPolicy (`2.5.29.32.0`) when every policy is valid. It is empty when a
certificate of the path has no certificate policies extension.

## Names

- **Distinguished names** are compared as §7.1 requires: the same number
  of RDNs, each with the same set of attributes. Directory strings are
  prepared with LDAPPrep for caseIgnoreMatch (RFC 4518; see
  [codec-stringprep.md](codec-stringprep.md)), so case and insignificant
  spaces do not matter. IA5 strings are compared without ASCII case. Other
  values are compared by their encoding. `Name::matches` and
  `Name::is_within` (a subtree of a directory name) are in `x509`.
- **Name constraints** apply to the subject and the subject alternative
  names of each certificate after the CA that set them, except self-issued
  intermediates (§6.1.3 (b)). Without alternative names, the
  `emailAddress` attributes of the subject are checked as e-mail
  addresses.
  - DNS names: a constraint is a name of labels; a name is within it if
    it ends with all its labels. A leading dot and wildcards are not
    allowed in constraints. A wildcard name (`*.example.com`) is within a
    permitted subtree only if every name it covers is, and is refused if
    any name it covers is excluded.
  - E-mail addresses: a mailbox, a host (every mailbox of it) or a domain
    starting with a dot (every host below it) (§4.2.1.10).
  - URIs: the host of the URI, as a host or a domain starting with a dot;
    a URI without a host (`urn:`) cannot be compared, so it fails the path
    when a URI constraint applies to it.
  - IP addresses: an address and a mask of the same family, the mask a
    CIDR prefix.
  - Directory names: RDNs prefixes, by §7.1.
  - A comparison that cannot be made fails the path (§4.2.1.10 requires
    processing the constraint or rejecting the certificate): a constraint
    of a form this module does not compare (`otherName`, `x400Address`,
    `ediPartyName`, `registeredID`) applied to a name of that form, a
    `minimum` or `maximum` other than the profile's, and a malformed
    constraint or name.

## Identity (RFC 9525)

`ServiceIdentity::DNS` is matched against the `dNSName`s of the target. A
wildcard is the whole leftmost label (`*.example.com`) and covers one
label. `ServiceIdentity::IPAddress` is matched against the `iPAddress`es and
`ServiceIdentity::Email` against the `rfc822Name`s (local part exact, domain
without case). The common name is never used (RFC 9525 §6.3).

## Revocation

`RevocationConfig { check, require, use_deltas, lifetime_without_next_update }`:
`NONE` checks nothing, `REQUIRED` requires every certificate to be covered
and applies delta CRLs. Both take a CRL or a status without `nextUpdate` as
current for one day after its `thisUpdate`
(`RevocationConfig::DEFAULT_LIFETIME`): without `nextUpdate`, newer
information is available at any time, so an old one must not be trusted.

For each certificate, the CRLs given are processed as §6.3.3 describes:

- the distribution points of the certificate, then the one its issuer is
  (its name and its issuer alternative names);
- the issuing distribution point and its `onlyContains...` flags;
- indirect CRLs and the certificate issuer of their entries (an entry of
  a CRL that is not indirect is always a certificate of the CRL's issuer);
- the reasons each CRL covers, until all are covered;
- a delta CRL of the same scope, newer than the complete CRL.

Every current CRL in scope is read, even after all reasons are covered,
and a revocation in any of them revokes: neither the order of the CRLs nor
a CRL that omits a revocation can hide a CRL that lists it.

A CRL in scope that cannot be used is skipped: malformed, signed with
SHA-1 when `accept_sha1` is not set, with a critical extension not
processed, or without a valid signer. A delta CRL that cannot be used is
skipped too. The signer is the certificate's issuer, the anchor, or the
key of an intermediate whose own path to the same anchor validates (under
the profile of RFC 5280 at most: the Web PKI rules of server certificates
do not apply to CRL issuers). When a status stays undetermined after a CRL
was skipped, the path fails with `InvalidCRL`, whether or not revocation
is required: the status exists but cannot be read.

`PathValidator::with_sources` adds other sources of status, consulted after
the CRLs (an OCSP response is one, see
[auth-cert-ocsp.md](auth-cert-ocsp.md)). The statuses combine:

- revoked if any source says so;
- otherwise unrevoked if any says so;
- otherwise undetermined, which fails the path with `RevocationUnknown`
  when `require` is set.

A source that cannot use what it has about the certificate is skipped like
an unusable CRL, and the path fails with `InvalidResponse` if the status
stays undetermined. A `RevocationSource` is any type that answers
`status(certificate, issuer, issuer_key, config)`.

## Profiles

- `PathProfile::Algorithm`: the algorithm of §6 alone. This is the setting
  of NIST PKITS.
- `PathProfile::RFC5280` adds the requirements of the profile of §4 that a
  relying party can check:
  - extensions marked critical or not as required;
  - key identifiers present;
  - names well formed;
  - a key usage consistent with the basic constraints;
  - CRLs with a CRL number and an authority key identifier.
- `PathProfile::WebPKI` adds the rules of the CA/Browser Forum Baseline
  Requirements:
  - v3 certificates only;
  - RSA keys of at least 2048 bits, a multiple of 8;
  - a target that is not a CA, with an extended key usage without
    anyExtendedKeyUsage, and a critical subject alternative name only
    when the subject is empty;
  - intermediates whose extended key usage, if any, allows the purpose
    asked for;
  - the trust anchor's certificate without an extended key usage, and an
    authority key identifier that is its key identifier alone.

## Conformance

- NIST PKITS: every test of section 4 passes under `PathProfile::Algorithm`,
  except 4.1.4 and 4.1.5 (DSA signatures, which `auth-cert-key` does not
  verify).
- x509-limbo: every case passes except 13, where this module is stricter
  or does less than the suite expects:
  - 9 Web PKI checks of the common name, which RFC 9525 §6.3 no longer
    uses for identity, so it is not checked;
  - 2 wildcards on public suffixes, which need the Public Suffix List;
  - non-critical name constraints accepted by the Web PKI, where this
    module keeps the MUST of RFC 5280 §4.2.1.10 that they are critical;
  - a trusted root, cross-signed elsewhere, without an authority key
    identifier, which the suite refuses: this module trusts the anchor as
    configured, and checks the rule of §4.2.1.1 on the certificates of the
    path, not on the anchor's.

  The list and reasons are in `tests/auth/cert/path.rs`
  (`LimboCase::DIVERGENCES`). The full suite runs with
  `UMILIB_LIMBO=path/to/limbo.json cargo test`.

## C and Python

`include/umilib/auth/cert/path.h` and the Python package
`umilib.auth.cert.path` give the configuration, trust anchors and
validation. In C, `path_validator_validate` takes lists of anchors,
certificates, CRLs and sources, and writes an outcome. `path_outcome_error`
gives the reason (a status), the index and the revocation reason. In Python,
`PathConfig` is a data class, and `PathValidator.validate` returns a
`ValidatedPath` or raises `PathError`, which carries `name`, `index` and
`revocation_reason`.
