# The X.509 public-key infrastructure

How `umilib::auth::cert` is built. The user-facing descriptions are
`docs/auth-cert-*.md`.

## Keys (`auth-cert-key`)

- **Dependencies:** the feature depends on the crypto features of the
  mainstream PKIX algorithms (RSA, ECDSA on the NIST curves, EdDSA, XDH,
  ML-DSA, SLH-DSA, ML-KEM, the SHA families, PBKDF2, AES-CBC). A
  certificate library needs them all, and making each one optional would
  multiply the `cfg`s. Only secp256k1 and the brainpool curves follow
  their own features (`with_curve!` gives `KeyError::Unsupported`
  otherwise).
- **Dispatch:** the macros in `key/mod.rs` (`with_digest!`, `with_curve!`,
  `with_mldsa!`, `with_slhdsa!`, `with_mlkem!`) turn an enum value into the
  type parameter of the crypto module, so each operation is written once.
- **Typed keys:** `PrivateKey` keeps the crypto module's key in a
  `Box<dyn Any + Send + Sync>`, and `PublicKey` keeps one in an
  `Arc<dyn Any + Send + Sync>`, beside its bytes. Every private key type
  zeroizes itself in `Drop`, which an `Any` box preserves. An enum of the
  ~30 key types would be larger and no clearer. Rebuilding a key for each
  operation would cost a key generation per ML-DSA signature, and ~20% of
  an Ed25519 verification (the point decompression).
- **OIDs:** the identifiers are DER constants generated from the arcs of
  the RFCs by a script. `identifiers_are_those_of_the_rfcs` checks them
  against the arcs written in the tests.
- **Consistency checks:** reading a key checks the consistency RFC 9881,
  RFC 9935 and FIPS 203 ask for, and an ML-KEM pairwise check beyond them.
  The second bad key of RFC 9935 C.4 (a mutated `s` with a valid hash) is
  only found by the pairwise check.
- **OpenSSL:** the fixtures in `tests/vectors/auth/cert/key/openssl` are
  remade with `make.sh` in Debian trixie (OpenSSL 3.5, the first with
  ML-DSA, ML-KEM and SLH-DSA). The other direction (OpenSSL reading
  umilib's keys and signatures) was checked by hand. Repeat it after
  changing an encoding: write keys with a small program, then run
  `openssl pkey -pubout` and `openssl pkeyutl -verify` on them.

### Findings of the independent review

The review of `auth-cert-key` found these problems; each has a test:

- **RSASSA-PSS salt length (crypto).** `RSAPSS::verify_digest` computed
  `hLen + sLen + 2` unchecked. On a 32-bit target a salt length near 2^32,
  from the parameters of a certificate, wrapped the check and then sliced
  out of range: a panic, which aborts through the C ABI. The sum is now
  checked. Signing refuses a salt that cannot fit before allocating it
  (`pss_salt_lengths_that_do_not_fit_are_refused`). The fuzz target
  `auth-cert-keys` now verifies arbitrary identifiers and signatures with
  a key of every family.
- **RSA keys of any size** made one verification take minutes. Hence
  `KeyLimits`.
- **Secrets in memory.** The `Debug` of the borrowed views printed private
  keys. `DERWriter` left copies of what it wrote in the buffers it outgrew
  and in its nested writers, and the padding of PBES2 moved the plaintext.
  The writer now grows its buffer itself and zeroizes what it leaves, and
  the plaintext has room for its padding.
- **Specifications.**
  - rsaEncryption parameters MUST be `NULL` (absent ones were accepted).
  - RFC 5958 requires receivers to accept BER (only DER was).
  - A compressed EC point in a v2 key was refused.
  - RFC 8018's minimums (8-byte salt, 1000 iterations) were not enforced.
- **Tests.** The test of a wrong public point used a "foreign" key from
  the same seeded generator, so it was the same key. An `||` in the
  assertion hid that the case tested nothing. Every key meant to differ
  now comes from `random_with(seed)`.

## Certificates and CRLs (`auth-cert-x509`)

- **Borrowed or owned:** every value is `Type<'a>` with `Cow` fields.
  `from_der` borrows from the input (one allocation, the list of
  extensions), and `into_owned` copies. A design that keeps one owned
  buffer and offsets into it needs either self-references or accessors
  that parse again. The FFI handles hold `Certificate<'static>`.
- **Names keep their encoding.** `Name` and `RelativeDistinguishedName`
  are their DER, checked when made or read. `rdns()` and `attributes()`
  read it again without allocating. Their iterators end silently on an
  error, which cannot happen on a checked encoding. Equality is that of
  the encoding; `Name::matches` is the comparison of RFC 5280 §7.1, with
  LDAPPrep from `codec-stringprep` (a dependency of `auth-cert-x509`, so
  that `is_self_issued` and every user compare names the same way).
  Relative names compare their attributes as sorted lists of
  `ComparableValue`s, each prepared once. The first version matched each
  attribute against every other, preparing both each time: a multi-valued
  RDN of a few thousand attributes, which path building compares before
  any signature is checked, cost millions of preparations. Values of
  different string types under one attribute type are compared by their
  prepared text. IA5 types (`domainComponent`, `emailAddress`) are
  IA5String by their definitions, so they never meet a directory string.
- **Signed objects are immutable.** `Certificate`, `CertificateList` and
  `CertificationRequest` keep the signed bytes as read and expose them
  through accessors. Verification then never depends on writing the
  fields again, and the lenient readings below never change what
  verifies. The outer structure is read as strict DER, so `to_der`
  rebuilds the input byte for byte; the fuzz targets check this.
- **Three levels of rules.**
  - `decode` and `encode`: the ASN.1 syntax, with its SIZE constraints and
    the constraints written in its comments (the version against the
    fields, the AKI issuer and serial together, one `onlyContains` flag),
    and repeated extensions.
  - `check`: the requirements on what a CA issues, which `sign` runs.
  - Path validation: the rest.
  
  Reading and writing check the same syntax, so a value read always writes
  back. Writing never produces what reading refuses. The structural MUSTs
  that make a value empty or meaningless (empty name or policy
  constraints, a distribution point of only reasons, an empty IDP, a key
  usage without bits) count as syntax: an empty value has no meaning to
  keep, and leaving it to `check` would let `decode` accept what `encode`
  refuses.
- **Deliberate leniency** (each documented in `docs/auth-cert-x509.md`):
  - `DEFAULT` values written out;
  - trailing zero bits of named bit lists;
  - GeneralizedTime before 2050;
  - an empty `revokedCertificates` written out (read as no entries, and
    omitted when written; the signed bytes are kept, so signatures are
    unaffected).

  Go, BoringSSL and webpki accept these too. Refusing them would break
  deployed certificates without making anything safer. Everything else of
  DER is strict. That includes SET OF order in names: unsorted
  multi-valued RDNs are refused, as the TBS must be DER.
- **Unknown values are refused, not guessed:** versions after v3 (CRLs
  after v2, requests after v1), CRL reason codes RFC 5280 does not define,
  and KeyUsage and ReasonFlags bits beyond the named ones.
- **Policy qualifiers stay raw.** `PolicyQualifierInfo` keeps the
  qualifier's encoding, and `cps_uri()` and `notice()` decode it on
  request. A non-conforming qualifier of a non-critical policies extension
  would otherwise make the policy OIDs, which path validation needs,
  unreadable.
- **The holdInstruction arc.** RFC 5280 appendix A.2 writes
  `holdInstruction` as `{joint-iso-itu-t(2) member-body(2) us(840)
  x9cm(10040) 2}`. `member-body` is an arc of `iso(1)`, so this is
  impossible. The registered identifiers, which OpenSSL and every
  implementation use, are `1.2.840.10040.2.x`. The OpenSSL fixture
  `intermediate.crl` caught the mistake: the first implementation followed
  the RFC's text.
- **RFC 4514:** a type without a short name is printed with the hexadecimal
  form (§2.4 requires it), not as text. The first implementation printed
  text, and the `emailAddress` of the OpenSSL leaf caught it.
- **`DERReader::read_set_of_tagged`** was added for `[0] IMPLICIT SET OF`
  (the attributes of PKCS #10), and `BitString::from_named_bits` /
  `named_bits` for named bit lists. Both are general codec functions.

### Interoperability with OpenSSL 3.5

`tests/vectors/auth/cert/x509/openssl/make.sh` builds the fixtures:
- a P-256 root;
- an RSA intermediate with every certificate extension OpenSSL writes;
- leaves with every form of general name, including P-256, RSASSA-PSS,
  ML-KEM-768 and X25519 keys;
- self-signed certificates of every signature family;
- CRLs with reason, invalidity date and hold instruction;
- requests with attributes and extensions.

The tests read every fixture and verify its signature. They decode every
extension and check that the fields are those OpenSSL was asked to write.
Every fixture and every extension value writes back to the same bytes.

In the other direction, umilib built a chain (an Ed25519 root, an ML-DSA-65
CA with name constraints and policies, an RSA leaf), a CRL and an
RSASSA-PSS request. OpenSSL 3.5 checked all of them:
- `openssl verify` accepted the chain, also with `-crl_check` against the
  CRL;
- `openssl crl -verify` and `openssl req -verify` accepted the CRL and the
  request;
- `-text` showed every extension decoded as written.

### Findings of the independent review

The review of `auth-cert-x509` and `auth-cert-csr` found no panic in 300k
mutations of the fixtures. It found these problems; each now has a test:

- **Read but not written.** Empty name and policy constraints were read,
  but writing refused them. RFC 5280 forbids them, so reading now refuses
  them too. The same rule now applies on both sides to:
  - a distribution point of only reasons;
  - an empty issuing distribution point;
  - a key usage without bits.
- **Invalidity dates** accepted and wrote a fraction of a second. §5.3.2
  defers to §4.1.2.5.2, which forbids it.
- **The C ABI wrote outputs before failing** on a later null output, which
  leaked a buffer and broke the contract of `docs/ffi.md`. Every function
  with several outputs now checks them all first.
- **Ranges of the C ABI.**
  - CRL numbers were `uint64_t`, though RFC 5280 allows 20 octets; they
    are now the contents octets of the INTEGER.
  - The authority key identifier read only its key identifier; it now
    reads the issuer and serial number too.
- **`check`** gained the rule of §4.2.1.9: a `pathLenConstraint` only with
  `cA` and `keyCertSign`.
- **Tests.**
  - The CSR test of a changed byte flipped a length octet, so decoding
    failed and nothing was verified.
  - The test of an omitted empty revoked list did not look at the bytes.

## String preparation (`codec-stringprep`)

- **Why it exists:** RFC 5280 §7.1 compares distinguished names after the
  string preparation of RFC 4518, and SASL (RFC 4013) needs SASLprep. Both
  are profiles of stringprep (RFC 3454), which is defined with Unicode 3.2.
  A normalizer of current Unicode would give other results for code points
  whose data changed, so the module carries its own Unicode 3.2 data.
- **Tables:** `tools/stringprep_tables.py` generates `tables.rs` from the
  text of RFC 3454 (appendices A to D) and from `UnicodeData-3.2.0.txt` and
  `CompositionExclusions-3.2.0.txt` in `tests/vectors/codec/stringprep`.
  Sets are sorted ranges searched by bisection. Decompositions are one
  level per code point, applied recursively. Hangul is algorithmic, as the
  standard specifies it.
- **Composition** blocks a character when a character of class 0, or of a
  class not lower than its own, comes between it and the starter. This is
  the rule as Corrigendum #5 corrected it. The full `NormalizationTest-3.2.0.txt`
  passes, and the fuzz target `codec-stringprep` checks idempotence and
  that the composed forms do not depend on the form they start from.
- **LDAPPrep** follows RFC 4518 with its verified errata:
  - 860: the mapping of the characters of §2.2;
  - 1757: the spaces of the parts of substring assertions;
  - 1758: the steps of insignificant character handling.

  A space followed by a combining mark is significant (§2.6.1), which
  needs the combining marks of Unicode 3.2 (categories Mn, Mc, Me), also
  generated.

## Path validation (`auth-cert-path`)

- **The policy graph of RFC 9618** replaces the policy tree of RFC 5280.
  The tree can grow exponentially with policy mappings (RFC 9618 §3.2 has
  a path of a few kilobytes that needs gigabytes). The graph gives the
  same results and grows linearly. `the_policy_graph_grows_linearly` runs
  the example of RFC 9618 §3.2 over 64 levels, and the fuzz target bounds
  the nodes of each level. Qualifiers are not kept (RFC 9618 §5.2 allows
  it).
- **Budgets.** One `PathBudget` pays for a whole validation: every
  signature (certificates, self-signed checks, CRLs, delta CRLs, and the
  paths of CRL issuers, which share it) and every comparison of a name
  with a name constraint. Both fail with `Work`. The first version gave
  each nested validation of a CRL issuer a fresh budget and verified CRLs
  outside it, so a few hostile intermediates and CRLs multiplied the work.
  CRL issuer paths nest at most `MAXIMUM_NESTED_SIGNERS` (4) deep.
- **A CRL issuer covered by its own CRL.** A CRL issuer whose path is
  already being validated (a cycle) is taken as valid for the CRL, and
  that outer validation decides it. NIST PKITS 4.14.30 requires this: the
  certificate of an indirect CRL issuer is covered only by the CRL it
  issues. A compromised CRL-signing key can then sign a CRL that omits its
  own revocation; this is why every usable CRL in scope is read (below),
  so the CA's own CRL that lists it still counts.
- **Depth.** `maximum_intermediates` counts intermediates that are not
  self-issued, as path length constraints do (§4.2.1.9). Key rollover
  certificates then do not shorten what a CA may build. x509-limbo has
  cases that need this.
- **Trust anchors are not path certificates.** The rules on serial numbers
  and on the authority key identifier are what CAs must issue. A
  relying party configures the anchor, so they are not applied to the
  anchor's certificate. Its validity, basic constraints, key usage and
  critical extensions are checked under the profiles beyond the
  algorithm, because a relying party that trusts an expired root by
  mistake should learn of it.
- **The common name is not an identity** (RFC 9525 §6.3), so the Web PKI
  profile does not check it either. x509-limbo has 9 cases that expect
  checks of it (`LimboCase::DIVERGENCES`). An earlier version had a rule
  "the CN is one of the SANs"; it was removed, because RFC 9525 makes the
  CN irrelevant and the Baseline Requirements rule concerns what CAs
  issue.
- **Name constraints are strict where RFC 5280 is.** Constraints that
  cannot be compared fail the path (§4.2.1.10: process or reject):
  - a leading dot in a DNS constraint;
  - a minimum or maximum other than the profile's;
  - unsupported forms.

  A wildcard SAN must be within permitted subtrees for every name it
  covers, and fails when it can cover an excluded name. Under the Web PKI
  profile name constraints must be critical, as RFC 5280 says. The
  Baseline Requirements allow non-critical ones, and one limbo case
  expects that.
- **Every usable CRL is read.** RFC 5280 §6.3.3 stops when the reasons of
  the CRLs read cover all reasons. In what order CRLs are read is left
  open, so a CRL that omits a revocation (an old one, or one forged with a
  compromised CRL-signing key) could hide one that lists it. Reading every
  current CRL in scope, and letting any revocation win, makes the result
  independent of the order. PKITS and x509-limbo pass with this.
- **Unusable CRLs are skipped, then fail closed.** A CRL in scope that is
  malformed, signed with SHA-1 when `accept_sha1` is not set, has an
  unknown critical extension, or has no valid signer is skipped, as are
  unusable delta CRLs. If the status is still undetermined, the path fails
  with `InvalidCRL`, whether or not revocation is required. The first
  version failed the path at the first unusable CRL, so a garbage CRL
  given before a good one failed paths the good one covers. Sources follow
  the same rule (`InvalidResponse`).
- **Statuses without `nextUpdate`** are current for
  `lifetime_without_next_update` (one day by default) after `thisUpdate`,
  for CRLs and OCSP alike. RFC 6960 §4.2.2.1 says newer information is
  then available at any time, and §3.2 asks for a recent `thisUpdate`. The
  first version took such a status as current forever, so a captured old
  "good" response could be replayed after a revocation. mozilla::pkix
  also takes a day for such OCSP responses.
- **CRL issuers under the Web PKI profile.** The path of a CRL issuer is
  validated under the RFC 5280 profile at most. The Web PKI rules on the
  target are rules on server certificates: a CA that signs CRLs has no
  server purpose, so applying them refused every CA CRL signer.
- **Combining sources:** revoked wins, then unrevoked, then undetermined
  (`RevocationStatus::combine`). Sources are consulted after the CRLs and
  stop at the first revocation. Whatever the order, a revocation is never
  hidden by a source that says "good".
- **Dependency direction:** `RevocationSource` is defined in `path`, and
  `ocsp` implements it under `cfg(auth-cert-path)`. `path` does not depend
  on `ocsp`, so other sources can be added without changing it, and
  `ocsp` does not need `path` unless both are enabled.
- **The C ABI** returns a validation as an outcome handle (`PathOutcome`)
  rather than as a status. The convention of `docs/ffi.md` writes outputs
  only on success, and a refused path needs its index and the reason of a
  revocation. The reason is a status pointer written as a value, so C code
  compares `->name` as it does for any error. Python raises `PathError`
  with `index` and `revocation_reason`.

### Test suites

- **NIST PKITS** (`tests/vectors/auth/cert/path/pkits`, see its `SOURCE`):
  - `cases.txt` was transcribed from `PKITS.pdf`: the objects of each
    test, its expected result, and its settings. Every row was then
    checked against its title (Valid/Invalid).
  - The first transcription got 6 expectations wrong, all fixed after
    reading the PDF again. The PDF's typo "The path not should validate"
    defeated the pattern, and 4.12.x states its results conditionally.
  - All 245 supported tests pass under `PathProfile::Algorithm`. 4.1.4
    and 4.1.5 need DSA signatures, which `auth-cert-key` does not verify.
  - OpenSSL 3.5 (`openssl verify` with `-crl_check_all`, run on the same
    rows as an oracle) disagreed with the PDF on 31 tests. All are areas
    `openssl verify` does not handle as RFC 5280 does, or that its command
    line cannot express:
    - CRLs signed by a key other than the certificates' (4.4.19, 4.5.4,
      4.5.6);
    - the policy tests of 4.8 to 4.12 (16 tests);
    - CRLs partitioned by reason, indirect CRLs and `cRLIssuer` (4.14.x,
      9 tests);
    - delta CRLs (4.15.4, 4.15.5);
    - DSA parameter inheritance (4.1.5).

    Each was checked against the PDF, and the transcription follows the PDF.
- **x509-limbo** (`tests/vectors/auth/cert/path/limbo`):
  - The subset of `tools/limbo_subset.py` (905 cases) runs by default;
    `UMILIB_LIMBO` runs the full suite (9802 cases).
  - A case without `validation_time` is validated at the current time, as
    the suite specifies.
  - The 13 divergences are listed with their reasons in
    `tests/auth/cert/path.rs`. Each is a place where this module is
    stricter (non-critical name constraints), does less (CN checks, the
    Public Suffix List), or trusts the anchor as configured.

## OCSP (`auth-cert-ocsp`)

- **Messages keep their signed bytes**, as certificates do, so
  verification never depends on writing fields again.
  `BasicOCSPCertificates` keeps "no certificates field" (`None`) apart
  from "an empty list" (`Some(vec![])`), so a response read writes back to
  its bytes.
- **Undefined response status codes** (4, 7 and beyond) are decoding
  errors, not `OCSPError::Status`. A status error would claim a responder
  answered `InternalError` when it answered nothing defined.
- **Times** follow RFC 5280 §4.1.2.5.2 (RFC 6960 §4.2.2.1 refers to it):
  GeneralizedTime in UTC without a fraction. The check time is truncated
  to whole seconds, as path validation does.
- **Signer authorization** (§4.2.2.2) is the CA's key, or a certificate in
  the response that the CA issued directly with `id-kp-OCSPSigning`. The
  responder identifier must name that signer. A responder of another CA
  with the same name is refused. `response-other.der` is that case. The
  responder's certificate is a certificate like any other: RFC 5280 §4.2
  forbids using it with a critical extension that is not processed, and
  §4.2.1.3 with a key usage that does not allow signatures.
  `BasicOCSPResponse::authorizes` checks both. The first version did not,
  which the manual review of the module found.
- **`id-pkix-ocsp-nocheck`** is not required: a delegated responder's
  certificate is never checked for revocation. Checking it with OCSP would
  loop, and responders do not publish CRLs for it.
- **Nonces** (RFC 8954) are checked only when the caller sets one in
  `OCSPConfig`. Path validation sets none: stapled and cached responses
  have none, and `thisUpdate`/`nextUpdate` (or the lifetime of a status
  without `nextUpdate`) bound their replay.
- **Work.** `signer` verifies at most `maximum_signatures` signatures, so
  a stapled response with many certificates named like the responder
  costs little.

### Interoperability with OpenSSL 3.5

`tests/vectors/auth/cert/ocsp/openssl/make.sh` builds:
- a root, an authorized responder, a responder of another root;
- leaves that are good, revoked (keyCompromise, with an invalidity date)
  and unknown;
- requests with and without a nonce, signed and not;
- responses by the root, by the responder (by name and by key), without
  `nextUpdate`, by an unauthorized signer, and by the other root's
  responder.

The tests read every fixture back to the same bytes and check each case
of RFC 6960 §3.2.

In the other direction, OpenSSL 3.5 checked responses umilib made:
- `openssl ocsp -respin ... -reqin request-nonce.der` accepted a response
  signed by the CA and one signed by a delegated responder named by key,
  both repeating the request's nonce ("Response verify OK");
- with `-cert`, it printed the same good, revoked (keyCompromise) and
  unknown statuses;
- `openssl dgst -verify` accepted the signature of a signed request, and
  `-req_text` printed its requestor name, identifiers and nonce.

Note for repeating this: `openssl ocsp` with both `-reqin` and `-cert`
builds a second request with a fresh nonce and reports "Nonce Verify
error", even for its own responses. Check the nonce with `-reqin` alone,
and the statuses with `-cert ... -no_nonce`.
