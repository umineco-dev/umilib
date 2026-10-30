# Certification requests: `umilib::auth::cert::csr`

`auth-cert-csr` (no `std`) reads, writes, signs and verifies certification
requests: PKCS #10 (RFC 2986), with the extensions they request (the PKCS
#9 `extensionRequest` attribute, RFC 2985 §5.4.2).

```rust
use umilib::auth::cert::csr::{CertificationRequest, CertificationRequestInfo};
use umilib::auth::cert::key::{HashAlgorithm, SignatureAlgorithm};
use umilib::auth::cert::x509::{Extension, Extensions, GeneralName, Name, NameAttribute, SubjectAlternativeName};

let mut extensions = Extensions::new();
let names = SubjectAlternativeName { names: vec![GeneralName::DNSName("www.example.com".into())] };
extensions.push(Extension::new(&names, false)?)?;
let info = CertificationRequestInfo {
    subject: Name::from_attributes(&[(NameAttribute::CommonName, "www.example.com")])?,
    subject_public_key_info: key.public_key()?.info()?.into_owned(),
    attributes: vec![CertificationRequestInfo::extension_request(&extensions)?],
};
let request = info.sign(&key, &SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256), &mut random)?;

// A CA reads a request and checks that the requester holds the key.
let request = CertificationRequest::from_pem(&text)?;
request.verify()?;
let requested = request.info().extensions()?;
```

- The version is v1 (0), the only one RFC 2986 defines. Any other version
  is refused with `X509Error::Version`.
- The attributes are required (`[0]`, possibly empty) and written in the
  order DER requires. Each has at least one value (`InvalidAttribute`).
- `extensions()` reads the `extensionRequest` attribute, which must appear
  at most once with one value.
- `sign` proves possession of the key: it refuses a key other than the
  private key of the subject public key (`KeyError::Mismatch`).
- `from_pem` accepts the labels `CERTIFICATE REQUEST` and
  `NEW CERTIFICATE REQUEST` (RFC 7468 §7). `to_pem` writes the first.
- Like certificates, a request keeps its signed bytes as read.
  `info_encoding()` returns them.

The C ABI (`include/umilib/auth/cert/csr.h`) and the Python package
`umilib.auth.cert.csr` build a request from a name, a public key and
extensions, then add attributes and sign. A request that is read gives its
subject, key, attributes and requested extensions.
