# Certificates and CRLs: `umilib::auth::cert::x509`

`auth-cert-x509` (no `std`) reads, writes, signs and verifies X.509
certificates and CRLs (RFC 5280). It also handles their parts: names,
general names and every extension of RFC 5280 §4.2, §5.2 and §5.3. Path
validation (RFC 5280 §6) is a separate feature, `auth-cert-path`.

```rust
use umilib::auth::cert::key::{HashAlgorithm, PrivateKey, SignatureAlgorithm};
use umilib::auth::cert::x509::{
    BasicConstraints, Certificate, Extension, Extensions, KeyUsage, Name, NameAttribute, SerialNumber,
    SubjectKeyIdentifier, TBSCertificate, Validity, Version,
};

// Reading: DER borrows from the input; PEM gives a certificate that owns its bytes.
let certificate = Certificate::from_der(&bytes)?;
certificate.verify(&issuer.public_key()?)?;
let tbs = certificate.tbs_certificate();
println!("{}", tbs.subject);                                 // "CN=www.example.com,O=Example,C=JP" (RFC 4514)
if let Some(constraints) = tbs.extensions.typed::<BasicConstraints>()? {
    println!("CA: {}", constraints.ca);
}

// Building and signing.
let name = Name::from_attributes(&[(NameAttribute::Country, "JP"), (NameAttribute::CommonName, "Example CA")])?;
let mut extensions = Extensions::new();
extensions.push(Extension::new(&BasicConstraints { ca: true, path_length: None }, true)?)?;
extensions.push(Extension::new(&(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN), true)?)?;
extensions.push(Extension::new(&SubjectKeyIdentifier::from_public_key(&key.public_key()?), false)?)?;
let tbs = TBSCertificate {
    version: Version::V3,
    serial_number: SerialNumber::random(&mut random)?,
    signature: SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256).identifier()?,
    issuer: name.clone(),
    validity: Validity::new(not_before, not_after)?,         // UTCTime or GeneralizedTime as RFC 5280 requires
    subject: name,
    subject_public_key_info: key.public_key()?.info()?.into_owned(),
    issuer_unique_id: None,
    subject_unique_id: None,
    extensions,
};
let certificate = tbs.sign(&key, &mut random)?;              // checks the fields first (see "Writing")
let pem = certificate.to_pem()?;
```

## Types

| Type | What it is |
| --- | --- |
| `Certificate`, `TBSCertificate` | A certificate, and the fields its issuer signs (§4.1) |
| `CertificateList`, `TBSCertList`, `RevokedCertificate` | A CRL, its signed fields and its entries (§5.1) |
| `Version` | v1, v2 or v3; an unknown version is refused (`X509Error::Version`) |
| `SerialNumber` | The INTEGER of a serial number; `random` draws a positive one of 159 bits |
| `Time`, `Validity` | `Time::UTC` or `Time::Generalized`; `Time::new` picks the form RFC 5280 requires for the year |
| `Name`, `RelativeDistinguishedName`, `AttributeTypeAndValue`, `NameAttribute` | Distinguished names (§4.1.2.4) |
| `GeneralName`, `OtherName` | General names (§4.2.1.6) |
| `Extension`, `Extensions`, `ExtensionValue` | Extensions as read, and the trait of their typed values |
| `Attribute` | An attribute with its values (subject directory attributes, certification requests) |

Signed objects (`Certificate`, `CertificateList`) cannot be changed. They
keep the signed bytes exactly as read, so a signature always verifies over
what the issuer signed. To make a new object, build its `TBS*` fields and
call `sign`.

Every type has a lifetime: what is read with `from_der` borrows from the
input, and `into_owned()` makes a copy that does not. `from_pem` returns
owned values.

## Names

`Name` keeps its DER encoding:
- `rdns()` and `attributes()` iterate over its parts;
- `to_rfc4514()` (and `Display`) give the string representation of RFC 4514.

Types with a short name (`CN`, `L`, `ST`, `O`, `OU`, `C`, `STREET`, `DC`,
`UID`) print as text, escaped as §2.4 requires. Other types print as the
dotted identifier, `#` and the hexadecimal encoding of the value.

Names are equal (`==`) when their encodings are equal. `Name::matches`
compares them as RFC 5280 §7.1 requires, as path validation does: the same
number of RDNs, each with the same set of attributes, directory strings
prepared with LDAPPrep for caseIgnoreMatch (RFC 4518, so case and
insignificant spaces do not matter), IA5 strings without ASCII case, and
other values by their encoding. `Name::is_within` says whether a name is in
the subtree of another (its RDNs start with the other's).
`AttributeTypeAndValue::comparable` gives the prepared form of a value.

`Name::from_attributes` and `AttributeTypeAndValue::from_text` build names.
They write each type in its syntax:
- `countryName`, `serialNumber` and `dnQualifier` as PrintableString;
- `domainComponent` and `emailAddress` as IA5String;
- the directory strings as UTF8String, as §4.1.2.4 allows.

They also check the size bounds of RFC 5280 appendix A, for example 2
characters for a country and 64 for a common name.

`AttributeTypeAndValue::text` reads the value of any of these string types:
UTF8String, PrintableString, IA5String, VisibleString, NumericString,
BMPString, UniversalString, and TeletexString (read as ISO 8859-1).

## Extensions

`Extensions` holds the extensions in order, each type at most once (§4.2).
`typed::<T>()` decodes the extension of type `T` if there is one;
`Extension::new(&value, critical)` writes one. The types:

| Extension | Type | RFC 5280 |
| --- | --- | --- |
| Authority key identifier | `AuthorityKeyIdentifier` | §4.2.1.1 |
| Subject key identifier | `SubjectKeyIdentifier` (`from_public_key`: method 1, SHA-1) | §4.2.1.2 |
| Key usage | `KeyUsage` (bits, `contains`, `\|`) | §4.2.1.3 |
| Private key usage period | `PrivateKeyUsagePeriod` | X.509, appendix A.2 |
| Certificate policies | `CertificatePolicies`, `PolicyInformation`, `PolicyQualifierInfo` (`cps_uri`, `notice`), `UserNotice` | §4.2.1.4 |
| Policy mappings | `PolicyMappings` | §4.2.1.5 |
| Subject and issuer alternative names | `SubjectAlternativeName`, `IssuerAlternativeName` | §4.2.1.6, §4.2.1.7 |
| Subject directory attributes | `SubjectDirectoryAttributes` | §4.2.1.8 |
| Basic constraints | `BasicConstraints` | §4.2.1.9 |
| Name constraints | `NameConstraints`, `GeneralSubtree` | §4.2.1.10 |
| Policy constraints | `PolicyConstraints` | §4.2.1.11 |
| Extended key usage | `ExtendedKeyUsage` (with the purposes of §4.2.1.12 as constants) | §4.2.1.12 |
| CRL distribution points, freshest CRL | `CRLDistributionPoints`, `FreshestCRL`, `DistributionPoint`, `ReasonFlags` | §4.2.1.13, §4.2.1.15 |
| Inhibit anyPolicy | `InhibitAnyPolicy` | §4.2.1.14 |
| Authority and subject information access | `AuthorityInformationAccess`, `SubjectInformationAccess`, `AccessDescription` | §4.2.2 |
| CRL number, delta CRL indicator | `CRLNumber`, `DeltaCRLIndicator` | §5.2.3, §5.2.4 |
| Issuing distribution point | `IssuingDistributionPoint` | §5.2.5 |
| Reason code, invalidity date, certificate issuer, hold instruction | `CRLReason`, `InvalidityDate`, `CertificateIssuer`, `HoldInstructionCode` | §5.3 |

Policy qualifiers are kept as their encoding and decoded on request, so a
qualifier of an unexpected form never hides its policy. Counts (path
lengths, `SkipCerts`) are `u32`; larger values are refused.

## Reading

Reading accepts the DER of the syntax of RFC 5280 and checks its
structural rules:
- an unknown version, and a version that does not allow the fields
  present (unique identifiers before v2, extensions before v3, a CRL
  version other than v1 or v2): `X509Error::Version`;
- an outer signature algorithm different from the inner one:
  `AlgorithmMismatch`;
- two extensions of one type: `DuplicateExtension`;
- an empty list where RFC 5280 requires at least one item (extensions,
  general names, policies, distribution points and the like):
  `InvalidExtension` or `InvalidName`;
- an empty value where RFC 5280 requires one of its fields: name and
  policy constraints (§4.2.1.10, §4.2.1.11), a distribution point without a
  name or CRL issuer (§4.2.1.13), an issuing distribution point (§5.2.5),
  and a key usage without any bit (§4.2.1.3): `InvalidExtension`;
- a GeneralizedTime with a fraction of a second, a signature of partial
  octets, and data after the end: `Encoding`.

Four deviations seen in deployed certificates and CRLs change no meaning,
and reading accepts them:
- a value equal to its `DEFAULT` written out (a v1 version, a FALSE
  `critical`, `cA` or IDP flag);
- trailing zero bits in `KeyUsage` and `ReasonFlags`;
- GeneralizedTime before 2050 (in validity and CRL times; an invalidity
  date is always GeneralizedTime, without a fraction);
- an empty list of revoked certificates written out (§5.1.2.6 requires the
  field to be absent; writing omits it).

Reading does not check the rules RFC 5280 places on CAs: §4.1.2.2 asks
users to handle non-positive and long serial numbers gracefully.

## Writing

`encode` and `to_der` check the same syntax that reading does.

`check()` also checks the requirements on what CAs issue, and `sign` runs
it first:
- a positive serial number of at most 20 octets (§4.1.2.2);
- a non-empty issuer (§4.1.2.4, §5.1.2.3);
- UTCTime through 2049 and GeneralizedTime from 2050 (§4.1.2.5);
- an empty subject only with a critical subject alternative name
  (§4.1.2.6);
- no unique identifiers (§4.1.2.8);
- a `pathLenConstraint` only with `cA` and the `keyCertSign` key usage
  (§4.2.1.9);
- a `nextUpdate` in CRLs (§5.1.2.5).

`check()` leaves out the rules on which extensions to include, such as an
authority key identifier in every certificate that is not self-signed.
They depend on the issuer and the use, so they are the caller's to follow.

## Errors

`X509Error`: `Encoding`, `PEM`, `PEMLabel`, `Key` (a `KeyError` of the
algorithm, key or signature), `Version`, `AlgorithmMismatch`,
`DuplicateExtension`, `InvalidExtension`, `InvalidName`, `InvalidTime`,
`InvalidSerialNumber`, `InvalidAttribute`.

## C and Python

The C ABI (`include/umilib/auth/cert/x509.h`) has handles for names, lists
of general names and of extensions, certificates, CRLs and their signed
fields. Times are seconds since the epoch, and serial numbers are the
contents octets of their INTEGER. Extensions are read and written as the
DER of their value. Functions named after an extension convert that value
to and from its fields: basic constraints, key usage, extended key usage,
alternative names, key identifiers, CRL number and reason. The Python
package `umilib.auth.cert.x509` mirrors it, with Python integers for serial
numbers and dataclasses or enums for the extensions.
