# `umilib::codec::asn1`

ASN.1 encodings (ITU-T X.690). Features: `codec-asn1-der`, `codec-asn1-ber` (which also enables DER), or `codec-asn1`.

## Shared types

| Type | Purpose |
| --- | --- |
| `Tag`, `TagClass` | Identifiers; constants for every universal type (`Tag::SEQUENCE`, ...), `Tag::context(n, constructed)` |
| `ObjectIdentifier` | Contents octets of an OID; `parse("1.2.840.113549")`, `from_arcs`, `arcs()`, `Display`; `from_static(&[...])` for constants. Arcs up to 128 bits (UUID arcs). |
| `ASN1Integer` | INTEGER contents (two's complement, fewest octets); `as_i64`, `as_u128`, `magnitude()` for unsigned big numbers |
| `BitString` | BIT STRING value: unused bits and octets; `bit(i)`, `named_bits()` and `from_named_bits(bits)` (without trailing zero bits, X.690 section 11.2.2) for named bit lists |
| `ASN1Time` | A moment in UTC; DER and BER forms of UTCTime and GeneralizedTime, Unix time conversion |
| `ASN1Real` | REAL contents (X.690 section 8.5): `to_der` converts any BER form to the DER form of section 11.3, `validate_der` checks it |
| `ASN1String` | Character set checks (PrintableString, IA5String, ...) and BMP/Universal string conversion |

UTCTime two-digit years follow RFC 5280: 50–99 are 1950–1999, 00–49 are 2000–2049.
Leap seconds are not accepted. GeneralizedTime fractions may have any number
of digits: `check_generalized_time` validates them all and
`generalized_time_ber_to_der` keeps them all, while `ASN1Time` holds
nanoseconds, so decoding a finer fraction fails with `OutOfRange` instead of
rounding. BER fractions of an hour or a minute (`2024010112.5Z`) are converted
exactly.

`Tag::compare_order` is the canonical order of X.680 section 8.6 (class, then
number), which orders SET components; it differs from comparing identifier
octets, and from the derived `Ord`, because the form is not part of it.

## DER

```rust
use umilib::codec::asn1::der::{DERReader, DERWriter};

let mut writer = DERWriter::new();
writer.write_sequence(|fields| {
    fields.write_integer_i128(5);
    fields.write_explicit(0, |tagged| { tagged.write_boolean(true); Ok(()) })
})?;
let encoding = writer.into_bytes();

let mut sequence = DERReader::new(&encoding).read_sequence()?;
let number = sequence.read_integer()?.as_i64()?;
let flag = sequence.read_explicit(0)?.read_boolean()?;
sequence.finish()?;
```

`DERReader` accepts only the DER encoding: definite, minimal lengths; primitive
strings; `0xFF` for TRUE; zero padding bits; minimal integers, identifiers and
tags; the DER forms of times and reals. `read_set` requires SET components in
ascending tag order and `read_set_of` SET OF components in ascending order of
their encodings (`read_set_of_tagged` for an implicitly tagged SET OF); `DERWriter::write_set` and `write_set_of` sort them so.
`DERWriter` may write secrets (private keys). It leaves no copy in freed
memory: it grows its buffer itself (`reserve`), zeroizing the one it
leaves, and zeroizes its nested writers and, when dropped, itself.
Every read either returns a valid element or fails without moving.

`DERReader::validate` checks a whole encoding. Without the schema it accepts a
SET whose components follow either order (`DERSetOrder`). SEQUENCE, SET,
EXTERNAL, EMBEDDED PDV and CHARACTER STRING must be constructed and every
other universal type primitive. The contents of BOOLEAN, INTEGER, ENUMERATED,
BIT STRING, NULL, OBJECT IDENTIFIER, RELATIVE-OID, REAL, UTCTime,
GeneralizedTime and the strings with a known character set are checked; those
of ObjectDescriptor, TIME, TeletexString, VideotexString, GraphicString,
GeneralString, DATE, TIME-OF-DAY, DATE-TIME, DURATION, the IRI types and
unassigned numbers are not. Nesting is limited (`DEFAULT_MAXIMUM_DEPTH` = 64)
and walked with explicit stacks, so a raised limit never exhausts the call stack.

For implicitly tagged values, read the element with `read_expected(tag)` and
decode it with the `DERElement::as_*` methods.

## BER

`BERReader` additionally accepts non-minimal lengths (including more length
octets than any length needs), indefinite lengths, segmented (constructed)
strings, any non-zero octet for TRUE, set padding bits, every BER form of
REAL, and the BER forms of times (offsets are converted to UTC; local times
without a zone are rejected). Contents rules that are the same in BER (minimal
integers, valid identifiers and character sets, primitive-only and
constructed-only types) are enforced. An indefinite length is resolved by
scanning for the end of its contents, so the time grows with the nesting depth
times the size: the default depth limit keeps it linear.

`BERReader::to_der` converts an encoding to DER, for example to check a
signature computed over the DER form. SET components are sorted by tag when
their tags are distinct (a SET) and by encoding otherwise (a SET OF). Three
conversions need the schema and are not done: values equal to their DEFAULT
are kept, implicitly tagged strings split into segments stay constructed, and
a SET OF whose components have distinct tags (a SET OF CHOICE) is sorted as
a SET.
