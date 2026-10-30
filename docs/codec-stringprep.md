# String preparation: `umilib::codec::stringprep`

`codec-stringprep` (no `std`) prepares Unicode strings so that strings that
mean the same compare equal:

- the tables of stringprep (RFC 3454) and the normalization forms of
  Unicode 3.2, the version stringprep is defined with;
- the profile SASLprep (RFC 4013), used for user names and passwords, and
  the "trace" profile of SASL ANONYMOUS (RFC 4505 §3);
- LDAPPrep (RFC 4518, with its errata 860, 1757 and 1758), which RFC 5280
  §7.1 requires for comparing distinguished names.

```rust
use umilib::codec::stringprep::{LDAPMatching, LDAPPrep, LDAPString, NormalizationForm, StringPrepProfile, Unassigned};

// SASLprep of a stored password: SOFT HYPHEN removed, NFKC applied.
assert_eq!(StringPrepProfile::SASLPREP.prepare("I\u{ad}X", Unassigned::Prohibited)?, "IX");
assert_eq!(StringPrepProfile::SASLPREP.prepare("\u{2168}", Unassigned::Prohibited)?, "IX");

// LDAPPrep for caseIgnoreMatch: case folded, one space around, two between words.
assert_eq!(LDAPPrep::prepare("  Foo   Bar ", LDAPMatching::CaseIgnore, LDAPString::Value)?, " foo  bar ");

// The normalization forms of Unicode 3.2.
assert_eq!(NormalizationForm::NFC.normalize("e\u{301}"), "\u{e9}");
```

## Profiles

A `StringPrepProfile` is the four steps of RFC 3454 §2:

1. The mappings: for each code point, the first table of `mappings` that
   has it decides. `StringPrepMapping::Nothing` removes it,
   `StringPrepMapping::Space` replaces it with SPACE, and
   `StringPrepMapping::Table` replaces it with what the table maps it to.
2. The normalization (`None` for none).
3. The prohibited tables.
4. With `check_bidi`, the rules of bidirectional text of §6.

`Unassigned` says whether the string may hold code points unassigned in
Unicode 3.2 (table A.1). RFC 3454 §7 allows them in queries
(`Unassigned::Allowed`) and prohibits them in stored strings
(`Unassigned::Prohibited`).

`StringPrepProfile::SASLPREP` maps the non-ASCII spaces (C.1.2) to SPACE
and B.1 to nothing, normalizes with NFKC, prohibits the tables of RFC 4013
§2.3, and checks bidirectional text. It does not fold case.

`StringPrepProfile::TRACE` neither maps nor normalizes: it prohibits C.2.1,
C.2.2, C.3, C.4, C.5, C.6, C.8 and C.9, checks bidirectional text, and
allows unassigned code points.

## LDAPPrep

`LDAPPrep::prepare(text, matching, kind)` runs the six steps of RFC 4518:

1. transcode;
2. map (B.1 and the other characters of §2.2 to nothing, the spaces to
   SPACE, and with `LDAPMatching::CaseIgnore` or `Numeric` case folding by
   B.2);
3. NFKC;
4. prohibit: unassigned code points (A.1, refused as `Unassigned`), and
   private use (C.3), non-characters (C.4), surrogates (C.5), the
   characters of C.8 and REPLACEMENT CHARACTER (refused as `Prohibited`);
5. check bidi: nothing, as RFC 4518 §2.5 says;
6. handle insignificant characters, which depends on the matching rule:
   - `CaseIgnore` and `Exact`: spaces (§2.6.1). A value becomes one space,
     its words separated by two spaces, and one space; a value of only
     spaces becomes two spaces. The parts of a substring assertion
     (`LDAPString::InitialSubstring`, `AnySubstring`, `FinalSubstring`)
     follow erratum 1757: an initial part starts with one space and a final
     part ends with one, as a value does; an end where the part meets
     another part has one space only if the text has spaces there; a part
     of only spaces becomes one space.
   - `Numeric`: every space (§2.6.2).
   - `TelephoneNumber`: every space and hyphen (§2.6.3).

## Normalization

`NormalizationForm::{NFD, NFC, NFKD, NFKC}` normalize as Unicode 3.2 does,
with the composition exclusions of that version. Hangul syllables are
decomposed and composed by the algorithm of the Unicode standard. Strings of
code points assigned after Unicode 3.2 normalize as unassigned code points
do (they are left as they are), which is what stringprep requires; for
current Unicode, use a normalizer of that version.

`NormalizationForm::combining_class`, `decomposition` and `composition`
give the data of single code points; `decompose`, `order` and `compose`
are the steps of the algorithm.

## Tables

`StringPrepTable` names the tables of RFC 3454 appendices A to D:
`contains(character)` for the sets, and `mapping(character)` for B.1, B.2
and B.3. `ranges()` and `mappings()` give their contents. The tables are
generated from the text of RFC 3454 by `tools/stringprep_tables.py`.

## Errors

`StringPrepError::Prohibited(character)`, `Unassigned(character)` and
`Bidi`.

## C and Python

`include/umilib/codec/stringprep.h` and the Python package
`umilib.codec.stringprep` give the same functions. Forms, tables, matching
rules and string kinds are numbers (Python `IntEnum`s). The SASLprep profile
is a handle (`StringPrepProfile.SASLPREP` in Python). A refused string
fails with a status whose name is the variant: `Prohibited`, `Unassigned`
or `Bidi`.
