# `umilib::codec::pem`

PEM textual encoding (RFC 7468). Feature: `codec-pem` (uses `codec-base-base64` and `secret`).

```rust
use umilib::codec::pem::{PEMConfig, PEMDocument, PEMLabel};

let document = PEMDocument::new(PEMLabel::PUBLIC_KEY, der_bytes)?;
let text = document.encode();                         // strict format, 64-character lines
let parsed = PEMDocument::decode(text.as_bytes(), PEMConfig::default())?;
let all = PEMDocument::decode_all(bundle, PEMConfig::default())?; // every document of a file
```

- `PEMStrictness::Strict` (figure 3), `Standard` (figure 1, the default) and
  `Lax` (figure 2) select the grammar of RFC 7468 section 3. Encoding always
  writes the strict format.
- Text outside documents (explanatory text, section 5.2) is ignored.
- The END label must equal the BEGIN label unless `require_matching_label`
  is false. Labels must follow the grammar of section 3; `PEMLabel` lists the
  labels of sections 5 to 13. Legacy labels such as `X509 CERTIFICATE` are
  parsed as written and not treated as `CERTIFICATE` (section 5.1).
- Base64 decoding is strict and constant-time (see `codec-base.md`).
- In the standard grammar the data may be followed by one empty line before
  the END line, and nothing may follow a line with padding except the second
  padding character on its own line (RFC 7468 figure 1, `base64finl`).
- Decoded data is zeroized when the document is dropped, and so is data
  decoded before an error; `encode` allocates its text once, so no copies of
  the encoded data are left in freed memory. `into_data` hands
  the responsibility to you.
- `maximum_length` (16 MiB by default) bounds the text.
- An empty document (no data lines) is accepted in every grammar, although
  the strict grammar cannot express it.
