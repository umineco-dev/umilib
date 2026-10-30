use umilib::codec::base::BaseError;
use umilib::codec::pem::{PEMConfig, PEMDocument, PEMError, PEMLabel, PEMLineEnding, PEMStrictness};

use crate::Vectors;

fn config(strictness: PEMStrictness) -> PEMConfig {
    PEMConfig { strictness, ..PEMConfig::default() }
}

#[test]
fn every_example_of_rfc7468_decodes_and_re_encodes_identically() {
    let text = Vectors::read("codec/pem/rfc7468.txt");
    let documents = PEMDocument::decode_all(text.as_bytes(), PEMConfig::default()).unwrap();
    let labels: Vec<&str> = documents.iter().map(PEMDocument::label).collect();
    assert_eq!(
        labels,
        [
            "CERTIFICATE",
            "CERTIFICATE",
            "X509 CRL",
            "CERTIFICATE REQUEST",
            "PKCS7",
            "CMS",
            "PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "ATTRIBUTE CERTIFICATE",
            "PUBLIC KEY",
            "X509 CERTIFICATE",
            "X.509 CERTIFICATE",
            "NEW CERTIFICATE REQUEST",
            "CERTIFICATE CHAIN",
        ]
    );
    // The examples are in the strict format, which is what the encoder writes.
    let blocks: Vec<String> = text
        .split("\n-----BEGIN ")
        .skip(1)
        .map(|block| {
            format!(
                "-----BEGIN {}\n",
                &block[..block.find("\n-----END ").unwrap()
                    + block[block.find("\n-----END ").unwrap() + 1..].find('\n').unwrap()
                    + 1]
            )
        })
        .collect();
    assert_eq!(blocks.len(), documents.len());
    for (document, block) in documents.iter().zip(&blocks) {
        // Every example is a DER structure: a SEQUENCE.
        assert_eq!(document.data()[0], 0x30, "{}", document.label());
        assert_eq!(&document.encode(), block, "{}", document.label());
        let strict = PEMDocument::decode(block.as_bytes(), config(PEMStrictness::Strict)).unwrap();
        assert_eq!(strict.data(), document.data());
    }
}

#[test]
fn labels_follow_the_grammar() {
    for valid in ["", "CERTIFICATE", "X509 CRL", "X.509 CERTIFICATE", "A-B", "!~"] {
        assert!(PEMLabel::is_valid(valid), "{valid:?}");
    }
    for invalid in [" A", "A ", "-A", "A-", "A--B", "A  B", "A- B", "Ä", "A\tB"] {
        assert!(!PEMLabel::is_valid(invalid), "{invalid:?}");
    }
    assert_eq!(PEMLabel::PRIVATE_KEY, "PRIVATE KEY");
    assert!(PEMDocument::new("A--B", Vec::new()).is_err());
    assert_eq!(
        PEMDocument::decode(b"-----BEGIN A--B-----\n-----END A--B-----\n", PEMConfig::default()),
        Err(PEMError::InvalidLabel { position: 11 })
    );
}

#[test]
fn end_labels_must_match_unless_disregarded() {
    let text = b"-----BEGIN A-----\nAQID\n-----END B-----\n";
    assert_eq!(PEMDocument::decode(text, PEMConfig::default()), Err(PEMError::LabelMismatch { position: 23 }));
    let disregard = PEMConfig { require_matching_label: false, ..PEMConfig::default() };
    assert_eq!(PEMDocument::decode(text, disregard).unwrap().data(), [1, 2, 3]);
}

#[test]
fn grammars_differ_in_white_space_and_line_lengths() {
    let short = b"-----BEGIN X-----\nAQID\nBAUG\n-----END X-----\n";
    // Strict: only the last line may be shorter than 64 characters.
    assert_eq!(PEMDocument::decode(short, config(PEMStrictness::Strict)), Err(PEMError::InvalidLine { position: 23 }));
    assert_eq!(PEMDocument::decode(short, config(PEMStrictness::Standard)).unwrap().data(), [1, 2, 3, 4, 5, 6]);

    let spaced = b"-----BEGIN X-----  \n\n  \nAQID \t\nBA==\n-----END X----- \n";
    assert_eq!(PEMDocument::decode(spaced, config(PEMStrictness::Standard)).unwrap().data(), [1, 2, 3, 4]);
    assert!(PEMDocument::decode(spaced, config(PEMStrictness::Strict)).is_err());

    // The second padding character may be on its own line (RFC 7468 figure 1).
    let split = b"-----BEGIN X-----\nBA=\n=\n-----END X-----\n";
    assert_eq!(PEMDocument::decode(split, config(PEMStrictness::Standard)).unwrap().data(), [4]);
    // Data after padding, and blank lines inside the data, are not allowed.
    assert!(PEMDocument::decode(b"-----BEGIN X-----\nBA==\nAQID\n-----END X-----\n", PEMConfig::default()).is_err());
    assert!(PEMDocument::decode(b"-----BEGIN X-----\nAQID\n\nBAUG\n-----END X-----\n", PEMConfig::default()).is_err());

    let lax = b"  -----BEGIN X-----AQ ID\tBA\x0b=\x0c=-----END X----- \n";
    assert_eq!(PEMDocument::decode(lax, config(PEMStrictness::Lax)).unwrap().data(), [1, 2, 3, 4]);
    assert!(PEMDocument::decode(lax, config(PEMStrictness::Standard)).is_err());
    assert_eq!(
        PEMDocument::decode(b"-----BEGIN X-----A*A=-----END X-----", config(PEMStrictness::Lax)),
        Err(PEMError::InvalidLine { position: 18 })
    );
}

#[test]
fn line_endings_and_base64_errors() {
    let document = PEMDocument::new(PEMLabel::PUBLIC_KEY, (0..100).collect()).unwrap();
    let crlf = document.encode_with(PEMLineEnding::CRLF);
    assert!(crlf.contains("-----\r\n") && !crlf.replace("\r\n", "").contains('\n'));
    assert_eq!(PEMDocument::decode(crlf.as_bytes(), config(PEMStrictness::Strict)).unwrap(), document);
    let cr = document.encode().replace('\n', "\r");
    assert_eq!(PEMDocument::decode(cr.as_bytes(), PEMConfig::default()).unwrap(), document);
    // Strict: whole lines, padding required.
    assert!(matches!(
        PEMDocument::decode(b"-----BEGIN X-----\nBA\n-----END X-----\n", config(PEMStrictness::Strict)),
        Err(PEMError::InvalidLine { .. })
    ));
    assert_eq!(
        PEMDocument::decode(b"-----BEGIN X-----\nBA\n-----END X-----\n", PEMConfig::default()).unwrap().data(),
        [4]
    );
    assert_eq!(
        PEMDocument::decode(b"-----BEGIN X-----\nBB==\n-----END X-----\n", PEMConfig::default()),
        Err(PEMError::Base64(BaseError::NonCanonical { position: 1 }))
    );
    assert_eq!(document.encode().lines().nth(1).unwrap().len(), 64);
}

#[test]
fn surrounding_text_and_limits() {
    assert_eq!(PEMDocument::decode(b"no document here", PEMConfig::default()), Err(PEMError::NotFound));
    assert_eq!(
        PEMDocument::decode(b"-----BEGIN X-----\nAQID\n", PEMConfig::default()),
        Err(PEMError::MissingEnd { position: 0 })
    );
    let two = b"Subject: one\n-----BEGIN A-----\nAQ==\n-----END A-----\ntext\n-----BEGIN B-----\nAg==\n-----END B-----";
    let documents = PEMDocument::decode_all(two, PEMConfig::default()).unwrap();
    assert_eq!(
        documents.iter().map(|document| (document.label(), document.data().to_vec())).collect::<Vec<_>>(),
        [("A", vec![1]), ("B", vec![2])]
    );
    // Strict requires an end of line after the END line.
    assert!(PEMDocument::decode(b"-----BEGIN B-----\nAg==\n-----END B-----", config(PEMStrictness::Strict)).is_err());
    let limited = PEMConfig { maximum_length: 10, ..PEMConfig::default() };
    assert_eq!(PEMDocument::decode(two, limited), Err(PEMError::TooLong { length: two.len(), maximum: 10 }));
    let empty = PEMDocument::new("EMPTY", Vec::new()).unwrap();
    assert_eq!(empty.encode(), "-----BEGIN EMPTY-----\n-----END EMPTY-----\n");
    assert_eq!(PEMDocument::decode(empty.encode().as_bytes(), PEMConfig::default()).unwrap(), empty);
    assert_eq!(format!("{empty:?}"), "PEMDocument { label: \"EMPTY\", length: 0 }");
    assert_eq!(PEMDocument::new("K", vec![9]).unwrap().into_data(), vec![9]);
}

#[test]
fn the_standard_grammar_allows_one_empty_final_line() {
    // RFC 7468 figure 1: base64text = *base64line base64finl, where the final
    // line may be empty, and a padded final line is followed by the END line.
    let standard = config(PEMStrictness::Standard);
    let accepted = ["-----BEGIN X-----\nAAAA\n\n-----END X-----\n", "-----BEGIN X-----\nAA=\n=\n-----END X-----\n"];
    for text in accepted {
        assert!(PEMDocument::decode(text.as_bytes(), standard).is_ok(), "{text:?}");
    }
    let rejected = [
        "-----BEGIN X-----\nAAAA\n\n\n-----END X-----\n",
        "-----BEGIN X-----\nAA==\n\n-----END X-----\n",
        "-----BEGIN X-----\nAA==\nAAAA\n-----END X-----\n",
    ];
    for text in rejected {
        assert!(
            matches!(PEMDocument::decode(text.as_bytes(), standard), Err(PEMError::InvalidLine { .. })),
            "{text:?}"
        );
    }
    // The lax grammar accepts any white space.
    assert!(PEMDocument::decode(rejected[0].as_bytes(), config(PEMStrictness::Lax)).is_ok());
}

#[test]
fn positions_beyond_the_text_find_nothing() {
    let text = b"-----BEGIN X-----\nAAAA\n-----END X-----\n";
    for start in [text.len(), text.len() + 1, usize::MAX] {
        assert_eq!(PEMDocument::find_begin(text, start, PEMStrictness::Standard), None);
        assert_eq!(PEMDocument::decode_next(text, start, PEMConfig::default()), Ok(None));
    }
    let mut base64 = Vec::new();
    assert!(PEMDocument::collect(text, 20, 10, PEMStrictness::Standard, &mut base64).is_err());
    assert!(PEMDocument::collect(text, 0, text.len() + 1, PEMStrictness::Lax, &mut base64).is_err());
}

#[test]
fn base64_characters_are_classified_exactly() {
    for byte in 0..=u8::MAX {
        let expected = byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/';
        assert_eq!(PEMDocument::is_base64(byte), expected, "{byte:#04x}");
    }
}

#[test]
fn encoding_round_trips_with_both_line_endings() {
    for length in [0, 1, 47, 48, 49, 100] {
        let document = PEMDocument::new(PEMLabel::PRIVATE_KEY, (0..length as u8).collect()).unwrap();
        for ending in [PEMLineEnding::LF, PEMLineEnding::CRLF] {
            let text = document.encode_with(ending);
            assert_eq!(
                PEMDocument::decode(text.as_bytes(), config(PEMStrictness::Strict)).unwrap().data(),
                document.data()
            );
        }
    }
}
