//! Tests of `umilib::codec::asn1` against the rules and examples of ITU-T X.690.

use umilib::codec::asn1::ber::BERReader;
use umilib::codec::asn1::der::{DERReader, DERWriter};
use umilib::codec::asn1::{ASN1Error, ASN1Integer, ASN1String, ASN1Time, BitString, ObjectIdentifier, Tag, TagClass};

use crate::Vectors;

fn der(build: impl FnOnce(&mut DERWriter) -> Result<(), ASN1Error>) -> Vec<u8> {
    let mut writer = DERWriter::new();
    build(&mut writer).unwrap();
    writer.into_bytes()
}

#[test]
fn identifiers_follow_section_8_1_2() {
    assert_eq!(Tag::decode(&[0x30], 0), Ok((Tag::SEQUENCE, 1)));
    assert_eq!(Tag::decode(&[0xA3], 0), Ok((Tag::context(3, true), 1)));
    assert_eq!(Tag::decode(&[0x5F, 0x1F], 0), Ok((Tag::application(31, false), 2)));
    assert_eq!(Tag::decode(&[0xDF, 0x81, 0x00], 0), Ok((Tag::private(128, false), 3)));
    // Numbers below 31 use one octet, and the long form has no leading 0x80.
    assert_eq!(Tag::decode(&[0x1F, 0x1E], 0), Err(ASN1Error::InvalidTag { position: 0 }));
    assert_eq!(Tag::decode(&[0x1F, 0x80, 0x7F], 0), Err(ASN1Error::InvalidTag { position: 0 }));
    for tag in [Tag::INTEGER, Tag::context(0, true), Tag::application(31, false), Tag::private(0xFFFF_FFFF, true)] {
        let mut encoded = Vec::new();
        tag.encode(&mut encoded);
        assert_eq!(Tag::decode(&encoded, 0), Ok((tag, encoded.len())));
    }
    assert_eq!(Tag::context(2, false).class, TagClass::ContextSpecific);
}

#[test]
fn lengths_are_minimal_and_definite_in_der() {
    assert_eq!(DERReader::decode_length(&[0x05], 0, true), Ok((Some(5), 1)));
    assert_eq!(DERReader::decode_length(&[0x81, 0x80], 0, true), Ok((Some(128), 2)));
    assert_eq!(DERReader::decode_length(&[0x82, 0x01, 0x00], 0, true), Ok((Some(256), 3)));
    assert_eq!(DERReader::decode_length(&[0x81, 0x05], 0, true), Err(ASN1Error::NonCanonical { position: 0 }));
    assert_eq!(DERReader::decode_length(&[0x82, 0x00, 0x80], 0, true), Err(ASN1Error::NonCanonical { position: 0 }));
    assert_eq!(DERReader::decode_length(&[0x81, 0x05], 0, false), Ok((Some(5), 2)));
    assert_eq!(DERReader::decode_length(&[0x80], 0, false), Ok((None, 1)));
    assert_eq!(DERReader::decode_length(&[0xFF], 0, false), Err(ASN1Error::InvalidLength { position: 0 }));
    assert_eq!(DERReader::new(&[0x30, 0x80, 0x00, 0x00]).read_sequence(), Err(ASN1Error::NonCanonical { position: 1 }));
    assert_eq!(DERReader::new(&[0x04, 0x05, 0x00]).read_octet_string(), Err(ASN1Error::UnexpectedEnd { position: 0 }));
    let mut length = Vec::new();
    DERWriter::encode_length(0x1_0000, &mut length);
    assert_eq!(length, [0x83, 0x01, 0x00, 0x00]);
}

#[test]
fn booleans_and_nulls() {
    assert_eq!(
        der(|writer| {
            writer.write_boolean(true);
            Ok(())
        }),
        [0x01, 0x01, 0xFF]
    );
    assert_eq!(
        der(|writer| {
            writer.write_boolean(false);
            Ok(())
        }),
        [0x01, 0x01, 0x00]
    );
    assert_eq!(DERReader::new(&[0x01, 0x01, 0xFF]).read_boolean(), Ok(true));
    assert_eq!(DERReader::new(&[0x01, 0x01, 0x01]).read_boolean(), Err(ASN1Error::NonCanonical { position: 0 }));
    assert_eq!(
        DERReader::new(&[0x01, 0x02, 0x00, 0x00]).read_boolean(),
        Err(ASN1Error::InvalidContent { position: 2 })
    );
    assert_eq!(BERReader::new(&[0x01, 0x01, 0x01]).read_element().unwrap().as_boolean(), Ok(true));
    assert_eq!(
        der(|writer| {
            writer.write_null();
            Ok(())
        }),
        [0x05, 0x00]
    );
    assert_eq!(DERReader::new(&[0x05, 0x01, 0x00]).read_null(), Err(ASN1Error::InvalidContent { position: 2 }));
}

#[test]
fn integers_use_the_fewest_octets() {
    // X.690 section 8.3 and common examples.
    for (value, encoding) in [
        (0i128, &[0x00][..]),
        (127, &[0x7F]),
        (128, &[0x00, 0x80]),
        (256, &[0x01, 0x00]),
        (-1, &[0xFF]),
        (-128, &[0x80]),
        (-129, &[0xFF, 0x7F]),
        (i128::MAX, &[0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
    ] {
        let written = der(|writer| {
            writer.write_integer_i128(value);
            Ok(())
        });
        assert_eq!(&written[2..], encoding, "{value}");
        assert_eq!(DERReader::new(&written).read_integer().unwrap().as_i128(), Ok(value));
    }
    for invalid in [&[][..], &[0x00, 0x7F], &[0xFF, 0x80]] {
        assert!(ASN1Integer::new(invalid).is_err(), "{invalid:?}");
    }
    let modulus = [0xC0, 0x01];
    let written = der(|writer| {
        writer.write_integer_unsigned(&[0x00, 0x00, 0xC0, 0x01]);
        Ok(())
    });
    assert_eq!(written, [0x02, 0x03, 0x00, 0xC0, 0x01]);
    let integer = DERReader::new(&written).read_integer().unwrap();
    assert_eq!(integer.magnitude(), Some(&modulus[..]));
    assert_eq!(integer.as_u64(), Ok(0xC001));
    assert_eq!(ASN1Integer::new(&[0x80]).unwrap().as_u64(), Err(ASN1Error::OutOfRange));
    assert_eq!(ASN1Integer::new(&[0x01; 17]).unwrap().as_i128(), Err(ASN1Error::OutOfRange));
    assert_eq!(
        der(|writer| {
            writer.write_integer_unsigned(&[]);
            Ok(())
        }),
        [0x02, 0x01, 0x00]
    );
}

#[test]
fn bit_strings_follow_section_8_6() {
    // X.690 8.6.4.2: the 44 bits 0A3B5F291CD, primitive and constructed.
    let primitive = [0x03, 0x07, 0x04, 0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xD0];
    let bits = DERReader::new(&primitive).read_bit_string().unwrap();
    assert_eq!((bits.unused_bits(), bits.bit_length()), (4, 44));
    assert!(bits.bit(4) && !bits.bit(0) && !bits.bit(44));
    let constructed = [0x23, 0x80, 0x03, 0x03, 0x00, 0x0A, 0x3B, 0x03, 0x05, 0x04, 0x5F, 0x29, 0x1C, 0xD0, 0x00, 0x00];
    assert_eq!(BERReader::new(&constructed).read_element().unwrap().as_bit_string().unwrap(), bits);
    assert_eq!(BERReader::to_der(&constructed, 64).unwrap(), primitive);
    assert!(DERReader::new(&constructed).read_bit_string().is_err());
    // DER requires the unused bits to be zero.
    assert_eq!(
        DERReader::new(&[0x03, 0x02, 0x04, 0x0F]).read_bit_string(),
        Err(ASN1Error::NonCanonical { position: 0 })
    );
    assert_eq!(BERReader::to_der(&[0x03, 0x02, 0x04, 0x0F], 64).unwrap(), [0x03, 0x02, 0x04, 0x00]);
    assert!(BitString::new(8, &[0u8][..]).is_err() && BitString::new(1, &[][..]).is_err());
    assert_eq!(DERReader::new(&[0x03, 0x01, 0x00]).read_bit_string().unwrap().bit_length(), 0);
    let mut writer = DERWriter::new();
    assert!(writer.write_bit_string(&BitString::new(4, &[0x0F][..]).unwrap()).is_err());
}

#[test]
fn object_identifiers_follow_section_8_19() {
    // X.690 8.19.5: { 2 999 3 } is 88 37 03.
    let oid = ObjectIdentifier::from_arcs(&[2, 999, 3]).unwrap();
    assert_eq!(oid.as_bytes(), [0x88, 0x37, 0x03]);
    assert_eq!(oid.to_string(), "2.999.3");
    let rsa = ObjectIdentifier::parse("1.2.840.113549").unwrap();
    assert_eq!(rsa.as_bytes(), [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]);
    assert_eq!(rsa, ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]));
    assert_eq!(DERReader::new(&[0x06, 0x03, 0x88, 0x37, 0x03]).read_object_identifier().unwrap(), oid);
    // A 128-bit UUID arc (ITU-T X.667).
    let uuid = ObjectIdentifier::parse("2.25.329800735698586629295641978511506172918").unwrap();
    assert_eq!(uuid.arcs()[2], 329800735698586629295641978511506172918);
    assert_eq!(uuid.to_string(), "2.25.329800735698586629295641978511506172918");
    for invalid in [&[][..], &[0x80, 0x01], &[0x2A, 0x86], &[0x2A, 0x80, 0x01]] {
        assert!(ObjectIdentifier::new(invalid).is_err(), "{invalid:?}");
    }
    for invalid in ["", "1", "3.1", "1.40", "1.2.", "1.02", "1.-2", "1.2.a"] {
        assert!(ObjectIdentifier::parse(invalid).is_err(), "{invalid}");
    }
    assert_eq!(ObjectIdentifier::parse("1.39").unwrap().to_string(), "1.39");
    assert!(ObjectIdentifier::parse(&format!("2.25.{}", u128::MAX)).is_ok());
}

#[test]
fn sequences_and_tagging_follow_the_examples_of_section_8() {
    // X.690 8.9.3: SEQUENCE { name IA5String, ok BOOLEAN } { name "Smith", ok TRUE }.
    let sequence = der(|writer| {
        writer.write_sequence(|inner| {
            inner.write_ia5_string("Smith")?;
            inner.write_boolean(true);
            Ok(())
        })
    });
    assert_eq!(sequence, [0x30, 0x0A, 0x16, 0x05, b'S', b'm', b'i', b't', b'h', 0x01, 0x01, 0xFF]);
    let mut reader = DERReader::new(&sequence);
    let mut inner = reader.read_sequence().unwrap();
    assert_eq!((inner.read_ia5_string(), inner.read_boolean()), (Ok("Smith"), Ok(true)));
    assert!(inner.finish().is_ok() && reader.finish().is_ok());

    // X.690 8.14: Type1 ::= VisibleString; Type2 ::= [APPLICATION 3] IMPLICIT Type1;
    // Type3 ::= [2] Type2; Type4 ::= [APPLICATION 7] IMPLICIT Type3; Type5 ::= [2] IMPLICIT Type2.
    let jones = b"Jones";
    let type1 = der(|writer| writer.write_visible_string("Jones"));
    assert_eq!(type1, [&[0x1A, 0x05][..], jones].concat());
    let type2 = der(|writer| {
        writer.write_element(Tag::application(3, false), jones);
        Ok(())
    });
    assert_eq!(type2, [&[0x43, 0x05][..], jones].concat());
    let type3 = der(|writer| {
        writer.write_explicit(2, |inner| {
            inner.write_raw(&type2);
            Ok(())
        })
    });
    assert_eq!(type3, [&[0xA2, 0x07, 0x43, 0x05][..], jones].concat());
    let type4 = der(|writer| {
        writer.write_constructed(Tag::application(7, true), |inner| {
            inner.write_raw(&type2);
            Ok(())
        })
    });
    assert_eq!(type4, [&[0x67, 0x07, 0x43, 0x05][..], jones].concat());
    let type5 = der(|writer| {
        writer.write_element(Tag::context(2, false), jones);
        Ok(())
    });
    assert_eq!(type5, [&[0x82, 0x05][..], jones].concat());
    let mut explicit = DERReader::new(&type3).read_explicit(2).unwrap();
    assert_eq!(explicit.read_expected(Tag::application(3, false)).unwrap().as_visible_string(), Ok("Jones"));
    assert_eq!(DERReader::new(&type5).read_expected(Tag::context(2, false)).unwrap().as_visible_string(), Ok("Jones"));
}

#[test]
fn set_of_components_are_sorted() {
    let set = der(|writer| {
        writer.write_set_of(|inner| {
            inner.write_integer_i128(3);
            inner.write_integer_i128(1);
            inner.write_octet_string(&[0xFF]);
            inner.write_integer_i128(256);
            Ok(())
        })
    });
    // Sorted as octet strings: 02 01 01 < 02 01 03 < 02 02 01 00 < 04 01 FF.
    assert_eq!(set, [0x31, 0x0D, 0x02, 0x01, 0x01, 0x02, 0x01, 0x03, 0x02, 0x02, 0x01, 0x00, 0x04, 0x01, 0xFF]);
    assert!(DERReader::new(&set).read_set_of().is_ok());
    let unsorted = [0x31, 0x06, 0x02, 0x01, 0x03, 0x02, 0x01, 0x01];
    assert_eq!(DERReader::new(&unsorted).read_set_of(), Err(ASN1Error::NonCanonical { position: 5 }));
    assert!(DERReader::validate(&unsorted, 64).is_err());
    assert_eq!(BERReader::to_der(&unsorted, 64).unwrap(), [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x03]);
    assert_eq!(DERReader::compare_encodings(&[1, 0], &[1]), core::cmp::Ordering::Equal);
    // An implicitly tagged SET OF ([0] IMPLICIT SET OF) has the same order.
    let mut tagged = set.clone();
    tagged[0] = 0xA0;
    assert!(DERReader::new(&tagged).read_set_of_tagged(Tag::context(0, true)).is_ok());
    assert!(matches!(DERReader::new(&tagged).read_set_of(), Err(ASN1Error::UnexpectedTag { .. })));
    let mut unsorted_tagged = unsorted;
    unsorted_tagged[0] = 0xA0;
    assert_eq!(
        DERReader::new(&unsorted_tagged).read_set_of_tagged(Tag::context(0, true)),
        Err(ASN1Error::NonCanonical { position: 5 })
    );
}

#[test]
fn named_bit_lists_drop_trailing_zero_bits() {
    // X.690 section 11.2.2: the encoding of a named bit list has no trailing 0 bits.
    let encode = |bits: u64| {
        let mut content = Vec::new();
        BitString::from_named_bits(bits).encode_content(&mut content);
        content
    };
    assert_eq!(encode(0), [0x00]);
    assert_eq!(encode(1 << 0), [0x07, 0x80]);
    assert_eq!(encode((1 << 5) | (1 << 6)), [0x01, 0x06]);
    assert_eq!(encode(1 << 7), [0x00, 0x01]);
    assert_eq!(encode(1 << 8), [0x07, 0x00, 0x80]);
    assert_eq!(encode(1 << 63).len(), 9);
    for bits in [0, 1, 0x1FF, 0x8000_0000_0000_0001, u64::MAX] {
        assert_eq!(BitString::from_named_bits(bits).named_bits(), Ok(bits));
    }
    // Trailing zero bits read as the same bits; a bit beyond 63 does not fit.
    assert_eq!(BitString::new(0, vec![0x80, 0x00]).unwrap().named_bits(), Ok(1));
    let mut long = vec![0u8; 9];
    long[8] = 0x80;
    assert_eq!(BitString::new(0, long).unwrap().named_bits(), Err(ASN1Error::OutOfRange));
}

#[test]
fn times_follow_the_der_forms() {
    let time = ASN1Time::new(2049, 12, 31, 23, 59, 59, 0).unwrap();
    let utc = der(|writer| writer.write_utc_time(&time));
    assert_eq!(&utc[2..], b"491231235959Z");
    assert_eq!(DERReader::new(&utc).read_utc_time(), Ok(time));
    assert_eq!(ASN1Time::decode_utc_time(b"500101000000Z").unwrap().year, 1950);
    assert!(ASN1Time::new(2050, 1, 1, 0, 0, 0, 0).unwrap().encode_utc_time(&mut Vec::new()).is_err());
    let fraction = ASN1Time::new(1985, 11, 6, 21, 6, 27, 300_000_000).unwrap();
    let generalized = der(|writer| writer.write_generalized_time(&fraction));
    assert_eq!(&generalized[2..], b"19851106210627.3Z");
    assert_eq!(DERReader::new(&generalized).read_generalized_time(), Ok(fraction));
    for invalid in [
        &b"19851106210627.30Z"[..],
        b"19851106210627.Z",
        b"198511062106Z",
        b"19851106210627",
        b"19851106210627+0100",
        b"19851306210627Z",
        b"19850229000000Z",
    ] {
        assert!(ASN1Time::decode_generalized_time(invalid).is_err(), "{}", String::from_utf8_lossy(invalid));
    }
    for invalid in [&b"9105062345Z"[..], b"910506234540+0100", b"911306234540Z", b"9105062345401Z"] {
        assert!(ASN1Time::decode_utc_time(invalid).is_err(), "{}", String::from_utf8_lossy(invalid));
    }
    // BER forms are converted to UTC.
    assert_eq!(
        ASN1Time::decode_utc_time_ber(b"9105062345-0700").unwrap(),
        ASN1Time::new(1991, 5, 7, 6, 45, 0, 0).unwrap()
    );
    assert_eq!(
        ASN1Time::decode_generalized_time_ber(b"19851106210627,5+01").unwrap(),
        ASN1Time::new(1985, 11, 6, 20, 6, 27, 500_000_000).unwrap()
    );
    assert!(ASN1Time::decode_generalized_time_ber(b"19851106210627").is_err(), "local times have no zone");
    assert_eq!(
        BERReader::to_der(b"\x17\x0f9105062345-0700", 64).unwrap(),
        [&[0x17, 0x0D][..], b"910507064500Z"].concat()
    );
    // Leap years: 2000 and 2024 are, 1900 and 2100 are not.
    assert!(ASN1Time::new(2000, 2, 29, 0, 0, 0, 0).is_ok() && ASN1Time::new(2024, 2, 29, 0, 0, 0, 0).is_ok());
    assert!(ASN1Time::new(1900, 2, 29, 0, 0, 0, 0).is_err() && ASN1Time::new(2100, 2, 29, 0, 0, 0, 0).is_err());
    assert!(ASN1Time::new(2024, 1, 1, 0, 0, 60, 0).is_err());
    // Unix time: 2000-03-01 is 951868800.
    assert_eq!(ASN1Time::new(2000, 3, 1, 0, 0, 0, 0).unwrap().to_unix_seconds(), 951_868_800);
    for seconds in [0i64, 951_868_800, -1, 4_102_444_800, -62_135_596_800, 253_402_300_799] {
        assert_eq!(ASN1Time::from_unix_seconds(seconds).unwrap().to_unix_seconds(), seconds);
    }
}

#[test]
fn strings_are_restricted_to_their_characters() {
    assert!(ASN1String::is_printable(b"Abc 012 '()+,-./:=?"));
    for character in *b"@*&_!" {
        assert!(!ASN1String::is_printable(&[character]), "{}", character as char);
    }
    let mut writer = DERWriter::new();
    assert!(writer.write_printable_string("a@b").is_err());
    assert!(writer.write_numeric_string("12 34").is_ok() && writer.write_numeric_string("1a").is_err());
    assert_eq!(ASN1String::decode_bmp(&[0x00, 0x41, 0x30, 0x42]).unwrap(), "Aあ");
    assert!(ASN1String::decode_bmp(&[0xD8, 0x00]).is_err(), "surrogates are not UCS-2");
    assert!(ASN1String::encode_bmp("😀").is_err());
    assert_eq!(ASN1String::decode_universal(&ASN1String::encode_universal("A😀")).unwrap(), "A😀");
    assert!(DERReader::new(&[0x0C, 0x01, 0xFF]).read_utf8_string().is_err());
    // DER never constructs strings; BER may.
    let segmented = [0x24, 0x80, 0x04, 0x01, 0x41, 0x04, 0x01, 0x42, 0x00, 0x00];
    assert!(DERReader::validate(&segmented, 64).is_err());
    assert_eq!(&*BERReader::new(&segmented).read_element().unwrap().as_octet_string().unwrap(), b"AB");
    assert_eq!(BERReader::to_der(&segmented, 64).unwrap(), [0x04, 0x02, 0x41, 0x42]);
}

#[test]
fn ber_lengths_and_nesting() {
    // Non-minimal and indefinite lengths are BER, and convert to DER.
    let ber = [0x30, 0x80, 0x02, 0x81, 0x01, 0x05, 0x31, 0x80, 0x01, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(BERReader::to_der(&ber, 64).unwrap(), [0x30, 0x08, 0x02, 0x01, 0x05, 0x31, 0x03, 0x01, 0x01, 0xFF]);
    assert!(BERReader::to_der(&[0x30, 0x80, 0x02, 0x01, 0x05], 64).is_err(), "missing end of contents");
    assert!(
        BERReader::new(&[0x04, 0x80, 0x00, 0x00]).read_element().is_err(),
        "primitive elements cannot be indefinite"
    );
    assert!(BERReader::new(&[0x00, 0x00]).read_element().is_err());
    assert!(BERReader::new(&[0x00, 0x01, 0x00]).read_element().is_err(), "tag 0 is reserved");
    // Contents rules are the same in BER: an identifier must end its last subidentifier.
    assert!(matches!(BERReader::to_der(&[0x06, 0x02, 0x2A, 0x80], 64), Err(ASN1Error::InvalidContent { .. })));
    assert!(matches!(BERReader::to_der(&[0x13, 0x01, b'@'], 64), Err(ASN1Error::InvalidContent { .. })));
    // Identifiers, integers and booleans are primitive in BER too (X.690 8.19, 8.3, 8.2).
    assert!(matches!(BERReader::to_der(&[0x2D, 0x03, 0x02, 0x01, 0x05], 64), Err(ASN1Error::InvalidContent { .. })));
    assert!(matches!(BERReader::to_der(&[0x22, 0x03, 0x02, 0x01, 0x05], 64), Err(ASN1Error::InvalidContent { .. })));
    assert!(BERReader::may_be_constructed(16) && BERReader::may_be_constructed(4) && !BERReader::may_be_constructed(6));
    let deep: Vec<u8> = [0x30u8, 0x80].repeat(100).into_iter().chain([0x00; 200]).collect();
    assert!(matches!(BERReader::new(&deep).read_element(), Err(ASN1Error::TooDeep { .. })));
    let mut nested = vec![0x05, 0x00];
    for _ in 0..80 {
        let mut outer = vec![0x30];
        DERWriter::encode_length(nested.len(), &mut outer);
        outer.extend_from_slice(&nested);
        nested = outer;
    }
    assert!(matches!(DERReader::validate(&nested, 64), Err(ASN1Error::TooDeep { .. })));
    assert!(DERReader::validate(&nested, 128).is_ok());
    assert_eq!(BERReader::to_der(&nested, 128).unwrap(), nested);
}

#[test]
fn the_der_structures_of_rfc7468_validate_and_convert_unchanged() {
    let text = Vectors::read("codec/pem/rfc7468.txt");
    let mut count = 0;
    for block in text.split("\n-----BEGIN ").skip(1) {
        let body = &block[block.find('\n').unwrap() + 1..block.find("\n-----END ").unwrap()];
        let der = umilib::codec::base::Encoding::decode(
            &umilib::codec::base::base64::Base64::STANDARD,
            body.replace('\n', "").as_bytes(),
        )
        .unwrap();
        DERReader::validate(&der, 64).unwrap_or_else(|error| panic!("{}: {error}", &block[..block.find('-').unwrap()]));
        assert_eq!(BERReader::to_der(&der, 64).unwrap(), der);
        count += 1;
    }
    assert_eq!(count, 14);
    // The first certificate: SEQUENCE { tbsCertificate, signatureAlgorithm ecdsa-with-SHA256, signature }.
    let first = &text
        [text.find("-----BEGIN CERTIFICATE-----\n").unwrap() + 28..text.find("\n-----END CERTIFICATE-----").unwrap()];
    let der = umilib::codec::base::Encoding::decode(
        &umilib::codec::base::base64::Base64::STANDARD,
        first.replace('\n', "").as_bytes(),
    )
    .unwrap();
    let mut certificate = DERReader::new(&der).read_sequence().unwrap();
    let mut tbs = certificate.read_sequence().unwrap();
    let mut version = tbs.read_explicit(0).unwrap();
    assert_eq!(version.read_integer().unwrap().as_i64(), Ok(2));
    assert_eq!(tbs.read_integer().unwrap().as_i64(), Ok(0));
    let mut algorithm = certificate.read_sequence().unwrap();
    assert_eq!(algorithm.read_object_identifier().unwrap().to_string(), "1.2.840.10045.4.3.2");
    let signature = certificate.read_bit_string().unwrap();
    assert_eq!(signature.unused_bits(), 0);
    assert!(certificate.finish().is_ok());
}

#[test]
fn set_components_follow_the_order_of_their_tags() {
    // X.690 section 10.3 and X.680 section 8.6: SET components are ordered by
    // class and number, not by identifier octets, so [0] constructed (A0)
    // comes before [1] primitive (81).
    let tag_order = [0x31, 0x06, 0xA0, 0x02, 0x05, 0x00, 0x81, 0x00];
    assert_eq!(DERReader::validate(&tag_order, 64), Ok(()));
    assert!(DERReader::new(&tag_order).read_set().is_ok());
    assert_eq!(BERReader::to_der(&tag_order, 64).unwrap(), tag_order);
    // [5] constructed (A5) comes before [31] primitive (9F 1F).
    let swapped = [0x31, 0x05, 0x9F, 0x1F, 0x00, 0xA5, 0x00];
    assert_eq!(BERReader::to_der(&swapped, 64).unwrap(), [0x31, 0x05, 0xA5, 0x00, 0x9F, 0x1F, 0x00]);
    assert_eq!(DERReader::new(&swapped).read_set().unwrap_err(), ASN1Error::NonCanonical { position: 5 });
    // Without the schema, a SET in encoding order is accepted as a SET OF.
    assert_eq!(DERReader::validate(&swapped, 64), Ok(()));
    // Equal tags in neither order are a SET OF out of order.
    let unsorted = [0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
    assert_eq!(DERReader::validate(&unsorted, 64), Err(ASN1Error::NonCanonical { position: 5 }));
    assert_eq!(BERReader::to_der(&unsorted, 64).unwrap(), [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    // The writer sorts a SET by tag and rejects equal tags.
    let written = der(|writer| {
        writer.write_set(|set| {
            set.write_element(Tag::context(1, false), &[]);
            set.write_constructed(Tag::context(0, true), |inner| {
                inner.write_null();
                Ok(())
            })
        })
    });
    assert_eq!(written, tag_order);
    let mut writer = DERWriter::new();
    let duplicate = writer.write_set(|set| {
        set.write_null();
        set.write_null();
        Ok(())
    });
    assert_eq!(duplicate, Err(ASN1Error::InvalidContent { position: 2 }));
    assert_eq!(Tag::context(0, true).compare_order(&Tag::context(1, false)), core::cmp::Ordering::Less);
    assert_eq!(Tag::private(0, false).compare_order(&Tag::context(100, true)), core::cmp::Ordering::Greater);
    assert_eq!(Tag::SEQUENCE.compare_order(&Tag::SEQUENCE.with_constructed(false)), core::cmp::Ordering::Equal);
}

#[test]
fn constructed_types_are_never_primitive() {
    // X.690 sections 8.9.1 and 8.11.1: SEQUENCE and SET are constructed.
    for primitive in [[0x10, 0x00], [0x11, 0x00], [0x08, 0x00], [0x0B, 0x00], [0x1D, 0x00]] {
        assert_eq!(DERReader::validate(&primitive, 64), Err(ASN1Error::NonCanonical { position: 0 }), "{primitive:?}");
        assert!(BERReader::to_der(&primitive, 64).is_err(), "{primitive:?}");
    }
    assert!(BERReader::must_be_constructed(16) && BERReader::must_be_constructed(29));
    assert!(!BERReader::must_be_constructed(4));
}

#[test]
fn reals_follow_sections_8_5_and_11_3() {
    use umilib::codec::asn1::ASN1Real;
    // DER: base 2, F = 0, N odd, M and E in the fewest octets (section 11.3.1).
    let canonical: [&[u8]; 7] = [
        &[],                       // plus zero (section 8.5.2)
        &[0x80, 0x00, 0x01],       // 1 = 1 * 2^0
        &[0x80, 0xFF, 0x01],       // 0.5 = 1 * 2^-1
        &[0xC0, 0x00, 0x03],       // -3
        &[0x81, 0x01, 0x00, 0x01], // 2^256
        &[0x40],                   // PLUS-INFINITY (section 8.5.9)
        &[0x43],                   // minus zero
    ];
    for content in canonical {
        assert_eq!(ASN1Real::validate_der(content), Ok(()), "{content:02x?}");
        assert_eq!(ASN1Real::to_der(content).unwrap(), content);
    }
    // BER forms and their DER forms.
    let conversions: [(&[u8], &[u8]); 8] = [
        (&[0x90, 0x01, 0x01], &[0x80, 0x03, 0x01]), // base 8 (bits 6-5 = 01): 1 * 8^1 = 1 * 2^3
        (&[0xA0, 0x01, 0x01], &[0x80, 0x04, 0x01]), // base 16 (bits 6-5 = 10): 1 * 16^1 = 1 * 2^4
        (&[0x84, 0x00, 0x01], &[0x80, 0x01, 0x01]), // F = 1: 1 * 2^1
        (&[0x80, 0x00, 0x04], &[0x80, 0x02, 0x01]), // N even: 4 = 1 * 2^2
        (&[0x80, 0x00, 0x00, 0x03], &[0x80, 0x00, 0x03]), // a leading zero octet in N
        (&[0x81, 0x00, 0x00, 0x05], &[0x80, 0x00, 0x05]), // a two-octet exponent 0
        (&[0xA0, 0xFF, 0x03, 0x00], &[0x80, 0x04, 0x03]), // 0x300 * 16^-1 = 3 * 2^8 * 2^-4
        (&[0xC8, 0xFE, 0x01], &[0xC0, 0x00, 0x01]), // negative, F = 2, E = -2: -1 * 2^2 * 2^-2 = -1
    ];
    for (ber, expected) in conversions {
        assert_eq!(ASN1Real::to_der(ber).unwrap(), expected, "{ber:02x?}");
        assert_eq!(ASN1Real::validate_der(ber), Err(ASN1Error::NonCanonical { position: 0 }), "{ber:02x?}");
    }
    // Invalid: base bits 11, binary N = 0, empty long exponent, a reserved special value,
    // a long exponent whose first nine bits are zeros.
    for invalid in [
        &[0xB0u8, 0x00, 0x01][..],
        &[0x80, 0x00, 0x00],
        &[0x83, 0x00, 0x01],
        &[0x44],
        &[0x40, 0x00],
        &[0x83, 0x02, 0x00, 0x01, 0x01],
    ] {
        assert_eq!(ASN1Real::to_der(invalid), Err(ASN1Error::InvalidContent { position: 0 }), "{invalid:02x?}");
    }
    // Decimal: NR3 with no superfluous zeros, "E+0" for a zero exponent (section 11.3.2).
    for (ber, expected) in [
        (&b"\x021.5"[..], &b"\x0315.E-1"[..]),
        (b"\x01  -0012", b"\x03-12.E+0"),
        (b"\x031.0E3", b"\x031.E3"),
        (b"\x02,250", b"\x0325.E-2"),
        (b"\x03100.e-2", b"\x031.E+0"),
    ] {
        assert_eq!(ASN1Real::to_der(ber).unwrap(), expected, "{ber:?}");
    }
    assert_eq!(ASN1Real::to_der(b"\x02-0.0").unwrap(), [ASN1Real::MINUS_ZERO]);
    assert_eq!(ASN1Real::to_der(b"\x020.00").unwrap(), []);
    assert_eq!(ASN1Real::validate_der(b"\x0315.E-1"), Ok(()));
    for not_der in [&b"\x021.5"[..], b"\x031.E0", b"\x0315.E+1", b"\x03 1.E+0", b"\x03+1.E+0", b"\x03150.E-2"] {
        assert_eq!(ASN1Real::validate_der(not_der), Err(ASN1Error::NonCanonical { position: 0 }), "{not_der:?}");
    }
    for invalid in [&b"\x011.5"[..], b"\x021", b"\x03", b"\x041", b"\x021.5x", b"\x031.E"] {
        assert_eq!(ASN1Real::to_der(invalid), Err(ASN1Error::InvalidContent { position: 0 }), "{invalid:?}");
    }
    // Through the readers.
    assert_eq!(DERReader::validate(&[0x09, 0x03, 0x80, 0x00, 0x01], 64), Ok(()));
    assert_eq!(DERReader::validate(&[0x09, 0x03, 0x80, 0x00, 0x04], 64), Err(ASN1Error::NonCanonical { position: 2 }));
    assert_eq!(BERReader::to_der(&[0x09, 0x03, 0xA0, 0x01, 0x01], 64).unwrap(), [0x09, 0x03, 0x80, 0x04, 0x01]);
}

#[test]
fn relative_object_identifiers_follow_section_8_20() {
    // The example of section 8.20.5: {8571 3 2}.
    assert_eq!(DERReader::validate(&[0x0D, 0x04, 0xC2, 0x7B, 0x03, 0x02], 64), Ok(()));
    assert_eq!(ObjectIdentifier::validate_subidentifiers(&[0xC2, 0x7B, 0x03, 0x02]), Ok(()));
    for invalid in [&[0x0Du8, 0x02, 0x80, 0x01][..], &[0x0D, 0x00], &[0x0D, 0x01, 0x81]] {
        assert_eq!(DERReader::validate(invalid, 64), Err(ASN1Error::InvalidContent { position: 2 }), "{invalid:02x?}");
    }
}

#[test]
fn generalized_time_fractions_are_exact() {
    // X.690 section 11.7 sets no limit on the digits of the fraction.
    let ten_digits = b"20240101000000.0000000001Z";
    let mut element = vec![0x18, ten_digits.len() as u8];
    element.extend_from_slice(ten_digits);
    assert_eq!(DERReader::validate(&element, 64), Ok(()));
    assert_eq!(ASN1Time::decode_generalized_time(ten_digits), Err(ASN1Error::OutOfRange));
    assert_eq!(BERReader::to_der(&element, 64).unwrap(), element);
    assert_eq!(ASN1Time::generalized_time_ber_to_der(b"20240101000000,00000000010Z").unwrap(), ten_digits);
    // Fractions of an hour or a minute (X.680 section 46.2, ISO 8601).
    for (ber, der) in [
        (&b"2024010112.5Z"[..], &b"20240101123000Z"[..]),
        (b"202401011230.25Z", b"20240101123015Z"),
        (b"2024010100.0001Z", b"20240101000000.36Z"),
        (b"2024010112.5+0100", b"20240101113000Z"),
        (b"20241231235959.5-0001", b"20250101000059.5Z"),
    ] {
        assert_eq!(ASN1Time::generalized_time_ber_to_der(ber).unwrap(), der, "{}", String::from_utf8_lossy(ber));
    }
    let half_hour = ASN1Time::decode_generalized_time_ber(b"2024010112.5Z").unwrap();
    assert_eq!((half_hour.hour, half_hour.minute, half_hour.second), (12, 30, 0));
    for invalid in [&b"2024010112.Z"[..], b"20240101.5Z", b"2024010112.5", b"202401011230.2xZ"] {
        assert!(ASN1Time::generalized_time_ber_to_der(invalid).is_err(), "{}", String::from_utf8_lossy(invalid));
    }
    // DER keeps rejecting trailing zeros and missing seconds.
    assert!(ASN1Time::check_generalized_time(b"20240101000000.10Z").is_err());
    assert!(ASN1Time::check_generalized_time(b"202401010000Z").is_err());
}

#[test]
fn ber_lengths_may_have_leading_zero_octets() {
    // X.690 section 8.1.3.5, note 2: more length octets than needed are a sender's option.
    let long = [0x04, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xAB];
    let mut reader = BERReader::new(&long);
    assert_eq!(reader.read_element().unwrap().content, [0xAB]);
    assert_eq!(BERReader::to_der(&long, 64).unwrap(), [0x04, 0x01, 0xAB]);
    assert_eq!(DERReader::validate(&long, 64), Err(ASN1Error::NonCanonical { position: 1 }));
    // A length that does not fit the address space is still an error.
    let huge = [0x04, 0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(BERReader::new(&huge).read_element().is_err());
}

/// `depth` SEQUENCEs nested in definite form around a NULL, built in linear time.
fn nested_sequences(depth: usize) -> Vec<u8> {
    // The contents length of every level, from the innermost.
    let mut lengths = Vec::with_capacity(depth);
    let mut inner = 2;
    for _ in 0..depth {
        lengths.push(inner);
        let mut length = Vec::new();
        DERWriter::encode_length(inner, &mut length);
        inner += 1 + length.len();
    }
    let mut encoding = Vec::with_capacity(inner);
    for &length in lengths.iter().rev() {
        encoding.push(0x30);
        DERWriter::encode_length(length, &mut encoding);
    }
    encoding.extend_from_slice(&[0x05, 0x00]);
    encoding
}

#[test]
fn deep_nesting_uses_no_call_stack() {
    // Nested elements are walked with explicit stacks, so depths far beyond
    // what recursion could handle work once the limit allows them.
    let deep = nested_sequences(100_000);
    assert_eq!(DERReader::validate(&deep, usize::MAX), Ok(()));
    assert!(matches!(DERReader::validate(&deep, 64), Err(ASN1Error::TooDeep { maximum: 64, .. })));
    assert_eq!(BERReader::to_der(&deep, usize::MAX).unwrap(), deep);
    // The indefinite form needs a scan for the end of every level, so the
    // time grows with depth times size; a smaller depth still exceeds what
    // the call stack of a test thread holds.
    let depth = 5_000;
    let mut indefinite = Vec::new();
    for _ in 0..depth {
        indefinite.extend_from_slice(&[0x30, 0x80]);
    }
    indefinite.extend_from_slice(&[0x05, 0x00]);
    for _ in 0..depth {
        indefinite.extend_from_slice(&[0x00, 0x00]);
    }
    assert_eq!(BERReader::to_der(&indefinite, usize::MAX).unwrap(), nested_sequences(depth));
    let mut segments = Vec::new();
    for _ in 0..depth {
        segments.extend_from_slice(&[0x24, 0x80]);
    }
    segments.extend_from_slice(&[0x04, 0x01, 0x7A]);
    for _ in 0..depth {
        segments.extend_from_slice(&[0x00, 0x00]);
    }
    assert_eq!(BERReader::to_der(&segments, usize::MAX).unwrap(), [0x04, 0x01, 0x7A]);
}
