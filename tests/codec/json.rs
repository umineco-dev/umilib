use umilib::codec::json::{
    DuplicateKeys, JSONConfig, JSONEncoder, JSONError, JSONEvent, JSONNumber, JSONObject, JSONReader, JSONValue,
};

/// The files of JSONTestSuite whose names start with `prefix`.
fn suite(prefix: &str) -> Vec<(String, Vec<u8>)> {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/codec/json/test_parsing");
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with(prefix))
        .map(|path| (path.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read(&path).unwrap()))
        .collect();
    files.sort();
    files
}

#[test]
fn accepts_every_valid_text_of_json_test_suite() {
    let files = suite("y_");
    assert_eq!(files.len(), 95);
    // RFC 8259 allows duplicate keys in the grammar (names SHOULD be unique,
    // and section 4 lets implementations reject them, which umilib does by
    // default); check the grammar with every member kept.
    let grammar = JSONConfig { duplicate_keys: DuplicateKeys::KeepAll, ..JSONConfig::default() };
    for (name, text) in files {
        assert!(JSONReader::new(&text, JSONConfig::default()).unwrap().validate().is_ok(), "{name}");
        let value = JSONValue::decode(&text, grammar).unwrap_or_else(|error| panic!("{name}: {error}"));
        // Encoding then decoding gives the same value.
        let reparse = |text: &str| JSONValue::decode(text.as_bytes(), grammar).unwrap();
        assert_eq!(reparse(&value.encode()), value, "{name}");
        assert_eq!(reparse(&JSONEncoder::PRETTY.encode(&value)), value, "{name}");
        let ascii = JSONEncoder { indent: None, ascii_only: true }.encode(&value);
        assert!(ascii.is_ascii(), "{name}");
        assert_eq!(reparse(&ascii), value, "{name}");
    }
}

#[test]
fn rejects_every_invalid_text_of_json_test_suite() {
    let files = suite("n_");
    assert_eq!(files.len(), 188);
    for (name, text) in files {
        assert!(JSONValue::decode(&text, JSONConfig::default()).is_err(), "{name} must be rejected");
        assert!(JSONReader::new(&text, JSONConfig::default()).unwrap().validate().is_err(), "{name}");
    }
}

#[test]
fn implementation_defined_texts_never_panic() {
    let files = suite("i_");
    assert_eq!(files.len(), 35);
    let config = JSONConfig { maximum_depth: 1000, ..JSONConfig::default() };
    for (_, text) in files {
        let _ = JSONValue::decode(&text, config);
    }
    // umilib's choices: lone surrogates and invalid UTF-8 are errors, as Rust strings cannot hold them.
    assert!(matches!(JSONValue::parse("[\"\\uD800\"]"), Err(JSONError::LoneSurrogate { position: 2 })));
    assert!(matches!(JSONValue::parse("[\"\\uDC00\\uD800\"]"), Err(JSONError::LoneSurrogate { .. })));
    assert!(matches!(
        JSONValue::decode(b"[\"\xff\"]", JSONConfig::default()),
        Err(JSONError::InvalidUTF8 { position: 2 })
    ));
}

#[test]
fn reader_yields_events_that_borrow_the_input() {
    let text = br#" {"a": [1, -2.5e3, true, false, null], "b\u0041": "x\ny"} "#;
    let mut reader = JSONReader::new(text, JSONConfig::default()).unwrap();
    let mut events = Vec::new();
    while let Some(event) = reader.next_event().unwrap() {
        events.push(event);
    }
    assert_eq!(events.len(), 12);
    assert_eq!(events[0], JSONEvent::BeginObject);
    assert!(matches!(events[1], JSONEvent::Key(key) if key.as_str() == Some("a")));
    assert_eq!(events[3], JSONEvent::Number("1"));
    assert_eq!(events[4], JSONEvent::Number("-2.5e3"));
    assert_eq!(
        (events[5], events[6], events[7], events[8]),
        (JSONEvent::Bool(true), JSONEvent::Bool(false), JSONEvent::Null, JSONEvent::EndArray)
    );
    match events[9] {
        JSONEvent::Key(key) => {
            assert_eq!(key.raw(), "b\\u0041");
            assert!(key.is_escaped() && key.as_str().is_none());
            assert_eq!(key.decode().unwrap(), "bA");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(events[10], JSONEvent::String(value) if value.decode().unwrap() == "x\ny"));
    assert_eq!(events[11], JSONEvent::EndObject);
    assert_eq!(reader.depth(), 0);
}

#[test]
fn escapes_follow_section_7() {
    let value = JSONValue::parse(r#""\"\\\/\b\f\n\r\t\u00e9\ud83d\ude00""#).unwrap();
    assert_eq!(value.as_str(), Some("\"\\/\u{8}\u{c}\n\r\té😀"));
    assert_eq!(value.encode(), "\"\\\"\\\\/\\b\\f\\n\\r\\té😀\"");
    assert_eq!(
        JSONEncoder { indent: None, ascii_only: true }.encode(&value),
        "\"\\\"\\\\/\\b\\f\\n\\r\\t\\u00e9\\ud83d\\ude00\""
    );
    assert_eq!(JSONValue::from("\u{1}").encode(), "\"\\u0001\"");
    for invalid in [r#""\x""#, r#""\u12""#, r#""\u12G4""#, "\"\u{1}\""] {
        assert!(JSONValue::parse(invalid).is_err(), "{invalid}");
    }
    assert_eq!(JSONValue::parse("\"\t\""), Err(JSONError::ControlCharacter { position: 1 }));
}

#[test]
fn numbers_follow_section_6_exactly() {
    for valid in ["0", "-0", "1", "-1", "0.5", "1e5", "1E+5", "1e-5", "123.456e-789", "12345678901234567890123"] {
        assert_eq!(JSONNumber::new(valid).unwrap().as_str(), valid);
        assert_eq!(JSONValue::parse(valid).unwrap().as_number().unwrap().as_str(), valid);
    }
    for invalid in ["01", "+1", "1.", ".5", "1e", "1e+", "-", "0x10", "1.0.0", "Infinity", "NaN", "- 1"] {
        assert!(JSONNumber::new(invalid).is_err(), "{invalid}");
        assert!(JSONValue::parse(invalid).is_err(), "{invalid}");
    }
    let big = JSONNumber::new("12345678901234567890123").unwrap();
    assert_eq!(big.as_i64(), Err(JSONError::OutOfRange));
    assert_eq!(big.as_i128(), Ok(12345678901234567890123));
    assert_eq!(JSONNumber::new("-5").unwrap().as_u64(), Err(JSONError::OutOfRange));
    // -0 is the integer zero (RFC 8259 section 6 gives it no other meaning).
    assert_eq!(JSONNumber::new("-0").unwrap().as_u64(), Ok(0));
    assert_eq!(JSONNumber::new("-0").unwrap().as_i64(), Ok(0));
    assert_eq!(JSONNumber::new("1.0").unwrap().as_i64(), Err(JSONError::OutOfRange));
    assert_eq!(JSONNumber::new("18446744073709551615").unwrap().as_u64(), Ok(u64::MAX));
    assert_eq!(JSONNumber::new("0.1").unwrap().as_f64(), Some(0.1));
    assert_eq!(JSONNumber::new("1e400").unwrap().as_f64(), None);
    for value in [0.0, -0.0, 0.1, 1.0 / 3.0, 1e300, 5e-324, -123.5, f64::MAX] {
        let number = JSONNumber::from_f64(value).unwrap();
        assert_eq!(number.as_f64().unwrap().to_bits(), value.to_bits(), "{value}");
    }
    assert_eq!(JSONNumber::from_f64(1e300).unwrap().as_str(), "1e300");
    assert_eq!(JSONNumber::from_f64(0.5).unwrap().as_str(), "0.5");
    assert!(JSONNumber::from_f64(f64::NAN).is_none() && JSONNumber::from_f64(f64::INFINITY).is_none());
    assert_eq!(JSONNumber::from(-7i64).as_str(), "-7");
    assert!(JSONNumber::from(7u64).is_integer());
}

#[test]
fn structure_errors_carry_their_position() {
    assert_eq!(JSONValue::parse("[1,]"), Err(JSONError::UnexpectedCharacter { position: 3, character: b']' }));
    assert_eq!(JSONValue::parse("{\"a\" 1}"), Err(JSONError::UnexpectedCharacter { position: 5, character: b'1' }));
    assert_eq!(JSONValue::parse("[1"), Err(JSONError::UnexpectedEnd { position: 2 }));
    assert_eq!(JSONValue::parse("1 2"), Err(JSONError::TrailingData { position: 2 }));
    assert_eq!(JSONValue::parse("tru"), Err(JSONError::UnexpectedEnd { position: 3 }));
    assert_eq!(JSONValue::parse("trux"), Err(JSONError::UnexpectedCharacter { position: 3, character: b'x' }));
    assert_eq!(JSONValue::parse(""), Err(JSONError::UnexpectedEnd { position: 0 }));
    assert_eq!(JSONValue::parse(" \t\r\n "), Err(JSONError::UnexpectedEnd { position: 5 }));
    // Only space, tab, line feed and carriage return are white space.
    assert!(JSONValue::parse("\u{c}1").is_err());
    assert!(JSONValue::parse("\u{a0}1").is_err());
}

#[test]
fn limits_are_enforced() {
    let deep = "[".repeat(200) + &"]".repeat(200);
    assert!(matches!(JSONValue::parse(&deep), Err(JSONError::TooDeep { position: 128, maximum: 128 })));
    let config = JSONConfig { maximum_depth: 200, ..JSONConfig::default() };
    assert!(JSONValue::decode(deep.as_bytes(), config).is_ok());
    // The reader alone handles any depth without recursion.
    let very_deep = "[".repeat(100_000) + &"]".repeat(100_000);
    let config = JSONConfig { maximum_depth: usize::MAX, ..JSONConfig::default() };
    assert!(JSONReader::new(very_deep.as_bytes(), config).unwrap().validate().is_ok());
    let limited = JSONConfig { maximum_length: 3, ..JSONConfig::default() };
    assert_eq!(JSONValue::decode(b"1234", limited), Err(JSONError::TooLong { length: 4, maximum: 3 }));
    assert_eq!(
        JSONValue::decode(b"\xEF\xBB\xBF{}", JSONConfig::default()),
        Err(JSONError::UnexpectedCharacter { position: 0, character: 0xEF })
    );
    let bom = JSONConfig { allow_byte_order_mark: true, ..JSONConfig::default() };
    assert_eq!(JSONValue::decode(b"\xEF\xBB\xBF{}", bom), Ok(JSONValue::Object(JSONObject::new())));
}

#[test]
fn duplicate_keys_follow_the_policy() {
    let text = br#"{"a": 1, "b": 2, "a": 3, "c": 4, "a": 5}"#;
    assert_eq!(JSONValue::decode(text, JSONConfig::default()), Err(JSONError::DuplicateKey { position: 17 }));
    let decode =
        |policy| JSONValue::decode(text, JSONConfig { duplicate_keys: policy, ..JSONConfig::default() }).unwrap();
    assert_eq!(decode(DuplicateKeys::KeepFirst).encode(), r#"{"a":1,"b":2,"c":4}"#);
    assert_eq!(decode(DuplicateKeys::KeepLast).encode(), r#"{"b":2,"c":4,"a":5}"#);
    assert_eq!(decode(DuplicateKeys::KeepAll).encode(), r#"{"a":1,"b":2,"a":3,"c":4,"a":5}"#);
    // Keys are compared after escapes are replaced.
    assert!(matches!(JSONValue::parse(r#"{"a": 1, "\u0061": 2}"#), Err(JSONError::DuplicateKey { position: 9 })));
}

#[test]
fn values_can_be_built_and_queried() {
    let mut object = JSONObject::new();
    assert_eq!(object.insert(String::from("name"), JSONValue::from("umilib")), None);
    object.insert(
        String::from("list"),
        JSONValue::from(vec![JSONValue::from(1i64), JSONValue::Null, JSONValue::from(true)]),
    );
    assert_eq!(object.insert(String::from("name"), JSONValue::from("x")), Some(JSONValue::from("umilib")));
    let value = JSONValue::from(object.clone());
    assert_eq!(value.get("name").and_then(JSONValue::as_str), Some("x"));
    assert_eq!(value.get("list").and_then(|list| list.index(2)).and_then(JSONValue::as_bool), Some(true));
    assert!(value.get("list").unwrap().index(1).unwrap().is_null());
    assert_eq!(value.encode(), r#"{"name":"x","list":[1,null,true]}"#);
    assert_eq!(
        JSONEncoder::PRETTY.encode(&value),
        "{\n  \"name\": \"x\",\n  \"list\": [\n    1,\n    null,\n    true\n  ]\n}"
    );
    assert_eq!(JSONEncoder::PRETTY.encode(&JSONValue::Array(Vec::new())), "[]");
    let mut copy = object;
    assert_eq!(copy.remove("name"), Some(JSONValue::from("x")));
    assert_eq!(copy.len(), 1);
    assert!(copy.get("name").is_none());
}

#[test]
fn deep_trees_use_no_call_stack() {
    // Decoding, dropping, cloning, comparing and encoding walk the tree with
    // explicit stacks, so depths beyond the call stack work once allowed.
    let depth = 200_000;
    let text = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    let config = JSONConfig { maximum_depth: usize::MAX, ..JSONConfig::default() };
    let value = JSONValue::decode(text.as_bytes(), config).unwrap();
    let copy = value.clone();
    assert_eq!(copy, value);
    assert_eq!(JSONEncoder::COMPACT.encode(&value), text);
    let mut different =
        JSONValue::decode(format!("{}1{}", "[".repeat(depth), "]".repeat(depth)).as_bytes(), config).unwrap();
    assert_ne!(different, value);
    different =
        JSONValue::decode(format!("{}{{\"a\":null}}{}", "[".repeat(depth), "]".repeat(depth)).as_bytes(), config)
            .unwrap();
    assert!(format!("{different:?}").ends_with(&format!("{{\"a\":null}}{})", "]".repeat(depth))));
    drop(value);
    drop(copy);
    drop(different);
}

#[test]
fn pretty_output_indents_by_level() {
    let value = JSONValue::parse(r#"{"a":[1,{"b":true}],"c":{}}"#).unwrap();
    let wide = JSONEncoder { indent: Some(u8::MAX), ascii_only: false }.encode(&value);
    assert!(wide.contains(&format!("\n{}1", " ".repeat(2 * 255))));
    assert_eq!(
        JSONEncoder { indent: Some(1), ascii_only: false }.encode(&value),
        "{\n \"a\": [\n  1,\n  {\n   \"b\": true\n  }\n ],\n \"c\": {}\n}"
    );
    assert_eq!(
        JSONEncoder { indent: Some(0), ascii_only: false }.encode(&value),
        "{\n\"a\": [\n1,\n{\n\"b\": true\n}\n],\n\"c\": {}\n}"
    );
}
