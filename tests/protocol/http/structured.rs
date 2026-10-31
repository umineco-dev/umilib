//! Structured field values (RFC 9651) against the test suite of the HTTP
//! working group (tests/vectors/protocol/http/structured-field-tests): each
//! value parsed as its type, compared with the expected structure, and
//! serialized to its canonical form; the serialization tests serialized.

use umilib::protocol::http::{HTTPBareItem, HTTPItem, HTTPMember, HTTPParameters, HTTPStructuredField};

use crate::JSON;

const DIRECTORY: &str = "protocol/http/structured-field-tests";

/// The bytes of RFC 4648 base32 text, as the suite gives binary values.
fn base32(text: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u64;
    let mut count = 0;
    let mut out = Vec::new();
    for byte in text.bytes().filter(|byte| *byte != b'=') {
        bits = bits << 5 | alphabet.iter().position(|letter| *letter == byte).unwrap() as u64;
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    out
}

/// A JSON number's text as a bare item: an integer, or a decimal rounded as serialization does.
fn number(text: &str) -> Option<HTTPBareItem> {
    match text.split_once('.') {
        None => Some(HTTPBareItem::Integer(text.parse().ok()?)),
        Some((whole, fraction)) => {
            let negative = whole.starts_with('-');
            let digits: String = format!("{}{fraction}", whole.trim_start_matches('-'));
            let value: i128 = digits.parse().ok()?;
            HTTPBareItem::decimal(if negative { -value } else { value }, fraction.len() as u32)
        }
    }
}

/// The bare item of the suite's JSON; `None` for one the type cannot hold.
fn bare(json: &JSON) -> Option<HTTPBareItem> {
    Some(match json {
        JSON::Number(text) => number(text)?,
        JSON::String(text) => HTTPBareItem::String(text.clone()),
        JSON::Bool(value) => HTTPBareItem::Boolean(*value),
        JSON::Object(_) => {
            let value = json.field("value");
            match json.field("__type").as_str() {
                "token" => HTTPBareItem::Token(value.as_str().to_string()),
                "binary" => HTTPBareItem::ByteSequence(base32(value.as_str())),
                "date" => match value {
                    JSON::Number(text) => HTTPBareItem::Date(text.parse().ok()?),
                    _ => return None,
                },
                "displaystring" => HTTPBareItem::DisplayString(value.as_str().to_string()),
                other => panic!("type {other}"),
            }
        }
        other => panic!("bare item {other:?}"),
    })
}

fn parameters(json: &JSON) -> Option<HTTPParameters> {
    let mut parameters = HTTPParameters::default();
    for pair in json.items() {
        parameters.parameters.push((pair.items()[0].as_str().to_string(), bare(&pair.items()[1])?));
    }
    Some(parameters)
}

fn item(json: &JSON) -> Option<HTTPItem> {
    Some(HTTPItem { bare: bare(&json.items()[0])?, parameters: parameters(&json.items()[1])? })
}

/// A member: an inner list is `[[items], parameters]`, an item `[bare, parameters]`.
fn member(json: &JSON) -> Option<HTTPMember> {
    let parts = json.items();
    match &parts[0] {
        JSON::Array(items) => {
            let items = items.iter().map(item).collect::<Option<Vec<_>>>()?;
            Some(HTTPMember::InnerList(items, parameters(&parts[1])?))
        }
        _ => Some(HTTPMember::Item(item(json)?)),
    }
}

/// A parsed or expected value of a type.
#[derive(Debug, PartialEq)]
enum Value {
    Item(HTTPItem),
    List(Vec<HTTPMember>),
    Dictionary(Vec<(String, HTTPMember)>),
}

fn expected(kind: &str, json: &JSON) -> Option<Value> {
    Some(match kind {
        "item" => Value::Item(item(json)?),
        "list" => Value::List(json.items().iter().map(member).collect::<Option<Vec<_>>>()?),
        "dictionary" => Value::Dictionary(
            json.items()
                .iter()
                .map(|pair| Some((pair.items()[0].as_str().to_string(), member(&pair.items()[1])?)))
                .collect::<Option<Vec<_>>>()?,
        ),
        other => panic!("type {other}"),
    })
}

fn parse(kind: &str, input: &[u8]) -> Option<Value> {
    match kind {
        "item" => HTTPStructuredField::parse_item(input).ok().map(Value::Item),
        "list" => HTTPStructuredField::parse_list(input).ok().map(Value::List),
        _ => HTTPStructuredField::parse_dictionary(input).ok().map(Value::Dictionary),
    }
}

fn serialize(value: &Value) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match value {
        Value::Item(item) => HTTPStructuredField::serialize_item(item, &mut out).ok()?,
        Value::List(list) => HTTPStructuredField::serialize_list(list, &mut out).ok()?,
        Value::Dictionary(dictionary) => HTTPStructuredField::serialize_dictionary(dictionary, &mut out).ok()?,
    }
    Some(out)
}

fn files(directory: &str) -> Vec<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors").join(directory);
    let mut names: Vec<String> = std::fs::read_dir(&root)
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.ends_with(".json"))
        .map(|name| format!("{directory}/{name}"))
        .collect();
    names.sort();
    names
}

#[test]
fn parsing() {
    let mut count = 0;
    for path in files(DIRECTORY) {
        for test in JSON::read(&path).items() {
            let name = format!("{path}: {}", test.field("name").as_str());
            let kind = test.field("header_type").as_str();
            let lines: Vec<&str> = test.field("raw").items().iter().map(JSON::as_str).collect();
            // The lines of a field combine into one value (RFC 9651 §4.2).
            let input = lines.join(", ");
            let must_fail = test.get("must_fail") == Some(&JSON::Bool(true));
            let can_fail = test.get("can_fail") == Some(&JSON::Bool(true));
            let parsed = parse(kind, input.as_bytes());
            count += 1;
            if must_fail {
                assert!(parsed.is_none(), "{name}: parsed {parsed:?}");
                continue;
            }
            let Some(parsed) = parsed else {
                assert!(can_fail, "{name}: failed");
                continue;
            };
            let expected = expected(kind, test.field("expected")).unwrap_or_else(|| panic!("{name}: expected"));
            assert_eq!(parsed, expected, "{name}");
            let canonical = match test.get("canonical") {
                Some(canonical) => canonical.items().iter().map(JSON::as_str).collect::<Vec<_>>().join(", "),
                None => input.clone(),
            };
            assert_eq!(serialize(&parsed).map(String::from_utf8), Some(Ok(canonical)), "{name}: serialized");
        }
    }
    assert!(count > 1000, "{count} tests");
}

#[test]
fn serialization() {
    let mut count = 0;
    for path in files(&format!("{DIRECTORY}/serialisation-tests")) {
        for test in JSON::read(&path).items() {
            let name = format!("{path}: {}", test.field("name").as_str());
            let kind = test.field("header_type").as_str();
            let must_fail = test.get("must_fail") == Some(&JSON::Bool(true));
            count += 1;
            let serialized = expected(kind, test.field("expected")).and_then(|value| serialize(&value));
            if must_fail {
                assert!(serialized.is_none(), "{name}: serialized {serialized:?}");
                continue;
            }
            let canonical = test.field("canonical").items().iter().map(JSON::as_str).collect::<Vec<_>>().join(", ");
            assert_eq!(serialized.map(String::from_utf8), Some(Ok(canonical)), "{name}");
        }
    }
    assert!(count > 100, "{count} tests");
}
