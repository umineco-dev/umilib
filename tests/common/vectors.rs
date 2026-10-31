//! Access to the test vectors in `tests/vectors`, shared by the test crates
//! through `#[path]`.

use std::collections::BTreeMap;

/// The files of `tests/vectors`.
pub struct Vectors;

impl Vectors {
    pub fn read(path: &str) -> String {
        let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors").join(path);
        std::fs::read_to_string(&full).unwrap_or_else(|error| panic!("{}: {error}", full.display()))
    }

    /// The bytes of a binary file.
    // Used by the tests of some crates only.
    #[allow(dead_code)]
    pub fn bytes(path: &str) -> Vec<u8> {
        let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors").join(path);
        std::fs::read(&full).unwrap_or_else(|error| panic!("{}: {error}", full.display()))
    }

    /// The bytes of hexadecimal `text`, ignoring whitespace.
    pub fn hex(text: &str) -> Vec<u8> {
        let text: String = text.chars().filter(|character| !character.is_whitespace()).collect();
        assert!(text.len().is_multiple_of(2), "odd hexadecimal length: {text}");
        (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
    }
}

/// One record of a NIST CAVP response file: its fields in order and the
/// bracketed header lines (such as `[L = 32]`) in force for it. A field may
/// repeat, as `AdditionalInput` does in the DRBG files.
#[derive(Clone, Debug, Default)]
pub struct Record {
    pub header: BTreeMap<String, String>,
    pub fields: Vec<(String, String)>,
}

#[allow(dead_code)]
impl Record {
    /// The records of the CAVP response file `path`: `Key = Value` lines (or
    /// a bare `Key`), separated by blank lines, under `[Key = Value]` or
    /// `[Name]` headers.
    pub fn all(path: &str) -> Vec<Record> {
        let mut records = Vec::new();
        let mut header = BTreeMap::new();
        let mut header_fresh = false;
        let mut current = Record::default();
        for line in Vectors::read(path).lines().map(str::trim) {
            if line.starts_with('#') {
                continue;
            }
            if line.is_empty() {
                if !current.fields.is_empty() {
                    records.push(std::mem::take(&mut current));
                }
                continue;
            }
            if let Some(inner) = line.strip_prefix('[').and_then(|line| line.strip_suffix(']')) {
                if !header_fresh {
                    header = BTreeMap::new();
                    header_fresh = true;
                }
                match inner.split_once('=') {
                    Some((key, value)) => header.insert(key.trim().to_string(), value.trim().to_string()),
                    None => header.insert(inner.trim().to_string(), String::new()),
                };
                continue;
            }
            header_fresh = false;
            // A line without "=" is a field without value, such as "FAIL".
            let (key, value) = line.split_once('=').unwrap_or((line, ""));
            current.header = header.clone();
            current.fields.push((key.trim().to_string(), value.trim().to_string()));
        }
        if !current.fields.is_empty() {
            records.push(current);
        }
        records
    }

    /// The first value of `key`, if any.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.iter().find(|field| field.0 == key).map(|field| field.1.as_str())
    }

    /// The first value of `key`.
    pub fn field(&self, key: &str) -> &str {
        self.get(key).unwrap_or_else(|| panic!("no field {key} in {self:?}"))
    }

    /// Every value of `key`, in order.
    pub fn values(&self, key: &str) -> Vec<&str> {
        self.fields.iter().filter(|field| field.0 == key).map(|field| field.1.as_str()).collect()
    }

    pub fn bytes(&self, key: &str) -> Vec<u8> {
        Vectors::hex(self.field(key))
    }

    /// The message of a hash record: `Len` bits of `Msg` (`Msg = 00` for the empty message).
    pub fn message(&self) -> Vec<u8> {
        let bits: usize = self.field("Len").parse().unwrap();
        assert_eq!(bits % 8, 0, "byte-oriented vectors only");
        let mut message = self.bytes("Msg");
        message.truncate(bits / 8);
        message
    }
}

/// A JSON value, parsed by the tests themselves so that they do not depend
/// on the JSON codec of the library under test.
// Not every test crate reads JSON.
#[allow(dead_code, clippy::upper_case_acronyms)]
#[derive(Clone, Debug, PartialEq)]
pub enum JSON {
    Null,
    Bool(bool),
    /// A number as written.
    Number(String),
    String(String),
    Array(Vec<JSON>),
    Object(Vec<(String, JSON)>),
}

#[allow(dead_code)]
impl JSON {
    /// The value of the file `path` of `tests/vectors`.
    pub fn read(path: &str) -> JSON {
        JSON::from_text(&Vectors::read(path))
    }

    /// The value of the JSON text `text`.
    pub fn from_text(text: &str) -> JSON {
        let mut position = 0;
        JSON::parse(text.as_bytes(), &mut position)
    }

    fn skip(bytes: &[u8], position: &mut usize) {
        while *position < bytes.len() && bytes[*position].is_ascii_whitespace() {
            *position += 1;
        }
    }

    fn parse(bytes: &[u8], position: &mut usize) -> JSON {
        JSON::skip(bytes, position);
        match bytes[*position] {
            b'{' => {
                *position += 1;
                let mut members = Vec::new();
                loop {
                    JSON::skip(bytes, position);
                    if bytes[*position] == b'}' {
                        *position += 1;
                        return JSON::Object(members);
                    }
                    let JSON::String(key) = JSON::parse(bytes, position) else { panic!("an object key is a string") };
                    JSON::skip(bytes, position);
                    assert_eq!(bytes[*position], b':');
                    *position += 1;
                    members.push((key, JSON::parse(bytes, position)));
                    JSON::skip(bytes, position);
                    if bytes[*position] == b',' {
                        *position += 1;
                    }
                }
            }
            b'[' => {
                *position += 1;
                let mut items = Vec::new();
                loop {
                    JSON::skip(bytes, position);
                    if bytes[*position] == b']' {
                        *position += 1;
                        return JSON::Array(items);
                    }
                    items.push(JSON::parse(bytes, position));
                    JSON::skip(bytes, position);
                    if bytes[*position] == b',' {
                        *position += 1;
                    }
                }
            }
            b'"' => {
                *position += 1;
                let mut text = String::new();
                while bytes[*position] != b'"' {
                    if bytes[*position] == b'\\' {
                        *position += 1;
                        match bytes[*position] {
                            b'n' => text.push('\n'),
                            b't' => text.push('\t'),
                            b'r' => text.push('\r'),
                            b'b' => text.push('\u{8}'),
                            b'f' => text.push('\u{c}'),
                            b'u' => {
                                let code = u32::from_str_radix(
                                    std::str::from_utf8(&bytes[*position + 1..*position + 5]).unwrap(),
                                    16,
                                )
                                .unwrap();
                                text.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                                *position += 4;
                            }
                            other => text.push(other as char),
                        }
                        *position += 1;
                        continue;
                    }
                    let start = *position;
                    while bytes[*position] != b'"' && bytes[*position] != b'\\' {
                        *position += 1;
                    }
                    text.push_str(std::str::from_utf8(&bytes[start..*position]).unwrap());
                }
                *position += 1;
                JSON::String(text)
            }
            b't' => {
                *position += 4;
                JSON::Bool(true)
            }
            b'f' => {
                *position += 5;
                JSON::Bool(false)
            }
            b'n' => {
                *position += 4;
                JSON::Null
            }
            _ => {
                let start = *position;
                while *position < bytes.len()
                    && matches!(bytes[*position], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                {
                    *position += 1;
                }
                JSON::Number(std::str::from_utf8(&bytes[start..*position]).unwrap().to_string())
            }
        }
    }

    /// The member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&JSON> {
        match self {
            JSON::Object(members) => members.iter().find(|member| member.0 == key).map(|member| &member.1),
            _ => None,
        }
    }

    /// The member `key`, which must exist.
    pub fn field(&self, key: &str) -> &JSON {
        self.get(key).unwrap_or_else(|| panic!("no member {key}"))
    }

    pub fn as_str(&self) -> &str {
        match self {
            JSON::String(text) => text,
            other => panic!("{other:?} is not a string"),
        }
    }

    pub fn as_usize(&self) -> usize {
        match self {
            JSON::Number(number) => number.parse().unwrap(),
            other => panic!("{other:?} is not a number"),
        }
    }

    pub fn items(&self) -> &[JSON] {
        match self {
            JSON::Array(items) => items,
            other => panic!("{other:?} is not an array"),
        }
    }

    /// The bytes of the hexadecimal string member `key`.
    pub fn bytes(&self, key: &str) -> Vec<u8> {
        Vectors::hex(self.field(key).as_str())
    }

    /// The JSON text of the value, without white space, members in order.
    pub fn encode(&self) -> String {
        match self {
            JSON::Null => String::from("null"),
            JSON::Bool(value) => value.to_string(),
            JSON::Number(number) => number.clone(),
            JSON::String(text) => {
                let mut out = String::from("\"");
                for character in text.chars() {
                    match character {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        control if (control as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", control as u32)),
                        other => out.push(other),
                    }
                }
                out.push('"');
                out
            }
            JSON::Array(items) => format!("[{}]", items.iter().map(JSON::encode).collect::<Vec<_>>().join(",")),
            JSON::Object(members) => format!(
                "{{{}}}",
                members
                    .iter()
                    .map(|(key, value)| format!("{}:{}", JSON::String(key.clone()).encode(), value.encode()))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
}

/// The tests of a Project Wycheproof file: each with its group.
#[allow(dead_code)]
pub struct Wycheproof;

#[allow(dead_code)]
impl Wycheproof {
    /// Every test of the file `path`, with the group it belongs to.
    pub fn tests(path: &str) -> Vec<(JSON, JSON)> {
        let document = JSON::read(path);
        let mut tests = Vec::new();
        for group in document.field("testGroups").items() {
            for test in group.field("tests").items() {
                tests.push((group.clone(), test.clone()));
            }
        }
        tests
    }

    /// Whether the test's result is "valid" ("acceptable" tests are neither valid nor invalid).
    pub fn valid(test: &JSON) -> bool {
        test.field("result").as_str() == "valid"
    }
}

/// The test vectors of the NESSIE project: "Set n, vector# m:" followed by
/// `name=value` lines (such as `key`, `plain`, `cipher` and
/// `Iterated 100 times`).
pub struct Nessie;

#[allow(dead_code)]
impl Nessie {
    /// The vectors of `path`, each with its label and its fields.
    pub fn vectors(path: &str) -> Vec<(String, BTreeMap<String, String>)> {
        let mut vectors: Vec<(String, BTreeMap<String, String>)> = Vec::new();
        for line in Vectors::read(path).lines().map(str::trim) {
            if line.starts_with("Set ") && line.ends_with(':') {
                vectors.push((line.trim_end_matches(':').to_string(), BTreeMap::new()));
            } else if let (Some((name, value)), Some(vector)) = (line.split_once('='), vectors.last_mut()) {
                vector.1.insert(name.trim().to_string(), value.trim().to_string());
            }
        }
        vectors
    }
}

/// Frames captured from a network: `# ` lines that describe a frame (the
/// summary of tcpdump) followed by a line of its bytes in hexadecimal.
pub struct Capture;

#[allow(dead_code)]
impl Capture {
    /// The frames of `path`, each with its description.
    pub fn frames(path: &str) -> Vec<(String, Vec<u8>)> {
        let mut frames = Vec::new();
        let mut description = String::new();
        for line in Vectors::read(path).lines() {
            if let Some(comment) = line.strip_prefix("# ") {
                description.push_str(comment);
                description.push('\n');
            } else if !line.trim().is_empty() {
                frames.push((std::mem::take(&mut description), Vectors::hex(line)));
            }
        }
        frames
    }
}

/// The values of the RFCs in `tests/vectors`.
#[allow(dead_code, clippy::upper_case_acronyms)]
pub struct RFC;

#[allow(dead_code)]
impl RFC {
    /// Whether `line` is part of a page break of an RFC text: a footer, a
    /// header or a form feed.
    pub fn is_page_break(line: &str) -> bool {
        let line = line.trim();
        line.contains('\u{c}')
            || line.ends_with(']') && line.contains("[Page ")
            || line.starts_with("RFC ")
                && line.split_whitespace().nth(1).is_some_and(|number| number.chars().all(|c| c.is_ascii_digit()))
    }

    /// The lines from the first one whose text starts with `prefix` to the
    /// next blank line: trimmed, page breaks left out, joined without
    /// separators (see [`RFC::block`]).
    pub fn block_from(path: &str, prefix: &str) -> String {
        let text = Vectors::read(path);
        let lines = text.lines().skip_while(|line| !line.trim_start().starts_with(prefix));
        let mut out = String::new();
        for line in lines.filter(|line| !RFC::is_page_break(line)) {
            if line.trim().is_empty() {
                break;
            }
            out.push_str(line.trim());
        }
        assert!(!out.is_empty(), "{path}: no line starting with {prefix}");
        out
    }

    /// The text of the lines from the first non-blank line after the line
    /// containing `marker` to the next blank line, or, with `end`, to the
    /// line containing `end` (blank lines included): trimmed, page breaks
    /// left out, joined without separators. RFCs fold long values and
    /// JSON this way.
    pub fn block(path: &str, marker: &str, end: Option<&str>) -> String {
        let text = Vectors::read(path);
        let mut lines = text.lines().skip_while(|line| !line.contains(marker)).skip(1);
        let mut out = String::new();
        let mut started = false;
        for line in lines.by_ref() {
            if RFC::is_page_break(line) {
                continue;
            }
            if let Some(end) = end
                && line.contains(end)
            {
                break;
            }
            if line.trim().is_empty() {
                if started && end.is_none() {
                    break;
                }
                continue;
            }
            started = true;
            out.push_str(line.trim());
        }
        assert!(!out.is_empty(), "{path}: nothing after {marker}");
        out
    }

    /// The text of `path` from the line starting with `start` to the next
    /// line starting with `end`.
    pub fn section(path: &str, start: &str, end: &str) -> String {
        let text = Vectors::read(path);
        let mut lines = text.lines().skip_while(|line| !line.starts_with(start));
        let first = lines.next().unwrap_or_else(|| panic!("{path}: no section {start}"));
        let rest = lines.take_while(|line| !line.starts_with(end));
        core::iter::once(first).chain(rest).collect::<Vec<_>>().join("\n")
    }

    /// The hexadecimal values that follow each line whose text is `label`,
    /// on the following lines up to the first line that is not hexadecimal.
    pub fn values(text: &str, label: &str) -> Vec<String> {
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        let is_hex = |line: &str| !line.is_empty() && line.chars().all(|character| character.is_ascii_hexdigit());
        let mut values = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            if *line != label {
                continue;
            }
            let following = lines[index + 1..].iter().skip_while(|line| line.is_empty());
            values.push(following.take_while(|line| is_hex(line)).copied().collect::<String>());
        }
        values
    }

    /// The single value after `label`.
    /// The single value after `label`, on the following lines or after it
    /// on its own line ("dA =" then the value, or "dA = value").
    pub fn value(text: &str, label: &str) -> String {
        let mut values = RFC::values(text, label);
        values.extend(RFC::values_after(text, &format!("{label} ")));
        assert_eq!(values.len(), 1, "{label}");
        values[0].clone()
    }

    /// The values written on the same line after `prefix` ("k = ...").
    /// A value continues on the following lines that are hexadecimal alone.
    pub fn values_after(text: &str, prefix: &str) -> Vec<String> {
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        let is_hex = |line: &&&str| !line.is_empty() && line.chars().all(|character| character.is_ascii_hexdigit());
        let mut values = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            if let Some(first) = line.strip_prefix(prefix) {
                let rest = lines[index + 1..].iter().take_while(is_hex).copied();
                values.push(core::iter::once(first).chain(rest).collect::<String>());
            }
        }
        values
    }

    pub fn value_after(text: &str, prefix: &str) -> String {
        let values = RFC::values_after(text, prefix);
        assert_eq!(values.len(), 1, "{prefix}");
        values[0].clone()
    }
}

/// The examples of the GM/T standards in `tests/vectors`, whose values are
/// located by the English text before them, since the text layer of the
/// documents loses the symbols ("?" in the extractions).
#[allow(dead_code, clippy::upper_case_acronyms)]
pub struct GMT {
    text: String,
}

#[allow(dead_code)]
impl GMT {
    /// The text of `path` without its page breaks: the "=== page" marker of
    /// the extraction and the page number on the line after it.
    pub fn read(path: &str) -> GMT {
        let text = Vectors::read(path);
        let mut kept = Vec::new();
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            if line.starts_with("=== page") {
                lines.next();
                continue;
            }
            kept.push(line);
        }
        GMT { text: kept.join("\n") }
    }

    /// The part of the text from `start` to `end`, both texts that occur in it.
    pub fn section(&self, start: &str, end: &str) -> GMT {
        let from = self.text.find(start).unwrap_or_else(|| panic!("no {start}"));
        let to = from + self.text[from..].find(end).unwrap_or_else(|| panic!("no {end}"));
        GMT { text: self.text[from..to].to_string() }
    }

    /// The part of the text from `start` to its end.
    pub fn after(&self, start: &str) -> GMT {
        let from = self.text.find(start).unwrap_or_else(|| panic!("no {start}"));
        GMT { text: self.text[from..].to_string() }
    }

    /// The `count` values after the first `label`: runs of hexadecimal
    /// words, a value ending at a comma, a closing parenthesis, a word that
    /// is not hexadecimal or the end of the text.
    pub fn values(&self, label: &str, count: usize) -> Vec<Vec<u8>> {
        let start = self.text.find(label).unwrap_or_else(|| panic!("no {label}")) + label.len();
        let mut values = Vec::new();
        let mut current = String::new();
        // "." after the last word ends the value the text ends with.
        for token in self.text[start..].split_whitespace().chain(["."]) {
            let word = token.trim_start_matches('(').trim_end_matches([',', ')']);
            let hexadecimal = !word.is_empty() && word.chars().all(|character| character.is_ascii_hexdigit());
            if hexadecimal {
                current.push_str(word);
            }
            if (!hexadecimal || token.ends_with([',', ')'])) && !current.is_empty() {
                let padded = if current.len() % 2 == 1 { format!("0{current}") } else { current.clone() };
                values.push(Vectors::hex(&padded));
                current.clear();
                if values.len() == count {
                    return values;
                }
            }
        }
        panic!("{label}: {} of {count} values", values.len());
    }

    pub fn value(&self, label: &str) -> Vec<u8> {
        self.values(label, 1).remove(0)
    }

    /// The value after `label` with zeros before it up to `length` bytes, as
    /// the examples print integers without their leading zeros.
    pub fn padded(&self, label: &str, length: usize) -> Vec<u8> {
        let value = self.value(label);
        assert!(value.len() <= length, "{label}: {} bytes", value.len());
        let mut padded = vec![0u8; length - value.len()];
        padded.extend(value);
        padded
    }
}
