use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use super::{JSONString, JSONValue};

/// How [`JSONValue`]s are written as text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JSONEncoder {
    /// Spaces per level for pretty output; `None` writes everything on one line without spaces.
    pub indent: Option<u8>,
    /// Whether characters outside ASCII are written as `\u` escapes (with
    /// surrogate pairs above U+FFFF); otherwise they are written as UTF-8.
    pub ascii_only: bool,
}

impl JSONEncoder {
    /// One line, no spaces, UTF-8.
    pub const COMPACT: JSONEncoder = JSONEncoder { indent: None, ascii_only: false };
    /// Two spaces per level.
    pub const PRETTY: JSONEncoder = JSONEncoder { indent: Some(2), ascii_only: false };

    /// Writes `value` as text.
    pub fn encode(&self, value: &JSONValue) -> String {
        let mut output = String::new();
        self.encode_to(value, &mut output);
        output
    }

    /// Appends `value` as text to `output`.
    pub fn encode_to(&self, value: &JSONValue, output: &mut String) {
        self.write_value(value, 0, output);
    }

    /// Appends `text` as a JSON string literal: quotes, backslashes and control
    /// characters are escaped (RFC 8259 section 7).
    pub fn write_string(&self, text: &str, output: &mut String) {
        output.push('"');
        for character in text.chars() {
            match character {
                '"' => output.push_str("\\\""),
                '\\' => output.push_str("\\\\"),
                '\n' => output.push_str("\\n"),
                '\r' => output.push_str("\\r"),
                '\t' => output.push_str("\\t"),
                '\u{8}' => output.push_str("\\b"),
                '\u{c}' => output.push_str("\\f"),
                character if (character as u32) < 0x20 || (self.ascii_only && !character.is_ascii()) => {
                    let mut units = [0u16; 2];
                    for unit in character.encode_utf16(&mut units) {
                        let _ = write!(output, "\\u{unit:04x}");
                    }
                }
                character => output.push(character),
            }
        }
        output.push('"');
    }

    /// Appends a line break and the indentation of `depth`, in pretty output.
    pub fn write_newline(&self, depth: usize, output: &mut String) {
        if let Some(indent) = self.indent {
            output.push('\n');
            for _ in 0..depth {
                for _ in 0..indent {
                    output.push(' ');
                }
            }
        }
    }

    /// Appends `value`, nested `depth` levels deep. Nested values are written
    /// with an explicit stack, so trees of any depth are handled.
    pub fn write_value(&self, value: &JSONValue, depth: usize, output: &mut String) {
        // Each open container and the index of its next child.
        let mut open: Vec<(&JSONValue, usize)> = Vec::new();
        let mut next = Some(value);
        loop {
            if let Some(value) = next.take() {
                match value {
                    JSONValue::Null => output.push_str("null"),
                    JSONValue::Bool(true) => output.push_str("true"),
                    JSONValue::Bool(false) => output.push_str("false"),
                    JSONValue::Number(number) => output.push_str(number.as_str()),
                    JSONValue::String(text) => self.write_string(text, output),
                    JSONValue::Array(_) => {
                        output.push('[');
                        open.push((value, 0));
                    }
                    JSONValue::Object(_) => {
                        output.push('{');
                        open.push((value, 0));
                    }
                }
            }
            let level = depth + open.len();
            let Some((container, index)) = open.last_mut() else {
                return;
            };
            let (length, close) = match container {
                JSONValue::Array(values) => (values.len(), ']'),
                JSONValue::Object(object) => (object.len(), '}'),
                _ => (0, ' '),
            };
            if *index == length {
                open.pop();
                if length > 0 {
                    self.write_newline(level - 1, output);
                }
                output.push(close);
                continue;
            }
            if *index > 0 {
                output.push(',');
            }
            self.write_newline(level, output);
            next = match container {
                JSONValue::Array(values) => values.get(*index),
                JSONValue::Object(object) => object.members.get(*index).map(|(key, value)| {
                    self.write_string(key, output);
                    output.push(':');
                    if self.indent.is_some() {
                        output.push(' ');
                    }
                    value
                }),
                _ => None,
            };
            *index += 1;
        }
    }

    /// Appends a borrowed [`JSONString`] as a literal, without decoding it
    /// first when it needs no change.
    pub fn write_json_string(&self, string: &JSONString<'_>, output: &mut String) -> Result<(), super::JSONError> {
        if !self.ascii_only
            && let Some(text) = string.as_str()
            && text.bytes().all(|byte| byte >= 0x20 && byte != b'"' && byte != b'\\')
        {
            output.push('"');
            output.push_str(text);
            output.push('"');
            return Ok(());
        }
        self.write_string(&string.decode()?, output);
        Ok(())
    }
}
