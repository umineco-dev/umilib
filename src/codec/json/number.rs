use alloc::string::{String, ToString};

use super::JSONError;

/// A JSON number, kept exactly as written so that no precision is lost.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct JSONNumber {
    text: String,
}

impl JSONNumber {
    /// Returns the length of the number that starts at `start` in `input`
    /// (RFC 8259 section 6: `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`).
    pub fn scan(input: &[u8], start: usize) -> Result<usize, JSONError> {
        let digits = |mut position: usize| {
            while input.get(position).is_some_and(u8::is_ascii_digit) {
                position += 1;
            }
            position
        };
        let invalid = JSONError::InvalidNumber { position: start };
        let mut position = start;
        if input.get(position) == Some(&b'-') {
            position += 1;
        }
        match input.get(position) {
            Some(b'0') => position += 1,
            Some(b'1'..=b'9') => position = digits(position + 1),
            _ => return Err(invalid),
        }
        if input.get(position) == Some(&b'.') {
            let end = digits(position + 1);
            if end == position + 1 {
                return Err(invalid);
            }
            position = end;
        }
        if matches!(input.get(position), Some(b'e' | b'E')) {
            position += 1;
            if matches!(input.get(position), Some(b'+' | b'-')) {
                position += 1;
            }
            let end = digits(position);
            if end == position {
                return Err(invalid);
            }
            position = end;
        }
        Ok(position - start)
    }

    /// Creates a number from its text, which must follow the JSON grammar exactly.
    pub fn new(text: &str) -> Result<JSONNumber, JSONError> {
        if JSONNumber::scan(text.as_bytes(), 0)? != text.len() {
            return Err(JSONError::InvalidNumber { position: 0 });
        }
        Ok(JSONNumber { text: String::from(text) })
    }

    /// Creates a number from a finite `f64`, written as the shortest text that
    /// reads back as the same value; `None` for NaN and infinities, which JSON
    /// cannot represent.
    pub fn from_f64(value: f64) -> Option<JSONNumber> {
        if !value.is_finite() {
            return None;
        }
        // Both forms are the shortest digits that read back as `value`; keep the
        // shorter text (`1e300` rather than 301 digits, `0.5` rather than `5e-1`).
        let plain = value.to_string();
        let exponent = alloc::format!("{value:e}");
        let text = if exponent.len() < plain.len() { exponent } else { plain };
        JSONNumber::new(&text).ok()
    }

    /// The number as written.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether the number is written without fraction or exponent.
    pub fn is_integer(&self) -> bool {
        !self.text.contains(['.', 'e', 'E'])
    }

    /// The nearest `f64`; `None` if the number is too large for `f64`.
    pub fn as_f64(&self) -> Option<f64> {
        self.text.parse::<f64>().ok().filter(|value| value.is_finite())
    }

    /// The number as an `i64`, if it is an integer in range.
    pub fn as_i64(&self) -> Result<i64, JSONError> {
        if !self.is_integer() {
            return Err(JSONError::OutOfRange);
        }
        self.text.parse().map_err(|_| JSONError::OutOfRange)
    }

    /// The number as a `u64`, if it is a non-negative integer in range;
    /// `-0` is zero, as it is for [`JSONNumber::as_i64`].
    pub fn as_u64(&self) -> Result<u64, JSONError> {
        if !self.is_integer() {
            return Err(JSONError::OutOfRange);
        }
        self.text
            .strip_prefix("-")
            .filter(|digits| *digits == "0")
            .unwrap_or(&self.text)
            .parse()
            .map_err(|_| JSONError::OutOfRange)
    }

    /// The number as an `i128`, if it is an integer in range.
    pub fn as_i128(&self) -> Result<i128, JSONError> {
        if !self.is_integer() {
            return Err(JSONError::OutOfRange);
        }
        self.text.parse().map_err(|_| JSONError::OutOfRange)
    }
}

impl From<i64> for JSONNumber {
    fn from(value: i64) -> JSONNumber {
        JSONNumber { text: value.to_string() }
    }
}

impl From<u64> for JSONNumber {
    fn from(value: u64) -> JSONNumber {
        JSONNumber { text: value.to_string() }
    }
}

impl From<i128> for JSONNumber {
    fn from(value: i128) -> JSONNumber {
        JSONNumber { text: value.to_string() }
    }
}
