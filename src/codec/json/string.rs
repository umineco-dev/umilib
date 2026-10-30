use alloc::string::String;

use super::JSONError;

/// A string of a JSON text, borrowed from the input with its escape
/// sequences, which [`JSONReader`](super::JSONReader) has already validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JSONString<'a> {
    raw: &'a str,
    escaped: bool,
}

impl<'a> JSONString<'a> {
    /// Validates the string that starts after the opening quote at `start` in
    /// `input`, and returns it with the position just after its closing quote.
    pub fn scan(input: &'a [u8], start: usize) -> Result<(JSONString<'a>, usize), JSONError> {
        let mut position = start;
        let mut escaped = false;
        loop {
            let Some(&byte) = input.get(position) else {
                return Err(JSONError::UnexpectedEnd { position });
            };
            match byte {
                b'"' => break,
                b'\\' => {
                    escaped = true;
                    position = JSONString::scan_escape(input, position)?;
                }
                0x00..=0x1F => return Err(JSONError::ControlCharacter { position }),
                _ => position += 1,
            }
        }
        let raw = core::str::from_utf8(&input[start..position])
            .map_err(|error| JSONError::InvalidUTF8 { position: start + error.valid_up_to() })?;
        Ok((JSONString { raw, escaped }, position + 1))
    }

    /// Validates the escape sequence starting with the backslash at `position`
    /// and returns the position after it. Surrogate escapes must form pairs.
    pub fn scan_escape(input: &[u8], position: usize) -> Result<usize, JSONError> {
        match input.get(position + 1) {
            None => Err(JSONError::UnexpectedEnd { position: position + 1 }),
            Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => Ok(position + 2),
            Some(b'u') => {
                let unit = JSONString::hexadecimal(input, position + 2)?;
                match unit {
                    0xD800..=0xDBFF => {
                        if input.get(position + 6) != Some(&b'\\') || input.get(position + 7) != Some(&b'u') {
                            return Err(JSONError::LoneSurrogate { position });
                        }
                        match JSONString::hexadecimal(input, position + 8)? {
                            0xDC00..=0xDFFF => Ok(position + 12),
                            _ => Err(JSONError::LoneSurrogate { position }),
                        }
                    }
                    0xDC00..=0xDFFF => Err(JSONError::LoneSurrogate { position }),
                    _ => Ok(position + 6),
                }
            }
            Some(_) => Err(JSONError::InvalidEscape { position }),
        }
    }

    /// The value of the four hexadecimal digits at `position`.
    pub fn hexadecimal(input: &[u8], position: usize) -> Result<u32, JSONError> {
        let digits = input.get(position..position + 4).ok_or(JSONError::UnexpectedEnd { position: input.len() })?;
        digits.iter().try_fold(0u32, |value, &digit| {
            let digit = (digit as char).to_digit(16).ok_or(JSONError::InvalidEscape { position: position - 2 })?;
            Ok(value << 4 | digit)
        })
    }

    /// The string as written, with its escape sequences.
    pub fn raw(&self) -> &'a str {
        self.raw
    }

    /// Whether the string contains escape sequences.
    pub fn is_escaped(&self) -> bool {
        self.escaped
    }

    /// The string without copying, if it has no escape sequences.
    pub fn as_str(&self) -> Option<&'a str> {
        if self.escaped { None } else { Some(self.raw) }
    }

    /// Appends the string, with escape sequences replaced, to `output`.
    pub fn write_to(&self, output: &mut String) -> Result<(), JSONError> {
        output.try_reserve(self.raw.len()).map_err(|_| JSONError::AllocationFailed)?;
        if !self.escaped {
            output.push_str(self.raw);
            return Ok(());
        }
        let bytes = self.raw.as_bytes();
        let mut position = 0;
        while position < bytes.len() {
            let start = position;
            while position < bytes.len() && bytes[position] != b'\\' {
                position += 1;
            }
            output.push_str(&self.raw[start..position]);
            if position == bytes.len() {
                break;
            }
            // The reader validated every escape sequence.
            let character = match bytes[position + 1] {
                b'b' => '\u{8}',
                b'f' => '\u{c}',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'u' => {
                    let unit = JSONString::hexadecimal(bytes, position + 2)?;
                    if (0xD800..=0xDBFF).contains(&unit) {
                        let low = JSONString::hexadecimal(bytes, position + 8)?;
                        position += 6;
                        char::from_u32(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00))
                            .ok_or(JSONError::LoneSurrogate { position })?
                    } else {
                        char::from_u32(unit).ok_or(JSONError::LoneSurrogate { position })?
                    }
                }
                other => other as char,
            };
            position += if bytes[position + 1] == b'u' { 6 } else { 2 };
            output.push(character);
        }
        Ok(())
    }

    /// The string with escape sequences replaced.
    pub fn decode(&self) -> Result<String, JSONError> {
        let mut output = String::new();
        self.write_to(&mut output)?;
        Ok(output)
    }
}
