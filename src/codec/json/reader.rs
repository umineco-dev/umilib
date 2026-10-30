use alloc::vec::Vec;

use super::{JSONConfig, JSONError, JSONEvent, JSONNumber, JSONString};

/// The kind of an open array or object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JSONContainer {
    Array,
    Object,
}

/// What the reader expects next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JSONState {
    /// Any value: at the start, after a colon or after a comma in an array.
    Value,
    /// A value or the end of an array, just after `[`.
    ArrayStart,
    /// A key or the end of an object, just after `{`.
    ObjectStart,
    /// A key, after a comma in an object.
    Key,
    /// The colon after a key.
    Colon,
    /// A comma or the end of the current container, or the end of the input.
    AfterValue,
    /// The value is complete.
    Done,
}

/// A pull parser that yields the [`JSONEvent`]s of a JSON text.
///
/// It keeps an explicit stack of open containers instead of recursing, so
/// any nesting allowed by [`JSONConfig::maximum_depth`] is safe. Events
/// borrow the input; nothing else is allocated besides the stack.
#[derive(Clone, Debug)]
pub struct JSONReader<'a> {
    input: &'a [u8],
    position: usize,
    stack: Vec<JSONContainer>,
    state: JSONState,
    config: JSONConfig,
}

impl<'a> JSONReader<'a> {
    /// The UTF-8 byte order mark.
    pub const BYTE_ORDER_MARK: [u8; 3] = [0xEF, 0xBB, 0xBF];

    /// Creates a reader over `input` with the limits of `config`.
    pub fn new(input: &'a [u8], config: JSONConfig) -> Result<JSONReader<'a>, JSONError> {
        if input.len() > config.maximum_length {
            return Err(JSONError::TooLong { length: input.len(), maximum: config.maximum_length });
        }
        let position =
            if config.allow_byte_order_mark && input.starts_with(&JSONReader::BYTE_ORDER_MARK) { 3 } else { 0 };
        Ok(JSONReader { input, position, stack: Vec::new(), state: JSONState::Value, config })
    }

    /// The byte offset of the next unread byte.
    pub fn position(&self) -> usize {
        self.position
    }

    /// The number of open arrays and objects.
    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    /// Whether `byte` is JSON white space (RFC 8259 section 2).
    pub fn is_whitespace(byte: u8) -> bool {
        matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
    }

    /// Skips white space and returns the next byte, if any.
    pub fn peek(&mut self) -> Option<u8> {
        while let Some(&byte) = self.input.get(self.position) {
            if !JSONReader::is_whitespace(byte) {
                return Some(byte);
            }
            self.position += 1;
        }
        None
    }

    /// Opens a container, checking the depth limit.
    pub fn open(&mut self, container: JSONContainer) -> Result<(), JSONError> {
        if self.stack.len() >= self.config.maximum_depth {
            return Err(JSONError::TooDeep { position: self.position, maximum: self.config.maximum_depth });
        }
        self.stack.try_reserve(1).map_err(|_| JSONError::AllocationFailed)?;
        self.stack.push(container);
        self.position += 1;
        self.state = match container {
            JSONContainer::Array => JSONState::ArrayStart,
            JSONContainer::Object => JSONState::ObjectStart,
        };
        Ok(())
    }

    /// Closes the current container if it is `container`.
    pub fn close(&mut self, container: JSONContainer, character: u8) -> Result<(), JSONError> {
        if self.stack.last() != Some(&container) {
            return Err(JSONError::UnexpectedCharacter { position: self.position, character });
        }
        self.stack.pop();
        self.position += 1;
        self.state = if self.stack.is_empty() { JSONState::Done } else { JSONState::AfterValue };
        Ok(())
    }

    /// Reads a scalar or opens a container at the current position.
    pub fn value(&mut self) -> Result<JSONEvent<'a>, JSONError> {
        let position = self.position;
        let Some(byte) = self.peek() else {
            return Err(JSONError::UnexpectedEnd { position: self.input.len() });
        };
        let after = if self.stack.is_empty() { JSONState::Done } else { JSONState::AfterValue };
        let literal = |reader: &mut JSONReader<'a>, text: &[u8], event: JSONEvent<'a>| {
            if reader.input[reader.position..].starts_with(text) {
                reader.position += text.len();
                reader.state = after;
                Ok(event)
            } else {
                let end = reader.input.len().min(reader.position + text.len());
                let mismatch =
                    (reader.position..end).find(|&index| reader.input[index] != text[index - reader.position]);
                match mismatch {
                    Some(index) => {
                        Err(JSONError::UnexpectedCharacter { position: index, character: reader.input[index] })
                    }
                    None => Err(JSONError::UnexpectedEnd { position: reader.input.len() }),
                }
            }
        };
        match byte {
            b'{' => self.open(JSONContainer::Object).map(|()| JSONEvent::BeginObject),
            b'[' => self.open(JSONContainer::Array).map(|()| JSONEvent::BeginArray),
            b'"' => {
                let (string, end) = JSONString::scan(self.input, self.position + 1)?;
                self.position = end;
                self.state = after;
                Ok(JSONEvent::String(string))
            }
            b't' => literal(self, b"true", JSONEvent::Bool(true)),
            b'f' => literal(self, b"false", JSONEvent::Bool(false)),
            b'n' => literal(self, b"null", JSONEvent::Null),
            b'-' | b'0'..=b'9' => {
                let length = JSONNumber::scan(self.input, self.position)?;
                // The number was validated as ASCII digits and signs.
                let text = core::str::from_utf8(&self.input[self.position..self.position + length])
                    .map_err(|_| JSONError::InvalidNumber { position })?;
                self.position += length;
                self.state = after;
                Ok(JSONEvent::Number(text))
            }
            character => Err(JSONError::UnexpectedCharacter { position: self.position, character }),
        }
    }

    /// Reads a key and checks for the colon that follows it.
    pub fn key(&mut self) -> Result<JSONEvent<'a>, JSONError> {
        match self.peek() {
            Some(b'"') => {
                let (string, end) = JSONString::scan(self.input, self.position + 1)?;
                self.position = end;
                self.state = JSONState::Colon;
                Ok(JSONEvent::Key(string))
            }
            Some(character) => Err(JSONError::UnexpectedCharacter { position: self.position, character }),
            None => Err(JSONError::UnexpectedEnd { position: self.input.len() }),
        }
    }

    /// The next event, or `None` once the value and the white space after it
    /// have been read. After an error, the reader must not be used again.
    pub fn next_event(&mut self) -> Result<Option<JSONEvent<'a>>, JSONError> {
        loop {
            match self.state {
                JSONState::Value => return self.value().map(Some),
                JSONState::ArrayStart => {
                    if self.peek() == Some(b']') {
                        self.close(JSONContainer::Array, b']')?;
                        return Ok(Some(JSONEvent::EndArray));
                    }
                    return self.value().map(Some);
                }
                JSONState::ObjectStart => {
                    if self.peek() == Some(b'}') {
                        self.close(JSONContainer::Object, b'}')?;
                        return Ok(Some(JSONEvent::EndObject));
                    }
                    return self.key().map(Some);
                }
                JSONState::Key => return self.key().map(Some),
                JSONState::Colon => match self.peek() {
                    Some(b':') => {
                        self.position += 1;
                        self.state = JSONState::Value;
                    }
                    Some(character) => {
                        return Err(JSONError::UnexpectedCharacter { position: self.position, character });
                    }
                    None => return Err(JSONError::UnexpectedEnd { position: self.input.len() }),
                },
                JSONState::AfterValue => match self.peek() {
                    Some(b',') => {
                        self.position += 1;
                        self.state = match self.stack.last() {
                            Some(JSONContainer::Object) => JSONState::Key,
                            _ => JSONState::Value,
                        };
                    }
                    Some(b']') => {
                        self.close(JSONContainer::Array, b']')?;
                        return Ok(Some(JSONEvent::EndArray));
                    }
                    Some(b'}') => {
                        self.close(JSONContainer::Object, b'}')?;
                        return Ok(Some(JSONEvent::EndObject));
                    }
                    Some(character) => {
                        return Err(JSONError::UnexpectedCharacter { position: self.position, character });
                    }
                    None => return Err(JSONError::UnexpectedEnd { position: self.input.len() }),
                },
                JSONState::Done => {
                    return match self.peek() {
                        None => Ok(None),
                        Some(_) => Err(JSONError::TrailingData { position: self.position }),
                    };
                }
            }
        }
    }

    /// Reads every event, which validates the whole text.
    pub fn validate(mut self) -> Result<(), JSONError> {
        while self.next_event()?.is_some() {}
        Ok(())
    }
}
