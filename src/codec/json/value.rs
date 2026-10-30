use alloc::string::String;
use alloc::vec::Vec;

use super::{DuplicateKeys, JSONConfig, JSONEncoder, JSONError, JSONEvent, JSONNumber, JSONObject, JSONReader};

/// A JSON value.
///
/// Dropping, cloning, comparing and formatting walk nested values with an
/// explicit stack, so trees of any depth are handled without exhausting the
/// call stack. `Debug` writes the value as compact JSON.
#[derive(Default)]
pub enum JSONValue {
    #[default]
    Null,
    Bool(bool),
    Number(JSONNumber),
    String(String),
    Array(Vec<JSONValue>),
    Object(JSONObject),
}

/// A container being built by [`JSONValue::decode`], which keeps a stack of them.
#[derive(Debug)]
pub enum JSONFrame {
    Array(Vec<JSONValue>),
    /// An object, the input positions of its keys, and the key waiting for its value.
    Object(JSONObject, Vec<usize>, Option<String>),
}

impl JSONValue {
    /// Parses `input` with the limits of `config`.
    pub fn decode(input: &[u8], config: JSONConfig) -> Result<JSONValue, JSONError> {
        let mut reader = JSONReader::new(input, config)?;
        let mut stack: Vec<JSONFrame> = Vec::new();
        let mut result = None;
        loop {
            let position = reader.position();
            let Some(event) = reader.next_event()? else {
                break;
            };
            let value = match event {
                JSONEvent::BeginArray => {
                    stack.try_reserve(1).map_err(|_| JSONError::AllocationFailed)?;
                    stack.push(JSONFrame::Array(Vec::new()));
                    continue;
                }
                JSONEvent::BeginObject => {
                    stack.try_reserve(1).map_err(|_| JSONError::AllocationFailed)?;
                    stack.push(JSONFrame::Object(JSONObject::new(), Vec::new(), None));
                    continue;
                }
                JSONEvent::Key(key) => {
                    if let Some(JSONFrame::Object(_, positions, pending)) = stack.last_mut() {
                        positions.try_reserve(1).map_err(|_| JSONError::AllocationFailed)?;
                        // The position of the key is that of its opening quote.
                        positions.push(reader.position() - key.raw().len() - 2);
                        *pending = Some(key.decode()?);
                    }
                    continue;
                }
                JSONEvent::EndArray => match stack.pop() {
                    Some(JSONFrame::Array(values)) => JSONValue::Array(values),
                    _ => return Err(JSONError::UnexpectedCharacter { position, character: b']' }),
                },
                JSONEvent::EndObject => match stack.pop() {
                    Some(JSONFrame::Object(object, positions, _)) => {
                        JSONValue::Object(JSONValue::resolve_duplicates(object, &positions, config.duplicate_keys)?)
                    }
                    _ => return Err(JSONError::UnexpectedCharacter { position, character: b'}' }),
                },
                JSONEvent::String(string) => JSONValue::String(string.decode()?),
                JSONEvent::Number(text) => JSONValue::Number(JSONNumber::new(text)?),
                JSONEvent::Bool(value) => JSONValue::Bool(value),
                JSONEvent::Null => JSONValue::Null,
            };
            match stack.last_mut() {
                None => result = Some(value),
                Some(JSONFrame::Array(values)) => {
                    values.try_reserve(1).map_err(|_| JSONError::AllocationFailed)?;
                    values.push(value);
                }
                Some(JSONFrame::Object(object, _, pending)) => {
                    let key = pending.take().unwrap_or_default();
                    object.members.try_reserve(1).map_err(|_| JSONError::AllocationFailed)?;
                    object.members.push((key, value));
                }
            }
        }
        result.ok_or(JSONError::UnexpectedEnd { position: input.len() })
    }

    /// Parses `text` with the default limits.
    pub fn parse(text: &str) -> Result<JSONValue, JSONError> {
        JSONValue::decode(text.as_bytes(), JSONConfig::default())
    }

    /// Applies `policy` to the members of `object` with equal keys, whose keys
    /// were written at `positions`. Takes O(n log n) time for n members.
    pub fn resolve_duplicates(
        object: JSONObject,
        positions: &[usize],
        policy: DuplicateKeys,
    ) -> Result<JSONObject, JSONError> {
        if policy == DuplicateKeys::KeepAll || object.members.len() < 2 {
            return Ok(object);
        }
        let mut order: Vec<usize> = Vec::new();
        order.try_reserve_exact(object.members.len()).map_err(|_| JSONError::AllocationFailed)?;
        order.extend(0..object.members.len());
        order.sort_by(|&a, &b| object.members[a].0.cmp(&object.members[b].0).then(a.cmp(&b)));
        let mut keep: Vec<bool> = Vec::new();
        keep.try_reserve_exact(object.members.len()).map_err(|_| JSONError::AllocationFailed)?;
        keep.resize(object.members.len(), true);
        for pair in order.windows(2) {
            let (first, second) = (pair[0], pair[1]);
            if object.members[first].0 != object.members[second].0 {
                continue;
            }
            match policy {
                DuplicateKeys::Reject => {
                    return Err(JSONError::DuplicateKey { position: positions.get(second).copied().unwrap_or(0) });
                }
                // Within equal keys the order is by index: drop every later one,
                // or every earlier one.
                DuplicateKeys::KeepFirst => keep[second] = false,
                DuplicateKeys::KeepLast => keep[first] = false,
                DuplicateKeys::KeepAll => {}
            }
        }
        let members =
            object.members.into_iter().zip(keep).filter(|(_, keep)| *keep).map(|(member, _)| member).collect();
        Ok(JSONObject { members })
    }

    pub fn is_null(&self) -> bool {
        matches!(self, JSONValue::Null)
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JSONValue::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<&JSONNumber> {
        match self {
            JSONValue::Number(number) => Some(number),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JSONValue::String(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<JSONValue>> {
        match self {
            JSONValue::Array(values) => Some(values),
            _ => None,
        }
    }

    pub fn as_array_mut(&mut self) -> Option<&mut Vec<JSONValue>> {
        match self {
            JSONValue::Array(values) => Some(values),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&JSONObject> {
        match self {
            JSONValue::Object(object) => Some(object),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<&mut JSONObject> {
        match self {
            JSONValue::Object(object) => Some(object),
            _ => None,
        }
    }

    /// The value of the member `key`, if this is an object that has it.
    pub fn get(&self, key: &str) -> Option<&JSONValue> {
        self.as_object()?.get(key)
    }

    /// The element at `index`, if this is an array that long.
    pub fn index(&self, index: usize) -> Option<&JSONValue> {
        self.as_array()?.get(index)
    }

    /// The value as compact JSON text.
    pub fn encode(&self) -> String {
        super::JSONEncoder::COMPACT.encode(self)
    }
}

impl From<bool> for JSONValue {
    fn from(value: bool) -> JSONValue {
        JSONValue::Bool(value)
    }
}

impl From<&str> for JSONValue {
    fn from(value: &str) -> JSONValue {
        JSONValue::String(String::from(value))
    }
}

impl From<String> for JSONValue {
    fn from(value: String) -> JSONValue {
        JSONValue::String(value)
    }
}

impl From<i64> for JSONValue {
    fn from(value: i64) -> JSONValue {
        JSONValue::Number(JSONNumber::from(value))
    }
}

impl From<u64> for JSONValue {
    fn from(value: u64) -> JSONValue {
        JSONValue::Number(JSONNumber::from(value))
    }
}

impl From<JSONNumber> for JSONValue {
    fn from(value: JSONNumber) -> JSONValue {
        JSONValue::Number(value)
    }
}

impl From<Vec<JSONValue>> for JSONValue {
    fn from(value: Vec<JSONValue>) -> JSONValue {
        JSONValue::Array(value)
    }
}

impl From<JSONObject> for JSONValue {
    fn from(value: JSONObject) -> JSONValue {
        JSONValue::Object(value)
    }
}

impl JSONValue {
    /// Moves the values directly inside `self` (array elements or member
    /// values) to the end of `values`, leaving `self` empty.
    pub fn take_children(&mut self, values: &mut Vec<JSONValue>) {
        match self {
            JSONValue::Array(elements) => values.append(elements),
            JSONValue::Object(object) => values.extend(object.members.drain(..).map(|(_, value)| value)),
            _ => {}
        }
    }
}

/// A step of cloning a tree of values without recursion: visit a value, or
/// rebuild a container from the clones of its children.
#[derive(Clone, Copy, Debug)]
pub enum JSONCloneStep<'a> {
    Visit(&'a JSONValue),
    /// Builds an array from the last `usize` clones.
    Array(usize),
    /// Builds an object with the keys of the object from the clones of its values.
    Object(&'a JSONObject),
}

impl Drop for JSONValue {
    fn drop(&mut self) {
        let mut pending = Vec::new();
        self.take_children(&mut pending);
        // Children are emptied before they are dropped, so no drop recurses.
        while let Some(mut value) = pending.pop() {
            value.take_children(&mut pending);
        }
    }
}

impl Clone for JSONValue {
    fn clone(&self) -> JSONValue {
        // Values are visited in order; a container is rebuilt once its
        // children are cloned, from the end of `done`.
        let mut steps = Vec::from([JSONCloneStep::Visit(self)]);
        let mut done: Vec<JSONValue> = Vec::new();
        while let Some(step) = steps.pop() {
            match step {
                JSONCloneStep::Visit(JSONValue::Array(values)) => {
                    steps.push(JSONCloneStep::Array(values.len()));
                    steps.extend(values.iter().rev().map(JSONCloneStep::Visit));
                }
                JSONCloneStep::Visit(JSONValue::Object(object)) => {
                    steps.push(JSONCloneStep::Object(object));
                    steps.extend(object.members.iter().rev().map(|(_, value)| JSONCloneStep::Visit(value)));
                }
                JSONCloneStep::Visit(JSONValue::Null) => done.push(JSONValue::Null),
                JSONCloneStep::Visit(JSONValue::Bool(value)) => done.push(JSONValue::Bool(*value)),
                JSONCloneStep::Visit(JSONValue::Number(number)) => done.push(JSONValue::Number(number.clone())),
                JSONCloneStep::Visit(JSONValue::String(text)) => done.push(JSONValue::String(text.clone())),
                JSONCloneStep::Array(length) => {
                    let values = done.split_off(done.len() - length);
                    done.push(JSONValue::Array(values));
                }
                JSONCloneStep::Object(object) => {
                    let values = done.split_off(done.len() - object.members.len());
                    let members = object.members.iter().map(|(key, _)| key.clone()).zip(values).collect();
                    done.push(JSONValue::Object(JSONObject { members }));
                }
            }
        }
        done.pop().unwrap_or_default()
    }
}

impl PartialEq for JSONValue {
    /// Values are equal if they have the same kind and contents; numbers
    /// compare by their text and objects by their members in order.
    fn eq(&self, other: &JSONValue) -> bool {
        let mut pairs = Vec::from([(self, other)]);
        while let Some(pair) = pairs.pop() {
            match pair {
                (JSONValue::Null, JSONValue::Null) => {}
                (JSONValue::Bool(a), JSONValue::Bool(b)) if a == b => {}
                (JSONValue::Number(a), JSONValue::Number(b)) if a == b => {}
                (JSONValue::String(a), JSONValue::String(b)) if a == b => {}
                (JSONValue::Array(a), JSONValue::Array(b)) if a.len() == b.len() => pairs.extend(a.iter().zip(b)),
                (JSONValue::Object(a), JSONValue::Object(b)) if a.members.len() == b.members.len() => {
                    for ((a_key, a_value), (b_key, b_value)) in a.members.iter().zip(&b.members) {
                        if a_key != b_key {
                            return false;
                        }
                        pairs.push((a_value, b_value));
                    }
                }
                _ => return false,
            }
        }
        true
    }
}

impl core::fmt::Debug for JSONValue {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "JSONValue({})", JSONEncoder::COMPACT.encode(self))
    }
}
