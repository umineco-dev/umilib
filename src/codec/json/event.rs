use super::JSONString;

/// One step of a JSON text, as yielded by [`JSONReader`](super::JSONReader).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JSONEvent<'a> {
    BeginObject,
    EndObject,
    BeginArray,
    EndArray,
    /// The key of the next member of the current object.
    Key(JSONString<'a>),
    String(JSONString<'a>),
    /// A number, as written in the input (already validated).
    Number(&'a str),
    Bool(bool),
    Null,
}
