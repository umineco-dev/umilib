//! JSON, RFC 8259.
//!
//! [`JSONReader`] is a pull parser that validates the input and yields
//! [`JSONEvent`]s that borrow it, without building a tree. [`JSONValue`] is a
//! tree built on top of it, and [`JSONEncoder`] writes values as text.
//! Parsing is strict (the grammar of RFC 8259 and valid UTF-8 only) and bounded
//! by [`JSONConfig`]: nesting depth, input length and duplicate keys.

mod config;
mod encoder;
mod error;
mod event;
mod number;
mod object;
mod reader;
mod string;
mod value;

pub use config::{DuplicateKeys, JSONConfig};
pub use encoder::JSONEncoder;
pub use error::JSONError;
pub use event::JSONEvent;
pub use number::JSONNumber;
pub use object::JSONObject;
pub use reader::{JSONContainer, JSONReader, JSONState};
pub use string::JSONString;
pub use value::{JSONCloneStep, JSONFrame, JSONValue};
