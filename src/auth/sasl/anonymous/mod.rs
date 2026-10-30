//! ANONYMOUS (RFC 4505): the client logs in without credentials, with
//! optional trace information (an email address or an opaque token) that
//! has no meaning to the server beyond its logs.

use alloc::string::String;
use alloc::vec::Vec;

use super::SASLError;
use crate::codec::stringprep::{StringPrepProfile, Unassigned};

/// The message of ANONYMOUS (RFC 4505 §2): the trace information, if any.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ANONYMOUSMessage {
    pub trace: Option<String>,
}

impl ANONYMOUSMessage {
    /// The most characters of the trace information (RFC 4505 §2).
    pub const MAXIMUM_CHARACTERS: usize = 255;

    pub fn new(trace: Option<&str>) -> ANONYMOUSMessage {
        ANONYMOUSMessage { trace: trace.map(String::from) }
    }

    /// The trace information prepared with the "trace" profile (RFC 4505
    /// §3); fails with [`SASLError::Length`] for an empty one or one of
    /// more than 255 characters.
    pub fn encode(&self) -> Result<Vec<u8>, SASLError> {
        let Some(trace) = &self.trace else { return Ok(Vec::new()) };
        Ok(ANONYMOUSMessage::prepare(trace)?.into_bytes())
    }

    /// The message of `message`: empty, or UTF-8 trace information that the
    /// "trace" profile accepts, of at most 255 characters.
    pub fn decode(message: &[u8]) -> Result<ANONYMOUSMessage, SASLError> {
        if message.is_empty() {
            return Ok(ANONYMOUSMessage::new(None));
        }
        let text = core::str::from_utf8(message).map_err(|_| SASLError::Format)?;
        // The profile neither maps nor normalizes: checking is all it does.
        ANONYMOUSMessage::prepare(text)?;
        Ok(ANONYMOUSMessage::new(Some(text)))
    }

    /// `trace` prepared with the "trace" profile (unassigned code points
    /// allowed), checked to hold 1 to 255 characters.
    pub fn prepare(trace: &str) -> Result<String, SASLError> {
        let prepared = StringPrepProfile::TRACE.prepare(trace, Unassigned::Allowed)?;
        if !(1..=ANONYMOUSMessage::MAXIMUM_CHARACTERS).contains(&prepared.chars().count()) {
            return Err(SASLError::Length);
        }
        Ok(prepared)
    }

    /// Whether the trace information has the form of an email address
    /// (it holds `@`); the other form is an opaque token without `@`.
    pub fn is_email(&self) -> bool {
        self.trace.as_deref().is_some_and(|trace| trace.contains('@'))
    }
}
