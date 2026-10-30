use alloc::string::String;
use alloc::vec::Vec;

use super::{HTTPBareItem, HTTPError, HTTPItem, HTTPMember, HTTPStructuredField};

/// The priority of a response (RFC 9218 §4): its urgency, 0 the most
/// urgent to 7, 3 by default, and whether it may be sent incrementally,
/// interleaved with others of its urgency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HTTPPriority {
    pub urgency: u8,
    pub incremental: bool,
}

impl Default for HTTPPriority {
    fn default() -> HTTPPriority {
        HTTPPriority { urgency: HTTPPriority::DEFAULT_URGENCY, incremental: false }
    }
}

impl HTTPPriority {
    pub const DEFAULT_URGENCY: u8 = 3;
    pub const LOWEST_URGENCY: u8 = 7;

    /// The priority of a Priority field value or PRIORITY_UPDATE frame's
    /// Priority Field Value, a dictionary (RFC 9218 §4, §5): "u" an integer
    /// of 0 to 7, "i" a boolean; members of other types or out of range and
    /// unknown keys are ignored (§4.1, §4.2). A value that is not a
    /// dictionary gives the default.
    pub fn parse(value: &[u8]) -> HTTPPriority {
        let mut priority = HTTPPriority::default();
        let Ok(members) = HTTPStructuredField::parse_dictionary(value) else { return priority };
        for (key, member) in members {
            let HTTPMember::Item(HTTPItem { bare, .. }) = member else { continue };
            match (key.as_str(), bare) {
                ("u", HTTPBareItem::Integer(urgency)) if (0..=7).contains(&urgency) => priority.urgency = urgency as u8,
                ("i", HTTPBareItem::Boolean(incremental)) => priority.incremental = incremental,
                _ => {}
            }
        }
        priority
    }

    /// The field value, leaving out what is the default.
    pub fn serialize(&self) -> Vec<u8> {
        let mut members = Vec::new();
        if self.urgency != HTTPPriority::DEFAULT_URGENCY {
            members.push((
                String::from("u"),
                HTTPMember::Item(HTTPItem::new(HTTPBareItem::Integer(self.urgency.min(7) as i64))),
            ));
        }
        if self.incremental {
            members.push((String::from("i"), HTTPMember::Item(HTTPItem::new(HTTPBareItem::Boolean(true)))));
        }
        let mut out = Vec::new();
        // Integers of 0 to 7 and booleans always serialize.
        let _: Result<(), HTTPError> = HTTPStructuredField::serialize_dictionary(&members, &mut out);
        out
    }
}
