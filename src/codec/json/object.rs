use alloc::string::String;
use alloc::vec::Vec;

use super::JSONValue;

/// A JSON object: members in the order they were written or inserted.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct JSONObject {
    pub members: Vec<(String, JSONValue)>,
}

impl JSONObject {
    /// An empty object.
    pub const fn new() -> JSONObject {
        JSONObject { members: Vec::new() }
    }

    /// The number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the object has no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The value of the first member named `key`.
    pub fn get(&self, key: &str) -> Option<&JSONValue> {
        self.members.iter().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    /// The value of the first member named `key`, mutably.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut JSONValue> {
        self.members.iter_mut().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    /// Sets the member named `key`: replaces the value of the first such
    /// member, or appends a new member. Returns the replaced value.
    pub fn insert(&mut self, key: String, value: JSONValue) -> Option<JSONValue> {
        match self.get_mut(&key) {
            Some(existing) => Some(core::mem::replace(existing, value)),
            None => {
                self.members.push((key, value));
                None
            }
        }
    }

    /// Removes every member named `key` and returns the value of the first one.
    pub fn remove(&mut self, key: &str) -> Option<JSONValue> {
        let mut removed = None;
        let mut index = 0;
        while index < self.members.len() {
            if self.members[index].0 == key {
                let (_, value) = self.members.remove(index);
                removed.get_or_insert(value);
            } else {
                index += 1;
            }
        }
        removed
    }

    /// The members, in order.
    pub fn iter(&self) -> core::slice::Iter<'_, (String, JSONValue)> {
        self.members.iter()
    }
}
