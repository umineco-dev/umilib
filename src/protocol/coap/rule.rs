use alloc::string::String;
use alloc::vec::Vec;

use crate::service::Rule;

use super::{CoAPCode, CoAPMessage};

/// The rule of a [`Router`](crate::service::Router) that routes CoAP
/// requests by their path (its Uri-Path options, the rule's segments
/// first) and, if given, their method.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CoAPRule {
    pub path: Vec<String>,
    pub method: Option<CoAPCode>,
}

impl CoAPRule {
    /// The requests of paths at or below `path` ("/sensors/temp").
    pub fn new(path: &str) -> CoAPRule {
        CoAPRule {
            path: path.split('/').filter(|segment| !segment.is_empty()).map(String::from).collect(),
            method: None,
        }
    }

    pub fn with_method(self, method: CoAPCode) -> CoAPRule {
        CoAPRule { method: Some(method), ..self }
    }
}

impl Rule<CoAPMessage> for CoAPRule {
    fn matches(&self, message: &CoAPMessage) -> bool {
        let path = message.options.path();
        message.code.is_request()
            && path.starts_with(&self.path)
            && self.method.is_none_or(|method| method == message.code)
    }
}
