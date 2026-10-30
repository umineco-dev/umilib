use crate::service::Rule;

use super::{DNSClass, DNSMessage, DNSName, DNSType};

/// The rule of a [`Router`](crate::service::Router) that routes DNS
/// messages by their question: a zone (the name or below it, without
/// case), and if given a type and a class. A message without a question
/// matches no rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSRule {
    pub zone: DNSName,
    pub kind: Option<DNSType>,
    pub class: Option<DNSClass>,
}

impl DNSRule {
    /// The messages of a question in `zone`, of any type and class.
    pub fn new(zone: DNSName) -> DNSRule {
        DNSRule { zone, kind: None, class: None }
    }

    pub fn with_type(self, kind: DNSType) -> DNSRule {
        DNSRule { kind: Some(kind), ..self }
    }

    pub fn with_class(self, class: DNSClass) -> DNSRule {
        DNSRule { class: Some(class), ..self }
    }
}

impl Default for DNSRule {
    fn default() -> DNSRule {
        DNSRule::new(DNSName::root())
    }
}

impl Rule<DNSMessage> for DNSRule {
    fn matches(&self, message: &DNSMessage) -> bool {
        message.question().is_some_and(|question| {
            question.name.is_subdomain_of(&self.zone)
                && self.kind.is_none_or(|kind| kind == question.kind)
                && self.class.is_none_or(|class| class == question.class)
        })
    }
}
