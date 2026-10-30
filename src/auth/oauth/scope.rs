use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use super::OAuthError;

/// A scope (RFC 6749 §3.3): scope tokens, each `1*( %x21 / %x23-5B / %x5D-7E )`, whose order
/// does not matter. A token given twice is kept once.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct OAuthScope {
    tokens: Vec<String>,
}

impl OAuthScope {
    /// The scope of the space-delimited `text`.
    pub fn parse(text: &str) -> Result<OAuthScope, OAuthError> {
        let mut scope = OAuthScope::default();
        let mut seen = BTreeSet::new();
        for token in text.split(' ') {
            if token.is_empty() || !token.bytes().all(OAuthScope::is_nqchar) {
                return Err(OAuthError::Invalid { parameter: "scope" });
            }
            if seen.insert(token) {
                scope.tokens.push(token.to_string());
            }
        }
        Ok(scope)
    }

    /// Whether `byte` is an NQCHAR (RFC 6749 Appendix A): a character of a scope token.
    pub fn is_nqchar(byte: u8) -> bool {
        matches!(byte, 0x21 | 0x23..=0x5B | 0x5D..=0x7E)
    }

    /// Adds `token`, which must be of the grammar of a scope token.
    pub fn insert(&mut self, token: &str) -> Result<(), OAuthError> {
        if token.is_empty() || !token.bytes().all(OAuthScope::is_nqchar) {
            return Err(OAuthError::Invalid { parameter: "scope" });
        }
        if !self.contains(token) {
            self.tokens.push(token.to_string());
        }
        Ok(())
    }

    /// Whether the scope has `token`.
    pub fn contains(&self, token: &str) -> bool {
        self.tokens.iter().any(|own| own == token)
    }

    /// Whether every token of this scope is in `other`.
    pub fn is_subset_of(&self, other: &OAuthScope) -> bool {
        let other: BTreeSet<&str> = other.tokens.iter().map(String::as_str).collect();
        self.tokens.iter().all(|token| other.contains(token.as_str()))
    }

    /// The tokens of this scope that are also in `other`.
    pub fn intersection(&self, other: &OAuthScope) -> OAuthScope {
        let other: BTreeSet<&str> = other.tokens.iter().map(String::as_str).collect();
        OAuthScope { tokens: self.tokens.iter().filter(|token| other.contains(token.as_str())).cloned().collect() }
    }

    /// The tokens, in the order they were added.
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }

    /// Whether the scope has no token.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

impl fmt::Display for OAuthScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, token) in self.tokens.iter().enumerate() {
            if index > 0 {
                formatter.write_str(" ")?;
            }
            formatter.write_str(token)?;
        }
        Ok(())
    }
}
