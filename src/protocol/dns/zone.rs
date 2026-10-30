use alloc::string::String;
use alloc::vec::Vec;

use super::{DNSClass, DNSData, DNSError, DNSName, DNSRecord, DNSToken, DNSType};

/// Where a zone file failed: its line (from 1) and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DNSZoneError {
    pub line: usize,
    pub error: DNSError,
}

/// The reading of zone files (RFC 1035 §5, RFC 2308 §4 for $TTL, RFC 3597
/// §5 for unknown types): entries one per line or across parentheses,
/// comments after ";", an owner left blank for the previous one, the TTL
/// and the class in either order. $INCLUDE needs a file system: it fails.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DNSZoneFile {
    pub origin: Option<DNSName>,
    pub default_ttl: Option<u32>,
}

impl DNSZoneFile {
    pub fn new(origin: Option<DNSName>) -> DNSZoneFile {
        DNSZoneFile { origin, default_ttl: None }
    }

    /// The records of `text`.
    pub fn parse(&mut self, text: &str) -> Result<Vec<DNSRecord>, DNSZoneError> {
        let mut records = Vec::new();
        let mut owner: Option<DNSName> = None;
        let mut class = DNSClass::IN;
        let mut last_ttl: Option<u32> = None;
        for (line, entry) in DNSZoneFile::entries(text)? {
            let fail = |error| DNSZoneError { line, error };
            let blank_owner = entry.starts_with([' ', '\t']);
            let tokens = DNSToken::split(&entry).map_err(fail)?;
            let Some(first) = tokens.first() else { continue };
            match first.as_str().map_err(fail)? {
                "$ORIGIN" => {
                    let name = tokens.get(1).ok_or(fail(DNSError::Syntax("$ORIGIN without a name")))?;
                    self.origin =
                        Some(DNSName::parse(name.as_str().map_err(fail)?, self.origin.as_ref()).map_err(fail)?);
                    continue;
                }
                "$TTL" => {
                    let ttl = tokens.get(1).ok_or(fail(DNSError::Syntax("$TTL without a value")))?;
                    self.default_ttl = Some(DNSToken::ttl(ttl.as_str().map_err(fail)?).map_err(fail)?);
                    continue;
                }
                "$INCLUDE" => return Err(fail(DNSError::Syntax("$INCLUDE is not supported"))),
                directive if directive.starts_with('$') => return Err(fail(DNSError::Syntax("an unknown directive"))),
                _ => {}
            }
            let mut rest = &tokens[..];
            if !blank_owner {
                owner = Some(DNSName::parse(rest[0].as_str().map_err(fail)?, self.origin.as_ref()).map_err(fail)?);
                rest = &rest[1..];
            }
            let owner = owner.clone().ok_or(fail(DNSError::Syntax("an entry without an owner")))?;
            let mut ttl = None;
            let kind = loop {
                let token = rest.first().ok_or(fail(DNSError::Syntax("an entry without a type")))?;
                let text = token.as_str().map_err(fail)?;
                rest = &rest[1..];
                // A name of both a class and a type (ANY) is the class if a type follows it (RFC 1035 §5.1).
                let type_follows =
                    rest.first().and_then(|next| next.as_str().ok()).is_some_and(|next| DNSType::parse(next).is_ok());
                if ttl.is_none() && text.starts_with(|first: char| first.is_ascii_digit()) {
                    ttl = Some(DNSToken::ttl(text).map_err(fail)?);
                } else if let Some(parsed) =
                    DNSClass::parse(text).ok().filter(|_| DNSType::parse(text).is_err() || type_follows)
                {
                    class = parsed;
                } else {
                    break DNSType::parse(text).map_err(fail)?;
                }
            };
            let data = DNSData::parse(kind, rest, self.origin.as_ref()).map_err(fail)?;
            // RFC 2308 §4: $TTL, else (RFC 1035) the TTL of the entry before.
            let ttl = ttl.or(self.default_ttl).or(last_ttl).or(match &data {
                DNSData::SOA(soa) => Some(soa.minimum),
                _ => None,
            });
            let ttl = ttl.ok_or(fail(DNSError::Syntax("an entry without a TTL and no $TTL before it")))?;
            last_ttl = Some(ttl);
            records.push(DNSRecord { name: owner, kind, class, ttl, data });
        }
        Ok(records)
    }

    /// The entries of `text` with their first lines: comments removed,
    /// lines inside parentheses joined.
    pub fn entries(text: &str) -> Result<Vec<(usize, String)>, DNSZoneError> {
        let mut entries = Vec::new();
        let mut entry = String::new();
        let mut start = 0;
        let mut depth = 0usize;
        let mut quoted = false;
        for (number, line) in text.lines().enumerate() {
            if depth == 0 {
                start = number + 1;
            }
            let mut escaped = false;
            for character in line.chars() {
                if escaped {
                    entry.push(character);
                    escaped = false;
                    continue;
                }
                match character {
                    '\\' => {
                        escaped = true;
                        entry.push(character);
                    }
                    '"' => {
                        quoted = !quoted;
                        entry.push(character);
                    }
                    ';' if !quoted => break,
                    '(' if !quoted => {
                        depth += 1;
                        entry.push(' ');
                    }
                    ')' if !quoted => {
                        depth = depth.checked_sub(1).ok_or(DNSZoneError {
                            line: number + 1,
                            error: DNSError::Syntax("a ')' without its '('"),
                        })?;
                        entry.push(' ');
                    }
                    other => entry.push(other),
                }
            }
            if depth > 0 || quoted {
                entry.push(' ');
                continue;
            }
            if !entry.trim().is_empty() {
                entries.push((start, core::mem::take(&mut entry)));
            }
            entry.clear();
        }
        if depth > 0 || quoted {
            return Err(DNSZoneError { line: start, error: DNSError::Syntax("an entry without its ')' or '\"'") });
        }
        Ok(entries)
    }
}
