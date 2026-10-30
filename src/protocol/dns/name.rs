use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

use super::DNSError;

/// A domain name (RFC 1035 §3.1): its labels in the wire form, uncompressed,
/// ending with the root's empty label. Names compare without ASCII case
/// (RFC 4343) and keep the case they were made with.
#[derive(Clone, Debug, Default)]
pub struct DNSName {
    wire: Vec<u8>,
}

impl DNSName {
    /// The longest name in the wire form (RFC 1035 §2.3.4).
    pub const MAXIMUM_LENGTH: usize = 255;
    /// The longest label.
    pub const MAXIMUM_LABEL: usize = 63;

    /// The root, ".".
    pub fn root() -> DNSName {
        DNSName { wire: alloc::vec![0] }
    }

    /// The name of `labels`, the most specific first.
    pub fn from_labels<L: AsRef<[u8]>>(labels: &[L]) -> Result<DNSName, DNSError> {
        let mut wire = Vec::new();
        for label in labels {
            let label = label.as_ref();
            if label.is_empty() || label.len() > DNSName::MAXIMUM_LABEL {
                return Err(DNSError::Syntax("a label empty or longer than 63 bytes"));
            }
            wire.push(label.len() as u8);
            wire.extend_from_slice(label);
        }
        wire.push(0);
        if wire.len() > DNSName::MAXIMUM_LENGTH {
            return Err(DNSError::TooLarge("a name longer than 255 bytes"));
        }
        Ok(DNSName { wire })
    }

    /// The name of the wire form `wire`, uncompressed and whole.
    pub fn from_wire(wire: &[u8]) -> Result<DNSName, DNSError> {
        let (name, length) = DNSName::decode(wire, 0)?;
        if length != wire.len() {
            return Err(DNSError::Malformed("bytes after a name"));
        }
        Ok(name)
    }

    /// The wire form, uncompressed.
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// The labels, the most specific first, the root's empty one not included.
    pub fn labels(&self) -> DNSLabels<'_> {
        DNSLabels { rest: &self.wire }
    }

    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    pub fn is_root(&self) -> bool {
        self.wire == [0]
    }

    /// Whether the name's first label is "*", a wildcard (RFC 4592 §2.1.1).
    pub fn is_wildcard(&self) -> bool {
        self.labels().next() == Some(b"*")
    }

    /// The name with its first label removed; the root's parent is none.
    pub fn parent(&self) -> Option<DNSName> {
        let first = *self.wire.first()? as usize;
        (first != 0).then(|| DNSName { wire: self.wire[first + 1..].to_vec() })
    }

    /// `label` followed by this name.
    pub fn prepend(&self, label: &[u8]) -> Result<DNSName, DNSError> {
        if label.is_empty() || label.len() > DNSName::MAXIMUM_LABEL {
            return Err(DNSError::Syntax("a label empty or longer than 63 bytes"));
        }
        let mut wire = Vec::with_capacity(self.wire.len() + label.len() + 1);
        wire.push(label.len() as u8);
        wire.extend_from_slice(label);
        wire.extend_from_slice(&self.wire);
        if wire.len() > DNSName::MAXIMUM_LENGTH {
            return Err(DNSError::TooLarge("a name longer than 255 bytes"));
        }
        Ok(DNSName { wire })
    }

    /// This name, relative, followed by `origin`: what a relative name of a
    /// zone file means (RFC 1035 §5.1).
    pub fn append(&self, origin: &DNSName) -> Result<DNSName, DNSError> {
        let mut wire = self.wire[..self.wire.len() - 1].to_vec();
        wire.extend_from_slice(&origin.wire);
        if wire.len() > DNSName::MAXIMUM_LENGTH {
            return Err(DNSError::TooLarge("a name longer than 255 bytes"));
        }
        Ok(DNSName { wire })
    }

    /// The `count` last labels of the name (its ancestor of that many labels).
    pub fn suffix(&self, count: usize) -> DNSName {
        let total = self.label_count();
        let mut name = self.clone();
        for _ in count..total {
            name = name.parent().unwrap_or_else(DNSName::root);
        }
        name
    }

    /// Whether this name is `ancestor` or below it, without ASCII case.
    pub fn is_subdomain_of(&self, ancestor: &DNSName) -> bool {
        let (mine, theirs) = (self.label_count(), ancestor.label_count());
        mine >= theirs && self.suffix(theirs) == *ancestor
    }

    /// The longest name that both this name and `other` are at or below.
    pub fn common_ancestor(&self, other: &DNSName) -> DNSName {
        let mine: Vec<&[u8]> = self.labels().collect();
        let theirs: Vec<&[u8]> = other.labels().collect();
        let common = mine.iter().rev().zip(theirs.iter().rev()).take_while(|(a, b)| a.eq_ignore_ascii_case(b)).count();
        self.suffix(common)
    }

    /// The name lowercased: its canonical form (RFC 4034 §6.2).
    pub fn canonical(&self) -> DNSName {
        DNSName { wire: self.wire.to_ascii_lowercase() }
    }

    /// The canonical order of names (RFC 4034 §6.1): label by label from
    /// the root, each compared as lowercased bytes; without allocating.
    pub fn canonical_cmp(&self, other: &DNSName) -> Ordering {
        let (mut mine, mut theirs) = ([0u8; 128], [0u8; 128]);
        let (count, other_count) = (self.label_offsets(&mut mine), other.label_offsets(&mut theirs));
        for index in 1..=count.min(other_count) {
            let a = self.label_at(mine[count - index]);
            let b = other.label_at(theirs[other_count - index]);
            let ordering = a.iter().map(u8::to_ascii_lowercase).cmp(b.iter().map(u8::to_ascii_lowercase));
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
        count.cmp(&other_count)
    }

    /// Writes the offset of each label in the wire form into `out`, the
    /// most specific first, and returns how many (at most 127: a name has
    /// at most 255 bytes).
    pub fn label_offsets(&self, out: &mut [u8; 128]) -> usize {
        let (mut offset, mut count) = (0usize, 0usize);
        while let Some(&length) = self.wire.get(offset)
            && length != 0
            && count < out.len()
        {
            out[count] = offset as u8;
            count += 1;
            offset += 1 + usize::from(length);
        }
        count
    }

    /// The label at `offset` of the wire form.
    pub fn label_at(&self, offset: u8) -> &[u8] {
        let offset = usize::from(offset);
        let length = usize::from(self.wire[offset]);
        &self.wire[offset + 1..offset + 1 + length]
    }

    /// The name at `offset` of `message`, following compression pointers
    /// (RFC 1035 §4.1.4) backward only, so that they cannot loop; and the
    /// offset after it in place (after its pointer, if any).
    pub fn decode(message: &[u8], offset: usize) -> Result<(DNSName, usize), DNSError> {
        let mut wire = Vec::new();
        let mut position = offset;
        let mut end = None;
        let mut lowest = offset;
        loop {
            let length = *message.get(position).ok_or(DNSError::Malformed("a name cut short"))? as usize;
            match length & 0xC0 {
                0x00 => {
                    let label = message
                        .get(position + 1..position + 1 + length)
                        .ok_or(DNSError::Malformed("a label cut short"))?;
                    wire.push(length as u8);
                    wire.extend_from_slice(label);
                    if wire.len() > DNSName::MAXIMUM_LENGTH {
                        return Err(DNSError::Malformed("a name longer than 255 bytes"));
                    }
                    position += 1 + length;
                    if length == 0 {
                        return Ok((DNSName { wire }, end.unwrap_or(position)));
                    }
                }
                0xC0 => {
                    let low = *message.get(position + 1).ok_or(DNSError::Malformed("a pointer cut short"))? as usize;
                    let target = (length & 0x3F) << 8 | low;
                    // Only to what came before: no loop is possible.
                    if target >= lowest {
                        return Err(DNSError::Malformed("a compression pointer forward or to itself"));
                    }
                    end.get_or_insert(position + 2);
                    lowest = target;
                    position = target;
                }
                _ => return Err(DNSError::Malformed("a label of a reserved type")),
            }
        }
    }

    /// Appends the name, compressed against the names already written to
    /// `out` if `compression` (RFC 1035 §4.1.4).
    pub fn encode(&self, out: &mut Vec<u8>, compression: Option<&mut DNSCompression>) {
        let Some(compression) = compression else {
            out.extend_from_slice(&self.wire);
            return;
        };
        let mut rest = &self.wire[..];
        while rest[0] != 0 {
            let key = rest.to_ascii_lowercase();
            if let Some(&pointer) = compression.offsets.get(&key) {
                out.extend_from_slice(&(0xC000 | pointer).to_be_bytes());
                return;
            }
            if out.len() < 0x4000 {
                compression.offsets.insert(key, out.len() as u16);
            }
            let length = rest[0] as usize;
            out.extend_from_slice(&rest[..=length]);
            rest = &rest[length + 1..];
        }
        out.push(0);
    }

    /// The name of the text `text` (RFC 1035 §5.1): labels separated by
    /// dots, `\X` for a character and `\DDD` for a byte in decimal. A name
    /// that does not end with a dot is relative to `origin` (fails without one).
    pub fn parse(text: &str, origin: Option<&DNSName>) -> Result<DNSName, DNSError> {
        let syntax = DNSError::Syntax;
        if text == "." {
            return Ok(DNSName::root());
        }
        if text == "@" {
            return origin.cloned().ok_or(syntax("@ without an origin"));
        }
        if text.is_empty() {
            return Err(syntax("an empty name"));
        }
        let bytes = text.as_bytes();
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut label = Vec::new();
        let mut index = 0;
        let mut absolute = false;
        while index < bytes.len() {
            match bytes[index] {
                b'\\' => {
                    let digits = bytes.get(index + 1..index + 4);
                    if let Some(digits) = digits.filter(|digits| digits.iter().all(u8::is_ascii_digit)) {
                        let value = digits.iter().fold(0u32, |value, digit| value * 10 + u32::from(digit - b'0'));
                        label.push(u8::try_from(value).map_err(|_| syntax("an escape above 255"))?);
                        index += 4;
                    } else {
                        label.push(*bytes.get(index + 1).ok_or(syntax("an escape at the end"))?);
                        index += 2;
                    }
                }
                b'.' => {
                    if label.is_empty() {
                        return Err(syntax("an empty label"));
                    }
                    labels.push(core::mem::take(&mut label));
                    index += 1;
                    if index == bytes.len() {
                        absolute = true;
                    }
                }
                byte => {
                    label.push(byte);
                    index += 1;
                }
            }
        }
        if !label.is_empty() {
            labels.push(label);
        }
        let name = DNSName::from_labels(&labels)?;
        match (absolute, origin) {
            (true, _) => Ok(name),
            (false, Some(origin)) => name.append(origin),
            (false, None) => Err(syntax("a relative name without an origin")),
        }
    }
}

impl PartialEq for DNSName {
    fn eq(&self, other: &DNSName) -> bool {
        self.wire.eq_ignore_ascii_case(&other.wire)
    }
}

impl Eq for DNSName {}

impl core::hash::Hash for DNSName {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        for byte in &self.wire {
            state.write_u8(byte.to_ascii_lowercase());
        }
    }
}

impl PartialOrd for DNSName {
    fn partial_cmp(&self, other: &DNSName) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The canonical order (RFC 4034 §6.1).
impl Ord for DNSName {
    fn cmp(&self, other: &DNSName) -> Ordering {
        self.canonical_cmp(other)
    }
}

/// The text of the name, absolute, with a final dot; bytes other than
/// letters, digits, "-", "_" and "*" escaped (RFC 1035 §5.1, RFC 4343 §2.1).
impl fmt::Display for DNSName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return formatter.write_str(".");
        }
        for label in self.labels() {
            let mut text = String::new();
            for &byte in label {
                match byte {
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'*' => text.push(byte as char),
                    b'.' | b'\\' | b'"' | b'(' | b')' | b';' | b'@' | b'$' => {
                        text.push('\\');
                        text.push(byte as char);
                    }
                    0x21..=0x7E => text.push(byte as char),
                    _ => text.push_str(&alloc::format!("\\{byte:03}")),
                }
            }
            formatter.write_str(&text)?;
            formatter.write_str(".")?;
        }
        Ok(())
    }
}

/// The labels of a [`DNSName`], the most specific first.
#[derive(Clone, Debug)]
pub struct DNSLabels<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for DNSLabels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let length = *self.rest.first()? as usize;
        if length == 0 {
            return None;
        }
        let label = &self.rest[1..=length];
        self.rest = &self.rest[length + 1..];
        Some(label)
    }
}

/// The names written so far in a message, by their wire form lowercased,
/// and where: the targets of compression pointers (RFC 1035 §4.1.4).
#[derive(Clone, Debug, Default)]
pub struct DNSCompression {
    pub offsets: BTreeMap<Vec<u8>, u16>,
}

impl DNSCompression {
    pub fn new() -> DNSCompression {
        DNSCompression::default()
    }
}
