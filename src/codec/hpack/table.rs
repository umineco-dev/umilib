use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// The static table (RFC 7541 Appendix A): 61 fields, from index 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HPACKStaticTable;

impl HPACKStaticTable {
    pub const ENTRIES: [(&'static [u8], &'static [u8]); 61] = [
        (b":authority", b""),
        (b":method", b"GET"),
        (b":method", b"POST"),
        (b":path", b"/"),
        (b":path", b"/index.html"),
        (b":scheme", b"http"),
        (b":scheme", b"https"),
        (b":status", b"200"),
        (b":status", b"204"),
        (b":status", b"206"),
        (b":status", b"304"),
        (b":status", b"400"),
        (b":status", b"404"),
        (b":status", b"500"),
        (b"accept-charset", b""),
        (b"accept-encoding", b"gzip, deflate"),
        (b"accept-language", b""),
        (b"accept-ranges", b""),
        (b"accept", b""),
        (b"access-control-allow-origin", b""),
        (b"age", b""),
        (b"allow", b""),
        (b"authorization", b""),
        (b"cache-control", b""),
        (b"content-disposition", b""),
        (b"content-encoding", b""),
        (b"content-language", b""),
        (b"content-length", b""),
        (b"content-location", b""),
        (b"content-range", b""),
        (b"content-type", b""),
        (b"cookie", b""),
        (b"date", b""),
        (b"etag", b""),
        (b"expect", b""),
        (b"expires", b""),
        (b"from", b""),
        (b"host", b""),
        (b"if-match", b""),
        (b"if-modified-since", b""),
        (b"if-none-match", b""),
        (b"if-range", b""),
        (b"if-unmodified-since", b""),
        (b"last-modified", b""),
        (b"link", b""),
        (b"location", b""),
        (b"max-forwards", b""),
        (b"proxy-authenticate", b""),
        (b"proxy-authorization", b""),
        (b"range", b""),
        (b"referer", b""),
        (b"refresh", b""),
        (b"retry-after", b""),
        (b"server", b""),
        (b"set-cookie", b""),
        (b"strict-transport-security", b""),
        (b"transfer-encoding", b""),
        (b"user-agent", b""),
        (b"vary", b""),
        (b"via", b""),
        (b"www-authenticate", b""),
    ];

    /// The entry of `index`, 1 to 61.
    pub fn get(index: usize) -> Option<(&'static [u8], &'static [u8])> {
        index.checked_sub(1).and_then(|index| HPACKStaticTable::ENTRIES.get(index)).copied()
    }

    /// The index of an entry of `name` and `value`, else of `name`, and
    /// whether the value matches too.
    pub fn find(name: &[u8], value: &[u8]) -> Option<(usize, bool)> {
        let mut found = None;
        for (index, (entry_name, entry_value)) in HPACKStaticTable::ENTRIES.iter().enumerate() {
            if *entry_name == name {
                if *entry_value == value {
                    return Some((index + 1, true));
                }
                found = found.or(Some((index + 1, false)));
            }
        }
        found
    }
}

/// An entry of a dynamic table: its name and value in one allocation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HPACKEntry {
    pub bytes: Vec<u8>,
    pub name_length: usize,
}

impl HPACKEntry {
    pub fn new(name: &[u8], value: &[u8]) -> HPACKEntry {
        let mut bytes = Vec::with_capacity(name.len() + value.len());
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(value);
        HPACKEntry { bytes, name_length: name.len() }
    }

    pub fn name(&self) -> &[u8] {
        &self.bytes[..self.name_length]
    }

    pub fn value(&self) -> &[u8] {
        &self.bytes[self.name_length..]
    }

    /// Its size in the table (RFC 7541 §4.1).
    pub fn size(&self) -> usize {
        self.bytes.len() + HPACKDynamicTable::ENTRY_OVERHEAD
    }
}

/// The dynamic table (RFC 7541 §2.3.2, §4): the fields added, the newest
/// first, within a maximum size; adding evicts the oldest until the new
/// one fits, and one larger than the maximum empties the table.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HPACKDynamicTable {
    pub entries: VecDeque<HPACKEntry>,
    pub size: usize,
    pub maximum: usize,
}

impl HPACKDynamicTable {
    /// The bytes each entry takes beyond its name and value (RFC 7541 §4.1).
    pub const ENTRY_OVERHEAD: usize = 32;

    pub fn new(maximum: usize) -> HPACKDynamicTable {
        HPACKDynamicTable { entries: VecDeque::new(), size: 0, maximum }
    }

    /// The size an entry of `name` and `value` takes.
    pub fn entry_size(name: &[u8], value: &[u8]) -> usize {
        name.len().saturating_add(value.len()).saturating_add(HPACKDynamicTable::ENTRY_OVERHEAD)
    }

    /// The entry of `index`, 0 for the newest.
    pub fn get(&self, index: usize) -> Option<&HPACKEntry> {
        self.entries.get(index)
    }

    /// Adds an entry (RFC 7541 §4.4).
    pub fn insert(&mut self, name: &[u8], value: &[u8]) {
        let size = HPACKDynamicTable::entry_size(name, value);
        if size > self.maximum {
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.evict(self.maximum - size);
        self.entries.push_front(HPACKEntry::new(name, value));
        self.size += size;
    }

    /// Sets the maximum size, evicting what does not fit (RFC 7541 §4.3).
    pub fn set_maximum(&mut self, maximum: usize) {
        self.maximum = maximum;
        self.evict(maximum);
    }

    /// Evicts the oldest entries until the table takes at most `size` bytes.
    pub fn evict(&mut self, size: usize) {
        while self.size > size {
            let Some(entry) = self.entries.pop_back() else { break };
            self.size -= entry.size();
        }
    }

    /// The index of an entry of `name` and `value`, else of `name`, and
    /// whether the value matches too.
    pub fn find(&self, name: &[u8], value: &[u8]) -> Option<(usize, bool)> {
        let mut found = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.name() == name {
                if entry.value() == value {
                    return Some((index, true));
                }
                found = found.or(Some((index, false)));
            }
        }
        found
    }
}
