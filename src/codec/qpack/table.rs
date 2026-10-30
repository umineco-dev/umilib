use alloc::collections::VecDeque;

use crate::codec::hpack::{HPACKDynamicTable, HPACKEntry};

/// The static table (RFC 9204 Appendix A): 99 fields, from index 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QPACKStaticTable;

impl QPACKStaticTable {
    pub const ENTRIES: [(&'static [u8], &'static [u8]); 99] = [
        (b":authority", b""),
        (b":path", b"/"),
        (b"age", b"0"),
        (b"content-disposition", b""),
        (b"content-length", b"0"),
        (b"cookie", b""),
        (b"date", b""),
        (b"etag", b""),
        (b"if-modified-since", b""),
        (b"if-none-match", b""),
        (b"last-modified", b""),
        (b"link", b""),
        (b"location", b""),
        (b"referer", b""),
        (b"set-cookie", b""),
        (b":method", b"CONNECT"),
        (b":method", b"DELETE"),
        (b":method", b"GET"),
        (b":method", b"HEAD"),
        (b":method", b"OPTIONS"),
        (b":method", b"POST"),
        (b":method", b"PUT"),
        (b":scheme", b"http"),
        (b":scheme", b"https"),
        (b":status", b"103"),
        (b":status", b"200"),
        (b":status", b"304"),
        (b":status", b"404"),
        (b":status", b"503"),
        (b"accept", b"*/*"),
        (b"accept", b"application/dns-message"),
        (b"accept-encoding", b"gzip, deflate, br"),
        (b"accept-ranges", b"bytes"),
        (b"access-control-allow-headers", b"cache-control"),
        (b"access-control-allow-headers", b"content-type"),
        (b"access-control-allow-origin", b"*"),
        (b"cache-control", b"max-age=0"),
        (b"cache-control", b"max-age=2592000"),
        (b"cache-control", b"max-age=604800"),
        (b"cache-control", b"no-cache"),
        (b"cache-control", b"no-store"),
        (b"cache-control", b"public, max-age=31536000"),
        (b"content-encoding", b"br"),
        (b"content-encoding", b"gzip"),
        (b"content-type", b"application/dns-message"),
        (b"content-type", b"application/javascript"),
        (b"content-type", b"application/json"),
        (b"content-type", b"application/x-www-form-urlencoded"),
        (b"content-type", b"image/gif"),
        (b"content-type", b"image/jpeg"),
        (b"content-type", b"image/png"),
        (b"content-type", b"text/css"),
        (b"content-type", b"text/html; charset=utf-8"),
        (b"content-type", b"text/plain"),
        (b"content-type", b"text/plain;charset=utf-8"),
        (b"range", b"bytes=0-"),
        (b"strict-transport-security", b"max-age=31536000"),
        (b"strict-transport-security", b"max-age=31536000; includesubdomains"),
        (b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
        (b"vary", b"accept-encoding"),
        (b"vary", b"origin"),
        (b"x-content-type-options", b"nosniff"),
        (b"x-xss-protection", b"1; mode=block"),
        (b":status", b"100"),
        (b":status", b"204"),
        (b":status", b"206"),
        (b":status", b"302"),
        (b":status", b"400"),
        (b":status", b"403"),
        (b":status", b"421"),
        (b":status", b"425"),
        (b":status", b"500"),
        (b"accept-language", b""),
        (b"access-control-allow-credentials", b"FALSE"),
        (b"access-control-allow-credentials", b"TRUE"),
        (b"access-control-allow-headers", b"*"),
        (b"access-control-allow-methods", b"get"),
        (b"access-control-allow-methods", b"get, post, options"),
        (b"access-control-allow-methods", b"options"),
        (b"access-control-expose-headers", b"content-length"),
        (b"access-control-request-headers", b"content-type"),
        (b"access-control-request-method", b"get"),
        (b"access-control-request-method", b"post"),
        (b"alt-svc", b"clear"),
        (b"authorization", b""),
        (b"content-security-policy", b"script-src 'none'; object-src 'none'; base-uri 'none'"),
        (b"early-data", b"1"),
        (b"expect-ct", b""),
        (b"forwarded", b""),
        (b"if-range", b""),
        (b"origin", b""),
        (b"purpose", b"prefetch"),
        (b"server", b""),
        (b"timing-allow-origin", b"*"),
        (b"upgrade-insecure-requests", b"1"),
        (b"user-agent", b""),
        (b"x-forwarded-for", b""),
        (b"x-frame-options", b"deny"),
        (b"x-frame-options", b"sameorigin"),
    ];

    /// The entry of `index`, 0 to 98.
    pub fn get(index: u64) -> Option<(&'static [u8], &'static [u8])> {
        usize::try_from(index).ok().and_then(|index| QPACKStaticTable::ENTRIES.get(index)).copied()
    }

    /// The index of an entry of `name` and `value`, else of `name`, and
    /// whether the value matches too.
    pub fn find(name: &[u8], value: &[u8]) -> Option<(u64, bool)> {
        let mut found = None;
        for (index, (entry_name, entry_value)) in QPACKStaticTable::ENTRIES.iter().enumerate() {
            if *entry_name == name {
                if *entry_value == value {
                    return Some((index as u64, true));
                }
                found = found.or(Some((index as u64, false)));
            }
        }
        found
    }
}

/// The dynamic table of QPACK (RFC 9204 §3.2): entries in the order of
/// their insertion, each of an absolute index from 0 (§3.2.4), the oldest
/// first, within a capacity the encoder sets up to the decoder's maximum.
/// Entries take the space of HPACK's (§3.2.1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct QPACKDynamicTable {
    pub entries: VecDeque<HPACKEntry>,
    /// The entries ever inserted: the Insert Count (§2.1.4).
    pub inserted: u64,
    pub size: usize,
    pub capacity: usize,
    /// The largest capacity allowed (SETTINGS_QPACK_MAX_TABLE_CAPACITY).
    pub maximum: usize,
}

impl QPACKDynamicTable {
    /// A table of capacity 0, as each connection starts (§3.2.2), allowed up to `maximum`.
    pub fn new(maximum: usize) -> QPACKDynamicTable {
        QPACKDynamicTable { entries: VecDeque::new(), inserted: 0, size: 0, capacity: 0, maximum }
    }

    /// The most entries the table can hold: floor(maximum / 32) (§4.5.1.1).
    pub fn maximum_entries(&self) -> u64 {
        (self.maximum / HPACKDynamicTable::ENTRY_OVERHEAD) as u64
    }

    /// The absolute index of the oldest entry.
    pub fn first(&self) -> u64 {
        self.inserted - self.entries.len() as u64
    }

    /// The entry of absolute index `index`, if inserted and not evicted.
    pub fn get(&self, index: u64) -> Option<&HPACKEntry> {
        index.checked_sub(self.first()).and_then(|offset| self.entries.get(offset as usize))
    }

    /// How many of the oldest entries adding an entry of `size` evicts;
    /// `None` if it does not fit the capacity at all.
    pub fn evictions(&self, size: usize) -> Option<usize> {
        let room = self.capacity.checked_sub(size)?;
        let mut taken = self.size;
        let mut count = 0;
        for entry in &self.entries {
            if taken <= room {
                break;
            }
            taken -= entry.size();
            count += 1;
        }
        Some(count)
    }

    /// Adds an entry, evicting the oldest as needed (§3.2.2); false if it is
    /// larger than the capacity.
    pub fn insert(&mut self, name: &[u8], value: &[u8]) -> bool {
        let entry = HPACKEntry::new(name, value);
        let Some(count) = self.evictions(entry.size()) else { return false };
        for _ in 0..count {
            if let Some(evicted) = self.entries.pop_front() {
                self.size -= evicted.size();
            }
        }
        self.size += entry.size();
        self.entries.push_back(entry);
        self.inserted += 1;
        true
    }

    /// Sets the capacity, evicting the oldest entries that no longer fit;
    /// false if it is above the maximum.
    pub fn set_capacity(&mut self, capacity: usize) -> bool {
        if capacity > self.maximum {
            return false;
        }
        self.capacity = capacity;
        while self.size > capacity {
            let Some(evicted) = self.entries.pop_front() else { break };
            self.size -= evicted.size();
        }
        true
    }

    /// The absolute index of an entry of `name` and `value` among those
    /// `usable` allows, the newest first, else of `name`; and whether the value matches.
    pub fn find(&self, name: &[u8], value: &[u8], usable: impl Fn(u64) -> bool) -> Option<(u64, bool)> {
        let mut found = None;
        let first = self.first();
        for (offset, entry) in self.entries.iter().enumerate().rev() {
            let index = first + offset as u64;
            if !usable(index) || entry.name() != name {
                continue;
            }
            if entry.value() == value {
                return Some((index, true));
            }
            found = found.or(Some((index, false)));
        }
        found
    }
}
