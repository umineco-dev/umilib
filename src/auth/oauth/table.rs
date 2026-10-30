use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::OAuthError;

/// A record an [`OAuthTable`] keeps: something issued to a client.
pub trait OAuthRecord {
    /// The client the record was issued to, whose share of the table it counts against.
    fn client_id(&self) -> &str;
}

/// A bounded table of records, each kept until a time of its own: at most `maximum` records,
/// and at most `maximum_per_client` of one client, so that one client cannot fill the table
/// for the others. Records are dropped in the order of their times, without looking at the
/// others, so dropping what expired costs nothing when nothing did.
#[derive(Clone, Debug)]
pub struct OAuthTable<K: Ord + Clone, V: OAuthRecord> {
    entries: BTreeMap<K, (i64, V)>,
    until: BTreeSet<(i64, K)>,
    clients: BTreeMap<String, usize>,
    pub maximum: usize,
    pub maximum_per_client: usize,
}

impl<K: Ord + Clone, V: OAuthRecord> OAuthTable<K, V> {
    pub fn new(maximum: usize, maximum_per_client: usize) -> OAuthTable<K, V> {
        OAuthTable {
            entries: BTreeMap::new(),
            until: BTreeSet::new(),
            clients: BTreeMap::new(),
            maximum,
            maximum_per_client,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The number of records of `client_id`.
    pub fn count(&self, client_id: &str) -> usize {
        self.clients.get(client_id).copied().unwrap_or(0)
    }

    /// Whether `count` more records of `client_id` fit.
    pub fn has_room(&self, client_id: &str, count: usize) -> bool {
        self.entries.len().saturating_add(count) <= self.maximum
            && self.count(client_id).saturating_add(count) <= self.maximum_per_client
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|(_, value)| value)
    }

    /// The time the record of `key` is kept until.
    pub fn kept_until(&self, key: &K) -> Option<i64> {
        self.entries.get(key).map(|(until, _)| *until)
    }

    /// Keeps `value` under `key` until `until`, replacing a record of the same key; fails with
    /// Limit when it does not fit.
    pub fn insert(&mut self, key: K, value: V, until: i64) -> Result<(), OAuthError> {
        let replaced = self.entries.contains_key(&key);
        if !replaced && !self.has_room(value.client_id(), 1) {
            return Err(OAuthError::Limit);
        }
        self.remove(&key);
        self.add(value.client_id());
        self.until.insert((until, key.clone()));
        self.entries.insert(key, (until, value));
        Ok(())
    }

    /// Changes the record of `key` and the time it is kept until with `change`, and returns its
    /// result; `None` without a record.
    pub fn update<R>(&mut self, key: &K, change: impl FnOnce(&mut V, &mut i64) -> R) -> Option<R> {
        let (until, value) = self.entries.get_mut(key)?;
        let (old_until, old_client) = (*until, value.client_id().to_string());
        let result = change(value, until);
        if *until != old_until {
            self.until.remove(&(old_until, key.clone()));
            self.until.insert((*until, key.clone()));
        }
        let new_client = value.client_id().to_string();
        if new_client != old_client {
            self.subtract(&old_client);
            self.add(&new_client);
        }
        Some(result)
    }

    /// Removes the record of `key`.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let (until, value) = self.entries.remove(key)?;
        self.until.remove(&(until, key.clone()));
        self.subtract(value.client_id());
        Some(value)
    }

    /// Removes the records `keep` refuses; this looks at every record.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        let gone: Vec<K> =
            self.entries.iter().filter(|(key, (_, value))| !keep(key, value)).map(|(key, _)| key.clone()).collect();
        for key in gone {
            self.remove(&key);
        }
    }

    /// Removes and returns the records kept until before `now`.
    pub fn expire(&mut self, now: i64) -> Vec<(K, V)> {
        let mut removed = Vec::new();
        while let Some((until, key)) = self.until.first().cloned() {
            if until >= now {
                break;
            }
            if let Some(value) = self.remove(&key) {
                removed.push((key, value));
            }
        }
        removed
    }

    /// The records, in the order of their keys.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(key, (_, value))| (key, value))
    }

    fn add(&mut self, client_id: &str) {
        *self.clients.entry(client_id.to_string()).or_insert(0) += 1;
    }

    fn subtract(&mut self, client_id: &str) {
        if let Some(count) = self.clients.get_mut(client_id) {
            *count -= 1;
            if *count == 0 {
                self.clients.remove(client_id);
            }
        }
    }
}

/// A client identifier is the record of what is only counted against its client, such as the
/// identifier of a client assertion used.
impl OAuthRecord for String {
    fn client_id(&self) -> &str {
        self
    }
}
