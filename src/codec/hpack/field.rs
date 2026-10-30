use alloc::vec::Vec;

/// A field line of a block: its name and value, and whether it is
/// sensitive, which an encoder never puts in the dynamic table and a
/// decoder reports when its encoder said so (RFC 7541 §6.2.3, §7.1.3), so
/// that intermediaries keep it out of their tables too.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HPACKField {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub sensitive: bool,
}

impl HPACKField {
    pub fn new(name: &[u8], value: &[u8]) -> HPACKField {
        HPACKField { name: name.to_vec(), value: value.to_vec(), sensitive: false }
    }

    /// A field never indexed.
    pub fn sensitive(name: &[u8], value: &[u8]) -> HPACKField {
        HPACKField { name: name.to_vec(), value: value.to_vec(), sensitive: true }
    }

    /// The size the field takes in a table and a field list: its name and
    /// value and 32 bytes (RFC 7541 §4.1, RFC 9113 §6.5.2).
    pub fn size(&self) -> usize {
        super::HPACKDynamicTable::entry_size(&self.name, &self.value)
    }
}
