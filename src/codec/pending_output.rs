use alloc::vec::Vec;

/// Bytes a [`Compressor`](super::Compressor) or a [`Decompressor`](super::Decompressor)
/// has made but not yet delivered, because the caller's output was full:
/// they are appended at the back and delivered from the front.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PendingOutput {
    bytes: Vec<u8>,
    delivered: usize,
}

impl PendingOutput {
    pub const fn new() -> PendingOutput {
        PendingOutput { bytes: Vec::new(), delivered: 0 }
    }

    /// The number of bytes not yet delivered.
    pub fn len(&self) -> usize {
        self.bytes.len() - self.delivered
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes not yet delivered.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[self.delivered..]
    }

    /// Appends `bytes`.
    pub fn extend(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// Copies the first pending bytes into `output`, as many as fit,
    /// returning the number copied.
    pub fn deliver(&mut self, output: &mut [u8]) -> usize {
        let count = output.len().min(self.len());
        output[..count].copy_from_slice(&self.bytes[self.delivered..self.delivered + count]);
        self.delivered += count;
        if self.delivered == self.bytes.len() {
            self.clear();
        }
        count
    }

    /// Drops every pending byte, keeping the allocation.
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.delivered = 0;
    }
}
