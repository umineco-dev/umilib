use crate::secret::Zeroize;

/// The partial block of a block-based hash function.
///
/// [`BlockBuffer::update`] calls the compression function on every complete
/// block, directly from the input when no partial block is pending, and keeps
/// the rest. [`BlockBuffer::pad`] applies the padding of the Merkle–Damgård
/// functions (MD4, MD5, SHA-1, SHA-2, RIPEMD, SM3): a `1` bit, zeros, and
/// the message length.
///
/// The pending bytes are input, which may be secret: they are zeroized on
/// drop and not printed by `Debug`.
#[derive(Clone)]
pub struct BlockBuffer<const N: usize> {
    block: [u8; N],
    length: usize,
}

impl<const N: usize> BlockBuffer<N> {
    pub const fn new() -> BlockBuffer<N> {
        BlockBuffer { block: [0; N], length: 0 }
    }

    /// The number of bytes pending.
    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// The pending bytes.
    pub fn pending(&self) -> &[u8] {
        &self.block[..self.length]
    }

    /// Appends `data`, calling `compress` on every block it completes.
    pub fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8; N])) {
        if self.length > 0 {
            let taken = data.len().min(N - self.length);
            self.block[self.length..self.length + taken].copy_from_slice(&data[..taken]);
            self.length += taken;
            data = &data[taken..];
            if self.length < N {
                return;
            }
            compress(&self.block);
            self.length = 0;
        }
        let (blocks, rest) = data.as_chunks::<N>();
        for block in blocks {
            compress(block);
        }
        self.block[..rest.len()].copy_from_slice(rest);
        self.length = rest.len();
    }

    /// Appends the padding `0x80`, zeros and `length` (the encoded message
    /// length, which ends the last block), calling `compress` on the blocks.
    pub fn pad(&mut self, length: &[u8], mut compress: impl FnMut(&[u8; N])) {
        self.block[self.length] = 0x80;
        self.length += 1;
        if self.length > N - length.len() {
            self.block[self.length..].fill(0);
            compress(&self.block);
            self.length = 0;
        }
        self.block[self.length..N - length.len()].fill(0);
        self.block[N - length.len()..].copy_from_slice(length);
        compress(&self.block);
        self.length = 0;
    }

    /// Discards the pending bytes.
    pub fn reset(&mut self) {
        self.block.zeroize();
        self.length = 0;
    }
}

impl<const N: usize> Default for BlockBuffer<N> {
    fn default() -> BlockBuffer<N> {
        BlockBuffer::new()
    }
}

impl<const N: usize> Zeroize for BlockBuffer<N> {
    fn zeroize(&mut self) {
        self.block.zeroize();
        self.length.zeroize();
    }
}

impl<const N: usize> Drop for BlockBuffer<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> core::fmt::Debug for BlockBuffer<N> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "BlockBuffer({} of {N} bytes, ..)", self.length)
    }
}
