use crate::crypto::BlockCipher;
use crate::secret::Zeroize;

/// Groups of blocks of a cipher, copied from and back to a byte slice, so
/// that the modes give bitsliced ciphers several blocks at once.
pub struct Blocks;

impl Blocks {
    /// The number of blocks of a group.
    pub const GROUP: usize = 8;

    /// Calls `operation` on the blocks of `data`, whose length must be a
    /// multiple of the block size, in order and in groups of up to
    /// [`Blocks::GROUP`], and writes the blocks back.
    pub fn apply<C: BlockCipher>(data: &mut [u8], mut operation: impl FnMut(&mut [C::Block])) {
        debug_assert!(data.len().is_multiple_of(C::BLOCK_SIZE));
        let mut group = [C::Block::default(); Blocks::GROUP];
        for chunk in data.chunks_mut(Blocks::GROUP * C::BLOCK_SIZE) {
            let count = chunk.len() / C::BLOCK_SIZE;
            for (block, bytes) in group.iter_mut().zip(chunk.chunks(C::BLOCK_SIZE)) {
                block.as_mut().copy_from_slice(bytes);
            }
            operation(&mut group[..count]);
            for (block, bytes) in group.iter().zip(chunk.chunks_mut(C::BLOCK_SIZE)) {
                bytes.copy_from_slice(block.as_ref());
            }
        }
        for block in group.iter_mut() {
            block.as_mut().zeroize();
        }
    }

    /// A block of `C` with the bytes of `bytes`, which must have the block size.
    pub fn block<C: BlockCipher>(bytes: &[u8]) -> C::Block {
        let mut block = C::Block::default();
        block.as_mut().copy_from_slice(bytes);
        block
    }

    /// `target ^= source`, byte by byte over the shorter length.
    pub fn xor(target: &mut [u8], source: &[u8]) {
        for (byte, value) in target.iter_mut().zip(source) {
            *byte ^= value;
        }
    }
}
