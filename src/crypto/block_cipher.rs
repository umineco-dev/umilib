use crate::secret::Zeroize;

/// A block cipher: a keyed permutation of blocks of `BLOCK_SIZE` bytes.
///
/// The round keys are zeroized when the cipher is dropped. The functions of
/// several blocks let bitsliced implementations process blocks together;
/// they give the results of the functions of one block.
pub trait BlockCipher: Clone + Zeroize {
    /// The number of bytes of a block.
    const BLOCK_SIZE: usize;
    /// A block: `[u8; BLOCK_SIZE]`.
    type Block: AsRef<[u8]> + AsMut<[u8]> + Clone + Copy + Default + Eq + core::fmt::Debug;

    fn encrypt_block(&self, block: &mut Self::Block);

    fn decrypt_block(&self, block: &mut Self::Block);

    fn encrypt_blocks(&self, blocks: &mut [Self::Block]) {
        for block in blocks {
            self.encrypt_block(block);
        }
    }

    fn decrypt_blocks(&self, blocks: &mut [Self::Block]) {
        for block in blocks {
            self.decrypt_block(block);
        }
    }
}
