/// An incremental hash function with an output of fixed length.
///
/// ```ignore
/// let mut hash = SHA256::default();
/// hash.update(b"abc");
/// let digest: [u8; 32] = hash.finalize();
/// assert_eq!(SHA256::digest(b"abc"), digest);
/// ```
pub trait Digest: Clone {
    /// The number of bytes of the digest.
    const OUTPUT_SIZE: usize;
    /// The number of bytes the compression function takes at once (the `B`
    /// of HMAC, RFC 2104 section 2).
    const BLOCK_SIZE: usize;
    /// The digest: `[u8; OUTPUT_SIZE]`.
    type Output: AsRef<[u8]> + AsMut<[u8]> + Clone + Copy + Eq + core::fmt::Debug;

    /// Adds `data` to the hashed input.
    fn update(&mut self, data: &[u8]);

    /// The digest of the input so far; the state is consumed (and zeroed).
    fn finalize(self) -> Self::Output;

    /// Returns to the state of no input, keeping parameters such as keys.
    fn reset(&mut self);

    /// The digest of the input so far, then [`Digest::reset`].
    fn finalize_reset(&mut self) -> Self::Output {
        let output = self.clone().finalize();
        self.reset();
        output
    }

    /// The digest of `data` with the default parameters.
    fn digest(data: &[u8]) -> Self::Output
    where
        Self: Default,
    {
        let mut hash = Self::default();
        hash.update(data);
        hash.finalize()
    }
}
