/// An extendable-output function (XOF): any number of output bytes may be
/// read after the input, such as SHAKE (FIPS 202) or BLAKE3.
pub trait ExtendableOutput: Clone {
    /// The number of bytes the function absorbs at once (the rate of a sponge).
    const BLOCK_SIZE: usize;
    /// What reads the output.
    type Reader: XOFReader;

    /// Adds `data` to the input.
    fn update(&mut self, data: &[u8]);

    /// Ends the input and returns the reader of the output.
    fn finalize_xof(self) -> Self::Reader;

    /// Returns to the state of no input, keeping parameters.
    fn reset(&mut self);

    /// Writes the first `out.len()` bytes of the output for `data` into `out`.
    fn digest_xof(data: &[u8], out: &mut [u8])
    where
        Self: Default,
    {
        let mut function = Self::default();
        function.update(data);
        function.finalize_xof().read(out);
    }
}

/// Reads the output of an [`ExtendableOutput`] function; successive reads
/// continue where the previous one ended.
pub trait XOFReader {
    fn read(&mut self, out: &mut [u8]);
}
