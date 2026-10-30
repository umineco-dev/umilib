/// What one call of a [`Compressor`](super::Compressor) or a
/// [`Decompressor`](super::Decompressor) did: the bytes it consumed from
/// its input and produced into its output, and whether the stream ended
/// (every byte of it written, for a compressor finishing; its end reached,
/// for a decompressor).
/// The layout is C's, so that the C ABI writes it as it is.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub consumed: usize,
    pub produced: usize,
    pub finished: bool,
}
