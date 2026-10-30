/// A filter: a reversible transformation of data that keeps its size,
/// done in place on successive pieces of a stream (the filters of .xz and
/// .7z that prepare data for a compressor).
///
/// A filter may need the bytes after a position to convert the bytes at it
/// (an instruction that continues in the next piece): `encode` and `decode`
/// convert what they can and return how many bytes they converted; the
/// bytes after those, at most [`Filter::lookahead`] of them, are left as
/// they are and must be given again, at the start of the next call, with
/// the bytes that follow them. At the end of the stream, the bytes left
/// unconverted stay as they are (the same on both sides).
///
/// A filter object either encodes or decodes a stream; [`Filter::reset`]
/// starts a new stream.
pub trait Filter {
    /// The most bytes at the end of a piece that may be left unconverted.
    fn lookahead(&self) -> usize;

    /// Encodes the bytes of `data` it can, in place; returns how many.
    fn encode(&mut self, data: &mut [u8]) -> usize;

    /// Decodes the bytes of `data` it can, in place; returns how many.
    fn decode(&mut self, data: &mut [u8]) -> usize;

    /// Starts a new stream with the same parameters.
    fn reset(&mut self);
}
