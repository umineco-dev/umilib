use alloc::vec::Vec;

use super::{CompressionError, Progress};

/// A streaming decompressor without I/O: each call consumes what it can of
/// `input` (buffering up to a unit of its format, such as a block) and
/// writes what it can into `output`. It stops when it needs more input or
/// more room; [`Progress::finished`] is set once the stream ended, and the
/// bytes after it are not consumed.
///
/// The streams of most formats mark their end. Those of a few (PackBits,
/// LZSS) end with their input: [`Decompressor::finish`] tells the
/// decompressor that the input ended.
///
/// A decompressor never writes more than its configured limit (an
/// exceeding stream fails with [`CompressionError::LimitExceeded`]) and
/// never buffers more than the units of its format allow, so that a small
/// input cannot make it allocate without bound.
pub trait Decompressor {
    /// Decompresses from `input` into `output`.
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError>;

    /// Tells the decompressor that the input ended with the bytes it
    /// consumed: succeeds if the stream may end there (it ended, or its
    /// format ends with the input at a whole unit) and fails with
    /// `UnexpectedEnd` otherwise. Calls of `decompress` that need more input
    /// come first, so that everything is written.
    fn finish(&mut self) -> Result<(), CompressionError>;

    /// Returns to the state of a new stream, keeping the configuration.
    fn reset(&mut self);

    /// The data of the stream in `input`, which must hold all of it, in a
    /// new vector of at most `limit` bytes; fails with `UnexpectedEnd` if the
    /// stream does not end within `input` (see [`Decompressor::finish`]) and
    /// `LimitExceeded` beyond `limit`. Bytes after the end of the stream are ignored.
    fn decompress_to_vec(&mut self, mut input: &[u8], limit: usize) -> Result<Vec<u8>, CompressionError> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let room = chunk.len().min((limit - out.len()).saturating_add(1));
            let progress = self.decompress(input, &mut chunk[..room])?;
            input = &input[progress.consumed..];
            out.extend_from_slice(&chunk[..progress.produced]);
            if out.len() > limit {
                return Err(CompressionError::LimitExceeded { limit: limit as u64 });
            }
            if progress.finished {
                return Ok(out);
            }
            if progress.consumed == 0 && progress.produced == 0 {
                self.finish()?;
                return Ok(out);
            }
        }
    }
}
