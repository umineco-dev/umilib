use alloc::vec::Vec;

use super::{CompressionError, Progress};

/// What a [`Compressor`] does with the input it has buffered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flush {
    /// Keeps it until a block is full, for the best compression.
    None,
    /// Compresses it and writes everything a decompressor needs to recover
    /// it so far, without ending the stream (as a sync flush of zlib does).
    Sync,
    /// Compresses it and ends the stream; later calls must keep `Finish`
    /// until [`Progress::finished`], then the compressor is [`Compressor::reset`] to reuse it.
    Finish,
}

/// A streaming compressor without I/O: each call consumes what it can of
/// `input` and writes what it can into `output`, buffering the rest
/// internally (up to a block of its format); the caller calls again with
/// the remaining input or a fresh output.
pub trait Compressor {
    /// Compresses from `input` into `output`, as [`Flush`] asks.
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError>;

    /// Returns to the state of a new stream, keeping the parameters.
    fn reset(&mut self);

    /// The whole stream of `input` (compressed and finished) in a new vector.
    fn compress_to_vec(&mut self, mut input: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let progress = self.compress(input, &mut chunk, Flush::Finish)?;
            input = &input[progress.consumed..];
            out.extend_from_slice(&chunk[..progress.produced]);
            if progress.finished {
                return Ok(out);
            }
        }
    }
}
