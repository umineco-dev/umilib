use alloc::vec::Vec;

use super::PackBitsFormat;
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};

/// Compresses into the format of [`PackBitsFormat`]: runs of at least
/// [`PackBitsFormat::MINIMUM_REPEAT`] equal bytes as repeats, the other
/// bytes as copies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackBitsCompressor {
    /// Input not yet encoded: less than a run, unless the stream is flushed.
    buffer: Vec<u8>,
    pending: PendingOutput,
    finished: bool,
}

impl PackBitsCompressor {
    pub fn new() -> PackBitsCompressor {
        PackBitsCompressor::default()
    }

    /// The runs of `data`, all of it if `all`, otherwise those that more
    /// input cannot change; returns the bytes encoded.
    pub fn encode(data: &[u8], all: bool, out: &mut Vec<u8>) -> usize {
        let mut position = 0;
        let mut literal_start = 0;
        while position < data.len() {
            let byte = data[position];
            let run =
                data[position..].iter().take(PackBitsFormat::MAXIMUM_RUN).take_while(|other| **other == byte).count();
            // A run that reaches the end of the data could continue in the next input.
            if !all && position + run == data.len() {
                break;
            }
            if run >= PackBitsFormat::MINIMUM_REPEAT {
                PackBitsCompressor::copy(&data[literal_start..position], out);
                out.extend_from_slice(&[(257 - run) as u8, byte]);
                position += run;
                literal_start = position;
            } else {
                position += run;
            }
        }
        if !all {
            // Bytes before the undecided tail are copies, written in whole runs only.
            let whole = (position - literal_start) / PackBitsFormat::MAXIMUM_RUN * PackBitsFormat::MAXIMUM_RUN;
            PackBitsCompressor::copy(&data[literal_start..literal_start + whole], out);
            return literal_start + whole;
        }
        PackBitsCompressor::copy(&data[literal_start..], out);
        data.len()
    }

    /// Writes `bytes` as copies of at most 128 bytes.
    pub fn copy(bytes: &[u8], out: &mut Vec<u8>) {
        for chunk in bytes.chunks(PackBitsFormat::MAXIMUM_RUN) {
            out.push((chunk.len() - 1) as u8);
            out.extend_from_slice(chunk);
        }
    }
}

impl Compressor for PackBitsCompressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        let (mut consumed, mut produced) = (0, 0);
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() || self.finished {
                break;
            }
            // At most a few runs at a time, so that the output keeps up.
            let take =
                (input.len() - consumed).min((4 * PackBitsFormat::MAXIMUM_RUN).saturating_sub(self.buffer.len()));
            self.buffer.extend_from_slice(&input[consumed..consumed + take]);
            consumed += take;
            let all = consumed == input.len() && flush != Flush::None;
            let mut out = Vec::new();
            let encoded = PackBitsCompressor::encode(&self.buffer, all, &mut out);
            self.buffer.drain(..encoded);
            self.pending.extend(&out);
            if all && flush == Flush::Finish {
                self.finished = true;
            } else if self.pending.is_empty() && consumed == input.len() {
                break;
            }
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.pending.clear();
        self.finished = false;
    }
}
