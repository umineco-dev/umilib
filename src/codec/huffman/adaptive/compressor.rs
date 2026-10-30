use super::{AdaptiveHuffmanFormat, AdaptiveHuffmanTree};
use crate::bytes::BitWriter;
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};

/// Compresses into the format of [`AdaptiveHuffmanFormat`], each byte as it comes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptiveHuffmanCompressor {
    tree: AdaptiveHuffmanTree,
    writer: BitWriter,
    pending: PendingOutput,
    /// Whether symbols were written since the last `FLUSH`.
    unflushed: bool,
    finished: bool,
}

impl AdaptiveHuffmanCompressor {
    pub fn new() -> AdaptiveHuffmanCompressor {
        AdaptiveHuffmanCompressor {
            tree: AdaptiveHuffmanCompressor::tree(),
            writer: BitWriter::new(),
            pending: PendingOutput::new(),
            unflushed: false,
            finished: false,
        }
    }

    /// The tree of the format before its first symbol.
    pub fn tree() -> AdaptiveHuffmanTree {
        AdaptiveHuffmanTree::new(AdaptiveHuffmanFormat::SYMBOLS).expect("258 symbols are a valid alphabet")
    }

    /// Writes the code of `symbol` and updates the tree.
    pub fn write_symbol(&mut self, symbol: u16) {
        let (mut bits, mut length) = self.tree.code(symbol as usize);
        while length > 0 {
            let count = length.min(BitWriter::MAXIMUM_BITS);
            self.writer.write(bits as u64, count);
            bits >>= count;
            length -= count;
        }
        self.tree.update(symbol as usize);
    }
}

impl Default for AdaptiveHuffmanCompressor {
    fn default() -> AdaptiveHuffmanCompressor {
        AdaptiveHuffmanCompressor::new()
    }
}

impl Compressor for AdaptiveHuffmanCompressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        let (mut consumed, mut produced) = (0, 0);
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() || self.finished {
                break;
            }
            // Encodes no more than the output has room for.
            let room = output.len() - produced;
            while consumed < input.len() && self.writer.completed().len() < room {
                self.write_symbol(input[consumed] as u16);
                consumed += 1;
                self.unflushed = true;
            }
            if consumed == input.len() {
                if flush == Flush::Finish {
                    self.write_symbol(AdaptiveHuffmanFormat::END);
                    self.writer.align();
                    self.finished = true;
                } else if flush == Flush::Sync && self.unflushed {
                    self.write_symbol(AdaptiveHuffmanFormat::FLUSH);
                    self.writer.align();
                    self.unflushed = false;
                }
            }
            self.pending.extend(self.writer.completed());
            self.writer.clear_completed();
            if self.pending.is_empty() {
                break;
            }
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        *self = AdaptiveHuffmanCompressor::new();
    }
}
