use super::{AdaptiveHuffmanCompressor, AdaptiveHuffmanFormat, AdaptiveHuffmanNode, AdaptiveHuffmanTree};
use crate::bytes::BitQueue;
use crate::codec::{CompressionError, Decompressor, Progress};

/// Where an [`AdaptiveHuffmanDecompressor`] is in its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdaptiveHuffmanState {
    /// Following a code from the root, at the node at `position`.
    Code { position: u32 },
    /// Reading the fixed-length index of an unseen symbol: `count` bits of value `value` so far.
    Index { value: u32, count: u32 },
    /// A decoded symbol to emit.
    Symbol { symbol: u16 },
    /// After the stream.
    End,
}

/// Decompresses the format of [`AdaptiveHuffmanFormat`] bit by bit; it
/// needs no buffer beyond its tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptiveHuffmanDecompressor {
    tree: AdaptiveHuffmanTree,
    queue: BitQueue,
    state: AdaptiveHuffmanState,
}

impl AdaptiveHuffmanDecompressor {
    pub fn new() -> AdaptiveHuffmanDecompressor {
        let tree = AdaptiveHuffmanCompressor::tree();
        let state = AdaptiveHuffmanState::Code { position: tree.root() };
        AdaptiveHuffmanDecompressor { tree, queue: BitQueue::new(), state }
    }

    pub fn state(&self) -> AdaptiveHuffmanState {
        self.state
    }
}

impl Default for AdaptiveHuffmanDecompressor {
    fn default() -> AdaptiveHuffmanDecompressor {
        AdaptiveHuffmanDecompressor::new()
    }
}

impl Decompressor for AdaptiveHuffmanDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let mut rest = input;
        let mut produced = 0;
        loop {
            match self.state {
                AdaptiveHuffmanState::Code { position } => match self.tree.node(position) {
                    AdaptiveHuffmanNode::Internal { .. } => {
                        let Some(bit) = self.queue.read_from(1, &mut rest) else { break };
                        self.state = AdaptiveHuffmanState::Code { position: self.tree.child(position, bit as u32) };
                    }
                    AdaptiveHuffmanNode::Leaf { symbol } => self.state = AdaptiveHuffmanState::Symbol { symbol },
                    AdaptiveHuffmanNode::Unseen => self.state = AdaptiveHuffmanState::Index { value: 0, count: 0 },
                    AdaptiveHuffmanNode::Unused => unreachable!("codes lead to nodes of the tree"),
                },
                AdaptiveHuffmanState::Index { value, count } => {
                    let (e, _) = self.tree.index_parameters();
                    if count < e || (count == e && self.tree.index_continues(value)) {
                        let Some(bit) = self.queue.read_from(1, &mut rest) else { break };
                        self.state = AdaptiveHuffmanState::Index { value: value << 1 | bit as u32, count: count + 1 };
                        continue;
                    }
                    // Every index of e or e + 1 bits read this way names a symbol.
                    let symbol = self
                        .tree
                        .symbol_of_index(value, count)
                        .ok_or(CompressionError::InvalidData { reason: "invalid symbol index" })?;
                    self.state = AdaptiveHuffmanState::Symbol { symbol: symbol as u16 };
                }
                AdaptiveHuffmanState::Symbol { symbol } => {
                    if symbol < 256 {
                        if produced == output.len() {
                            break;
                        }
                        output[produced] = symbol as u8;
                        produced += 1;
                    }
                    self.tree.update(symbol as usize);
                    self.state = AdaptiveHuffmanState::Code { position: self.tree.root() };
                    if symbol == AdaptiveHuffmanFormat::END || symbol == AdaptiveHuffmanFormat::FLUSH {
                        if self.queue.align() != 0 {
                            return Err(CompressionError::InvalidData { reason: "nonzero padding" });
                        }
                        if symbol == AdaptiveHuffmanFormat::END {
                            self.state = AdaptiveHuffmanState::End;
                        }
                    }
                }
                AdaptiveHuffmanState::End => break,
            }
        }
        let finished = self.state == AdaptiveHuffmanState::End;
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished })
    }

    fn finish(&mut self) -> Result<(), CompressionError> {
        if self.state == AdaptiveHuffmanState::End { Ok(()) } else { Err(CompressionError::UnexpectedEnd) }
    }

    fn reset(&mut self) {
        *self = AdaptiveHuffmanDecompressor::new();
    }
}
