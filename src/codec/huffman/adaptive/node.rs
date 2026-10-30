/// A node of an [`AdaptiveHuffmanTree`](super::AdaptiveHuffmanTree).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdaptiveHuffmanNode {
    /// The leaf of a symbol that has occurred.
    Leaf { symbol: u16 },
    /// An internal node whose children are at the positions `left` (bit 0)
    /// and `left + 1` (bit 1).
    Internal { left: u32 },
    /// The leaf of weight 0 that stands for every symbol yet to occur (the
    /// "0-node" of Vitter).
    Unseen,
    /// A position the tree does not use yet.
    Unused,
}
