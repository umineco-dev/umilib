use alloc::vec;
use alloc::vec::Vec;

use super::AdaptiveHuffmanNode;
use crate::codec::huffman::HuffmanError;

/// The code tree of adaptive Huffman coding by Vitter's algorithm Λ (J. S.
/// Vitter, "Design and Analysis of Dynamic Huffman Codes", JACM 34(4),
/// 1987): after each symbol, [`AdaptiveHuffmanTree::update`] makes the tree
/// a Huffman tree of the counts of the symbols so far that also minimizes
/// the sum and the maximum of the depths of its leaves.
///
/// Nodes are kept at positions ordered by weight (the implicit numbering of
/// Vitter): a node's weight is at most the weight of every node at a higher
/// position, the leaves of a weight precede the internal nodes of that
/// weight, the two children of a node are at adjacent positions, the left
/// one even, and the root is at the highest position. A symbol that has not
/// occurred is sent as the code of the [`AdaptiveHuffmanNode::Unseen`] leaf
/// followed by its index in fixed-length bits: with symbols = 2^e + r
/// (0 <= r < 2^e), the symbol s as s in e + 1 bits if s < 2r and as s - r in
/// e bits otherwise, most significant bit first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptiveHuffmanTree {
    nodes: Vec<AdaptiveHuffmanNode>,
    weights: Vec<u64>,
    /// The position of the parent of the node at each position; NONE for the root.
    parents: Vec<u32>,
    /// The position of the leaf of each symbol; NONE before it occurs.
    positions: Vec<u32>,
    unseen: u32,
}

impl AdaptiveHuffmanTree {
    /// The most symbols of an alphabet.
    pub const MAXIMUM_SYMBOLS: usize = 1 << 15;
    /// The position of no node.
    pub const NONE: u32 = u32::MAX;

    /// The tree of an alphabet of `symbols` symbols (2 to
    /// [`AdaptiveHuffmanTree::MAXIMUM_SYMBOLS`]) before any occurred: the
    /// [`AdaptiveHuffmanNode::Unseen`] leaf alone.
    pub fn new(symbols: usize) -> Result<AdaptiveHuffmanTree, HuffmanError> {
        if !(2..=AdaptiveHuffmanTree::MAXIMUM_SYMBOLS).contains(&symbols) {
            return Err(HuffmanError::InvalidAlphabet { maximum: AdaptiveHuffmanTree::MAXIMUM_SYMBOLS });
        }
        // A leaf for each symbol and the unseen leaf, and an internal node for each symbol.
        let count = 2 * symbols + 1;
        let root = (count - 1) as u32;
        let mut nodes = vec![AdaptiveHuffmanNode::Unused; count];
        nodes[root as usize] = AdaptiveHuffmanNode::Unseen;
        Ok(AdaptiveHuffmanTree {
            nodes,
            weights: vec![0; count],
            parents: vec![AdaptiveHuffmanTree::NONE; count],
            positions: vec![AdaptiveHuffmanTree::NONE; symbols],
            unseen: root,
        })
    }

    /// The number of symbols of the alphabet.
    pub fn symbols(&self) -> usize {
        self.positions.len()
    }

    /// The position of the root.
    pub fn root(&self) -> u32 {
        (self.nodes.len() - 1) as u32
    }

    pub fn node(&self, position: u32) -> AdaptiveHuffmanNode {
        self.nodes[position as usize]
    }

    /// The number of occurrences the subtree at `position` counts.
    pub fn weight(&self, position: u32) -> u64 {
        self.weights[position as usize]
    }

    /// The position of the parent of the node at `position`; NONE for the root.
    pub fn parent(&self, position: u32) -> u32 {
        self.parents[position as usize]
    }

    /// The position of the leaf of `symbol`; `None` before it occurs.
    pub fn position(&self, symbol: usize) -> Option<u32> {
        let position = self.positions[symbol];
        (position != AdaptiveHuffmanTree::NONE).then_some(position)
    }

    /// The position of the [`AdaptiveHuffmanNode::Unseen`] leaf.
    pub fn unseen(&self) -> u32 {
        self.unseen
    }

    /// (e, r) with symbols = 2^e + r and 0 <= r < 2^e: the fixed-length
    /// index of an unseen symbol takes e or e + 1 bits.
    pub fn index_parameters(&self) -> (u32, u32) {
        let symbols = self.symbols() as u32;
        let e = symbols.ilog2();
        (e, symbols - (1 << e))
    }

    /// The fixed-length index of an unseen `symbol`: its value and its number of bits.
    pub fn index(&self, symbol: usize) -> (u32, u32) {
        let (e, r) = self.index_parameters();
        let symbol = symbol as u32;
        if symbol < 2 * r { (symbol, e + 1) } else { (symbol - r, e) }
    }

    /// The code of `symbol` in the current tree (with the index of an
    /// unseen symbol): its bits, the first the least significant, and their
    /// number. The depth of a leaf is below 93 for counts below 2^64, so a
    /// code fits 128 bits.
    pub fn code(&self, symbol: usize) -> (u128, u32) {
        let (leaf, index) = match self.position(symbol) {
            Some(position) => (position, (0, 0)),
            None => (self.unseen, self.index(symbol)),
        };
        // The bits of the path, read from the leaf up: the last one read is the first.
        let (mut bits, mut length) = (0u128, 0u32);
        let mut position = leaf;
        while position != self.root() {
            bits = bits << 1 | (position & 1) as u128;
            length += 1;
            position = self.parent(position);
        }
        // The index follows, most significant bit first.
        let (value, count) = index;
        for bit in (0..count).rev() {
            bits |= (((value >> bit) & 1) as u128) << length;
            length += 1;
        }
        (bits, length)
    }

    /// The position the bit `bit` leads to from the internal node at `position`.
    pub fn child(&self, position: u32, bit: u32) -> u32 {
        match self.node(position) {
            AdaptiveHuffmanNode::Internal { left } => left + (bit & 1),
            _ => AdaptiveHuffmanTree::NONE,
        }
    }

    /// The symbol whose fixed-length index is the `count` bits `value`
    /// (the inverse of [`AdaptiveHuffmanTree::index`]); `None` if no symbol has it.
    pub fn symbol_of_index(&self, value: u32, count: u32) -> Option<usize> {
        let (e, r) = self.index_parameters();
        let symbol = if count == e + 1 && value < 2 * r {
            value
        } else if count == e && (r..1 << e).contains(&value) {
            value + r
        } else {
            return None;
        };
        Some(symbol as usize)
    }

    /// Whether the index whose first e bits are `value` has a bit e + 1.
    pub fn index_continues(&self, value: u32) -> bool {
        value < self.index_parameters().1
    }

    /// Counts an occurrence of `symbol` and restores the invariants of the
    /// tree (procedure Update of algorithm Λ).
    pub fn update(&mut self, symbol: usize) {
        let mut leaf_to_increment = AdaptiveHuffmanTree::NONE;
        let mut position = match self.position(symbol) {
            None => {
                // The unseen leaf becomes an internal node over a new unseen leaf and the symbol's leaf.
                let parent = self.unseen;
                let left = parent - 2;
                self.nodes[parent as usize] = AdaptiveHuffmanNode::Internal { left };
                self.nodes[left as usize] = AdaptiveHuffmanNode::Unseen;
                self.nodes[left as usize + 1] = AdaptiveHuffmanNode::Leaf { symbol: symbol as u16 };
                self.parents[left as usize] = parent;
                self.parents[left as usize + 1] = parent;
                self.positions[symbol] = left + 1;
                self.unseen = left;
                leaf_to_increment = left + 1;
                parent
            }
            Some(position) => {
                let leader = self.leader(position);
                self.swap(position, leader);
                if self.parent(leader) == self.parent(self.unseen) {
                    // Its parent has its weight: the leaf is incremented after it.
                    leaf_to_increment = leader;
                    self.parent(leader)
                } else {
                    leader
                }
            }
        };
        while position != AdaptiveHuffmanTree::NONE {
            position = self.slide_and_increment(position);
        }
        if leaf_to_increment != AdaptiveHuffmanTree::NONE {
            self.slide_and_increment(leaf_to_increment);
        }
    }

    /// The highest position of the leaves of the weight of the leaf at `position`.
    pub fn leader(&self, position: u32) -> u32 {
        let weight = self.weight(position);
        let mut leader = position;
        while leader < self.root()
            && matches!(self.node(leader + 1), AdaptiveHuffmanNode::Leaf { .. })
            && self.weight(leader + 1) == weight
        {
            leader += 1;
        }
        leader
    }

    /// Moves the node at `position` above the nodes of the next block (the
    /// internal nodes of its weight w for a leaf, the leaves of weight w + 1
    /// for an internal node), increments its weight and returns the next
    /// node to increment: the new parent of a leaf, the former parent of an
    /// internal node (procedure SlideAndIncrement of algorithm Λ).
    pub fn slide_and_increment(&mut self, position: u32) -> u32 {
        let weight = self.weight(position);
        let internal = matches!(self.node(position), AdaptiveHuffmanNode::Internal { .. });
        let former_parent = self.parent(position);
        let mut current = position;
        while current < self.root() {
            let next = current + 1;
            let slides = match self.node(next) {
                AdaptiveHuffmanNode::Internal { .. } => !internal && self.weight(next) == weight,
                AdaptiveHuffmanNode::Leaf { .. } => internal && self.weight(next) == weight + 1,
                _ => false,
            };
            if !slides {
                break;
            }
            self.swap(current, next);
            current = next;
        }
        self.weights[current as usize] += 1;
        if internal { former_parent } else { self.parent(current) }
    }

    /// Exchanges the subtrees at the positions `a` and `b` (neither an
    /// ancestor of the other); the positions keep their parents.
    pub fn swap(&mut self, a: u32, b: u32) {
        self.nodes.swap(a as usize, b as usize);
        self.weights.swap(a as usize, b as usize);
        self.attach(a);
        self.attach(b);
    }

    /// Points the children, the symbol or the unseen leaf of the node at `position` to it.
    pub fn attach(&mut self, position: u32) {
        match self.node(position) {
            AdaptiveHuffmanNode::Internal { left } => {
                self.parents[left as usize] = position;
                self.parents[left as usize + 1] = position;
            }
            AdaptiveHuffmanNode::Leaf { symbol } => self.positions[symbol as usize] = position,
            AdaptiveHuffmanNode::Unseen => self.unseen = position,
            AdaptiveHuffmanNode::Unused => {}
        }
    }
}
