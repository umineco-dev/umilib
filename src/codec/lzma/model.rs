use alloc::vec;
use alloc::vec::Vec;

use super::LZMAProperties;

/// The adaptive state of an LZMA coder: every probability (11-bit, in one
/// array, at the offsets of [`LZMAModel`]'s constants), the state (0 to 11)
/// and the last 4 distances (zero-based). Encoders and decoders keep the
/// same model and update it the same way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZMAModel {
    pub properties: LZMAProperties,
    pub probabilities: Vec<u16>,
    pub state: usize,
    pub reps: [u32; 4],
}

impl LZMAModel {
    /// The bits of a probability and the probability of an even chance.
    pub const PROBABILITY_BITS: u32 = 11;
    pub const PROBABILITY_INITIAL: u16 = 1 << 10;
    /// The shift of a probability's update.
    pub const MOVE_BITS: u32 = 5;
    pub const STATES: usize = 12;
    /// The states after which a literal is coded against the byte at rep0.
    pub const LITERAL_STATES: usize = 7;
    pub const MAXIMUM_POSITION_BITS: usize = 4;
    pub const LENGTH_TO_POSITION_STATES: usize = 4;
    pub const END_POSITION_MODEL_INDEX: u32 = 14;
    pub const FULL_DISTANCES: u32 = 1 << (LZMAModel::END_POSITION_MODEL_INDEX >> 1);
    pub const ALIGN_BITS: u32 = 4;
    pub const MINIMUM_MATCH: u32 = 2;
    pub const MAXIMUM_MATCH: u32 = 273;

    /// The offsets of the probabilities in the array.
    pub const IS_MATCH: usize = 0;
    pub const IS_REP: usize = LZMAModel::IS_MATCH + (LZMAModel::STATES << LZMAModel::MAXIMUM_POSITION_BITS);
    pub const IS_REP_G0: usize = LZMAModel::IS_REP + LZMAModel::STATES;
    pub const IS_REP_G1: usize = LZMAModel::IS_REP_G0 + LZMAModel::STATES;
    pub const IS_REP_G2: usize = LZMAModel::IS_REP_G1 + LZMAModel::STATES;
    pub const IS_REP0_LONG: usize = LZMAModel::IS_REP_G2 + LZMAModel::STATES;
    pub const POSITION_SLOT: usize = LZMAModel::IS_REP0_LONG + (LZMAModel::STATES << LZMAModel::MAXIMUM_POSITION_BITS);
    pub const POSITION_SPECIAL: usize = LZMAModel::POSITION_SLOT + (LZMAModel::LENGTH_TO_POSITION_STATES << 6);
    pub const ALIGN: usize = LZMAModel::POSITION_SPECIAL + 1 + LZMAModel::FULL_DISTANCES as usize
        - LZMAModel::END_POSITION_MODEL_INDEX as usize;
    pub const LENGTH: usize = LZMAModel::ALIGN + (1 << LZMAModel::ALIGN_BITS);
    pub const REP_LENGTH: usize = LZMAModel::LENGTH + LZMAModel::LENGTH_PROBABILITIES;
    pub const LITERAL: usize = LZMAModel::REP_LENGTH + LZMAModel::LENGTH_PROBABILITIES;
    /// A length coder: choice, choice 2, 16 low trees of 3 bits, 16 middle trees of 3 bits, a high tree of 8 bits.
    pub const LENGTH_PROBABILITIES: usize = 2 + 2 * (16 << 3) + (1 << 8);
    pub const LENGTH_CHOICE: usize = 0;
    pub const LENGTH_CHOICE2: usize = 1;
    pub const LENGTH_LOW: usize = 2;
    pub const LENGTH_MID: usize = 2 + (16 << 3);
    pub const LENGTH_HIGH: usize = 2 + 2 * (16 << 3);

    /// The model of `properties` in its initial state.
    pub fn new(properties: LZMAProperties) -> LZMAModel {
        let literals = 0x300usize << (properties.literal_context_bits + properties.literal_position_bits);
        LZMAModel {
            properties,
            probabilities: vec![LZMAModel::PROBABILITY_INITIAL; LZMAModel::LITERAL + literals],
            state: 0,
            reps: [0; 4],
        }
    }

    /// Returns to the initial state (with new `properties`).
    pub fn reset(&mut self, properties: LZMAProperties) {
        let literals = 0x300usize << (properties.literal_context_bits + properties.literal_position_bits);
        self.properties = properties;
        self.probabilities.clear();
        self.probabilities.resize(LZMAModel::LITERAL + literals, LZMAModel::PROBABILITY_INITIAL);
        self.state = 0;
        self.reps = [0; 4];
    }

    /// The low pb bits of `position`.
    pub fn position_state(&self, position: u64) -> usize {
        (position & ((1 << self.properties.position_bits) - 1)) as usize
    }

    /// The offset of the literal probabilities of the context of `position` and the previous byte.
    pub fn literal_offset(&self, position: u64, previous: u8) -> usize {
        let properties = &self.properties;
        let low = (position & ((1 << properties.literal_position_bits) - 1)) as usize;
        let context =
            (low << properties.literal_context_bits) + (previous as usize >> (8 - properties.literal_context_bits));
        LZMAModel::LITERAL + 0x300 * context
    }

    /// The state after a literal in `state` (UpdateState_Literal).
    pub const fn after_literal(state: usize) -> usize {
        match state {
            0..=3 => 0,
            4..=9 => state - 3,
            _ => state - 6,
        }
    }

    /// The state after a simple match.
    pub const fn after_match(state: usize) -> usize {
        if state < 7 { 7 } else { 10 }
    }

    /// The state after a rep match.
    pub const fn after_rep(state: usize) -> usize {
        if state < 7 { 8 } else { 11 }
    }

    /// The state after a short rep match.
    pub const fn after_short_rep(state: usize) -> usize {
        if state < 7 { 9 } else { 11 }
    }

    /// The distance slot of a zero-based distance: the distance in its slot's range.
    pub fn distance_slot(distance: u32) -> u32 {
        if distance < 4 {
            return distance;
        }
        let bits = 31 - distance.leading_zeros();
        2 * bits + ((distance >> (bits - 1)) & 1)
    }
}
