use super::{LZMAModel, LZMAProperties, LZMARangeEncoder};
use crate::codec::CompressionError;
use crate::codec::lz77::{LZ77MatchFinder, LZ77MatchFinderConfig};

/// The search of an LZMA encoder level (0 to 9): the dictionary (as xz's
/// presets size it), the candidates examined and the length that ends a search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZMALevel {
    pub dictionary_size: usize,
    pub chain_limit: usize,
    pub nice_length: usize,
}

impl LZMALevel {
    pub const LEVELS: [LZMALevel; 10] = [
        LZMALevel { dictionary_size: 1 << 18, chain_limit: 4, nice_length: 32 },
        LZMALevel { dictionary_size: 1 << 20, chain_limit: 8, nice_length: 64 },
        LZMALevel { dictionary_size: 1 << 21, chain_limit: 16, nice_length: 128 },
        LZMALevel { dictionary_size: 1 << 22, chain_limit: 24, nice_length: 128 },
        LZMALevel { dictionary_size: 1 << 22, chain_limit: 32, nice_length: 128 },
        LZMALevel { dictionary_size: 1 << 23, chain_limit: 48, nice_length: 273 },
        LZMALevel { dictionary_size: 1 << 23, chain_limit: 64, nice_length: 273 },
        LZMALevel { dictionary_size: 1 << 24, chain_limit: 128, nice_length: 273 },
        LZMALevel { dictionary_size: 1 << 25, chain_limit: 256, nice_length: 273 },
        LZMALevel { dictionary_size: 1 << 26, chain_limit: 512, nice_length: 273 },
    ];
}

/// A decision of the encoder at a position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LZMAChoice {
    Literal,
    /// A match of `length` bytes `distance` (zero-based) back.
    Match {
        distance: u32,
        length: usize,
    },
    /// A match of `length` bytes at the distance `index` of the 4 last ones.
    Rep {
        index: usize,
        length: usize,
    },
    /// One byte at the last distance.
    ShortRep,
}

/// The core of an LZMA encoder: the model, the match finder (whose data are
/// the history and the input to encode) and a range encoder, with greedy
/// parsing that prefers repeated distances and defers a match by one byte
/// when the next position has a longer one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZMAEncoder {
    pub model: LZMAModel,
    pub range: LZMARangeEncoder,
    pub finder: LZ77MatchFinder,
    /// The position in the finder's data of the next byte to encode.
    pub position: usize,
    /// The bytes encoded since the dictionary was reset (the context of positions).
    pub total: u64,
    pub dictionary_size: usize,
    pub nice_length: usize,
}

impl LZMAEncoder {
    /// An encoder of `properties`, a dictionary of `dictionary_size` bytes
    /// (4 KiB to 1.5 GiB) and the search of `level`.
    pub fn new(
        properties: LZMAProperties,
        dictionary_size: usize,
        level: &LZMALevel,
    ) -> Result<LZMAEncoder, CompressionError> {
        if !(1 << 12..=3 << 29).contains(&dictionary_size) {
            return Err(CompressionError::InvalidParameter);
        }
        let window_bits = usize::BITS - (dictionary_size - 1).leading_zeros();
        let finder = LZ77MatchFinder::new(LZ77MatchFinderConfig {
            window_bits: window_bits.clamp(8, 30),
            chain_bits: window_bits.clamp(8, 22),
            hash_bits: 18,
            maximum_distance: dictionary_size,
            minimum_length: 3,
            maximum_length: LZMAModel::MAXIMUM_MATCH as usize,
            chain_limit: level.chain_limit,
            nice_length: level.nice_length,
        })?;
        Ok(LZMAEncoder {
            model: LZMAModel::new(properties),
            range: LZMARangeEncoder::new(),
            finder,
            position: 0,
            total: 0,
            dictionary_size,
            nice_length: level.nice_length,
        })
    }

    /// Forgets the data (a dictionary reset), keeping the model.
    pub fn clear(&mut self) {
        self.finder.clear();
        self.position = 0;
        self.total = 0;
    }

    /// The bytes of the data at `position` that equal those `distance` + 1 back, up to `limit`.
    pub fn match_length(&self, position: usize, distance: u32, limit: usize) -> usize {
        let back = distance as usize + 1;
        if back > position || back as u64 > self.total + (position - self.position) as u64 {
            return 0;
        }
        let data = self.finder.data();
        (0..limit).take_while(|index| data[position + index] == data[position - back + index]).count()
    }

    /// The decision at the current position, with `available` bytes after it.
    pub fn choose(&mut self, available: usize) -> LZMAChoice {
        let limit = available.min(LZMAModel::MAXIMUM_MATCH as usize);
        if limit < LZMAModel::MINIMUM_MATCH as usize {
            return self.short_rep_or_literal();
        }
        let (mut rep_index, mut rep_length) = (0, 0);
        for index in 0..4 {
            let length = self.match_length(self.position, self.model.reps[index], limit);
            if length > rep_length {
                (rep_index, rep_length) = (index, length);
            }
        }
        if rep_length >= self.nice_length {
            return LZMAChoice::Rep { index: rep_index, length: rep_length };
        }
        let found = self.finder.find(self.position, limit);
        let main = found.map_or(0, |found| found.length);
        if main >= self.nice_length && main > rep_length {
            return self.as_rep(found.expect("a match").distance as u32 - 1, main);
        }
        if rep_length >= 2 && rep_length + 1 >= main {
            return LZMAChoice::Rep { index: rep_index, length: rep_length };
        }
        if let Some(found) = found {
            // A longer match at the next position defers this one.
            if limit > main {
                let next = self.finder.find(self.position + 1, limit - 1).map_or(0, |next| next.length);
                if next > main + 1 {
                    return self.short_rep_or_literal();
                }
            }
            return self.as_rep(found.distance as u32 - 1, main);
        }
        self.short_rep_or_literal()
    }

    /// A match at `distance`, as a rep match if the distance is one of the last 4.
    pub fn as_rep(&self, distance: u32, length: usize) -> LZMAChoice {
        match self.model.reps.iter().position(|rep| *rep == distance) {
            Some(index) => LZMAChoice::Rep { index, length },
            None => LZMAChoice::Match { distance, length },
        }
    }

    /// A short rep match when the byte equals the byte at the last distance, otherwise a literal.
    pub fn short_rep_or_literal(&self) -> LZMAChoice {
        if self.match_length(self.position, self.model.reps[0], 1) == 1 && self.model.state >= LZMAModel::LITERAL_STATES
        {
            return LZMAChoice::ShortRep;
        }
        LZMAChoice::Literal
    }

    /// Encodes the next decision over the data and advances.
    pub fn encode_next(&mut self) {
        let available = self.finder.data().len() - self.position;
        let choice = self.choose(available);
        let length = match choice {
            LZMAChoice::Literal | LZMAChoice::ShortRep => 1,
            LZMAChoice::Match { length, .. } | LZMAChoice::Rep { length, .. } => length,
        };
        self.encode(choice);
        self.position += length;
        self.total += length as u64;
    }

    /// Encodes `choice` at the current position (the reverse of [`LZMADecoder::decode_symbol`](super::LZMADecoder::decode_symbol)).
    pub fn encode(&mut self, choice: LZMAChoice) {
        let LZMAModel { properties, probabilities, state: model_state, reps } = &mut self.model;
        let range = &mut self.range;
        let state = *model_state;
        let position_state = (self.total & ((1 << properties.position_bits) - 1)) as usize;
        let state2 = (state << LZMAModel::MAXIMUM_POSITION_BITS) + position_state;
        let data = self.finder.data();
        match choice {
            LZMAChoice::Literal => {
                range.encode_bit(probabilities, LZMAModel::IS_MATCH + state2, 0);
                let byte = data[self.position];
                let previous = if self.total > 0 { data[self.position - 1] } else { 0 };
                let low = (self.total & ((1 << properties.literal_position_bits) - 1)) as usize;
                let context = (low << properties.literal_context_bits)
                    + (previous as usize >> (8 - properties.literal_context_bits));
                let offset = LZMAModel::LITERAL + 0x300 * context;
                let mut symbol = 1usize;
                let mut matched = state >= LZMAModel::LITERAL_STATES;
                let mut match_byte = if matched { data[self.position - reps[0] as usize - 1] as usize } else { 0 };
                for bit in (0..8).rev() {
                    let bit = (byte >> bit) as usize & 1;
                    if matched {
                        let match_bit = (match_byte >> 7) & 1;
                        match_byte <<= 1;
                        range.encode_bit(probabilities, offset + ((1 + match_bit) << 8) + symbol, bit as u32);
                        matched = match_bit == bit;
                    } else {
                        range.encode_bit(probabilities, offset + symbol, bit as u32);
                    }
                    symbol = symbol << 1 | bit;
                }
                *model_state = LZMAModel::after_literal(state);
            }
            LZMAChoice::ShortRep => {
                range.encode_bit(probabilities, LZMAModel::IS_MATCH + state2, 1);
                range.encode_bit(probabilities, LZMAModel::IS_REP + state, 1);
                range.encode_bit(probabilities, LZMAModel::IS_REP_G0 + state, 0);
                range.encode_bit(probabilities, LZMAModel::IS_REP0_LONG + state2, 0);
                *model_state = LZMAModel::after_short_rep(state);
            }
            LZMAChoice::Rep { index, length } => {
                range.encode_bit(probabilities, LZMAModel::IS_MATCH + state2, 1);
                range.encode_bit(probabilities, LZMAModel::IS_REP + state, 1);
                if index == 0 {
                    range.encode_bit(probabilities, LZMAModel::IS_REP_G0 + state, 0);
                    range.encode_bit(probabilities, LZMAModel::IS_REP0_LONG + state2, 1);
                } else {
                    range.encode_bit(probabilities, LZMAModel::IS_REP_G0 + state, 1);
                    if index == 1 {
                        range.encode_bit(probabilities, LZMAModel::IS_REP_G1 + state, 0);
                    } else {
                        range.encode_bit(probabilities, LZMAModel::IS_REP_G1 + state, 1);
                        range.encode_bit(probabilities, LZMAModel::IS_REP_G2 + state, index as u32 - 2);
                    }
                    let distance = reps[index];
                    reps.copy_within(0..index, 1);
                    reps[0] = distance;
                }
                LZMAEncoder::encode_length(
                    range,
                    probabilities,
                    LZMAModel::REP_LENGTH,
                    position_state,
                    length as u32 - LZMAModel::MINIMUM_MATCH,
                );
                *model_state = LZMAModel::after_rep(state);
            }
            LZMAChoice::Match { distance, length } => {
                range.encode_bit(probabilities, LZMAModel::IS_MATCH + state2, 1);
                range.encode_bit(probabilities, LZMAModel::IS_REP + state, 0);
                let length = length as u32 - LZMAModel::MINIMUM_MATCH;
                LZMAEncoder::encode_length(range, probabilities, LZMAModel::LENGTH, position_state, length);
                LZMAEncoder::encode_distance(range, probabilities, length, distance);
                reps.copy_within(0..3, 1);
                reps[0] = distance;
                *model_state = LZMAModel::after_match(state);
            }
        }
    }

    /// Encodes the end marker: a match of length 2 at the distance 2^32.
    pub fn encode_end_marker(&mut self) {
        let LZMAModel { properties, probabilities, state, .. } = &mut self.model;
        let position_state = (self.total & ((1 << properties.position_bits) - 1)) as usize;
        let state2 = (*state << LZMAModel::MAXIMUM_POSITION_BITS) + position_state;
        self.range.encode_bit(probabilities, LZMAModel::IS_MATCH + state2, 1);
        self.range.encode_bit(probabilities, LZMAModel::IS_REP + *state, 0);
        LZMAEncoder::encode_length(&mut self.range, probabilities, LZMAModel::LENGTH, position_state, 0);
        LZMAEncoder::encode_distance(&mut self.range, probabilities, 0, u32::MAX);
        *state = LZMAModel::after_match(*state);
    }

    /// Encodes the zero-based `length` with the length coder at `offset`.
    pub fn encode_length(
        range: &mut LZMARangeEncoder,
        probabilities: &mut [u16],
        offset: usize,
        position_state: usize,
        length: u32,
    ) {
        if length < 8 {
            range.encode_bit(probabilities, offset + LZMAModel::LENGTH_CHOICE, 0);
            range.encode_tree(probabilities, offset + LZMAModel::LENGTH_LOW + (position_state << 3), 3, length);
        } else if length < 16 {
            range.encode_bit(probabilities, offset + LZMAModel::LENGTH_CHOICE, 1);
            range.encode_bit(probabilities, offset + LZMAModel::LENGTH_CHOICE2, 0);
            range.encode_tree(probabilities, offset + LZMAModel::LENGTH_MID + (position_state << 3), 3, length - 8);
        } else {
            range.encode_bit(probabilities, offset + LZMAModel::LENGTH_CHOICE, 1);
            range.encode_bit(probabilities, offset + LZMAModel::LENGTH_CHOICE2, 1);
            range.encode_tree(probabilities, offset + LZMAModel::LENGTH_HIGH, 8, length - 16);
        }
    }

    /// Encodes the zero-based `distance` of a match of zero-based `length`.
    pub fn encode_distance(range: &mut LZMARangeEncoder, probabilities: &mut [u16], length: u32, distance: u32) {
        let length_state = length.min(LZMAModel::LENGTH_TO_POSITION_STATES as u32 - 1) as usize;
        let slot = LZMAModel::distance_slot(distance);
        range.encode_tree(probabilities, LZMAModel::POSITION_SLOT + (length_state << 6), 6, slot);
        if slot < 4 {
            return;
        }
        let direct = (slot >> 1) - 1;
        let base = (2 | (slot & 1)) << direct;
        let rest = distance - base;
        if slot < LZMAModel::END_POSITION_MODEL_INDEX {
            range.encode_reverse_tree(
                probabilities,
                LZMAModel::POSITION_SPECIAL + base as usize - slot as usize,
                direct,
                rest,
            );
        } else {
            range.encode_direct_bits(rest >> LZMAModel::ALIGN_BITS, direct - LZMAModel::ALIGN_BITS);
            range.encode_reverse_tree(
                probabilities,
                LZMAModel::ALIGN,
                LZMAModel::ALIGN_BITS,
                rest & ((1 << LZMAModel::ALIGN_BITS) - 1),
            );
        }
    }
}
