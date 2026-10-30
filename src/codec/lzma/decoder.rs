use alloc::vec::Vec;

use super::{LZMAModel, LZMAProperties, LZMARangeDecoder};
use crate::codec::CompressionError;
use crate::codec::lz77::LZ77Window;

/// A symbol of an LZMA stream: a literal, a match (simple, rep or short
/// rep: `distance` back, `length` bytes) or the end marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LZMASymbol {
    Literal(u8),
    Match { distance: usize, length: usize },
    End,
}

/// The core of an LZMA decoder (lzma-specification, "LZMA Decoding"): the
/// model, the range decoder and the window. [`LZMADecoder::decode`] decodes
/// one symbol, or undoes everything it changed when the input ends inside
/// the symbol, so that a streaming decoder can resume with more input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZMADecoder {
    pub model: LZMAModel,
    pub range: Option<LZMARangeDecoder>,
    pub window: LZ77Window,
    /// The dictionary size: no match reaches farther.
    pub dictionary_size: usize,
    undo: Vec<(u32, u16)>,
    /// The input a symbol needs that the last call did not have.
    held: Vec<u8>,
}

impl LZMADecoder {
    /// The most input bytes a symbol takes (the bits of a match, at most one byte each).
    pub const MAXIMUM_SYMBOL_INPUT: usize = 64;

    /// A decoder of `properties` keeping a window of `dictionary_size` bytes.
    pub fn new(properties: LZMAProperties, dictionary_size: usize) -> LZMADecoder {
        LZMADecoder {
            model: LZMAModel::new(properties),
            range: None,
            window: LZ77Window::new(dictionary_size),
            dictionary_size,
            undo: Vec::new(),
            held: Vec::new(),
        }
    }

    /// Whether input waits in the decoder.
    pub fn holds_input(&self) -> bool {
        !self.held.is_empty()
    }

    /// Starts the range decoder with the 5 bytes at the front of `input`
    /// (and those held); false if they are not all there yet.
    pub fn start(&mut self, input: &mut &[u8]) -> Result<bool, CompressionError> {
        let take = (5 - self.held.len()).min(input.len());
        self.held.extend_from_slice(&input[..take]);
        *input = &input[take..];
        if self.held.len() < 5 {
            return Ok(false);
        }
        let start: [u8; 5] = self.held[..5].try_into().expect("5 bytes");
        self.held.clear();
        self.range = Some(
            LZMARangeDecoder::new(start)
                .ok_or(CompressionError::InvalidData { reason: "invalid first byte of the range coder" })?,
        );
        Ok(true)
    }

    /// Decodes the next symbol from the bytes held and those at the front of
    /// `input`, which it advances past the bytes it takes (holding those of a
    /// symbol that is not complete yet); `None` if the input ended inside it.
    pub fn decode(&mut self, input: &mut &[u8]) -> Result<Option<LZMASymbol>, CompressionError> {
        if self.held.is_empty() && input.len() >= LZMADecoder::MAXIMUM_SYMBOL_INPUT {
            let mut position = 0;
            let symbol = self.decode_from(input, &mut position)?;
            *input = &input[position..];
            return Ok(symbol);
        }
        // Too little input to be sure of a whole symbol: try with what there is.
        let mut combined = core::mem::take(&mut self.held);
        let held = combined.len();
        let take = (LZMADecoder::MAXIMUM_SYMBOL_INPUT - held.min(LZMADecoder::MAXIMUM_SYMBOL_INPUT)).min(input.len());
        combined.extend_from_slice(&input[..take]);
        let mut position = 0;
        match self.decode_from(&combined, &mut position)? {
            Some(symbol) => {
                // The held bytes come first; the rest of the symbol came from the input.
                *input = &input[position.saturating_sub(held)..];
                combined.drain(..position.min(held));
                combined.truncate(held - position.min(held));
                self.held = combined;
                Ok(Some(symbol))
            }
            None => {
                if combined.len() >= LZMADecoder::MAXIMUM_SYMBOL_INPUT {
                    return Err(CompressionError::InvalidData { reason: "symbol longer than possible" });
                }
                *input = &input[take..];
                self.held = combined;
                Ok(None)
            }
        }
    }

    /// Decodes a symbol from `input` at `position`, or undoes it if the input ends inside it.
    pub fn decode_from(&mut self, input: &[u8], position: &mut usize) -> Result<Option<LZMASymbol>, CompressionError> {
        let saved = (self.range, self.model.state, self.model.reps, *position);
        self.undo.clear();
        let result = self.decode_symbol(input, position);
        if !matches!(result, Ok(Some(_))) {
            // Undo the probabilities in reverse, then the rest of the state.
            for (index, value) in self.undo.iter().rev() {
                self.model.probabilities[*index as usize] = *value;
            }
            (self.range, self.model.state, self.model.reps, *position) = saved;
        }
        result
    }

    /// The symbol at `position` of `input` (the main loop of the specification).
    pub fn decode_symbol(
        &mut self,
        input: &[u8],
        position: &mut usize,
    ) -> Result<Option<LZMASymbol>, CompressionError> {
        let range = self.range.as_mut().expect("started before decoding");
        let LZMAModel { properties, probabilities, state: model_state, reps } = &mut self.model;
        let undo = &mut self.undo;
        let total = self.window.total();
        let position_state = (total & ((1 << properties.position_bits) - 1)) as usize;
        let state = *model_state;
        let state2 = (state << LZMAModel::MAXIMUM_POSITION_BITS) + position_state;
        let Some(is_match) = range.decode_bit(probabilities, LZMAModel::IS_MATCH + state2, undo, input, position)
        else {
            return Ok(None);
        };
        if is_match == 0 {
            let previous = self.window.byte(1).unwrap_or(0);
            let low = (total & ((1 << properties.literal_position_bits) - 1)) as usize;
            let context =
                (low << properties.literal_context_bits) + (previous as usize >> (8 - properties.literal_context_bits));
            let offset = LZMAModel::LITERAL + 0x300 * context;
            let mut symbol = 1usize;
            if state >= LZMAModel::LITERAL_STATES {
                let mut match_byte = self.window.byte(reps[0] as usize + 1).unwrap_or(0) as usize;
                while symbol < 0x100 {
                    let match_bit = (match_byte >> 7) & 1;
                    match_byte <<= 1;
                    let Some(bit) = range.decode_bit(
                        probabilities,
                        offset + ((1 + match_bit) << 8) + symbol,
                        undo,
                        input,
                        position,
                    ) else {
                        return Ok(None);
                    };
                    symbol = symbol << 1 | bit as usize;
                    if match_bit != bit as usize {
                        break;
                    }
                }
            }
            while symbol < 0x100 {
                let Some(bit) = range.decode_bit(probabilities, offset + symbol, undo, input, position) else {
                    return Ok(None);
                };
                symbol = symbol << 1 | bit as usize;
            }
            *model_state = LZMAModel::after_literal(state);
            return Ok(Some(LZMASymbol::Literal((symbol - 0x100) as u8)));
        }
        let Some(is_rep) = range.decode_bit(probabilities, LZMAModel::IS_REP + state, undo, input, position) else {
            return Ok(None);
        };
        let length;
        if is_rep == 1 {
            if self.window.is_empty() {
                return Err(CompressionError::InvalidData { reason: "repeated match before any data" });
            }
            let Some(g0) = range.decode_bit(probabilities, LZMAModel::IS_REP_G0 + state, undo, input, position) else {
                return Ok(None);
            };
            if g0 == 0 {
                let Some(long) =
                    range.decode_bit(probabilities, LZMAModel::IS_REP0_LONG + state2, undo, input, position)
                else {
                    return Ok(None);
                };
                if long == 0 {
                    *model_state = LZMAModel::after_short_rep(state);
                    return Ok(Some(LZMASymbol::Match { distance: reps[0] as usize + 1, length: 1 }));
                }
            } else {
                let Some(g1) = range.decode_bit(probabilities, LZMAModel::IS_REP_G1 + state, undo, input, position)
                else {
                    return Ok(None);
                };
                let index = if g1 == 0 {
                    1
                } else {
                    let Some(g2) = range.decode_bit(probabilities, LZMAModel::IS_REP_G2 + state, undo, input, position)
                    else {
                        return Ok(None);
                    };
                    2 + g2 as usize
                };
                let distance = reps[index];
                reps.copy_within(0..index, 1);
                reps[0] = distance;
            }
            let Some(decoded) = LZMADecoder::decode_length(
                range,
                probabilities,
                LZMAModel::REP_LENGTH,
                position_state,
                undo,
                input,
                position,
            ) else {
                return Ok(None);
            };
            length = decoded;
            *model_state = LZMAModel::after_rep(state);
        } else {
            reps.copy_within(0..3, 1);
            let Some(decoded) = LZMADecoder::decode_length(
                range,
                probabilities,
                LZMAModel::LENGTH,
                position_state,
                undo,
                input,
                position,
            ) else {
                return Ok(None);
            };
            length = decoded;
            *model_state = LZMAModel::after_match(state);
            let Some(distance) = LZMADecoder::decode_distance(range, probabilities, length, undo, input, position)
            else {
                return Ok(None);
            };
            reps[0] = distance;
            if distance == u32::MAX {
                return Ok(Some(LZMASymbol::End));
            }
            if distance as usize >= self.dictionary_size || distance as u64 >= self.window.total() {
                return Err(CompressionError::InvalidData { reason: "distance beyond the data" });
            }
        }
        Ok(Some(LZMASymbol::Match {
            distance: reps[0] as usize + 1,
            length: (length + LZMAModel::MINIMUM_MATCH) as usize,
        }))
    }

    /// The zero-based length of the length coder at `offset`.
    pub fn decode_length(
        range: &mut LZMARangeDecoder,
        probabilities: &mut [u16],
        offset: usize,
        position_state: usize,
        undo: &mut Vec<(u32, u16)>,
        input: &[u8],
        position: &mut usize,
    ) -> Option<u32> {
        if range.decode_bit(probabilities, offset + LZMAModel::LENGTH_CHOICE, undo, input, position)? == 0 {
            return range.decode_tree(
                probabilities,
                offset + LZMAModel::LENGTH_LOW + (position_state << 3),
                3,
                undo,
                input,
                position,
            );
        }
        if range.decode_bit(probabilities, offset + LZMAModel::LENGTH_CHOICE2, undo, input, position)? == 0 {
            return Some(
                8 + range.decode_tree(
                    probabilities,
                    offset + LZMAModel::LENGTH_MID + (position_state << 3),
                    3,
                    undo,
                    input,
                    position,
                )?,
            );
        }
        Some(16 + range.decode_tree(probabilities, offset + LZMAModel::LENGTH_HIGH, 8, undo, input, position)?)
    }

    /// The zero-based distance of a match of zero-based `length`.
    pub fn decode_distance(
        range: &mut LZMARangeDecoder,
        probabilities: &mut [u16],
        length: u32,
        undo: &mut Vec<(u32, u16)>,
        input: &[u8],
        position: &mut usize,
    ) -> Option<u32> {
        let length_state = length.min(LZMAModel::LENGTH_TO_POSITION_STATES as u32 - 1) as usize;
        let slot = range.decode_tree(
            probabilities,
            LZMAModel::POSITION_SLOT + (length_state << 6),
            6,
            undo,
            input,
            position,
        )?;
        if slot < 4 {
            return Some(slot);
        }
        let direct = (slot >> 1) - 1;
        let base = (2 | (slot & 1)) << direct;
        if slot < LZMAModel::END_POSITION_MODEL_INDEX {
            let offset = LZMAModel::POSITION_SPECIAL + base as usize - slot as usize;
            return Some(base + range.decode_reverse_tree(probabilities, offset, direct, undo, input, position)?);
        }
        let middle = range.decode_direct_bits(direct - LZMAModel::ALIGN_BITS, input, position)?;
        let align =
            range.decode_reverse_tree(probabilities, LZMAModel::ALIGN, LZMAModel::ALIGN_BITS, undo, input, position)?;
        Some(base.wrapping_add(middle << LZMAModel::ALIGN_BITS).wrapping_add(align))
    }

    /// Writes the literal or copies the match into `output` (as far as it
    /// has room) and the window; returns the bytes written.
    pub fn write(&mut self, symbol: LZMASymbol, output: &mut [u8]) -> Result<usize, CompressionError> {
        match symbol {
            LZMASymbol::Literal(byte) => {
                output[0] = byte;
                self.window.push(byte);
                Ok(1)
            }
            LZMASymbol::Match { distance, length } => self.window.copy(distance, length, output),
            LZMASymbol::End => Ok(0),
        }
    }

    /// Empties the input held.
    pub fn clear_held(&mut self) {
        self.held.clear();
    }
}
