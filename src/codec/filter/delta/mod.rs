//! The Delta filter (.xz format specification, section 5.3.3): each byte
//! is replaced by its difference with the byte a distance of 1 to 256
//! before it.

use crate::codec::CompressionError;
use crate::codec::filter::Filter;

/// The Delta filter of a distance of 1 to 256 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaFilter {
    distance: usize,
    /// The last 256 bytes of the original data, `position` the slot of the next one (counting down).
    history: [u8; 256],
    position: u8,
}

impl DeltaFilter {
    /// The longest distance.
    pub const MAXIMUM_DISTANCE: usize = 256;

    /// A filter of `distance` (1 to 256) bytes; fails with `InvalidParameter` outside that range.
    pub fn new(distance: usize) -> Result<DeltaFilter, CompressionError> {
        if !(1..=DeltaFilter::MAXIMUM_DISTANCE).contains(&distance) {
            return Err(CompressionError::InvalidParameter);
        }
        Ok(DeltaFilter { distance, history: [0; 256], position: 0 })
    }

    pub fn distance(&self) -> usize {
        self.distance
    }

    /// The original byte `distance` bytes back (0 before the stream).
    pub fn previous(&self) -> u8 {
        self.history[self.position.wrapping_add(self.distance as u8) as usize]
    }

    /// Records the original byte `byte`.
    pub fn record(&mut self, byte: u8) {
        self.history[self.position as usize] = byte;
        self.position = self.position.wrapping_sub(1);
    }
}

impl Filter for DeltaFilter {
    fn lookahead(&self) -> usize {
        0
    }

    fn encode(&mut self, data: &mut [u8]) -> usize {
        for byte in data.iter_mut() {
            let original = *byte;
            *byte = original.wrapping_sub(self.previous());
            self.record(original);
        }
        data.len()
    }

    fn decode(&mut self, data: &mut [u8]) -> usize {
        for byte in data.iter_mut() {
            *byte = byte.wrapping_add(self.previous());
            self.record(*byte);
        }
        data.len()
    }

    fn reset(&mut self) {
        self.history = [0; 256];
        self.position = 0;
    }
}
