use core::fmt;

use crate::crypto::random::Random;

use super::QUICError;

/// A connection ID of QUIC versions 1 and 2: 0 to 20 bytes (RFC 9000 §5.1,
/// §17.2), kept inline so that it is copied without allocation. The bytes
/// past the length are always zero, so that equal IDs compare equal.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct QUICConnectionID {
    length: u8,
    bytes: [u8; QUICConnectionID::MAXIMUM_LENGTH],
}

impl QUICConnectionID {
    /// The longest connection ID of versions 1 and 2 (RFC 9000 §17.2).
    pub const MAXIMUM_LENGTH: usize = 20;
    /// The empty connection ID.
    pub const EMPTY: QUICConnectionID = QUICConnectionID { length: 0, bytes: [0; QUICConnectionID::MAXIMUM_LENGTH] };

    /// The connection ID of `bytes`, or `None` if it is longer than 20 bytes.
    pub fn new(bytes: &[u8]) -> Option<QUICConnectionID> {
        let mut id = QUICConnectionID::EMPTY;
        id.bytes.get_mut(..bytes.len())?.copy_from_slice(bytes);
        id.length = bytes.len() as u8;
        Some(id)
    }

    /// A connection ID of `length` random bytes; fails with
    /// [`QUICError::Config`] for a length above 20, or [`QUICError::Random`].
    pub fn random(length: usize, random: &mut (impl Random + ?Sized)) -> Result<QUICConnectionID, QUICError> {
        if length > QUICConnectionID::MAXIMUM_LENGTH {
            return Err(QUICError::Config);
        }
        let mut id = QUICConnectionID { length: length as u8, ..QUICConnectionID::EMPTY };
        random.fill(&mut id.bytes[..length]).map_err(|_| QUICError::Random)?;
        Ok(id)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }

    pub const fn len(&self) -> usize {
        self.length as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

impl fmt::Debug for QUICConnectionID {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QUICConnectionID(")?;
        for byte in self.as_slice() {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}
