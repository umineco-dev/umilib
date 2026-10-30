/// The Internet checksum (RFC 1071): the 16-bit one's complement of the one's
/// complement sum of the data taken as big-endian 16-bit words, the last odd
/// byte padded with a zero byte. The sum is independent of how the data is
/// split between calls of [`InternetChecksum::update`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct InternetChecksum {
    /// The sum of the words so far, folded to at most 33 bits after every update.
    pub sum: u64,
    /// Whether an odd number of bytes was added: the next byte is the low byte of a word.
    pub odd: bool,
}

impl InternetChecksum {
    /// The bytes summed between two foldings of [`InternetChecksum::sum`]: their
    /// 32-bit words cannot overflow 64 bits.
    pub const CHUNK: usize = 1 << 16;

    pub const fn new() -> InternetChecksum {
        InternetChecksum { sum: 0, odd: false }
    }

    /// Adds `bytes`, which follow the bytes added before.
    pub fn update(&mut self, mut bytes: &[u8]) {
        // A sum set from outside may have more than 33 bits.
        self.sum = InternetChecksum::fold(self.sum) as u64;
        if self.odd {
            let Some((&first, rest)) = bytes.split_first() else { return };
            self.sum += first as u64;
            self.odd = false;
            bytes = rest;
        }
        for chunk in bytes.chunks(InternetChecksum::CHUNK) {
            // 32-bit words fold to the same sum as their 16-bit halves (RFC 1071 §2 (C)).
            let (words, rest) = chunk.as_chunks::<4>();
            for word in words {
                self.sum += u32::from_be_bytes(*word) as u64;
            }
            let (pairs, rest) = rest.as_chunks::<2>();
            for pair in pairs {
                self.sum += u16::from_be_bytes(*pair) as u64;
            }
            if let [last] = rest {
                self.sum += (*last as u64) << 8;
                self.odd = true;
            }
            self.sum = (self.sum & 0xFFFF_FFFF) + (self.sum >> 32);
        }
    }

    /// The one's complement sum of the bytes added, folded to 16 bits.
    pub fn sum16(&self) -> u16 {
        InternetChecksum::fold(self.sum)
    }

    /// The checksum of the bytes added: the one's complement of [`InternetChecksum::sum16`].
    pub fn finish(&self) -> u16 {
        !self.sum16()
    }

    /// The checksum of `bytes`.
    pub fn checksum(bytes: &[u8]) -> u16 {
        let mut checksum = InternetChecksum::new();
        checksum.update(bytes);
        checksum.finish()
    }

    /// Whether `bytes`, which contain their checksum field, sum to all one
    /// bits, as correct data does (RFC 1071 §1).
    pub fn verify(bytes: &[u8]) -> bool {
        let mut checksum = InternetChecksum::new();
        checksum.update(bytes);
        checksum.sum16() == 0xFFFF
    }

    /// The checksum `checksum` after a 16-bit word of the data changes from
    /// `old` to `new` (RFC 1624 §3, equation 3: `HC' = ~(~HC + ~m + m')`).
    pub fn adjust(checksum: u16, old: u16, new: u16) -> u16 {
        !InternetChecksum::fold(!checksum as u64 + !old as u64 + new as u64)
    }

    /// The checksum `checksum` after the bytes `old` of the data, which start
    /// at an even offset, change to `new` of the same length; `None` if the
    /// lengths differ.
    pub fn adjust_bytes(checksum: u16, old: &[u8], new: &[u8]) -> Option<u16> {
        if old.len() != new.len() {
            return None;
        }
        let mut sum = !checksum as u64;
        for (old, new) in old.chunks(2).zip(new.chunks(2)) {
            let word = |pair: &[u8]| u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
            sum += !word(old) as u64 + word(new) as u64;
            sum = (sum & 0xFFFF_FFFF) + (sum >> 32);
        }
        Some(!InternetChecksum::fold(sum))
    }

    /// `sum` folded to 16 bits by adding the carries back (end-around carry).
    pub fn fold(mut sum: u64) -> u16 {
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum as u16
    }
}
