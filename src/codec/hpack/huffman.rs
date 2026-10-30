use alloc::vec::Vec;

use crate::bytes::{BitOrder, BitQueue, BitWriter};
use crate::codec::huffman::canonical::{HuffmanCode, HuffmanTable};

use super::HPACKError;

/// The Huffman code of HPACK string literals (RFC 7541 Appendix B): a
/// canonical code of 257 symbols, the bytes and EOS, of 5 to 30 bits, the
/// first bit of each byte its most significant. A string ends with the
/// first bits of EOS as padding to a byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HPACKHuffman {
    pub code: HuffmanCode,
    pub table: HuffmanTable,
}

impl HPACKHuffman {
    /// The end-of-string symbol, which only pads.
    pub const EOS: usize = 256;
    /// The length of each symbol's code; the RFC's codes are the canonical
    /// codes of these lengths, which the tests check.
    pub const LENGTHS: [u8; 257] = [
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28,
        28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15,
        6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
        15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22,
        20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23,
        23, 24, 22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22,
        22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26,
        27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27,
        26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30,
    ];

    pub fn new() -> HPACKHuffman {
        let code = HuffmanCode::from_lengths(&HPACKHuffman::LENGTHS).expect("the lengths of RFC 7541 Appendix B");
        let table = HuffmanTable::new(&code, BitOrder::MostSignificantFirst);
        HPACKHuffman { code, table }
    }

    /// The bytes of `bytes` coded.
    pub fn encoded_length(&self, bytes: &[u8]) -> usize {
        let bits: usize = bytes.iter().map(|byte| HPACKHuffman::LENGTHS[*byte as usize] as usize).sum();
        bits.div_ceil(8)
    }

    /// Appends `bytes` coded, padded with the first bits of EOS (RFC 7541 §5.2).
    pub fn encode(&self, bytes: &[u8], out: &mut Vec<u8>) {
        let mut writer = BitWriter::with_order(BitOrder::MostSignificantFirst);
        for byte in bytes {
            writer.write(u64::from(self.code.code(*byte as usize)), self.code.length(*byte as usize));
        }
        let padding = (8 - writer.bit_length() % 8) % 8;
        writer.write(BitQueue::mask(padding as u32), padding as u32);
        out.extend_from_slice(&writer.finish());
    }

    /// Appends the bytes `bytes` code; fails with
    /// [`HPACKError::InvalidHuffman`] for the EOS symbol, padding longer
    /// than 7 bits or not of ones (RFC 7541 §5.2), and with
    /// [`HPACKError::StringTooLong`] past `limit` bytes of output.
    pub fn decode(&self, bytes: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), HPACKError> {
        let start = out.len();
        let mut queue = BitQueue::with_order(BitOrder::MostSignificantFirst);
        let mut input = bytes;
        while let Some(symbol) = self.table.read(&mut queue, &mut input).map_err(|_| HPACKError::InvalidHuffman)? {
            if symbol as usize == HPACKHuffman::EOS {
                return Err(HPACKError::InvalidHuffman);
            }
            if out.len() - start >= limit {
                return Err(HPACKError::StringTooLong);
            }
            out.push(symbol as u8);
        }
        let padding = queue.count();
        if padding > 7 || queue.peek_padded(padding) != BitQueue::mask(padding) {
            return Err(HPACKError::InvalidHuffman);
        }
        Ok(())
    }
}

impl Default for HPACKHuffman {
    fn default() -> HPACKHuffman {
        HPACKHuffman::new()
    }
}
