use super::{CRCRegister, CRCTable};
use crate::hash::Digest;

/// A CRC computation with a [`CRCTable`], such as one of
/// [`CRCCatalogue`](super::CRCCatalogue). As a [`Digest`] the output is the
/// value in big-endian order in the bytes of `W`.
#[derive(Clone, Copy, Debug)]
pub struct CRC<'a, W> {
    table: &'a CRCTable<W>,
    register: W,
}

impl<'a, W: CRCRegister> CRC<'a, W> {
    pub fn new(table: &'a CRCTable<W>) -> CRC<'a, W> {
        CRC { table, register: table.initial_register() }
    }

    /// The CRC of `data`.
    pub fn checksum(table: &'a CRCTable<W>, data: &[u8]) -> W {
        let mut crc = CRC::new(table);
        crc.update(data);
        crc.value()
    }

    pub fn table(&self) -> &'a CRCTable<W> {
        self.table
    }

    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.register = self.table.step(self.register, byte);
        }
    }

    /// The CRC of the input so far.
    pub fn value(&self) -> W {
        self.remainder() ^ self.table.parameters().xor_output
    }

    /// The CRC of the input so far before the final xor: after an
    /// error-free codeword of whole bytes, the residue of the parameters.
    pub fn remainder(&self) -> W {
        self.table.remainder(self.register)
    }

    pub fn reset(&mut self) {
        self.register = self.table.initial_register();
    }
}

impl<W: CRCRegister> Digest for CRC<'_, W> {
    const OUTPUT_SIZE: usize = W::SIZE;
    const BLOCK_SIZE: usize = 1;
    type Output = W::Bytes;

    fn update(&mut self, data: &[u8]) {
        CRC::update(self, data);
    }

    fn finalize(self) -> W::Bytes {
        self.value().to_be_bytes()
    }

    fn finalize_reset(&mut self) -> W::Bytes {
        let output = self.value().to_be_bytes();
        self.reset();
        output
    }

    fn reset(&mut self) {
        CRC::reset(self);
    }
}
