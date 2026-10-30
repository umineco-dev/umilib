/// A CRC algorithm in the Rocksoft model, with the names of the RevEng
/// catalogue; [`CRCTable::new`](super::CRCTable) checks every value but the residue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CRCParameters<W> {
    /// The name in the catalogue, such as `CRC-32/ISO-HDLC`.
    pub name: &'static str,
    /// The number of bits of the register, 1 to the bits of `W`.
    pub width: u32,
    /// The generator polynomial without its highest term, most significant bit first.
    pub polynomial: W,
    /// The register before the first input bit, in the unreflected order.
    pub initial: W,
    /// Whether each input byte is read from its least significant bit.
    pub reflect_input: bool,
    /// Whether the register is reflected before the final xor.
    pub reflect_output: bool,
    /// The value xored into the output.
    pub xor_output: W,
    /// The output for the nine ASCII bytes `123456789`.
    pub check: W,
    /// The register after an error-free codeword, before the final xor (for
    /// codewords that fill whole bytes).
    pub residue: W,
}
