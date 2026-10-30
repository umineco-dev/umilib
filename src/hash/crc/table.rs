use super::{CRCParameters, CRCRegister};
use crate::hash::HashError;

/// The parameters of a CRC and its table of the register change for each
/// byte value. In the reflected order the register holds its value in the
/// lowest `width` bits; otherwise in the highest, so that one byte at a time
/// works for every width.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CRCTable<W> {
    parameters: CRCParameters<W>,
    entries: [W; 256],
}

/// Implements the constant construction of [`CRCTable`] for an unsigned
/// integer type; generic code cannot run in constants.
macro_rules! crc_table {
    ($($type:ty),*) => {$(
        impl CRCTable<$type> {
            /// The table of `parameters`; fails unless the width is 1 to the bits
            /// of the register, every value fits the width and `check` is the
            /// CRC of `123456789` (which catches mistyped parameters). The
            /// residue is not checked: it describes the algorithm and is not used.
            pub const fn new(parameters: CRCParameters<$type>) -> Result<CRCTable<$type>, HashError> {
                let width = parameters.width;
                let values = parameters.polynomial
                    | parameters.initial
                    | parameters.xor_output
                    | parameters.check
                    | parameters.residue;
                let fits = match values.checked_shr(width) {
                    Some(excess) => excess == 0,
                    None => true,
                };
                if width == 0 || width > <$type>::BITS || !fits {
                    return Err(HashError::InvalidParameter);
                }
                let mut entries = [0 as $type; 256];
                let mut index = 0;
                if parameters.reflect_input {
                    let polynomial = parameters.polynomial.reverse_bits() >> (<$type>::BITS - width);
                    while index < 256 {
                        let mut value = index as $type;
                        let mut bit = 0;
                        while bit < 8 {
                            value = if value & 1 == 1 { (value >> 1) ^ polynomial } else { value >> 1 };
                            bit += 1;
                        }
                        entries[index] = value;
                        index += 1;
                    }
                } else {
                    let polynomial = parameters.polynomial << (<$type>::BITS - width);
                    let top = 1 << (<$type>::BITS - 1);
                    while index < 256 {
                        let mut value = (index as $type) << (<$type>::BITS - 8);
                        let mut bit = 0;
                        while bit < 8 {
                            value = if value & top != 0 { (value << 1) ^ polynomial } else { value << 1 };
                            bit += 1;
                        }
                        entries[index] = value;
                        index += 1;
                    }
                }
                let table = CRCTable { parameters, entries };
                if table.const_checksum(b"123456789") != parameters.check {
                    return Err(HashError::InvalidParameter);
                }
                Ok(table)
            }

            /// The CRC of `data`, computable in constants, as
            /// [`CRC::checksum`](super::CRC::checksum) computes it.
            pub const fn const_checksum(&self, data: &[u8]) -> $type {
                let parameters = &self.parameters;
                let width = parameters.width;
                let bits = <$type>::BITS;
                let mut register = if parameters.reflect_input {
                    parameters.initial.reverse_bits() >> (bits - width)
                } else {
                    parameters.initial << (bits - width)
                };
                let mut index = 0;
                while index < data.len() {
                    register = if parameters.reflect_input {
                        let rest = match register.checked_shr(8) {
                            Some(rest) => rest,
                            None => 0,
                        };
                        self.entries[((register as u8) ^ data[index]) as usize] ^ rest
                    } else {
                        let rest = match register.checked_shl(8) {
                            Some(rest) => rest,
                            None => 0,
                        };
                        self.entries[((register >> (bits - 8)) as u8 ^ data[index]) as usize] ^ rest
                    };
                    index += 1;
                }
                let mut value = if parameters.reflect_input { register } else { register >> (bits - width) };
                if parameters.reflect_input != parameters.reflect_output {
                    value = value.reverse_bits() >> (bits - width);
                }
                value ^ parameters.xor_output
            }

            /// The table of a preset, whose parameters are valid.
            pub const fn preset(parameters: CRCParameters<$type>) -> CRCTable<$type> {
                match CRCTable::<$type>::new(parameters) {
                    Ok(table) => table,
                    Err(_) => panic!("invalid CRC parameters"),
                }
            }
        }
    )*};
}

crc_table!(u8, u16, u32, u64, u128);

impl<W: CRCRegister> CRCTable<W> {
    pub fn parameters(&self) -> &CRCParameters<W> {
        &self.parameters
    }

    pub fn entries(&self) -> &[W; 256] {
        &self.entries
    }

    /// The register before any input.
    pub fn initial_register(&self) -> W {
        let parameters = &self.parameters;
        if parameters.reflect_input {
            parameters.initial.reflect(parameters.width)
        } else {
            parameters.initial.shift_left(W::BITS - parameters.width)
        }
    }

    /// The register after the byte `byte`.
    pub fn step(&self, register: W, byte: u8) -> W {
        if self.parameters.reflect_input {
            self.entries[(register.low_byte() ^ byte) as usize] ^ register.shift_right(8)
        } else {
            self.entries[(register.high_byte() ^ byte) as usize] ^ register.shift_left(8)
        }
    }

    /// The register in the output order, before the final xor.
    pub fn remainder(&self, register: W) -> W {
        let parameters = &self.parameters;
        let value = if parameters.reflect_input { register } else { register.shift_right(W::BITS - parameters.width) };
        if parameters.reflect_input == parameters.reflect_output { value } else { value.reflect(parameters.width) }
    }
}
