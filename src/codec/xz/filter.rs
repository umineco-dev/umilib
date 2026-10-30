use alloc::boxed::Box;
use alloc::vec::Vec;

use super::XZFormat;
use crate::codec::CompressionError;
use crate::codec::filter::Filter;
use crate::codec::filter::bcj::{BCJArchitecture, BCJFilter};
use crate::codec::filter::delta::DeltaFilter;
use crate::codec::lzma::LZMAFormat;

/// A filter of a .xz filter chain (section 5.3) with its properties.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XZFilter {
    /// LZMA2, the last filter, with the dictionary size its properties
    /// byte gives (4 KiB to 4 GiB - 1).
    LZMA2 { dictionary_size: u64 },
    /// Delta of a distance of 1 to 256 bytes.
    Delta { distance: u16 },
    /// A BCJ filter and its start offset (a multiple of the architecture's alignment).
    BCJ { architecture: BCJArchitecture, start_offset: u32 },
}

impl XZFilter {
    /// The filter ID.
    pub const fn id(&self) -> u64 {
        match self {
            XZFilter::LZMA2 { .. } => XZFormat::LZMA2,
            XZFilter::Delta { .. } => XZFormat::DELTA,
            XZFilter::BCJ { architecture, .. } => XZFilter::bcj_id(*architecture),
        }
    }

    /// The filter ID of the BCJ filter of `architecture`.
    pub const fn bcj_id(architecture: BCJArchitecture) -> u64 {
        match architecture {
            BCJArchitecture::X86 => XZFormat::X86,
            BCJArchitecture::PowerPC => XZFormat::POWER_PC,
            BCJArchitecture::IA64 => XZFormat::IA64,
            BCJArchitecture::ARM => XZFormat::ARM,
            BCJArchitecture::ARMThumb => XZFormat::ARM_THUMB,
            BCJArchitecture::SPARC => XZFormat::SPARC,
            BCJArchitecture::ARM64 => XZFormat::ARM64,
            BCJArchitecture::RISCV => XZFormat::RISCV,
        }
    }

    /// The filter of the Filter ID `id` and Filter Properties
    /// `properties`; fails with `Unsupported` for an unknown filter or
    /// reserved properties, and `InvalidData` for properties of the wrong size or value.
    pub fn from_flags(id: u64, properties: &[u8]) -> Result<XZFilter, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        match id {
            XZFormat::LZMA2 => {
                let [byte] = properties else { return Err(invalid("LZMA2 properties not of 1 byte")) };
                if byte & 0xC0 != 0 {
                    return Err(CompressionError::Unsupported { feature: "reserved bits of the LZMA2 properties" });
                }
                let dictionary_size = LZMAFormat::lzma2_dictionary_size(*byte)
                    .ok_or(CompressionError::Unsupported { feature: "LZMA2 dictionary larger than 4 GiB" })?;
                Ok(XZFilter::LZMA2 { dictionary_size })
            }
            XZFormat::DELTA => {
                let [byte] = properties else { return Err(invalid("Delta properties not of 1 byte")) };
                Ok(XZFilter::Delta { distance: *byte as u16 + 1 })
            }
            XZFormat::X86..=XZFormat::RISCV => {
                let architecture = BCJArchitecture::ALL[(id - XZFormat::X86) as usize];
                let start_offset = match properties {
                    [] => 0,
                    [a, b, c, d] => u32::from_le_bytes([*a, *b, *c, *d]),
                    _ => return Err(invalid("BCJ properties not of 0 or 4 bytes")),
                };
                if !start_offset.is_multiple_of(architecture.alignment()) {
                    return Err(invalid("BCJ start offset not a multiple of the alignment"));
                }
                Ok(XZFilter::BCJ { architecture, start_offset })
            }
            _ => Err(CompressionError::Unsupported { feature: "unknown filter" }),
        }
    }

    /// Appends the Filter Flags of the filter (the shortest properties).
    pub fn write_flags(&self, out: &mut Vec<u8>) {
        XZFormat::write_integer(self.id(), out);
        match self {
            XZFilter::LZMA2 { dictionary_size } => out.extend([1, LZMAFormat::lzma2_dictionary_byte(*dictionary_size)]),
            XZFilter::Delta { distance } => out.extend([1, (distance - 1) as u8]),
            XZFilter::BCJ { start_offset: 0, .. } => out.push(0),
            XZFilter::BCJ { start_offset, .. } => {
                out.push(4);
                out.extend(start_offset.to_le_bytes());
            }
        }
    }

    /// Checks the parameters of the filter (as a compressor is given them);
    /// fails with `InvalidParameter`.
    pub fn check(&self) -> Result<(), CompressionError> {
        let valid = match self {
            XZFilter::LZMA2 { dictionary_size } => {
                (LZMAFormat::MINIMUM_DICTIONARY as u64..=u32::MAX as u64).contains(dictionary_size)
            }
            XZFilter::Delta { distance } => (1..=DeltaFilter::MAXIMUM_DISTANCE as u16).contains(distance),
            XZFilter::BCJ { architecture, start_offset } => start_offset.is_multiple_of(architecture.alignment()),
        };
        if valid { Ok(()) } else { Err(CompressionError::InvalidParameter) }
    }

    /// Checks a filter chain: 1 to 4 filters, LZMA2 last and only last;
    /// fails with `Unsupported` (as liblzma does: the chain may be of a newer format).
    pub fn check_chain(filters: &[XZFilter]) -> Result<(), CompressionError> {
        let unsupported = CompressionError::Unsupported { feature: "filter chain" };
        let Some((last, others)) = filters.split_last() else { return Err(unsupported) };
        if filters.len() > XZFormat::MAXIMUM_FILTERS
            || !matches!(last, XZFilter::LZMA2 { .. })
            || others.iter().any(|filter| matches!(filter, XZFilter::LZMA2 { .. }))
        {
            return Err(unsupported);
        }
        Ok(())
    }

    /// The coder of a filter that is not the last one (`None` for LZMA2).
    pub fn coder(&self) -> Option<XZFilterCoder> {
        match self {
            XZFilter::LZMA2 { .. } => None,
            XZFilter::Delta { distance } => {
                DeltaFilter::new(*distance as usize).ok().map(|filter| XZFilterCoder::Delta(Box::new(filter)))
            }
            XZFilter::BCJ { architecture, start_offset } => {
                BCJFilter::new(*architecture, *start_offset).ok().map(XZFilterCoder::BCJ)
            }
        }
    }
}

/// The coder of a filter of a .xz chain that is not the last one (the
/// history of Delta boxed, so that a BCJ coder stays small).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XZFilterCoder {
    Delta(Box<DeltaFilter>),
    BCJ(BCJFilter),
}

impl Filter for XZFilterCoder {
    fn lookahead(&self) -> usize {
        match self {
            XZFilterCoder::Delta(filter) => filter.lookahead(),
            XZFilterCoder::BCJ(filter) => filter.lookahead(),
        }
    }

    fn encode(&mut self, data: &mut [u8]) -> usize {
        match self {
            XZFilterCoder::Delta(filter) => filter.encode(data),
            XZFilterCoder::BCJ(filter) => filter.encode(data),
        }
    }

    fn decode(&mut self, data: &mut [u8]) -> usize {
        match self {
            XZFilterCoder::Delta(filter) => filter.decode(data),
            XZFilterCoder::BCJ(filter) => filter.decode(data),
        }
    }

    fn reset(&mut self) {
        match self {
            XZFilterCoder::Delta(filter) => filter.reset(),
            XZFilterCoder::BCJ(filter) => filter.reset(),
        }
    }
}
