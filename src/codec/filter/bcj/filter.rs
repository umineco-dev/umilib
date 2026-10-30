use super::BCJArchitecture;
use crate::codec::CompressionError;
use crate::codec::filter::Filter;

/// A BCJ filter of one architecture. Addresses are computed from the
/// position of each instruction in the stream plus the start offset, modulo
/// 2^32, as XZ Utils does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BCJFilter {
    architecture: BCJArchitecture,
    start_offset: u32,
    /// The address of the next byte.
    position: u32,
    /// The x86 filter's state: which of the last bytes were opcodes E8/E9
    /// that were not converted, and the position of the last one.
    x86_mask: u32,
    x86_previous: u32,
}

impl BCJFilter {
    /// A filter of `architecture` whose first byte is at the address
    /// `start_offset`; fails with `InvalidParameter` unless the offset is a
    /// multiple of the architecture's alignment.
    pub fn new(architecture: BCJArchitecture, start_offset: u32) -> Result<BCJFilter, CompressionError> {
        if !start_offset.is_multiple_of(architecture.alignment()) {
            return Err(CompressionError::InvalidParameter);
        }
        Ok(BCJFilter {
            architecture,
            start_offset,
            position: start_offset,
            x86_mask: 0,
            x86_previous: 0u32.wrapping_sub(5),
        })
    }

    pub fn architecture(&self) -> BCJArchitecture {
        self.architecture
    }

    pub fn start_offset(&self) -> u32 {
        self.start_offset
    }

    /// Converts what it can of `data`, encoding or decoding, and advances the position.
    pub fn convert(&mut self, data: &mut [u8], encoding: bool) -> usize {
        let done = match self.architecture {
            BCJArchitecture::X86 => self.x86(data, encoding),
            BCJArchitecture::PowerPC => BCJFilter::power_pc(self.position, data, encoding),
            BCJArchitecture::IA64 => BCJFilter::ia64(self.position, data, encoding),
            BCJArchitecture::ARM => BCJFilter::arm(self.position, data, encoding),
            BCJArchitecture::ARMThumb => BCJFilter::arm_thumb(self.position, data, encoding),
            BCJArchitecture::SPARC => BCJFilter::sparc(self.position, data, encoding),
            BCJArchitecture::ARM64 => BCJFilter::arm64(self.position, data, encoding),
            BCJArchitecture::RISCV if encoding => BCJFilter::riscv_encode(self.position, data),
            BCJArchitecture::RISCV => BCJFilter::riscv_decode(self.position, data),
        };
        self.position = self.position.wrapping_add(done as u32);
        done
    }

    /// The 32-bit little endian word at `index` of `data`.
    pub fn read_le(data: &[u8], index: usize) -> u32 {
        u32::from_le_bytes([data[index], data[index + 1], data[index + 2], data[index + 3]])
    }

    /// The 32-bit big endian word at `index` of `data`.
    pub fn read_be(data: &[u8], index: usize) -> u32 {
        u32::from_be_bytes([data[index], data[index + 1], data[index + 2], data[index + 3]])
    }

    /// x86: CALL (E8) and JMP (E9) whose 32-bit displacement has a high byte of 00 or FF.
    pub fn x86(&mut self, data: &mut [u8], encoding: bool) -> usize {
        const MASK_TO_BIT_NUMBER: [u32; 5] = [0, 1, 2, 2, 3];
        let is_high_byte = |byte: u8| byte == 0x00 || byte == 0xFF;
        if data.len() < 5 {
            return 0;
        }
        let now = self.position;
        let (mut mask, mut previous) = (self.x86_mask, self.x86_previous);
        if now.wrapping_sub(previous) > 5 {
            previous = now.wrapping_sub(5);
        }
        let limit = data.len() - 5;
        let mut index = 0;
        while index <= limit {
            let opcode = data[index];
            if opcode != 0xE8 && opcode != 0xE9 {
                index += 1;
                continue;
            }
            let here = now.wrapping_add(index as u32);
            let offset = here.wrapping_sub(previous);
            previous = here;
            if offset > 5 {
                mask = 0;
            } else {
                for _ in 0..offset {
                    mask = (mask & 0x77) << 1;
                }
            }
            let high = data[index + 4];
            if is_high_byte(high) && (mask >> 1) <= 4 && (mask >> 1) != 3 {
                let mut source = BCJFilter::read_le(data, index + 1);
                let pc = here.wrapping_add(5);
                let mut destination;
                loop {
                    destination = if encoding { source.wrapping_add(pc) } else { source.wrapping_sub(pc) };
                    if mask == 0 {
                        break;
                    }
                    let bit = MASK_TO_BIT_NUMBER[(mask >> 1) as usize];
                    if !is_high_byte((destination >> (24 - bit * 8)) as u8) {
                        break;
                    }
                    source = destination ^ (u32::MAX >> (bit * 8));
                }
                // The high byte becomes 00 or FF after bit 24 (the sign of a 25-bit displacement).
                let sign = if (destination >> 24) & 1 == 1 { 0xFF } else { 0x00 };
                data[index + 1..index + 4].copy_from_slice(&destination.to_le_bytes()[..3]);
                data[index + 4] = sign;
                index += 5;
                mask = 0;
            } else {
                index += 1;
                mask |= 1;
                if is_high_byte(high) {
                    mask |= 0x10;
                }
            }
        }
        (self.x86_mask, self.x86_previous) = (mask, previous);
        index
    }

    /// PowerPC: B and BL (opcode 18 with AA = 0 and LK = 1), big endian.
    pub fn power_pc(position: u32, data: &mut [u8], encoding: bool) -> usize {
        let size = data.len() & !3;
        for index in (0..size).step_by(4) {
            if data[index] >> 2 != 0x12 || data[index + 3] & 3 != 1 {
                continue;
            }
            let source = BCJFilter::read_be(data, index) & 0x03FF_FFFC;
            let pc = position.wrapping_add(index as u32);
            let destination = if encoding { pc.wrapping_add(source) } else { source.wrapping_sub(pc) };
            let instruction = 0x4800_0000 | (destination & 0x03FF_FFFC) | (data[index + 3] as u32 & 3);
            data[index..index + 4].copy_from_slice(&instruction.to_be_bytes());
        }
        size
    }

    /// IA-64: the branch slots of the bundle templates that hold them.
    pub fn ia64(position: u32, data: &mut [u8], encoding: bool) -> usize {
        const BRANCH_TABLE: [u32; 32] =
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
        let size = data.len() & !15;
        for index in (0..size).step_by(16) {
            let mask = BRANCH_TABLE[(data[index] & 0x1F) as usize];
            for slot in 0..3 {
                if (mask >> slot) & 1 == 0 {
                    continue;
                }
                let bit_position = 5 + 41 * slot;
                let (byte_position, bit_offset) = (index + (bit_position >> 3), bit_position & 7);
                let mut instruction = 0u64;
                for (shift, byte) in data[byte_position..byte_position + 6].iter().enumerate() {
                    instruction |= (*byte as u64) << (8 * shift);
                }
                let mut normalized = instruction >> bit_offset;
                if (normalized >> 37) & 0xF != 0x5 || (normalized >> 9) & 0x7 != 0 {
                    continue;
                }
                let mut source = ((normalized >> 13) & 0xF_FFFF) as u32;
                source |= (((normalized >> 36) & 1) as u32) << 20;
                source <<= 4;
                let pc = position.wrapping_add(index as u32);
                let destination = (if encoding { pc.wrapping_add(source) } else { source.wrapping_sub(pc) }) >> 4;
                normalized &= !(0x8F_FFFFu64 << 13);
                normalized |= ((destination & 0xF_FFFF) as u64) << 13;
                normalized |= ((destination & 0x10_0000) as u64) << (36 - 20);
                instruction &= (1u64 << bit_offset) - 1;
                instruction |= normalized << bit_offset;
                for (shift, byte) in data[byte_position..byte_position + 6].iter_mut().enumerate() {
                    *byte = (instruction >> (8 * shift)) as u8;
                }
            }
        }
        size
    }

    /// 32-bit ARM: BL (condition "always").
    pub fn arm(position: u32, data: &mut [u8], encoding: bool) -> usize {
        let size = data.len() & !3;
        for index in (0..size).step_by(4) {
            if data[index + 3] != 0xEB {
                continue;
            }
            let source = (BCJFilter::read_le(data, index) & 0x00FF_FFFF) << 2;
            let pc = position.wrapping_add(index as u32).wrapping_add(8);
            let destination = (if encoding { pc.wrapping_add(source) } else { source.wrapping_sub(pc) }) >> 2;
            data[index..index + 3].copy_from_slice(&destination.to_le_bytes()[..3]);
        }
        size
    }

    /// ARM Thumb: the two halves of BL.
    pub fn arm_thumb(position: u32, data: &mut [u8], encoding: bool) -> usize {
        if data.len() < 4 {
            return 0;
        }
        let last = data.len() - 4;
        let mut index = 0;
        while index <= last {
            if data[index + 1] & 0xF8 != 0xF0 || data[index + 3] & 0xF8 != 0xF8 {
                index += 2;
                continue;
            }
            let source = ((data[index + 1] as u32 & 7) << 19
                | (data[index] as u32) << 11
                | (data[index + 3] as u32 & 7) << 8
                | data[index + 2] as u32)
                << 1;
            let pc = position.wrapping_add(index as u32).wrapping_add(4);
            let destination = (if encoding { pc.wrapping_add(source) } else { source.wrapping_sub(pc) }) >> 1;
            data[index + 1] = 0xF0 | ((destination >> 19) & 7) as u8;
            data[index] = (destination >> 11) as u8;
            data[index + 3] = 0xF8 | ((destination >> 8) & 7) as u8;
            data[index + 2] = destination as u8;
            index += 4;
        }
        index
    }

    /// SPARC: CALL with a displacement within ±2^22 words, big endian.
    pub fn sparc(position: u32, data: &mut [u8], encoding: bool) -> usize {
        let size = data.len() & !3;
        for index in (0..size).step_by(4) {
            let (first, second) = (data[index], data[index + 1]);
            if !((first == 0x40 && second & 0xC0 == 0x00) || (first == 0x7F && second & 0xC0 == 0xC0)) {
                continue;
            }
            let source = BCJFilter::read_be(data, index) << 2;
            let pc = position.wrapping_add(index as u32);
            let destination = (if encoding { pc.wrapping_add(source) } else { source.wrapping_sub(pc) }) >> 2;
            let sign = (0u32.wrapping_sub((destination >> 22) & 1) << 22) & 0x3FFF_FFFF;
            let instruction = sign | (destination & 0x3F_FFFF) | 0x4000_0000;
            data[index..index + 4].copy_from_slice(&instruction.to_be_bytes());
        }
        size
    }

    /// ARM64: BL (the whole 26-bit immediate) and ADRP (within ±512 MiB).
    pub fn arm64(position: u32, data: &mut [u8], encoding: bool) -> usize {
        let size = data.len() & !3;
        for index in (0..size).step_by(4) {
            let pc = position.wrapping_add(index as u32);
            let mut instruction = BCJFilter::read_le(data, index);
            if instruction >> 26 == 0x25 {
                let pc = if encoding { pc >> 2 } else { 0u32.wrapping_sub(pc >> 2) };
                instruction = 0x9400_0000 | (instruction.wrapping_add(pc) & 0x03FF_FFFF);
            } else if instruction & 0x9F00_0000 == 0x9000_0000 {
                let source = ((instruction >> 29) & 3) | ((instruction >> 3) & 0x001F_FFFC);
                if source.wrapping_add(0x0002_0000) & 0x001C_0000 != 0 {
                    continue;
                }
                let pc = if encoding { pc >> 12 } else { 0u32.wrapping_sub(pc >> 12) };
                let destination = source.wrapping_add(pc);
                instruction &= 0x9000_001F;
                instruction |= (destination & 3) << 29;
                instruction |= (destination & 0x0003_FFFC) << 3;
                instruction |= 0u32.wrapping_sub(destination & 0x0002_0000) & 0x00E0_0000;
            } else {
                continue;
            }
            data[index..index + 4].copy_from_slice(&instruction.to_le_bytes());
        }
        size
    }

    /// RISC-V: whether `auipc` and `second` are not an AUIPC with an
    /// instruction using its register (that the filter converts).
    pub fn not_auipc_pair(auipc: u32, second: u32) -> bool {
        ((auipc << 8) ^ second.wrapping_sub(3)) & 0xF_8003 != 0
    }

    /// RISC-V: whether `auipc` (whose rd is x0 or x2) is not in the special
    /// format of a converted pair, whose second register is `rs1`.
    pub fn not_special_auipc(auipc: u32, rs1: u32) -> bool {
        (auipc.wrapping_sub(0x3117) << 18) >= (rs1 & 0x1D)
    }

    /// RISC-V encoding: JAL with rd x1 or x5, and AUIPC with the next instruction.
    pub fn riscv_encode(position: u32, data: &mut [u8]) -> usize {
        if data.len() < 8 {
            return 0;
        }
        let last = data.len() - 8;
        let mut index = 0;
        while index <= last {
            let first = data[index] as u32;
            if first == 0xEF {
                let b1 = data[index + 1] as u32;
                if b1 & 0x0D != 0 {
                    index += 2;
                    continue;
                }
                let (b2, b3) = (data[index + 2] as u32, data[index + 3] as u32);
                let pc = position.wrapping_add(index as u32);
                let address = ((b1 & 0xF0) << 8
                    | (b2 & 0x0F) << 16
                    | (b2 & 0x10) << 7
                    | (b2 & 0xE0) >> 4
                    | (b3 & 0x7F) << 4
                    | (b3 & 0x80) << 13)
                    .wrapping_add(pc);
                data[index + 1] = ((b1 & 0x0F) | ((address >> 13) & 0xF0)) as u8;
                data[index + 2] = (address >> 9) as u8;
                data[index + 3] = (address >> 1) as u8;
                index += 4;
            } else if first & 0x7F == 0x17 {
                let instruction = BCJFilter::read_le(data, index);
                if instruction & 0xE80 != 0 {
                    // rd is neither x0 nor x2: a pair with the next instruction if it uses rd.
                    let second = BCJFilter::read_le(data, index + 4);
                    if BCJFilter::not_auipc_pair(instruction, second) {
                        index += 6;
                        continue;
                    }
                    let address = (instruction & 0xFFFF_F000)
                        .wrapping_add((second >> 20).wrapping_sub((second >> 19) & 0x1000))
                        .wrapping_add(position.wrapping_add(index as u32));
                    let converted = 0x17 | (2 << 7) | (second << 12);
                    data[index..index + 4].copy_from_slice(&converted.to_le_bytes());
                    data[index + 4..index + 8].copy_from_slice(&address.to_be_bytes());
                } else {
                    // rd is x0 or x2: data in the special format is "fake" decoded to stay reversible.
                    let rs1 = instruction >> 27;
                    if BCJFilter::not_special_auipc(instruction, rs1) {
                        index += 4;
                        continue;
                    }
                    let address = BCJFilter::read_le(data, index + 4);
                    let second = (instruction >> 12) | (address << 20);
                    let converted = 0x17 | (rs1 << 7) | (address & 0xFFFF_F000);
                    data[index..index + 4].copy_from_slice(&converted.to_le_bytes());
                    data[index + 4..index + 8].copy_from_slice(&second.to_le_bytes());
                }
                index += 8;
            } else {
                index += 2;
            }
        }
        index
    }

    /// RISC-V decoding, the inverse of [`BCJFilter::riscv_encode`].
    pub fn riscv_decode(position: u32, data: &mut [u8]) -> usize {
        if data.len() < 8 {
            return 0;
        }
        let last = data.len() - 8;
        let mut index = 0;
        while index <= last {
            let first = data[index] as u32;
            if first == 0xEF {
                let b1 = data[index + 1] as u32;
                if b1 & 0x0D != 0 {
                    index += 2;
                    continue;
                }
                let (b2, b3) = (data[index + 2] as u32, data[index + 3] as u32);
                let pc = position.wrapping_add(index as u32);
                let address = ((b1 & 0xF0) << 13 | b2 << 9 | b3 << 1).wrapping_sub(pc);
                data[index + 1] = ((b1 & 0x0F) | ((address >> 8) & 0xF0)) as u8;
                data[index + 2] = (((address >> 16) & 0x0F) | ((address >> 7) & 0x10) | ((address << 4) & 0xE0)) as u8;
                data[index + 3] = (((address >> 4) & 0x7F) | ((address >> 13) & 0x80)) as u8;
                index += 4;
            } else if first & 0x7F == 0x17 {
                let mut instruction = BCJFilter::read_le(data, index);
                let second;
                if instruction & 0xE80 != 0 {
                    // A "fake" pair of the encoder: re-encoded without address conversion.
                    let fake = BCJFilter::read_le(data, index + 4);
                    if BCJFilter::not_auipc_pair(instruction, fake) {
                        index += 6;
                        continue;
                    }
                    let address = (instruction & 0xFFFF_F000).wrapping_add(fake >> 20);
                    instruction = 0x17 | (2 << 7) | (fake << 12);
                    second = address;
                } else {
                    let rs1 = instruction >> 27;
                    if BCJFilter::not_special_auipc(instruction, rs1) {
                        index += 4;
                        continue;
                    }
                    let address = BCJFilter::read_be(data, index + 4).wrapping_sub(position.wrapping_add(index as u32));
                    second = (instruction >> 12) | (address << 20);
                    instruction = 0x17 | (rs1 << 7) | (address.wrapping_add(0x800) & 0xFFFF_F000);
                }
                data[index..index + 4].copy_from_slice(&instruction.to_le_bytes());
                data[index + 4..index + 8].copy_from_slice(&second.to_le_bytes());
                index += 8;
            } else {
                index += 2;
            }
        }
        index
    }
}

impl Filter for BCJFilter {
    fn lookahead(&self) -> usize {
        self.architecture.lookahead()
    }

    fn encode(&mut self, data: &mut [u8]) -> usize {
        self.convert(data, true)
    }

    fn decode(&mut self, data: &mut [u8]) -> usize {
        self.convert(data, false)
    }

    fn reset(&mut self) {
        *self = BCJFilter::new(self.architecture, self.start_offset).expect("an aligned start offset");
    }
}
