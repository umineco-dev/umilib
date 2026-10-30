/// The instruction sets of the BCJ filters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BCJArchitecture {
    /// x86 and x86-64: CALL and JMP with 32-bit displacements.
    X86,
    /// PowerPC (big endian): B and BL.
    PowerPC,
    /// IA-64 (Itanium): branches in instruction bundles.
    IA64,
    /// 32-bit ARM (little endian instructions): BL.
    ARM,
    /// ARM Thumb (little endian instructions): BL.
    ARMThumb,
    /// SPARC: CALL.
    SPARC,
    /// ARM64 (AArch64): BL and ADRP.
    ARM64,
    /// RISC-V: JAL, and AUIPC with the instruction after it.
    RISCV,
}

impl BCJArchitecture {
    /// Every architecture.
    pub const ALL: [BCJArchitecture; 8] = [
        BCJArchitecture::X86,
        BCJArchitecture::PowerPC,
        BCJArchitecture::IA64,
        BCJArchitecture::ARM,
        BCJArchitecture::ARMThumb,
        BCJArchitecture::SPARC,
        BCJArchitecture::ARM64,
        BCJArchitecture::RISCV,
    ];

    /// The alignment of the instructions converted, and of start offsets.
    pub const fn alignment(self) -> u32 {
        match self {
            BCJArchitecture::X86 => 1,
            BCJArchitecture::ARMThumb | BCJArchitecture::RISCV => 2,
            BCJArchitecture::PowerPC | BCJArchitecture::ARM | BCJArchitecture::SPARC | BCJArchitecture::ARM64 => 4,
            BCJArchitecture::IA64 => 16,
        }
    }

    /// The most bytes at the end of a piece a filter may leave unconverted
    /// (those that may begin an instruction that continues after them).
    pub const fn lookahead(self) -> usize {
        match self {
            BCJArchitecture::X86 => 5,
            BCJArchitecture::PowerPC
            | BCJArchitecture::ARM
            | BCJArchitecture::ARMThumb
            | BCJArchitecture::SPARC
            | BCJArchitecture::ARM64 => 4,
            BCJArchitecture::RISCV => 8,
            BCJArchitecture::IA64 => 16,
        }
    }
}
