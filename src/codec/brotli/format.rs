/// An elementary transform of a dictionary word (RFC 7932 section 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrotliTransformKind {
    Identity,
    FermentFirst,
    FermentAll,
    /// The word without its first `k` bytes.
    OmitFirst(u8),
    /// The word without its last `k` bytes.
    OmitLast(u8),
}

/// A word transformation: prefix + transform(word) + suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrotliTransform {
    pub prefix: &'static [u8],
    pub kind: BrotliTransformKind,
    pub suffix: &'static [u8],
}

/// The constants of the Brotli format (RFC 7932).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrotliFormat;

impl BrotliFormat {
    /// The static dictionary of Appendix A (122,784 bytes, CRC-32 0x5136cb04).
    pub const DICTIONARY: &'static [u8; 122784] = include_bytes!("dictionary.bin");
    /// NDBITS: the base-2 logarithm of the number of words of each length 0 to 24.
    pub const DICTIONARY_BITS: [u8; 25] =
        [0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5];
    /// The shortest and the longest dictionary word.
    pub const MINIMUM_WORD: usize = 4;
    pub const MAXIMUM_WORD: usize = 24;
    /// The insert length codes 0 to 23 (section 5): base lengths and extra bits.
    pub const INSERT_BASES: [u32; 24] =
        [0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594];
    pub const INSERT_BITS: [u8; 24] = [0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24];
    /// The copy length codes 0 to 23.
    pub const COPY_BASES: [u32; 24] =
        [2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118];
    pub const COPY_BITS: [u8; 24] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24];
    /// The block count codes 0 to 25 (section 6).
    pub const BLOCK_COUNT_BASES: [u32; 26] = [
        1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265, 2289, 4337,
        8433, 16625,
    ];
    pub const BLOCK_COUNT_BITS: [u8; 26] =
        [2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24];
    /// The insert and copy length code bases of the cells of insert-and-copy codes 128 to 703.
    pub const COMMAND_CELLS: [(u8, u8); 9] =
        [(0, 0), (0, 8), (8, 0), (8, 8), (0, 16), (16, 0), (8, 16), (16, 8), (16, 16)];
    /// The order of the code lengths of the code length code (section 3.5).
    pub const CODE_LENGTH_ORDER: [usize; 18] = [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    /// The static code of the code length code lengths 0 to 5 (section 3.5):
    /// the value [`BitWriter::write`](crate::bytes::BitWriter::write) writes and its bits.
    pub const CODE_LENGTH_CODES: [(u8, u8); 6] =
        [(0b00, 2), (0b0111, 4), (0b011, 3), (0b10, 2), (0b01, 2), (0b1111, 4)];
    /// The same code by the next 4 bits of the stream (first bit least
    /// significant): the code length code length and the bits of its code.
    pub const CODE_LENGTH_DECODING: [(u8, u8); 16] = [
        (0, 2),
        (4, 2),
        (3, 2),
        (2, 3),
        (0, 2),
        (4, 2),
        (3, 2),
        (1, 4),
        (0, 2),
        (4, 2),
        (3, 2),
        (2, 3),
        (0, 2),
        (4, 2),
        (3, 2),
        (5, 4),
    ];
    /// The length code 16 repeats before any non-zero code length is read.
    pub const INITIAL_CODE_LENGTH: u8 = 8;
    /// The alphabet sizes of literals, insert-and-copy lengths and block counts.
    pub const LITERALS: usize = 256;
    pub const COMMANDS: usize = 704;
    pub const BLOCK_COUNTS: usize = 26;
    /// The initial last distances, last first (section 4).
    pub const INITIAL_DISTANCES: [u32; 4] = [4, 11, 15, 16];
    /// The block count when a category has one block type.
    pub const UNLIMITED_BLOCK: u32 = 1 << 24;
    /// The longest code.
    pub const MAXIMUM_CODE_LENGTH: u32 = 15;
    /// The smallest and largest window logarithms.
    pub const MINIMUM_WINDOW_BITS: u32 = 10;
    pub const MAXIMUM_WINDOW_BITS: u32 = 24;

    /// The context lookup tables of section 7.1.
    pub const LUT0: [u8; 256] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 12, 16, 12,
        12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
        12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24,
        12, 28, 12, 12, 12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56, 60, 60,
        60, 60, 60, 24, 12, 28, 12, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
        1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
        2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2,
        3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    ];
    pub const LUT1: [u8; 256] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    ];
    pub const LUT2: [u8; 256] = [
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7,
    ];
    /// The 121 word transformations of Appendix B.
    pub const TRANSFORMS: [BrotliTransform; 121] = [
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" " },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::Identity, suffix: b" " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitFirst(1), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentFirst, suffix: b" " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" the " },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::Identity, suffix: b"" },
        BrotliTransform { prefix: b"s ", kind: BrotliTransformKind::Identity, suffix: b" " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" of " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentFirst, suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" and " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitFirst(2), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitLast(1), suffix: b"" },
        BrotliTransform { prefix: b", ", kind: BrotliTransformKind::Identity, suffix: b" " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b", " },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentFirst, suffix: b" " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" in " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" to " },
        BrotliTransform { prefix: b"e ", kind: BrotliTransformKind::Identity, suffix: b" " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"\x22" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"." },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"\x22>" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"\x0a" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitLast(3), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"]" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" for " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitFirst(3), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitLast(2), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" a " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" that " },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentFirst, suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b". " },
        BrotliTransform { prefix: b".", kind: BrotliTransformKind::Identity, suffix: b"" },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::Identity, suffix: b", " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitFirst(4), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" with " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"'" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" from " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" by " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitFirst(5), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitFirst(6), suffix: b"" },
        BrotliTransform { prefix: b" the ", kind: BrotliTransformKind::Identity, suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitLast(4), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b". The " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentAll, suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" on " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" as " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" is " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitLast(7), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitLast(1), suffix: b"ing " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"\x0a\x09" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b":" },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::Identity, suffix: b". " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"ed " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitFirst(9), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitFirst(7), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitLast(6), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"(" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentFirst, suffix: b", " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitLast(8), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" at " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"ly " },
        BrotliTransform { prefix: b" the ", kind: BrotliTransformKind::Identity, suffix: b" of " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitLast(5), suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::OmitLast(9), suffix: b"" },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentFirst, suffix: b", " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentFirst, suffix: b"\x22" },
        BrotliTransform { prefix: b".", kind: BrotliTransformKind::Identity, suffix: b"(" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentAll, suffix: b" " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentFirst, suffix: b"\x22>" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"=\x22" },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::Identity, suffix: b"." },
        BrotliTransform { prefix: b".com/", kind: BrotliTransformKind::Identity, suffix: b"" },
        BrotliTransform { prefix: b" the ", kind: BrotliTransformKind::Identity, suffix: b" of the " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentFirst, suffix: b"'" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b". This " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"," },
        BrotliTransform { prefix: b".", kind: BrotliTransformKind::Identity, suffix: b" " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentFirst, suffix: b"(" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentFirst, suffix: b"." },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b" not " },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::Identity, suffix: b"=\x22" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"er " },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentAll, suffix: b" " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"al " },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentAll, suffix: b"" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"='" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentAll, suffix: b"\x22" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentFirst, suffix: b". " },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::Identity, suffix: b"(" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"ful " },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentFirst, suffix: b". " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"ive " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"less " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentAll, suffix: b"'" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"est " },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentFirst, suffix: b"." },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentAll, suffix: b"\x22>" },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::Identity, suffix: b"='" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentFirst, suffix: b"," },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"ize " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentAll, suffix: b"." },
        BrotliTransform { prefix: b"\xc2\xa0", kind: BrotliTransformKind::Identity, suffix: b"" },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::Identity, suffix: b"," },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentFirst, suffix: b"=\x22" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentAll, suffix: b"=\x22" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::Identity, suffix: b"ous " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentAll, suffix: b", " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentFirst, suffix: b"='" },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentFirst, suffix: b"," },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentAll, suffix: b"=\x22" },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentAll, suffix: b", " },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentAll, suffix: b"," },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentAll, suffix: b"(" },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentAll, suffix: b". " },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentAll, suffix: b"." },
        BrotliTransform { prefix: b"", kind: BrotliTransformKind::FermentAll, suffix: b"='" },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentAll, suffix: b". " },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentFirst, suffix: b"=\x22" },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentAll, suffix: b"='" },
        BrotliTransform { prefix: b" ", kind: BrotliTransformKind::FermentFirst, suffix: b"='" },
    ];

    /// The insert length code, the copy length code and whether the
    /// distance is an implicit 0 (the last distance) of the insert-and-copy
    /// length symbol `symbol` (section 5).
    pub fn command(symbol: u16) -> (usize, usize, bool) {
        let implicit = symbol < 128;
        let index = if implicit { symbol } else { symbol - 128 } as usize;
        let (insert, copy) = BrotliFormat::COMMAND_CELLS[index >> 6];
        (insert as usize + (index >> 3 & 7), copy as usize + (index & 7), implicit)
    }

    /// The insert-and-copy length symbol of an insert length code and a copy
    /// length code, with an implicit distance code 0 if `implicit` (which
    /// needs an insert length code below 8 and a copy length code below 16).
    pub fn command_symbol(insert: usize, copy: usize, implicit: bool) -> u16 {
        debug_assert!(!implicit || (insert < 8 && copy < 16));
        let cell = (insert & !7, copy & !7);
        let index = BrotliFormat::COMMAND_CELLS
            .iter()
            .position(|(i, c)| (*i as usize, *c as usize) == cell)
            .expect("codes below 24");
        let symbol = (index << 6 | (insert & 7) << 3 | (copy & 7)) as u16;
        if implicit { symbol } else { symbol + 128 }
    }

    /// The insert length code of `length` and its extra bits.
    pub fn insert_code(length: u32) -> (usize, u32) {
        let code = BrotliFormat::INSERT_BASES.iter().rposition(|base| *base <= length).expect("the base 0");
        (code, length - BrotliFormat::INSERT_BASES[code])
    }

    /// The copy length code of `length` (2 or more) and its extra bits.
    pub fn copy_code(length: u32) -> (usize, u32) {
        let code = BrotliFormat::COPY_BASES.iter().rposition(|base| *base <= length).expect("a length of 2 or more");
        (code, length - BrotliFormat::COPY_BASES[code])
    }

    /// The window of WBITS: 2^WBITS - 16 bytes.
    pub const fn window_size(bits: u32) -> usize {
        (1 << bits) - 16
    }

    /// The context ID of a literal after the bytes p1 (last) and p2 in context `mode` (section 7.1).
    pub const fn literal_context(mode: u8, p1: u8, p2: u8) -> usize {
        match mode {
            0 => (p1 & 0x3F) as usize,
            1 => (p1 >> 2) as usize,
            2 => (BrotliFormat::LUT0[p1 as usize] | BrotliFormat::LUT1[p2 as usize]) as usize,
            _ => ((BrotliFormat::LUT2[p1 as usize] << 3) | BrotliFormat::LUT2[p2 as usize]) as usize,
        }
    }

    /// The offset of the dictionary words of `length` (DOFFSET).
    pub fn word_offset(length: usize) -> usize {
        (BrotliFormat::MINIMUM_WORD..length).map(|shorter| shorter << BrotliFormat::DICTIONARY_BITS[shorter]).sum()
    }

    /// The word `index` of `length` bytes of the dictionary.
    pub fn word(length: usize, index: usize) -> &'static [u8] {
        let start = BrotliFormat::word_offset(length) + index * length;
        &BrotliFormat::DICTIONARY[start..start + length]
    }

    /// Changes the case of the UTF-8 character at `position` of `word` as
    /// Ferment does; returns the bytes of the character.
    pub fn ferment(word: &mut [u8], position: usize) -> usize {
        let byte = word[position];
        if byte < 192 {
            if byte.is_ascii_lowercase() {
                word[position] ^= 32;
            }
            1
        } else if byte < 224 {
            if position + 1 < word.len() {
                word[position + 1] ^= 32;
            }
            2
        } else {
            if position + 2 < word.len() {
                word[position + 2] ^= 5;
            }
            3
        }
    }

    /// Writes the transform `transform` of `word` into `out` (at most 38 bytes); returns its length.
    pub fn transform(transform: &BrotliTransform, word: &[u8], out: &mut [u8; 38]) -> usize {
        let mut length = 0;
        out[..transform.prefix.len()].copy_from_slice(transform.prefix);
        length += transform.prefix.len();
        let body = match transform.kind {
            BrotliTransformKind::OmitFirst(count) => word.get(count as usize..).unwrap_or(&[]),
            BrotliTransformKind::OmitLast(count) => &word[..word.len().saturating_sub(count as usize)],
            _ => word,
        };
        let start = length;
        out[start..start + body.len()].copy_from_slice(body);
        length += body.len();
        match transform.kind {
            BrotliTransformKind::FermentFirst if !body.is_empty() => {
                BrotliFormat::ferment(&mut out[start..start + body.len()], 0);
            }
            BrotliTransformKind::FermentAll => {
                let mut position = 0;
                while position < body.len() {
                    position += BrotliFormat::ferment(&mut out[start..start + body.len()], position);
                }
            }
            _ => {}
        }
        out[length..length + transform.suffix.len()].copy_from_slice(transform.suffix);
        length + transform.suffix.len()
    }
}
