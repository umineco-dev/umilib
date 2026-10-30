use umilib::hash::Digest;
use umilib::hash::crc::*;

use crate::Vectors;

/// The parameters of one line of the catalogue, in a 128-bit register.
#[derive(Debug)]
struct Entry {
    name: String,
    width: u32,
    polynomial: u128,
    initial: u128,
    reflect_input: bool,
    reflect_output: bool,
    xor_output: u128,
    check: u128,
    residue: u128,
}

impl Entry {
    fn all() -> Vec<Entry> {
        let text = Vectors::read("hash/crc/catalogue.txt");
        text.lines()
            .map(|line| {
                let field = |key: &str| {
                    let start = line.find(&format!("{key}=")).unwrap() + key.len() + 1;
                    line[start..].split(' ').next().unwrap().trim_matches('"').to_string()
                };
                let number = |key: &str| u128::from_str_radix(field(key).trim_start_matches("0x"), 16).unwrap();
                Entry {
                    name: field("name"),
                    width: field("width").parse().unwrap(),
                    polynomial: number("poly"),
                    initial: number("init"),
                    reflect_input: field("refin") == "true",
                    reflect_output: field("refout") == "true",
                    xor_output: number("xorout"),
                    check: number("check"),
                    residue: number("residue"),
                }
            })
            .collect()
    }

    /// The CRC by its definition: polynomial division one bit at a time.
    fn bitwise(&self, data: &[u8]) -> (u128, u128) {
        let mask = if self.width == 128 { u128::MAX } else { (1 << self.width) - 1 };
        let mut register = self.initial;
        for &byte in data {
            for bit in 0..8 {
                let input = if self.reflect_input { (byte >> bit) & 1 } else { (byte >> (7 - bit)) & 1 };
                let top = (register >> (self.width - 1)) & 1;
                register = (register << 1) & mask;
                if top ^ input as u128 == 1 {
                    register ^= self.polynomial;
                }
            }
        }
        let remainder = if self.reflect_output { register.reverse_bits() >> (128 - self.width) } else { register };
        (remainder ^ self.xor_output, remainder)
    }

    /// The residue as the RevEng catalogue defines it, for every width: the
    /// register that starts at the final xor value and is fed `width` zero
    /// bits, in the output order.
    fn residue_by_definition(&self) -> u128 {
        let mask = if self.width == 128 { u128::MAX } else { (1 << self.width) - 1 };
        let reflect = |value: u128| value.reverse_bits() >> (128 - self.width);
        let mut register = if self.reflect_output { reflect(self.xor_output) } else { self.xor_output };
        for _ in 0..self.width {
            let top = (register >> (self.width - 1)) & 1;
            register = (register << 1) & mask;
            if top == 1 {
                register ^= self.polynomial;
            }
        }
        if self.reflect_output { reflect(register) } else { register }
    }

    /// The codeword of `data`: the data and its CRC, sent in the bit order of the input.
    fn codeword(&self, data: &[u8]) -> Option<Vec<u8>> {
        if !self.width.is_multiple_of(8) || self.reflect_input != self.reflect_output {
            return None;
        }
        let value = self.bitwise(data).0;
        let bytes = (self.width / 8) as usize;
        let mut codeword = data.to_vec();
        for index in 0..bytes {
            let shift = if self.reflect_output { 8 * index } else { 8 * (bytes - 1 - index) };
            codeword.push((value >> shift) as u8);
        }
        Some(codeword)
    }
}

/// Checks `table` against `entry`: parameters, check value, residue, and
/// the definition on other inputs, whole and byte by byte.
fn check<W: CRCRegister + Into<u128> + TryFrom<u128>>(table: &CRCTable<W>, entry: &Entry)
where
    <W as TryFrom<u128>>::Error: core::fmt::Debug,
{
    let parameters = table.parameters();
    let convert = |value: u128| W::try_from(value).unwrap();
    assert_eq!(
        *parameters,
        CRCParameters {
            name: parameters.name,
            width: entry.width,
            polynomial: convert(entry.polynomial),
            initial: convert(entry.initial),
            reflect_input: entry.reflect_input,
            reflect_output: entry.reflect_output,
            xor_output: convert(entry.xor_output),
            check: convert(entry.check),
            residue: convert(entry.residue),
        }
    );
    assert_eq!(parameters.name, entry.name);
    assert_eq!(CRC::checksum(table, b"123456789").into(), entry.check, "{}", entry.name);
    assert_eq!(entry.bitwise(b"123456789").0, entry.check, "{} by definition", entry.name);
    if let Some(codeword) = entry.codeword(b"123456789") {
        let mut crc = CRC::new(table);
        crc.update(&codeword);
        assert_eq!(crc.remainder().into(), entry.residue, "{} residue", entry.name);
    }
    assert_eq!(entry.residue_by_definition(), entry.residue, "{} residue by definition", entry.name);
    let rebuilt = CRCTable::<u128>::new(CRCParameters {
        name: "",
        width: entry.width,
        polynomial: entry.polynomial,
        initial: entry.initial,
        reflect_input: entry.reflect_input,
        reflect_output: entry.reflect_output,
        xor_output: entry.xor_output,
        check: entry.check,
        residue: entry.residue,
    })
    .unwrap();
    for length in [0usize, 1, 2, 3, 7, 8, 9, 31, 64, 300] {
        let data: Vec<u8> = (0..length).map(|index| (index * 151 + 7) as u8).collect();
        let expected = entry.bitwise(&data).0;
        let mut crc = CRC::new(table);
        data.iter().for_each(|byte| crc.update(&[*byte]));
        assert_eq!(crc.value().into(), expected, "{} of {length} bytes", entry.name);
        assert_eq!(CRC::checksum(&rebuilt, &data), expected, "{} in a 128-bit register", entry.name);
        let mut digest = CRC::new(table);
        Digest::update(&mut digest, &data);
        let bytes = digest.finalize();
        assert_eq!(bytes.as_ref(), &expected.to_be_bytes()[16 - W::SIZE..]);
    }
}

#[test]
fn crc_presets_follow_the_catalogue() {
    let entries = Entry::all();
    assert_eq!(entries.len(), 113);
    let total = CRCCatalogue::TABLES_U8.len()
        + CRCCatalogue::TABLES_U16.len()
        + CRCCatalogue::TABLES_U32.len()
        + CRCCatalogue::TABLES_U64.len()
        + CRCCatalogue::TABLES_U128.len();
    assert_eq!(total, entries.len());
    for entry in &entries {
        let name = entry.name.as_str();
        match entry.width {
            1..=8 => {
                check(CRCCatalogue::TABLES_U8.iter().find(|table| table.parameters().name == name).unwrap(), entry)
            }
            9..=16 => {
                check(CRCCatalogue::TABLES_U16.iter().find(|table| table.parameters().name == name).unwrap(), entry)
            }
            17..=32 => {
                check(CRCCatalogue::TABLES_U32.iter().find(|table| table.parameters().name == name).unwrap(), entry)
            }
            33..=64 => {
                check(CRCCatalogue::TABLES_U64.iter().find(|table| table.parameters().name == name).unwrap(), entry)
            }
            _ => check(CRCCatalogue::TABLES_U128.iter().find(|table| table.parameters().name == name).unwrap(), entry),
        }
    }
    assert_eq!(CRC::checksum(CRCCatalogue::CRC32_ISO_HDLC, b"123456789"), 0xCBF43926);
    assert_eq!(CRC::checksum(CRCCatalogue::CRC32_ISCSI, b"123456789"), 0xE3069283);
}

#[test]
fn crc_tables_reject_invalid_parameters() {
    let valid = CRCParameters {
        name: "test",
        width: 8,
        polynomial: 0x07u8,
        initial: 0,
        reflect_input: false,
        reflect_output: false,
        xor_output: 0,
        // CRC-8/SMBUS.
        check: 0xF4,
        residue: 0,
    };
    assert!(CRCTable::<u8>::new(valid).is_ok());
    // A check value that is not the CRC of "123456789" means mistyped parameters.
    assert!(CRCTable::<u8>::new(CRCParameters { check: 0xF5, ..valid }).is_err());
    assert!(CRCTable::<u8>::new(CRCParameters { width: 0, ..valid }).is_err());
    assert!(CRCTable::<u8>::new(CRCParameters { width: 9, ..valid }).is_err());
    assert!(CRCTable::<u8>::new(CRCParameters { width: 2, ..valid }).is_err());
    assert!(CRCTable::<u8>::new(CRCParameters { width: 3, residue: 8, ..valid }).is_err());
    assert!(CRCTable::<u8>::new(CRCParameters { width: 3, polynomial: 3, check: 0x9, ..valid }).is_err());
    let mut crc = CRC::new(CRCCatalogue::CRC16_ARC);
    crc.update(b"abc");
    crc.reset();
    crc.update(b"123456789");
    assert_eq!(crc.value(), 0xBB3D);
}

/// Random parameters of every width, in every register type that holds the
/// width, against the definition.
#[test]
fn crc_of_random_parameters_follows_the_definition() {
    let mut state = 0x2545F4914F6CDD1Du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as u128 | ((state.rotate_left(32) as u128) << 64)
    };
    for _ in 0..400 {
        let width = 1 + (next() % 128) as u32;
        let mask = if width == 128 { u128::MAX } else { (1 << width) - 1 };
        let mut entry = Entry {
            name: String::new(),
            width,
            polynomial: next() & mask,
            initial: next() & mask,
            reflect_input: next() & 1 == 1,
            reflect_output: next() & 1 == 1,
            xor_output: next() & mask,
            check: 0,
            residue: 0,
        };
        entry.check = entry.bitwise(b"123456789").0;
        let data: Vec<u8> = (0..(next() % 40) as usize).map(|_| next() as u8).collect();
        let expected = entry.bitwise(&data);
        macro_rules! register {
            ($type:ty) => {
                if width <= <$type>::BITS {
                    let table = CRCTable::<$type>::new(CRCParameters {
                        name: "",
                        width,
                        polynomial: entry.polynomial as $type,
                        initial: entry.initial as $type,
                        reflect_input: entry.reflect_input,
                        reflect_output: entry.reflect_output,
                        xor_output: entry.xor_output as $type,
                        check: entry.check as $type,
                        residue: 0,
                    })
                    .unwrap();
                    let mut crc = CRC::new(&table);
                    crc.update(&data);
                    assert_eq!(
                        (crc.value() as u128, crc.remainder() as u128),
                        expected,
                        "{entry:?} in {}",
                        stringify!($type)
                    );
                }
            };
        }
        register!(u8);
        register!(u16);
        register!(u32);
        register!(u64);
        register!(u128);
    }
}
