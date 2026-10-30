use super::IPv4Error;

/// The option-type octet of an IPv4 option (RFC 791 §3.1): the copied
/// flag, the class and the number, from the IANA registry "IP Option
/// Numbers".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct IPv4OptionKind(pub u8);

impl IPv4OptionKind {
    pub const END_OF_OPTIONS: IPv4OptionKind = IPv4OptionKind(0);
    pub const NO_OPERATION: IPv4OptionKind = IPv4OptionKind(1);
    pub const RECORD_ROUTE: IPv4OptionKind = IPv4OptionKind(7);
    pub const TIMESTAMP: IPv4OptionKind = IPv4OptionKind(68);
    /// The basic security option of RFC 1108.
    pub const SECURITY: IPv4OptionKind = IPv4OptionKind(130);
    pub const LOOSE_SOURCE_ROUTE: IPv4OptionKind = IPv4OptionKind(131);
    pub const STREAM_IDENTIFIER: IPv4OptionKind = IPv4OptionKind(136);
    pub const STRICT_SOURCE_ROUTE: IPv4OptionKind = IPv4OptionKind(137);
    /// RFC 2113.
    pub const ROUTER_ALERT: IPv4OptionKind = IPv4OptionKind(148);

    /// Whether the option is copied into every fragment (RFC 791 §3.1).
    pub const fn is_copied(&self) -> bool {
        self.0 & 0x80 != 0
    }

    /// 0 for control, 2 for debugging and measurement; 1 and 3 are reserved.
    pub const fn class(&self) -> u8 {
        (self.0 >> 5) & 0b11
    }

    pub const fn number(&self) -> u8 {
        self.0 & 0x1F
    }

    /// Whether the option is one octet without a length (End of Option
    /// List and No Operation).
    pub const fn is_single_octet(&self) -> bool {
        self.0 <= 1
    }
}

/// One option: its kind and the option-data after the type and length octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPv4Option<'a> {
    pub kind: IPv4OptionKind,
    pub data: &'a [u8],
}

/// The options of a header, as the bytes after the fixed 20 bytes: at most
/// 40, padded with zeros (End of Option List) to a multiple of 4 when encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct IPv4Options {
    pub bytes: [u8; IPv4Options::MAXIMUM_LENGTH],
    /// The count of bytes of `bytes` used; beyond 40 counts as 40.
    pub length: u8,
}

impl IPv4Options {
    pub const MAXIMUM_LENGTH: usize = 40;

    pub const fn new() -> IPv4Options {
        IPv4Options { bytes: [0; IPv4Options::MAXIMUM_LENGTH], length: 0 }
    }

    /// The options of `bytes`, which must follow the formats of RFC 791 §3.1.
    pub fn decode(bytes: &[u8]) -> Result<IPv4Options, IPv4Error> {
        if bytes.len() > IPv4Options::MAXIMUM_LENGTH {
            return Err(IPv4Error::Option);
        }
        let mut options = IPv4Options::new();
        options.bytes[..bytes.len()].copy_from_slice(bytes);
        options.length = bytes.len() as u8;
        for option in options.iter() {
            option?;
        }
        Ok(options)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..(self.length as usize).min(IPv4Options::MAXIMUM_LENGTH)]
    }

    /// The length of the options padded to a multiple of 4.
    pub fn padded_length(&self) -> usize {
        self.as_bytes().len().div_ceil(4) * 4
    }

    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// The options up to the End of Option List, without No Operation.
    pub fn iter(&self) -> IPv4OptionIterator<'_> {
        IPv4OptionIterator { bytes: self.as_bytes() }
    }

    /// Appends an option of `kind` with `data` (none for a single-octet kind).
    pub fn push(&mut self, kind: IPv4OptionKind, data: &[u8]) -> Result<(), IPv4Error> {
        let start = self.as_bytes().len();
        let length = if kind.is_single_octet() { 1 } else { data.len() + 2 };
        if (kind.is_single_octet() && !data.is_empty()) || start + length > IPv4Options::MAXIMUM_LENGTH {
            return Err(IPv4Error::Option);
        }
        self.bytes[start] = kind.0;
        if !kind.is_single_octet() {
            self.bytes[start + 1] = length as u8;
            self.bytes[start + 2..start + length].copy_from_slice(data);
        }
        self.length = (start + length) as u8;
        Ok(())
    }

    /// The options copied into every fragment but the first (RFC 791 §3.2).
    pub fn copied(&self) -> IPv4Options {
        let mut copied = IPv4Options::new();
        for option in self.iter().flatten() {
            if option.kind.is_copied() {
                // A subset of options that fit fits.
                let _ = copied.push(option.kind, option.data);
            }
        }
        copied
    }
}

impl Default for IPv4Options {
    fn default() -> IPv4Options {
        IPv4Options::new()
    }
}

/// The options of [`IPv4Options::iter`]; an error ends it.
#[derive(Clone, Debug)]
pub struct IPv4OptionIterator<'a> {
    pub bytes: &'a [u8],
}

impl<'a> Iterator for IPv4OptionIterator<'a> {
    type Item = Result<IPv4Option<'a>, IPv4Error>;

    fn next(&mut self) -> Option<Result<IPv4Option<'a>, IPv4Error>> {
        loop {
            let (&kind, rest) = self.bytes.split_first()?;
            let kind = IPv4OptionKind(kind);
            if kind == IPv4OptionKind::END_OF_OPTIONS {
                self.bytes = &[];
                return None;
            }
            if kind == IPv4OptionKind::NO_OPERATION {
                self.bytes = rest;
                continue;
            }
            let length = rest.first().map(|&length| length as usize);
            let Some(length) = length.filter(|&length| length >= 2 && length <= self.bytes.len()) else {
                self.bytes = &[];
                return Some(Err(IPv4Error::Option));
            };
            let data = &self.bytes[2..length];
            self.bytes = &self.bytes[length..];
            return Some(Ok(IPv4Option { kind, data }));
        }
    }
}
