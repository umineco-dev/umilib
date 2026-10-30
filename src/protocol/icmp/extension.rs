use crate::bytes::Writer;
use crate::protocol::ip::InternetChecksum;

use super::ICMPError;

/// One object of an extension structure (RFC 4884 §8): its class, its
/// sub-type and its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ICMPExtensionObject<'a> {
    pub class: u8,
    pub kind: u8,
    pub payload: &'a [u8],
}

impl ICMPExtensionObject<'_> {
    /// The length of the object header.
    pub const HEADER_LENGTH: usize = 4;
    /// The class of the Interface Information Object (RFC 5837).
    pub const INTERFACE_INFORMATION: u8 = 2;
    /// The class of the MPLS Label Stack Object (RFC 4950).
    pub const MPLS_LABEL_STACK: u8 = 1;

    /// The unit of object lengths: objects are 32-bit words (RFC 4884 §8).
    pub const UNIT: usize = 4;

    /// Writes the object; the payload must make it a multiple of 4 bytes, at most 65,535.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), ICMPError> {
        let length = ICMPExtensionObject::HEADER_LENGTH + self.payload.len();
        if !length.is_multiple_of(ICMPExtensionObject::UNIT) {
            return Err(ICMPError::Length);
        }
        let length = u16::try_from(length).map_err(|_| ICMPError::Length)?;
        out.write(&length.to_be_bytes())?;
        out.write(&[self.class, self.kind])?;
        Ok(out.write(self.payload)?)
    }
}

/// The extension structure appended to an ICMP error message (RFC 4884
/// §7): the header, of version 2, and the objects after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ICMPExtensions<'a> {
    /// The checksum as received; zero if none was sent.
    pub checksum: u16,
    /// The objects, as bytes.
    pub objects: &'a [u8],
}

impl<'a> ICMPExtensions<'a> {
    pub const VERSION: u8 = 2;
    pub const HEADER_LENGTH: usize = 4;
    /// The fewest bytes of the original datagram before extensions (RFC 4884 §4).
    pub const MINIMUM_ORIGINAL_LENGTH: usize = 128;
    /// The words of the length attribute: 32 bits for ICMP, 64 bits for ICMPv6 (RFC 4884 §4).
    pub const WORDS: [usize; 2] = [4, 8];

    /// The structure that `bytes` is. The version must be 2, the checksum,
    /// if one was sent, right, and the objects well formed: one or more
    /// (RFC 4884 §7), each of whole 32-bit words (§8).
    pub fn decode(bytes: &'a [u8]) -> Result<ICMPExtensions<'a>, ICMPError> {
        let header = bytes.get(..ICMPExtensions::HEADER_LENGTH).ok_or(ICMPError::Length)?;
        if header[0] >> 4 != ICMPExtensions::VERSION {
            return Err(ICMPError::Version);
        }
        let checksum = u16::from_be_bytes([header[2], header[3]]);
        if checksum != 0 && !InternetChecksum::verify(bytes) {
            return Err(ICMPError::Checksum);
        }
        let extensions = ICMPExtensions { checksum, objects: &bytes[ICMPExtensions::HEADER_LENGTH..] };
        extensions.check()?;
        Ok(extensions)
    }

    /// Checks that the objects are one or more and well formed (RFC 4884 §7, §8).
    pub fn check(&self) -> Result<(), ICMPError> {
        if self.objects.is_empty() {
            return Err(ICMPError::Length);
        }
        for object in self.iter() {
            object?;
        }
        Ok(())
    }

    /// Checks that `word` is the word of a version of ICMP (RFC 4884 §4).
    pub fn check_word(word: usize) -> Result<(), ICMPError> {
        if ICMPExtensions::WORDS.contains(&word) { Ok(()) } else { Err(ICMPError::Invalid) }
    }

    /// Writes the body of an extended error message (RFC 4884 §4): the
    /// original datagram `original`, zero-padded to a multiple of `word`
    /// bytes (4 for ICMP, 8 for ICMPv6, else [`ICMPError::Invalid`]) and to
    /// at least 128 bytes, then the structure. Returns the length attribute:
    /// the padded original datagram in words, which must fit 8 bits.
    pub fn encode_body(&self, original: &[u8], word: usize, out: &mut impl Writer) -> Result<u8, ICMPError> {
        ICMPExtensions::check_word(word)?;
        self.check()?;
        let padded = original.len().max(ICMPExtensions::MINIMUM_ORIGINAL_LENGTH).next_multiple_of(word);
        let attribute = u8::try_from(padded / word).map_err(|_| ICMPError::Length)?;
        out.write(original)?;
        let zeros = [0u8; 8];
        for _ in 0..(padded - original.len()) / zeros.len() {
            out.write(&zeros)?;
        }
        out.write(&zeros[..(padded - original.len()) % zeros.len()])?;
        self.encode(out)?;
        Ok(attribute)
    }

    /// Splits the body of an error message whose length attribute is
    /// `attribute` words of `word` bytes into the original datagram and the
    /// extension structure, if any (RFC 4884 §4, §5): without the attribute
    /// (zero), the whole body is the original datagram. A structure needs an
    /// original datagram of at least 128 bytes before it (RFC 4884 §4).
    pub fn split_body(
        body: &'a [u8],
        attribute: u8,
        word: usize,
    ) -> Result<(&'a [u8], Option<ICMPExtensions<'a>>), ICMPError> {
        ICMPExtensions::check_word(word)?;
        if attribute == 0 {
            return Ok((body, None));
        }
        let length = attribute as usize * word;
        let original = body.get(..length).ok_or(ICMPError::Length)?;
        let rest = &body[length..];
        if rest.is_empty() {
            return Ok((original, None));
        }
        if length < ICMPExtensions::MINIMUM_ORIGINAL_LENGTH {
            return Err(ICMPError::Length);
        }
        Ok((original, Some(ICMPExtensions::decode(rest)?)))
    }

    /// The objects in order.
    pub fn iter(&self) -> ICMPExtensionObjects<'a> {
        ICMPExtensionObjects { bytes: self.objects }
    }

    /// Writes the structure: its objects (encoded, as by
    /// [`ICMPExtensionObject::encode`], one or more) after a header with
    /// their checksum (`checksum` is not used).
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), ICMPError> {
        self.check()?;
        let mut checksum = InternetChecksum::new();
        checksum.update(&[ICMPExtensions::VERSION << 4, 0, 0, 0]);
        checksum.update(self.objects);
        out.write(&[ICMPExtensions::VERSION << 4, 0])?;
        out.write(&checksum.finish().to_be_bytes())?;
        Ok(out.write(self.objects)?)
    }
}

/// The objects of [`ICMPExtensions::iter`]; an error ends it.
#[derive(Clone, Debug)]
pub struct ICMPExtensionObjects<'a> {
    pub bytes: &'a [u8],
}

impl<'a> Iterator for ICMPExtensionObjects<'a> {
    type Item = Result<ICMPExtensionObject<'a>, ICMPError>;

    fn next(&mut self) -> Option<Result<ICMPExtensionObject<'a>, ICMPError>> {
        if self.bytes.is_empty() {
            return None;
        }
        let length = self.bytes.get(..2).map(|length| u16::from_be_bytes([length[0], length[1]]) as usize);
        let Some(length) = length.filter(|&length| {
            length >= ICMPExtensionObject::HEADER_LENGTH
                && length <= self.bytes.len()
                && length.is_multiple_of(ICMPExtensionObject::UNIT)
        }) else {
            self.bytes = &[];
            return Some(Err(ICMPError::Length));
        };
        let object = ICMPExtensionObject { class: self.bytes[2], kind: self.bytes[3], payload: &self.bytes[4..length] };
        self.bytes = &self.bytes[length..];
        Some(Ok(object))
    }
}
