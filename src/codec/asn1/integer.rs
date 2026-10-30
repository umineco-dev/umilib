use alloc::vec::Vec;

use super::ASN1Error;

/// The contents of an INTEGER or ENUMERATED: a big-endian two's complement
/// number in the fewest octets (X.690 section 8.3), borrowed from the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ASN1Integer<'a> {
    bytes: &'a [u8],
}

impl<'a> ASN1Integer<'a> {
    /// Validates contents: at least one octet, and the first nine bits are
    /// neither all zeros nor all ones (X.690 section 8.3.2, required by BER and DER).
    pub fn new(bytes: &'a [u8]) -> Result<ASN1Integer<'a>, ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        match bytes {
            [] => Err(invalid),
            [0x00, second, ..] if second & 0x80 == 0 => Err(invalid),
            [0xFF, second, ..] if second & 0x80 != 0 => Err(invalid),
            _ => Ok(ASN1Integer { bytes }),
        }
    }

    /// The contents octets.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn is_negative(&self) -> bool {
        self.bytes[0] & 0x80 != 0
    }

    /// The big-endian magnitude of a non-negative integer without the leading
    /// zero octet that keeps it positive (for example an RSA modulus); `None`
    /// for negative integers.
    pub fn magnitude(&self) -> Option<&'a [u8]> {
        if self.is_negative() {
            return None;
        }
        Some(if self.bytes.len() > 1 && self.bytes[0] == 0 { &self.bytes[1..] } else { self.bytes })
    }

    pub fn as_i128(&self) -> Result<i128, ASN1Error> {
        if self.bytes.len() > 16 {
            return Err(ASN1Error::OutOfRange);
        }
        let fill = if self.is_negative() { 0xFF } else { 0x00 };
        let mut full = [fill; 16];
        full[16 - self.bytes.len()..].copy_from_slice(self.bytes);
        Ok(i128::from_be_bytes(full))
    }

    pub fn as_u128(&self) -> Result<u128, ASN1Error> {
        let magnitude = self.magnitude().ok_or(ASN1Error::OutOfRange)?;
        if magnitude.len() > 16 {
            return Err(ASN1Error::OutOfRange);
        }
        let mut full = [0u8; 16];
        full[16 - magnitude.len()..].copy_from_slice(magnitude);
        Ok(u128::from_be_bytes(full))
    }

    pub fn as_i64(&self) -> Result<i64, ASN1Error> {
        i64::try_from(self.as_i128()?).map_err(|_| ASN1Error::OutOfRange)
    }

    pub fn as_u64(&self) -> Result<u64, ASN1Error> {
        u64::try_from(self.as_u128()?).map_err(|_| ASN1Error::OutOfRange)
    }

    /// Appends the contents octets of `value`.
    pub fn encode_i128(value: i128, output: &mut Vec<u8>) {
        let bytes = value.to_be_bytes();
        let mut start = 0;
        // Drop octets that only repeat the sign of the next one.
        while start < 15
            && ((bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0)
                || (bytes[start] == 0xFF && bytes[start + 1] & 0x80 != 0))
        {
            start += 1;
        }
        output.extend_from_slice(&bytes[start..]);
    }

    /// Appends the contents octets of the non-negative integer with the
    /// big-endian `magnitude`: leading zeros are dropped, and one zero octet is
    /// added when the first bit is set.
    pub fn encode_unsigned(magnitude: &[u8], output: &mut Vec<u8>) {
        let start = magnitude.iter().position(|&byte| byte != 0).unwrap_or(magnitude.len());
        let magnitude = &magnitude[start..];
        if magnitude.is_empty() {
            output.push(0);
            return;
        }
        if magnitude[0] & 0x80 != 0 {
            output.push(0);
        }
        output.extend_from_slice(magnitude);
    }
}
