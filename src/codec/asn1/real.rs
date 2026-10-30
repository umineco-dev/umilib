use alloc::vec::Vec;

use super::ASN1Error;

/// The contents octets of a REAL (X.690 section 8.5) and their DER form
/// (section 11.3).
///
/// A REAL is zero (no contents octets), a special value (one octet), a binary
/// value `S * N * 2^F * B^E` with the base `B` 2, 8 or 16, or a decimal value
/// in an ISO 6093 form. DER writes binary values in base 2 with `F = 0`, an
/// odd `N` and both `N` and `E` in the fewest octets, and decimal values in
/// the NR3 form `[-]digits.E[-]digits` without superfluous zeros.
pub struct ASN1Real;

impl ASN1Real {
    pub const PLUS_INFINITY: u8 = 0x40;
    pub const MINUS_INFINITY: u8 = 0x41;
    pub const NOT_A_NUMBER: u8 = 0x42;
    pub const MINUS_ZERO: u8 = 0x43;
    /// The first octet of a decimal value in the NR3 form.
    pub const NR3: u8 = 0x03;

    /// The DER contents of the REAL whose BER contents are `content`. Binary
    /// values stay binary and decimal values stay decimal, because the base
    /// of the abstract value is kept (section 8.5.4). Exponents that do not
    /// fit 128 bits (binary) or 64 bits (decimal) fail with `OutOfRange`.
    pub fn to_der(content: &[u8]) -> Result<Vec<u8>, ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        let Some(&first) = content.first() else {
            return Ok(Vec::new());
        };
        if first & 0x80 != 0 {
            return ASN1Real::binary_to_der(content);
        }
        if first & 0x40 != 0 {
            if content.len() != 1 || first > ASN1Real::MINUS_ZERO {
                return Err(invalid);
            }
            return Ok(Vec::from(content));
        }
        ASN1Real::decimal_to_der(first & 0x3F, &content[1..])
    }

    /// Fails unless `content` is the DER contents of a REAL: `NonCanonical`
    /// if it is a valid BER encoding of a value with another DER encoding.
    pub fn validate_der(content: &[u8]) -> Result<(), ASN1Error> {
        if ASN1Real::to_der(content)? != content {
            return Err(ASN1Error::NonCanonical { position: 0 });
        }
        Ok(())
    }

    /// The DER form of a binary value (sections 8.5.7 and 11.3.1).
    pub fn binary_to_der(content: &[u8]) -> Result<Vec<u8>, ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        let first = content[0];
        let negative = first & 0x40 != 0;
        let base_bits: i128 = match (first >> 4) & 0x03 {
            0 => 1,
            1 => 3,
            2 => 4,
            _ => return Err(invalid),
        };
        let scale = ((first >> 2) & 0x03) as i128;
        let (exponent_bytes, mantissa) = match first & 0x03 {
            format @ 0..=2 => {
                let length = format as usize + 1;
                if content.len() < 1 + length {
                    return Err(invalid);
                }
                (&content[1..1 + length], &content[1 + length..])
            }
            _ => {
                let length = *content.get(1).ok_or(invalid)? as usize;
                if length == 0 || content.len() < 2 + length {
                    return Err(invalid);
                }
                let exponent = &content[2..2 + length];
                // The first nine bits are neither all zeros nor all ones.
                if length > 1
                    && ((exponent[0] == 0 && exponent[1] & 0x80 == 0)
                        || (exponent[0] == 0xFF && exponent[1] & 0x80 != 0))
                {
                    return Err(invalid);
                }
                (exponent, &content[2 + length..])
            }
        };
        let exponent = ASN1Real::signed(exponent_bytes)?;
        // N is a positive integer: zero is written without contents octets.
        let mut mantissa: Vec<u8> = mantissa.iter().copied().skip_while(|&byte| byte == 0).collect();
        if mantissa.is_empty() {
            return Err(invalid);
        }
        // Make N odd: the zero bits shifted out move into the exponent.
        let zero_bytes = mantissa.iter().rev().take_while(|&&byte| byte == 0).count();
        mantissa.truncate(mantissa.len() - zero_bytes);
        let zero_bits = mantissa.last().map_or(0, |byte| byte.trailing_zeros());
        if zero_bits > 0 {
            let mut carry = 0u8;
            for byte in mantissa.iter_mut() {
                let shifted_out = *byte << (8 - zero_bits);
                *byte = (*byte >> zero_bits) | carry;
                carry = shifted_out;
            }
            if mantissa.first() == Some(&0) {
                mantissa.remove(0);
            }
        }
        let shift = zero_bytes as i128 * 8 + zero_bits as i128;
        let exponent = exponent
            .checked_mul(base_bits)
            .and_then(|exponent| exponent.checked_add(scale))
            .and_then(|exponent| exponent.checked_add(shift))
            .ok_or(ASN1Error::OutOfRange)?;
        let exponent_bytes = ASN1Real::minimal_signed(exponent);
        let mut output = Vec::with_capacity(3 + exponent_bytes.len() + mantissa.len());
        let sign = if negative { 0x40 } else { 0 };
        match exponent_bytes.len() {
            length @ 1..=3 => output.push(0x80 | sign | (length as u8 - 1)),
            length => {
                output.push(0x80 | sign | 0x03);
                output.push(length as u8);
            }
        }
        output.extend_from_slice(&exponent_bytes);
        output.extend_from_slice(&mantissa);
        Ok(output)
    }

    /// The two's complement big-endian `bytes` as an `i128`.
    pub fn signed(bytes: &[u8]) -> Result<i128, ASN1Error> {
        let negative = bytes.first().is_some_and(|&byte| byte & 0x80 != 0);
        let fill = if negative { 0xFF } else { 0x00 };
        // Leading sign octets beyond 16 bytes do not change the value.
        let start = bytes.len().saturating_sub(16);
        if bytes[..start].iter().any(|&byte| byte != fill) || (start > 0 && (bytes[start] & 0x80 != 0) != negative) {
            return Err(ASN1Error::OutOfRange);
        }
        let mut value: i128 = if negative { -1 } else { 0 };
        for &byte in &bytes[start..] {
            value = (value << 8) | byte as i128;
        }
        Ok(value)
    }

    /// `value` in two's complement in the fewest octets.
    pub fn minimal_signed(value: i128) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let mut start = 0;
        while start < bytes.len() - 1
            && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
                || (bytes[start] == 0xFF && bytes[start + 1] & 0x80 != 0))
        {
            start += 1;
        }
        Vec::from(&bytes[start..])
    }

    /// The DER form of a decimal value in the ISO 6093 form `form` (1, 2 or 3
    /// for NR1, NR2 and NR3) with the characters `text` (sections 8.5.8 and 11.3.2).
    pub fn decimal_to_der(form: u8, text: &[u8]) -> Result<Vec<u8>, ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        if !(1..=3).contains(&form) {
            return Err(invalid);
        }
        let mut rest = &text[text.iter().take_while(|&&byte| byte == b' ').count()..];
        let negative = match rest.first() {
            Some(b'-') => {
                rest = &rest[1..];
                true
            }
            Some(b'+') => {
                rest = &rest[1..];
                false
            }
            _ => false,
        };
        let integer_length = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        let (integer, mut rest) = rest.split_at(integer_length);
        let mut fraction: &[u8] = &[];
        let has_mark = matches!(rest.first(), Some(b'.' | b','));
        if has_mark {
            let fraction_length = rest[1..].iter().take_while(|byte| byte.is_ascii_digit()).count();
            fraction = &rest[1..1 + fraction_length];
            rest = &rest[1 + fraction_length..];
        }
        let mut exponent: i64 = 0;
        let has_exponent = matches!(rest.first(), Some(b'E' | b'e'));
        if has_exponent {
            let mut digits = &rest[1..];
            let exponent_negative = match digits.first() {
                Some(b'-') => {
                    digits = &digits[1..];
                    true
                }
                Some(b'+') => {
                    digits = &digits[1..];
                    false
                }
                _ => false,
            };
            if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                return Err(invalid);
            }
            for &digit in digits {
                exponent = exponent
                    .checked_mul(10)
                    .and_then(|exponent| exponent.checked_add((digit - b'0') as i64))
                    .ok_or(ASN1Error::OutOfRange)?;
            }
            if exponent_negative {
                exponent = -exponent;
            }
            rest = &rest[rest.len()..];
        }
        let shape = match form {
            1 => !has_mark && !has_exponent && !integer.is_empty(),
            2 => has_mark && !has_exponent && !(integer.is_empty() && fraction.is_empty()),
            _ => has_mark && has_exponent && !(integer.is_empty() && fraction.is_empty()),
        };
        if !shape || !rest.is_empty() {
            return Err(invalid);
        }
        // The value is the integer `digits` times 10^exponent.
        let mut digits: Vec<u8> = integer.iter().chain(fraction).copied().skip_while(|&digit| digit == b'0').collect();
        exponent = exponent.checked_sub(fraction.len() as i64).ok_or(ASN1Error::OutOfRange)?;
        if digits.is_empty() {
            return Ok(if negative { Vec::from([ASN1Real::MINUS_ZERO]) } else { Vec::new() });
        }
        let trailing = digits.iter().rev().take_while(|&&digit| digit == b'0').count();
        digits.truncate(digits.len() - trailing);
        exponent = exponent.checked_add(trailing as i64).ok_or(ASN1Error::OutOfRange)?;
        let mut output = Vec::with_capacity(digits.len() + 24);
        output.push(ASN1Real::NR3);
        if negative {
            output.push(b'-');
        }
        output.extend_from_slice(&digits);
        output.extend_from_slice(b".E");
        if exponent == 0 {
            output.extend_from_slice(b"+0");
        } else {
            output.extend_from_slice(alloc::format!("{exponent}").as_bytes());
        }
        Ok(output)
    }
}
