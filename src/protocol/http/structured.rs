use alloc::string::String;
use alloc::vec::Vec;

use crate::codec::base::base64::Base64;
use crate::codec::base::{Encoding, Padding};

use super::HTTPError;

/// A bare item of a structured field (RFC 9651 §3.3). Decimals are held
/// in thousandths, the precision the format has (§3.3.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HTTPBareItem {
    Integer(i64),
    Decimal(i64),
    String(String),
    Token(String),
    ByteSequence(Vec<u8>),
    Boolean(bool),
    Date(i64),
    DisplayString(String),
}

impl HTTPBareItem {
    /// The decimal `value` × 10^-`scale`, rounded to three places, to the
    /// even one when halfway (RFC 9651 §4.1.5); `None` beyond 12 digits
    /// before the point.
    pub fn decimal(value: i128, scale: u32) -> Option<HTTPBareItem> {
        let thousandths = if scale <= 3 {
            value.checked_mul(10i128.checked_pow(3 - scale)?)?
        } else {
            let divisor = 10i128.checked_pow(scale - 3)?;
            let (quotient, remainder) = (value / divisor, (value % divisor).abs());
            let twice = remainder * 2;
            let away = twice > divisor || (twice == divisor && quotient % 2 != 0);
            if away { quotient + value.signum() } else { quotient }
        };
        let thousandths = i64::try_from(thousandths).ok()?;
        (thousandths.unsigned_abs() <= HTTPStructuredField::MAXIMUM_DECIMAL as u64)
            .then_some(HTTPBareItem::Decimal(thousandths))
    }
}

/// The parameters of an item or inner list (RFC 9651 §3.1.2), in order,
/// each key once.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HTTPParameters {
    pub parameters: Vec<(String, HTTPBareItem)>,
}

impl HTTPParameters {
    pub fn get(&self, key: &str) -> Option<&HTTPBareItem> {
        self.parameters.iter().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    /// Sets `key` to `value`, in the place of an earlier value (RFC 9651 §4.2.3.2).
    pub fn set(&mut self, key: &str, value: HTTPBareItem) {
        match self.parameters.iter_mut().find(|(name, _)| name == key) {
            Some(entry) => entry.1 = value,
            None => self.parameters.push((String::from(key), value)),
        }
    }
}

/// An item: a bare item and its parameters (RFC 9651 §3.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HTTPItem {
    pub bare: HTTPBareItem,
    pub parameters: HTTPParameters,
}

impl HTTPItem {
    pub fn new(bare: HTTPBareItem) -> HTTPItem {
        HTTPItem { bare, parameters: HTTPParameters::default() }
    }
}

/// A member of a list or dictionary: an item or an inner list (RFC 9651 §3.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HTTPMember {
    Item(HTTPItem),
    InnerList(Vec<HTTPItem>, HTTPParameters),
}

/// Structured field values (RFC 9651): their parsing (§4.2) and
/// serialization (§4.1) as lists, dictionaries and items.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HTTPStructuredField;

impl HTTPStructuredField {
    /// The largest integer: 15 digits (RFC 9651 §3.3.1).
    pub const MAXIMUM_INTEGER: i64 = 999_999_999_999_999;
    /// The largest decimal in thousandths: 12 digits before the point (§3.3.2).
    pub const MAXIMUM_DECIMAL: i64 = 999_999_999_999_999;

    /// The error of a value that does not parse or serialize.
    pub fn invalid() -> HTTPError {
        HTTPError::Malformed("an invalid structured field")
    }

    /// The list of `value`, the field's lines combined (RFC 9651 §4.2.1); an
    /// empty value is an empty list.
    pub fn parse_list(value: &[u8]) -> Result<Vec<HTTPMember>, HTTPError> {
        let mut input = HTTPStructuredField::start(value)?;
        let mut members = Vec::new();
        while !input.is_empty() {
            members.push(HTTPStructuredField::member(&mut input)?);
            HTTPStructuredField::next(&mut input)?;
        }
        Ok(members)
    }

    /// The dictionary of `value` (RFC 9651 §4.2.2): members in order, a
    /// later one of a key replacing the earlier in its place.
    pub fn parse_dictionary(value: &[u8]) -> Result<Vec<(String, HTTPMember)>, HTTPError> {
        let mut input = HTTPStructuredField::start(value)?;
        let mut members: Vec<(String, HTTPMember)> = Vec::new();
        while !input.is_empty() {
            let key = HTTPStructuredField::key(&mut input)?;
            let member = if input.first() == Some(&b'=') {
                input = &input[1..];
                HTTPStructuredField::member(&mut input)?
            } else {
                let parameters = HTTPStructuredField::parameters(&mut input)?;
                HTTPMember::Item(HTTPItem { bare: HTTPBareItem::Boolean(true), parameters })
            };
            match members.iter_mut().find(|(name, _)| *name == key) {
                Some(entry) => entry.1 = member,
                None => members.push((key, member)),
            }
            HTTPStructuredField::next(&mut input)?;
        }
        Ok(members)
    }

    /// The item of `value` (RFC 9651 §4.2.3).
    pub fn parse_item(value: &[u8]) -> Result<HTTPItem, HTTPError> {
        let mut input = HTTPStructuredField::start(value)?;
        let item = HTTPStructuredField::item(&mut input)?;
        if !HTTPStructuredField::skip_spaces(input).is_empty() {
            return Err(HTTPStructuredField::invalid());
        }
        Ok(item)
    }

    /// The ASCII input without leading spaces (RFC 9651 §4.2 steps 1, 2).
    pub fn start(value: &[u8]) -> Result<&[u8], HTTPError> {
        if !value.is_ascii() {
            return Err(HTTPStructuredField::invalid());
        }
        Ok(HTTPStructuredField::skip_spaces(value))
    }

    pub fn skip_spaces(input: &[u8]) -> &[u8] {
        let start = input.iter().position(|byte| *byte != b' ').unwrap_or(input.len());
        &input[start..]
    }

    pub fn skip_whitespace(input: &[u8]) -> &[u8] {
        let start = input.iter().position(|byte| *byte != b' ' && *byte != b'\t').unwrap_or(input.len());
        &input[start..]
    }

    /// After a member of a list or dictionary: whitespace, then the end or a
    /// comma and more members.
    pub fn next(input: &mut &[u8]) -> Result<(), HTTPError> {
        *input = HTTPStructuredField::skip_whitespace(input);
        if input.is_empty() {
            return Ok(());
        }
        if input[0] != b',' {
            return Err(HTTPStructuredField::invalid());
        }
        *input = HTTPStructuredField::skip_whitespace(&input[1..]);
        if input.is_empty() {
            return Err(HTTPStructuredField::invalid());
        }
        Ok(())
    }

    /// An item or an inner list (RFC 9651 §4.2.1.1).
    pub fn member(input: &mut &[u8]) -> Result<HTTPMember, HTTPError> {
        if input.first() != Some(&b'(') {
            return Ok(HTTPMember::Item(HTTPStructuredField::item(input)?));
        }
        *input = &input[1..];
        let mut items = Vec::new();
        loop {
            *input = HTTPStructuredField::skip_spaces(input);
            match input.first() {
                Some(b')') => {
                    *input = &input[1..];
                    let parameters = HTTPStructuredField::parameters(input)?;
                    return Ok(HTTPMember::InnerList(items, parameters));
                }
                Some(_) => {
                    items.push(HTTPStructuredField::item(input)?);
                    if !matches!(input.first(), Some(b' ') | Some(b')')) {
                        return Err(HTTPStructuredField::invalid());
                    }
                }
                None => return Err(HTTPStructuredField::invalid()),
            }
        }
    }

    pub fn item(input: &mut &[u8]) -> Result<HTTPItem, HTTPError> {
        let bare = HTTPStructuredField::bare_item(input)?;
        let parameters = HTTPStructuredField::parameters(input)?;
        Ok(HTTPItem { bare, parameters })
    }

    /// Parameters (RFC 9651 §4.2.3.2).
    pub fn parameters(input: &mut &[u8]) -> Result<HTTPParameters, HTTPError> {
        let mut parameters = HTTPParameters::default();
        while input.first() == Some(&b';') {
            *input = HTTPStructuredField::skip_spaces(&input[1..]);
            let key = HTTPStructuredField::key(input)?;
            let value = if input.first() == Some(&b'=') {
                *input = &input[1..];
                HTTPStructuredField::bare_item(input)?
            } else {
                HTTPBareItem::Boolean(true)
            };
            parameters.set(&key, value);
        }
        Ok(parameters)
    }

    /// A key (RFC 9651 §4.2.3.3): a lowercase letter or "*", then lowercase
    /// letters, digits, "_", "-", "." and "*".
    pub fn key(input: &mut &[u8]) -> Result<String, HTTPError> {
        if !input.first().is_some_and(|byte| byte.is_ascii_lowercase() || *byte == b'*') {
            return Err(HTTPStructuredField::invalid());
        }
        let end = input
            .iter()
            .position(|byte| {
                !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.' | b'*'))
            })
            .unwrap_or(input.len());
        let key = String::from_utf8_lossy(&input[..end]).into_owned();
        *input = &input[end..];
        Ok(key)
    }

    /// A bare item (RFC 9651 §4.2.3.1).
    pub fn bare_item(input: &mut &[u8]) -> Result<HTTPBareItem, HTTPError> {
        match input.first() {
            Some(b'-') | Some(b'0'..=b'9') => HTTPStructuredField::number(input),
            Some(b'"') => HTTPStructuredField::string(input).map(HTTPBareItem::String),
            Some(b'*') | Some(b'a'..=b'z') | Some(b'A'..=b'Z') => HTTPStructuredField::token(input),
            Some(b':') => HTTPStructuredField::byte_sequence(input),
            Some(b'?') => match input.get(1) {
                Some(b'0') | Some(b'1') => {
                    let value = input[1] == b'1';
                    *input = &input[2..];
                    Ok(HTTPBareItem::Boolean(value))
                }
                _ => Err(HTTPStructuredField::invalid()),
            },
            Some(b'@') => {
                *input = &input[1..];
                match HTTPStructuredField::number(input)? {
                    HTTPBareItem::Integer(seconds) => Ok(HTTPBareItem::Date(seconds)),
                    _ => Err(HTTPStructuredField::invalid()),
                }
            }
            Some(b'%') => HTTPStructuredField::display_string(input),
            _ => Err(HTTPStructuredField::invalid()),
        }
    }

    /// An integer or a decimal (RFC 9651 §4.2.4).
    pub fn number(input: &mut &[u8]) -> Result<HTTPBareItem, HTTPError> {
        let invalid = HTTPStructuredField::invalid;
        let negative = input.first() == Some(&b'-');
        let digits: &[u8] = if negative { &input[1..] } else { input };
        if !digits.first().is_some_and(u8::is_ascii_digit) {
            return Err(invalid());
        }
        let mut length = 0;
        let mut point = None;
        for byte in digits {
            match byte {
                b'0'..=b'9' => {}
                b'.' if point.is_none() => {
                    if length > 12 {
                        return Err(invalid());
                    }
                    point = Some(length);
                }
                _ => break,
            }
            length += 1;
            if point.is_none() && length > 15 || length > 16 {
                return Err(invalid());
            }
        }
        let text = &digits[..length];
        let value = match point {
            None => {
                let value = text.iter().fold(0i64, |value, digit| value * 10 + i64::from(digit - b'0'));
                HTTPBareItem::Integer(if negative { -value } else { value })
            }
            Some(point) => {
                let fraction = &text[point + 1..];
                if fraction.is_empty() || fraction.len() > 3 {
                    return Err(invalid());
                }
                let whole = text[..point].iter().fold(0i64, |value, digit| value * 10 + i64::from(digit - b'0'));
                let mut thousandths = fraction.iter().fold(0i64, |value, digit| value * 10 + i64::from(digit - b'0'));
                thousandths *= 10i64.pow(3 - fraction.len() as u32);
                let value = whole * 1000 + thousandths;
                HTTPBareItem::Decimal(if negative { -value } else { value })
            }
        };
        *input = &digits[length..];
        Ok(value)
    }

    /// A string (RFC 9651 §4.2.5): visible ASCII and spaces, with "\" before "\"" and "\\" only.
    pub fn string(input: &mut &[u8]) -> Result<String, HTTPError> {
        let mut out = String::new();
        let mut index = 1;
        loop {
            match input.get(index) {
                Some(b'\\') => match input.get(index + 1) {
                    Some(byte @ (b'"' | b'\\')) => {
                        out.push(*byte as char);
                        index += 2;
                    }
                    _ => return Err(HTTPStructuredField::invalid()),
                },
                Some(b'"') => {
                    *input = &input[index + 1..];
                    return Ok(out);
                }
                Some(byte @ 0x20..=0x7E) => {
                    out.push(*byte as char);
                    index += 1;
                }
                _ => return Err(HTTPStructuredField::invalid()),
            }
        }
    }

    /// A token (RFC 9651 §4.2.6): a letter or "*", then tchar, ":" and "/".
    pub fn token(input: &mut &[u8]) -> Result<HTTPBareItem, HTTPError> {
        let end = input
            .iter()
            .skip(1)
            .position(|byte| !(super::HTTPSyntax::is_tchar(*byte) || *byte == b':' || *byte == b'/'))
            .map_or(input.len(), |offset| offset + 1);
        let token = String::from_utf8_lossy(&input[..end]).into_owned();
        *input = &input[end..];
        Ok(HTTPBareItem::Token(token))
    }

    /// A byte sequence (RFC 9651 §4.2.7): base64 between colons, padding optional.
    pub fn byte_sequence(input: &mut &[u8]) -> Result<HTTPBareItem, HTTPError> {
        let end = input[1..].iter().position(|byte| *byte == b':').ok_or(HTTPStructuredField::invalid())? + 1;
        let encoded = &input[1..end];
        let lenient = Base64::new(Base64::STANDARD_ALPHABET, Padding::Indifferent);
        let decoded = lenient.decode(encoded).map_err(|_| HTTPStructuredField::invalid())?;
        *input = &input[end + 1..];
        Ok(HTTPBareItem::ByteSequence(decoded))
    }

    /// A display string (RFC 9651 §4.2.10): "%" and a string whose bytes
    /// of UTF-8 other than visible ASCII are escaped "%" and two lowercase hex digits.
    pub fn display_string(input: &mut &[u8]) -> Result<HTTPBareItem, HTTPError> {
        let invalid = HTTPStructuredField::invalid;
        if input.get(1) != Some(&b'"') {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        let mut index = 2;
        loop {
            match input.get(index) {
                Some(b'%') => {
                    let hex = input.get(index + 1..index + 3).ok_or(invalid())?;
                    let digit = |byte: u8| match byte {
                        b'0'..=b'9' => Some(byte - b'0'),
                        b'a'..=b'f' => Some(byte - b'a' + 10),
                        _ => None,
                    };
                    let (Some(high), Some(low)) = (digit(hex[0]), digit(hex[1])) else { return Err(invalid()) };
                    bytes.push(high << 4 | low);
                    index += 3;
                }
                Some(b'"') => {
                    let text = String::from_utf8(bytes).map_err(|_| invalid())?;
                    *input = &input[index + 1..];
                    return Ok(HTTPBareItem::DisplayString(text));
                }
                Some(byte @ 0x20..=0x7E) => {
                    bytes.push(*byte);
                    index += 1;
                }
                _ => return Err(invalid()),
            }
        }
    }

    /// Appends the list `members` (RFC 9651 §4.1.1).
    pub fn serialize_list(members: &[HTTPMember], out: &mut Vec<u8>) -> Result<(), HTTPError> {
        for (index, member) in members.iter().enumerate() {
            if index > 0 {
                out.extend_from_slice(b", ");
            }
            HTTPStructuredField::serialize_member(member, out)?;
        }
        Ok(())
    }

    /// Appends the dictionary `members` (RFC 9651 §4.1.2).
    pub fn serialize_dictionary(members: &[(String, HTTPMember)], out: &mut Vec<u8>) -> Result<(), HTTPError> {
        for (index, (key, member)) in members.iter().enumerate() {
            if index > 0 {
                out.extend_from_slice(b", ");
            }
            HTTPStructuredField::serialize_key(key, out)?;
            match member {
                HTTPMember::Item(HTTPItem { bare: HTTPBareItem::Boolean(true), parameters }) => {
                    HTTPStructuredField::serialize_parameters(parameters, out)?
                }
                member => {
                    out.push(b'=');
                    HTTPStructuredField::serialize_member(member, out)?;
                }
            }
        }
        Ok(())
    }

    /// Appends `item` (RFC 9651 §4.1.3).
    pub fn serialize_item(item: &HTTPItem, out: &mut Vec<u8>) -> Result<(), HTTPError> {
        HTTPStructuredField::serialize_bare_item(&item.bare, out)?;
        HTTPStructuredField::serialize_parameters(&item.parameters, out)
    }

    pub fn serialize_member(member: &HTTPMember, out: &mut Vec<u8>) -> Result<(), HTTPError> {
        match member {
            HTTPMember::Item(item) => HTTPStructuredField::serialize_item(item, out),
            HTTPMember::InnerList(items, parameters) => {
                out.push(b'(');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(b' ');
                    }
                    HTTPStructuredField::serialize_item(item, out)?;
                }
                out.push(b')');
                HTTPStructuredField::serialize_parameters(parameters, out)
            }
        }
    }

    pub fn serialize_parameters(parameters: &HTTPParameters, out: &mut Vec<u8>) -> Result<(), HTTPError> {
        for (key, value) in &parameters.parameters {
            out.push(b';');
            HTTPStructuredField::serialize_key(key, out)?;
            if *value != HTTPBareItem::Boolean(true) {
                out.push(b'=');
                HTTPStructuredField::serialize_bare_item(value, out)?;
            }
        }
        Ok(())
    }

    pub fn serialize_key(key: &str, out: &mut Vec<u8>) -> Result<(), HTTPError> {
        let mut input = key.as_bytes();
        if HTTPStructuredField::key(&mut input).is_err() || !input.is_empty() {
            return Err(HTTPStructuredField::invalid());
        }
        out.extend_from_slice(key.as_bytes());
        Ok(())
    }

    /// Appends a bare item (RFC 9651 §4.1.3.1); decimals are already of three places.
    pub fn serialize_bare_item(bare: &HTTPBareItem, out: &mut Vec<u8>) -> Result<(), HTTPError> {
        let invalid = HTTPStructuredField::invalid;
        match bare {
            HTTPBareItem::Integer(value) | HTTPBareItem::Date(value) => {
                if value.unsigned_abs() > HTTPStructuredField::MAXIMUM_INTEGER as u64 {
                    return Err(invalid());
                }
                if matches!(bare, HTTPBareItem::Date(_)) {
                    out.push(b'@');
                }
                out.extend_from_slice(alloc::format!("{value}").as_bytes());
            }
            HTTPBareItem::Decimal(thousandths) => {
                if thousandths.unsigned_abs() > HTTPStructuredField::MAXIMUM_DECIMAL as u64 {
                    return Err(invalid());
                }
                if *thousandths < 0 {
                    out.push(b'-');
                }
                let magnitude = thousandths.unsigned_abs();
                let fraction = alloc::format!("{:03}", magnitude % 1000);
                let fraction = fraction.trim_end_matches('0');
                let fraction = if fraction.is_empty() { "0" } else { fraction };
                out.extend_from_slice(alloc::format!("{}.{fraction}", magnitude / 1000).as_bytes());
            }
            HTTPBareItem::String(text) => {
                out.push(b'"');
                for byte in text.bytes() {
                    if !(0x20..=0x7E).contains(&byte) {
                        return Err(invalid());
                    }
                    if byte == b'"' || byte == b'\\' {
                        out.push(b'\\');
                    }
                    out.push(byte);
                }
                out.push(b'"');
            }
            HTTPBareItem::Token(token) => {
                let mut input = token.as_bytes();
                let first = input.first().is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'*');
                if !first || HTTPStructuredField::token(&mut input).is_err() || !input.is_empty() {
                    return Err(invalid());
                }
                out.extend_from_slice(token.as_bytes());
            }
            HTTPBareItem::ByteSequence(bytes) => {
                out.push(b':');
                out.extend_from_slice(Base64::STANDARD.encode(bytes).as_bytes());
                out.push(b':');
            }
            HTTPBareItem::Boolean(value) => out.extend_from_slice(if *value { b"?1" } else { b"?0" }),
            HTTPBareItem::DisplayString(text) => {
                out.extend_from_slice(b"%\"");
                for byte in text.bytes() {
                    if byte == b'%' || byte == b'"' || !(0x20..=0x7E).contains(&byte) {
                        out.extend_from_slice(alloc::format!("%{byte:02x}").as_bytes());
                    } else {
                        out.push(byte);
                    }
                }
                out.push(b'"');
            }
        }
        Ok(())
    }
}
