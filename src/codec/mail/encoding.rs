use alloc::string::String;
use alloc::vec::Vec;

use super::{MIMEQuotedPrintable, MailError, MailReader};
use crate::codec::base::base64::Base64;
use crate::codec::base::{Encoding, Padding};

/// A Content-Transfer-Encoding (RFC 2045 §6).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MIMETransferEncoding {
    SevenBit,
    EightBit,
    Binary,
    QuotedPrintable,
    Base64,
    /// Another: an `x-` token, which is not decoded (§6.4).
    Other(String),
}

impl MIMETransferEncoding {
    /// The longest line of Base64 data (RFC 2045 §6.8).
    pub const BASE64_LINE: usize = 76;

    /// The encoding of a field value; a token in any case, CFWS around it (§6.1).
    pub fn parse(value: &[u8]) -> Result<MIMETransferEncoding, MailError> {
        let mut reader = MailReader::new(value, false);
        let token = reader.token()?;
        if !reader.is_end() {
            return Err(reader.error("more after a transfer encoding"));
        }
        let token = core::str::from_utf8(token).unwrap_or_default();
        Ok(match token.to_ascii_lowercase().as_str() {
            "7bit" => MIMETransferEncoding::SevenBit,
            "8bit" => MIMETransferEncoding::EightBit,
            "binary" => MIMETransferEncoding::Binary,
            "quoted-printable" => MIMETransferEncoding::QuotedPrintable,
            "base64" => MIMETransferEncoding::Base64,
            _ => MIMETransferEncoding::Other(String::from(token)),
        })
    }

    pub fn name(&self) -> &str {
        match self {
            MIMETransferEncoding::SevenBit => "7bit",
            MIMETransferEncoding::EightBit => "8bit",
            MIMETransferEncoding::Binary => "binary",
            MIMETransferEncoding::QuotedPrintable => "quoted-printable",
            MIMETransferEncoding::Base64 => "base64",
            MIMETransferEncoding::Other(name) => name,
        }
    }

    /// Whether the encoding is an identity: the body is the data (§6.2).
    pub fn is_identity(&self) -> bool {
        matches!(self, MIMETransferEncoding::SevenBit | MIMETransferEncoding::EightBit | MIMETransferEncoding::Binary)
    }

    /// The data of `body`. Quoted-Printable as text (its line breaks CRLF).
    /// Fails for another encoding, which RFC 2045 §6.4 says to treat as
    /// application/octet-stream.
    pub fn decode(&self, body: &[u8]) -> Result<Vec<u8>, MailError> {
        match self {
            MIMETransferEncoding::QuotedPrintable => Ok(MIMEQuotedPrintable::new(false).decode(body)),
            MIMETransferEncoding::Base64 => MIMETransferEncoding::decode_base64(body),
            MIMETransferEncoding::Other(_) => Err(MailError::Encoding),
            _ => Ok(body.to_vec()),
        }
    }

    /// Writes `data` encoded to `out`: Base64 in lines of 76 characters,
    /// Quoted-Printable as text, an identity as it is. Fails for another.
    pub fn encode(&self, data: &[u8], out: &mut Vec<u8>) -> Result<(), MailError> {
        match self {
            MIMETransferEncoding::QuotedPrintable => MIMEQuotedPrintable::new(false).encode(data, out),
            MIMETransferEncoding::Base64 => {
                let group = MIMETransferEncoding::BASE64_LINE / 4 * 3;
                for (index, chunk) in data.chunks(group).enumerate() {
                    if index > 0 {
                        out.extend_from_slice(b"\r\n");
                    }
                    out.extend_from_slice(Base64::STANDARD.encode(chunk).as_bytes());
                }
            }
            MIMETransferEncoding::Other(_) => return Err(MailError::Encoding),
            _ => out.extend_from_slice(data),
        }
        Ok(())
    }

    /// The data of Base64 text of a body: characters not of the alphabet,
    /// line breaks among them, are ignored (§6.8), the data ends at the
    /// padding, and bits after the last byte are ignored.
    pub fn decode_base64(body: &[u8]) -> Result<Vec<u8>, MailError> {
        let alphabet = Base64::STANDARD_ALPHABET;
        let mut text: Vec<u8> =
            body.iter().copied().filter(|byte| *byte == b'=' || alphabet.decode(*byte).is_some()).collect();
        if let Some(padding) = text.iter().position(|byte| *byte == b'=') {
            text.truncate(padding);
        }
        // The last character of a group of 2 or 3 has bits of no byte: clear them.
        let unused = match text.len() % 4 {
            2 => 4,
            3 => 2,
            1 => return Err(MailError::Base64(crate::codec::base::BaseError::InvalidLength { length: text.len() })),
            _ => 0,
        };
        if let Some(last) = text.last_mut()
            && let Some(value) = alphabet.decode(*last)
        {
            *last = alphabet.encode(value & !((1 << unused) - 1));
        }
        Ok(Base64::new(alphabet, Padding::Forbidden).decode(&text)?)
    }
}
