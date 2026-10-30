use crate::bytes::{Reader, Writer};

use super::{TLSAlertDescription, TLSError, TLSVersion};

/// The type of a record's content: `ContentType` (RFC 9846 §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TLSContentType(pub u8);

impl TLSContentType {
    pub const INVALID: TLSContentType = TLSContentType(0);
    pub const CHANGE_CIPHER_SPEC: TLSContentType = TLSContentType(20);
    pub const ALERT: TLSContentType = TLSContentType(21);
    pub const HANDSHAKE: TLSContentType = TLSContentType(22);
    pub const APPLICATION_DATA: TLSContentType = TLSContentType(23);
}

/// The 5-byte header of a record: its content type, `legacy_record_version`
/// and length (RFC 9846 §5.1, §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TLSRecordHeader {
    pub content_type: TLSContentType,
    pub version: TLSVersion,
    pub length: u16,
}

impl TLSRecordHeader {
    pub const LENGTH: usize = 5;
    /// The largest plaintext fragment: 2^14 bytes (RFC 9846 §5.1).
    pub const MAXIMUM_PLAINTEXT: usize = 1 << 14;
    /// The largest protected record: 2^14 + 256 bytes (RFC 9846 §5.2). TLS
    /// 1.2 allows 2^14 + 2048 (RFC 5246 §6.2.3); no AEAD of TLS 1.2 adds
    /// more than 256, so the limit of TLS 1.3 holds for both.
    pub const MAXIMUM_CIPHERTEXT: usize = (1 << 14) + 256;

    /// The header at the start of `bytes`; fails with `record_overflow` for
    /// a length above `maximum`, the largest fragment acceptable now.
    pub fn decode(bytes: &[u8], maximum: usize) -> Result<TLSRecordHeader, TLSError> {
        let mut reader = Reader::new(bytes);
        let header = TLSRecordHeader {
            content_type: TLSContentType(reader.read_u8().map_err(|_| TLSError::decode())?),
            version: TLSVersion(reader.read_be().map_err(|_| TLSError::decode())?),
            length: reader.read_be().map_err(|_| TLSError::decode())?,
        };
        if header.length as usize > maximum {
            return Err(TLSError::Protocol(TLSAlertDescription::RECORD_OVERFLOW));
        }
        Ok(header)
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write_u8(self.content_type.0)?;
        out.write_be(self.version.0)?;
        out.write_be(self.length)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; TLSRecordHeader::LENGTH] {
        let [version_high, version_low] = self.version.0.to_be_bytes();
        let [length_high, length_low] = self.length.to_be_bytes();
        [self.content_type.0, version_high, version_low, length_high, length_low]
    }
}

/// A record: its header and fragment, borrowed from the bytes read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TLSRecord<'a> {
    pub header: TLSRecordHeader,
    pub fragment: &'a [u8],
}

impl<'a> TLSRecord<'a> {
    /// The first record of `bytes` and the bytes it takes, or `None` if
    /// they do not hold a whole record yet. Fails with `record_overflow`
    /// for a length above `maximum`, which the caller sets to
    /// [`TLSRecordHeader::MAXIMUM_PLAINTEXT`] before record protection and
    /// [`TLSRecordHeader::MAXIMUM_CIPHERTEXT`] after.
    pub fn decode(bytes: &'a [u8], maximum: usize) -> Result<Option<(TLSRecord<'a>, usize)>, TLSError> {
        let Some(head) = bytes.get(..TLSRecordHeader::LENGTH) else { return Ok(None) };
        let header = TLSRecordHeader::decode(head, maximum)?;
        let end = TLSRecordHeader::LENGTH + header.length as usize;
        Ok(bytes.get(TLSRecordHeader::LENGTH..end).map(|fragment| (TLSRecord { header, fragment }, end)))
    }

    /// Writes the record, its header's length being that of the fragment.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        let length =
            u16::try_from(self.fragment.len()).map_err(|_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR))?;
        TLSRecordHeader { length, ..self.header }.encode(out)?;
        out.write(self.fragment)?;
        Ok(())
    }
}
