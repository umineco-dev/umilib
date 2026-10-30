use super::X509Error;
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Time, Tag};

/// A `Time` (RFC 5280 §4.1.2.5): a UTCTime or a GeneralizedTime, in whole
/// seconds of UTC.
///
/// Reading accepts both forms for any year they can hold; RFC 5280 asks CAs
/// for UTCTime through 2049 and GeneralizedTime from 2050, which
/// [`Time::new`] chooses and [`Time::is_canonical`] checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Time {
    UTC(ASN1Time),
    Generalized(ASN1Time),
}

impl Time {
    /// `time` in the form RFC 5280 §4.1.2.5 requires: UTCTime for the years
    /// 1950 to 2049, GeneralizedTime for the others. Fails with
    /// [`X509Error::InvalidTime`] for a fraction of a second, which neither
    /// form may carry in a certificate.
    pub fn new(time: ASN1Time) -> Result<Time, X509Error> {
        if time.nanosecond != 0 {
            return Err(X509Error::InvalidTime);
        }
        Ok(if (1950..=2049).contains(&time.year) { Time::UTC(time) } else { Time::Generalized(time) })
    }

    /// The time `seconds` after 1970-01-01T00:00:00Z (see [`Time::new`]).
    pub fn from_unix_seconds(seconds: i64) -> Result<Time, X509Error> {
        Time::new(ASN1Time::from_unix_seconds(seconds).map_err(|_| X509Error::InvalidTime)?)
    }

    /// The moment, whatever the form.
    pub const fn time(&self) -> ASN1Time {
        match self {
            Time::UTC(time) | Time::Generalized(time) => *time,
        }
    }

    /// Seconds since 1970-01-01T00:00:00Z.
    pub fn to_unix_seconds(&self) -> i64 {
        self.time().to_unix_seconds()
    }

    /// Whether the form is the one RFC 5280 §4.1.2.5 requires for the year.
    pub fn is_canonical(&self) -> bool {
        match Time::new(self.time()) {
            Ok(canonical) => canonical == *self,
            Err(_) => false,
        }
    }

    /// Reads the next `Time` of `reader`: a UTCTime, or a GeneralizedTime
    /// without a fraction of a second (RFC 5280 §4.1.2.5.2).
    pub fn decode(reader: &mut DERReader<'_>) -> Result<Time, X509Error> {
        if reader.peek_tag() == Some(Tag::UTC_TIME) {
            return Ok(Time::UTC(reader.read_utc_time()?));
        }
        let time = reader.read_with(Tag::GENERALIZED_TIME, |element| {
            let content = element.primitive()?;
            let (time, fraction) = ASN1Time::check_generalized_time(content).map_err(|_| element.invalid())?;
            if !fraction.is_empty() {
                return Err(element.invalid());
            }
            Ok(time)
        })?;
        Ok(Time::Generalized(time))
    }

    /// Reads a GeneralizedTime as RFC 5280 §4.1.2.5.2 defines it: in UTC,
    /// without a fraction of a second (the form of the times of CRL entry
    /// extensions and of OCSP, RFC 6960 §4.2.2.1).
    pub fn decode_generalized(reader: &mut DERReader<'_>) -> Result<ASN1Time, X509Error> {
        match reader.peek_tag() {
            Some(Tag::GENERALIZED_TIME) => Ok(Time::decode(reader)?.time()),
            _ => Err(X509Error::InvalidTime),
        }
    }

    /// Writes `time` as a GeneralizedTime of RFC 5280 §4.1.2.5.2; fails with
    /// [`X509Error::InvalidTime`] for a fraction of a second.
    pub fn encode_generalized(time: &ASN1Time, writer: &mut DERWriter) -> Result<(), X509Error> {
        Time::Generalized(*time).encode(writer)
    }

    /// Writes the time in its form; fails with [`X509Error::InvalidTime`] if
    /// the form cannot hold it (UTCTime outside 1950 to 2049, a fraction).
    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        let written = match self {
            Time::UTC(time) => writer.write_utc_time(time),
            Time::Generalized(time) if time.nanosecond == 0 => writer.write_generalized_time(time),
            Time::Generalized(_) => return Err(X509Error::InvalidTime),
        };
        written.map_err(|_| X509Error::InvalidTime)
    }
}

/// A `Validity` (RFC 5280 §4.1.2.5): the period of a certificate, both ends included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Validity {
    pub not_before: Time,
    pub not_after: Time,
}

impl Validity {
    /// The `notAfter` of a certificate with no well-defined expiration date
    /// (RFC 5280 §4.1.2.5): 9999-12-31T23:59:59Z.
    pub const NO_EXPIRATION: ASN1Time =
        ASN1Time { year: 9999, month: 12, day: 31, hour: 23, minute: 59, second: 59, nanosecond: 0 };

    /// The period from `not_before` through `not_after`, each in the form
    /// [`Time::new`] chooses.
    pub fn new(not_before: ASN1Time, not_after: ASN1Time) -> Result<Validity, X509Error> {
        Ok(Validity { not_before: Time::new(not_before)?, not_after: Time::new(not_after)? })
    }

    /// Whether `time` is within the period, both ends included.
    pub fn contains(&self, time: ASN1Time) -> bool {
        self.not_before.time() <= time && time <= self.not_after.time()
    }

    /// Reads the next `Validity` of `reader`.
    pub fn decode(reader: &mut DERReader<'_>) -> Result<Validity, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let not_before = Time::decode(&mut sequence)?;
        let not_after = Time::decode(&mut sequence)?;
        sequence.finish()?;
        Ok(Validity { not_before, not_after })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        let mut inner = DERWriter::new();
        self.not_before.encode(&mut inner)?;
        self.not_after.encode(&mut inner)?;
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }
}
