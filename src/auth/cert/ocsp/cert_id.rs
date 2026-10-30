use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::OCSPError;
use crate::auth::cert::key::{AlgorithmIdentifier, HashAlgorithm};
use crate::auth::cert::x509::{Certificate, Name, SerialNumber};
use crate::codec::asn1::Tag;
use crate::codec::asn1::der::{DERReader, DERWriter};

/// A `CertID` (RFC 6960 §4.1.1): a certificate named by the hashes of its
/// issuer's name and key and its serial number.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertID<'a> {
    pub hash_algorithm: AlgorithmIdentifier<'a>,
    pub issuer_name_hash: Cow<'a, [u8]>,
    pub issuer_key_hash: Cow<'a, [u8]>,
    pub serial_number: SerialNumber<'a>,
}

impl<'a> CertID<'a> {
    /// The identifier of `certificate`, issued by the holder of `issuer_key`
    /// (the bits of its `subjectPublicKey`), with `hash`: the hash of the
    /// DER of the certificate's issuer name and of the key.
    pub fn new(certificate: &Certificate<'_>, issuer_key: &[u8], hash: HashAlgorithm) -> CertID<'static> {
        let tbs = certificate.tbs_certificate();
        CertID::of(&tbs.issuer, issuer_key, &tbs.serial_number, hash)
    }

    /// The identifier of the certificate of `serial_number` issued by the holder of `issuer` and `issuer_key`.
    pub fn of(
        issuer: &Name<'_>,
        issuer_key: &[u8],
        serial_number: &SerialNumber<'_>,
        hash: HashAlgorithm,
    ) -> CertID<'static> {
        let digest = |data: &[u8]| {
            let mut out = [0u8; 64];
            let length = hash.digest(data, &mut out);
            Cow::Owned(out[..length].to_vec())
        };
        CertID {
            hash_algorithm: hash.identifier(),
            issuer_name_hash: digest(issuer.as_der()),
            issuer_key_hash: digest(issuer_key),
            serial_number: serial_number.clone().into_owned(),
        }
    }

    /// Whether both identify the same certificate: the same hash function
    /// (whatever the encoding of its parameters), hashes and serial number.
    pub fn matches(&self, other: &CertID<'_>) -> bool {
        let same_hash = match (
            HashAlgorithm::from_identifier(&self.hash_algorithm),
            HashAlgorithm::from_identifier(&other.hash_algorithm),
        ) {
            (Ok(mine), Ok(theirs)) => mine == theirs,
            _ => self.hash_algorithm == other.hash_algorithm,
        };
        same_hash
            && self.issuer_name_hash == other.issuer_name_hash
            && self.issuer_key_hash == other.issuer_key_hash
            && self.serial_number == other.serial_number
    }

    /// Whether the identifier names `certificate`, issued by the holder of
    /// `issuer_key` (the bits of its `subjectPublicKey`), by its own hash
    /// function; false for a hash function this module does not know.
    pub fn identifies(&self, certificate: &Certificate<'_>, issuer_key: &[u8]) -> bool {
        match HashAlgorithm::from_identifier(&self.hash_algorithm) {
            Ok(hash) => self.matches(&CertID::new(certificate, issuer_key, hash)),
            Err(_) => false,
        }
    }

    pub fn decode(reader: &mut DERReader<'a>) -> Result<CertID<'a>, OCSPError> {
        let mut sequence = reader.read_sequence()?;
        let hash_algorithm = AlgorithmIdentifier::decode(&mut sequence)?;
        let issuer_name_hash = Cow::Borrowed(sequence.read_octet_string()?);
        let issuer_key_hash = Cow::Borrowed(sequence.read_octet_string()?);
        let serial_number = SerialNumber::decode(&mut sequence)?;
        sequence.finish()?;
        Ok(CertID { hash_algorithm, issuer_name_hash, issuer_key_hash, serial_number })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), OCSPError> {
        let mut inner = DERWriter::new();
        self.hash_algorithm.encode(&mut inner)?;
        inner.write_octet_string(&self.issuer_name_hash);
        inner.write_octet_string(&self.issuer_key_hash);
        self.serial_number.encode(&mut inner);
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn from_der(bytes: &'a [u8]) -> Result<CertID<'a>, OCSPError> {
        let mut reader = DERReader::new(bytes);
        let cert_id = CertID::decode(&mut reader)?;
        reader.finish()?;
        Ok(cert_id)
    }

    pub fn to_der(&self) -> Result<Vec<u8>, OCSPError> {
        let mut writer = DERWriter::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }

    pub fn into_owned(self) -> CertID<'static> {
        CertID {
            hash_algorithm: self.hash_algorithm.into_owned(),
            issuer_name_hash: Cow::Owned(self.issuer_name_hash.into_owned()),
            issuer_key_hash: Cow::Owned(self.issuer_key_hash.into_owned()),
            serial_number: self.serial_number.into_owned(),
        }
    }
}
