use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use super::{Certificate, Extensions, Name, SerialNumber, Time, Version, X509Error};
use crate::auth::cert::key::{AlgorithmIdentifier, PrivateKey, PublicKey, SignatureAlgorithm};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{BitString, Tag};
use crate::codec::pem::{PEMConfig, PEMDocument};
use crate::crypto::random::Random;

/// An entry of `revokedCertificates` (RFC 5280 §5.1.2.6): a revoked
/// certificate, when it was revoked, and the entry extensions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RevokedCertificate<'a> {
    pub serial_number: SerialNumber<'a>,
    pub revocation_date: Time,
    /// The entry extensions; an empty list stands for the absent field.
    pub extensions: Extensions<'a>,
}

impl<'a> RevokedCertificate<'a> {
    pub fn decode(reader: &mut DERReader<'a>) -> Result<RevokedCertificate<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let serial_number = SerialNumber::decode(&mut sequence)?;
        let revocation_date = Time::decode(&mut sequence)?;
        let extensions = if sequence.is_empty() { Extensions::new() } else { Extensions::decode(&mut sequence)? };
        sequence.finish()?;
        Ok(RevokedCertificate { serial_number, revocation_date, extensions })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        let mut inner = DERWriter::new();
        self.serial_number.encode(&mut inner);
        self.revocation_date.encode(&mut inner)?;
        if !self.extensions.is_empty() {
            self.extensions.encode(&mut inner)?;
        }
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn into_owned(self) -> RevokedCertificate<'static> {
        RevokedCertificate {
            serial_number: self.serial_number.into_owned(),
            revocation_date: self.revocation_date,
            extensions: self.extensions.into_owned(),
        }
    }
}

/// A `TBSCertList` (RFC 5280 §5.1): the fields of a CRL that its issuer signs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TBSCertList<'a> {
    /// [`Version::V1`] for the absent field, [`Version::V2`] for a v2 CRL.
    pub version: Version,
    /// The signature algorithm, which must equal the one outside the signed fields.
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: Name<'a>,
    pub this_update: Time,
    pub next_update: Option<Time>,
    /// The revoked certificates; an empty list stands for the absent field,
    /// which RFC 5280 §5.1.2.6 requires when there are none (an empty list
    /// written out is read, and is not written).
    pub revoked_certificates: Vec<RevokedCertificate<'a>>,
    /// The CRL extensions; an empty list stands for the absent field.
    pub extensions: Extensions<'a>,
}

impl<'a> TBSCertList<'a> {
    /// Fails with [`X509Error::Version`] unless the version is v1 or v2 and
    /// is v2 when there are CRL or entry extensions (RFC 5280 §5.1.2.1).
    pub fn check_version(&self) -> Result<(), X509Error> {
        let extensions =
            !self.extensions.is_empty() || self.revoked_certificates.iter().any(|entry| !entry.extensions.is_empty());
        if self.version == Version::V3 || (extensions && self.version != Version::V2) {
            return Err(X509Error::Version);
        }
        Ok(())
    }

    /// Checks the requirements RFC 5280 places on the CRLs an issuer makes,
    /// beyond the syntax that [`TBSCertList::encode`] checks:
    /// - a non-empty issuer (§5.1.2.3);
    /// - times in UTCTime through 2049 and GeneralizedTime from 2050 (§5.1.2.4 to §5.1.2.6);
    /// - a `nextUpdate` (§5.1.2.5);
    /// - extensions of different types in the CRL and in each entry (§5.2, §5.3).
    pub fn check(&self) -> Result<(), X509Error> {
        self.check_version()?;
        if self.issuer.is_empty() {
            return Err(X509Error::InvalidName);
        }
        let next_update = self.next_update.ok_or(X509Error::InvalidTime)?;
        let mut times = [self.this_update, next_update]
            .into_iter()
            .chain(self.revoked_certificates.iter().map(|entry| entry.revocation_date));
        if !times.all(|time| time.is_canonical()) {
            return Err(X509Error::InvalidTime);
        }
        self.extensions.check()?;
        self.revoked_certificates.iter().try_for_each(|entry| entry.extensions.check())
    }

    /// Reads the next `TBSCertList` of `reader`. A version other than v2
    /// written out is refused, as is a version that does not allow the
    /// extensions present (see [`TBSCertList::check_version`]).
    pub fn decode(reader: &mut DERReader<'a>) -> Result<TBSCertList<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let version = match sequence.peek_tag() {
            Some(Tag::INTEGER) => match sequence.read_integer()?.as_i128() {
                Ok(1) => Version::V2,
                _ => return Err(X509Error::Version),
            },
            _ => Version::V1,
        };
        let signature = AlgorithmIdentifier::decode(&mut sequence)?;
        let issuer = Name::decode(&mut sequence)?;
        let this_update = Time::decode(&mut sequence)?;
        let next_update = match sequence.peek_tag() {
            Some(Tag::UTC_TIME | Tag::GENERALIZED_TIME) => Some(Time::decode(&mut sequence)?),
            _ => None,
        };
        let mut revoked_certificates = Vec::new();
        if sequence.peek_tag() == Some(Tag::SEQUENCE) {
            let mut entries = sequence.read_sequence()?;
            while !entries.is_empty() {
                revoked_certificates.push(RevokedCertificate::decode(&mut entries)?);
            }
        }
        let extensions = match sequence.read_optional_explicit(0)? {
            Some(mut explicit) => {
                let extensions = Extensions::decode(&mut explicit)?;
                explicit.finish()?;
                extensions
            }
            None => Extensions::new(),
        };
        sequence.finish()?;
        let tbs =
            TBSCertList { version, signature, issuer, this_update, next_update, revoked_certificates, extensions };
        tbs.check_version()?;
        Ok(tbs)
    }

    /// The `TBSCertList` of the DER encoding `bytes`.
    pub fn from_der(bytes: &'a [u8]) -> Result<TBSCertList<'a>, X509Error> {
        let mut reader = DERReader::new(bytes);
        let tbs = TBSCertList::decode(&mut reader)?;
        reader.finish()?;
        Ok(tbs)
    }

    /// Writes the fields; fails if the version does not allow the
    /// extensions present or a list of extensions repeats a type.
    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        self.check_version()?;
        let mut inner = DERWriter::new();
        if self.version == Version::V2 {
            inner.write_integer_i128(Version::V2.to_integer());
        }
        self.signature.encode(&mut inner)?;
        self.issuer.encode(&mut inner);
        self.this_update.encode(&mut inner)?;
        if let Some(next_update) = &self.next_update {
            next_update.encode(&mut inner)?;
        }
        if !self.revoked_certificates.is_empty() {
            let mut entries = DERWriter::new();
            self.revoked_certificates.iter().try_for_each(|entry| entry.encode(&mut entries))?;
            inner.write_element(Tag::SEQUENCE, entries.as_bytes());
        }
        if !self.extensions.is_empty() {
            let mut extensions = DERWriter::new();
            self.extensions.encode(&mut extensions)?;
            inner.write_element(Tag::context(0, true), extensions.as_bytes());
        }
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn to_der(&self) -> Result<Vec<u8>, X509Error> {
        let mut writer = DERWriter::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }

    /// The CRL of these fields signed by `key` with the algorithm of
    /// [`TBSCertList::signature`], after [`TBSCertList::check`].
    pub fn sign<R: Random>(&self, key: &PrivateKey, random: &mut R) -> Result<CertificateList<'static>, X509Error> {
        self.check()?;
        let algorithm = SignatureAlgorithm::from_identifier(&self.signature)?;
        let tbs_encoding = self.to_der()?;
        let signature = key.sign(&algorithm, &tbs_encoding, random)?;
        Ok(CertificateList {
            tbs_cert_list: self.clone().into_owned(),
            tbs_encoding: Cow::Owned(tbs_encoding),
            signature_algorithm: self.signature.clone().into_owned(),
            signature: Cow::Owned(signature),
        })
    }

    pub fn into_owned(self) -> TBSCertList<'static> {
        TBSCertList {
            version: self.version,
            signature: self.signature.into_owned(),
            issuer: self.issuer.into_owned(),
            this_update: self.this_update,
            next_update: self.next_update,
            revoked_certificates: self.revoked_certificates.into_iter().map(RevokedCertificate::into_owned).collect(),
            extensions: self.extensions.into_owned(),
        }
    }
}

/// A `CertificateList` (RFC 5280 §5.1), a CRL: signed fields, the
/// signature algorithm and the signature. Like a [`Certificate`], it is
/// never changed and keeps the signed bytes as they were read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertificateList<'a> {
    tbs_cert_list: TBSCertList<'a>,
    tbs_encoding: Cow<'a, [u8]>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: Cow<'a, [u8]>,
}

impl<'a> CertificateList<'a> {
    /// The label of a CRL in PEM (RFC 7468 §6).
    pub const PEM_LABEL: &'static str = "X509 CRL";

    /// Reads the next `CertificateList` of `reader`. The signature
    /// algorithm must equal the one inside the signed fields, and the
    /// signature must be whole octets.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<CertificateList<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let tbs_encoding = sequence.peek()?.encoding;
        let tbs_cert_list = TBSCertList::decode(&mut sequence)?;
        let signature_algorithm = AlgorithmIdentifier::decode(&mut sequence)?;
        let signature = Certificate::decode_signature(&mut sequence)?;
        sequence.finish()?;
        if signature_algorithm != tbs_cert_list.signature {
            return Err(X509Error::AlgorithmMismatch);
        }
        Ok(CertificateList {
            tbs_cert_list,
            tbs_encoding: Cow::Borrowed(tbs_encoding),
            signature_algorithm,
            signature: Cow::Borrowed(signature),
        })
    }

    /// The CRL of the DER encoding `bytes`.
    pub fn from_der(bytes: &'a [u8]) -> Result<CertificateList<'a>, X509Error> {
        let mut reader = DERReader::new(bytes);
        let list = CertificateList::decode(&mut reader)?;
        reader.finish()?;
        Ok(list)
    }

    /// The CRL of the first PEM document of `text`, which must have the label `X509 CRL`.
    pub fn from_pem(text: &str) -> Result<CertificateList<'static>, X509Error> {
        let document = PEMDocument::decode(text.as_bytes(), PEMConfig::default())?;
        if document.label() != CertificateList::PEM_LABEL {
            return Err(X509Error::PEMLabel);
        }
        Ok(CertificateList::from_der(document.data())?.into_owned())
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        let mut inner = DERWriter::new();
        inner.write_raw(&self.tbs_encoding);
        self.signature_algorithm.encode(&mut inner)?;
        inner.write_bit_string(&BitString::new(0, self.signature.as_ref())?)?;
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn to_der(&self) -> Result<Vec<u8>, X509Error> {
        let mut writer = DERWriter::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }

    pub fn to_pem(&self) -> Result<String, X509Error> {
        Ok(PEMDocument::new(CertificateList::PEM_LABEL, self.to_der()?)?.encode())
    }

    pub fn tbs_cert_list(&self) -> &TBSCertList<'a> {
        &self.tbs_cert_list
    }

    /// The signed bytes: the DER encoding of the `TBSCertList` as read.
    pub fn tbs_encoding(&self) -> &[u8] {
        &self.tbs_encoding
    }

    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier<'a> {
        &self.signature_algorithm
    }

    /// The octets of the signature.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Succeeds if the signature verifies under `issuer`, the public key of
    /// the CRL issuer, with the signature algorithm of the CRL.
    pub fn verify(&self, issuer: &PublicKey) -> Result<(), X509Error> {
        let algorithm = SignatureAlgorithm::from_identifier(&self.signature_algorithm)?;
        Ok(issuer.verify(&algorithm, &self.tbs_encoding, &self.signature)?)
    }

    /// The entry of `serial_number`, if the CRL lists it. The entries of
    /// an indirect CRL belong to the issuers their `CertificateIssuer`
    /// extensions name, which this lookup does not consider.
    pub fn find(&self, serial_number: &SerialNumber<'_>) -> Option<&RevokedCertificate<'a>> {
        self.tbs_cert_list.revoked_certificates.iter().find(|entry| entry.serial_number == *serial_number)
    }

    pub fn into_owned(self) -> CertificateList<'static> {
        CertificateList {
            tbs_cert_list: self.tbs_cert_list.into_owned(),
            tbs_encoding: Cow::Owned(self.tbs_encoding.into_owned()),
            signature_algorithm: self.signature_algorithm.into_owned(),
            signature: Cow::Owned(self.signature.into_owned()),
        }
    }
}
