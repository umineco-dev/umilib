use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use super::{
    BasicConstraints, ExtensionValue, Extensions, KeyUsage, Name, SerialNumber, SubjectAlternativeName, Validity,
    X509Error,
};
use crate::auth::cert::key::{AlgorithmIdentifier, PrivateKey, PublicKey, SignatureAlgorithm, SubjectPublicKeyInfo};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Error, BitString, Tag};
use crate::codec::pem::{PEMConfig, PEMDocument};
use crate::crypto::random::Random;

/// The version of a certificate or a CRL (RFC 5280 §4.1.2.1, §5.1.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Version {
    V1,
    V2,
    V3,
}

impl Version {
    /// The version of the INTEGER `value` of the `Version` syntax (0 for
    /// v1); other values, versions this module does not know, are refused.
    pub fn from_integer(value: i128) -> Result<Version, X509Error> {
        match value {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2),
            2 => Ok(Version::V3),
            _ => Err(X509Error::Version),
        }
    }

    /// The INTEGER of the `Version` syntax.
    pub const fn to_integer(self) -> i128 {
        match self {
            Version::V1 => 0,
            Version::V2 => 1,
            Version::V3 => 2,
        }
    }
}

/// A `TBSCertificate` (RFC 5280 §4.1): the fields of a certificate that its
/// issuer signs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TBSCertificate<'a> {
    pub version: Version,
    pub serial_number: SerialNumber<'a>,
    /// The signature algorithm, which must equal the one outside the signed fields.
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: Name<'a>,
    pub validity: Validity,
    pub subject: Name<'a>,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    pub issuer_unique_id: Option<BitString<'a>>,
    pub subject_unique_id: Option<BitString<'a>>,
    /// The extensions; an empty list stands for the absent field.
    pub extensions: Extensions<'a>,
}

impl<'a> TBSCertificate<'a> {
    /// Fails with [`X509Error::Version`] if the version does not allow the
    /// fields present: unique identifiers need v2 or v3, extensions v3.
    pub fn check_version(&self) -> Result<(), X509Error> {
        let unique_ids = self.issuer_unique_id.is_some() || self.subject_unique_id.is_some();
        if (unique_ids && self.version < Version::V2) || (!self.extensions.is_empty() && self.version < Version::V3) {
            return Err(X509Error::Version);
        }
        Ok(())
    }

    /// Checks the requirements RFC 5280 places on the certificates a CA
    /// issues, beyond the syntax that [`TBSCertificate::encode`] checks:
    /// - a positive serial number of at most 20 octets (§4.1.2.2);
    /// - a non-empty issuer (§4.1.2.4);
    /// - times in UTCTime through 2049 and GeneralizedTime from 2050 (§4.1.2.5);
    /// - an empty subject only with a critical subject alternative name (§4.1.2.6);
    /// - no unique identifiers (§4.1.2.8);
    /// - extensions of different types (§4.2);
    /// - a `pathLenConstraint` only with `cA` and the `keyCertSign` key usage (§4.2.1.9).
    pub fn check(&self) -> Result<(), X509Error> {
        self.check_version()?;
        self.serial_number.check()?;
        if self.issuer.is_empty() {
            return Err(X509Error::InvalidName);
        }
        if !self.validity.not_before.is_canonical() || !self.validity.not_after.is_canonical() {
            return Err(X509Error::InvalidTime);
        }
        if self.subject.is_empty() {
            let alternative_name = self.extensions.get(&SubjectAlternativeName::OID);
            if !alternative_name.is_some_and(|extension| extension.critical) {
                return Err(X509Error::InvalidName);
            }
        }
        if self.issuer_unique_id.is_some() || self.subject_unique_id.is_some() {
            return Err(X509Error::InvalidName);
        }
        self.extensions.check()?;
        if let Some(constraints) = self.extensions.typed::<BasicConstraints>()?
            && constraints.path_length.is_some()
        {
            let signs =
                self.extensions.typed::<KeyUsage>()?.is_some_and(|usage| usage.contains(KeyUsage::KEY_CERT_SIGN));
            if !constraints.ca || !signs {
                return Err(X509Error::InvalidExtension);
            }
        }
        Ok(())
    }

    /// Reads the next `TBSCertificate` of `reader`. The version written as
    /// v1, which DER omits, is accepted; a version that does not allow the
    /// fields present is refused (see [`TBSCertificate::check_version`]).
    pub fn decode(reader: &mut DERReader<'a>) -> Result<TBSCertificate<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let version = match sequence.read_optional_explicit(0)? {
            Some(mut explicit) => {
                let integer = explicit.read_integer()?;
                explicit.finish()?;
                Version::from_integer(integer.as_i128().map_err(|_| X509Error::Version)?)?
            }
            None => Version::V1,
        };
        let serial_number = SerialNumber::decode(&mut sequence)?;
        let signature = AlgorithmIdentifier::decode(&mut sequence)?;
        let issuer = Name::decode(&mut sequence)?;
        let validity = Validity::decode(&mut sequence)?;
        let subject = Name::decode(&mut sequence)?;
        let subject_public_key_info = SubjectPublicKeyInfo::decode(&mut sequence)?;
        let issuer_unique_id =
            sequence.read_optional(Tag::context(1, false))?.map(|element| element.as_bit_string()).transpose()?;
        let subject_unique_id =
            sequence.read_optional(Tag::context(2, false))?.map(|element| element.as_bit_string()).transpose()?;
        let extensions = match sequence.read_optional_explicit(3)? {
            Some(mut explicit) => {
                let extensions = Extensions::decode(&mut explicit)?;
                explicit.finish()?;
                extensions
            }
            None => Extensions::new(),
        };
        sequence.finish()?;
        let tbs = TBSCertificate {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id,
            subject_unique_id,
            extensions,
        };
        tbs.check_version()?;
        Ok(tbs)
    }

    /// The `TBSCertificate` of the DER encoding `bytes`.
    pub fn from_der(bytes: &'a [u8]) -> Result<TBSCertificate<'a>, X509Error> {
        let mut reader = DERReader::new(bytes);
        let tbs = TBSCertificate::decode(&mut reader)?;
        reader.finish()?;
        Ok(tbs)
    }

    /// Writes the fields; fails if the version does not allow the fields
    /// present or the extensions repeat a type.
    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        self.check_version()?;
        let mut inner = DERWriter::new();
        if self.version != Version::V1 {
            inner.write_explicit(0, |explicit| {
                explicit.write_integer_i128(self.version.to_integer());
                Ok(())
            })?;
        }
        self.serial_number.encode(&mut inner);
        self.signature.encode(&mut inner)?;
        self.issuer.encode(&mut inner);
        self.validity.encode(&mut inner)?;
        self.subject.encode(&mut inner);
        self.subject_public_key_info.encode(&mut inner)?;
        for (number, unique_id) in [(1, &self.issuer_unique_id), (2, &self.subject_unique_id)] {
            if let Some(unique_id) = unique_id {
                let mut content = Vec::new();
                unique_id.encode_content(&mut content);
                inner.write_element(Tag::context(number, false), &content);
            }
        }
        if !self.extensions.is_empty() {
            let mut extensions = DERWriter::new();
            self.extensions.encode(&mut extensions)?;
            inner.write_element(Tag::context(3, true), extensions.as_bytes());
        }
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn to_der(&self) -> Result<Vec<u8>, X509Error> {
        let mut writer = DERWriter::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }

    /// The certificate of these fields signed by `key` with the algorithm of
    /// [`TBSCertificate::signature`], after [`TBSCertificate::check`].
    pub fn sign<R: Random>(&self, key: &PrivateKey, random: &mut R) -> Result<Certificate<'static>, X509Error> {
        self.check()?;
        let algorithm = SignatureAlgorithm::from_identifier(&self.signature)?;
        let tbs_encoding = self.to_der()?;
        let signature = key.sign(&algorithm, &tbs_encoding, random)?;
        Ok(Certificate {
            tbs_certificate: self.clone().into_owned(),
            tbs_encoding: Cow::Owned(tbs_encoding),
            signature_algorithm: self.signature.clone().into_owned(),
            signature: Cow::Owned(signature),
        })
    }

    pub fn into_owned(self) -> TBSCertificate<'static> {
        TBSCertificate {
            version: self.version,
            serial_number: self.serial_number.into_owned(),
            signature: self.signature.into_owned(),
            issuer: self.issuer.into_owned(),
            validity: self.validity,
            subject: self.subject.into_owned(),
            subject_public_key_info: self.subject_public_key_info.into_owned(),
            issuer_unique_id: self.issuer_unique_id.map(BitString::into_owned),
            subject_unique_id: self.subject_unique_id.map(BitString::into_owned),
            extensions: self.extensions.into_owned(),
        }
    }
}

/// A `Certificate` (RFC 5280 §4.1): signed fields, the signature algorithm
/// and the signature.
///
/// A certificate is read from or made into its encoding and never changed,
/// so that the fields always match the signed bytes; it keeps the signed
/// bytes as they were read, so that a signature over an encoding that
/// [`TBSCertificate::encode`] would write differently still verifies.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<'a> {
    tbs_certificate: TBSCertificate<'a>,
    tbs_encoding: Cow<'a, [u8]>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: Cow<'a, [u8]>,
}

impl<'a> Certificate<'a> {
    /// The label of a certificate in PEM (RFC 7468 §5).
    pub const PEM_LABEL: &'static str = "CERTIFICATE";

    /// Reads the next `Certificate` of `reader`. The signature algorithm
    /// must equal the one inside the signed fields, and the signature must
    /// be whole octets.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<Certificate<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let tbs_encoding = sequence.peek()?.encoding;
        let tbs_certificate = TBSCertificate::decode(&mut sequence)?;
        let signature_algorithm = AlgorithmIdentifier::decode(&mut sequence)?;
        let signature = Certificate::decode_signature(&mut sequence)?;
        sequence.finish()?;
        if signature_algorithm != tbs_certificate.signature {
            return Err(X509Error::AlgorithmMismatch);
        }
        Ok(Certificate {
            tbs_certificate,
            tbs_encoding: Cow::Borrowed(tbs_encoding),
            signature_algorithm,
            signature: Cow::Borrowed(signature),
        })
    }

    /// Reads a signature BIT STRING of whole octets.
    pub fn decode_signature(reader: &mut DERReader<'a>) -> Result<&'a [u8], X509Error> {
        reader
            .read_with(Tag::BIT_STRING, |element| {
                let content = element.primitive()?;
                match content.split_first() {
                    Some((0, octets)) => Ok(octets),
                    _ => Err(ASN1Error::InvalidContent { position: element.content_position() }),
                }
            })
            .map_err(X509Error::from)
    }

    /// The certificate of the DER encoding `bytes`.
    pub fn from_der(bytes: &'a [u8]) -> Result<Certificate<'a>, X509Error> {
        let mut reader = DERReader::new(bytes);
        let certificate = Certificate::decode(&mut reader)?;
        reader.finish()?;
        Ok(certificate)
    }

    /// The certificate of the first PEM document of `text`, which must have the label `CERTIFICATE`.
    pub fn from_pem(text: &str) -> Result<Certificate<'static>, X509Error> {
        Certificate::from_pem_document(&PEMDocument::decode(text.as_bytes(), PEMConfig::default())?)
    }

    /// The certificates of every PEM document of `text`, in order (a chain
    /// or a set of trust anchors); each must have the label `CERTIFICATE`.
    pub fn from_pem_all(text: &str) -> Result<Vec<Certificate<'static>>, X509Error> {
        let documents = PEMDocument::decode_all(text.as_bytes(), PEMConfig::default())?;
        documents.iter().map(Certificate::from_pem_document).collect()
    }

    /// The certificate of a PEM document, which must have the label `CERTIFICATE`.
    pub fn from_pem_document(document: &PEMDocument) -> Result<Certificate<'static>, X509Error> {
        if document.label() != Certificate::PEM_LABEL {
            return Err(X509Error::PEMLabel);
        }
        Ok(Certificate::from_der(document.data())?.into_owned())
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
        Ok(PEMDocument::new(Certificate::PEM_LABEL, self.to_der()?)?.encode())
    }

    pub fn tbs_certificate(&self) -> &TBSCertificate<'a> {
        &self.tbs_certificate
    }

    /// The signed bytes: the DER encoding of the `TBSCertificate` as read.
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

    /// The subject's public key, within the default key limits.
    pub fn public_key(&self) -> Result<PublicKey, X509Error> {
        Ok(PublicKey::from_info(&self.tbs_certificate.subject_public_key_info)?)
    }

    /// Succeeds if the signature verifies under `issuer`, the public key of
    /// the issuer, with the signature algorithm of the certificate.
    pub fn verify(&self, issuer: &PublicKey) -> Result<(), X509Error> {
        let algorithm = SignatureAlgorithm::from_identifier(&self.signature_algorithm)?;
        Ok(issuer.verify(&algorithm, &self.tbs_encoding, &self.signature)?)
    }

    /// Whether the issuer and subject names match, by the comparison of
    /// RFC 5280 §7.1 (a self-issued certificate, §6.1).
    pub fn is_self_issued(&self) -> bool {
        self.tbs_certificate.issuer.matches(&self.tbs_certificate.subject)
    }

    pub fn into_owned(self) -> Certificate<'static> {
        Certificate {
            tbs_certificate: self.tbs_certificate.into_owned(),
            tbs_encoding: Cow::Owned(self.tbs_encoding.into_owned()),
            signature_algorithm: self.signature_algorithm.into_owned(),
            signature: Cow::Owned(self.signature.into_owned()),
        }
    }
}
