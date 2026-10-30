use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use crate::auth::cert::key::{
    AlgorithmIdentifier, KeyError, PrivateKey, PublicKey, SignatureAlgorithm, SubjectPublicKeyInfo,
};
use crate::auth::cert::x509::{Attribute, Certificate, Extensions, Name, X509Error};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{BitString, ObjectIdentifier, Tag};
use crate::codec::pem::{PEMConfig, PEMDocument};
use crate::crypto::random::Random;

/// A `CertificationRequestInfo` (RFC 2986 §4.1): the subject, its public
/// key and attributes, which the subject signs. Its version is v1 (0), the
/// only one RFC 2986 defines.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertificationRequestInfo<'a> {
    pub subject: Name<'a>,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    pub attributes: Vec<Attribute<'a>>,
}

impl<'a> CertificationRequestInfo<'a> {
    /// `extensionRequest` (PKCS #9, RFC 2985 §5.4.2): the extensions to put
    /// in the certificate, one `Extensions` value.
    pub const EXTENSION_REQUEST: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E]);
    /// `challengePassword` (PKCS #9, RFC 2985 §5.4.1): a password for the
    /// revocation of the certificate, one `DirectoryString` value.
    pub const CHALLENGE_PASSWORD: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07]);

    /// The `extensionRequest` attribute of `extensions`.
    pub fn extension_request(extensions: &Extensions<'_>) -> Result<Attribute<'static>, X509Error> {
        let mut writer = DERWriter::new();
        extensions.encode(&mut writer)?;
        Ok(Attribute {
            oid: CertificationRequestInfo::EXTENSION_REQUEST,
            values: alloc::vec![Cow::Owned(writer.into_bytes())],
        })
    }

    /// The extensions requested, or none; fails with
    /// [`X509Error::InvalidAttribute`] if there is more than one
    /// `extensionRequest` attribute or it has more than one value.
    pub fn extensions(&self) -> Result<Extensions<'_>, X509Error> {
        let mut requests =
            self.attributes.iter().filter(|attribute| attribute.oid == CertificationRequestInfo::EXTENSION_REQUEST);
        let Some(request) = requests.next() else {
            return Ok(Extensions::new());
        };
        if requests.next().is_some() || request.values.len() != 1 {
            return Err(X509Error::InvalidAttribute);
        }
        let mut reader = DERReader::new(&request.values[0]);
        let extensions = Extensions::decode(&mut reader)?;
        reader.finish()?;
        Ok(extensions)
    }

    /// Checks that the attributes are valid and that the requested
    /// extensions decode, each of a different type.
    pub fn check(&self) -> Result<(), X509Error> {
        self.extensions().map(drop)
    }

    /// Reads the next `CertificationRequestInfo` of `reader`; a version
    /// other than v1 is refused.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<CertificationRequestInfo<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        if sequence.read_integer()?.as_i128() != Ok(0) {
            return Err(X509Error::Version);
        }
        let subject = Name::decode(&mut sequence)?;
        let subject_public_key_info = SubjectPublicKeyInfo::decode(&mut sequence)?;
        let attributes = Attribute::decode_set(&mut sequence.read_set_of_tagged(Tag::context(0, true))?)?;
        sequence.finish()?;
        Ok(CertificationRequestInfo { subject, subject_public_key_info, attributes })
    }

    /// The `CertificationRequestInfo` of the DER encoding `bytes`.
    pub fn from_der(bytes: &'a [u8]) -> Result<CertificationRequestInfo<'a>, X509Error> {
        let mut reader = DERReader::new(bytes);
        let info = CertificationRequestInfo::decode(&mut reader)?;
        reader.finish()?;
        Ok(info)
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        let mut inner = DERWriter::new();
        inner.write_integer_i128(0);
        self.subject.encode(&mut inner);
        self.subject_public_key_info.encode(&mut inner)?;
        Attribute::encode_set(&self.attributes, Tag::context(0, true), &mut inner)?;
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn to_der(&self) -> Result<Vec<u8>, X509Error> {
        let mut writer = DERWriter::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }

    /// The request of these fields signed by `key` with `algorithm`, after
    /// [`CertificationRequestInfo::check`]. `key` must be the private key
    /// of the subject public key, whose possession the signature proves;
    /// fails with [`KeyError::Mismatch`] otherwise.
    pub fn sign<R: Random>(
        &self,
        key: &PrivateKey,
        algorithm: &SignatureAlgorithm,
        random: &mut R,
    ) -> Result<CertificationRequest<'static>, X509Error> {
        self.check()?;
        if key.public_key()? != PublicKey::from_info(&self.subject_public_key_info)? {
            return Err(X509Error::Key(KeyError::Mismatch));
        }
        let info_encoding = self.to_der()?;
        let signature = key.sign(algorithm, &info_encoding, random)?;
        Ok(CertificationRequest {
            info: self.clone().into_owned(),
            info_encoding: Cow::Owned(info_encoding),
            signature_algorithm: algorithm.identifier()?,
            signature: Cow::Owned(signature),
        })
    }

    pub fn into_owned(self) -> CertificationRequestInfo<'static> {
        CertificationRequestInfo {
            subject: self.subject.into_owned(),
            subject_public_key_info: self.subject_public_key_info.into_owned(),
            attributes: self.attributes.into_iter().map(Attribute::into_owned).collect(),
        }
    }
}

/// A `CertificationRequest` (RFC 2986 §4.2): the signed request
/// information, the signature algorithm and the signature. Like a
/// [`Certificate`], it is never changed and keeps the signed bytes as they were read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertificationRequest<'a> {
    info: CertificationRequestInfo<'a>,
    info_encoding: Cow<'a, [u8]>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: Cow<'a, [u8]>,
}

impl<'a> CertificationRequest<'a> {
    /// The label of a certification request in PEM (RFC 7468 §7).
    pub const PEM_LABEL: &'static str = "CERTIFICATE REQUEST";
    /// The label some software writes, which RFC 7468 §7 lets parsers accept.
    pub const LEGACY_PEM_LABEL: &'static str = "NEW CERTIFICATE REQUEST";

    /// Reads the next `CertificationRequest` of `reader`; the signature must be whole octets.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<CertificationRequest<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let info_encoding = sequence.peek()?.encoding;
        let info = CertificationRequestInfo::decode(&mut sequence)?;
        let signature_algorithm = AlgorithmIdentifier::decode(&mut sequence)?;
        let signature = Certificate::decode_signature(&mut sequence)?;
        sequence.finish()?;
        Ok(CertificationRequest {
            info,
            info_encoding: Cow::Borrowed(info_encoding),
            signature_algorithm,
            signature: Cow::Borrowed(signature),
        })
    }

    /// The request of the DER encoding `bytes`.
    pub fn from_der(bytes: &'a [u8]) -> Result<CertificationRequest<'a>, X509Error> {
        let mut reader = DERReader::new(bytes);
        let request = CertificationRequest::decode(&mut reader)?;
        reader.finish()?;
        Ok(request)
    }

    /// The request of the first PEM document of `text`, which must have the
    /// label `CERTIFICATE REQUEST` or `NEW CERTIFICATE REQUEST`.
    pub fn from_pem(text: &str) -> Result<CertificationRequest<'static>, X509Error> {
        let document = PEMDocument::decode(text.as_bytes(), PEMConfig::default())?;
        if document.label() != CertificationRequest::PEM_LABEL
            && document.label() != CertificationRequest::LEGACY_PEM_LABEL
        {
            return Err(X509Error::PEMLabel);
        }
        Ok(CertificationRequest::from_der(document.data())?.into_owned())
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        let mut inner = DERWriter::new();
        inner.write_raw(&self.info_encoding);
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

    /// The PEM text, with the label `CERTIFICATE REQUEST`.
    pub fn to_pem(&self) -> Result<String, X509Error> {
        Ok(PEMDocument::new(CertificationRequest::PEM_LABEL, self.to_der()?)?.encode())
    }

    pub fn info(&self) -> &CertificationRequestInfo<'a> {
        &self.info
    }

    /// The signed bytes: the DER encoding of the `CertificationRequestInfo` as read.
    pub fn info_encoding(&self) -> &[u8] {
        &self.info_encoding
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
        Ok(PublicKey::from_info(&self.info.subject_public_key_info)?)
    }

    /// Succeeds if the signature verifies under the subject public key of
    /// the request, which proves that the subject holds its private key.
    pub fn verify(&self) -> Result<(), X509Error> {
        let algorithm = SignatureAlgorithm::from_identifier(&self.signature_algorithm)?;
        Ok(self.public_key()?.verify(&algorithm, &self.info_encoding, &self.signature)?)
    }

    pub fn into_owned(self) -> CertificationRequest<'static> {
        CertificationRequest {
            info: self.info.into_owned(),
            info_encoding: Cow::Owned(self.info_encoding.into_owned()),
            signature_algorithm: self.signature_algorithm.into_owned(),
            signature: Cow::Owned(self.signature.into_owned()),
        }
    }
}
