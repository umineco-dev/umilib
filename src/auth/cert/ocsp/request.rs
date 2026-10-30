use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::{CertID, OCSPError};
use crate::auth::cert::key::{AlgorithmIdentifier, PrivateKey, PublicKey, SignatureAlgorithm};
use crate::auth::cert::x509::{Certificate, ExtensionValue, Extensions, GeneralName, X509Error};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{BitString, ObjectIdentifier, Tag};
use crate::crypto::random::Random;

/// The nonce extension (RFC 8954, updating RFC 6960 §4.4.1): 1 to 32 octets
/// that a response repeats, which binds it to the request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OCSPNonce<'a> {
    pub nonce: Cow<'a, [u8]>,
}

impl OCSPNonce<'_> {
    /// The sizes RFC 8954 §2.1 allows.
    pub const SIZE: core::ops::RangeInclusive<usize> = 1..=32;

    /// A nonce of 32 random octets, the most RFC 8954 allows.
    pub fn random<R: Random>(random: &mut R) -> Result<OCSPNonce<'static>, OCSPError> {
        let mut nonce = [0u8; 32];
        random.fill(&mut nonce).map_err(|_| {
            OCSPError::Key(crate::auth::cert::key::KeyError::Crypto(crate::crypto::CryptoError::RandomFailed))
        })?;
        Ok(OCSPNonce { nonce: Cow::Owned(nonce.to_vec()) })
    }

    pub fn into_owned(self) -> OCSPNonce<'static> {
        OCSPNonce { nonce: Cow::Owned(self.nonce.into_owned()) }
    }
}

impl<'a> ExtensionValue<'a> for OCSPNonce<'a> {
    const OID: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02]);

    fn decode(reader: &mut DERReader<'a>) -> Result<OCSPNonce<'a>, X509Error> {
        let nonce = reader.read_octet_string()?;
        if !OCSPNonce::SIZE.contains(&nonce.len()) {
            return Err(X509Error::InvalidExtension);
        }
        Ok(OCSPNonce { nonce: Cow::Borrowed(nonce) })
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        if !OCSPNonce::SIZE.contains(&self.nonce.len()) {
            return Err(X509Error::InvalidExtension);
        }
        writer.write_octet_string(&self.nonce);
        Ok(())
    }
}

/// A `Request` (RFC 6960 §4.1.1): a certificate asked about, and the extensions of that request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Request<'a> {
    pub cert_id: CertID<'a>,
    /// An empty list stands for the absent field.
    pub extensions: Extensions<'a>,
}

impl<'a> Request<'a> {
    pub fn decode(reader: &mut DERReader<'a>) -> Result<Request<'a>, OCSPError> {
        let mut sequence = reader.read_sequence()?;
        let cert_id = CertID::decode(&mut sequence)?;
        let extensions = OCSPRequest::decode_extensions(&mut sequence, 0)?;
        sequence.finish()?;
        Ok(Request { cert_id, extensions })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), OCSPError> {
        let mut inner = DERWriter::new();
        self.cert_id.encode(&mut inner)?;
        OCSPRequest::encode_extensions(&self.extensions, 0, &mut inner)?;
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn into_owned(self) -> Request<'static> {
        Request { cert_id: self.cert_id.into_owned(), extensions: self.extensions.into_owned() }
    }
}

/// A `TBSRequest` (RFC 6960 §4.1.1): the certificates asked about, the
/// requestor's name and the request extensions. Its version is v1, the
/// only one RFC 6960 defines.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TBSRequest<'a> {
    pub requestor_name: Option<GeneralName<'a>>,
    pub requests: Vec<Request<'a>>,
    /// An empty list stands for the absent field.
    pub extensions: Extensions<'a>,
}

impl<'a> TBSRequest<'a> {
    /// Reads the next `TBSRequest`; a version other than v1 is refused (v1
    /// written out, which DER omits, is accepted).
    pub fn decode(reader: &mut DERReader<'a>) -> Result<TBSRequest<'a>, OCSPError> {
        let mut sequence = reader.read_sequence()?;
        OCSPRequest::decode_version(&mut sequence)?;
        let requestor_name = match sequence.read_optional_explicit(1)? {
            Some(mut explicit) => {
                let name = GeneralName::decode(&mut explicit)?;
                explicit.finish()?;
                Some(name)
            }
            None => None,
        };
        let mut list = sequence.read_sequence()?;
        let mut requests = Vec::new();
        while !list.is_empty() {
            requests.push(Request::decode(&mut list)?);
        }
        let extensions = OCSPRequest::decode_extensions(&mut sequence, 2)?;
        sequence.finish()?;
        Ok(TBSRequest { requestor_name, requests, extensions })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), OCSPError> {
        let mut inner = DERWriter::new();
        if let Some(name) = &self.requestor_name {
            let mut explicit = DERWriter::new();
            name.encode(&mut explicit)?;
            inner.write_element(Tag::context(1, true), explicit.as_bytes());
        }
        let mut list = DERWriter::new();
        self.requests.iter().try_for_each(|request| request.encode(&mut list))?;
        inner.write_element(Tag::SEQUENCE, list.as_bytes());
        OCSPRequest::encode_extensions(&self.extensions, 2, &mut inner)?;
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn to_der(&self) -> Result<Vec<u8>, OCSPError> {
        let mut writer = DERWriter::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }

    /// The nonce of the request, if it has one.
    pub fn nonce(&self) -> Result<Option<OCSPNonce<'_>>, OCSPError> {
        Ok(self.extensions.typed::<OCSPNonce<'_>>()?)
    }

    pub fn into_owned(self) -> TBSRequest<'static> {
        TBSRequest {
            requestor_name: self.requestor_name.map(GeneralName::into_owned),
            requests: self.requests.into_iter().map(Request::into_owned).collect(),
            extensions: self.extensions.into_owned(),
        }
    }
}

/// The `Signature` of a signed request (RFC 6960 §4.1.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OCSPSignature<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub signature: Cow<'a, [u8]>,
    /// Certificates that help to verify the signature (`None` for the absent field).
    pub certificates: Option<Vec<Certificate<'a>>>,
}

/// An `OCSPRequest` (RFC 6960 §4.1.1): the fields of a request, signed or
/// not. It keeps the signed bytes as read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OCSPRequest<'a> {
    tbs_request: TBSRequest<'a>,
    tbs_encoding: Cow<'a, [u8]>,
    signature: Option<OCSPSignature<'a>>,
}

impl<'a> OCSPRequest<'a> {
    /// Reads `[0] EXPLICIT Version DEFAULT v1`; fails for another version.
    pub fn decode_version(reader: &mut DERReader<'_>) -> Result<(), OCSPError> {
        if let Some(mut explicit) = reader.read_optional_explicit(0)? {
            let version = explicit.read_integer()?;
            explicit.finish()?;
            if version.as_bytes() != [0] {
                return Err(OCSPError::Version);
            }
        }
        Ok(())
    }

    /// Reads `[number] EXPLICIT Extensions OPTIONAL`.
    pub fn decode_extensions(reader: &mut DERReader<'a>, number: u32) -> Result<Extensions<'a>, OCSPError> {
        match reader.read_optional_explicit(number)? {
            Some(mut explicit) => {
                let extensions = Extensions::decode(&mut explicit)?;
                explicit.finish()?;
                Ok(extensions)
            }
            None => Ok(Extensions::new()),
        }
    }

    /// Writes `[number] EXPLICIT Extensions`, nothing for an empty list.
    pub fn encode_extensions(
        extensions: &Extensions<'_>,
        number: u32,
        writer: &mut DERWriter,
    ) -> Result<(), OCSPError> {
        if !extensions.is_empty() {
            let mut explicit = DERWriter::new();
            extensions.encode(&mut explicit)?;
            writer.write_element(Tag::context(number, true), explicit.as_bytes());
        }
        Ok(())
    }

    /// An unsigned request of `tbs_request`.
    pub fn new(tbs_request: TBSRequest<'_>) -> Result<OCSPRequest<'static>, OCSPError> {
        let tbs_encoding = tbs_request.to_der()?;
        Ok(OCSPRequest {
            tbs_request: tbs_request.into_owned(),
            tbs_encoding: Cow::Owned(tbs_encoding),
            signature: None,
        })
    }

    /// The request of `tbs_request` signed by `key` with `algorithm`, with
    /// `certificates` to help verify it.
    pub fn sign<R: Random>(
        tbs_request: TBSRequest<'_>,
        key: &PrivateKey,
        algorithm: &SignatureAlgorithm,
        certificates: Option<Vec<Certificate<'static>>>,
        random: &mut R,
    ) -> Result<OCSPRequest<'static>, OCSPError> {
        let tbs_encoding = tbs_request.to_der()?;
        let signature = key.sign(algorithm, &tbs_encoding, random)?;
        let signature =
            OCSPSignature { algorithm: algorithm.identifier()?, signature: Cow::Owned(signature), certificates };
        Ok(OCSPRequest {
            tbs_request: tbs_request.into_owned(),
            tbs_encoding: Cow::Owned(tbs_encoding),
            signature: Some(signature),
        })
    }

    pub fn decode(reader: &mut DERReader<'a>) -> Result<OCSPRequest<'a>, OCSPError> {
        let mut sequence = reader.read_sequence()?;
        let tbs_encoding = sequence.peek()?.encoding;
        let tbs_request = TBSRequest::decode(&mut sequence)?;
        let signature = match sequence.read_optional_explicit(0)? {
            Some(mut explicit) => {
                let mut fields = explicit.read_sequence()?;
                let algorithm = AlgorithmIdentifier::decode(&mut fields)?;
                let signature = Certificate::decode_signature(&mut fields)?;
                let certificates = BasicOCSPCertificates::decode(&mut fields)?;
                fields.finish()?;
                explicit.finish()?;
                Some(OCSPSignature { algorithm, signature: Cow::Borrowed(signature), certificates })
            }
            None => None,
        };
        sequence.finish()?;
        Ok(OCSPRequest { tbs_request, tbs_encoding: Cow::Borrowed(tbs_encoding), signature })
    }

    pub fn from_der(bytes: &'a [u8]) -> Result<OCSPRequest<'a>, OCSPError> {
        let mut reader = DERReader::new(bytes);
        let request = OCSPRequest::decode(&mut reader)?;
        reader.finish()?;
        Ok(request)
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), OCSPError> {
        let mut inner = DERWriter::new();
        inner.write_raw(&self.tbs_encoding);
        if let Some(signature) = &self.signature {
            let mut fields = DERWriter::new();
            signature.algorithm.encode(&mut fields)?;
            fields.write_bit_string(&BitString::new(0, signature.signature.as_ref())?)?;
            BasicOCSPCertificates::encode(&signature.certificates, &mut fields)?;
            let mut explicit = DERWriter::new();
            explicit.write_element(Tag::SEQUENCE, fields.as_bytes());
            inner.write_element(Tag::context(0, true), explicit.as_bytes());
        }
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn to_der(&self) -> Result<Vec<u8>, OCSPError> {
        let mut writer = DERWriter::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }

    pub fn tbs_request(&self) -> &TBSRequest<'a> {
        &self.tbs_request
    }

    pub fn signature(&self) -> Option<&OCSPSignature<'a>> {
        self.signature.as_ref()
    }

    /// Succeeds if the request is signed and the signature verifies under `key`.
    pub fn verify(&self, key: &PublicKey) -> Result<(), OCSPError> {
        let signature = self.signature.as_ref().ok_or(OCSPError::Signer)?;
        let algorithm = SignatureAlgorithm::from_identifier(&signature.algorithm)?;
        Ok(key.verify(&algorithm, &self.tbs_encoding, &signature.signature)?)
    }

    pub fn into_owned(self) -> OCSPRequest<'static> {
        let signature = self.signature.map(|signature| OCSPSignature {
            algorithm: signature.algorithm.into_owned(),
            signature: Cow::Owned(signature.signature.into_owned()),
            certificates: signature.certificates.map(BasicOCSPCertificates::into_owned),
        });
        OCSPRequest {
            tbs_request: self.tbs_request.into_owned(),
            tbs_encoding: Cow::Owned(self.tbs_encoding.into_owned()),
            signature,
        }
    }
}

/// The `[0] EXPLICIT SEQUENCE OF Certificate OPTIONAL` of signatures and
/// basic responses; `None` stands for the absent field, so that a list
/// written empty is written back so.
pub struct BasicOCSPCertificates;

impl BasicOCSPCertificates {
    pub fn decode<'a>(reader: &mut DERReader<'a>) -> Result<Option<Vec<Certificate<'a>>>, OCSPError> {
        let Some(mut explicit) = reader.read_optional_explicit(0)? else { return Ok(None) };
        let mut list = explicit.read_sequence()?;
        let mut certificates = Vec::new();
        while !list.is_empty() {
            certificates.push(Certificate::decode(&mut list)?);
        }
        explicit.finish()?;
        Ok(Some(certificates))
    }

    pub fn encode(certificates: &Option<Vec<Certificate<'_>>>, writer: &mut DERWriter) -> Result<(), OCSPError> {
        let Some(certificates) = certificates else { return Ok(()) };
        let mut list = DERWriter::new();
        certificates.iter().try_for_each(|certificate| certificate.encode(&mut list))?;
        let mut explicit = DERWriter::new();
        explicit.write_element(Tag::SEQUENCE, list.as_bytes());
        writer.write_element(Tag::context(0, true), explicit.as_bytes());
        Ok(())
    }

    pub fn into_owned(certificates: Vec<Certificate<'_>>) -> Vec<Certificate<'static>> {
        certificates.into_iter().map(Certificate::into_owned).collect()
    }
}
