use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::{BasicOCSPCertificates, CertID, OCSPConfig, OCSPError, OCSPNonce, OCSPRequest};
use crate::auth::cert::key::{AlgorithmIdentifier, HashAlgorithm, PrivateKey, PublicKey, SignatureAlgorithm};
use crate::auth::cert::x509::{
    AuthorityInformationAccess, AuthorityKeyIdentifier, BasicConstraints, CRLDistributionPoints, CRLReason,
    Certificate, ExtendedKeyUsage, ExtensionValue, Extensions, IssuerAlternativeName, KeyUsage, Name,
    SubjectAlternativeName, SubjectKeyIdentifier, Time, X509Error,
};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Time, BitString, ObjectIdentifier, Tag};
use crate::crypto::random::Random;

/// The `OCSPResponseStatus` of RFC 6960 §4.2.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OCSPResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

impl OCSPResponseStatus {
    pub const ALL: [OCSPResponseStatus; 6] = [
        OCSPResponseStatus::Successful,
        OCSPResponseStatus::MalformedRequest,
        OCSPResponseStatus::InternalError,
        OCSPResponseStatus::TryLater,
        OCSPResponseStatus::SigRequired,
        OCSPResponseStatus::Unauthorized,
    ];

    pub fn from_code(code: i128) -> Option<OCSPResponseStatus> {
        OCSPResponseStatus::ALL.into_iter().find(|status| *status as i128 == code)
    }
}

/// A `ResponderID` (RFC 6960 §4.2.1): the responder's name, or the SHA-1
/// hash of its `subjectPublicKey`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResponderID<'a> {
    ByName(Name<'a>),
    ByKey(Cow<'a, [u8]>),
}

impl<'a> ResponderID<'a> {
    /// The identifier by key of the key whose `subjectPublicKey` bits are `key`.
    pub fn by_key(key: &[u8]) -> ResponderID<'static> {
        let mut digest = [0u8; 64];
        let length = HashAlgorithm::SHA1.digest(key, &mut digest);
        ResponderID::ByKey(Cow::Owned(digest[..length].to_vec()))
    }

    /// Whether the identifier names the holder of `name` and `key` (the `subjectPublicKey` bits).
    pub fn names(&self, name: &Name<'_>, key: &[u8]) -> bool {
        match self {
            ResponderID::ByName(responder) => responder.matches(name),
            by_key => *by_key == ResponderID::by_key(key),
        }
    }

    pub fn decode(reader: &mut DERReader<'a>) -> Result<ResponderID<'a>, OCSPError> {
        if let Some(mut explicit) = reader.read_optional_explicit(1)? {
            let name = Name::decode(&mut explicit)?;
            explicit.finish()?;
            return Ok(ResponderID::ByName(name));
        }
        let mut explicit = reader.read_explicit(2)?;
        let key = explicit.read_octet_string()?;
        explicit.finish()?;
        Ok(ResponderID::ByKey(Cow::Borrowed(key)))
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), OCSPError> {
        match self {
            ResponderID::ByName(name) => writer.write_element(Tag::context(1, true), name.as_der()),
            ResponderID::ByKey(key) => {
                let mut explicit = DERWriter::new();
                explicit.write_octet_string(key);
                writer.write_element(Tag::context(2, true), explicit.as_bytes());
            }
        }
        Ok(())
    }

    pub fn into_owned(self) -> ResponderID<'static> {
        match self {
            ResponderID::ByName(name) => ResponderID::ByName(name.into_owned()),
            ResponderID::ByKey(key) => ResponderID::ByKey(Cow::Owned(key.into_owned())),
        }
    }
}

/// A `CertStatus` (RFC 6960 §4.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CertStatus {
    Good,
    Revoked { time: ASN1Time, reason: Option<CRLReason> },
    Unknown,
}

impl CertStatus {
    pub fn decode(reader: &mut DERReader<'_>) -> Result<CertStatus, OCSPError> {
        let element = reader.read_element()?;
        let status = match element.tag {
            tag if tag == Tag::context(0, false) => element.as_null().map(|_| CertStatus::Good)?,
            tag if tag == Tag::context(2, false) => element.as_null().map(|_| CertStatus::Unknown)?,
            tag if tag == Tag::context(1, true) => {
                let mut fields = reader.nested(&element)?;
                let time = Time::decode_generalized(&mut fields)?;
                let reason = match fields.read_optional_explicit(0)? {
                    Some(mut explicit) => {
                        let reason = CRLReason::decode(&mut explicit).map_err(|_| X509Error::InvalidExtension)?;
                        explicit.finish()?;
                        Some(reason)
                    }
                    None => None,
                };
                fields.finish()?;
                CertStatus::Revoked { time, reason }
            }
            _ => {
                return Err(OCSPError::from(crate::codec::asn1::ASN1Error::UnexpectedTag {
                    position: element.position,
                }));
            }
        };
        Ok(status)
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), OCSPError> {
        match self {
            CertStatus::Good => writer.write_element(Tag::context(0, false), &[]),
            CertStatus::Unknown => writer.write_element(Tag::context(2, false), &[]),
            CertStatus::Revoked { time, reason } => {
                let mut fields = DERWriter::new();
                Time::encode_generalized(time, &mut fields)?;
                if let Some(reason) = reason {
                    let mut explicit = DERWriter::new();
                    reason.encode(&mut explicit)?;
                    fields.write_element(Tag::context(0, true), explicit.as_bytes());
                }
                writer.write_element(Tag::context(1, true), fields.as_bytes());
            }
        }
        Ok(())
    }
}

/// A `SingleResponse` (RFC 6960 §4.2.1): the status of one certificate and
/// the interval in which it is current.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SingleResponse<'a> {
    pub cert_id: CertID<'a>,
    pub status: CertStatus,
    pub this_update: ASN1Time,
    pub next_update: Option<ASN1Time>,
    /// An empty list stands for the absent field.
    pub extensions: Extensions<'a>,
}

impl<'a> SingleResponse<'a> {
    pub fn decode(reader: &mut DERReader<'a>) -> Result<SingleResponse<'a>, OCSPError> {
        let mut sequence = reader.read_sequence()?;
        let cert_id = CertID::decode(&mut sequence)?;
        let status = CertStatus::decode(&mut sequence)?;
        let this_update = Time::decode_generalized(&mut sequence)?;
        let next_update = match sequence.read_optional_explicit(0)? {
            Some(mut explicit) => {
                let time = Time::decode_generalized(&mut explicit)?;
                explicit.finish()?;
                Some(time)
            }
            None => None,
        };
        let extensions = OCSPRequest::decode_extensions(&mut sequence, 1)?;
        sequence.finish()?;
        Ok(SingleResponse { cert_id, status, this_update, next_update, extensions })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), OCSPError> {
        let mut inner = DERWriter::new();
        self.cert_id.encode(&mut inner)?;
        self.status.encode(&mut inner)?;
        Time::encode_generalized(&self.this_update, &mut inner)?;
        if let Some(next_update) = &self.next_update {
            let mut explicit = DERWriter::new();
            Time::encode_generalized(next_update, &mut explicit)?;
            inner.write_element(Tag::context(0, true), explicit.as_bytes());
        }
        OCSPRequest::encode_extensions(&self.extensions, 1, &mut inner)?;
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    /// Whether the status is current at `time` (RFC 6960 §3.2, §4.2.2.1):
    /// `thisUpdate` not after it, and `nextUpdate` not before it or,
    /// without `nextUpdate`, `thisUpdate` at most `lifetime_without_next_update`
    /// seconds before it (newer information is then available at any time,
    /// so the status must be recent).
    pub fn is_current(&self, time: ASN1Time, lifetime_without_next_update: u64) -> bool {
        let expiry = match self.next_update {
            Some(next_update) => next_update.to_unix_seconds(),
            None => self.this_update.to_unix_seconds().saturating_add_unsigned(lifetime_without_next_update),
        };
        self.this_update <= time && time.to_unix_seconds() <= expiry
    }

    pub fn into_owned(self) -> SingleResponse<'static> {
        SingleResponse { cert_id: self.cert_id.into_owned(), extensions: self.extensions.into_owned(), ..self }
    }
}

/// A `ResponseData` (RFC 6960 §4.2.1): the responder, when the response
/// was produced, and the statuses. Its version is v1.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResponseData<'a> {
    pub responder_id: ResponderID<'a>,
    pub produced_at: ASN1Time,
    pub responses: Vec<SingleResponse<'a>>,
    /// An empty list stands for the absent field.
    pub extensions: Extensions<'a>,
}

impl<'a> ResponseData<'a> {
    /// Reads the next `ResponseData`; a version other than v1 is refused.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<ResponseData<'a>, OCSPError> {
        let mut sequence = reader.read_sequence()?;
        OCSPRequest::decode_version(&mut sequence)?;
        let responder_id = ResponderID::decode(&mut sequence)?;
        let produced_at = Time::decode_generalized(&mut sequence)?;
        let mut list = sequence.read_sequence()?;
        let mut responses = Vec::new();
        while !list.is_empty() {
            responses.push(SingleResponse::decode(&mut list)?);
        }
        let extensions = OCSPRequest::decode_extensions(&mut sequence, 1)?;
        sequence.finish()?;
        Ok(ResponseData { responder_id, produced_at, responses, extensions })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), OCSPError> {
        let mut inner = DERWriter::new();
        self.responder_id.encode(&mut inner)?;
        Time::encode_generalized(&self.produced_at, &mut inner)?;
        let mut list = DERWriter::new();
        self.responses.iter().try_for_each(|response| response.encode(&mut list))?;
        inner.write_element(Tag::SEQUENCE, list.as_bytes());
        OCSPRequest::encode_extensions(&self.extensions, 1, &mut inner)?;
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn to_der(&self) -> Result<Vec<u8>, OCSPError> {
        let mut writer = DERWriter::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }

    /// The basic response of these fields signed by `key` with `algorithm`,
    /// with `certificates` (the responder's certificate, for a delegated responder).
    pub fn sign<R: Random>(
        &self,
        key: &PrivateKey,
        algorithm: &SignatureAlgorithm,
        certificates: Option<Vec<Certificate<'static>>>,
        random: &mut R,
    ) -> Result<BasicOCSPResponse<'static>, OCSPError> {
        let tbs_encoding = self.to_der()?;
        let signature = key.sign(algorithm, &tbs_encoding, random)?;
        Ok(BasicOCSPResponse {
            tbs_response_data: self.clone().into_owned(),
            tbs_encoding: Cow::Owned(tbs_encoding),
            signature_algorithm: algorithm.identifier()?,
            signature: Cow::Owned(signature),
            certificates,
        })
    }

    pub fn into_owned(self) -> ResponseData<'static> {
        ResponseData {
            responder_id: self.responder_id.into_owned(),
            produced_at: self.produced_at,
            responses: self.responses.into_iter().map(SingleResponse::into_owned).collect(),
            extensions: self.extensions.into_owned(),
        }
    }
}

/// A `BasicOCSPResponse` (RFC 6960 §4.2.1): signed response data, the
/// signature, and certificates that help to verify it. It keeps the signed
/// bytes as read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BasicOCSPResponse<'a> {
    tbs_response_data: ResponseData<'a>,
    tbs_encoding: Cow<'a, [u8]>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: Cow<'a, [u8]>,
    certificates: Option<Vec<Certificate<'a>>>,
}

impl<'a> BasicOCSPResponse<'a> {
    /// `id-pkix-ocsp-basic`.
    pub const OID: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]);
    /// `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1): a responder certificate not checked for revocation.
    pub const NO_CHECK: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05]);
    /// The response extensions processed; another critical one makes the response unusable.
    pub const EXTENSIONS: [ObjectIdentifier<'static>; 1] = [OCSPNonce::OID];
    /// The extensions of a delegated responder's certificate processed (or
    /// harmless when critical); a certificate with another critical one is
    /// not used (RFC 5280 §4.2).
    pub const RESPONDER_EXTENSIONS: [ObjectIdentifier<'static>; 10] = [
        BasicConstraints::OID,
        KeyUsage::OID,
        ExtendedKeyUsage::OID,
        SubjectKeyIdentifier::OID,
        AuthorityKeyIdentifier::OID,
        SubjectAlternativeName::OID,
        IssuerAlternativeName::OID,
        AuthorityInformationAccess::OID,
        CRLDistributionPoints::OID,
        BasicOCSPResponse::NO_CHECK,
    ];

    /// Whether `certificate`, issued by the holder of `issuer_name` and
    /// `issuer_key`, authorizes its key to sign responses for that CA under
    /// `config` (RFC 6960 §4.2.2.2): issued with the CA's key in an accepted
    /// signature algorithm, valid at the time, with `id-kp-OCSPSigning`, a
    /// key usage (if any) that allows signatures, and no critical extension
    /// not processed.
    pub fn authorizes(
        certificate: &Certificate<'_>,
        issuer_name: &Name<'_>,
        issuer_key: &PublicKey,
        config: &OCSPConfig,
    ) -> bool {
        let tbs = certificate.tbs_certificate();
        let extensions = &tbs.extensions;
        tbs.issuer.matches(issuer_name)
            && config.accepts(certificate.signature_algorithm())
            && tbs.validity.contains(config.second())
            && extensions.entries.iter().all(|extension| {
                !extension.critical || BasicOCSPResponse::RESPONDER_EXTENSIONS.contains(&extension.oid)
            })
            && extensions
                .typed::<ExtendedKeyUsage<'_>>()
                .is_ok_and(|usage| usage.is_some_and(|usage| usage.contains(&ExtendedKeyUsage::OCSP_SIGNING)))
            && extensions
                .typed::<KeyUsage>()
                .is_ok_and(|usage| usage.is_none_or(|usage| usage.contains(KeyUsage::DIGITAL_SIGNATURE)))
            && certificate.verify(issuer_key).is_ok()
    }

    pub fn decode(reader: &mut DERReader<'a>) -> Result<BasicOCSPResponse<'a>, OCSPError> {
        let mut sequence = reader.read_sequence()?;
        let tbs_encoding = sequence.peek()?.encoding;
        let tbs_response_data = ResponseData::decode(&mut sequence)?;
        let signature_algorithm = AlgorithmIdentifier::decode(&mut sequence)?;
        let signature = Certificate::decode_signature(&mut sequence)?;
        let certificates = BasicOCSPCertificates::decode(&mut sequence)?;
        sequence.finish()?;
        Ok(BasicOCSPResponse {
            tbs_response_data,
            tbs_encoding: Cow::Borrowed(tbs_encoding),
            signature_algorithm,
            signature: Cow::Borrowed(signature),
            certificates,
        })
    }

    pub fn from_der(bytes: &'a [u8]) -> Result<BasicOCSPResponse<'a>, OCSPError> {
        let mut reader = DERReader::new(bytes);
        let response = BasicOCSPResponse::decode(&mut reader)?;
        reader.finish()?;
        Ok(response)
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), OCSPError> {
        let mut inner = DERWriter::new();
        inner.write_raw(&self.tbs_encoding);
        self.signature_algorithm.encode(&mut inner)?;
        inner.write_bit_string(&BitString::new(0, self.signature.as_ref())?)?;
        BasicOCSPCertificates::encode(&self.certificates, &mut inner)?;
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn to_der(&self) -> Result<Vec<u8>, OCSPError> {
        let mut writer = DERWriter::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }

    pub fn tbs_response_data(&self) -> &ResponseData<'a> {
        &self.tbs_response_data
    }

    /// The signed bytes: the DER of the `ResponseData` as read.
    pub fn tbs_encoding(&self) -> &[u8] {
        &self.tbs_encoding
    }

    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier<'a> {
        &self.signature_algorithm
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn certificates(&self) -> &[Certificate<'a>] {
        self.certificates.as_deref().unwrap_or_default()
    }

    /// Whether the signature verifies under `key`.
    pub fn verifies(&self, key: &PublicKey) -> bool {
        match SignatureAlgorithm::from_identifier(&self.signature_algorithm) {
            Ok(algorithm) => key.verify(&algorithm, &self.tbs_encoding, &self.signature).is_ok(),
            Err(_) => false,
        }
    }

    /// The key that signed the response, if it may answer for the
    /// certificates of the CA of `issuer_name` and `issuer_key` (RFC 6960
    /// §4.2.2.2): the CA's own key, or the key of a certificate of the
    /// response that [`BasicOCSPResponse::authorizes`].
    /// The responder identifier must name the signer. At most
    /// `config.maximum_signatures` signatures are verified, so that a
    /// response with many certificates costs little. A delegated
    /// responder's certificate is not checked for revocation, as if it had
    /// the extension `id-pkix-ocsp-nocheck` (§4.2.2.2.1).
    pub fn signer(
        &self,
        issuer_name: &Name<'_>,
        issuer_key: &PublicKey,
        config: &OCSPConfig,
    ) -> Result<PublicKey, OCSPError> {
        if !config.accepts(&self.signature_algorithm) {
            return Err(OCSPError::Algorithm);
        }
        let responder = &self.tbs_response_data.responder_id;
        let mut signatures = config.maximum_signatures;
        if responder.names(issuer_name, issuer_key.key()) {
            signatures = signatures.checked_sub(1).ok_or(OCSPError::Signer)?;
            if self.verifies(issuer_key) {
                return Ok(issuer_key.clone());
            }
        }
        for certificate in self.certificates() {
            let tbs = certificate.tbs_certificate();
            let Ok(key) = PublicKey::from_info_with_limits(&tbs.subject_public_key_info, &config.key_limits) else {
                continue;
            };
            if !responder.names(&tbs.subject, key.key()) {
                continue;
            }
            // The certificate's signature and the response's.
            signatures = signatures.checked_sub(2).ok_or(OCSPError::Signer)?;
            if BasicOCSPResponse::authorizes(certificate, issuer_name, issuer_key, config) && self.verifies(&key) {
                return Ok(key);
            }
        }
        Err(OCSPError::Signer)
    }

    /// The status of the certificate `cert_id` names, after checking the
    /// response as RFC 6960 §3.2 requires: no critical extension not
    /// processed, signed by a key that may answer for the CA of
    /// `issuer_name` and `issuer_key`, repeating the nonce of `config` if
    /// it has one (RFC 8954), and current at the time of `config`.
    pub fn verify(
        &self,
        cert_id: &CertID<'_>,
        issuer_name: &Name<'_>,
        issuer_key: &PublicKey,
        config: &OCSPConfig,
    ) -> Result<&SingleResponse<'a>, OCSPError> {
        let data = &self.tbs_response_data;
        let unknown = |extensions: &Extensions<'_>| {
            extensions
                .entries
                .iter()
                .any(|extension| extension.critical && !BasicOCSPResponse::EXTENSIONS.contains(&extension.oid))
        };
        let response =
            data.responses.iter().find(|response| response.cert_id.matches(cert_id)).ok_or(OCSPError::NotFound)?;
        if unknown(&data.extensions) || unknown(&response.extensions) {
            return Err(OCSPError::UnknownCriticalExtension);
        }
        self.signer(issuer_name, issuer_key, config)?;
        if let Some(nonce) = &config.nonce {
            let answered = data.extensions.typed::<OCSPNonce<'_>>()?;
            if answered.is_none_or(|answered| answered.nonce.as_ref() != nonce.as_slice()) {
                return Err(OCSPError::Nonce);
            }
        }
        if !response.is_current(config.second(), config.lifetime_without_next_update) {
            return Err(OCSPError::Time);
        }
        Ok(response)
    }

    pub fn into_owned(self) -> BasicOCSPResponse<'static> {
        BasicOCSPResponse {
            tbs_response_data: self.tbs_response_data.into_owned(),
            tbs_encoding: Cow::Owned(self.tbs_encoding.into_owned()),
            signature_algorithm: self.signature_algorithm.into_owned(),
            signature: Cow::Owned(self.signature.into_owned()),
            certificates: self.certificates.map(BasicOCSPCertificates::into_owned),
        }
    }
}

/// An `OCSPResponse` (RFC 6960 §4.2.1): a status, and a basic response
/// when the status is successful.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OCSPResponse<'a> {
    pub status: OCSPResponseStatus,
    pub response: Option<BasicOCSPResponse<'a>>,
}

impl<'a> OCSPResponse<'a> {
    /// Reads a response: a successful one carries a basic response
    /// (`ResponseType` for another type or none); another status carries none.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<OCSPResponse<'a>, OCSPError> {
        let mut sequence = reader.read_sequence()?;
        let status = sequence.read_with(Tag::ENUMERATED, |element| {
            let code = element.as_integer()?.as_i128().map_err(|_| element.invalid())?;
            OCSPResponseStatus::from_code(code).ok_or_else(|| element.invalid())
        })?;
        let response = match sequence.read_optional_explicit(0)? {
            Some(mut explicit) => {
                let mut bytes = explicit.read_sequence()?;
                let response_type = bytes.read_object_identifier()?;
                let content = bytes.read_octet_string()?;
                bytes.finish()?;
                explicit.finish()?;
                if response_type != BasicOCSPResponse::OID {
                    return Err(OCSPError::ResponseType);
                }
                Some(BasicOCSPResponse::from_der(content)?)
            }
            None => None,
        };
        sequence.finish()?;
        if (status == OCSPResponseStatus::Successful) != response.is_some() {
            return Err(OCSPError::ResponseType);
        }
        Ok(OCSPResponse { status, response })
    }

    pub fn from_der(bytes: &'a [u8]) -> Result<OCSPResponse<'a>, OCSPError> {
        let mut reader = DERReader::new(bytes);
        let response = OCSPResponse::decode(&mut reader)?;
        reader.finish()?;
        Ok(response)
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), OCSPError> {
        if (self.status == OCSPResponseStatus::Successful) != self.response.is_some() {
            return Err(OCSPError::ResponseType);
        }
        let mut inner = DERWriter::new();
        inner.write_enumerated(self.status as i128);
        if let Some(response) = &self.response {
            let mut bytes = DERWriter::new();
            bytes.write_object_identifier(&BasicOCSPResponse::OID);
            bytes.write_octet_string(&response.to_der()?);
            let mut explicit = DERWriter::new();
            explicit.write_element(Tag::SEQUENCE, bytes.as_bytes());
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

    /// The basic response of a successful response; `Status` otherwise.
    pub fn basic(&self) -> Result<&BasicOCSPResponse<'a>, OCSPError> {
        self.response.as_ref().ok_or(OCSPError::Status(self.status))
    }

    pub fn into_owned(self) -> OCSPResponse<'static> {
        OCSPResponse { status: self.status, response: self.response.map(BasicOCSPResponse::into_owned) }
    }
}
