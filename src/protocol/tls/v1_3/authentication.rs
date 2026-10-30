use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::auth::cert::path::ServiceIdentity;
use crate::auth::cert::x509::Certificate;
use crate::protocol::tls::{
    TLSAEADAlgorithm, TLSAlertDescription, TLSCertificateStatus, TLSCertificateVerifier, TLSCertificateVerify,
    TLSCertifiedKey, TLSContext, TLSDirection, TLSEncryptionLevel, TLSError, TLSExtension, TLSExtensionContext,
    TLSExtensionType, TLSHandshake, TLSHandshakeType, TLSRecordLayer, TLSSignatureScheme, TLSTrafficSecret,
    TLSTranscript, TLSVersion,
};
use crate::secret::{ConstantTimeEq, Secret};

use super::{TLS13Certificate, TLS13CertificateEntry, TLS13KeySchedule, TLS13RecordProtection};

/// A peer's Certificate as received: the chain, the end-entity certificate
/// first (empty if the peer sent none), and the OCSP response stapled to it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TLS13ReceivedCertificate {
    pub chain: Vec<Vec<u8>>,
    pub status: Option<Vec<u8>>,
}

/// What TLS 1.3 authenticates with: Certificate, CertificateVerify and
/// Finished (RFC 9846 §4.5), for either end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TLS13Authentication;

impl TLS13Authentication {
    pub const SERVER_CONTEXT: &'static [u8] = b"TLS 1.3, server CertificateVerify";
    pub const CLIENT_CONTEXT: &'static [u8] = b"TLS 1.3, client CertificateVerify";

    /// What a CertificateVerify signs: 64 spaces, the context string, a
    /// zero byte, and the transcript hash (RFC 9846 §4.5.2).
    pub fn content(server: bool, transcript_hash: &[u8]) -> Vec<u8> {
        let context = if server { TLS13Authentication::SERVER_CONTEXT } else { TLS13Authentication::CLIENT_CONTEXT };
        let mut content = Vec::with_capacity(64 + context.len() + 1 + transcript_hash.len());
        content.extend_from_slice(&[0x20; 64]);
        content.extend_from_slice(context);
        content.push(0);
        content.extend_from_slice(transcript_hash);
        content
    }

    /// Writes the Certificate, CertificateVerify (when the chain is not
    /// empty) of `key` signed with `scheme`, as `server` or client, and adds
    /// them to the transcript. `request` is the context of the
    /// CertificateRequest answered (empty in the handshake); `status` is
    /// whether to staple the key's OCSP response.
    pub fn send(
        key: Option<&TLSCertifiedKey>,
        scheme: Option<TLSSignatureScheme>,
        request: &[u8],
        status: bool,
        server: bool,
        transcript: &mut TLSTranscript,
        context: &mut TLSContext<'_>,
    ) -> Result<(), TLSError> {
        let mut entries = Vec::new();
        for (index, data) in key.map(|key| key.chain.as_slice()).unwrap_or(&[]).iter().enumerate() {
            let mut extensions = Vec::new();
            if index == 0
                && status
                && let Some(response) = key.and_then(|key| key.ocsp.as_ref())
            {
                let response = TLSCertificateStatus::Response(response.clone());
                extensions.push(TLSExtension::with(TLSExtensionType::STATUS_REQUEST, |out| response.encode(out))?);
            }
            entries.push(TLS13CertificateEntry { data: data.clone(), extensions });
        }
        let certificate = TLS13Certificate { context: request.to_vec(), entries };
        let message = TLSHandshake::with(TLSHandshakeType::CERTIFICATE, |body| certificate.encode(body))?;
        transcript.update(&context.layer.write_handshake(&message)?);
        let (Some(key), Some(scheme)) = (key, scheme) else { return Ok(()) };
        let content = TLS13Authentication::content(server, &transcript.hash());
        let signature = scheme.sign(&key.key, &content, &mut &mut *context.random)?;
        let verify = TLSCertificateVerify { algorithm: scheme, signature };
        let message = TLSHandshake::with(TLSHandshakeType::CERTIFICATE_VERIFY, |body| verify.encode(body))?;
        transcript.update(&context.layer.write_handshake(&message)?);
        Ok(())
    }

    /// Reads a peer's Certificate: the context of the request it answers
    /// (`illegal_parameter`; empty in the handshake), extensions allowed
    /// (`illegal_parameter`) and requested (`unsupported_extension`), and
    /// the chain checked with `verifier` for `identity`, with the stapled
    /// OCSP response. An empty chain is returned as such; the caller decides.
    pub fn receive_certificate(
        body: &[u8],
        request: &[u8],
        requested_status: bool,
        verifier: &dyn TLSCertificateVerifier,
        identity: Option<&ServiceIdentity>,
        time: i64,
    ) -> Result<TLS13ReceivedCertificate, TLSError> {
        let certificate = TLS13Certificate::decode(body)?;
        if certificate.context != request {
            return Err(TLSError::illegal());
        }
        let mut status = None;
        for (index, entry) in certificate.entries.iter().enumerate() {
            TLSExtension::check(&entry.extensions, TLSExtensionContext::Certificate)?;
            for extension in &entry.extensions {
                if extension.kind != TLSExtensionType::STATUS_REQUEST || !requested_status {
                    return Err(TLSError::Protocol(TLSAlertDescription::UNSUPPORTED_EXTENSION));
                }
                if index == 0 {
                    match TLSCertificateStatus::decode(&extension.data, true)? {
                        TLSCertificateStatus::Response(response) => status = Some(response),
                        TLSCertificateStatus::Request { .. } => return Err(TLSError::decode()),
                    }
                }
            }
        }
        let chain: Vec<Vec<u8>> = certificate.entries.into_iter().map(|entry| entry.data).collect();
        if !chain.is_empty() {
            verifier.verify(&chain, identity, status.as_deref(), time).map_err(TLSError::Protocol)?;
        }
        Ok(TLS13ReceivedCertificate { chain, status })
    }

    /// Checks a peer's CertificateVerify against the end-entity certificate
    /// of `chain`: a scheme of `accepted` (`illegal_parameter`) that
    /// verifies (`decrypt_error`) over the transcript so far (RFC 9846 §4.5.2).
    pub fn receive_verify(
        body: &[u8],
        chain: &[Vec<u8>],
        accepted: &[TLSSignatureScheme],
        server: bool,
        transcript: &TLSTranscript,
    ) -> Result<TLSSignatureScheme, TLSError> {
        let verify = TLSCertificateVerify::decode_body(body)?;
        if !accepted.contains(&verify.algorithm) {
            return Err(TLSError::illegal());
        }
        let certificate = Certificate::from_der(chain.first().ok_or(TLSError::unexpected())?)
            .map_err(|_| TLSError::Protocol(TLSAlertDescription::BAD_CERTIFICATE))?;
        let key =
            certificate.public_key().map_err(|_| TLSError::Protocol(TLSAlertDescription::UNSUPPORTED_CERTIFICATE))?;
        let content = TLS13Authentication::content(server, &transcript.hash());
        verify.algorithm.verify(&key, &content, &verify.signature, TLSVersion::TLS1_3)?;
        Ok(verify.algorithm)
    }

    /// Checks a Finished against the base key and the transcript so far,
    /// in constant time (`decrypt_error`, RFC 9846 §4.5.3).
    pub fn receive_finished(
        schedule: &TLS13KeySchedule,
        base: &[u8],
        body: &[u8],
        transcript: &TLSTranscript,
    ) -> Result<(), TLSError> {
        let expected = schedule.finished(base, &transcript.hash())?;
        if body.len() != expected.len() || !body.ct_eq(expected.as_slice()).into_bool() {
            return Err(TLSError::Protocol(TLSAlertDescription::DECRYPT_ERROR));
        }
        Ok(())
    }

    /// Writes a Finished of the base key and adds it to the transcript.
    pub fn send_finished(
        schedule: &TLS13KeySchedule,
        base: &[u8],
        transcript: &mut TLSTranscript,
        context: &mut TLSContext<'_>,
    ) -> Result<(), TLSError> {
        let verify_data = schedule.finished(base, &transcript.hash())?;
        let message = TLSHandshake::new(TLSHandshakeType::FINISHED, verify_data);
        transcript.update(&context.layer.write_handshake(&message)?);
        Ok(())
    }

    /// Starts protecting `direction` with the traffic secret `secret` of
    /// `level`: records under its keys (RFC 9846 §7.3), or, when QUIC
    /// carries the handshake, the secret handed to it (RFC 9001 §4.1.4).
    /// QUIC moves to a new level for reading only once the handshake
    /// messages of the previous one are complete (RFC 9001 §4.1.3).
    pub fn install(
        layer: &mut TLSRecordLayer,
        direction: TLSDirection,
        level: TLSEncryptionLevel,
        schedule: &TLS13KeySchedule,
        aead: TLSAEADAlgorithm,
        secret: &[u8],
    ) -> Result<(), TLSError> {
        let Some(quic) = &mut layer.quic else {
            let protection = Box::new(TLS13RecordProtection::new(schedule, aead, secret)?);
            match direction {
                TLSDirection::Reading => layer.reader = Some(protection),
                TLSDirection::Writing => layer.writer = Some(protection),
            }
            return Ok(());
        };
        if direction == TLSDirection::Reading && level != TLSEncryptionLevel::EarlyData && !layer.handshake.is_empty() {
            return Err(TLSError::Transport);
        }
        let secret = Secret::new(secret.to_vec());
        quic.install(TLSTrafficSecret { level, direction, hash: schedule.hash, aead, secret });
        Ok(())
    }
}
