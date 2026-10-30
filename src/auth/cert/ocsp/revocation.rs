use super::{BasicOCSPResponse, CertStatus, OCSPConfig, OCSPError, OCSPResponse};
use crate::auth::cert::key::PublicKey;
use crate::auth::cert::path::{PathConfig, PathErrorReason, RevocationSource, RevocationStatus};
use crate::auth::cert::x509::{CRLReason, Certificate, Name};

/// A basic response as a revocation source of path validation: the status
/// of the certificate it names, checked by [`BasicOCSPResponse::verify`]
/// without a nonce. A status that is not current is undetermined; a
/// response that names the certificate but fails another check fails with
/// `InvalidResponse`.
impl RevocationSource for BasicOCSPResponse<'_> {
    fn status(
        &self,
        certificate: &Certificate<'_>,
        issuer: &Name<'_>,
        issuer_key: &PublicKey,
        config: &PathConfig,
    ) -> Result<RevocationStatus, PathErrorReason> {
        let responses = &self.tbs_response_data().responses;
        let Some(named) = responses.iter().find(|response| response.cert_id.identifies(certificate, issuer_key.key()))
        else {
            return Ok(RevocationStatus::Undetermined);
        };
        let ocsp = OCSPConfig {
            key_limits: config.key_limits,
            accept_sha1: config.accept_sha1,
            lifetime_without_next_update: config.revocation.lifetime_without_next_update,
            ..OCSPConfig::new(config.time)
        };
        match self.verify(&named.cert_id, issuer, issuer_key, &ocsp) {
            Ok(response) => Ok(match response.status {
                CertStatus::Good => RevocationStatus::Unrevoked,
                CertStatus::Revoked { reason, .. } => {
                    RevocationStatus::Revoked(reason.unwrap_or(CRLReason::Unspecified))
                }
                CertStatus::Unknown => RevocationStatus::Undetermined,
            }),
            Err(OCSPError::Time) => Ok(RevocationStatus::Undetermined),
            Err(_) => Err(PathErrorReason::InvalidResponse),
        }
    }
}

/// A response as a revocation source: that of its basic response, or
/// undetermined for a response that is not successful.
impl RevocationSource for OCSPResponse<'_> {
    fn status(
        &self,
        certificate: &Certificate<'_>,
        issuer: &Name<'_>,
        issuer_key: &PublicKey,
        config: &PathConfig,
    ) -> Result<RevocationStatus, PathErrorReason> {
        match &self.response {
            Some(response) => response.status(certificate, issuer, issuer_key, config),
            None => Ok(RevocationStatus::Undetermined),
        }
    }
}
