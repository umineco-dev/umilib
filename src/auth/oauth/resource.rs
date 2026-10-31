use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::codec::json::JSONValue;
use crate::protocol::jwt::{JWKSet, JWSAlgorithm, JWSConfig, JWT, JWTValidation};

use super::{
    DPoPConfig, DPoPTarget, DPoPVerifier, OAuthEndpointRequest, OAuthError, OAuthErrorCode, OAuthErrorResponse,
    OAuthHTTPResponse, OAuthIntrospectionResponse, OAuthMembers, OAuthMetadata, OAuthMetadataKind, OAuthScope,
};

/// How an access token is presented in the `Authorization` header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OAuthTokenScheme {
    /// `Bearer` (RFC 6750 §2.1).
    Bearer,
    /// `DPoP`, with a proof in the `DPoP` header (RFC 9449 §7.1).
    DPoP,
}

impl OAuthTokenScheme {
    /// The name of the scheme.
    pub fn name(self) -> &'static str {
        match self {
            OAuthTokenScheme::Bearer => "Bearer",
            OAuthTokenScheme::DPoP => "DPoP",
        }
    }
}

/// An access token presented in a request (RFC 6750 §2.1, RFC 9449 §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthPresentedToken {
    pub scheme: OAuthTokenScheme,
    pub token: String,
}

impl OAuthPresentedToken {
    /// The token of the `Authorization` header `value`: `Bearer` or `DPoP` (names compared
    /// without regard to case), one or more spaces, and a `b64token`; `None` for another
    /// scheme. A Bearer or DPoP header whose token is not a `b64token` fails with Invalid.
    pub fn from_authorization(value: &str) -> Result<Option<OAuthPresentedToken>, OAuthError> {
        let (name, rest) = value.split_once(' ').unwrap_or((value, ""));
        let scheme = if name.eq_ignore_ascii_case("Bearer") {
            OAuthTokenScheme::Bearer
        } else if name.eq_ignore_ascii_case("DPoP") {
            OAuthTokenScheme::DPoP
        } else {
            return Ok(None);
        };
        let token = rest.trim_start_matches(' ');
        if !OAuthPresentedToken::is_b64token(token) {
            return Err(OAuthError::Invalid { parameter: "authorization" });
        }
        Ok(Some(OAuthPresentedToken { scheme, token: token.to_string() }))
    }

    /// Whether `text` is a `b64token` (RFC 6750 §2.1): `1*( ALPHA / DIGIT / "-" / "." / "_" /
    /// "~" / "+" / "/" ) *"="`.
    pub fn is_b64token(text: &str) -> bool {
        let body = text.trim_end_matches('=');
        !body.is_empty() && body.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
    }

    /// The value of an `Authorization` header that presents this token.
    pub fn authorization(&self) -> String {
        format!("{} {}", self.scheme.name(), self.token)
    }
}

/// A challenge of `WWW-Authenticate` (RFC 9110 §11.6.1): a scheme and its parameters, such
/// as those of RFC 6750 §3 (`realm`, `scope`, `error`, `error_description`, `error_uri`),
/// RFC 9449 §7.1 (`algs`), RFC 9470 §3 (`acr_values`, `max_age`) and RFC 9728 §5.1
/// (`resource_metadata`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthChallenge {
    pub scheme: String,
    pub parameters: Vec<(String, String)>,
}

impl OAuthChallenge {
    /// A challenge of `scheme` without parameters.
    pub fn new(scheme: &str) -> OAuthChallenge {
        OAuthChallenge { scheme: scheme.to_string(), parameters: Vec::new() }
    }

    /// Adds the parameter `name` of `value`.
    pub fn push(&mut self, name: &str, value: &str) {
        self.parameters.push((name.to_string(), value.to_string()));
    }

    /// The value of the parameter `name`, compared without regard to case.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.parameters.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    /// Whether the scheme is `name`, compared without regard to case.
    pub fn is_scheme(&self, name: &str) -> bool {
        self.scheme.eq_ignore_ascii_case(name)
    }

    /// The error response this challenge carries, if it has an `error`.
    pub fn error(&self) -> Option<Result<OAuthErrorResponse, OAuthError>> {
        let code = self.get("error")?;
        Some(OAuthErrorCode::parse(code).map(|code| OAuthErrorResponse {
            code,
            description: self.get("error_description").map(str::to_string),
            uri: self.get("error_uri").map(str::to_string),
        }))
    }

    /// Whether `character` may stand in a quoted-string (RFC 9110 §5.6.4: qdtext and
    /// quoted-pair take no control character but HTAB).
    pub fn is_quotable(character: char) -> bool {
        character == '\t' || !character.is_control()
    }

    /// Checks the challenge against RFC 9110 §11.6.1: the scheme and the names tokens, the
    /// values quotable (no CR, LF or other control character, which would end the field), and a
    /// parameter of an empty name a `token68`.
    pub fn check(&self) -> Result<(), OAuthError> {
        let invalid = OAuthError::Invalid { parameter: "www-authenticate" };
        let token = |text: &str| !text.is_empty() && text.bytes().all(OAuthChallenge::is_tchar);
        if !token(&self.scheme) {
            return Err(invalid);
        }
        for (name, value) in &self.parameters {
            let valid = match name.is_empty() {
                true => {
                    let body = value.trim_end_matches('=');
                    !body.is_empty() && body.bytes().all(OAuthChallenge::is_token68_char)
                }
                false => token(name) && value.chars().all(OAuthChallenge::is_quotable),
            };
            if !valid {
                return Err(invalid);
            }
        }
        Ok(())
    }

    /// The challenge as `WWW-Authenticate` carries it: every value a quoted-string (RFC 9110
    /// §5.6.4), as RFC 6750 §3 writes them, a `token68` as it is. A challenge that
    /// [`OAuthChallenge::check`] refuses fails, as it could inject header fields.
    pub fn encode(&self) -> Result<String, OAuthError> {
        self.check()?;
        let mut out = self.scheme.clone();
        for (index, (name, value)) in self.parameters.iter().enumerate() {
            out.push_str(if index == 0 { " " } else { ", " });
            if name.is_empty() {
                out.push_str(value);
                continue;
            }
            out.push_str(name);
            out.push_str("=\"");
            for character in value.chars() {
                if matches!(character, '"' | '\\') {
                    out.push('\\');
                }
                out.push(character);
            }
            out.push('"');
        }
        Ok(out)
    }

    /// Whether `byte` is a `tchar` (RFC 9110 §5.6.2), a character of a token.
    pub fn is_tchar(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
    }

    /// Whether `byte` is a character of a `token68` before its padding (RFC 9110 §11.2).
    pub fn is_token68_char(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte)
    }

    /// The challenges of a `WWW-Authenticate` value (RFC 9110 §11.6.1): schemes, each followed
    /// by a `token68` or by `name=value` parameters whose values are tokens or quoted-strings,
    /// all separated by commas. A `token68` is kept as a parameter of an empty name.
    ///
    /// After a comma, a token followed by `=` and a value is a parameter of the challenge
    /// before it; any other token begins a new challenge.
    pub fn parse(value: &str) -> Result<Vec<OAuthChallenge>, OAuthError> {
        let invalid = || OAuthError::Invalid { parameter: "www-authenticate" };
        let bytes = value.as_bytes();
        let skip = |mut index: usize, set: &[u8]| {
            while index < bytes.len() && set.contains(&bytes[index]) {
                index += 1;
            }
            index
        };
        let token_end = |mut index: usize| {
            while index < bytes.len() && OAuthChallenge::is_tchar(bytes[index]) {
                index += 1;
            }
            index
        };
        // Whether a list element ends at `index`: a comma or the end, after optional spaces.
        let ends = |index: usize| {
            let index = skip(index, b" \t");
            index >= bytes.len() || bytes[index] == b','
        };
        let mut challenges: Vec<OAuthChallenge> = Vec::new();
        let mut index = 0;
        loop {
            index = skip(index, b" \t,");
            if index >= bytes.len() {
                return Ok(challenges);
            }
            let end = token_end(index);
            if end == index {
                return Err(invalid());
            }
            let name = &value[index..end];
            let equals = skip(end, b" \t");
            let parameter = !challenges.is_empty() && bytes.get(equals) == Some(&b'=') && !ends(equals + 1) && {
                let next = skip(equals + 1, b" \t");
                bytes[next] != b'='
            };
            if parameter {
                let mut position = skip(equals + 1, b" \t");
                let text = if bytes[position] == b'"' {
                    position += 1;
                    let mut text = String::new();
                    loop {
                        match bytes.get(position) {
                            Some(b'"') => {
                                position += 1;
                                break;
                            }
                            Some(b'\\') if position + 1 < bytes.len() => {
                                let character = value[position + 1..].chars().next().ok_or_else(invalid)?;
                                if !OAuthChallenge::is_quotable(character) {
                                    return Err(invalid());
                                }
                                text.push(character);
                                position += 1 + character.len_utf8();
                            }
                            Some(_) => {
                                let character = value[position..].chars().next().ok_or_else(invalid)?;
                                if !OAuthChallenge::is_quotable(character) {
                                    return Err(invalid());
                                }
                                text.push(character);
                                position += character.len_utf8();
                            }
                            None => return Err(invalid()),
                        }
                    }
                    text
                } else {
                    let stop = token_end(position);
                    if stop == position {
                        return Err(invalid());
                    }
                    let text = value[position..stop].to_string();
                    position = stop;
                    text
                };
                if !ends(position) {
                    return Err(invalid());
                }
                challenges.last_mut().ok_or_else(invalid)?.parameters.push((name.to_string(), text));
                index = position;
                continue;
            }
            // A new challenge, and its token68 if one follows (`1*SP token68`).
            let mut challenge = OAuthChallenge::new(name);
            index = end;
            if bytes.get(index) == Some(&b' ') {
                let start = skip(index, b" ");
                let mut stop = start;
                while stop < bytes.len() && OAuthChallenge::is_token68_char(bytes[stop]) {
                    stop += 1;
                }
                let characters = stop;
                stop = skip(stop, b"=");
                if characters > start && ends(stop) {
                    challenge.parameters.push((String::new(), value[start..stop].to_string()));
                    index = stop;
                }
            }
            if !ends(index) && bytes.get(skip(index, b" \t")).is_some_and(|byte| !OAuthChallenge::is_tchar(*byte)) {
                return Err(invalid());
            }
            challenges.push(challenge);
        }
    }
}

/// What a resource server knows of an access token once it was taken.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthTokenInfo {
    pub client_id: Option<String>,
    pub subject: Option<String>,
    pub scope: OAuthScope,
    pub audience: Vec<String>,
    pub expires: Option<i64>,
    /// The thumbprint of the DPoP key the token is bound to (`cnf.jkt`, read by
    /// [`OAuthMembers::confirmation`]).
    pub confirmation: Option<String>,
    /// `auth_time` (RFC 9470 §4).
    pub authentication_time: Option<i64>,
    /// `acr` (RFC 9470 §4).
    pub authentication_context: Option<String>,
}

/// How a resource server checks the access tokens it receives.
#[derive(Clone, Debug)]
pub enum OAuthTokenValidation {
    /// JWT access tokens of RFC 9068, issued by `issuer` and signed by one of `keys` with one of
    /// `algorithms` (RFC 9068 §4).
    JWT { issuer: String, keys: JWKSet, algorithms: Vec<JWSAlgorithm> },
    /// Tokens the user introspects (RFC 7662) and hands over with
    /// [`OAuthResourceServer::accept_introspection`].
    Introspection,
}

/// The configuration of an [`OAuthResourceServer`].
#[derive(Clone, Debug)]
pub struct OAuthResourceConfig {
    /// The resource identifier (RFC 8707, RFC 9728 §2), which a token's audience must hold.
    pub resource: String,
    /// The `realm` of the challenges (RFC 6750 §3).
    pub realm: Option<String>,
    /// The URL of the resource's metadata, sent in challenges (RFC 9728 §5.1).
    pub resource_metadata: Option<String>,
    pub validation: OAuthTokenValidation,
    /// Whether only DPoP-bound tokens are taken (RFC 9449 §7.1).
    pub require_dpop: bool,
    pub dpop: DPoPConfig,
    /// The seconds of clock skew allowed on `exp`.
    pub leeway: u64,
}

/// A refusal of a resource server: the status and the challenges to send (RFC 6750 §3), and the
/// DPoP nonce to send in `DPoP-Nonce` (RFC 9449 §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthResourceError {
    pub status: u16,
    pub challenges: Vec<OAuthChallenge>,
    pub nonce: Option<String>,
}

impl OAuthResourceError {
    /// The HTTP response of the refusal: one `WWW-Authenticate` field per challenge.
    pub fn to_response(&self) -> OAuthHTTPResponse {
        // The challenges a resource server makes pass `check`; one that does not is left out.
        let mut headers: Vec<(String, String)> = self
            .challenges
            .iter()
            .filter_map(|challenge| Some(("www-authenticate".to_string(), challenge.encode().ok()?)))
            .collect();
        if let Some(nonce) = &self.nonce {
            headers.push(("dpop-nonce".to_string(), nonce.clone()));
        }
        headers.push(("cache-control".to_string(), "no-store".to_string()));
        OAuthHTTPResponse { status: self.status, headers, body: Vec::new() }
    }
}

/// The checks of a protected resource (RFC 6750, RFC 9068 §4, RFC 9449 §7, RFC 9470, RFC 9728)
/// without I/O: it reads the access token of a request, takes it as a JWT or from an
/// introspection response, checks its binding to a DPoP key, its scope and how the user
/// authenticated, and makes the challenges of a refusal.
pub struct OAuthResourceServer {
    config: OAuthResourceConfig,
    dpop: DPoPVerifier,
}

impl OAuthResourceServer {
    /// The checks of `config`, whose realm and metadata URL must be quotable in a challenge
    /// (RFC 9110 §5.6.4), or it fails with Invalid.
    pub fn new(config: OAuthResourceConfig) -> Result<OAuthResourceServer, OAuthError> {
        let quotable =
            |text: &Option<String>| text.as_deref().unwrap_or_default().chars().all(OAuthChallenge::is_quotable);
        if !quotable(&config.realm) || !quotable(&config.resource_metadata) {
            return Err(OAuthError::Invalid { parameter: "realm" });
        }
        Ok(OAuthResourceServer { dpop: DPoPVerifier::new(config.dpop.clone()), config })
    }

    pub fn config(&self) -> &OAuthResourceConfig {
        &self.config
    }

    /// The checks of DPoP proofs, whose nonce the user rotates (RFC 9449 §9).
    pub fn dpop(&mut self) -> &mut DPoPVerifier {
        &mut self.dpop
    }

    /// The metadata document of the resource (RFC 9728 §2), naming its authorization servers.
    pub fn metadata(&self, authorization_servers: &[&str], scopes: &[&str]) -> OAuthMetadata {
        let mut metadata = OAuthMetadata::new(OAuthMetadataKind::Resource, &self.config.resource);
        metadata.set_strings(OAuthMetadata::AUTHORIZATION_SERVERS, authorization_servers);
        metadata.set_strings(OAuthMetadata::BEARER_METHODS_SUPPORTED, &["header"]);
        if !scopes.is_empty() {
            metadata.set_strings(OAuthMetadata::SCOPES_SUPPORTED, scopes);
        }
        let algorithms: Vec<&str> = self.config.dpop.algorithms.iter().map(|algorithm| algorithm.name()).collect();
        metadata.set_strings(OAuthMetadata::DPOP_SIGNING_ALG_VALUES_SUPPORTED, &algorithms);
        if self.config.require_dpop {
            metadata.set_boolean(OAuthMetadata::DPOP_BOUND_ACCESS_TOKENS_REQUIRED, true);
        }
        metadata
    }

    /// A refusal of `error` (none for a request without credentials, RFC 6750 §3.1), challenged
    /// with `scheme`, or with every scheme the resource takes when `scheme` is `None`.
    pub fn refuse(&self, error: Option<&OAuthErrorResponse>, scheme: Option<OAuthTokenScheme>) -> OAuthResourceError {
        let status = match error.map(|error| &error.code) {
            None => 401,
            Some(OAuthErrorCode::InvalidRequest) => 400,
            Some(OAuthErrorCode::InsufficientScope) => 403,
            Some(OAuthErrorCode::ServerError) => 500,
            Some(_) => 401,
        };
        let schemes: Vec<OAuthTokenScheme> = match scheme {
            Some(scheme) => alloc::vec![scheme],
            None if self.config.require_dpop => alloc::vec![OAuthTokenScheme::DPoP],
            None => alloc::vec![OAuthTokenScheme::Bearer, OAuthTokenScheme::DPoP],
        };
        let challenges = schemes
            .into_iter()
            .map(|scheme| {
                let mut challenge = OAuthChallenge::new(scheme.name());
                if let Some(realm) = &self.config.realm {
                    challenge.push("realm", realm);
                }
                if let Some(error) = error {
                    challenge.push("error", error.code.as_str());
                    if let Some(description) = &error.description {
                        challenge.push("error_description", description);
                    }
                    if let Some(uri) = &error.uri {
                        challenge.push("error_uri", uri);
                    }
                }
                if scheme == OAuthTokenScheme::DPoP {
                    let algorithms: Vec<&str> =
                        self.config.dpop.algorithms.iter().map(|algorithm| algorithm.name()).collect();
                    challenge.push("algs", &algorithms.join(" "));
                }
                if let Some(metadata) = &self.config.resource_metadata {
                    challenge.push("resource_metadata", metadata);
                }
                challenge
            })
            .collect();
        let nonce = match error.map(|error| &error.code) {
            Some(OAuthErrorCode::UseDPoPNonce) => self.dpop.nonce().map(str::to_string),
            _ => None,
        };
        OAuthResourceError { status, challenges, nonce }
    }

    fn refuse_with(
        &self,
        code: OAuthErrorCode,
        description: &str,
        scheme: Option<OAuthTokenScheme>,
    ) -> OAuthResourceError {
        self.refuse(Some(&OAuthErrorResponse::with_description(code, description)), scheme)
    }

    /// The access token of `request`'s `Authorization` header; a request without one is refused
    /// without an error code (RFC 6750 §3.1), a malformed one with `invalid_request`.
    pub fn presented(&self, request: &OAuthEndpointRequest) -> Result<OAuthPresentedToken, OAuthResourceError> {
        let Some(value) = &request.authorization else {
            return Err(self.refuse(None, None));
        };
        match OAuthPresentedToken::from_authorization(value) {
            Ok(Some(token)) => Ok(token),
            Ok(None) => Err(self.refuse(None, None)),
            Err(_) => {
                Err(self.refuse_with(OAuthErrorCode::InvalidRequest, "the Authorization header is malformed", None))
            }
        }
    }

    /// The token of `request`, a JWT access token of RFC 9068 checked as its §4 says: the type
    /// `at+jwt`, the issuer, the audience (this resource), the signature, the lifetime; then the
    /// DPoP binding.
    pub fn accept_jwt(
        &mut self,
        request: &OAuthEndpointRequest,
        now: i64,
    ) -> Result<OAuthTokenInfo, OAuthResourceError> {
        let presented = self.presented(request)?;
        let OAuthTokenValidation::JWT { issuer, keys, algorithms } = &self.config.validation else {
            return Err(self.refuse_with(
                OAuthErrorCode::ServerError,
                "the resource does not take JWT access tokens",
                Some(presented.scheme),
            ));
        };
        let mut validation = JWTValidation::new(now);
        validation.leeway = self.config.leeway;
        validation.issuer = Some(issuer.clone());
        validation.audience = Some(self.config.resource.clone());
        validation.token_type = Some("at+jwt".to_string());
        validation.required =
            ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"].iter().map(|name| name.to_string()).collect();
        let config = JWSConfig::new(algorithms);
        let jwt = keys.keys.iter().find_map(|key| JWT::verify(&presented.token, key, &config, &validation).ok());
        let Some(jwt) = jwt else {
            return Err(self.refuse_with(
                OAuthErrorCode::InvalidToken,
                "the access token is not valid",
                Some(presented.scheme),
            ));
        };
        let claims = &jwt.claims;
        let string = |name| claims.string(name).ok().flatten().map(str::to_string);
        // A `cnf` this resource cannot check would otherwise make a bound token a bearer token.
        let Ok(confirmation) = (OAuthMembers { object: &claims.claims }).confirmation() else {
            return Err(self.refuse_with(
                OAuthErrorCode::InvalidToken,
                "the access token is bound by a confirmation method the resource does not check",
                Some(presented.scheme),
            ));
        };
        let info = OAuthTokenInfo {
            client_id: string("client_id"),
            subject: string("sub"),
            scope: string("scope")
                .map(|scope| OAuthScope::parse(&scope))
                .transpose()
                .ok()
                .flatten()
                .unwrap_or_default(),
            audience: claims
                .audience()
                .map(|audience| audience.iter().map(|value| value.to_string()).collect())
                .unwrap_or_default(),
            expires: claims.expiration().ok().flatten().map(|seconds| seconds as i64),
            confirmation,
            authentication_time: claims.numeric_date("auth_time").ok().flatten().map(|seconds| seconds as i64),
            authentication_context: string("acr"),
        };
        self.check_binding(request, &presented, info, now)
    }

    /// The token of `request` taken from `introspection`, the answer the authorization server
    /// gave about it (RFC 7662 §2.2): it must be active, an access token, not expired, and for
    /// this resource when it names an audience; then the DPoP binding.
    pub fn accept_introspection(
        &mut self,
        request: &OAuthEndpointRequest,
        introspection: &OAuthIntrospectionResponse,
        now: i64,
    ) -> Result<OAuthTokenInfo, OAuthResourceError> {
        let presented = self.presented(request)?;
        let refused = |server: &OAuthResourceServer| {
            server.refuse_with(OAuthErrorCode::InvalidToken, "the access token is not valid", Some(presented.scheme))
        };
        let expired = introspection
            .expires
            .is_some_and(|expires| expires + i64::try_from(self.config.leeway).unwrap_or(i64::MAX) < now);
        let refresh =
            introspection.token_type.as_deref().is_some_and(|kind| kind.eq_ignore_ascii_case("refresh_token"));
        let foreign = !introspection.audience.is_empty() && !introspection.audience.contains(&self.config.resource);
        if !introspection.active || expired || refresh || foreign {
            return Err(refused(self));
        }
        let info = OAuthTokenInfo {
            client_id: introspection.client_id.clone(),
            subject: introspection.subject.clone(),
            scope: introspection.scope.clone().unwrap_or_default(),
            audience: introspection.audience.clone(),
            expires: introspection.expires,
            confirmation: introspection.confirmation.clone(),
            authentication_time: introspection
                .other
                .get("auth_time")
                .and_then(JSONValue::as_number)
                .and_then(|number| number.as_i64().ok()),
            authentication_context: introspection.other.get("acr").and_then(JSONValue::as_str).map(str::to_string),
        };
        self.check_binding(request, &presented, info, now)
    }

    /// Checks the binding of `info` to a DPoP key (RFC 9449 §7): a bound token is presented with
    /// the `DPoP` scheme and a proof of its key for this request; a `DPoP` token is bound.
    pub fn check_binding(
        &mut self,
        request: &OAuthEndpointRequest,
        presented: &OAuthPresentedToken,
        info: OAuthTokenInfo,
        now: i64,
    ) -> Result<OAuthTokenInfo, OAuthResourceError> {
        let scheme = Some(presented.scheme);
        match (presented.scheme, &info.confirmation) {
            (OAuthTokenScheme::Bearer, Some(_)) => {
                return Err(self.refuse_with(
                    OAuthErrorCode::InvalidToken,
                    "the access token is bound to a DPoP key",
                    Some(OAuthTokenScheme::DPoP),
                ));
            }
            (OAuthTokenScheme::Bearer, None) if self.config.require_dpop => {
                return Err(self.refuse_with(
                    OAuthErrorCode::InvalidToken,
                    "a DPoP-bound access token is required",
                    Some(OAuthTokenScheme::DPoP),
                ));
            }
            (OAuthTokenScheme::Bearer, None) => return Ok(info),
            (OAuthTokenScheme::DPoP, None) => {
                return Err(self.refuse_with(
                    OAuthErrorCode::InvalidToken,
                    "the access token is not bound to a DPoP key",
                    scheme,
                ));
            }
            (OAuthTokenScheme::DPoP, Some(_)) => {}
        }
        let Some(proof) = &request.dpop else {
            return Err(self.refuse_with(OAuthErrorCode::InvalidDPoPProof, "a DPoP proof is required", scheme));
        };
        let target = DPoPTarget { method: &request.method, uri: &request.uri, access_token: Some(&presented.token) };
        let proof = match self.dpop.check(proof, &target, now) {
            Ok(proof) => proof,
            Err(error) => return Err(self.refuse(Some(&error), scheme)),
        };
        if Some(&proof.thumbprint) != info.confirmation.as_ref() {
            return Err(self.refuse_with(
                OAuthErrorCode::InvalidDPoPProof,
                "the DPoP key is not the key of the access token",
                scheme,
            ));
        }
        Ok(info)
    }

    /// Checks that `info` grants every token of `scope`; a refusal names the scope needed
    /// (`insufficient_scope`, RFC 6750 §3.1).
    pub fn require_scope(
        &self,
        info: &OAuthTokenInfo,
        scope: &OAuthScope,
        scheme: OAuthTokenScheme,
    ) -> Result<(), OAuthResourceError> {
        if scope.is_subset_of(&info.scope) {
            return Ok(());
        }
        let mut refusal = self.refuse_with(
            OAuthErrorCode::InsufficientScope,
            "the access token does not grant the scope",
            Some(scheme),
        );
        for challenge in &mut refusal.challenges {
            challenge.push("scope", &scope.to_string());
        }
        Err(refusal)
    }

    /// Checks that the user authenticated at most `max_age` seconds before `now` and with one of
    /// `acr_values`, when they are given; a refusal asks for a new authentication
    /// (`insufficient_user_authentication`, RFC 9470 §3).
    pub fn require_authentication(
        &self,
        info: &OAuthTokenInfo,
        now: i64,
        max_age: Option<i64>,
        acr_values: &[&str],
        scheme: OAuthTokenScheme,
    ) -> Result<(), OAuthResourceError> {
        let recent = max_age.is_none_or(|age| info.authentication_time.is_some_and(|time| now - time <= age));
        let strong = acr_values.is_empty()
            || info.authentication_context.as_deref().is_some_and(|acr| acr_values.contains(&acr));
        if recent && strong {
            return Ok(());
        }
        let mut refusal = self.refuse_with(
            OAuthErrorCode::InsufficientUserAuthentication,
            "a more recent or stronger authentication is required",
            Some(scheme),
        );
        // Values that could not be quoted are left out of the challenge.
        let acr_values: Vec<&str> =
            acr_values.iter().copied().filter(|value| value.chars().all(OAuthChallenge::is_quotable)).collect();
        for challenge in &mut refusal.challenges {
            if !acr_values.is_empty() {
                challenge.push("acr_values", &acr_values.join(" "));
            }
            if let Some(age) = max_age {
                challenge.push("max_age", &age.to_string());
            }
        }
        Err(refusal)
    }
}
