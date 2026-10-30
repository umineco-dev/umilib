//! OAuth against RFC 6749 (§2.3.1, §3.3, §4.1, §4.4, §5, §6 and their examples), RFC 7636
//! (Appendix B), RFC 8414 (§3), RFC 9728 (§3), RFC 9207 (§2), RFC 8707 (§2), RFC 7523 (§2.2,
//! §3) and RFC 9700 (no implicit or password grants, S256 only).

use umilib::auth::cert::key::{KeyAlgorithm, NamedCurve, PrivateKey};
use umilib::auth::oauth::{
    OAuthAuthorizationRequest, OAuthAuthorizationResponse, OAuthClient, OAuthClientAuthentication, OAuthClientConfig,
    OAuthError, OAuthErrorCode, OAuthErrorResponse, OAuthGrant, OAuthMetadata, OAuthMetadataKind, OAuthParameters,
    OAuthScope, OAuthTokenRequest, OAuthTokenResponse, PKCEChallenge, PKCEMethod, PKCEVerifier,
};
use umilib::codec::uri::URIReference;
use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;
use umilib::protocol::jwt::{JWK, JWSAlgorithm, JWSConfig, JWT, JWTValidation};
use umilib::secret::Secret;

use crate::{RFC, Vectors};

mod dpop;
mod server;

const RFC6749: &str = "auth/oauth/rfc6749.txt";

pub fn random() -> HMACDRBG<SHA256> {
    HMACDRBG::<SHA256>::new(&[7; 32], &[11; 16], b"umilib oauth tests").unwrap()
}

/// The parameters of the query of a request line or a `Location` that an RFC folds over lines.
fn query_of(path: &str, prefix: &str) -> OAuthParameters {
    let joined = RFC::block_from(path, prefix);
    let target = joined.split_whitespace().find(|word| word.contains('?')).unwrap_or(&joined).to_string();
    let target = target.strip_prefix("Location:").unwrap_or(&target);
    let query = &target[target.find('?').unwrap() + 1..];
    let query = query.split(" HTTP/1.1").next().unwrap();
    let query = query.split("HTTP/1.1").next().unwrap();
    OAuthParameters::parse(query.as_bytes()).unwrap()
}

/// The JSON object of the RFC at `path` that holds the text `marker`, page breaks left out.
pub fn json_around(path: &str, marker: &str) -> String {
    let text = Vectors::read(path);
    let start = text.find(marker).unwrap_or_else(|| panic!("{path}: no {marker}"));
    let open = text[..start].rfind('{').unwrap();
    let mut depth = 0;
    let mut in_string = false;
    for (index, character) in text[open..].char_indices() {
        match character {
            '"' => in_string = !in_string,
            '{' if !in_string => depth += 1,
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    let object = &text[open..=open + index];
                    return object.lines().filter(|line| !RFC::is_page_break(line)).collect::<Vec<_>>().join("\n");
                }
            }
            _ => {}
        }
    }
    panic!("{path}: unterminated object around {marker}");
}

#[test]
fn pkce_reproduces_appendix_b_of_rfc_7636() {
    let verifier_text = RFC::block_from("auth/oauth/rfc7636.txt", "dBjftJeZ4CVP");
    let challenge_text = RFC::block_from("auth/oauth/rfc7636.txt", "E9Melhoa2Ow");
    let verifier = PKCEVerifier::new(&verifier_text).unwrap();
    let challenge = verifier.challenge(PKCEMethod::S256);
    assert_eq!(challenge.value, challenge_text);
    assert!(PKCEChallenge::new(PKCEMethod::S256, &challenge_text).unwrap().verify(&verifier));
    let other = PKCEVerifier::new(&"a".repeat(43)).unwrap();
    assert!(!challenge.verify(&other));
    // §4.1: 43 to 128 unreserved characters.
    assert!(PKCEVerifier::new(&"a".repeat(42)).is_err());
    assert!(PKCEVerifier::new(&"~".repeat(128)).is_ok());
    assert!(PKCEVerifier::new(&"a".repeat(129)).is_err());
    assert!(PKCEVerifier::new(&format!("{}+", "a".repeat(43))).is_err());
    // A generated verifier is 43 characters from 32 random octets.
    let generated = PKCEVerifier::generate(&mut random()).unwrap();
    assert_eq!(generated.as_str().len(), 43);
    // RFC 9700 §2.1.1: plain is not taken; S256 is the only method.
    assert!(PKCEMethod::parse("plain").is_err());
    assert_eq!(PKCEMethod::parse("S256"), Ok(PKCEMethod::S256));
    assert!(PKCEMethod::parse("s256").is_err());
    // An S256 challenge is the 43 characters of an unpadded base64url SHA-256 digest.
    assert!(PKCEChallenge::new(PKCEMethod::S256, &challenge_text[..42]).is_err());
    assert!(PKCEChallenge::new(PKCEMethod::S256, &format!("{challenge_text}=")).is_err());
    assert!(PKCEChallenge::new(PKCEMethod::S256, &format!("{}+", &challenge_text[..42])).is_err());
}

#[test]
fn reads_the_authorization_requests_of_rfc_6749_and_rfc_8707() {
    let parameters = query_of(RFC6749, "GET /authorize?response_type=code&client_id=s6BhdRkqt3");
    let request = OAuthAuthorizationRequest::from_parameters(&parameters).unwrap();
    assert_eq!(request.response_type.as_deref(), Some("code"));
    assert_eq!(request.client_id, "s6BhdRkqt3");
    assert_eq!(request.state.as_deref(), Some("xyz"));
    assert_eq!(request.redirect_uri.as_deref(), Some("https://client.example.com/cb"));
    assert_eq!(OAuthAuthorizationRequest::from_parameters(&request.to_parameters()).unwrap(), request);

    // RFC 8707 §2.1 Figure 2: two resources and a scope.
    let parameters = query_of("auth/oauth/rfc8707.txt", "GET /as/authorization.oauth2?response_type=code");
    let request = OAuthAuthorizationRequest::from_parameters(&parameters).unwrap();
    assert_eq!(request.resources, ["https://cal.example.com/", "https://contacts.example.com/"]);
    assert_eq!(request.scope, Some(OAuthScope::parse("calendar contacts").unwrap()));
    assert_eq!(OAuthAuthorizationRequest::from_parameters(&request.to_parameters()).unwrap(), request);

    // §3.1: a parameter given twice is refused, one without a value is omitted.
    assert_eq!(
        OAuthParameters::parse(b"client_id=a&state=1&state=2"),
        Err(OAuthError::Repeated { parameter: "state".into() })
    );
    let parameters = OAuthParameters::parse(b"client_id=a&state=&scope=").unwrap();
    let request = OAuthAuthorizationRequest::from_parameters(&parameters).unwrap();
    assert_eq!((request.state, request.scope), (None, None));
    assert_eq!(
        OAuthAuthorizationRequest::from_parameters(&OAuthParameters::parse(b"state=x").unwrap()),
        Err(OAuthError::Missing { parameter: "client_id" })
    );
    // RFC 7636 §4.3: a challenge without a method is plain, which is refused.
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let plain = format!("client_id=a&code_challenge={challenge}");
    assert!(OAuthAuthorizationRequest::from_parameters(&OAuthParameters::parse(plain.as_bytes()).unwrap()).is_err());
    let s256 = format!("client_id=a&code_challenge={challenge}&code_challenge_method=S256");
    let request =
        OAuthAuthorizationRequest::from_parameters(&OAuthParameters::parse(s256.as_bytes()).unwrap()).unwrap();
    assert_eq!(request.code_challenge.unwrap().value, challenge);
    // Unknown parameters are kept.
    let request =
        OAuthAuthorizationRequest::from_parameters(&OAuthParameters::parse(b"client_id=a&prompt=none").unwrap())
            .unwrap();
    assert_eq!(request.other.get("prompt"), Some("none"));
}

#[test]
fn reads_the_authorization_responses_of_rfc_6749_and_rfc_9207() {
    let parameters = query_of(RFC6749, "Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA");
    let response = OAuthAuthorizationResponse::from_parameters(&parameters).unwrap();
    assert_eq!(response.code, "SplxlOBeZQQYbYS6WxSbIA");
    assert_eq!(response.state.as_deref(), Some("xyz"));
    let parameters = query_of(RFC6749, "Location: https://client.example.com/cb?error=access_denied");
    assert_eq!(
        OAuthAuthorizationResponse::from_parameters(&parameters),
        Err(OAuthError::Response(OAuthErrorResponse::new(OAuthErrorCode::AccessDenied)))
    );

    // RFC 9207 §2.1 and §2.2: the issuer is decoded from the form encoding.
    let joined = RFC::block_from("auth/oauth/rfc9207.txt", "Location: https://client.example/cb?");
    let query = joined.strip_prefix("Location: https://client.example/cb?").unwrap();
    let response =
        OAuthAuthorizationResponse::from_parameters(&OAuthParameters::parse(query.as_bytes()).unwrap()).unwrap();
    assert_eq!(response.issuer.as_deref(), Some("https://honest.as.example"));
    assert_eq!(response.code, "x1848ZT64p4IirMPT0R-X3141MFPTuBX-VFL_cvaplMH58");
    assert_eq!(OAuthAuthorizationResponse::from_parameters(&response.to_parameters()).unwrap(), response);
}

#[test]
fn reads_the_token_requests_of_rfc_6749() {
    // §4.1.3, with the Basic credentials of §2.3.1.
    let body = RFC::block_from(RFC6749, "grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA");
    let request = OAuthTokenRequest::from_parameters(&OAuthParameters::parse(body.as_bytes()).unwrap()).unwrap();
    let OAuthGrant::AuthorizationCode { code, redirect_uri, code_verifier } = &request.grant else {
        panic!("not an authorization code grant");
    };
    assert_eq!(code, "SplxlOBeZQQYbYS6WxSbIA");
    assert_eq!(redirect_uri.as_deref(), Some("https://client.example.com/cb"));
    assert!(code_verifier.is_none());
    let header = OAuthClientAuthentication::basic_credentials("s6BhdRkqt3", "gX1fBat3bV");
    assert_eq!(header.expose(), "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
    assert!(Vectors::read(RFC6749).contains(&format!("Authorization: {}", header.expose())));
    // §4.4.2 and §6.
    let request =
        OAuthTokenRequest::from_parameters(&OAuthParameters::parse(b"grant_type=client_credentials").unwrap()).unwrap();
    assert!(matches!(request.grant, OAuthGrant::ClientCredentials));
    let body = RFC::block_from(RFC6749, "grant_type=refresh_token&refresh_token=");
    let request = OAuthTokenRequest::from_parameters(&OAuthParameters::parse(body.as_bytes()).unwrap()).unwrap();
    assert!(
        matches!(&request.grant, OAuthGrant::RefreshToken { refresh_token } if refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA")
    );
    // The first example of §6 is §2.3.1's, with the client's credentials in the body: they are
    // client authentication, not part of the request.
    assert!(body.contains("client_secret=7Fjfp0ZBr1KtDRbnfVdmIw"));
    assert_eq!(request.to_parameters().encode(), "grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA");
    // RFC 9700 §2.4: the resource owner password credentials grant must not be used; the
    // implicit grant (response_type=token) has no token request at all.
    let password = RFC::block_from(RFC6749, "grant_type=password&username=johndoe");
    assert_eq!(
        OAuthTokenRequest::from_parameters(&OAuthParameters::parse(password.as_bytes()).unwrap()).err(),
        Some(OAuthError::Invalid { parameter: "grant_type" })
    );
    // Client authentication is not part of the request.
    let request = OAuthTokenRequest::from_parameters(
        &OAuthParameters::parse(b"grant_type=client_credentials&client_id=a&client_secret=b&audience=x").unwrap(),
    )
    .unwrap();
    assert_eq!(request.to_parameters().encode(), "grant_type=client_credentials&audience=x");
}

#[test]
fn reads_the_token_responses_of_rfc_6749() {
    let body = json_around(RFC6749, "\"token_type\":\"example\"");
    let response = OAuthTokenResponse::decode(200, body.as_bytes()).unwrap();
    assert_eq!(response.access_token, "2YotnFZFEjr1zCsicMWpAA");
    assert_eq!(response.token_type, "example");
    assert_eq!(response.expires_in, Some(3600));
    assert_eq!(response.refresh_token.as_deref(), Some("tGzv3JOkF0XG5Qx2TlKWIA"));
    assert_eq!(response.other.get("example_parameter").and_then(|value| value.as_str()), Some("example_value"));
    assert_eq!(OAuthTokenResponse::decode(200, response.encode().as_bytes()).unwrap(), response);
    assert!(response.is_token_type("EXAMPLE"));

    // §5.2.
    let body = json_around(RFC6749, "\"error\":\"invalid_request\"");
    assert_eq!(
        OAuthTokenResponse::decode(400, body.as_bytes()),
        Err(OAuthError::Response(OAuthErrorResponse::new(OAuthErrorCode::InvalidRequest)))
    );
    for (body, error) in [
        (r#"{"token_type":"Bearer"}"#, OAuthError::Missing { parameter: "access_token" }),
        (r#"{"access_token":"a"}"#, OAuthError::Missing { parameter: "token_type" }),
        (
            r#"{"access_token":"a","token_type":"Bearer","expires_in":-1}"#,
            OAuthError::Invalid { parameter: "expires_in" },
        ),
        (
            r#"{"access_token":"a","token_type":"Bearer","expires_in":"1"}"#,
            OAuthError::Invalid { parameter: "expires_in" },
        ),
        (r#"{"access_token":1,"token_type":"Bearer"}"#, OAuthError::Invalid { parameter: "access_token" }),
    ] {
        assert_eq!(OAuthTokenResponse::decode(200, body.as_bytes()), Err(error), "{body}");
    }
    // A repeated member is not taken: one of the two would be ignored.
    assert!(
        OAuthTokenResponse::decode(200, br#"{"access_token":"a","access_token":"b","token_type":"Bearer"}"#).is_err()
    );
}

#[test]
fn error_responses_follow_appendix_a() {
    for code in [
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "unauthorized_client",
        "unsupported_grant_type",
        "invalid_scope",
        "access_denied",
        "unsupported_response_type",
        "server_error",
        "temporarily_unavailable",
        "invalid_token",
        "insufficient_scope",
        "unsupported_token_type",
        "authorization_pending",
        "slow_down",
        "expired_token",
        "invalid_target",
        "invalid_dpop_proof",
        "use_dpop_nonce",
        "insufficient_user_authentication",
    ] {
        let parsed = OAuthErrorCode::parse(code).unwrap();
        assert!(!matches!(parsed, OAuthErrorCode::Other(_)), "{code}");
        assert_eq!(parsed.as_str(), code);
    }
    assert_eq!(OAuthErrorCode::parse("custom_code"), Ok(OAuthErrorCode::Other("custom_code".into())));
    // A.7, A.8: NQSCHAR excludes `"` and `\`.
    assert!(OAuthErrorCode::parse("bad\"code").is_err());
    assert!(OAuthErrorCode::parse("").is_err());
    assert!(OAuthErrorResponse::with_description(OAuthErrorCode::InvalidRequest, "a \\ b").check().is_err());
    let response = OAuthErrorResponse::with_description(OAuthErrorCode::InvalidRequest, "missing code");
    assert_eq!(response.encode(), r#"{"error":"invalid_request","error_description":"missing code"}"#);
    let mut parameters = OAuthParameters::new();
    response.to_parameters(&mut parameters);
    assert_eq!(OAuthErrorResponse::from_parameters(&parameters), Some(Ok(response)));
}

#[test]
fn scopes_follow_section_3_3() {
    let scope = OAuthScope::parse("read write read").unwrap();
    assert_eq!(scope.tokens(), ["read", "write"]);
    assert_eq!(scope.to_string(), "read write");
    assert!(OAuthScope::parse("read").unwrap().is_subset_of(&scope));
    assert!(!OAuthScope::parse("admin").unwrap().is_subset_of(&scope));
    for text in ["", " ", "a  b", "a ", "\"a\"", "a\\b", "é"] {
        assert!(OAuthScope::parse(text).is_err(), "{text:?}");
    }
    assert_eq!(scope.intersection(&OAuthScope::parse("write admin").unwrap()).to_string(), "write");
}

#[test]
fn metadata_follows_rfc_8414_and_rfc_9728() {
    let body = json_around("auth/oauth/rfc8414.txt", "\"https://server.example.com/userinfo\"");
    let metadata = OAuthMetadata::decode(OAuthMetadataKind::Server, body.as_bytes()).unwrap();
    metadata.check("https://server.example.com").unwrap();
    assert_eq!(metadata.check("https://server.example.com/"), Err(OAuthError::Issuer));
    assert_eq!(metadata.string(OAuthMetadata::TOKEN_ENDPOINT).unwrap(), Some("https://server.example.com/token"));
    assert!(metadata.lists(OAuthMetadata::TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, "private_key_jwt").unwrap());
    assert_eq!(metadata.strings(OAuthMetadata::SCOPES_SUPPORTED).unwrap().unwrap().len(), 6);
    assert_eq!(metadata.boolean(OAuthMetadata::REQUIRE_PUSHED_AUTHORIZATION_REQUESTS).unwrap(), None);
    assert!(metadata.boolean(OAuthMetadata::ISSUER).is_err());
    assert_eq!(OAuthMetadata::decode(OAuthMetadataKind::Server, metadata.encode().as_bytes()).unwrap(), metadata);
    assert_eq!(
        OAuthMetadata::decode(OAuthMetadataKind::Server, br#"{"token_endpoint":"https://a/t"}"#),
        Err(OAuthError::Missing { parameter: "issuer" })
    );

    // §3.1: the well-known path between the host and the path of the issuer.
    assert!(
        Vectors::read("auth/oauth/rfc8414.txt")
            .contains("GET /.well-known/oauth-authorization-server/issuer1 HTTP/1.1")
    );
    let location = |kind, identifier| OAuthMetadata::location(kind, identifier);
    assert_eq!(
        location(OAuthMetadataKind::Server, "https://example.com/issuer1").unwrap(),
        "https://example.com/.well-known/oauth-authorization-server/issuer1"
    );
    assert_eq!(
        location(OAuthMetadataKind::Server, "https://example.com/").unwrap(),
        "https://example.com/.well-known/oauth-authorization-server"
    );
    assert_eq!(
        location(OAuthMetadataKind::Server, "https://example.com/a/").unwrap(),
        "https://example.com/.well-known/oauth-authorization-server/a"
    );
    assert!(location(OAuthMetadataKind::Server, "https://example.com/?q").is_err());
    assert!(location(OAuthMetadataKind::Server, "https://example.com/#f").is_err());
    assert!(location(OAuthMetadataKind::Server, "/issuer").is_err());

    // RFC 9728.
    assert!(
        Vectors::read("auth/oauth/rfc9728.txt")
            .contains("GET /.well-known/oauth-protected-resource/resource1 HTTP/1.1")
    );
    assert_eq!(
        location(OAuthMetadataKind::Resource, "https://resource.example.com/resource1").unwrap(),
        "https://resource.example.com/.well-known/oauth-protected-resource/resource1"
    );
    assert_eq!(
        location(OAuthMetadataKind::Resource, "https://r.example.com/a?b=c").unwrap(),
        "https://r.example.com/.well-known/oauth-protected-resource/a?b=c"
    );
    let body = json_around("auth/oauth/rfc9728.txt", "\"https://as2.example.net\"");
    let metadata = OAuthMetadata::decode(OAuthMetadataKind::Resource, body.as_bytes()).unwrap();
    metadata.check("https://resource.example.com").unwrap();
    assert_eq!(
        metadata.strings(OAuthMetadata::AUTHORIZATION_SERVERS).unwrap().unwrap(),
        ["https://as1.example.com", "https://as2.example.net"]
    );
}

fn server_metadata() -> OAuthMetadata {
    let mut metadata = OAuthMetadata::new(OAuthMetadataKind::Server, "https://server.example.com");
    metadata.set_string(OAuthMetadata::AUTHORIZATION_ENDPOINT, "https://server.example.com/authorize?tenant=1");
    metadata.set_string(OAuthMetadata::TOKEN_ENDPOINT, "https://server.example.com/token");
    metadata.set_boolean(OAuthMetadata::AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED, true);
    metadata
}

fn secret_client() -> OAuthClient {
    let authentication = OAuthClientAuthentication::SecretBasic {
        client_id: "s6BhdRkqt3".into(),
        secret: Secret::new("gX1fBat3bV".into()),
    };
    OAuthClient::new(
        OAuthClientConfig::from_metadata(&server_metadata(), authentication, "https://client.example.com/cb").unwrap(),
    )
}

#[test]
fn the_client_runs_the_authorization_code_grant_with_pkce() {
    let mut random = random();
    let mut client = secret_client();
    let scope = OAuthScope::parse("read").unwrap();
    let url = client.authorize(Some(&scope), &["https://api.example.com/"], 1000, &mut random).unwrap();
    // §3.1: the query of the endpoint is kept.
    assert_eq!(url.path, "/authorize");
    assert!(url.query.as_deref().unwrap().starts_with("tenant=1&"));
    let parameters = OAuthParameters::from_query(&url).unwrap();
    let request = OAuthAuthorizationRequest::from_parameters(&parameters).unwrap();
    assert_eq!(request.response_type.as_deref(), Some("code"));
    assert_eq!(request.client_id, "s6BhdRkqt3");
    assert_eq!(request.redirect_uri.as_deref(), Some("https://client.example.com/cb"));
    assert_eq!(request.scope, Some(scope));
    assert_eq!(request.resources, ["https://api.example.com/"]);
    let challenge = request.code_challenge.clone().unwrap();
    assert_eq!(challenge.method, PKCEMethod::S256);
    let state = request.state.clone().unwrap();
    assert!(state.len() >= 22);

    // The response: the state of the request, the code and the issuer.
    let redirect = |query: &str| URIReference::parse(&format!("https://client.example.com/cb?{query}")).unwrap();
    let issuer = "iss=https%3A%2F%2Fserver.example.com";
    let token_request = client.callback(&redirect(&format!("code=abc&state={state}&{issuer}")), 1010).unwrap();
    let OAuthGrant::AuthorizationCode { code, redirect_uri, code_verifier } = &token_request.grant else {
        panic!("not an authorization code grant");
    };
    assert_eq!(code, "abc");
    assert_eq!(redirect_uri.as_deref(), Some("https://client.example.com/cb"));
    assert!(challenge.verify(code_verifier.as_ref().unwrap()));
    assert_eq!(token_request.resources, ["https://api.example.com/"]);
    // The state is used once (RFC 6749 §10.12).
    assert_eq!(
        client.callback(&redirect(&format!("code=abc&state={state}&{issuer}")), 1010).err(),
        Some(OAuthError::State)
    );

    // The token request: Basic credentials and the form body.
    let http = client.token_request(&token_request, 1010, &mut random).unwrap();
    assert_eq!(http.method, "POST");
    assert_eq!(http.uri, "https://server.example.com/token");
    assert_eq!(http.header("Content-Type"), Some("application/x-www-form-urlencoded"));
    assert_eq!(http.header("authorization"), Some("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW"));
    let body = OAuthParameters::parse(&http.body).unwrap();
    assert_eq!(body.get("grant_type"), Some("authorization_code"));
    assert_eq!(body.get("code_verifier"), code_verifier.as_ref().map(PKCEVerifier::as_str));
    assert_eq!(body.get("client_id"), None);
    assert_eq!(body.get("client_secret"), None);
}

#[test]
fn the_client_refuses_responses_it_did_not_ask_for() {
    let mut random = random();
    let mut client = secret_client();
    let redirect = |query: &str| URIReference::parse(&format!("https://client.example.com/cb?{query}")).unwrap();
    let state_of = |client: &mut OAuthClient, random: &mut HMACDRBG<SHA256>, now| {
        let url = client.authorize(None, &[], now, random).unwrap();
        OAuthParameters::from_query(&url).unwrap().get("state").unwrap().to_string()
    };
    let issuer = "iss=https%3A%2F%2Fserver.example.com";
    // No state, or a state of no request.
    assert_eq!(client.callback(&redirect(&format!("code=a&{issuer}")), 0).err(), Some(OAuthError::State));
    let state = state_of(&mut client, &mut random, 0);
    assert_eq!(
        client.callback(&redirect(&format!("code=a&state=x{state}&{issuer}")), 0).err(),
        Some(OAuthError::State)
    );
    // RFC 9207 §2.4: another issuer, or none from a server that sends one.
    assert_eq!(
        client.callback(&redirect(&format!("code=a&state={state}&iss=https%3A%2F%2Fevil.example")), 0).err(),
        Some(OAuthError::Issuer)
    );
    let state = state_of(&mut client, &mut random, 0);
    assert_eq!(client.callback(&redirect(&format!("code=a&state={state}")), 0).err(), Some(OAuthError::Issuer));
    // An error response, after the same checks.
    let state = state_of(&mut client, &mut random, 0);
    assert_eq!(
        client.callback(&redirect(&format!("error=access_denied&state={state}&{issuer}")), 0).err(),
        Some(OAuthError::Response(OAuthErrorResponse::new(OAuthErrorCode::AccessDenied)))
    );
    // A request older than its lifetime is forgotten.
    let state = state_of(&mut client, &mut random, 0);
    let late = client.config().pending_lifetime + 1;
    assert_eq!(
        client.callback(&redirect(&format!("code=a&state={state}&{issuer}")), late).err(),
        Some(OAuthError::State)
    );
    // At most `maximum_pending` requests wait; the oldest is forgotten.
    let first = state_of(&mut client, &mut random, 0);
    for _ in 0..client.config().maximum_pending {
        state_of(&mut client, &mut random, 0);
    }
    assert_eq!(client.pending().len(), client.config().maximum_pending);
    assert_eq!(client.callback(&redirect(&format!("code=a&state={first}&{issuer}")), 0).err(), Some(OAuthError::State));
}

#[test]
fn client_authentication_follows_rfc_6749_and_rfc_7523() {
    let mut random = random();
    // §2.3.1: identifier and secret are form-encoded before base64.
    assert_eq!(
        OAuthClientAuthentication::basic_credentials("a b", "c:d").expose(),
        &format!("Basic {}", "YStiOmMlM0Fk")
    );
    let mut parameters = OAuthParameters::new();
    let none = OAuthClientAuthentication::None { client_id: "public".into() };
    assert!(none.apply("https://as", 0, 60, &mut random, &mut parameters).unwrap().is_none());
    assert_eq!(parameters.encode(), "client_id=public");
    let post = OAuthClientAuthentication::SecretPost { client_id: "c".into(), secret: Secret::new("s".into()) };
    assert!(post.apply("https://as", 0, 60, &mut random, &mut parameters).unwrap().is_none());
    assert_eq!(parameters.encode(), "client_id=c&client_secret=s");

    // RFC 7523 §2.2 and §3: a signed assertion for the authorization server.
    let key = PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut random).unwrap();
    let jwk = JWK::from_private_key(&key).unwrap();
    let jwt = OAuthClientAuthentication::PrivateKeyJWT {
        client_id: "c".into(),
        key: Box::new(jwk.clone()),
        algorithm: JWSAlgorithm::ES256,
    };
    let mut parameters = OAuthParameters::new();
    assert!(jwt.apply("https://as.example", 1000, 60, &mut random, &mut parameters).unwrap().is_none());
    assert_eq!(parameters.get("client_assertion_type"), Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
    let assertion = parameters.get("client_assertion").unwrap().to_string();
    let mut validation = JWTValidation::new(1030);
    validation.issuer = Some("c".into());
    validation.subject = Some("c".into());
    validation.audience = Some("https://as.example".into());
    validation.required = vec!["jti".into(), "exp".into()];
    let verified =
        JWT::verify(&assertion, &jwk.to_public().unwrap(), &JWSConfig::new(&[JWSAlgorithm::ES256]), &validation)
            .unwrap();
    assert_eq!(verified.claims.expiration().unwrap(), Some(1060.0));
    // Expired a minute later.
    let late = JWTValidation { now: 1061, ..validation };
    assert!(
        JWT::verify(&assertion, &jwk.to_public().unwrap(), &JWSConfig::new(&[JWSAlgorithm::ES256]), &late).is_err()
    );
    // Each assertion has its own identifier.
    let mut again = OAuthParameters::new();
    jwt.apply("https://as.example", 1000, 60, &mut random, &mut again).unwrap();
    assert_ne!(again.get("client_assertion"), Some(assertion.as_str()));
}
