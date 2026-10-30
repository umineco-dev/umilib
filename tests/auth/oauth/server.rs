//! The authorization server against RFC 6749 (§3.1.2, §4.1, §4.4, §5.2, §6, §10.5), RFC 7636
//! (§4.6), RFC 9700 (§2.1, §4.14.2), RFC 8252 (§7.3), RFC 7662 (§2), RFC 7009 (§2), RFC 9126
//! (§2, §4), RFC 8628 (§3), RFC 9068 (§2) and RFC 7523 (§3), with this crate's client.

use umilib::auth::cert::key::{KeyAlgorithm, NamedCurve, PrivateKey};
use umilib::auth::oauth::{
    OAuthAccessTokenFormat, OAuthAuthorizationFailure, OAuthClient, OAuthClientAuthentication, OAuthClientConfig,
    OAuthClientMethod, OAuthClientRegistration, OAuthDeviceAuthorizationResponse, OAuthEndpointRequest, OAuthError,
    OAuthErrorCode, OAuthGrant, OAuthGrantRecord, OAuthHTTPRequest, OAuthHTTPResponse, OAuthIntrospectionResponse,
    OAuthMetadataKind, OAuthParameters, OAuthPushedAuthorizationResponse, OAuthScope, OAuthServer, OAuthServerConfig,
    OAuthTokenRequest, OAuthTokenResponse,
};
use umilib::codec::uri::URIReference;
use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;
use umilib::protocol::jwt::{JWK, JWKSet, JWSAlgorithm, JWSConfig, JWT, JWTValidation};
use umilib::secret::Secret;

use super::{json_around, random};

const ISSUER: &str = "https://as.example.com";
const REDIRECT: &str = "https://client.example.com/cb";

fn scope(text: &str) -> OAuthScope {
    OAuthScope::parse(text).unwrap()
}

fn server() -> OAuthServer {
    let mut server = OAuthServer::new(OAuthServerConfig::new(ISSUER));
    server
        .register(OAuthClientRegistration::public("app", &[REDIRECT, "http://127.0.0.1:8080/cb"], scope("read write")))
        .expect("a registration");
    let mut confidential = OAuthClientRegistration::confidential(
        "web",
        OAuthClientMethod::SecretBasic,
        "s3cret",
        &[OAuthGrant::AUTHORIZATION_CODE, OAuthGrant::CLIENT_CREDENTIALS, OAuthGrant::REFRESH_TOKEN],
        scope("read write admin"),
    );
    confidential.redirect_uris = vec![REDIRECT.into()];
    server.register(confidential).expect("a registration");
    let mut resource =
        OAuthClientRegistration::confidential("api", OAuthClientMethod::SecretPost, "api-secret", &[], scope("read"));
    resource.introspection = true;
    server.register(resource).expect("a registration");
    server
}

fn client(authentication: OAuthClientAuthentication, server: &OAuthServer) -> OAuthClient {
    OAuthClient::new(OAuthClientConfig::from_metadata(&server.metadata(), authentication, REDIRECT).unwrap())
}

/// The request the server's endpoint receives for the client's request `http`.
fn received(http: &OAuthHTTPRequest) -> OAuthEndpointRequest {
    OAuthEndpointRequest {
        method: http.method.clone(),
        uri: http.uri.clone(),
        authorization: http.header("authorization").map(str::to_string),
        dpop: http.header("dpop").map(str::to_string),
        content_type: http.header("content-type").map(str::to_string),
        body: http.body.clone(),
    }
}

/// A POST of the form `body` with `authorization`.
fn post(body: &str, authorization: Option<&str>) -> OAuthEndpointRequest {
    OAuthEndpointRequest {
        method: "POST".into(),
        uri: format!("{ISSUER}/token"),
        authorization: authorization.map(str::to_string),
        content_type: Some("application/x-www-form-urlencoded".into()),
        body: body.as_bytes().to_vec(),
        ..OAuthEndpointRequest::default()
    }
}

fn error_of(response: &OAuthHTTPResponse) -> OAuthErrorCode {
    match OAuthTokenResponse::decode(response.status, &response.body) {
        Err(OAuthError::Response(error)) => error.code,
        other => panic!("not an error response: {other:?}"),
    }
}

fn grant(client_id: &str, scope_text: &str) -> OAuthGrantRecord {
    OAuthGrantRecord {
        client_id: client_id.into(),
        subject: Some("alice".into()),
        scope: scope(scope_text),
        ..OAuthGrantRecord::default()
    }
}

/// Runs the authorization code grant to its token response.
fn code_flow(
    server: &mut OAuthServer,
    client: &mut OAuthClient,
    random: &mut HMACDRBG<SHA256>,
    now: i64,
) -> OAuthTokenResponse {
    let url = client.authorize(Some(&scope("read")), &[], now, random).unwrap();
    let authorization = server.authorize(&OAuthParameters::from_query(&url).unwrap(), now).unwrap();
    let redirect = server.approve(&authorization, grant(&authorization.client_id, "read"), now, random).unwrap();
    let request = client.callback(&redirect, now).unwrap();
    let http = client.token_request(&request, now, random).unwrap();
    let response = server.token(&received(&http), now, random);
    assert_eq!(response.status, 200, "{}", String::from_utf8_lossy(&response.body));
    assert_eq!(response.header("cache-control"), Some("no-store"));
    OAuthTokenResponse::decode(response.status, &response.body).unwrap()
}

#[test]
fn the_code_grant_runs_from_end_to_end() {
    let mut random = random();
    let mut server = server();
    for authentication in [
        OAuthClientAuthentication::None { client_id: "app".into() },
        OAuthClientAuthentication::SecretBasic { client_id: "web".into(), secret: Secret::new("s3cret".into()) },
    ] {
        let mut client = client(authentication, &server);
        let tokens = code_flow(&mut server, &mut client, &mut random, 1000);
        assert!(tokens.is_token_type("Bearer"));
        assert_eq!(tokens.scope, Some(scope("read")));
        assert!(tokens.refresh_token.is_some());
        let record = server.token_record(&tokens.access_token, 1000).unwrap();
        assert_eq!(record.grant.subject.as_deref(), Some("alice"));
    }
    // The metadata names what the server does (RFC 8414 §2).
    let metadata = server.metadata();
    metadata.check(ISSUER).unwrap();
    assert!(metadata.lists("code_challenge_methods_supported", "S256").unwrap());
    assert!(!metadata.lists("code_challenge_methods_supported", "plain").unwrap());
    assert!(!metadata.lists("response_types_supported", "token").unwrap());
    assert!(!metadata.lists("grant_types_supported", "password").unwrap());
    assert_eq!(metadata.kind, OAuthMetadataKind::Server);
}

#[test]
fn the_authorization_endpoint_checks_the_request() {
    let mut server = server();
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let mut request = |query: &str| {
        let parameters = OAuthParameters::parse(query.as_bytes()).unwrap();
        server.authorize(&parameters, 0)
    };
    let base = format!("response_type=code&client_id=app&code_challenge={challenge}&code_challenge_method=S256");
    // §4.1.2.1: an unknown client, or a redirect URI that is not registered, is not redirected to.
    for query in [
        format!("response_type=code&client_id=nobody&code_challenge={challenge}&code_challenge_method=S256"),
        format!("{base}&redirect_uri=https%3A%2F%2Fevil.example%2Fcb"),
        format!("{base}&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb%2F"),
        format!("{base}&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb%3Fx%3D1"),
        // §3.1.2.3: with two registered URIs, the request must name one.
        base.clone(),
    ] {
        assert!(matches!(request(&query), Err(OAuthAuthorizationFailure::Local(_))), "{query}");
    }
    let named = format!("{base}&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&state=s1");
    let accepted = request(&named).unwrap();
    assert_eq!(accepted.redirect_uri, REDIRECT);
    assert_eq!(accepted.scope, scope("read write"));
    // RFC 8252 §7.3: a loopback redirect URI may use any port; localhost is not loopback.
    assert!(request(&format!("{base}&redirect_uri=http%3A%2F%2F127.0.0.1%3A51004%2Fcb")).is_ok());
    assert!(request(&format!("{base}&redirect_uri=http%3A%2F%2F127.0.0.1%3A51004%2Fother")).is_err());
    assert!(request(&format!("{base}&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcb")).is_err());
    // Errors after the redirect URI is known go back to the client, with state and iss.
    let mut redirected = |query: &str| match request(query) {
        Err(OAuthAuthorizationFailure::Redirect(uri)) => {
            let parameters = OAuthParameters::from_query(&uri).unwrap();
            assert_eq!(parameters.get("state"), Some("s1"));
            assert_eq!(parameters.get("iss"), Some(ISSUER));
            assert!(uri.to_string().starts_with(REDIRECT));
            parameters.get("error").unwrap().to_string()
        }
        other => panic!("not redirected: {other:?}"),
    };
    let redirect = "redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&state=s1";
    // RFC 9700 §2.1.2: no implicit grant.
    assert_eq!(
        redirected(&format!(
            "response_type=token&client_id=app&code_challenge={challenge}&code_challenge_method=S256&{redirect}"
        )),
        "unsupported_response_type"
    );
    // RFC 9700 §2.1.1: PKCE is required.
    assert_eq!(redirected(&format!("response_type=code&client_id=app&{redirect}")), "invalid_request");
    assert_eq!(redirected(&format!("{base}&scope=admin&{redirect}")), "invalid_scope");
    assert_eq!(redirected(&format!("{base}&resource=https%3A%2F%2Fapi%23f&{redirect}")), "invalid_target");
    assert_eq!(redirected(&format!("{base}&resource=api&{redirect}")), "invalid_target");
}

#[test]
fn codes_are_bound_and_used_once() {
    let mut random = random();
    let mut server = server();
    let mut public = client(OAuthClientAuthentication::None { client_id: "app".into() }, &server);
    let url = public.authorize(None, &[], 0, &mut random).unwrap();
    let authorization = server.authorize(&OAuthParameters::from_query(&url).unwrap(), 0).unwrap();
    // The user may grant less than asked, never more.
    assert!(server.approve(&authorization, grant("app", "read write admin"), 0, &mut random).is_err());
    let redirect = server.approve(&authorization, grant("app", "read"), 0, &mut random).unwrap();
    let request = public.callback(&redirect, 0).unwrap();
    let OAuthGrant::AuthorizationCode { code, .. } = &request.grant else { unreachable!() };
    let exchange = |server: &mut OAuthServer, random: &mut HMACDRBG<SHA256>, body: String, now| {
        server.token(&post(&body, None), now, random)
    };
    // RFC 7636 §4.6: the verifier must match.
    let wrong = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&client_id=app&code_verifier={}",
        "a".repeat(43)
    );
    assert_eq!(error_of(&exchange(&mut server, &mut random, wrong, 1)), OAuthErrorCode::InvalidGrant);
    // The failed attempt used the code: the right verifier now fails too (§4.1.2).
    let http = public.token_request(&request, 1, &mut random).unwrap();
    assert_eq!(error_of(&server.token(&received(&http), 1, &mut random)), OAuthErrorCode::InvalidGrant);

    // A second exchange of a code revokes what the first gave (§4.1.2, §10.5).
    let url = public.authorize(None, &[], 0, &mut random).unwrap();
    let authorization = server.authorize(&OAuthParameters::from_query(&url).unwrap(), 0).unwrap();
    let redirect = server.approve(&authorization, grant("app", "read"), 0, &mut random).unwrap();
    let request = public.callback(&redirect, 0).unwrap();
    let http = public.token_request(&request, 1, &mut random).unwrap();
    let response = server.token(&received(&http), 1, &mut random);
    let tokens = OAuthTokenResponse::decode(response.status, &response.body).unwrap();
    assert!(server.token_record(&tokens.access_token, 1).is_some());
    assert_eq!(error_of(&server.token(&received(&http), 2, &mut random)), OAuthErrorCode::InvalidGrant);
    assert!(server.token_record(&tokens.access_token, 2).is_none());

    // §4.1.3: the redirect URI of the request, the client, and the lifetime of the code.
    let fresh = |server: &mut OAuthServer, public: &mut OAuthClient, random: &mut HMACDRBG<SHA256>| {
        let url = public.authorize(None, &[], 0, random).unwrap();
        let authorization = server.authorize(&OAuthParameters::from_query(&url).unwrap(), 0).unwrap();
        let redirect = server.approve(&authorization, grant("app", "read"), 0, random).unwrap();
        public.callback(&redirect, 0).unwrap()
    };
    let mut request = fresh(&mut server, &mut public, &mut random);
    if let OAuthGrant::AuthorizationCode { redirect_uri, .. } = &mut request.grant {
        *redirect_uri = Some("http://127.0.0.1:8080/cb".into());
    }
    let http = public.token_request(&request, 1, &mut random).unwrap();
    assert_eq!(error_of(&server.token(&received(&http), 1, &mut random)), OAuthErrorCode::InvalidGrant);
    let request = fresh(&mut server, &mut public, &mut random);
    let late = server.config().code_lifetime + 1;
    let http = public.token_request(&request, late, &mut random).unwrap();
    assert_eq!(error_of(&server.token(&received(&http), late, &mut random)), OAuthErrorCode::InvalidGrant);
    let request = fresh(&mut server, &mut public, &mut random);
    let web = client(
        OAuthClientAuthentication::SecretBasic { client_id: "web".into(), secret: Secret::new("s3cret".into()) },
        &server,
    );
    let http = web.token_request(&request, 1, &mut random).unwrap();
    assert_eq!(error_of(&server.token(&received(&http), 1, &mut random)), OAuthErrorCode::InvalidGrant);
}

#[test]
fn clients_authenticate_as_they_are_registered() {
    let mut random = random();
    let mut server = server();
    let body = "grant_type=client_credentials";
    let basic = OAuthClientAuthentication::basic_credentials("web", "s3cret");
    let response = server.token(&post(body, Some(basic.expose())), 0, &mut random);
    assert_eq!(response.status, 200);
    let tokens = OAuthTokenResponse::decode(200, &response.body).unwrap();
    // §4.4.3: no refresh token for client credentials.
    assert!(tokens.refresh_token.is_none());
    assert_eq!(tokens.scope, Some(scope("read write admin")));
    // §5.2: a client that fails with the Authorization header gets 401 and WWW-Authenticate.
    let wrong = OAuthClientAuthentication::basic_credentials("web", "wrong");
    let response = server.token(&post(body, Some(wrong.expose())), 0, &mut random);
    assert_eq!((response.status, error_of(&response)), (401, OAuthErrorCode::InvalidClient));
    assert!(response.header("www-authenticate").unwrap().starts_with("Basic"));
    // A client registered for Basic may not post its secret, and the reverse.
    let response =
        server.token(&post("grant_type=client_credentials&client_id=web&client_secret=s3cret", None), 0, &mut random);
    assert_eq!(error_of(&response), OAuthErrorCode::InvalidClient);
    assert!(response.header("www-authenticate").is_none());
    // §2.3: one method per request.
    let response = server.token(
        &post("grant_type=client_credentials&client_id=web&client_secret=s3cret", Some(basic.expose())),
        0,
        &mut random,
    );
    assert_eq!(error_of(&response), OAuthErrorCode::InvalidRequest);
    // §4.4: a public client may not use client credentials.
    let response = server.token(&post("grant_type=client_credentials&client_id=app", None), 0, &mut random);
    assert_eq!(error_of(&response), OAuthErrorCode::UnauthorizedClient);
    // A client that may not use a grant.
    let response = server.token(
        &post("grant_type=client_credentials&client_id=api&client_secret=api-secret", None),
        0,
        &mut random,
    );
    assert_eq!(error_of(&response), OAuthErrorCode::UnauthorizedClient);
    // §3.2: POST of a form, parameters once, a known grant type.
    let mut get = post(body, Some(basic.expose()));
    get.method = "GET".into();
    assert_eq!(error_of(&server.token(&get, 0, &mut random)), OAuthErrorCode::InvalidRequest);
    let mut json = post(body, Some(basic.expose()));
    json.content_type = Some("application/json".into());
    assert_eq!(error_of(&server.token(&json, 0, &mut random)), OAuthErrorCode::InvalidRequest);
    let response = server.token(
        &post("grant_type=client_credentials&scope=read&scope=write", Some(basic.expose())),
        0,
        &mut random,
    );
    assert_eq!(error_of(&response), OAuthErrorCode::InvalidRequest);
    let response =
        server.token(&post("grant_type=password&username=a&password=b", Some(basic.expose())), 0, &mut random);
    assert_eq!(error_of(&response), OAuthErrorCode::UnsupportedGrantType);
    let response =
        server.token(&post("grant_type=client_credentials&scope=other", Some(basic.expose())), 0, &mut random);
    assert_eq!(error_of(&response), OAuthErrorCode::InvalidScope);
}

#[test]
fn private_key_jwt_assertions_are_checked_and_used_once() {
    let mut random = random();
    let mut server = server();
    let key =
        JWK::from_private_key(&PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut random).unwrap()).unwrap();
    let mut registration = OAuthClientRegistration::confidential(
        "signed",
        OAuthClientMethod::PrivateKeyJWT,
        "",
        &[OAuthGrant::CLIENT_CREDENTIALS],
        scope("read"),
    );
    registration.secret_digest = None;
    registration.keys = Some(JWKSet { keys: vec![key.to_public().unwrap()], other: Default::default() });
    server.register(registration).expect("a registration");
    let assertion = |audience: &str, now, random: &mut HMACDRBG<SHA256>| {
        OAuthClientAuthentication::assertion("signed", audience, now, 60, &key, JWSAlgorithm::ES256, random).unwrap()
    };
    let body = |assertion: &str| {
        format!(
            "grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={assertion}"
        )
    };
    let first = assertion(ISSUER, 100, &mut random);
    assert_eq!(server.token(&post(&body(&first), None), 100, &mut random).status, 200);
    // RFC 7523 §3: used once.
    assert_eq!(error_of(&server.token(&post(&body(&first), None), 101, &mut random)), OAuthErrorCode::InvalidClient);
    // The token endpoint is a valid audience as well (RFC 7523 §3); another is not.
    let to_endpoint = assertion(&format!("{ISSUER}/token"), 100, &mut random);
    assert_eq!(server.token(&post(&body(&to_endpoint), None), 100, &mut random).status, 200);
    let elsewhere = assertion("https://other.example", 100, &mut random);
    assert_eq!(
        error_of(&server.token(&post(&body(&elsewhere), None), 100, &mut random)),
        OAuthErrorCode::InvalidClient
    );
    // Expired.
    let old = assertion(ISSUER, 0, &mut random);
    assert_eq!(error_of(&server.token(&post(&body(&old), None), 100, &mut random)), OAuthErrorCode::InvalidClient);
    // Signed by another key.
    let other =
        JWK::from_private_key(&PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut random).unwrap()).unwrap();
    let forged =
        OAuthClientAuthentication::assertion("signed", ISSUER, 100, 60, &other, JWSAlgorithm::ES256, &mut random)
            .unwrap();
    assert_eq!(error_of(&server.token(&post(&body(&forged), None), 100, &mut random)), OAuthErrorCode::InvalidClient);
    // Through the client.
    let signing = OAuthClientAuthentication::PrivateKeyJWT {
        client_id: "signed".into(),
        key: Box::new(key.clone()),
        algorithm: JWSAlgorithm::ES256,
    };
    let signed = client(signing, &server);
    let http = signed.token_request(&OAuthTokenRequest::new(OAuthGrant::ClientCredentials), 200, &mut random).unwrap();
    assert_eq!(server.token(&received(&http), 200, &mut random).status, 200);
}

#[test]
fn refresh_tokens_rotate_and_their_reuse_revokes_the_grant() {
    let mut random = random();
    let mut server = server();
    let mut web = client(
        OAuthClientAuthentication::SecretBasic { client_id: "web".into(), secret: Secret::new("s3cret".into()) },
        &server,
    );
    let tokens = code_flow(&mut server, &mut web, &mut random, 0);
    let first = tokens.refresh_token.clone().unwrap();
    let refresh = |token: &str, scope_text: Option<&str>| {
        let mut request = OAuthTokenRequest::new(OAuthGrant::RefreshToken { refresh_token: token.into() });
        request.scope = scope_text.map(scope);
        request
    };
    let http = web.token_request(&refresh(&first, None), 10, &mut random).unwrap();
    let response = server.token(&received(&http), 10, &mut random);
    let second = OAuthTokenResponse::decode(response.status, &response.body).unwrap();
    let second_refresh = second.refresh_token.clone().unwrap();
    assert_ne!(second_refresh, first);
    // §6: the scope may be narrowed, not widened.
    let http = web.token_request(&refresh(&second_refresh, Some("read write")), 11, &mut random).unwrap();
    assert_eq!(error_of(&server.token(&received(&http), 11, &mut random)), OAuthErrorCode::InvalidScope);
    // RFC 9700 §4.14.2: the replaced token used again revokes every token of the grant.
    let http = web.token_request(&refresh(&first, None), 12, &mut random).unwrap();
    assert_eq!(error_of(&server.token(&received(&http), 12, &mut random)), OAuthErrorCode::InvalidGrant);
    assert!(server.token_record(&second.access_token, 12).is_none());
    assert!(server.token_record(&tokens.access_token, 12).is_none());
    let http = web.token_request(&refresh(&second_refresh, None), 13, &mut random).unwrap();
    assert_eq!(error_of(&server.token(&received(&http), 13, &mut random)), OAuthErrorCode::InvalidGrant);
    // A refresh token of one client is nothing to another.
    let mut public = client(OAuthClientAuthentication::None { client_id: "app".into() }, &server);
    let tokens = code_flow(&mut server, &mut public, &mut random, 20);
    let http = web.token_request(&refresh(&tokens.refresh_token.unwrap(), None), 21, &mut random).unwrap();
    assert_eq!(error_of(&server.token(&received(&http), 21, &mut random)), OAuthErrorCode::InvalidGrant);
}

#[test]
fn introspection_and_revocation_follow_rfc_7662_and_rfc_7009() {
    let mut random = random();
    let mut server = server();
    let mut web = client(
        OAuthClientAuthentication::SecretBasic { client_id: "web".into(), secret: Secret::new("s3cret".into()) },
        &server,
    );
    let tokens = code_flow(&mut server, &mut web, &mut random, 0);
    let introspect = |server: &mut OAuthServer, token: &str, now| {
        let response =
            server.introspect(&post(&format!("token={token}&client_id=api&client_secret=api-secret"), None), now);
        OAuthIntrospectionResponse::decode(response.status, &response.body).unwrap()
    };
    let active = introspect(&mut server, &tokens.access_token, 1);
    assert!(active.active);
    assert_eq!(active.client_id.as_deref(), Some("web"));
    assert_eq!(active.subject.as_deref(), Some("alice"));
    assert_eq!(active.scope, Some(scope("read")));
    assert_eq!(active.issuer.as_deref(), Some(ISSUER));
    assert_eq!(active.token_type.as_deref(), Some("Bearer"));
    // §2.2: unknown or expired tokens are inactive, with nothing else said.
    let response = server.introspect(&post("token=unknown&client_id=api&client_secret=api-secret", None), 1);
    assert_eq!(response.body, br#"{"active":false}"#);
    let late = server.config().access_token_lifetime + 1;
    assert!(!introspect(&mut server, &tokens.access_token, late).active);
    // §2.1: only an authorized protected resource may ask.
    let basic = OAuthClientAuthentication::basic_credentials("web", "s3cret");
    let response = server.introspect(&post(&format!("token={}", tokens.access_token), Some(basic.expose())), 1);
    assert_eq!(error_of(&response), OAuthErrorCode::UnauthorizedClient);

    // RFC 7009: a client revokes its own refresh token, and the access tokens of the grant go
    // with it; the answer is 200 for unknown tokens too.
    let tokens = code_flow(&mut server, &mut web, &mut random, 10);
    let revoke = |server: &mut OAuthServer, body: &str, authorization: Option<&str>| {
        server.revoke(&post(body, authorization), 11)
    };
    let response =
        revoke(&mut server, "token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token", Some(basic.expose()));
    assert_eq!(response.status, 200);
    // RFC 7009 §2.1: another client's revocation is refused, and the token stays.
    let response =
        revoke(&mut server, &format!("token={}&client_id=app", tokens.refresh_token.as_deref().unwrap()), None);
    assert_eq!((response.status, error_of(&response)), (400, OAuthErrorCode::UnauthorizedClient));
    assert!(server.token_record(&tokens.access_token, 11).is_some());
    let response =
        revoke(&mut server, &format!("token={}", tokens.refresh_token.as_deref().unwrap()), Some(basic.expose()));
    assert_eq!(response.status, 200);
    assert!(server.token_record(&tokens.access_token, 11).is_none());
    assert!(!introspect(&mut server, &tokens.access_token, 11).active);

    // The example of RFC 7662 §2.2 reads, and its extension member is kept.
    let body = json_around("auth/oauth/rfc7662.txt", "\"extension_field\": \"twenty-seven\"");
    let example = OAuthIntrospectionResponse::decode(200, body.as_bytes()).unwrap();
    assert!(example.active);
    assert_eq!(example.username.as_deref(), Some("jdoe"));
    assert_eq!(example.audience, ["https://protected.example.net/resource"]);
    assert_eq!(example.expires, Some(1419356238));
    assert_eq!(example.other.get("extension_field").and_then(|value| value.as_str()), Some("twenty-seven"));
    assert_eq!(OAuthIntrospectionResponse::decode(200, example.encode().as_bytes()).unwrap(), example);
    assert!(OAuthIntrospectionResponse::decode(200, br#"{"scope":"a"}"#).is_err());
}

#[test]
fn pushed_authorization_requests_follow_rfc_9126() {
    let mut random = random();
    let mut config = OAuthServerConfig::new(ISSUER);
    config.require_pushed_authorization_requests = true;
    let mut server = OAuthServer::new(config);
    server.register(OAuthClientRegistration::public("app", &[REDIRECT], scope("read"))).expect("a registration");
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let pushed = format!(
        "response_type=code&client_id=app&state=s&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&code_challenge={challenge}&code_challenge_method=S256"
    );
    // §5: a server that requires pushing refuses a request that was not pushed.
    assert!(server.authorize(&OAuthParameters::parse(pushed.as_bytes()).unwrap(), 0).is_err());
    let response = server.push(&post(&pushed, None), 0, &mut random);
    assert_eq!(response.status, 201);
    let answer = OAuthPushedAuthorizationResponse::decode(response.status, &response.body).unwrap();
    assert!(answer.request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
    assert_eq!(answer.expires_in, 60);
    // §4: the authorization request names the client and the request_uri, once.
    let query = |client_id: &str| {
        let mut parameters = OAuthParameters::new();
        parameters.push("client_id", client_id);
        parameters.push("request_uri", &answer.request_uri);
        parameters
    };
    assert!(matches!(server.authorize(&query("other"), 1), Err(OAuthAuthorizationFailure::Local(_))));
    let authorization = server.authorize(&query("app"), 1).unwrap();
    assert_eq!(authorization.state.as_deref(), Some("s"));
    assert!(server.authorize(&query("app"), 1).is_err());
    // §2.1: errors are answered as JSON, and request_uri may not be pushed.
    let response = server.push(&post("response_type=code&client_id=app&scope=admin&code_challenge_method=S256&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", None), 0, &mut random);
    assert_eq!((response.status, error_of(&response)), (400, OAuthErrorCode::InvalidScope));
    let response = server.push(&post("response_type=code&client_id=app&request_uri=urn%3Ax", None), 0, &mut random);
    assert_eq!(error_of(&response), OAuthErrorCode::InvalidRequest);
    // An expired request_uri.
    let response = server.push(&post(&pushed, None), 0, &mut random);
    let answer = OAuthPushedAuthorizationResponse::decode(response.status, &response.body).unwrap();
    let mut parameters = OAuthParameters::new();
    parameters.push("client_id", "app");
    parameters.push("request_uri", &answer.request_uri);
    assert!(server.authorize(&parameters, 61).is_err());
    // The example of §2.2 reads.
    let body = json_around("auth/oauth/rfc9126.txt", "\"request_uri\": \"urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2\"");
    let example = OAuthPushedAuthorizationResponse::decode(201, body.as_bytes()).unwrap();
    assert_eq!((example.request_uri.as_str(), example.expires_in), ("urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2", 90));
}

#[test]
fn device_authorization_follows_rfc_8628() {
    let mut random = random();
    let mut server = server();
    let mut device = OAuthClientRegistration::public("tv", &[], scope("read"));
    device.grant_types = vec![OAuthGrant::DEVICE_CODE.into()];
    server.register(device).expect("a registration");
    let response = server.device_authorize(&post("client_id=tv&scope=read", None), 0, &mut random);
    assert_eq!(response.status, 200, "{}", String::from_utf8_lossy(&response.body));
    let answer = OAuthDeviceAuthorizationResponse::decode(200, &response.body).unwrap();
    // §6.1: eight characters of the consonant set, shown in two groups.
    assert_eq!(answer.user_code.len(), 9);
    assert!(
        answer
            .user_code
            .chars()
            .all(|character| character == '-' || OAuthServer::USER_CODE_CHARACTERS.contains(&(character as u8)))
    );
    assert_eq!(answer.interval, Some(5));
    let complete = URIReference::parse(answer.verification_uri_complete.as_deref().unwrap()).unwrap();
    assert_eq!(OAuthParameters::from_query(&complete).unwrap().get("user_code"), Some(answer.user_code.as_str()));
    let poll = |server: &mut OAuthServer, random: &mut HMACDRBG<SHA256>, now| {
        let body = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code={}&client_id=tv",
            answer.device_code
        );
        server.token(&post(&body, None), now, random)
    };
    // §3.5: pending, too soon, then the interval grows by 5.
    assert_eq!(error_of(&poll(&mut server, &mut random, 10)), OAuthErrorCode::AuthorizationPending);
    assert_eq!(error_of(&poll(&mut server, &mut random, 12)), OAuthErrorCode::SlowDown);
    assert_eq!(error_of(&poll(&mut server, &mut random, 19)), OAuthErrorCode::SlowDown);
    assert_eq!(error_of(&poll(&mut server, &mut random, 40)), OAuthErrorCode::AuthorizationPending);
    // The user enters the code in any case, with or without the dash.
    let entered = answer.user_code.replace('-', "").to_lowercase();
    assert_eq!(server.device(&entered, 31).unwrap().client_id, "tv");
    server.device_approve(&entered, grant("tv", "read"), 31).unwrap();
    let response = poll(&mut server, &mut random, 60);
    assert_eq!(response.status, 200);
    // Used once.
    assert_eq!(error_of(&poll(&mut server, &mut random, 90)), OAuthErrorCode::InvalidGrant);
    // Denied, and expired.
    let response = server.device_authorize(&post("client_id=tv", None), 100, &mut random);
    let denied = OAuthDeviceAuthorizationResponse::decode(200, &response.body).unwrap();
    server.device_deny(&denied.user_code, 101).unwrap();
    let body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code={}&client_id=tv",
        denied.device_code
    );
    assert_eq!(error_of(&server.token(&post(&body, None), 110, &mut random)), OAuthErrorCode::AccessDenied);
    // The example of §3.2 reads.
    let body = json_around("auth/oauth/rfc8628.txt", "\"device_code\": \"GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS\"");
    let example = OAuthDeviceAuthorizationResponse::decode(200, body.as_bytes()).unwrap();
    assert_eq!(example.user_code, "WDJB-MJHT");
    assert_eq!(example.verification_uri_complete.as_deref(), Some("https://example.com/device?user_code=WDJB-MJHT"));
    assert_eq!(OAuthDeviceAuthorizationResponse::decode(200, example.encode().as_bytes()).unwrap(), example);
}

#[test]
fn jwt_access_tokens_follow_rfc_9068() {
    let mut random = random();
    let key =
        JWK::from_private_key(&PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut random).unwrap()).unwrap();
    let mut config = OAuthServerConfig::new(ISSUER);
    config.access_token_format = OAuthAccessTokenFormat::JWT {
        key: Box::new(key.clone()),
        algorithm: JWSAlgorithm::ES256,
        default_audience: "https://api.example.com".into(),
    };
    let mut server = OAuthServer::new(config);
    server
        .register(OAuthClientRegistration::confidential(
            "web",
            OAuthClientMethod::SecretBasic,
            "s3cret",
            &[OAuthGrant::CLIENT_CREDENTIALS],
            scope("read"),
        ))
        .expect("a registration");
    let basic = OAuthClientAuthentication::basic_credentials("web", "s3cret");
    let response = server.token(
        &post("grant_type=client_credentials&resource=https%3A%2F%2Fcal.example.com%2F", Some(basic.expose())),
        1000,
        &mut random,
    );
    let tokens = OAuthTokenResponse::decode(response.status, &response.body).unwrap();
    let public = server.jwks().unwrap().keys[0].clone();
    let mut validation = JWTValidation::new(1001);
    validation.issuer = Some(ISSUER.into());
    validation.audience = Some("https://cal.example.com/".into());
    validation.token_type = Some("at+jwt".into());
    validation.required =
        ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"].iter().map(|name| name.to_string()).collect();
    let jwt = JWT::verify(&tokens.access_token, &public, &JWSConfig::new(&[JWSAlgorithm::ES256]), &validation).unwrap();
    // §2.2: without a resource owner, sub names the client.
    assert_eq!(jwt.claims.subject().unwrap(), Some("web"));
    assert_eq!(jwt.claims.string("client_id").unwrap(), Some("web"));
    assert_eq!(jwt.claims.string("scope").unwrap(), Some("read"));
    assert_eq!(jwt.claims.expiration().unwrap(), Some(1000.0 + server.config().access_token_lifetime as f64));
    // Without a resource, the default audience.
    let response = server.token(&post("grant_type=client_credentials", Some(basic.expose())), 1000, &mut random);
    let tokens = OAuthTokenResponse::decode(response.status, &response.body).unwrap();
    validation.audience = Some("https://api.example.com".into());
    assert!(JWT::verify(&tokens.access_token, &public, &JWSConfig::new(&[JWSAlgorithm::ES256]), &validation).is_ok());
}

#[test]
fn tables_are_bounded() {
    let mut random = random();
    let mut config = OAuthServerConfig::new(ISSUER);
    config.maximum_tokens = 4;
    let mut server = OAuthServer::new(config);
    server
        .register(OAuthClientRegistration::confidential(
            "web",
            OAuthClientMethod::SecretBasic,
            "s3cret",
            &[OAuthGrant::CLIENT_CREDENTIALS],
            scope("read"),
        ))
        .expect("a registration");
    let basic = OAuthClientAuthentication::basic_credentials("web", "s3cret");
    let mut statuses = Vec::new();
    for _ in 0..5 {
        statuses
            .push(server.token(&post("grant_type=client_credentials", Some(basic.expose())), 0, &mut random).status);
    }
    // One slot per token: client credentials issue no refresh token.
    assert_eq!(statuses, [200, 200, 200, 200, 503]);
    // Expired tokens make room.
    let later = server.config().access_token_lifetime + 1;
    assert_eq!(
        server.token(&post("grant_type=client_credentials", Some(basic.expose())), later, &mut random).status,
        200
    );
}

/// A server of the clients of `server()` with `change` made to its configuration.
fn server_with(change: impl FnOnce(&mut OAuthServerConfig)) -> OAuthServer {
    let mut config = OAuthServerConfig::new(ISSUER);
    change(&mut config);
    let mut server = OAuthServer::new(config);
    let reference = self::server();
    for client_id in ["app", "web", "api"] {
        server.register(reference.client(client_id).unwrap().clone()).expect("a registration");
    }
    server
}

#[test]
fn one_client_cannot_fill_a_table_for_the_others() {
    let mut random = random();
    let mut server = server_with(|config| {
        config.maximum_tokens = 8;
        config.maximum_tokens_per_client = 2;
    });
    let basic = OAuthClientAuthentication::basic_credentials("web", "s3cret");
    let statuses: Vec<u16> = (0..3)
        .map(|_| server.token(&post("grant_type=client_credentials", Some(basic.expose())), 0, &mut random).status)
        .collect();
    assert_eq!(statuses, [200, 200, 503]);
    // Another client still gets its tokens.
    let mut public = client(OAuthClientAuthentication::None { client_id: "app".into() }, &server);
    assert!(code_flow(&mut server, &mut public, &mut random, 0).refresh_token.is_some());
}

#[test]
fn a_refused_refresh_keeps_the_grant() {
    let mut random = random();
    let mut server = server_with(|config| config.maximum_tokens_per_client = 4);
    let mut public = client(OAuthClientAuthentication::None { client_id: "app".into() }, &server);
    let tokens = code_flow(&mut server, &mut public, &mut random, 0);
    let refresh = |token: &str| format!("grant_type=refresh_token&client_id=app&refresh_token={token}");
    // Two more tokens of the client fill its share: the refresh is refused with 503.
    let second = code_flow(&mut server, &mut public, &mut random, 0);
    let response = server.token(&post(&refresh(tokens.refresh_token.as_deref().unwrap()), None), 1, &mut random);
    assert_eq!((response.status, error_of(&response)), (503, OAuthErrorCode::TemporarilyUnavailable));
    // Once room is made, the same refresh token still works: it was not taken as stolen.
    let revoked = server.revoke(&post(&format!("token={}&client_id=app", second.refresh_token.unwrap()), None), 2);
    assert_eq!(revoked.status, 200);
    let response = server.token(&post(&refresh(tokens.refresh_token.as_deref().unwrap()), None), 3, &mut random);
    assert_eq!(response.status, 200, "{}", String::from_utf8_lossy(&response.body));
}

#[test]
fn only_the_last_replaced_refresh_token_is_kept() {
    let mut random = random();
    let mut server = server();
    let mut public = client(OAuthClientAuthentication::None { client_id: "app".into() }, &server);
    let first = code_flow(&mut server, &mut public, &mut random, 0).refresh_token.unwrap();
    let refresh = |server: &mut OAuthServer, random: &mut HMACDRBG<SHA256>, token: &str, now| {
        let response = server.token(
            &post(&format!("grant_type=refresh_token&client_id=app&refresh_token={token}"), None),
            now,
            random,
        );
        OAuthTokenResponse::decode(response.status, &response.body)
    };
    let second = refresh(&mut server, &mut random, &first, 1).unwrap().refresh_token.unwrap();
    let third = refresh(&mut server, &mut random, &second, 2).unwrap().refresh_token.unwrap();
    // The first is forgotten: refused, without revoking the grant.
    assert!(
        matches!(refresh(&mut server, &mut random, &first, 3), Err(OAuthError::Response(error)) if error.code == OAuthErrorCode::InvalidGrant)
    );
    let fourth = refresh(&mut server, &mut random, &third, 4).unwrap().refresh_token.unwrap();
    // The last replaced one, used again, revokes the grant (RFC 9700 §4.14.2).
    assert!(refresh(&mut server, &mut random, &third, 5).is_err());
    assert!(refresh(&mut server, &mut random, &fourth, 6).is_err());
}

#[test]
fn an_empty_scope_is_left_out() {
    let mut random = random();
    let mut server = server();
    server
        .register(OAuthClientRegistration::confidential(
            "none",
            OAuthClientMethod::SecretBasic,
            "s",
            &[OAuthGrant::CLIENT_CREDENTIALS],
            OAuthScope::default(),
        ))
        .unwrap();
    let basic = OAuthClientAuthentication::basic_credentials("none", "s");
    let response = server.token(&post("grant_type=client_credentials", Some(basic.expose())), 0, &mut random);
    assert!(!String::from_utf8_lossy(&response.body).contains("scope"));
    let tokens = OAuthTokenResponse::decode(response.status, &response.body).unwrap();
    assert_eq!(tokens.scope, None);
    let answer = server.introspection(&tokens.access_token, 0);
    assert!(answer.active && answer.scope.is_none());
    assert!(OAuthIntrospectionResponse::decode(200, answer.encode().as_bytes()).is_ok());
}

#[test]
fn the_authorization_endpoint_redirects_errors_of_syntax() {
    let mut server = server();
    let redirect = "redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&state=s1";
    // RFC 6749 §4.1.2.1: the client and its redirect URI are known, so the error goes back.
    for query in [
        format!(
            "response_type=code&client_id=app&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=plain&{redirect}"
        ),
        format!("response_type=code&client_id=app&scope=a%20%20b&{redirect}"),
    ] {
        match server.authorize(&OAuthParameters::parse(query.as_bytes()).unwrap(), 0) {
            Err(OAuthAuthorizationFailure::Redirect(uri)) => {
                let parameters = OAuthParameters::from_query(&uri).unwrap();
                assert_eq!(
                    (parameters.get("error"), parameters.get("state")),
                    (Some("invalid_request"), Some("s1")),
                    "{query}"
                );
            }
            other => panic!("not redirected: {other:?}"),
        }
    }
    let many: String = (0..300).map(|index| format!("x{index}=1&")).collect();
    assert!(matches!(
        server.authorize(&OAuthParameters::parse(many.as_bytes()).unwrap(), 0),
        Err(OAuthAuthorizationFailure::Local(_))
    ));
    let response = server.token(&post(&many, None), 0, &mut random());
    assert_eq!(error_of(&response), OAuthErrorCode::InvalidRequest);
}

#[test]
fn a_decision_is_checked_against_the_registration() {
    let mut random = random();
    let mut server = server();
    let mut public = client(OAuthClientAuthentication::None { client_id: "app".into() }, &server);
    let url = public.authorize(None, &[], 0, &mut random).unwrap();
    let authorization = server.authorize(&OAuthParameters::from_query(&url).unwrap(), 0).unwrap();
    // An authorization carried through the consent page and changed there.
    let mut moved = authorization.clone();
    moved.redirect_uri = "https://evil.example/cb".into();
    assert!(server.approve(&moved, grant("app", "read"), 0, &mut random).is_err());
    assert!(server.deny(&moved).is_err());
    let mut unprotected = authorization.clone();
    unprotected.challenge = None;
    assert!(server.approve(&unprotected, grant("app", "read"), 0, &mut random).is_err());
    assert!(server.approve(&authorization, grant("app", "read"), 0, &mut random).is_ok());
    // RFC 6749 §3.1.2: registered redirect URIs are absolute and have no fragment.
    for uri in ["/cb", "https://app.example/cb#f"] {
        assert!(server.register(OAuthClientRegistration::public("other", &[uri], scope("read"))).is_err(), "{uri}");
    }
    assert!(server.metadata().lists("response_modes_supported", "query").unwrap());
    assert!(!server.metadata().lists("response_modes_supported", "fragment").unwrap());
}

#[test]
fn pushed_requests_bind_the_code_to_a_dpop_key() {
    use umilib::auth::oauth::{DPoPProof, DPoPTarget};
    let mut random = random();
    let mut server = server();
    let key =
        JWK::from_private_key(&PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut random).unwrap()).unwrap();
    let thumbprint = DPoPProof::thumbprint(&key.to_public().unwrap()).unwrap();
    let verifier = umilib::auth::oauth::PKCEVerifier::generate(&mut random).unwrap();
    let challenge = verifier.challenge(umilib::auth::oauth::PKCEMethod::S256).value;
    let body = format!(
        "response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&code_challenge={challenge}&code_challenge_method=S256"
    );
    let par = format!("{ISSUER}/par");
    let proof = |random: &mut HMACDRBG<SHA256>, uri: &str| {
        DPoPProof::create(
            &key,
            JWSAlgorithm::ES256,
            &DPoPTarget { method: "POST", uri, access_token: None },
            0,
            None,
            random,
        )
        .unwrap()
    };
    // RFC 9449 §10.1: a dpop_jkt that differs from the proof's key is refused.
    let mut request = post(&format!("{body}&dpop_jkt=AAAA"), None);
    request.dpop = Some(proof(&mut random, &par));
    assert_eq!(error_of(&server.push(&request, 0, &mut random)), OAuthErrorCode::InvalidDPoPProof);
    let mut request = post(&body, None);
    request.dpop = Some(proof(&mut random, &par));
    let response = server.push(&request, 0, &mut random);
    assert_eq!(response.status, 201, "{}", String::from_utf8_lossy(&response.body));
    let request_uri =
        umilib::auth::oauth::OAuthPushedAuthorizationResponse::decode(201, &response.body).unwrap().request_uri;
    let mut parameters = OAuthParameters::new();
    parameters.push("client_id", "app");
    parameters.push("request_uri", &request_uri);
    let authorization = server.authorize(&parameters, 1).unwrap();
    assert_eq!(authorization.dpop_jkt.as_deref(), Some(thumbprint.as_str()));
    let redirect = server.approve(&authorization, grant("app", "read"), 1, &mut random).unwrap();
    let code = OAuthParameters::from_query(&redirect).unwrap().get("code").unwrap().to_string();
    let exchange = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&client_id=app&code_verifier={}",
        verifier.as_str()
    );
    // Without a proof of the key, the code is refused.
    assert_eq!(error_of(&server.token(&post(&exchange, None), 2, &mut random)), OAuthErrorCode::InvalidGrant);
}

#[test]
fn assertions_take_the_par_endpoint_and_a_full_table_answers_503() {
    let mut random = random();
    let mut server = server_with(|config| config.maximum_assertions_per_client = 1);
    let key =
        JWK::from_private_key(&PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut random).unwrap()).unwrap();
    let mut registration = OAuthClientRegistration::confidential(
        "signed",
        OAuthClientMethod::PrivateKeyJWT,
        "",
        &[OAuthGrant::CLIENT_CREDENTIALS],
        scope("read"),
    );
    registration.secret_digest = None;
    registration.keys = Some(JWKSet { keys: vec![key.to_public().unwrap()], other: Default::default() });
    server.register(registration).unwrap();
    let body = |assertion: &str| {
        format!(
            "grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={assertion}"
        )
    };
    // RFC 9126 §2: the PAR endpoint is an audience of this server.
    let assertion = OAuthClientAuthentication::assertion(
        "signed",
        &format!("{ISSUER}/par"),
        0,
        60,
        &key,
        JWSAlgorithm::ES256,
        &mut random,
    )
    .unwrap();
    assert_eq!(server.token(&post(&body(&assertion), None), 0, &mut random).status, 200);
    let assertion =
        OAuthClientAuthentication::assertion("signed", ISSUER, 0, 60, &key, JWSAlgorithm::ES256, &mut random).unwrap();
    let response = server.token(&post(&body(&assertion), None), 0, &mut random);
    assert_eq!((response.status, error_of(&response)), (503, OAuthErrorCode::TemporarilyUnavailable));
}

#[test]
fn an_expired_device_code_is_answered_expired_token() {
    let mut random = random();
    let mut server = server();
    let mut device = OAuthClientRegistration::public("tv", &[], scope("read"));
    device.grant_types = vec![OAuthGrant::DEVICE_CODE.into()];
    server.register(device).unwrap();
    let response = server.device_authorize(&post("client_id=tv", None), 0, &mut random);
    let answer = OAuthDeviceAuthorizationResponse::decode(200, &response.body).unwrap();
    let late = server.config().device_code_lifetime + 1;
    let body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code={}&client_id=tv",
        answer.device_code
    );
    assert_eq!(error_of(&server.token(&post(&body, None), late, &mut random)), OAuthErrorCode::ExpiredToken);
    // RFC 7662 §2.2: a refresh token has no access token type.
    let mut web = client(
        OAuthClientAuthentication::SecretBasic { client_id: "web".into(), secret: Secret::new("s3cret".into()) },
        &server,
    );
    let tokens = code_flow(&mut server, &mut web, &mut random, 0);
    let answer = server.introspection(tokens.refresh_token.as_deref().unwrap(), 0);
    assert!(answer.active && answer.token_type.is_none());
}
