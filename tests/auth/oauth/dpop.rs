//! DPoP against RFC 9449 (§4 to §10 and the proofs of its figures), and the protected
//! resource against RFC 6750 (§2.1, §3), RFC 9068 (§4), RFC 9470 (§3) and RFC 9728 (§5.1).

use umilib::auth::cert::key::{KeyAlgorithm, NamedCurve, PrivateKey};
use umilib::auth::oauth::{
    DPoPConfig, DPoPProof, DPoPTarget, DPoPVerifier, OAuthAccessTokenFormat, OAuthChallenge, OAuthClientAuthentication,
    OAuthClientMethod, OAuthClientRegistration, OAuthEndpointRequest, OAuthErrorCode, OAuthGrant, OAuthMetadata,
    OAuthPresentedToken, OAuthResourceConfig, OAuthResourceServer, OAuthScope, OAuthServer, OAuthServerConfig,
    OAuthTokenResponse, OAuthTokenScheme, OAuthTokenValidation,
};
use umilib::codec::json::JSONValue;
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::random::Random;
use umilib::hash::sha::v2::SHA256;
use umilib::protocol::jwt::{JOSEHeader, JWK, JWSAlgorithm, JWT, JWTClaims};

use super::random;
use crate::{RFC, Vectors};

const RFC9449: &str = "auth/oauth/rfc9449.txt";

/// The `n`th line of the RFC at `path` that starts with `prefix`, with the lines it is wrapped
/// over with `\` (RFC 8792), joined.
fn wrapped(path: &str, prefix: &str, n: usize) -> String {
    let text = Vectors::read(path);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().enumerate().filter(|(_, line)| line.trim_start().starts_with(prefix)).nth(n).unwrap().0;
    let mut out = String::new();
    for line in &lines[start..] {
        let line = line.trim();
        match line.strip_suffix('\\') {
            Some(part) => out.push_str(part),
            None => {
                out.push_str(line);
                break;
            }
        }
    }
    out
}

/// The value of the header field `name` on the `n`th line that starts with `prefix`.
fn field(path: &str, prefix: &str, n: usize, name: &str) -> String {
    wrapped(path, prefix, n).strip_prefix(name).unwrap().trim_start_matches(':').trim().to_string()
}

fn key(random: &mut HMACDRBG<SHA256>) -> JWK {
    JWK::from_private_key(&PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), random).unwrap()).unwrap()
}

#[test]
fn reads_the_proofs_of_rfc_9449() {
    let algorithms = DPoPConfig::default().algorithms;
    // Figure 2: a proof for the token endpoint.
    let proof = field(RFC9449, "DPoP: eyJ", 0, "DPoP");
    let target = DPoPTarget { method: "POST", uri: "https://server.example.com/token", access_token: None };
    let checked = DPoPProof::verify(&proof, &algorithms, &target, 1562262616, 60, 60).unwrap();
    // §6.1: the thumbprint of its key is the jkt of Figure 8.
    assert_eq!(checked.thumbprint, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    assert_eq!(checked.identifier(), Some("-BwC3ESc6acc2lTc"));
    // §4.3: the method, the target, the age and the type are checked.
    let wrong_method = DPoPTarget { method: "GET", ..target };
    assert!(DPoPProof::verify(&proof, &algorithms, &wrong_method, 1562262616, 60, 60).is_err());
    let wrong_uri = DPoPTarget { uri: "https://server.example.com/other", ..target };
    assert!(DPoPProof::verify(&proof, &algorithms, &wrong_uri, 1562262616, 60, 60).is_err());
    assert!(DPoPProof::verify(&proof, &algorithms, &target, 1562262616 + 61, 60, 60).is_err());
    assert!(DPoPProof::verify(&proof, &algorithms, &target, 1562262616 - 61, 60, 60).is_err());
    assert!(DPoPProof::verify(&proof, &[JWSAlgorithm::PS256], &target, 1562262616, 60, 60).is_err());
    // The query and fragment of the target are left out, and its syntax normalized.
    for uri in [
        "https://server.example.com/token?a=b",
        "HTTPS://Server.Example.COM:443/token#f",
        "https://server.example.com/%74oken",
    ] {
        let target = DPoPTarget { uri, ..target };
        assert!(DPoPProof::verify(&proof, &algorithms, &target, 1562262616, 60, 60).is_ok(), "{uri}");
    }
    // A proof that presents no token has no ath; a token needs one.
    let with_token = DPoPTarget { access_token: Some("x"), ..target };
    assert!(DPoPProof::verify(&proof, &algorithms, &with_token, 1562262616, 60, 60).is_err());

    // Figure 13: a proof for a protected resource, with the hash of the access token.
    let access_token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
    assert_eq!(DPoPProof::access_token_hash(access_token), "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
    let proof = field(RFC9449, "DPoP: eyJ", 3, "DPoP");
    let target = DPoPTarget {
        method: "GET",
        uri: "https://resource.example.org/protectedresource",
        access_token: Some(access_token),
    };
    let checked = DPoPProof::verify(&proof, &algorithms, &target, 1562262618, 60, 60).unwrap();
    assert_eq!(checked.thumbprint, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    let other_token = DPoPTarget { access_token: Some("other"), ..target };
    assert!(DPoPProof::verify(&proof, &algorithms, &other_token, 1562262618, 60, 60).is_err());
    assert!(
        DPoPProof::verify(&proof, &algorithms, &DPoPTarget { access_token: None, ..target }, 1562262618, 60, 60)
            .is_err()
    );
}

#[test]
fn proofs_are_used_once_and_carry_the_nonce() {
    let mut random = random();
    let key = key(&mut random);
    let target = DPoPTarget { method: "POST", uri: "https://as.example/token", access_token: None };
    let mut verifier = DPoPVerifier::new(DPoPConfig::default());
    let proof = DPoPProof::create(&key, JWSAlgorithm::ES256, &target, 100, None, &mut random).unwrap();
    assert!(verifier.check(&proof, &target, 100).is_ok());
    // §11.1: the same proof again is a replay.
    assert_eq!(verifier.check(&proof, &target, 101).unwrap_err().code, OAuthErrorCode::InvalidDPoPProof);
    // §4.3: a proof whose header holds a private key, or that a MAC signs, is refused.
    let sign = |header_key: &JWK, signing: &JWK, algorithm: JWSAlgorithm, random: &mut HMACDRBG<SHA256>| {
        let mut header = JOSEHeader::new();
        header.set_string("typ", "dpop+jwt");
        header.set_string("alg", algorithm.name());
        header.set("jwk", JSONValue::Object(header_key.to_object()));
        let mut claims = JWTClaims::new();
        claims.set_string("jti", &format!("{:?}", random.next_u64().unwrap()));
        claims.set_string("htm", "POST");
        claims.set_string("htu", "https://as.example/token");
        claims.set_numeric_date("iat", 100);
        JWT::sign(&claims, &header, signing, random).unwrap()
    };
    let public = key.to_public().unwrap();
    assert!(verifier.check(&sign(&public, &key, JWSAlgorithm::ES256, &mut random), &target, 100).is_ok());
    assert!(verifier.check(&sign(&key, &key, JWSAlgorithm::ES256, &mut random), &target, 100).is_err());
    let symmetric = JWK::symmetric(&[7; 32]);
    assert!(verifier.check(&sign(&symmetric, &symmetric, JWSAlgorithm::HS256, &mut random), &target, 100).is_err());
    // Another type.
    let mut header = JOSEHeader::new();
    header.set_string("typ", "JWT");
    header.set_string("alg", "ES256");
    header.set("jwk", JSONValue::Object(public.to_object()));
    let mut claims = JWTClaims::new();
    claims.set_string("jti", "typ");
    claims.set_string("htm", "POST");
    claims.set_string("htu", "https://as.example/token");
    claims.set_numeric_date("iat", 100);
    assert!(verifier.check(&JWT::sign(&claims, &header, &key, &mut random).unwrap(), &target, 100).is_err());

    // §8: a server that requires a nonce answers use_dpop_nonce, then takes the current and the
    // previous nonce.
    let mut verifier = DPoPVerifier::new(DPoPConfig { require_nonce: true, ..DPoPConfig::default() });
    let first = verifier.rotate_nonce(&mut random).unwrap().to_string();
    let proof = DPoPProof::create(&key, JWSAlgorithm::ES256, &target, 100, None, &mut random).unwrap();
    assert_eq!(verifier.check(&proof, &target, 100).unwrap_err().code, OAuthErrorCode::UseDPoPNonce);
    let proof = DPoPProof::create(&key, JWSAlgorithm::ES256, &target, 100, Some(&first), &mut random).unwrap();
    assert!(verifier.check(&proof, &target, 100).is_ok());
    let second = verifier.rotate_nonce(&mut random).unwrap().to_string();
    assert_ne!(first, second);
    let proof = DPoPProof::create(&key, JWSAlgorithm::ES256, &target, 100, Some(&first), &mut random).unwrap();
    assert!(verifier.check(&proof, &target, 100).is_ok());
    verifier.rotate_nonce(&mut random).unwrap();
    let proof = DPoPProof::create(&key, JWSAlgorithm::ES256, &target, 100, Some(&first), &mut random).unwrap();
    assert_eq!(verifier.check(&proof, &target, 100).unwrap_err().code, OAuthErrorCode::UseDPoPNonce);
}

/// A server with a public client "app" and a confidential client "web", issuing JWT access
/// tokens for `https://api.example`.
fn server(random: &mut HMACDRBG<SHA256>) -> (OAuthServer, JWK) {
    let signing = key(random);
    let mut config = OAuthServerConfig::new("https://as.example");
    config.access_token_format = OAuthAccessTokenFormat::JWT {
        key: Box::new(signing.clone()),
        algorithm: JWSAlgorithm::ES256,
        default_audience: "https://api.example".into(),
    };
    let mut server = OAuthServer::new(config);
    let mut public =
        OAuthClientRegistration::public("app", &["https://app.example/cb"], OAuthScope::parse("read write").unwrap());
    public.grant_types.push(OAuthGrant::DEVICE_CODE.into());
    server.register(public).expect("a registration");
    server
        .register(OAuthClientRegistration::confidential(
            "web",
            OAuthClientMethod::SecretBasic,
            "s3cret",
            &[OAuthGrant::CLIENT_CREDENTIALS],
            OAuthScope::parse("read").unwrap(),
        ))
        .expect("a registration");
    (server, signing)
}

fn post(body: &str, authorization: Option<&str>, dpop: Option<String>) -> OAuthEndpointRequest {
    OAuthEndpointRequest {
        method: "POST".into(),
        uri: "https://as.example/token".into(),
        authorization: authorization.map(str::to_string),
        dpop,
        content_type: Some("application/x-www-form-urlencoded".into()),
        body: body.as_bytes().to_vec(),
    }
}

#[test]
fn the_token_endpoint_binds_tokens_to_the_proof_key() {
    let mut random = random();
    let (mut server, _) = server(&mut random);
    let client_key = key(&mut random);
    let token_target = DPoPTarget { method: "POST", uri: "https://as.example/token", access_token: None };
    let basic = OAuthClientAuthentication::basic_credentials("web", "s3cret");
    let proof = DPoPProof::create(&client_key, JWSAlgorithm::ES256, &token_target, 0, None, &mut random).unwrap();
    let response =
        server.token(&post("grant_type=client_credentials", Some(basic.expose()), Some(proof)), 0, &mut random);
    let tokens = OAuthTokenResponse::decode(response.status, &response.body).unwrap();
    // §5: token_type DPoP, and cnf.jkt in the token (§6.1).
    assert!(tokens.is_token_type("DPoP"));
    let record = server.token_record(&tokens.access_token, 0).unwrap();
    assert_eq!(record.grant.confirmation, Some(DPoPProof::thumbprint(&client_key.to_public().unwrap()).unwrap()));
    // A bad proof is invalid_dpop_proof (§5).
    let response = server.token(
        &post("grant_type=client_credentials", Some(basic.expose()), Some("x.y.z".into())),
        0,
        &mut random,
    );
    assert_eq!(response.status, 400);
    assert!(String::from_utf8_lossy(&response.body).contains("invalid_dpop_proof"));
    // §8: a server that requires a nonce sends it with use_dpop_nonce.
    let nonce = server.dpop().rotate_nonce(&mut random).unwrap().to_string();
    let mut config = server.config().clone();
    config.dpop.require_nonce = true;
    let mut strict = OAuthServer::new(config);
    strict.register(server.client("web").unwrap().clone()).expect("a registration");
    let strict_nonce = strict.dpop().rotate_nonce(&mut random).unwrap().to_string();
    assert_ne!(nonce, strict_nonce);
    let proof = DPoPProof::create(&client_key, JWSAlgorithm::ES256, &token_target, 0, None, &mut random).unwrap();
    let response =
        strict.token(&post("grant_type=client_credentials", Some(basic.expose()), Some(proof)), 0, &mut random);
    assert_eq!(response.header("dpop-nonce"), Some(strict_nonce.as_str()));
    assert!(String::from_utf8_lossy(&response.body).contains("use_dpop_nonce"));
    let proof = DPoPProof::create(&client_key, JWSAlgorithm::ES256, &token_target, 0, Some(&strict_nonce), &mut random)
        .unwrap();
    assert_eq!(
        strict.token(&post("grant_type=client_credentials", Some(basic.expose()), Some(proof)), 0, &mut random).status,
        200
    );
}

#[test]
fn codes_and_public_refresh_tokens_stay_with_their_key() {
    let mut random = random();
    let (mut server, _) = server(&mut random);
    let client_key = key(&mut random);
    let thumbprint = DPoPProof::thumbprint(&client_key.to_public().unwrap()).unwrap();
    let token_target = DPoPTarget { method: "POST", uri: "https://as.example/token", access_token: None };
    let verifier = umilib::auth::oauth::PKCEVerifier::generate(&mut random).unwrap();
    let challenge = verifier.challenge(umilib::auth::oauth::PKCEMethod::S256);
    let mut parameters = umilib::auth::oauth::OAuthParameters::new();
    for (name, value) in [
        ("response_type", "code"),
        ("client_id", "app"),
        ("code_challenge", challenge.value.as_str()),
        ("code_challenge_method", "S256"),
        ("dpop_jkt", thumbprint.as_str()),
    ] {
        parameters.push(name, value);
    }
    let exchange = |server: &mut OAuthServer,
                    random: &mut HMACDRBG<SHA256>,
                    key: &JWK,
                    parameters: &umilib::auth::oauth::OAuthParameters| {
        let authorization = server.authorize(parameters, 0).unwrap();
        let grant = umilib::auth::oauth::OAuthGrantRecord {
            client_id: "app".into(),
            subject: Some("alice".into()),
            scope: authorization.scope.clone(),
            ..Default::default()
        };
        let redirect = server.approve(&authorization, grant, 0, random).unwrap();
        let query = umilib::auth::oauth::OAuthParameters::from_query(&redirect).unwrap();
        let body = format!(
            "grant_type=authorization_code&code={}&client_id=app&code_verifier={}",
            query.get("code").unwrap(),
            verifier.as_str()
        );
        let proof = DPoPProof::create(key, JWSAlgorithm::ES256, &token_target, 0, None, random).unwrap();
        server.token(&post(&body, None, Some(proof)), 0, random)
    };
    // §10: the code of a request with dpop_jkt is exchanged only with a proof of that key.
    let other_key = key(&mut random);
    let response = exchange(&mut server, &mut random, &other_key, &parameters);
    assert!(String::from_utf8_lossy(&response.body).contains("invalid_grant"));
    let response = exchange(&mut server, &mut random, &client_key, &parameters);
    let tokens = OAuthTokenResponse::decode(response.status, &response.body).unwrap();
    assert!(tokens.is_token_type("DPoP"));
    // §5: the refresh token of a public client is bound to the key too.
    let refresh = format!("grant_type=refresh_token&refresh_token={}&client_id=app", tokens.refresh_token.unwrap());
    let response = server.token(&post(&refresh, None, None), 1, &mut random);
    assert!(String::from_utf8_lossy(&response.body).contains("invalid_grant"));
    let proof = DPoPProof::create(&other_key, JWSAlgorithm::ES256, &token_target, 1, None, &mut random).unwrap();
    let response = server.token(&post(&refresh, None, Some(proof)), 1, &mut random);
    assert!(String::from_utf8_lossy(&response.body).contains("invalid_grant"));
    let proof = DPoPProof::create(&client_key, JWSAlgorithm::ES256, &token_target, 1, None, &mut random).unwrap();
    assert_eq!(server.token(&post(&refresh, None, Some(proof)), 1, &mut random).status, 200);
}

/// A resource server that takes the JWT access tokens of `server`.
fn resource(server: &OAuthServer, require_dpop: bool) -> OAuthResourceServer {
    OAuthResourceServer::new(OAuthResourceConfig {
        resource: "https://api.example".into(),
        realm: Some("example".into()),
        resource_metadata: Some("https://api.example/.well-known/oauth-protected-resource".into()),
        validation: OAuthTokenValidation::JWT {
            issuer: "https://as.example".into(),
            keys: server.jwks().unwrap(),
            algorithms: vec![JWSAlgorithm::ES256],
        },
        require_dpop,
        dpop: DPoPConfig::default(),
        leeway: 0,
    })
    .expect("a resource server")
}

fn get(authorization: Option<String>, dpop: Option<String>) -> OAuthEndpointRequest {
    OAuthEndpointRequest {
        method: "GET".into(),
        uri: "https://api.example/items".into(),
        authorization,
        dpop,
        ..Default::default()
    }
}

#[test]
fn the_resource_server_takes_bearer_and_dpop_tokens() {
    let mut random = random();
    let (mut server, _) = server(&mut random);
    let basic = OAuthClientAuthentication::basic_credentials("web", "s3cret");
    let response = server.token(&post("grant_type=client_credentials", Some(basic.expose()), None), 0, &mut random);
    let bearer = OAuthTokenResponse::decode(response.status, &response.body).unwrap().access_token;
    let mut api = resource(&server, false);
    // RFC 6750 §2.1 and §3.1.
    let info = api.accept_jwt(&get(Some(format!("Bearer {bearer}")), None), 1).unwrap();
    assert_eq!(info.client_id.as_deref(), Some("web"));
    assert_eq!(info.scope, OAuthScope::parse("read").unwrap());
    let refusal = api.accept_jwt(&get(None, None), 1).unwrap_err();
    assert_eq!(refusal.status, 401);
    assert_eq!(refusal.challenges.len(), 2);
    assert!(refusal.challenges.iter().all(|challenge| challenge.get("error").is_none()));
    assert_eq!(
        refusal.challenges[0].encode().unwrap(),
        "Bearer realm=\"example\", resource_metadata=\"https://api.example/.well-known/oauth-protected-resource\""
    );
    let refusal = api.accept_jwt(&get(Some("Bearer a b".into()), None), 1).unwrap_err();
    assert_eq!(refusal.status, 400);
    let refusal = api.accept_jwt(&get(Some("Bearer forged.token.value".into()), None), 1).unwrap_err();
    assert_eq!((refusal.status, refusal.challenges[0].get("error")), (401, Some("invalid_token")));
    let late = server.config().access_token_lifetime + 1;
    assert_eq!(
        api.accept_jwt(&get(Some(format!("Bearer {bearer}")), None), late).unwrap_err().challenges[0].get("error"),
        Some("invalid_token")
    );
    // A token for another audience.
    let mut elsewhere = resource(&server, false);
    let mut config = elsewhere.config().clone();
    config.resource = "https://other.example".into();
    elsewhere = OAuthResourceServer::new(config).expect("a resource server");
    assert_eq!(
        elsewhere.accept_jwt(&get(Some(format!("Bearer {bearer}")), None), 1).unwrap_err().challenges[0].get("error"),
        Some("invalid_token")
    );
    // §3.1: insufficient_scope is 403 and names the scope.
    let refusal = api.require_scope(&info, &OAuthScope::parse("write").unwrap(), OAuthTokenScheme::Bearer).unwrap_err();
    assert_eq!((refusal.status, refusal.challenges[0].get("scope")), (403, Some("write")));
    // RFC 9470 §3: step-up.
    let refusal = api.require_authentication(&info, 1, Some(5), &["myACR"], OAuthTokenScheme::Bearer).unwrap_err();
    assert_eq!(refusal.challenges[0].get("error"), Some("insufficient_user_authentication"));
    assert_eq!(refusal.challenges[0].get("acr_values"), Some("myACR"));
    assert_eq!(refusal.challenges[0].get("max_age"), Some("5"));

    // DPoP-bound tokens (RFC 9449 §7).
    let client_key = key(&mut random);
    let token_target = DPoPTarget { method: "POST", uri: "https://as.example/token", access_token: None };
    let proof = DPoPProof::create(&client_key, JWSAlgorithm::ES256, &token_target, 0, None, &mut random).unwrap();
    let response =
        server.token(&post("grant_type=client_credentials", Some(basic.expose()), Some(proof)), 0, &mut random);
    let bound = OAuthTokenResponse::decode(response.status, &response.body).unwrap().access_token;
    let resource_target = DPoPTarget { method: "GET", uri: "https://api.example/items", access_token: Some(&bound) };
    let proof = DPoPProof::create(&client_key, JWSAlgorithm::ES256, &resource_target, 1, None, &mut random).unwrap();
    let info = api.accept_jwt(&get(Some(format!("DPoP {bound}")), Some(proof.clone())), 1).unwrap();
    assert!(info.confirmation.is_some());
    // Replayed proof, missing proof, other key, bound token as Bearer, Bearer token as DPoP.
    assert_eq!(
        api.accept_jwt(&get(Some(format!("DPoP {bound}")), Some(proof)), 2).unwrap_err().challenges[0].get("error"),
        Some("invalid_dpop_proof")
    );
    assert_eq!(
        api.accept_jwt(&get(Some(format!("DPoP {bound}")), None), 2).unwrap_err().challenges[0].get("error"),
        Some("invalid_dpop_proof")
    );
    let other = key(&mut random);
    let proof = DPoPProof::create(&other, JWSAlgorithm::ES256, &resource_target, 2, None, &mut random).unwrap();
    assert_eq!(
        api.accept_jwt(&get(Some(format!("DPoP {bound}")), Some(proof)), 2).unwrap_err().challenges[0].get("error"),
        Some("invalid_dpop_proof")
    );
    let refusal = api.accept_jwt(&get(Some(format!("Bearer {bound}")), None), 2).unwrap_err();
    assert!(refusal.challenges[0].is_scheme("DPoP"));
    assert_eq!(refusal.challenges[0].get("error"), Some("invalid_token"));
    let proof = DPoPProof::create(
        &client_key,
        JWSAlgorithm::ES256,
        &DPoPTarget { access_token: Some(&bearer), ..resource_target },
        2,
        None,
        &mut random,
    )
    .unwrap();
    assert_eq!(
        api.accept_jwt(&get(Some(format!("DPoP {bearer}")), Some(proof)), 2).unwrap_err().challenges[0].get("error"),
        Some("invalid_token")
    );
    // A resource that requires DPoP refuses Bearer tokens.
    let mut strict = resource(&server, true);
    let refusal = strict.accept_jwt(&get(Some(format!("Bearer {bearer}")), None), 1).unwrap_err();
    assert!(refusal.challenges[0].is_scheme("DPoP"));
    assert!(refusal.challenges[0].get("algs").unwrap().contains("ES256"));
    let metadata = strict.metadata(&["https://as.example"], &["read"]);
    assert_eq!(metadata.boolean(OAuthMetadata::DPOP_BOUND_ACCESS_TOKENS_REQUIRED).unwrap(), Some(true));
    let response = refusal.to_response();
    assert_eq!(response.status, 401);
    assert!(response.header("www-authenticate").unwrap().starts_with("DPoP "));
}

#[test]
fn authorization_headers_follow_rfc_6750_and_rfc_9449() {
    let token = OAuthPresentedToken::from_authorization("Bearer mF_9.B5f-4.1JqM").unwrap().unwrap();
    assert_eq!((token.scheme, token.token.as_str()), (OAuthTokenScheme::Bearer, "mF_9.B5f-4.1JqM"));
    assert!(Vectors::read("auth/oauth/rfc6750.txt").contains("Authorization: Bearer mF_9.B5f-4.1JqM"));
    let token =
        OAuthPresentedToken::from_authorization("dpop Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU").unwrap().unwrap();
    assert_eq!(token.scheme, OAuthTokenScheme::DPoP);
    assert_eq!(OAuthPresentedToken::from_authorization("Basic YTpi").unwrap(), None);
    for value in ["Bearer", "Bearer ", "Bearer a b", "Bearer a=b", "Bearer =", "Bearer é"] {
        assert!(OAuthPresentedToken::from_authorization(value).is_err(), "{value}");
    }
    assert!(OAuthPresentedToken::from_authorization("Bearer abc==").unwrap().is_some());
}

#[test]
fn challenges_read_and_write_as_the_rfcs_show() {
    // RFC 6750 §3.
    let parsed = OAuthChallenge::parse(
        &RFC::block_from("auth/oauth/rfc6750.txt", "WWW-Authenticate: Bearer realm=\"example\",")[18..],
    )
    .unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].get("realm"), Some("example"));
    let error = parsed[0].error().unwrap().unwrap();
    assert_eq!(
        (error.code, error.description.as_deref()),
        (OAuthErrorCode::InvalidToken, Some("The access token expired"))
    );
    assert_eq!(OAuthChallenge::parse(&parsed[0].encode().unwrap()).unwrap(), parsed);
    // RFC 9449 Figures 17 and 19: two challenges in one field.
    let value = field(RFC9449, "WWW-Authenticate: Bearer error=\"invalid_request\"", 0, "WWW-Authenticate");
    let parsed = OAuthChallenge::parse(&value).unwrap();
    assert_eq!(parsed.len(), 2);
    assert!(parsed[0].is_scheme("Bearer") && parsed[1].is_scheme("DPoP"));
    assert_eq!(parsed[1].get("algs"), Some("ES256 PS256"));
    assert_eq!(parsed[1].get("error"), Some("invalid_request"));
    let parsed = OAuthChallenge::parse("Bearer, DPoP algs=\"ES256 PS256\"").unwrap();
    assert_eq!(parsed.len(), 2);
    assert!(parsed[0].parameters.is_empty());
    // RFC 9470 §3 and RFC 9728 §5.1.
    let step_up = RFC::block_from(
        "auth/oauth/rfc9470.txt",
        "WWW-Authenticate: Bearer error=\"insufficient_user_authentication\",",
    );
    let parsed = OAuthChallenge::parse(step_up.strip_prefix("WWW-Authenticate:").unwrap()).unwrap();
    assert_eq!(parsed[0].get("acr_values"), Some("myACR"));
    let metadata = RFC::block_from("auth/oauth/rfc9728.txt", "WWW-Authenticate: Bearer resource_metadata=");
    let parsed = OAuthChallenge::parse(metadata.strip_prefix("WWW-Authenticate:").unwrap()).unwrap();
    assert_eq!(
        parsed[0].get("resource_metadata"),
        Some("https://resource.example.com/.well-known/oauth-protected-resource")
    );
    // token68 and quoted-pair.
    let parsed = OAuthChallenge::parse("Basic abc==, Bearer realm=\"a \\\"b\\\"\"").unwrap();
    assert_eq!(parsed[0].parameters, [(String::new(), "abc==".to_string())]);
    assert_eq!(parsed[1].get("realm"), Some("a \"b\""));
    let mut challenge = OAuthChallenge::new("Bearer");
    challenge.push("error_description", "a \"quoted\" \\ text");
    assert_eq!(OAuthChallenge::parse(&challenge.encode().unwrap()).unwrap()[0], challenge);
    for value in ["Bearer realm=\"open", "=x", "Bearer realm=\"a\" x=\"b\"", "Bearer realm=\"a\"\"b\""] {
        assert!(OAuthChallenge::parse(value).is_err(), "{value}");
    }
    // `realm=` alone is a token68 (RFC 9110 §11.2), not a parameter without a value.
    assert_eq!(OAuthChallenge::parse("Bearer realm=").unwrap()[0].parameters, [(String::new(), "realm=".to_string())]);
}

#[test]
fn control_characters_never_reach_a_header_field() {
    // RFC 9110 §5.6.4: qdtext and quoted-pair take no control character but HTAB.
    for value in
        ["Bearer realm=\"a\rb\"", "Bearer realm=\"a\nb\"", "Bearer realm=\"a\\\nb\"", "Bearer realm=\"a\u{0}b\""]
    {
        assert!(OAuthChallenge::parse(value).is_err(), "{value:?}");
    }
    assert!(OAuthChallenge::parse("Bearer realm=\"a\tb\"").is_ok());
    let mut challenge = OAuthChallenge::new("Bearer");
    challenge.push("error_description", "a\r\nSet-Cookie: x=y");
    assert!(challenge.encode().is_err());
    let mut challenge = OAuthChallenge::new("Bearer");
    challenge.push("bad name", "x");
    assert!(challenge.encode().is_err());
    // A resource server whose realm could not be quoted is refused.
    let mut random = random();
    let (server, _) = server(&mut random);
    let config = OAuthResourceConfig {
        resource: "https://api.example".into(),
        realm: Some("a\r\nb".into()),
        resource_metadata: None,
        validation: OAuthTokenValidation::JWT {
            issuer: "https://as.example".into(),
            keys: server.jwks().unwrap(),
            algorithms: vec![JWSAlgorithm::ES256],
        },
        require_dpop: false,
        dpop: DPoPConfig::default(),
        leeway: 0,
    };
    assert!(OAuthResourceServer::new(config).is_err());
}

#[test]
fn a_nonce_required_but_never_made_is_a_server_error() {
    // RFC 9449 §8: without a nonce to send, use_dpop_nonce would refuse every proof for good.
    let mut random = random();
    let key = key(&mut random);
    let target = DPoPTarget { method: "POST", uri: "https://as.example/token", access_token: None };
    let mut verifier = DPoPVerifier::new(DPoPConfig { require_nonce: true, ..DPoPConfig::default() });
    let proof = DPoPProof::create(&key, JWSAlgorithm::ES256, &target, 0, None, &mut random).unwrap();
    assert_eq!(verifier.check(&proof, &target, 0).unwrap_err().code, OAuthErrorCode::ServerError);
}
