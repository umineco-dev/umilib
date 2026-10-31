//! Benchmarks of `umilib::auth`.

use umilib::platform::bench::Bench;

pub struct Benchmarks;

impl Benchmarks {
    pub fn run(bench: &mut Bench) {
        #[cfg(all(umilib_feature = "auth-totp", umilib_feature = "hash-sha-v1"))]
        {
            use std::hint::black_box;

            use umilib::auth::totp::{HOTP, TOTP, TOTPConfig};
            use umilib::hash::sha::v1::SHA1;
            use umilib::platform::bench::Throughput;
            let hotp = HOTP::<SHA1>::new(b"12345678901234567890", 6).unwrap();
            bench.run("auth-totp-hotp-generate", Some(Throughput::Elements(1)), || {
                black_box(hotp.generate(black_box(5)).unwrap());
            });
            let totp = TOTP::<SHA1>::new(b"12345678901234567890", &TOTPConfig::default()).unwrap();
            bench.run("auth-totp-verify-3-steps", Some(Throughput::Elements(3)), || {
                black_box(totp.verify(black_box(b"000000"), 1111111109, 1, 1).unwrap());
            });
        }
        #[cfg(umilib_feature = "auth-cert-key")]
        Benchmarks::keys(bench);
        #[cfg(umilib_feature = "auth-cert-x509")]
        Benchmarks::certificates(bench);
        #[cfg(umilib_feature = "auth-cert-path")]
        Benchmarks::paths(bench);
        #[cfg(umilib_feature = "auth-cert-ocsp")]
        Benchmarks::statuses(bench);
        #[cfg(all(
            umilib_feature = "auth-sasl-plain",
            umilib_feature = "auth-sasl-scram",
            umilib_feature = "auth-sasl-oauthbearer"
        ))]
        Benchmarks::sasl(bench);
        #[cfg(all(umilib_feature = "auth-oauth", umilib_feature = "hash-sha-v2"))]
        Benchmarks::oauth(bench);
        let _ = bench;
    }

    /// OAuth: reading a token request, the client credentials grant at the server (opaque and JWT
    /// access tokens), a whole authorization code exchange, and a DPoP proof checked.
    #[cfg(all(umilib_feature = "auth-oauth", umilib_feature = "hash-sha-v2"))]
    pub fn oauth(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::auth::cert::key::{KeyAlgorithm, NamedCurve, PrivateKey};
        use umilib::auth::oauth::{
            DPoPConfig, DPoPProof, DPoPTarget, DPoPVerifier, OAuthAccessTokenFormat, OAuthClientAuthentication,
            OAuthClientMethod, OAuthClientRegistration, OAuthEndpointRequest, OAuthGrant, OAuthParameters, OAuthScope,
            OAuthServer, OAuthServerConfig, OAuthTokenRequest,
        };
        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::platform::bench::Throughput;
        use umilib::protocol::jwt::{JWK, JWSAlgorithm};
        let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"umilib oauth bench").unwrap();
        let body = b"grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        bench.run("auth-oauth-token-request-parse", Some(Throughput::Bytes(body.len() as u64)), || {
            black_box(OAuthTokenRequest::from_parameters(&OAuthParameters::parse(black_box(body)).unwrap()).unwrap());
        });
        let key =
            JWK::from_private_key(&PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut random).unwrap())
                .unwrap();
        for (name, format) in [
            ("auth-oauth-server-client-credentials-opaque", OAuthAccessTokenFormat::Opaque),
            (
                "auth-oauth-server-client-credentials-jwt-es256",
                OAuthAccessTokenFormat::JWT {
                    key: Box::new(key.clone()),
                    algorithm: JWSAlgorithm::ES256,
                    default_audience: "https://api.example".into(),
                },
            ),
        ] {
            let mut config = OAuthServerConfig::new("https://as.example");
            config.access_token_format = format;
            config.access_token_lifetime = 1;
            let mut server = OAuthServer::new(config);
            server
                .register(OAuthClientRegistration::confidential(
                    "web",
                    OAuthClientMethod::SecretBasic,
                    "s3cret",
                    &[OAuthGrant::CLIENT_CREDENTIALS],
                    OAuthScope::parse("read").unwrap(),
                ))
                .expect("a registration");
            let request = OAuthEndpointRequest {
                method: "POST".into(),
                uri: "https://as.example/token".into(),
                authorization: Some(OAuthClientAuthentication::basic_credentials("web", "s3cret").expose().clone()),
                content_type: Some("application/x-www-form-urlencoded".into()),
                body: b"grant_type=client_credentials".to_vec(),
                ..OAuthEndpointRequest::default()
            };
            let mut now = 0;
            bench.run(name, Some(Throughput::Elements(1)), || {
                // Each token expires two seconds later, so the table stays small.
                now += 2;
                black_box(server.token(black_box(&request), now, &mut random));
            });
        }
        let target = DPoPTarget { method: "GET", uri: "https://api.example/items", access_token: Some("token") };
        let mut verifier = DPoPVerifier::new(DPoPConfig::default());
        let mut now = 0;
        bench.run("auth-oauth-dpop-proof-create-and-check-es256", Some(Throughput::Elements(1)), || {
            now += 1;
            let proof = DPoPProof::create(&key, JWSAlgorithm::ES256, &target, now, None, &mut random).unwrap();
            black_box(verifier.check(&proof, &target, now).unwrap());
        });
    }

    /// Parsing keys, and verifying through [`PublicKey`] (which rebuilds the
    /// typed key of each verification) against the raw schemes in `crypto`.
    #[cfg(umilib_feature = "auth-cert-key")]
    pub fn keys(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::auth::cert::key::{
            HashAlgorithm, KeyAlgorithm, NamedCurve, PrivateKey, PublicKey, SignatureAlgorithm,
        };
        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::platform::bench::Throughput;
        let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"bench").unwrap();
        for (name, algorithm, signature) in [
            ("ecdsa-p256", KeyAlgorithm::EC(NamedCurve::P256), SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256)),
            ("ed25519", KeyAlgorithm::Ed25519, SignatureAlgorithm::Ed25519),
        ] {
            let key = PrivateKey::generate(algorithm, &mut random).unwrap();
            let public_key = key.public_key().unwrap();
            let spki = public_key.to_der().unwrap();
            let pkcs8 = key.to_pkcs8_der().unwrap();
            let signed = key.sign(&signature, b"message", &mut random).unwrap();
            bench.run(&format!("auth-cert-key-{name}-parse-spki"), Some(Throughput::Elements(1)), || {
                black_box(PublicKey::from_der(black_box(&spki)).unwrap());
            });
            bench.run(&format!("auth-cert-key-{name}-parse-pkcs8"), Some(Throughput::Elements(1)), || {
                black_box(PrivateKey::from_pkcs8_der(black_box(pkcs8.expose())).unwrap());
            });
            bench.run(&format!("auth-cert-key-{name}-verify"), Some(Throughput::Elements(1)), || {
                public_key.verify(&signature, black_box(b"message"), black_box(&signed)).unwrap();
            });
        }
    }

    /// Reading certificates and CRLs, decoding their extensions, verifying
    /// a certificate, and signing one.
    #[cfg(umilib_feature = "auth-cert-x509")]
    pub fn certificates(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::auth::cert::key::PrivateKey;
        use umilib::auth::cert::x509::{
            BasicConstraints, Certificate, CertificateList, KeyUsage, SubjectAlternativeName,
        };
        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        use umilib::platform::bench::Throughput;
        let root = include_bytes!("../tests/vectors/auth/cert/x509/openssl/root.der");
        let leaf = include_bytes!("../tests/vectors/auth/cert/x509/openssl/leaf.der");
        let crl = include_bytes!("../tests/vectors/auth/cert/x509/openssl/intermediate.crl");
        let ed25519 = include_bytes!("../tests/vectors/auth/cert/x509/openssl/ed25519.der");
        bench.run("auth-cert-x509-parse-leaf", Some(Throughput::Bytes(leaf.len() as u64)), || {
            black_box(Certificate::from_der(black_box(leaf)).unwrap());
        });
        bench.run("auth-cert-x509-parse-crl", Some(Throughput::Bytes(crl.len() as u64)), || {
            black_box(CertificateList::from_der(black_box(crl)).unwrap());
        });
        let certificate = Certificate::from_der(leaf).unwrap();
        let extensions = &certificate.tbs_certificate().extensions;
        bench.run("auth-cert-x509-decode-extensions", Some(Throughput::Elements(3)), || {
            black_box(extensions.typed::<BasicConstraints>().unwrap());
            black_box(extensions.typed::<KeyUsage>().unwrap());
            black_box(extensions.typed::<SubjectAlternativeName>().unwrap());
        });
        bench.run("auth-cert-x509-subject-rfc4514", Some(Throughput::Elements(1)), || {
            black_box(certificate.tbs_certificate().subject.to_rfc4514());
        });
        let root = Certificate::from_der(root).unwrap();
        let root_key = root.public_key().unwrap();
        bench.run("auth-cert-x509-verify-ecdsa-p256", Some(Throughput::Elements(1)), || {
            root.verify(black_box(&root_key)).unwrap();
        });
        let self_signed = Certificate::from_der(ed25519).unwrap();
        let key = PrivateKey::from_pem(include_str!("../tests/vectors/auth/cert/x509/openssl/ed25519.key")).unwrap();
        let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"bench").unwrap();
        let tbs = self_signed.tbs_certificate().clone();
        bench.run("auth-cert-x509-sign-ed25519", Some(Throughput::Elements(1)), || {
            black_box(tbs.sign(&key, &mut random).unwrap());
        });
    }

    /// Validating a path of PKITS (a CA and its CRL), comparing distinguished
    /// names by RFC 5280 §7.1, and growing the policy graph of RFC 9618 §3.2.
    #[cfg(umilib_feature = "auth-cert-path")]
    pub fn paths(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::auth::cert::key::KeyLimits;
        use umilib::auth::cert::path::{
            PathConfig, PathProfile, PathValidator, PolicyGraph, RevocationConfig, TrustAnchor,
        };
        use umilib::auth::cert::x509::{
            Certificate, CertificateList, CertificatePolicies, Name, NameAttribute, PolicyInformation, PolicyMapping,
            PolicyMappings,
        };
        use umilib::codec::asn1::{ASN1Time, ObjectIdentifier};
        use umilib::platform::bench::Throughput;
        let pkits = |kind: &str, name: &str| {
            std::fs::read(format!("{}/tests/vectors/auth/cert/path/pkits/{kind}/{name}", env!("CARGO_MANIFEST_DIR")))
                .unwrap()
        };
        let root = Certificate::from_der(&pkits("certs", "TrustAnchorRootCertificate.crt")).unwrap().into_owned();
        let anchors = [TrustAnchor::from_certificate(root, &KeyLimits::default()).unwrap()];
        let intermediates = [Certificate::from_der(&pkits("certs", "GoodCACert.crt")).unwrap().into_owned()];
        let crls = [
            CertificateList::from_der(&pkits("crls", "TrustAnchorRootCRL.crl")).unwrap().into_owned(),
            CertificateList::from_der(&pkits("crls", "GoodCACRL.crl")).unwrap().into_owned(),
        ];
        let target = Certificate::from_der(&pkits("certs", "ValidCertificatePathTest1EE.crt")).unwrap().into_owned();
        let time = ASN1Time::new(2020, 1, 1, 0, 0, 0, 0).unwrap();
        for (name, revocation) in
            [("without-revocation", RevocationConfig::NONE), ("with-crls", RevocationConfig::REQUIRED)]
        {
            let config = PathConfig { profile: PathProfile::Algorithm, revocation, ..PathConfig::new(time) };
            let validator = PathValidator::new(&config, &anchors, &intermediates, &crls);
            bench.run(&format!("auth-cert-path-validate-pkits-4.1.1-{name}"), Some(Throughput::Elements(1)), || {
                black_box(validator.validate(black_box(&target)).unwrap());
            });
        }
        let first = Name::from_attributes(&[
            (NameAttribute::Country, "US"),
            (NameAttribute::Organization, "Test Certificates 2011"),
            (NameAttribute::CommonName, "Good CA"),
        ])
        .unwrap();
        let second = Name::from_attributes(&[
            (NameAttribute::Country, "US"),
            (NameAttribute::Organization, "  test   CERTIFICATES 2011 "),
            (NameAttribute::CommonName, "good ca"),
        ])
        .unwrap();
        bench.run("auth-cert-path-name-matches-rfc5280-7.1", Some(Throughput::Elements(1)), || {
            assert!(black_box(&first).matches(black_box(&second)));
        });
        let oid = |text: &str| ObjectIdentifier::parse(text).unwrap();
        let (one, two) = (oid("1.2.3.1"), oid("1.2.3.2"));
        let policies = CertificatePolicies {
            policies: [&one, &two]
                .map(|identifier| PolicyInformation { identifier: identifier.clone(), qualifiers: Vec::new() })
                .to_vec(),
        };
        let mappings = PolicyMappings {
            mappings: [(&one, &one), (&one, &two), (&two, &one), (&two, &two)]
                .map(|(issuer, subject)| PolicyMapping {
                    issuer_domain_policy: issuer.clone(),
                    subject_domain_policy: subject.clone(),
                })
                .to_vec(),
        };
        bench.run("auth-cert-path-policy-graph-rfc9618-64-levels", Some(Throughput::Elements(64)), || {
            let mut graph = PolicyGraph::new();
            for _ in 0..64 {
                graph.process(black_box(&policies), true);
                graph.map(black_box(&mappings), true);
            }
            black_box(graph.user_constrained_policies(None));
        });
    }

    /// Reading an OCSP response that OpenSSL made, checking it (a delegated
    /// responder's certificate and the response's signatures), and naming a certificate.
    #[cfg(umilib_feature = "auth-cert-ocsp")]
    pub fn statuses(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::auth::cert::key::HashAlgorithm;
        use umilib::auth::cert::ocsp::{CertID, OCSPConfig, OCSPResponse};
        use umilib::auth::cert::x509::Certificate;
        use umilib::codec::asn1::ASN1Time;
        use umilib::platform::bench::Throughput;
        let bytes = include_bytes!("../tests/vectors/auth/cert/ocsp/openssl/response-delegated.der");
        let root = Certificate::from_der(include_bytes!("../tests/vectors/auth/cert/ocsp/openssl/root.der")).unwrap();
        let good = Certificate::from_der(include_bytes!("../tests/vectors/auth/cert/ocsp/openssl/good.der")).unwrap();
        let root_key = root.public_key().unwrap();
        bench.run("auth-cert-ocsp-parse-response", Some(Throughput::Bytes(bytes.len() as u64)), || {
            black_box(OCSPResponse::from_der(black_box(bytes)).unwrap());
        });
        bench.run("auth-cert-ocsp-cert-id-sha256", Some(Throughput::Elements(1)), || {
            black_box(CertID::new(black_box(&good), root_key.key(), HashAlgorithm::SHA256));
        });
        let response = OCSPResponse::from_der(bytes).unwrap();
        let basic = response.basic().unwrap();
        let cert_id = CertID::new(&good, root_key.key(), HashAlgorithm::SHA256);
        let config = OCSPConfig::new(ASN1Time::new(2027, 1, 1, 0, 0, 0, 0).unwrap());
        let issuer = &root.tbs_certificate().subject;
        bench.run("auth-cert-ocsp-verify-delegated", Some(Throughput::Elements(1)), || {
            black_box(basic.verify(black_box(&cert_id), issuer, &root_key, &config).unwrap());
        });
    }

    /// SCRAM-SHA-256 (RFC 7677 §3, 4096 iterations, both sides), and the
    /// decoding of PLAIN and OAUTHBEARER messages.
    #[cfg(all(
        umilib_feature = "auth-sasl-plain",
        umilib_feature = "auth-sasl-scram",
        umilib_feature = "auth-sasl-oauthbearer"
    ))]
    pub fn sasl(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::auth::sasl::oauthbearer::OAUTHBEARERMessage;
        use umilib::auth::sasl::plain::PLAINMessage;
        use umilib::auth::sasl::scram::{SCRAMClient, SCRAMCredentials, SCRAMSecret, SCRAMServer};
        use umilib::hash::sha::v2::SHA256;
        use umilib::platform::bench::Throughput;
        use umilib::secret::Secret;
        let credentials = SCRAMCredentials::<SHA256>::new("pencil", b"salt of sixteen!", 4096).unwrap();
        bench.run("auth-sasl-scram-sha256-exchange-4096", Some(Throughput::Elements(1)), || {
            let secret = SCRAMSecret::Password(Secret::new(String::from("pencil")));
            let mut client = SCRAMClient::<SHA256>::new("user", secret, "rOprNGfwEbeRWgbNEkqO");
            let mut server = SCRAMServer::<SHA256>::new(false);
            server.receive_client_first(&client.client_first().unwrap()).unwrap();
            let server_first = server.server_first(&credentials, "servernonce").unwrap();
            let client_final = client.receive_server_first(&server_first).unwrap();
            client.receive_server_final(&server.receive_client_final(&client_final).unwrap()).unwrap();
            black_box(client);
        });
        let plain = b"Ursel\0Kurt\0xipj3plmq";
        bench.run("auth-sasl-plain-decode", Some(Throughput::Elements(1)), || {
            black_box(PLAINMessage::decode(black_box(plain)).unwrap());
        });
        let bearer = b"n,a=user@example.com,\x01host=server.example.com\x01port=143\x01auth=Bearer vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==\x01\x01";
        bench.run("auth-sasl-oauthbearer-decode", Some(Throughput::Elements(1)), || {
            black_box(OAUTHBEARERMessage::decode(black_box(bearer)).unwrap());
        });
    }
}
