//! The C ABI of `umilib::auth::oauth`: messages, PKCE, metadata, a client and a server talking
//! through it, a resource server, DPoP and challenges.

use std::ffi::CString;
use std::ptr;

use umilib::ffi::Buffer;
use umilib::ffi::auth::oauth::client::*;
use umilib::ffi::auth::oauth::dpop::*;
use umilib::ffi::auth::oauth::resource::*;
use umilib::ffi::auth::oauth::server::*;
use umilib::ffi::auth::oauth::*;
use umilib::ffi::crypto::random::hmac_drbg;

use super::super::Check;

fn take(buffer: &mut Buffer) -> String {
    let text = String::from_utf8(buffer.as_slice().to_vec()).unwrap();
    unsafe { umilib::ffi::umilib_ffi_buffer_free(buffer) };
    text
}

/// An array of C strings and the strings that keep it alive.
fn strings(values: &[&str]) -> (Vec<CString>, Vec<*const umilib::ffi::Char>) {
    let owned: Vec<CString> = values.iter().map(|value| CString::new(*value).unwrap()).collect();
    let pointers = owned.iter().map(|value| value.as_ptr().cast()).collect();
    (owned, pointers)
}

#[test]
fn oauth_messages_through_the_c_abi() {
    unsafe {
        // Parameters: §3.1 repeats, the order, the encoding.
        let mut parameters = ptr::null_mut();
        let (_names, repeatable) = strings(&["resource"]);
        let body = b"client_id=a&resource=r1&resource=r2&state=";
        Check::ok(umilib_auth_oauth_oauth_parameters_parse(
            body.as_ptr(),
            body.len(),
            repeatable.as_ptr(),
            1,
            &mut parameters,
        ));
        let mut count = 0;
        Check::ok(umilib_auth_oauth_oauth_parameters_count(parameters, &mut count));
        assert_eq!(count, 3);
        let (mut has, mut value) = (false, Buffer::EMPTY);
        Check::ok(umilib_auth_oauth_oauth_parameters_get(parameters, b"state".as_ptr(), 5, &mut has, &mut value));
        assert!(!has);
        take(&mut value);
        Check::fails(
            umilib_auth_oauth_oauth_parameters_parse(b"a=1&a=2".as_ptr(), 7, ptr::null(), 0, &mut parameters),
            "auth.oauth",
            "Repeated",
        );
        let mut encoded = Buffer::EMPTY;
        Check::ok(umilib_auth_oauth_oauth_parameters_push(parameters, b"scope".as_ptr(), 5, b"a b".as_ptr(), 3));
        Check::ok(umilib_auth_oauth_oauth_parameters_encode(parameters, &mut encoded));
        assert_eq!(take(&mut encoded), "client_id=a&resource=r1&resource=r2&scope=a+b");
        // The request read and written back canonical.
        let mut checked = ptr::null_mut();
        Check::ok(umilib_auth_oauth_oauth_authorization_request_check(parameters, &mut checked));
        Check::ok(umilib_auth_oauth_oauth_parameters_encode(checked, &mut encoded));
        assert_eq!(take(&mut encoded), "client_id=a&scope=a+b&resource=r1&resource=r2");
        umilib_auth_oauth_oauth_parameters_free(checked);
        let uri = "https://as.example/authorize?x=1";
        Check::ok(umilib_auth_oauth_oauth_parameters_add_to_query(parameters, uri.as_ptr(), uri.len(), &mut encoded));
        assert!(take(&mut encoded).starts_with("https://as.example/authorize?x=1&client_id=a"));
        umilib_auth_oauth_oauth_parameters_free(parameters);

        // PKCE: RFC 7636 Appendix B.
        let mut verifier = ptr::null_mut();
        let text = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        Check::ok(umilib_auth_oauth_pkce_verifier_new(text.as_ptr(), text.len(), &mut verifier));
        let mut challenge = Buffer::EMPTY;
        Check::ok(umilib_auth_oauth_pkce_verifier_challenge(verifier, 0, &mut challenge));
        let challenge = take(&mut challenge);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        let mut matches = false;
        Check::ok(umilib_auth_oauth_pkce_challenge_verify(
            0,
            challenge.as_ptr(),
            challenge.len(),
            verifier,
            &mut matches,
        ));
        assert!(matches);
        let mut method = 9;
        Check::fails(umilib_auth_oauth_pkce_method_parse(b"plain".as_ptr(), 5, &mut method), "auth.oauth", "Invalid");
        umilib_auth_oauth_pkce_verifier_free(verifier);

        // Scopes and error responses.
        let mut scope = Buffer::EMPTY;
        Check::ok(umilib_auth_oauth_oauth_scope_parse(b"b a b".as_ptr(), 5, &mut scope));
        assert_eq!(take(&mut scope), "b a");
        Check::fails(umilib_auth_oauth_oauth_scope_parse(b"a  b".as_ptr(), 4, &mut scope), "auth.oauth", "Invalid");
        let mut error = Buffer::EMPTY;
        Check::ok(umilib_auth_oauth_oauth_error_response_encode(
            b"invalid_grant".as_ptr(),
            13,
            b"used".as_ptr(),
            4,
            ptr::null(),
            0,
            &mut error,
        ));
        let error = take(&mut error);
        assert_eq!(error, r#"{"error":"invalid_grant","error_description":"used"}"#);
        // A token response that is an error fails with Response and gives the error's JSON.
        let (mut out, mut out_error) = (Buffer::EMPTY, Buffer::EMPTY);
        Check::fails(
            umilib_auth_oauth_oauth_token_response_decode(400, error.as_ptr(), error.len(), &mut out, &mut out_error),
            "auth.oauth",
            "Response",
        );
        assert_eq!(take(&mut out_error), error);
        let body = br#"{"access_token":"a","token_type":"Bearer","expires_in":60,"x":1}"#;
        Check::ok(umilib_auth_oauth_oauth_token_response_decode(
            200,
            body.as_ptr(),
            body.len(),
            &mut out,
            &mut out_error,
        ));
        assert_eq!(take(&mut out), r#"{"access_token":"a","token_type":"Bearer","expires_in":60,"x":1}"#);

        // Metadata.
        let issuer = "https://example.com/issuer1";
        Check::ok(umilib_auth_oauth_oauth_metadata_location(0, issuer.as_ptr(), issuer.len(), &mut out));
        assert_eq!(take(&mut out), "https://example.com/.well-known/oauth-authorization-server/issuer1");
        let document = br#"{"issuer":"https://a","token_endpoint":"https://a/t"}"#;
        Check::ok(umilib_auth_oauth_oauth_metadata_check(
            0,
            document.as_ptr(),
            document.len(),
            b"https://a".as_ptr(),
            9,
        ));
        Check::fails(
            umilib_auth_oauth_oauth_metadata_check(0, document.as_ptr(), document.len(), b"https://b".as_ptr(), 9),
            "auth.oauth",
            "Issuer",
        );

        // Challenges and presented tokens.
        let value = r#"Bearer realm="example", error="invalid_token", DPoP algs="ES256""#;
        let mut challenges = ptr::null_mut();
        Check::ok(umilib_auth_oauth_oauth_challenges_parse(value.as_ptr(), value.len(), &mut challenges));
        Check::ok(umilib_auth_oauth_oauth_challenges_count(challenges, &mut count));
        assert_eq!(count, 2);
        let (mut scheme, mut names, mut values) = (Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_auth_oauth_oauth_challenges_get(challenges, 0, &mut scheme, &mut names, &mut values));
        assert_eq!(
            (take(&mut scheme), take(&mut names), take(&mut values)),
            ("Bearer".into(), "realm\nerror".into(), "example\ninvalid_token".into())
        );
        umilib_auth_oauth_oauth_challenges_free(challenges);
        let (mut found, mut token_scheme, mut token) = (false, 9, Buffer::EMPTY);
        Check::ok(umilib_auth_oauth_oauth_presented_token_from_authorization(
            b"DPoP abc".as_ptr(),
            8,
            &mut found,
            &mut token_scheme,
            &mut token,
        ));
        assert!(found && token_scheme == 1);
        assert_eq!(take(&mut token), "abc");
        // One output given twice is refused.
        let mut same = false;
        Check::fails(
            umilib_auth_oauth_oauth_presented_token_from_authorization(
                b"DPoP abc".as_ptr(),
                8,
                &mut same,
                (&mut same as *mut bool).cast(),
                &mut token,
            ),
            "ffi",
            "InvalidArgument",
        );
    }
}

#[test]
fn oauth_client_and_server_through_the_c_abi() {
    unsafe {
        let hash = b"umilib_hash_sha_v2_SHA256";
        let kind = b"umilib_crypto_random_HMACDRBG";
        let mut random = ptr::null_mut();
        Check::ok(hmac_drbg::new(
            hash.as_ptr(),
            hash.len(),
            [7u8; 32].as_ptr(),
            32,
            [8u8; 16].as_ptr(),
            16,
            ptr::null(),
            0,
            &mut random,
        ));
        let random = random.cast();

        // A server with a public client.
        let issuer = "https://as.example";
        let mut config = ptr::null_mut();
        Check::ok(umilib_auth_oauth_oauth_server_config_new(issuer.as_ptr(), issuer.len(), &mut config));
        let mut limits: FFIOAuthServerLimits = std::mem::zeroed();
        Check::ok(umilib_auth_oauth_oauth_server_config_limits(config, &mut limits));
        assert!(limits.require_pkce && limits.rotate_refresh_tokens);
        limits.code_lifetime = 30;
        Check::ok(umilib_auth_oauth_oauth_server_config_set_limits(config, limits));
        let mut server = ptr::null_mut();
        Check::ok(umilib_auth_oauth_oauth_server_new(config, &mut server));
        umilib_auth_oauth_oauth_server_config_free(config);
        let (_r, redirects) = strings(&["https://app.example/cb"]);
        let (_g, grants) = strings(&["authorization_code", "refresh_token"]);
        Check::ok(umilib_auth_oauth_oauth_server_register(
            server,
            b"app".as_ptr(),
            3,
            0,
            ptr::null(),
            0,
            ptr::null(),
            redirects.as_ptr(),
            1,
            grants.as_ptr(),
            2,
            b"read".as_ptr(),
            4,
            ptr::null(),
            0,
            false,
        ));
        let mut metadata = Buffer::EMPTY;
        Check::ok(umilib_auth_oauth_oauth_server_metadata(server, &mut metadata));
        let metadata = take(&mut metadata);

        // The client of that server.
        let mut client = ptr::null_mut();
        let redirect = "https://app.example/cb";
        Check::ok(umilib_auth_oauth_oauth_client_new(
            metadata.as_ptr(),
            metadata.len(),
            0,
            b"app".as_ptr(),
            3,
            ptr::null(),
            0,
            ptr::null(),
            0,
            redirect.as_ptr(),
            redirect.len(),
            &mut client,
        ));
        let mut url = Buffer::EMPTY;
        Check::ok(umilib_auth_oauth_oauth_client_authorize(
            client,
            b"read".as_ptr(),
            4,
            ptr::null(),
            0,
            100,
            random,
            kind.as_ptr(),
            kind.len(),
            &mut url,
        ));
        let url = take(&mut url);
        let mut query = ptr::null_mut();
        Check::ok(umilib_auth_oauth_oauth_parameters_from_query(url.as_ptr(), url.len(), &mut query));
        let (mut kind_out, mut authorization, mut text) = (9u8, ptr::null_mut(), Buffer::EMPTY);
        Check::ok(umilib_auth_oauth_oauth_server_authorize(
            server,
            query,
            100,
            &mut kind_out,
            &mut authorization,
            &mut text,
        ));
        assert_eq!(kind_out, 0);
        take(&mut text);
        let mut back = Buffer::EMPTY;
        Check::ok(umilib_auth_oauth_oauth_server_approve(
            server,
            authorization,
            b"alice".as_ptr(),
            5,
            b"read".as_ptr(),
            4,
            ptr::null(),
            0,
            false,
            0,
            ptr::null(),
            0,
            100,
            random,
            kind.as_ptr(),
            kind.len(),
            &mut back,
        ));
        let back = take(&mut back);
        assert!(back.contains("iss=https%3A%2F%2Fas.example"));
        let (mut token_request, mut out_error) = (ptr::null_mut(), Buffer::EMPTY);
        Check::ok(umilib_auth_oauth_oauth_client_callback(
            client,
            back.as_ptr(),
            back.len(),
            101,
            &mut token_request,
            &mut out_error,
        ));
        // The same response again: the state was used.
        let mut again = ptr::null_mut();
        Check::fails(
            umilib_auth_oauth_oauth_client_callback(client, back.as_ptr(), back.len(), 101, &mut again, &mut out_error),
            "auth.oauth",
            "State",
        );
        let mut http = ptr::null_mut();
        Check::ok(umilib_auth_oauth_oauth_client_token_request(
            client,
            token_request,
            101,
            random,
            kind.as_ptr(),
            kind.len(),
            &mut http,
        ));
        let (mut method, mut uri, mut headers, mut body) = (Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_auth_oauth_oauth_http_request_parts(http, &mut method, &mut uri, &mut headers, &mut body));
        let (method, uri, headers, body) = (take(&mut method), take(&mut uri), take(&mut headers), take(&mut body));
        assert_eq!(
            (method.as_str(), uri.as_str(), headers.as_str()),
            ("POST", "https://as.example/token", "content-type: application/x-www-form-urlencoded")
        );

        // The server's token endpoint answers it.
        let mut request = ptr::null_mut();
        Check::ok(umilib_auth_oauth_oauth_endpoint_request_new(
            method.as_ptr(),
            method.len(),
            uri.as_ptr(),
            uri.len(),
            body.as_ptr(),
            body.len(),
            &mut request,
        ));
        let content_type = "application/x-www-form-urlencoded";
        Check::ok(umilib_auth_oauth_oauth_endpoint_request_set_fields(
            request,
            ptr::null(),
            0,
            ptr::null(),
            0,
            content_type.as_ptr(),
            content_type.len(),
        ));
        let mut response = ptr::null_mut();
        Check::ok(umilib_auth_oauth_oauth_server_token(
            server,
            request,
            101,
            random,
            kind.as_ptr(),
            kind.len(),
            &mut response,
        ));
        let (mut status, mut response_headers, mut response_body) = (0u16, Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_auth_oauth_oauth_http_response_parts(
            response,
            &mut status,
            &mut response_headers,
            &mut response_body,
        ));
        assert_eq!(status, 200);
        assert!(take(&mut response_headers).contains("cache-control: no-store"));
        let answer = take(&mut response_body);
        let mut canonical = Buffer::EMPTY;
        Check::ok(umilib_auth_oauth_oauth_token_response_decode(
            status,
            answer.as_ptr(),
            answer.len(),
            &mut canonical,
            &mut out_error,
        ));
        assert!(take(&mut canonical).contains(r#""token_type":"Bearer""#));
        // A second exchange of the code is invalid_grant.
        let mut second = ptr::null_mut();
        Check::ok(umilib_auth_oauth_oauth_server_token(
            server,
            request,
            102,
            random,
            kind.as_ptr(),
            kind.len(),
            &mut second,
        ));
        Check::ok(umilib_auth_oauth_oauth_http_response_parts(
            second,
            &mut status,
            &mut response_headers,
            &mut response_body,
        ));
        assert_eq!(status, 400);
        assert!(take(&mut response_body).contains("invalid_grant"));
        take(&mut response_headers);

        for response in [response, second] {
            umilib_auth_oauth_oauth_http_response_free(response);
        }
        umilib_auth_oauth_oauth_endpoint_request_free(request);
        umilib_auth_oauth_oauth_http_request_free(http);
        umilib_auth_oauth_oauth_parameters_free(token_request);
        umilib_auth_oauth_oauth_parameters_free(query);
        umilib_auth_oauth_oauth_authorization_free(authorization);
        umilib_auth_oauth_oauth_client_free(client);
        umilib_auth_oauth_oauth_server_free(server);
        hmac_drbg::free(random.cast());
    }
}

#[test]
fn oauth_resource_server_and_dpop_through_the_c_abi() {
    use umilib::ffi::protocol::jwt::{umilib_protocol_jwt_jwk_free, umilib_protocol_jwt_jwk_from_json};

    unsafe {
        // The key of RFC 9449's examples, public: its thumbprint is the jkt of §6.1.
        let jwk = br#"{"kty":"EC","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA","crv":"P-256"}"#;
        let mut key = ptr::null_mut();
        Check::ok(umilib_protocol_jwt_jwk_from_json(jwk.as_ptr(), jwk.len(), &mut key));
        let mut thumbprint = Buffer::EMPTY;
        Check::ok(umilib_auth_oauth_dpop_proof_thumbprint(key, &mut thumbprint));
        assert_eq!(take(&mut thumbprint), "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
        umilib_protocol_jwt_jwk_free(key);
        let token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
        let mut hash = Buffer::EMPTY;
        Check::ok(umilib_auth_oauth_dpop_proof_access_token_hash(token.as_ptr(), token.len(), &mut hash));
        assert_eq!(take(&mut hash), "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");

        // A resource server that introspects: a request without a token is refused with both
        // schemes and no error code (RFC 6750 §3.1).
        let resource = "https://api.example";
        let es256 = [9u8];
        let mut server = ptr::null_mut();
        Check::ok(umilib_auth_oauth_oauth_resource_server_new(
            resource.as_ptr(),
            resource.len(),
            b"example".as_ptr(),
            7,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
            0,
            false,
            es256.as_ptr(),
            1,
            300,
            60,
            false,
            1024,
            1,
            0,
            &mut server,
        ));
        let mut request = ptr::null_mut();
        Check::ok(umilib_auth_oauth_oauth_endpoint_request_new(
            b"GET".as_ptr(),
            3,
            resource.as_ptr(),
            resource.len(),
            ptr::null(),
            0,
            &mut request,
        ));
        let (mut accepted, mut info, mut refusal) = (true, ptr::null_mut(), ptr::null_mut());
        let active = br#"{"active":true,"scope":"read","client_id":"web","aud":"https://api.example"}"#;
        Check::ok(umilib_auth_oauth_oauth_resource_server_accept_introspection(
            server,
            request,
            active.as_ptr(),
            active.len(),
            0,
            &mut accepted,
            &mut info,
            &mut refusal,
        ));
        assert!(!accepted && info.is_null());
        let (mut status, mut has_nonce, mut nonce, mut challenges) = (0u16, true, Buffer::EMPTY, ptr::null_mut());
        Check::ok(umilib_auth_oauth_oauth_resource_error_parts(
            refusal,
            &mut status,
            &mut has_nonce,
            &mut nonce,
            &mut challenges,
        ));
        assert_eq!((status, has_nonce), (401, false));
        take(&mut nonce);
        let mut count = 0;
        Check::ok(umilib_auth_oauth_oauth_challenges_count(challenges, &mut count));
        assert_eq!(count, 2);
        umilib_auth_oauth_oauth_challenges_free(challenges);
        umilib_auth_oauth_oauth_resource_error_free(refusal);
        // With a Bearer token that introspection says is active, and its scope checked.
        let bearer = "Bearer abc";
        Check::ok(umilib_auth_oauth_oauth_endpoint_request_set_fields(
            request,
            bearer.as_ptr(),
            bearer.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
        ));
        Check::ok(umilib_auth_oauth_oauth_resource_server_accept_introspection(
            server,
            request,
            active.as_ptr(),
            active.len(),
            0,
            &mut accepted,
            &mut info,
            &mut refusal,
        ));
        assert!(accepted && refusal.is_null());
        Check::ok(umilib_auth_oauth_oauth_resource_server_require_scope(
            server,
            info,
            b"read".as_ptr(),
            4,
            0,
            &mut accepted,
            &mut refusal,
        ));
        assert!(accepted);
        Check::ok(umilib_auth_oauth_oauth_resource_server_require_scope(
            server,
            info,
            b"write".as_ptr(),
            5,
            0,
            &mut accepted,
            &mut refusal,
        ));
        assert!(!accepted);
        let mut response = ptr::null_mut();
        Check::ok(umilib_auth_oauth_oauth_resource_error_to_response(refusal, &mut response));
        let (mut headers, mut body) = (Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_auth_oauth_oauth_http_response_parts(response, &mut status, &mut headers, &mut body));
        assert_eq!(status, 403);
        assert!(take(&mut headers).contains(r#"error="insufficient_scope""#));
        take(&mut body);
        umilib_auth_oauth_oauth_http_response_free(response);
        umilib_auth_oauth_oauth_resource_error_free(refusal);
        let (mut has_client, mut client, mut has_subject, mut subject, mut scope, mut audience) =
            (false, Buffer::EMPTY, true, Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY);
        let (mut has_confirmation, mut confirmation, mut has_context, mut context) =
            (true, Buffer::EMPTY, true, Buffer::EMPTY);
        Check::ok(umilib_auth_oauth_oauth_token_info_texts(
            info,
            &mut has_client,
            &mut client,
            &mut has_subject,
            &mut subject,
            &mut scope,
            &mut audience,
            &mut has_confirmation,
            &mut confirmation,
            &mut has_context,
            &mut context,
        ));
        assert!(has_client && !has_subject && !has_confirmation && !has_context);
        assert_eq!(
            (take(&mut client), take(&mut scope), take(&mut audience)),
            ("web".into(), "read".into(), resource.into())
        );
        for buffer in [&mut subject, &mut confirmation, &mut context] {
            take(buffer);
        }
        umilib_auth_oauth_oauth_token_info_free(info);
        umilib_auth_oauth_oauth_endpoint_request_free(request);
        umilib_auth_oauth_oauth_resource_server_free(server);
    }
}
