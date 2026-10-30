"""Tests of umilib.auth.oauth: the examples of RFC 6749, RFC 7636, RFC 8414 and RFC 9449, a client and
a server talking to each other, and the server answering requests made with the standard library
(hashlib, base64, urllib.parse, json) as an independent client."""

import base64
import hashlib
import json
import re
import urllib.parse
from pathlib import Path

import pytest

from umilib.auth.cert.key import KeyAlgorithm, NamedCurve, PrivateKey
from umilib.auth.oauth import (
    DPoPConfig, DPoPProof, DPoPTarget, DPoPVerifier, OAuthAccessTokenFormat, OAuthAuthorizationFailure, OAuthAuthorizationRequest,
    OAuthAuthorizationResponse, OAuthChallenge, OAuthClient, OAuthClientAuthentication, OAuthClientMethod,
    OAuthClientRegistration, OAuthEndpointRequest, OAuthError, OAuthErrorResponse, OAuthGrant, OAuthGrantRecord,
    OAuthIntrospectionResponse, OAuthMetadata, OAuthMetadataKind, OAuthParameters, OAuthPresentedToken,
    OAuthResourceConfig, OAuthResourceError, OAuthResourceServer, OAuthScope, OAuthServer, OAuthServerConfig,
    OAuthTokenRequest, OAuthTokenResponse, OAuthTokenScheme, OAuthTokenValidation, PKCEChallenge, PKCEMethod,
    PKCEVerifier,
)  # fmt: skip
from umilib.crypto.random import HMACDRBG
from umilib.hash.sha.v2 import SHA256
from umilib.protocol.jwt import JWK, JWSAlgorithm

VECTORS = Path(__file__).resolve().parents[3] / "tests" / "vectors" / "auth" / "oauth"
ISSUER = "https://as.example"
REDIRECT = "https://app.example/cb"


def random() -> HMACDRBG:
    return HMACDRBG[SHA256](b"\x07" * 32, b"\x0b" * 16, b"umilib oauth tests")


def rfc(name: str) -> str:
    return (VECTORS / name).read_text(encoding="utf-8")


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


def test_pkce_follows_rfc_7636_and_hashlib():
    text = rfc("rfc7636.txt")
    verifier = re.search(r"dBjftJeZ4CVP\S+", text).group(0)
    challenge = re.search(r"E9Melhoa2Ow\S+", text).group(0)
    assert PKCEVerifier(verifier).challenge().value == challenge == s256(verifier)
    assert PKCEChallenge.new(PKCEMethod.S256, challenge).verify(PKCEVerifier(verifier))
    generated = PKCEVerifier.generate(random())
    assert len(generated.as_str()) == 43
    assert generated.challenge().value == s256(generated.as_str())
    for bad in ["a" * 42, "a" * 129, "a" * 42 + "+"]:
        with pytest.raises(OAuthError):
            PKCEVerifier(bad)
    with pytest.raises(OAuthError):
        PKCEMethod.parse("plain")


def test_parameters_and_messages():
    parameters = OAuthParameters.parse(b"client_id=a&resource=r1&resource=r2&state=&scope=b+a")
    assert parameters.pairs() == [("client_id", "a"), ("resource", "r1"), ("resource", "r2"), ("scope", "b a")]
    assert parameters.all("resource") == ["r1", "r2"]
    with pytest.raises(OAuthError) as error:
        OAuthParameters.parse(b"state=1&state=2")
    assert error.value.name == "Repeated"
    request = OAuthAuthorizationRequest.from_parameters(parameters)
    assert (request.client_id, request.resources, str(request.scope)) == ("a", ["r1", "r2"], "b a")
    assert OAuthAuthorizationRequest.from_parameters(request.to_parameters()) == request
    # The urlencoded form of Python reads the same.
    assert urllib.parse.parse_qsl(parameters.encode()) == parameters.pairs()

    # §4.1.2: the Location of the example, folded over two lines.
    folded = re.search(r"Location: (https://client\.example\.com/cb\?code=\S+)\s*\n\s*(&state=\S+)", rfc("rfc6749.txt"))
    location = folded.group(1) + folded.group(2)
    response = OAuthAuthorizationResponse.from_parameters(OAuthParameters.from_query(location))
    assert (response.code, response.state) == ("SplxlOBeZQQYbYS6WxSbIA", "xyz")
    with pytest.raises(OAuthError) as error:
        OAuthAuthorizationResponse.from_parameters(OAuthParameters.parse(b"error=access_denied&state=x"))
    assert error.value.name == "Response" and error.value.response.code == "access_denied"

    body = OAuthParameters.parse(b"grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&client_id=a&client_secret=b&scope=read")
    token_request = OAuthTokenRequest.from_parameters(body)
    assert isinstance(token_request.grant, OAuthGrant.RefreshToken)
    assert token_request.to_parameters().encode() == "grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&scope=read"
    with pytest.raises(OAuthError):
        OAuthTokenRequest.from_parameters(OAuthParameters.parse(b"grant_type=password&username=a&password=b"))

    tokens = OAuthTokenResponse.decode(200, b'{"access_token":"2YotnFZFEjr1zCsicMWpAA","token_type":"example","expires_in":3600,"example_parameter":"example_value"}')
    assert (tokens.expires_in, tokens.other) == (3600, {"example_parameter": "example_value"})
    with pytest.raises(OAuthError) as error:
        OAuthTokenResponse.decode(400, b'{"error":"invalid_request"}')
    assert error.value.response == OAuthErrorResponse("invalid_request")
    assert OAuthErrorResponse("invalid_grant", "used").encode() == '{"error":"invalid_grant","error_description":"used"}'
    with pytest.raises(OAuthError):
        OAuthErrorResponse("bad\"code").check()
    assert str(OAuthScope.parse("b a b")) == "b a"
    assert OAuthScope.parse("a").is_subset_of(OAuthScope.parse("a b"))
    assert not OAuthScope.parse("c").is_subset_of(OAuthScope.parse("a b"))


def test_metadata_follows_rfc_8414():
    assert OAuthMetadata.location(OAuthMetadataKind.Server, "https://example.com/issuer1") == "https://example.com/.well-known/oauth-authorization-server/issuer1"
    assert OAuthMetadata.location(OAuthMetadataKind.Resource, "https://resource.example.com/resource1") == "https://resource.example.com/.well-known/oauth-protected-resource/resource1"
    metadata = OAuthMetadata.decode(OAuthMetadataKind.Server, b'{"issuer":"https://server.example.com","token_endpoint_auth_methods_supported":["client_secret_basic","private_key_jwt"]}')
    metadata.check("https://server.example.com")
    with pytest.raises(OAuthError) as error:
        metadata.check("https://server.example.com/")
    assert error.value.name == "Issuer"
    assert metadata.lists(OAuthMetadata.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, "private_key_jwt")


def server() -> OAuthServer:
    config = OAuthServerConfig.new(ISSUER)
    assert config.require_pkce and config.token_endpoint == f"{ISSUER}/token"
    server = OAuthServer(config)
    server.register(OAuthClientRegistration.public("app", [REDIRECT], OAuthScope.parse("read write")))
    web = OAuthClientRegistration.confidential("web", OAuthClientMethod.SecretBasic, "s3cret", [OAuthGrant.AUTHORIZATION_CODE, OAuthGrant.CLIENT_CREDENTIALS, OAuthGrant.REFRESH_TOKEN], OAuthScope.parse("read"))
    web.redirect_uris = [REDIRECT]
    server.register(web)
    api = OAuthClientRegistration.confidential("api", OAuthClientMethod.SecretPost, "api-secret", [], OAuthScope.parse("read"))
    api.introspection = True
    server.register(api)
    return server


def received(http) -> OAuthEndpointRequest:
    return OAuthEndpointRequest(http.method, http.uri, http.header("authorization"), http.header("dpop"), http.header("content-type"), http.body)


def post(body: str, authorization: str | None = None, uri: str = f"{ISSUER}/token") -> OAuthEndpointRequest:
    return OAuthEndpointRequest("POST", uri, authorization, None, "application/x-www-form-urlencoded", body.encode())


def test_client_and_server_run_the_code_grant():
    generator = random()
    oauth = server()
    metadata = oauth.metadata()
    metadata.check(ISSUER)
    client = OAuthClient(metadata, OAuthClientAuthentication.SecretBasic("web", "s3cret"), REDIRECT)
    url = client.authorize(OAuthScope.parse("read"), [], 100, generator)
    authorization = oauth.authorize(OAuthParameters.from_query(str(url)), 100)
    assert (authorization.client_id, authorization.redirect_uri, str(authorization.scope)) == ("web", REDIRECT, "read")
    redirect = oauth.approve(authorization, OAuthGrantRecord("web", "alice", OAuthScope.parse("read")), 100, generator)
    token_request = client.callback(redirect, 101)
    with pytest.raises(OAuthError) as error:
        client.callback(redirect, 101)
    assert error.value.name == "State"
    http = client.token_request(token_request, 101, generator)
    assert http.header("authorization") == "Basic " + base64.b64encode(b"web:s3cret").decode()
    response = oauth.token(received(http), 101, generator)
    assert response.status == 200 and response.header("cache-control") == "no-store"
    tokens = OAuthTokenResponse.decode(response.status, response.body)
    assert tokens.is_token_type("Bearer") and tokens.refresh_token
    # The resource server learns of it by introspection (RFC 7662).
    answer = oauth.introspect(post(urllib.parse.urlencode({"token": tokens.access_token, "client_id": "api", "client_secret": "api-secret"}), uri=f"{ISSUER}/introspect"), 102)
    introspection = OAuthIntrospectionResponse.decode(answer.status, answer.body)
    assert introspection.active and introspection.subject == "alice"
    api = OAuthResourceServer(OAuthResourceConfig(ISSUER + "/api", OAuthTokenValidation.Introspection(), realm="example"))
    request = OAuthEndpointRequest("GET", ISSUER + "/api", f"Bearer {tokens.access_token}")
    info = api.accept_introspection(request, introspection, 102)
    assert (info.client_id, info.subject) == ("web", "alice")
    api.require_scope(info, OAuthScope.parse("read"), OAuthTokenScheme.Bearer)
    with pytest.raises(OAuthResourceError) as refusal:
        api.require_scope(info, OAuthScope.parse("write"), OAuthTokenScheme.Bearer)
    assert refusal.value.status == 403
    assert refusal.value.challenges[0].get("scope") == "write"
    assert refusal.value.to_response().header("www-authenticate").startswith('Bearer realm="example", error="insufficient_scope"')
    with pytest.raises(OAuthResourceError) as refusal:
        api.accept_introspection(OAuthEndpointRequest("GET", ISSUER + "/api"), introspection, 102)
    assert refusal.value.status == 401 and len(refusal.value.challenges) == 2


def test_the_server_answers_the_standard_library():
    oauth = server()
    generator = random()
    # A client of the standard library: PKCE with hashlib, the request with urllib.parse.
    verifier = base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode()
    query = urllib.parse.urlencode({"response_type": "code", "client_id": "app", "redirect_uri": REDIRECT, "state": "s", "code_challenge": s256(verifier), "code_challenge_method": "S256"})
    authorization = oauth.authorize(OAuthParameters.parse(query.encode()), 0)
    redirect = oauth.approve(authorization, OAuthGrantRecord("app", "bob", OAuthScope.parse("read")), 0, generator)
    split = urllib.parse.urlsplit(str(redirect))
    returned = dict(urllib.parse.parse_qsl(split.query))
    assert (returned["state"], returned["iss"]) == ("s", ISSUER)
    body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": returned["code"], "redirect_uri": REDIRECT, "client_id": "app", "code_verifier": verifier})
    response = oauth.token(post(body), 1, generator)
    tokens = json.loads(response.body)
    assert response.status == 200 and tokens["token_type"] == "Bearer" and tokens["scope"] == "read"
    # Refresh with the standard library, then revoke.
    body = urllib.parse.urlencode({"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": "app"})
    refreshed = json.loads(oauth.token(post(body), 2, generator).body)
    assert refreshed["refresh_token"] != tokens["refresh_token"]
    reused = oauth.token(post(body), 3, generator)
    assert json.loads(reused.body)["error"] == "invalid_grant"
    # Client credentials with Basic credentials of base64, and a wrong secret.
    basic = "Basic " + base64.b64encode(b"web:s3cret").decode()
    assert oauth.token(post("grant_type=client_credentials", basic), 4, generator).status == 200
    wrong = oauth.token(post("grant_type=client_credentials", "Basic " + base64.b64encode(b"web:x").decode()), 4, generator)
    assert wrong.status == 401 and wrong.header("www-authenticate").startswith("Basic")
    # Refused requests at the authorization endpoint.
    with pytest.raises(OAuthAuthorizationFailure) as failure:
        oauth.authorize(OAuthParameters.parse(urllib.parse.urlencode({"response_type": "code", "client_id": "app", "redirect_uri": "https://evil.example/cb"}).encode()), 0)
    assert failure.value.local is not None
    with pytest.raises(OAuthAuthorizationFailure) as failure:
        oauth.authorize(OAuthParameters.parse(urllib.parse.urlencode({"response_type": "token", "client_id": "app", "redirect_uri": REDIRECT, "state": "s"}).encode()), 0)
    assert dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(str(failure.value.redirect)).query))["error"] == "unsupported_response_type"


def test_device_and_pushed_requests():
    oauth = server()
    generator = random()
    tv = OAuthClientRegistration.public("tv", [], OAuthScope.parse("read"))
    tv.grant_types = [OAuthGrant.DEVICE_CODE]
    oauth.register(tv)
    answer = json.loads(oauth.device_authorize(post("client_id=tv", uri=f"{ISSUER}/device"), 0, generator).body)
    assert re.fullmatch(r"[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}", answer["user_code"])
    poll = urllib.parse.urlencode({"grant_type": OAuthGrant.DEVICE_CODE, "device_code": answer["device_code"], "client_id": "tv"})
    assert json.loads(oauth.token(post(poll), 1, generator).body)["error"] == "authorization_pending"
    record = oauth.device(answer["user_code"].lower(), 2)
    assert record is not None and record.client_id == "tv"
    oauth.device_approve(answer["user_code"], OAuthGrantRecord("tv", "carol", OAuthScope.parse("read")), 2)
    assert oauth.token(post(poll), 10, generator).status == 200

    challenge = s256("v" * 43)
    pushed = urllib.parse.urlencode({"response_type": "code", "client_id": "app", "redirect_uri": REDIRECT, "code_challenge": challenge, "code_challenge_method": "S256"})
    response = oauth.push(post(pushed, uri=f"{ISSUER}/par"), 0, generator)
    assert response.status == 201
    request_uri = json.loads(response.body)["request_uri"]
    authorization = oauth.authorize(OAuthParameters.parse(urllib.parse.urlencode({"client_id": "app", "request_uri": request_uri}).encode()), 1)
    assert authorization.redirect_uri == REDIRECT


def test_dpop_and_jwt_access_tokens():
    generator = random()
    text = rfc("rfc9449.txt")
    joined = re.search(r"DPoP: (eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2[^\n]*\\\n(?:\s+[^\n]*\\\n)*\s+[^\n]*)", text).group(1)
    proof = re.sub(r"\\\n\s*", "", joined).strip()
    checked = DPoPProof.verify(proof, [JWSAlgorithm.ES256], DPoPTarget("POST", "https://server.example.com/token"), 1562262616, 60, 60)
    assert checked.thumbprint == "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    assert checked.claims["htm"] == "POST"

    signing = JWK.from_private_key(PrivateKey.generate(KeyAlgorithm.ec(NamedCurve.P256), generator))
    config = OAuthServerConfig.new(ISSUER)
    config.access_token_format = OAuthAccessTokenFormat.JWT(signing, JWSAlgorithm.ES256, "https://api.example")
    oauth = OAuthServer(config)
    oauth.register(OAuthClientRegistration.confidential("web", OAuthClientMethod.SecretBasic, "s3cret", [OAuthGrant.CLIENT_CREDENTIALS], OAuthScope.parse("read")))
    client_key = JWK.from_private_key(PrivateKey.generate(KeyAlgorithm.ec(NamedCurve.P256), generator))
    token_proof = DPoPProof.create(client_key, JWSAlgorithm.ES256, DPoPTarget("POST", f"{ISSUER}/token"), 0, None, generator)
    request = OAuthEndpointRequest("POST", f"{ISSUER}/token", OAuthClientAuthentication.basic_credentials("web", "s3cret"), token_proof, "application/x-www-form-urlencoded", b"grant_type=client_credentials")
    tokens = OAuthTokenResponse.decode(200, oauth.token(request, 0, generator).body)
    assert tokens.is_token_type("DPoP")
    api = OAuthResourceServer(OAuthResourceConfig("https://api.example", OAuthTokenValidation.JWT(ISSUER, oauth.jwks(), [JWSAlgorithm.ES256])))
    resource_proof = DPoPProof.create(client_key, JWSAlgorithm.ES256, DPoPTarget("GET", "https://api.example/items", tokens.access_token), 1, None, generator)
    info = api.accept_jwt(OAuthEndpointRequest("GET", "https://api.example/items", f"DPoP {tokens.access_token}", resource_proof), 1)
    assert info.confirmation == DPoPProof.thumbprint_of(client_key.to_public())
    with pytest.raises(OAuthResourceError) as refusal:
        api.accept_jwt(OAuthEndpointRequest("GET", "https://api.example/items", f"Bearer {tokens.access_token}"), 1)
    assert refusal.value.challenges[0].is_scheme("DPoP")
    # A verifier takes a proof once (RFC 9449 §11.1), and one that requires a nonce answers
    # use_dpop_nonce (§8), both as the error response of the failure.
    verifier = DPoPVerifier()
    proof = DPoPProof.create(client_key, JWSAlgorithm.ES256, DPoPTarget("POST", "https://a/t"), 0, None, generator)
    assert verifier.check(proof, DPoPTarget("POST", "https://a/t"), 0).thumbprint == info.confirmation
    with pytest.raises(OAuthError) as error:
        verifier.check(proof, DPoPTarget("POST", "https://a/t"), 0)
    assert error.value.response.code == "invalid_dpop_proof"
    strict = DPoPVerifier(DPoPConfig(require_nonce=True))
    nonce = strict.rotate_nonce(generator)
    with pytest.raises(OAuthError) as error:
        strict.check(DPoPProof.create(client_key, JWSAlgorithm.ES256, DPoPTarget("POST", "https://a/t"), 0, None, generator), DPoPTarget("POST", "https://a/t"), 0)
    assert error.value.response.code == "use_dpop_nonce"
    assert strict.nonce() == nonce
    assert strict.check(DPoPProof.create(client_key, JWSAlgorithm.ES256, DPoPTarget("POST", "https://a/t"), 0, nonce, generator), DPoPTarget("POST", "https://a/t"), 0)


def test_challenges_and_presented_tokens():
    parsed = OAuthChallenge.parse('Bearer realm="example", error="invalid_token", error_description="The access token expired", DPoP algs="ES256 PS256"')
    assert [challenge.scheme for challenge in parsed] == ["Bearer", "DPoP"]
    assert parsed[0].error() == OAuthErrorResponse("invalid_token", "The access token expired")
    assert OAuthChallenge.parse(parsed[1].encode()) == [parsed[1]]
    assert OAuthPresentedToken.from_authorization("Bearer mF_9.B5f-4.1JqM") == OAuthPresentedToken(OAuthTokenScheme.Bearer, "mF_9.B5f-4.1JqM")
    assert OAuthPresentedToken.from_authorization("Basic YTpi") is None
    with pytest.raises(OAuthError):
        OAuthPresentedToken.from_authorization("Bearer a b")


def test_the_review_fixes_hold_in_python():
    oauth = server()
    generator = random()
    authorization = oauth.authorize(OAuthParameters.parse(urllib.parse.urlencode({"response_type": "code", "client_id": "app", "redirect_uri": REDIRECT, "code_challenge": s256("v" * 43), "code_challenge_method": "S256"}).encode()), 0)
    # A decision needs a resource owner, as in Rust.
    with pytest.raises(OAuthError):
        oauth.approve(authorization, OAuthGrantRecord("app", None, OAuthScope.parse("read")), 0, generator)
    # An empty scope is granted and left out of the response.
    redirect = oauth.approve(authorization, OAuthGrantRecord("app", "alice", OAuthScope()), 0, generator)
    assert "code=" in str(redirect)
    config = OAuthServerConfig.new(ISSUER)
    assert JWSAlgorithm.ES256 in config.assertion_algorithms and JWSAlgorithm.ES256 in config.dpop.algorithms
    assert config.maximum_tokens_per_client == 4096 and config.user_code_length == 8
    assert str(OAuthScope.parse("a b c").intersection(OAuthScope.parse("c a"))) == "a c"
    with pytest.raises(OAuthError):
        OAuthChallenge("Bearer", [("error_description", "a\r\nb")]).encode()
    api = OAuthResourceServer(OAuthResourceConfig("https://api.example", OAuthTokenValidation.Introspection(), realm="r"))
    with pytest.raises(OAuthResourceError) as refusal:
        api.accept_introspection(OAuthEndpointRequest("GET", "https://api.example"), OAuthIntrospectionResponse(True), 0)
    assert refusal.value.to_response().status == 401
    assert refusal.value.to_response().header("www-authenticate").startswith('Bearer realm="r"')
    with pytest.raises(OAuthError):
        OAuthResourceServer(OAuthResourceConfig("https://api.example", OAuthTokenValidation.Introspection(), realm="a\r\nb"))
