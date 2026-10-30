"""Tests of umilib.protocol.jwt against RFC 7515 to RFC 7520, RFC 7638, RFC 8037 and RFC 8725, with the
examples of the JOSE Cookbook in tests/vectors/protocol/jwt."""

import json

import pytest

from umilib.auth.cert.key import HashAlgorithm
from umilib.codec.json import JSONValue
from umilib.crypto.random import HMACDRBG
from umilib.hash.sha.v2 import SHA256
from umilib.protocol.jwt import (
    JOSEHeader,
    JWE,
    JWEAlgorithm,
    JWEConfig,
    JWEEncryption,
    JWK,
    JWKSet,
    JWS,
    JWSAlgorithm,
    JWSConfig,
    JWT,
    JWTClaims,
    JWTError,
    JWTValidation,
)
from vectors import ROOT

COOKBOOK = ROOT / "protocol" / "jwt" / "cookbook"
EVERY_JWS = JWSConfig([algorithm for algorithm in JWSAlgorithm if algorithm != JWSAlgorithm.None_])
EXPIRATION = 1300819380


def random(seed: bytes = b"0123456789abcdef0123456789abcdef") -> HMACDRBG:
    return HMACDRBG[SHA256](seed, b"nonce of 16 byte")


def every_jwe() -> JWEConfig:
    config = JWEConfig(list(JWEAlgorithm), list(JWEEncryption))
    config.set_compression(True)
    return config


def jwk(value: dict) -> JWK:
    return JWK.from_json(json.dumps(value))


def header(**parameters: str) -> JOSEHeader:
    return JOSEHeader.decode(json.dumps(parameters))


def test_cookbook_keys_read_back_and_have_their_thumbprints():
    for name in ["3_1.ec_public_key", "3_2.ec_private_key", "3_3.rsa_public_key", "3_4.rsa_private_key", "3_6.symmetric_key_encryption"]:
        value = json.loads((COOKBOOK / "jwk" / f"{name}.json").read_text(encoding="utf-8"))
        key = jwk(value)
        assert json.loads(key.to_json()) == value, name
        assert key.key_id == value["kid"]
        assert key.key_type == value["kty"]
    private = jwk(json.loads((COOKBOOK / "jwk" / "3_2.ec_private_key.json").read_text(encoding="utf-8")))
    assert private.is_secret and not private.to_public().is_secret
    from_key = JWK.from_public_key(private.public_key())
    assert from_key.thumbprint(HashAlgorithm.SHA256) == private.thumbprint(HashAlgorithm.SHA256)
    assert JWK.from_private_key(private.private_key()).is_secret
    # RFC 8037 appendix A.3: the thumbprint of the Ed25519 key.
    ed25519 = jwk({"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})
    assert ed25519.thumbprint(HashAlgorithm.SHA256).hex() == "90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89"
    # RFC 9278 section 3.
    assert ed25519.thumbprint_uri(HashAlgorithm.SHA256) == "urn:ietf:params:oauth:jwk-thumbprint:sha-256:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    key = JWK.symmetric(b"\x01" * 16)
    key.key_id, key.algorithm, key.key_use = "k1", "A128KW", "enc"
    assert (key.key_id, key.algorithm, key.key_use) == ("k1", "A128KW", "enc")
    key.key_use = None
    assert key.key_use is None
    keys = JWKSet()
    keys.push(key)
    keys.push(ed25519)
    assert len(JWKSet.from_json(keys.to_json())) == 2 and keys.find("k1")[0].algorithm == "A128KW"
    with pytest.raises(JWTError) as error:
        JWK.from_json('{"kty":"XYZ"}')
    assert error.value.name == "UnknownKeyType"


def test_jws_follows_the_cookbook():
    for name in ["4_2.rsa-pss_signature", "4_3.ecdsa_signature", "4_4.hmac-sha2_integrity_protection", "4_6.protecting_specific_header_fields", "4_8.multiple_signatures"]:
        example = json.loads((COOKBOOK / "jws" / f"{name}.json").read_text(encoding="utf-8"))
        keys = example["input"]["key"]
        keys = [jwk(key) for key in (keys if isinstance(keys, list) else [keys])]
        output = example["output"]
        if "compact" in output:
            jws = JWS.from_compact(output["compact"])
            assert jws.verify(keys[0], EVERY_JWS) == 0
            assert jws.to_compact() == output["compact"]
        jws = JWS.from_json(json.dumps(output["json"]))
        assert jws.payload == example["input"]["payload"].encode()
        for key in keys:
            jws.verify(key, EVERY_JWS)
        assert json.loads(jws.to_json()) == output["json"], name


def test_jws_signs_and_refuses_what_rfc_8725_refuses():
    key = JWK.symmetric(b"\x07" * 32)
    jws = JWS.new(b"payload")
    jws.sign(header(alg="HS256"), None, key, random())
    assert len(jws) == 1 and jws.signature_header(0).string("alg") == "HS256"
    compact = jws.to_compact()
    assert JWS.from_compact(compact).verify(key, JWSConfig([JWSAlgorithm.HS256])) == 0
    with pytest.raises(JWTError) as error:
        JWS.from_compact(compact).verify(key, JWSConfig([JWSAlgorithm.HS512]))
    assert error.value.name == "AlgorithmNotAllowed"
    unsecured = JWS.new(b"payload")
    unsecured.sign(header(alg="none"), None, key, random())
    with pytest.raises(JWTError):
        unsecured.verify(key, EVERY_JWS)
    unsecured.verify_unsecured()
    detached = JWS.from_compact_detached(jws.to_compact_detached(), b"payload")
    detached.verify(key, JWSConfig([JWSAlgorithm.HS256]))
    assert JWS.from_json_detached(jws.to_flattened_json_detached(), b"payload").payload == b"payload"


def test_jwe_follows_the_cookbook():
    config = every_jwe()
    for path in sorted((COOKBOOK / "jwe").glob("5_*.json")) + [COOKBOOK / "curve25519" / "ecdh-es.json"]:
        example = json.loads(path.read_text(encoding="utf-8"))
        source = example["input"]
        keys = source["key"] if "key" in source else JWK.symmetric(source["pwd"].encode())
        keys = [key if isinstance(key, JWK) else jwk(key) for key in (keys if isinstance(keys, list) else [keys])]
        algorithms = source["alg"] if isinstance(source["alg"], list) else [source["alg"]]
        for member, serialization in example["output"].items():
            jwe = JWE.from_compact(serialization) if member == "compact" else JWE.from_json(json.dumps(serialization))
            for key, name in zip(keys, algorithms):
                if JWEAlgorithm.from_name(name) is None:
                    # RSA1_5 is not implemented (RFC 8725 section 3.2).
                    with pytest.raises(JWTError):
                        jwe.decrypt(key, config, random(b"another seed of 32 bytes........"))
                    continue
                plaintext, _ = jwe.decrypt(key, config, random(b"another seed of 32 bytes........"))
                assert plaintext == source["plaintext"].encode(), f"{path.name} {member}"


def test_jwe_encrypts_for_several_recipients():
    rsa = jwk(json.loads((COOKBOOK / "jwk" / "3_4.rsa_private_key.json").read_text(encoding="utf-8")))
    rsa.key_use = None
    wrap, gcm = JWK.symmetric(b"\x01" * 16), JWK.symmetric(b"\x02" * 32)
    shared = header(cty="text/plain")
    recipients = [(rsa.to_public(), header(alg="RSA-OAEP-256")), (wrap, header(alg="A128KW")), (gcm, header(alg="A256GCMKW"))]
    jwe = JWE.encrypt(b"to all", header(enc="A128CBC-HS256"), shared, recipients, b"aad", random())
    assert len(jwe) == 3 and jwe.joined_header(2).string("alg") == "A256GCMKW"
    read = JWE.from_json(jwe.to_json())
    config = JWEConfig([JWEAlgorithm.RSAOAEP256, JWEAlgorithm.A128KW, JWEAlgorithm.A256GCMKW], [JWEEncryption.A128CBCHS256])
    for index, key in enumerate([rsa, wrap, gcm]):
        assert read.decrypt(key, config, random(b"another seed of 32 bytes........")) == (b"to all", index)
    with pytest.raises(JWTError) as error:
        jwe.to_compact()
    assert error.value.name == "Format"
    single = JWE.encrypt(b"x", header(alg="dir", enc="A128GCM"), None, [(JWK.symmetric(b"\x03" * 16), None)], None, random())
    assert JWE.from_compact(single.to_compact()).to_flattened_json() == single.to_flattened_json()
    with pytest.raises(JWTError) as error:
        single.decrypt(JWK.symmetric(b"\x04" * 16), JWEConfig([JWEAlgorithm.Dir], [JWEEncryption.A128GCM]), random())
    assert error.value.name == "Decryption"


def test_jwt_follows_rfc_7519_and_rfc_8725():
    # RFC 7519 section 3.1 with the key of RFC 7515 appendix A.1.
    key = jwk({"kty": "oct", "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"})
    token = (
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    config = JWSConfig([JWSAlgorithm.HS256])
    jwt = JWT.verify(token, key, config, JWTValidation(EXPIRATION - 1, issuer="joe", token_type="JWT"))
    assert jwt.claims.issuer() == "joe" and jwt.claims.expiration() == EXPIRATION
    assert jwt.claims.value("http://example.com/is_root") is True
    assert jwt.header.string("typ") == "JWT"
    for validation, name in [
        (JWTValidation(EXPIRATION), "Expired"),
        (JWTValidation(EXPIRATION - 1, issuer="john"), "Issuer"),
        (JWTValidation(EXPIRATION - 1, audience="https://example.com"), "Audience"),
        (JWTValidation(EXPIRATION - 1, required=["sub"]), "MissingClaim"),
        (JWTValidation(EXPIRATION - 1, token_type="at+jwt"), "Type"),
    ]:
        with pytest.raises(JWTError) as error:
            JWT.verify(token, key, config, validation)
        assert error.value.name == name
    JWT.verify(token, key, config, JWTValidation(EXPIRATION, leeway=1))


def test_jwts_round_trip_in_every_form():
    claims = JWTClaims()
    claims.set_string("iss", "https://issuer.example")
    claims.set_numeric_date("exp", 2_000_000_000)
    claims.set("aud", JSONValue.parse('["one","two"]'))
    validation = JWTValidation(1_999_999_999, audience="two", issuer="https://issuer.example")
    signing = JWK.symmetric(b"\x09" * 32)
    token = JWT.sign(claims, header(alg="HS256"), signing, random())
    assert JWT.verify(token, signing, JWSConfig([JWSAlgorithm.HS256]), validation).claims == claims
    encryption = JWK.symmetric(b"\x05" * 32)
    decryption = JWEConfig([JWEAlgorithm.Dir], [JWEEncryption.A256GCM])
    token = JWT.encrypt(claims, header(alg="dir", enc="A256GCM"), encryption, random())
    jwt = JWT.decrypt(token, encryption, decryption, validation, random())
    assert jwt.claims.audience() == ["one", "two"]
    nested = JWT.sign_and_encrypt(claims, header(alg="HS256"), signing, header(alg="dir", enc="A256GCM"), encryption, random())
    assert JWE.from_compact(nested).joined_header(0).string("cty") == "JWT"
    jwt = JWT.decrypt_and_verify(nested, encryption, decryption, signing, JWSConfig([JWSAlgorithm.HS256]), validation, random())
    assert jwt.claims == claims
    with pytest.raises(JWTError) as error:
        JWT.decrypt(nested, encryption, decryption, validation, random())
    assert error.value.name == "Type"


def test_the_nested_example_of_the_cookbook():
    example = json.loads((COOKBOOK / "6.nesting_signatures_and_encryption.json").read_text(encoding="utf-8"))
    signing = jwk(example["sign"]["input"]["key"])
    encryption = jwk(example["encrypt"]["input"]["key"])
    validation = JWTValidation(EXPIRATION - 1, issuer="hobbiton.example", token_type="JWT")
    jwt = JWT.decrypt_and_verify(
        example["encrypt"]["output"]["compact"],
        encryption,
        JWEConfig([JWEAlgorithm.RSAOAEP], [JWEEncryption.A128GCM]),
        signing.to_public(),
        JWSConfig([JWSAlgorithm.PS256]),
        validation,
        random(),
    )
    assert jwt.claims.encode() == example["sign"]["input"]["payload"]


def test_configurations_bound_the_work_of_one_object():
    key = JWK.symmetric(b"\x07" * 32)
    jws = JWS.new(b"payload")
    for _ in range(JWSConfig.MAXIMUM_SIGNATURES + 1):
        jws.sign(header(alg="HS256"), None, key, random())
    config = JWSConfig([JWSAlgorithm.HS256])
    with pytest.raises(JWTError) as error:
        jws.verify(key, config)
    assert error.value.name == "Limit"
    config.set_maximum_signatures(JWSConfig.MAXIMUM_SIGNATURES + 1)
    assert jws.verify(key, config) == 0
    wrap = JWK.symmetric(b"\x01" * 16)
    recipients = [(wrap, header(alg="A128KW")) for _ in range(JWEConfig.MAXIMUM_RECIPIENTS + 1)]
    jwe = JWE.encrypt(b"secret", header(enc="A128GCM"), None, recipients, None, random())
    decryption = JWEConfig([JWEAlgorithm.A128KW], [JWEEncryption.A128GCM])
    with pytest.raises(JWTError) as error:
        jwe.decrypt(wrap, decryption, random())
    assert error.value.name == "Limit"
    decryption.set_maximum_recipients(JWEConfig.MAXIMUM_RECIPIENTS + 1)
    assert jwe.decrypt(wrap, decryption, random(b"another seed of 32 bytes........"))[0] == b"secret"


def test_crit_follows_rfc_7515_section_4_1_11():
    key = JWK.symmetric(b"\x07" * 32)
    jws = JWS.new(b"payload")
    jws.sign(JOSEHeader.decode('{"alg":"HS256","crit":["exp"],"exp":1363284000}'), None, key, random())
    with pytest.raises(JWTError) as error:
        jws.verify(key, JWSConfig([JWSAlgorithm.HS256]))
    assert error.value.name == "Critical"
    assert jws.verify(key, JWSConfig([JWSAlgorithm.HS256], critical=["exp"])) == 0
