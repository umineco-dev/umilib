"""Tests of umilib.auth.sasl against RFC 4422, RFC 4505, RFC 4616, RFC 5801, RFC 5802, RFC 7628 and RFC 7677,
and SCRAM recomputed with hashlib and hmac of the Python standard library."""

import base64
import hashlib
import hmac

import pytest

from umilib.auth.sasl import GS2ChannelBinding, GS2Header, SASLError, SASLMechanism
from umilib.auth.sasl.anonymous import ANONYMOUSMessage
from umilib.auth.sasl.external import EXTERNALMessage
from umilib.auth.sasl.oauthbearer import OAUTHBEARERErrorResult, OAUTHBEARERMessage
from umilib.auth.sasl.plain import PLAINMessage
from umilib.auth.sasl.scram import SCRAMClient, SCRAMCredentials, SCRAMError, SCRAMNonce, SCRAMServer, SCRAMServerError
from umilib.codec.stringprep import StringPrepProfile, Unassigned
from umilib.crypto.random import HMACDRBG
from umilib.hash.sha.v1 import SHA1
from umilib.hash.sha.v2 import SHA256, SHA512

# RFC 5802 section 5 (SCRAM-SHA-1) and RFC 7677 section 3 (SCRAM-SHA-256): user "user", password "pencil".
EXAMPLES = {
    SHA1: (
        b"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
        b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
        b"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
        b"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=",
    ),
    SHA256: (
        b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
        b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
        b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
        b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
    ),
}
HASHLIB = {SHA1: "sha1", SHA256: "sha256"}


def random() -> HMACDRBG:
    return HMACDRBG[SHA256](b"0123456789abcdef0123456789abcdef", b"nonce of 16 byte")


@pytest.mark.parametrize("hash", [SHA1, SHA256])
def test_scram_follows_rfc_5802_and_rfc_7677(hash):
    client_first, server_first, client_final, server_final = EXAMPLES[hash]
    client_nonce = client_first.split(b"r=")[1].decode()
    attributes = dict(part.split(b"=", 1) for part in server_first.split(b","))
    salt, iterations = base64.b64decode(attributes[b"s"]), int(attributes[b"i"])
    client = SCRAMClient[hash]("user", "pencil", client_nonce)
    assert client.client_first() == client_first
    server = SCRAMServer[hash]()
    server.receive_client_first(client_first)
    assert server.username == "user"
    credentials = SCRAMCredentials[hash]("pencil", salt, iterations)
    assert server.server_first(credentials, attributes[b"r"].decode()[len(client_nonce) :]) == server_first
    assert client.receive_server_first(server_first) == client_final
    assert server.receive_client_final(client_final) == server_final
    # RFC 5802 section 5: the authenticated identity, for the check of the authorization identity.
    assert (server.username, server.authzid) == ("user", None)
    client.receive_server_final(server_final)
    assert client.mechanism() in (SASLMechanism.SCRAMSHA1, SASLMechanism.SCRAMSHA256)
    kept_salt, kept_iterations, salted = client.salted_secret()
    assert (kept_salt, kept_iterations) == (salt, iterations)
    again = SCRAMClient[hash].from_salted_password("user", kept_salt, kept_iterations, salted, client_nonce)
    again.client_first()
    assert again.receive_server_first(server_first) == client_final


@pytest.mark.parametrize("hash", [SHA1, SHA256])
def test_scram_agrees_with_the_formulas_of_rfc_5802_section_3(hash):
    name = HASHLIB[hash]
    password, salt, iterations = "pässwörd", b"salt of sixteen!", 4096
    client = SCRAMClient[hash]("user", password, "clientnonce")
    first = client.client_first()
    server_first = b"r=clientnonceservernonce,s=" + base64.b64encode(salt) + b",i=4096"
    final = client.receive_server_first(server_first)
    # Hi, HMAC and H of hashlib and hmac, with the password prepared by SASLprep (here unchanged).
    salted = hashlib.pbkdf2_hmac(name, password.encode(), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", name).digest()
    stored_key = hashlib.new(name, client_key).digest()
    without_proof = final.rsplit(b",p=", 1)[0]
    auth_message = first[3:] + b"," + server_first + b"," + without_proof
    signature = hmac.new(stored_key, auth_message, name).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, signature))
    assert final == without_proof + b",p=" + base64.b64encode(proof)
    server_key = hmac.new(salted, b"Server Key", name).digest()
    expected = b"v=" + base64.b64encode(hmac.new(server_key, auth_message, name).digest())
    client.receive_server_final(expected)
    credentials = SCRAMCredentials[hash]("pässwörd", salt, iterations)
    assert credentials.parts() == (salt, iterations, stored_key, bytearray(server_key))
    assert SCRAMCredentials[hash].from_parts(salt, iterations, stored_key, server_key).parts()[2] == stored_key


def test_scram_refuses_what_rfc_5802_refuses():
    nonce = SCRAMNonce.random(random())
    assert len(nonce) == 32
    # A wrong password: the server reports invalid-proof, which the client receives.
    client = SCRAMClient[SHA256]("user", "wrong", nonce)
    server = SCRAMServer[SHA256]()
    server.receive_client_first(client.client_first())
    final = client.receive_server_first(server.server_first(SCRAMCredentials[SHA256]("pencil", b"x" * 16, 4096), "server"))
    with pytest.raises(SCRAMError) as error:
        server.receive_client_final(final)
    assert error.value.name == "InvalidProof"
    rejection = server.reject(SCRAMServerError.InvalidProof)
    assert rejection == b"e=" + SCRAMServerError.InvalidProof.registered_name().encode()
    with pytest.raises(SCRAMError) as error:
        client.receive_server_final(rejection)
    assert error.value.name == "InvalidProof"
    # y from a client of a server that supports channel binding: a downgrade (section 6).
    client = SCRAMClient[SHA256]("user", "pencil", nonce)
    client.set_channel_binding(GS2ChannelBinding.NotOffered)
    server = SCRAMServer[SHA256]()
    server.add_channel_binding(GS2ChannelBinding.TLS_EXPORTER, b"exporter")
    with pytest.raises(SCRAMError) as error:
        server.receive_client_first(client.client_first())
    assert error.value.name == "ServerDoesSupportChannelBinding"
    # p with the channel's data: SCRAM-SHA-256-PLUS.
    client = SCRAMClient[SHA256]("user", "pencil", nonce)
    client.set_channel_binding(GS2ChannelBinding.Required, GS2ChannelBinding.TLS_EXPORTER, b"exporter")
    assert client.mechanism() == SASLMechanism.SCRAMSHA256PLUS
    server = SCRAMServer[SHA256](plus=True)
    server.add_channel_binding(GS2ChannelBinding.TLS_EXPORTER, b"exporter")
    server.receive_client_first(client.client_first())
    final = client.receive_server_first(server.server_first(SCRAMCredentials[SHA256]("pencil", b"x" * 16, 4096), "server"))
    client.receive_server_final(server.receive_client_final(final))
    # Iteration counts below the configuration; an authorization identity.
    client = SCRAMClient[SHA256]("user", "pencil", "abc")
    client.set_iterations(10000, 20000)
    client.set_authzid("admin")
    assert client.client_first() == b"n,a=admin,n=user,r=abc"
    with pytest.raises(SCRAMError) as error:
        client.receive_server_first(b"r=abcdef,s=AQID,i=4096")
    assert error.value.name == "Iterations"
    # SCRAM-SHA-512 is not registered (an expired draft).
    with pytest.raises(TypeError):
        SCRAMClient[SHA512]


def test_plain_follows_rfc_4616():
    # Section 4.
    message = PLAINMessage.decode(b"\x00tim\x00tanstaaftanstaaf")
    assert (message.authzid, message.authcid, message.password) == (None, "tim", "tanstaaftanstaaf")
    assert PLAINMessage.decode(b"Ursel\x00Kurt\x00xipj3plmq").authzid == "Ursel"
    assert bytes(PLAINMessage.new("Ursel", "Kurt", "xipj3plmq").encode()) == b"Ursel\x00Kurt\x00xipj3plmq"
    # Section 2: SASLprep, queries against stored strings (RFC 4013 section 3).
    assert PLAINMessage.new(None, "user", "I­X").verify_password("Ⅸ")
    assert PLAINMessage.prepare("ª", Unassigned.Prohibited) == "a"
    with pytest.raises(SASLError) as error:
        PLAINMessage.decode(b"tim\x00pass")
    assert error.value.name == "Format"
    with pytest.raises(SASLError):
        PLAINMessage.prepare("­", Unassigned.Allowed)


def test_external_anonymous_and_names():
    # RFC 4422 appendix A.
    assert EXTERNALMessage.decode(b"").authzid is None
    assert EXTERNALMessage.new("fred@example.com").encode() == b"fred@example.com"
    # RFC 4505 section 4: "sirhc", sent as c2lyaGM= by IMAP.
    message = ANONYMOUSMessage.decode(base64.b64decode("c2lyaGM="))
    assert message.trace == "sirhc" and not message.is_email()
    assert StringPrepProfile.TRACE.prepare("a b", Unassigned.Allowed) == "a b"
    with pytest.raises(Exception):
        ANONYMOUSMessage.decode("é".encode() * 256)
    # RFC 4422 section 3.1 and the registry.
    assert SASLMechanism.from_name("SCRAM-SHA-256-PLUS") == SASLMechanism.SCRAMSHA256PLUS
    assert SASLMechanism.SCRAMSHA1.registered_name() == "SCRAM-SHA-1"
    assert SASLMechanism.from_name("plain") is None and not SASLMechanism.is_name("plain")
    # RFC 5801 section 4.
    header, rest = GS2Header.decode("p=tls-unique,a=a=2Cb,rest")
    assert header.channel_binding == (GS2ChannelBinding.Required, "tls-unique") and header.authzid == "a,b" and rest == "rest"
    assert GS2Header.new(GS2ChannelBinding.Unsupported, authzid="x=y").encode() == "n,a=x=3Dy,"


def test_oauthbearer_follows_rfc_7628():
    # Section 4.1: the IMAP initial client response.
    response = base64.b64decode(
        "bixhPXVzZXJAZXhhbXBsZS5jb20sAWhvc3Q9c2VydmVyLmV4YW1wbGUuY29tAXBvcnQ9MTQzAWF1dGg9QmVhcmVyIHZGOWRmdDRxbVRjMk52YjNSbGNrQmhiSFJoZG1semRHRXVZMjl0Q2c9PQEB"
    )
    message = OAUTHBEARERMessage.decode(response)
    assert message.header.authzid == "user@example.com"
    assert (message.host(), message.port()) == ("server.example.com", 143)
    assert message.bearer_token() == "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg=="
    assert message.pairs[0] == ("host", "server.example.com")
    made = OAUTHBEARERMessage.new("user@example.com", "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==", "server.example.com", 143)
    assert made.encode() == response
    # Section 4.3: the error result and the dummy response.
    result = OAUTHBEARERErrorResult.decode(
        base64.b64decode(
            "eyJzdGF0dXMiOiJpbnZhbGlkX3Rva2VuIiwic2NvcGUiOiJleGFtcGxlX3Njb3BlIiwib3BlbmlkLWNvbmZpZ3VyYXRpb24iOiJodHRwczovL2V4YW1wbGUuY29tLy53ZWxsLWtub3duL29wZW5pZC1jb25maWd1cmF0aW9uIn0="
        )
    )
    assert (result.status, result.scope) == ("invalid_token", "example_scope")
    assert result.openid_configuration == "https://example.com/.well-known/openid-configuration"
    assert OAUTHBEARERErrorResult.decode(OAUTHBEARERErrorResult.new("invalid_token").encode()).scope is None
    assert OAUTHBEARERMessage.is_dummy(base64.b64decode("AQ=="))
    # auth is REQUIRED; port is a positive integer (section 3.1).
    with pytest.raises(SASLError):
        OAUTHBEARERMessage.decode(b"n,,\x01\x01")
    with pytest.raises(SASLError):
        OAUTHBEARERMessage.new(None, "x", port=0).encode()
    # Section 4.4 has "user=" where RFC 5801 has "a=" (erratum 8564).
    with pytest.raises(SASLError):
        OAUTHBEARERMessage.decode(b"n,user=someuser@example.com,\x01auth=Bearer x\x01\x01")
