"""OAuth 2.0 (RFC 6749) with the practices of RFC 9700: the authorization code grant with PKCE
(RFC 7636, S256 only), client credentials, refresh tokens, Bearer and DPoP tokens (RFC 6750,
RFC 9449), metadata (RFC 8414, RFC 9728), the issuer parameter (RFC 9207), resource indicators
(RFC 8707), JWT client authentication (RFC 7523), introspection (RFC 7662), revocation
(RFC 7009), pushed authorization requests (RFC 9126), device authorization (RFC 8628), JWT access
tokens (RFC 9068) and step-up authentication (RFC 9470). Mirrors ``umilib::auth::oauth``.

Messages are values read from and written to :class:`OAuthParameters` or JSON, checked by the
Rust types. :class:`OAuthClient`, :class:`OAuthServer` and :class:`OAuthResourceServer` work
without I/O: the HTTP requests and responses they make (:class:`OAuthHTTPRequest`,
:class:`OAuthHTTPResponse`) are sent by the user, and the requests their endpoints receive are
:class:`OAuthEndpointRequest`. Times are seconds since 1970. Errors are :class:`OAuthError`; an
error the other side answered with is ``Response``, its :attr:`OAuthError.response` the
:class:`OAuthErrorResponse`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
import json
from typing import Any, ClassVar

from umilib.codec.uri import URIReference
from umilib.crypto.random import Random
from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Text
from umilib.protocol.jwt import JWK, JWKSet, JWSAlgorithm


__all__ = [
    "DPoPConfig", "DPoPProof", "DPoPTarget", "DPoPVerifier", "OAuthAccessTokenFormat", "OAuthAuthorization",
    "OAuthAuthorizationFailure", "OAuthAuthorizationRequest", "OAuthAuthorizationResponse", "OAuthChallenge",
    "OAuthClient", "OAuthClientAuthentication", "OAuthClientMethod", "OAuthClientRegistration",
    "OAuthDeviceAuthorizationResponse", "OAuthDeviceRecord", "OAuthEndpointRequest", "OAuthError", "OAuthErrorCode",
    "OAuthErrorResponse", "OAuthGrant", "OAuthGrantRecord", "OAuthHTTPRequest", "OAuthHTTPResponse",
    "OAuthIntrospectionResponse", "OAuthMetadata", "OAuthMetadataKind", "OAuthParameters", "OAuthPresentedToken",
    "OAuthPushedAuthorizationResponse", "OAuthResourceConfig", "OAuthResourceError", "OAuthResourceServer",
    "OAuthScope", "OAuthServer", "OAuthServerConfig", "OAuthTokenInfo", "OAuthTokenRequest", "OAuthTokenResponse",
    "OAuthTokenScheme", "OAuthTokenValidation", "PKCEChallenge", "PKCEMethod", "PKCEVerifier",
]  # fmt: skip


class OAuthError(FFIError):
    """An error of OAuth: ``Repeated``, ``Missing``, ``Invalid``, ``Response`` (the other side
    answered with an error, in :attr:`response`), ``State``, ``Issuer`` or ``Limit``."""

    response: OAuthErrorResponse | None = None


Library.register_error("auth.oauth", OAuthError)


class Calls:
    """The calls of this module whose errors may carry an error response."""

    @staticmethod
    def with_response(name: str, *arguments: Any) -> None:
        """Calls ``name`` with a trailing ``out_error`` buffer and raises its error, with the error
        response it wrote, if any."""
        library = Library.default()
        error = Buffer()
        status = library.function(name)(*arguments, ctypes.byref(error))
        text = library.take(error)
        failure = library.error(status)
        if failure is None:
            return
        if isinstance(failure, OAuthError) and failure.name == "Response" and text:
            failure.response = OAuthErrorResponse.decode(text)
        raise failure

    @staticmethod
    def text(name: str, *arguments: Any) -> str:
        return Library.default().output(name, *arguments).decode("utf-8")

    @staticmethod
    def lines(text: str) -> list[str]:
        return text.split("\n") if text else []

    @staticmethod
    def header_pairs(text: str) -> list[tuple[str, str]]:
        pairs = []
        for line in Calls.lines(text):
            name, _, value = line.partition(":")
            pairs.append((name.strip(), value.strip()))
        return pairs

    @staticmethod
    def strings(texts: list[str] | None) -> tuple[Any, int, list[bytes]]:
        return Text.array(texts) if texts is not None else (None, 0, [])

    @staticmethod
    def algorithms(algorithms: list[JWSAlgorithm]) -> tuple[Any, int]:
        return Bytes.readable(bytes(int(algorithm) for algorithm in algorithms))


# Parameters, scopes and PKCE.


class OAuthParameters(Handle):
    """The parameters of a request or a response: the name and value pairs of a query or a form body
    (RFC 6749 Appendix B), in order. A parameter without a value is omitted, and one given twice
    fails with ``Repeated`` unless it is repeatable (RFC 6749 §3.1, §3.2)."""

    FREE = "umilib_auth_oauth_oauth_parameters_free"
    REPEATABLE: ClassVar[list[str]] = ["resource"]

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer if pointer is not None else Handle.create("umilib_auth_oauth_oauth_parameters_new"))

    @staticmethod
    def parse(data: bytes, repeatable: list[str] | None = None) -> OAuthParameters:
        """The parameters of the form-encoded ``data``, those of ``repeatable`` allowed more than once."""
        names = Text.array(repeatable if repeatable is not None else OAuthParameters.REPEATABLE)
        return OAuthParameters(Handle.create("umilib_auth_oauth_oauth_parameters_parse", *Bytes.readable(data), names[0], names[1]))

    @staticmethod
    def parse_with(data: bytes, repeatable: list[str]) -> OAuthParameters:
        return OAuthParameters.parse(data, repeatable)

    @staticmethod
    def from_query(uri: str) -> OAuthParameters:
        """The parameters of the query of the URI reference ``uri``."""
        return OAuthParameters(Handle.create("umilib_auth_oauth_oauth_parameters_from_query", *Text.encode(str(uri))))

    def add_to_query(self, uri: str) -> URIReference:
        """``uri`` with these parameters added to its query, which it keeps (RFC 6749 §3.1)."""
        return URIReference.parse(Calls.text("umilib_auth_oauth_oauth_parameters_add_to_query", self.handle, *Text.encode(str(uri))))

    def pairs(self) -> list[tuple[str, str]]:
        count = self.library.value("umilib_auth_oauth_oauth_parameters_count", ctypes.c_size_t, self.handle)
        pairs = []
        for index in range(count):
            name, value = Buffer(), Buffer()
            self.library.call("umilib_auth_oauth_oauth_parameters_entry", self.handle, index, ctypes.byref(name), ctypes.byref(value))
            pairs.append((self.library.take(name).decode("utf-8"), self.library.take(value).decode("utf-8")))
        return pairs

    def get(self, name: str) -> str | None:
        """The value of ``name``: the first if it is repeatable."""
        value = self.library.optional("umilib_auth_oauth_oauth_parameters_get", Buffer, self.handle, *Text.encode(name))
        return None if value is None else value.decode("utf-8")

    def all(self, name: str) -> list[str]:
        """Every value of ``name``, in order."""
        return [value for key, value in self.pairs() if key == name]

    def required(self, name: str) -> str:
        """The value of ``name``, which is required; raises ``Missing`` without one."""
        value = self.get(name)
        if value is None:
            raise OAuthError("auth.oauth", "Missing", f"the parameter {name} is missing")
        return value

    def push(self, name: str, value: str) -> None:
        """Appends ``name`` of ``value``; an empty value is not added."""
        self.library.call("umilib_auth_oauth_oauth_parameters_push", self.handle, *Text.encode(name), *Text.encode(value))

    def push_optional(self, name: str, value: str | None) -> None:
        if value is not None:
            self.push(name, value)

    def remove(self, name: str) -> None:
        self.library.call("umilib_auth_oauth_oauth_parameters_remove", self.handle, *Text.encode(name))

    def encode(self) -> str:
        """The parameters in the form encoding."""
        return Calls.text("umilib_auth_oauth_oauth_parameters_encode", self.handle)

    @staticmethod
    def of(pairs: list[tuple[str, str]]) -> OAuthParameters:
        parameters = OAuthParameters()
        for name, value in pairs:
            parameters.push(name, value)
        return parameters


@dataclasses.dataclass(frozen=True)
class OAuthScope:
    """A scope (RFC 6749 §3.3): scope tokens whose order does not matter, each once."""

    tokens: tuple[str, ...] = ()

    @staticmethod
    def parse(text: str) -> OAuthScope:
        """The scope of the space-delimited ``text``."""
        normalized = Calls.text("umilib_auth_oauth_oauth_scope_parse", *Text.encode(text))
        return OAuthScope(tuple(normalized.split(" ")))

    @staticmethod
    def is_nqchar(byte: int) -> bool:
        """Whether ``byte`` is an NQCHAR (RFC 6749 Appendix A): a character of a scope token."""
        return byte == 0x21 or 0x23 <= byte <= 0x5B or 0x5D <= byte <= 0x7E

    def insert(self, token: str) -> OAuthScope:
        """This scope with ``token``, which must be a scope token."""
        if token in self.tokens:
            OAuthScope.parse(token)
            return self
        return OAuthScope.parse(" ".join((*self.tokens, token)))

    def contains(self, token: str) -> bool:
        return token in self.tokens

    def is_subset_of(self, other: OAuthScope) -> bool:
        """Whether every token of this scope is in ``other``."""
        if not self.tokens:
            return True
        if not other.tokens:
            return False
        return Library.default().value("umilib_auth_oauth_oauth_scope_is_subset_of", ctypes.c_bool, *Text.encode(str(self)), *Text.encode(str(other)))

    def intersection(self, other: OAuthScope) -> OAuthScope:
        """The tokens of this scope that are also in ``other``."""
        if not self.tokens or not other.tokens:
            return OAuthScope()
        text = Calls.text("umilib_auth_oauth_oauth_scope_intersection", *Text.encode(str(self)), *Text.encode(str(other)))
        return OAuthScope(tuple(text.split(" "))) if text else OAuthScope()

    def is_empty(self) -> bool:
        return not self.tokens

    def __str__(self) -> str:
        return " ".join(self.tokens)


class PKCEMethod(enum.IntEnum):
    """A transformation of a code verifier (RFC 7636 §4.2); only S256 is taken (RFC 9700 §2.1.1)."""

    S256 = 0

    def as_str(self) -> str:
        return "S256"

    @staticmethod
    def parse(name: str) -> PKCEMethod:
        """The method named ``name``; ``plain`` and unknown names raise ``Invalid``."""
        return PKCEMethod(Library.default().value("umilib_auth_oauth_pkce_method_parse", ctypes.c_uint8, *Text.encode(name)))


class PKCEVerifier(Handle):
    """A code verifier (RFC 7636 §4.1): 43 to 128 unreserved characters, zeroized when released."""

    FREE = "umilib_auth_oauth_pkce_verifier_free"
    MINIMUM_LENGTH: ClassVar[int] = 43
    MAXIMUM_LENGTH: ClassVar[int] = 128
    RANDOM_OCTETS: ClassVar[int] = 32

    def __init__(self, text: str | None = None, pointer: int | None = None) -> None:
        if pointer is None:
            pointer = Handle.create("umilib_auth_oauth_pkce_verifier_new", *Text.encode(text or ""))
        super().__init__(pointer)

    @staticmethod
    def new(text: str) -> PKCEVerifier:
        return PKCEVerifier(text)

    @staticmethod
    def generate(random: Random) -> PKCEVerifier:
        """A verifier of 32 random octets, base64url-encoded."""
        return PKCEVerifier(pointer=Handle.create("umilib_auth_oauth_pkce_verifier_generate", *random.source()))

    def as_str(self) -> str:
        return Calls.text("umilib_auth_oauth_pkce_verifier_text", self.handle)

    def challenge(self, method: PKCEMethod = PKCEMethod.S256) -> PKCEChallenge:
        """The challenge of this verifier by ``method`` (§4.2)."""
        return PKCEChallenge(method, Calls.text("umilib_auth_oauth_pkce_verifier_challenge", self.handle, int(method)))


@dataclasses.dataclass(frozen=True)
class PKCEChallenge:
    """A code challenge (RFC 7636 §4.2) and the method that made it."""

    method: PKCEMethod
    value: str

    @staticmethod
    def new(method: PKCEMethod, value: str) -> PKCEChallenge:
        """The challenge ``value``, checked: for S256, 43 base64url characters of a SHA-256 digest."""
        Library.default().call("umilib_auth_oauth_pkce_challenge_check", int(method), *Text.encode(value))
        return PKCEChallenge(method, value)

    def verify(self, verifier: PKCEVerifier) -> bool:
        """Whether ``verifier`` is the verifier of this challenge (§4.6), compared in constant time."""
        return Library.default().value("umilib_auth_oauth_pkce_challenge_verify", ctypes.c_bool, int(self.method), *Text.encode(self.value), verifier.handle)


# Error responses and messages.


class OAuthErrorCode:
    """The error codes of RFC 6749 §11.4 and of the specifications this module implements; a code is
    its text, and any other ``1*NQSCHAR`` is taken too."""

    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    INVALID_SCOPE = "invalid_scope"
    ACCESS_DENIED = "access_denied"
    UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
    SERVER_ERROR = "server_error"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
    INVALID_TOKEN = "invalid_token"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    UNSUPPORTED_TOKEN_TYPE = "unsupported_token_type"
    AUTHORIZATION_PENDING = "authorization_pending"
    SLOW_DOWN = "slow_down"
    EXPIRED_TOKEN = "expired_token"
    INVALID_TARGET = "invalid_target"
    INVALID_DPOP_PROOF = "invalid_dpop_proof"
    USE_DPOP_NONCE = "use_dpop_nonce"
    INSUFFICIENT_USER_AUTHENTICATION = "insufficient_user_authentication"


@dataclasses.dataclass(frozen=True)
class OAuthErrorResponse:
    """An error response (RFC 6749 §4.1.2.1, §5.2): its code, and optionally a description and a URI."""

    code: str
    description: str | None = None
    uri: str | None = None

    def check(self) -> None:
        """Raises ``Invalid`` unless every member follows RFC 6749 Appendix A.7 to A.9."""
        self.encode()

    def encode(self) -> str:
        """The JSON text of the response."""
        return Calls.text("umilib_auth_oauth_oauth_error_response_encode", *Text.encode(self.code), *Text.encode(self.description), *Text.encode(self.uri))

    @staticmethod
    def decode(body: bytes) -> OAuthErrorResponse:
        """The response of a JSON body (RFC 6749 §5.2)."""
        library = Library.default()
        code, has_description, description, has_uri, uri = Buffer(), ctypes.c_bool(), Buffer(), ctypes.c_bool(), Buffer()
        library.call("umilib_auth_oauth_oauth_error_response_decode", *Bytes.readable(body), ctypes.byref(code), ctypes.byref(has_description), ctypes.byref(description), ctypes.byref(has_uri), ctypes.byref(uri))
        return OAuthErrorResponse(library.take(code).decode("utf-8"), library.take_optional_text(has_description, description), library.take_optional_text(has_uri, uri))

    @staticmethod
    def from_parameters(parameters: OAuthParameters) -> OAuthErrorResponse | None:
        """The response of the parameters of a redirect, or ``None`` without ``error``."""
        code = parameters.get("error")
        if code is None:
            return None
        response = OAuthErrorResponse(code, parameters.get("error_description"), parameters.get("error_uri"))
        response.check()
        return response

    def to_parameters(self, parameters: OAuthParameters) -> None:
        """Appends the members as the parameters of a redirect."""
        parameters.push("error", self.code)
        parameters.push_optional("error_description", self.description)
        parameters.push_optional("error_uri", self.uri)


@dataclasses.dataclass
class OAuthAuthorizationRequest:
    """An authorization request (RFC 6749 §4.1.1) with PKCE (RFC 7636 §4.3), resource indicators
    (RFC 8707), a pushed request's ``request_uri`` (RFC 9126 §4) and ``dpop_jkt`` (RFC 9449 §10)."""

    client_id: str
    response_type: str | None = None
    redirect_uri: str | None = None
    scope: OAuthScope | None = None
    state: str | None = None
    code_challenge: PKCEChallenge | None = None
    resources: list[str] = dataclasses.field(default_factory=list)
    request_uri: str | None = None
    dpop_jkt: str | None = None
    other: list[tuple[str, str]] = dataclasses.field(default_factory=list)

    PARAMETERS: ClassVar[list[str]] = ["response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "resource", "request_uri", "dpop_jkt"]

    @staticmethod
    def from_parameters(parameters: OAuthParameters) -> OAuthAuthorizationRequest:
        """The request of ``parameters``; a challenge without a method is ``plain`` and refused."""
        with OAuthParameters(Handle.create("umilib_auth_oauth_oauth_authorization_request_check", parameters.handle)) as checked:
            challenge = checked.get("code_challenge")
            scope = checked.get("scope")
            return OAuthAuthorizationRequest(
                client_id=checked.required("client_id"),
                response_type=checked.get("response_type"),
                redirect_uri=checked.get("redirect_uri"),
                scope=None if scope is None else OAuthScope.parse(scope),
                state=checked.get("state"),
                code_challenge=None if challenge is None else PKCEChallenge(PKCEMethod.S256, challenge),
                resources=checked.all("resource"),
                request_uri=checked.get("request_uri"),
                dpop_jkt=checked.get("dpop_jkt"),
                other=[(name, value) for name, value in checked.pairs() if name not in OAuthAuthorizationRequest.PARAMETERS],
            )

    def to_parameters(self) -> OAuthParameters:
        parameters = OAuthParameters()
        parameters.push_optional("response_type", self.response_type)
        parameters.push("client_id", self.client_id)
        parameters.push_optional("redirect_uri", self.redirect_uri)
        if self.scope is not None:
            parameters.push("scope", str(self.scope))
        parameters.push_optional("state", self.state)
        if self.code_challenge is not None:
            parameters.push("code_challenge", self.code_challenge.value)
            parameters.push("code_challenge_method", self.code_challenge.method.as_str())
        for resource in self.resources:
            parameters.push("resource", resource)
        parameters.push_optional("request_uri", self.request_uri)
        parameters.push_optional("dpop_jkt", self.dpop_jkt)
        for name, value in self.other:
            parameters.push(name, value)
        return parameters


@dataclasses.dataclass(frozen=True)
class OAuthAuthorizationResponse:
    """A successful authorization response (RFC 6749 §4.1.2) with the issuer of RFC 9207."""

    code: str
    state: str | None = None
    issuer: str | None = None

    @staticmethod
    def from_parameters(parameters: OAuthParameters) -> OAuthAuthorizationResponse:
        """The response of the parameters of a redirect; an error response raises ``Response``."""
        out = ctypes.c_void_p()
        Calls.with_response("umilib_auth_oauth_oauth_authorization_response_check", parameters.handle, ctypes.byref(out))
        with OAuthParameters(out.value) as checked:
            return OAuthAuthorizationResponse(checked.required("code"), checked.get("state"), checked.get("iss"))

    def to_parameters(self) -> OAuthParameters:
        parameters = OAuthParameters()
        parameters.push("code", self.code)
        parameters.push_optional("state", self.state)
        parameters.push_optional("iss", self.issuer)
        return parameters


class OAuthGrant:
    """The grants of a token request, as the variants of the Rust enum."""

    AUTHORIZATION_CODE: ClassVar[str] = "authorization_code"
    CLIENT_CREDENTIALS: ClassVar[str] = "client_credentials"
    REFRESH_TOKEN: ClassVar[str] = "refresh_token"
    DEVICE_CODE: ClassVar[str] = "urn:ietf:params:oauth:grant-type:device_code"
    JWT_BEARER: ClassVar[str] = "urn:ietf:params:oauth:grant-type:jwt-bearer"

    @dataclasses.dataclass
    class AuthorizationCode:
        code: str
        redirect_uri: str | None = None
        code_verifier: PKCEVerifier | None = None

        def grant_type(self) -> str:
            return OAuthGrant.AUTHORIZATION_CODE

    @dataclasses.dataclass
    class ClientCredentials:
        def grant_type(self) -> str:
            return OAuthGrant.CLIENT_CREDENTIALS

    @dataclasses.dataclass
    class RefreshToken:
        refresh_token: str

        def grant_type(self) -> str:
            return OAuthGrant.REFRESH_TOKEN

    @dataclasses.dataclass
    class DeviceCode:
        device_code: str

        def grant_type(self) -> str:
            return OAuthGrant.DEVICE_CODE

    @dataclasses.dataclass
    class JWTBearer:
        assertion: str

        def grant_type(self) -> str:
            return OAuthGrant.JWT_BEARER


@dataclasses.dataclass
class OAuthTokenRequest:
    """A token request (RFC 6749 §3.2): a grant, the scope asked for and resource indicators, without
    client authentication."""

    grant: Any
    scope: OAuthScope | None = None
    resources: list[str] = dataclasses.field(default_factory=list)
    other: list[tuple[str, str]] = dataclasses.field(default_factory=list)

    PARAMETERS: ClassVar[list[str]] = ["grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "device_code", "assertion", "scope", "resource", "client_id", "client_secret", "client_assertion_type", "client_assertion"]

    @staticmethod
    def from_parameters(parameters: OAuthParameters) -> OAuthTokenRequest:
        """The request of ``parameters``; an unknown grant type raises ``Invalid``."""
        with OAuthParameters(Handle.create("umilib_auth_oauth_oauth_token_request_check", parameters.handle)) as checked:
            kind = checked.required("grant_type")
            grant: Any
            if kind == OAuthGrant.AUTHORIZATION_CODE:
                verifier = checked.get("code_verifier")
                grant = OAuthGrant.AuthorizationCode(checked.required("code"), checked.get("redirect_uri"), None if verifier is None else PKCEVerifier(verifier))
            elif kind == OAuthGrant.CLIENT_CREDENTIALS:
                grant = OAuthGrant.ClientCredentials()
            elif kind == OAuthGrant.REFRESH_TOKEN:
                grant = OAuthGrant.RefreshToken(checked.required("refresh_token"))
            elif kind == OAuthGrant.DEVICE_CODE:
                grant = OAuthGrant.DeviceCode(checked.required("device_code"))
            else:
                grant = OAuthGrant.JWTBearer(checked.required("assertion"))
            scope = checked.get("scope")
            return OAuthTokenRequest(
                grant,
                None if scope is None else OAuthScope.parse(scope),
                checked.all("resource"),
                [(name, value) for name, value in checked.pairs() if name not in OAuthTokenRequest.PARAMETERS],
            )

    def to_parameters(self) -> OAuthParameters:
        parameters = OAuthParameters()
        parameters.push("grant_type", self.grant.grant_type())
        if isinstance(self.grant, OAuthGrant.AuthorizationCode):
            parameters.push("code", self.grant.code)
            parameters.push_optional("redirect_uri", self.grant.redirect_uri)
            if self.grant.code_verifier is not None:
                parameters.push("code_verifier", self.grant.code_verifier.as_str())
        elif isinstance(self.grant, OAuthGrant.RefreshToken):
            parameters.push("refresh_token", self.grant.refresh_token)
        elif isinstance(self.grant, OAuthGrant.DeviceCode):
            parameters.push("device_code", self.grant.device_code)
        elif isinstance(self.grant, OAuthGrant.JWTBearer):
            parameters.push("assertion", self.grant.assertion)
        if self.scope is not None:
            parameters.push("scope", str(self.scope))
        for resource in self.resources:
            parameters.push("resource", resource)
        for name, value in self.other:
            parameters.push(name, value)
        return parameters


class Documents:
    """The canonical JSON of documents, read by the Rust types."""

    @staticmethod
    def decode(name: str, status: int, body: bytes) -> dict[str, Any]:
        out = Buffer()
        Calls.with_response(name, status, *Bytes.readable(body), ctypes.byref(out))
        return json.loads(Library.default().take(out))

    @staticmethod
    def encode(members: dict[str, Any]) -> str:
        return json.dumps({name: value for name, value in members.items() if value is not None}, separators=(",", ":"), ensure_ascii=False)


@dataclasses.dataclass
class OAuthTokenResponse:
    """A successful token response (RFC 6749 §5.1); members it does not know are kept in ``other``."""

    access_token: str
    token_type: str
    expires_in: int | None = None
    refresh_token: str | None = None
    scope: OAuthScope | None = None
    other: dict[str, Any] = dataclasses.field(default_factory=dict)

    MEMBERS: ClassVar[list[str]] = ["access_token", "token_type", "expires_in", "refresh_token", "scope"]

    @staticmethod
    def decode(status: int, body: bytes) -> OAuthTokenResponse:
        """The response of a body: a success for status 200, otherwise raises ``Response``."""
        members = Documents.decode("umilib_auth_oauth_oauth_token_response_decode", status, body)
        scope = members.get("scope")
        return OAuthTokenResponse(
            members["access_token"],
            members["token_type"],
            members.get("expires_in"),
            members.get("refresh_token"),
            None if scope is None else OAuthScope.parse(scope),
            {name: value for name, value in members.items() if name not in OAuthTokenResponse.MEMBERS},
        )

    def is_token_type(self, name: str) -> bool:
        """Whether the token type is ``name``, compared without regard to case."""
        return self.token_type.lower() == name.lower()

    def encode(self) -> str:
        members: dict[str, Any] = {"access_token": self.access_token, "token_type": self.token_type, "expires_in": self.expires_in, "refresh_token": self.refresh_token, "scope": None if self.scope is None else str(self.scope)}
        members.update({name: value for name, value in self.other.items() if name not in OAuthTokenResponse.MEMBERS})
        return Documents.encode(members)


@dataclasses.dataclass
class OAuthIntrospectionResponse:
    """The response of the introspection endpoint (RFC 7662 §2.2)."""

    active: bool
    scope: OAuthScope | None = None
    client_id: str | None = None
    username: str | None = None
    token_type: str | None = None
    expires: int | None = None
    issued_at: int | None = None
    not_before: int | None = None
    subject: str | None = None
    audience: list[str] = dataclasses.field(default_factory=list)
    issuer: str | None = None
    identifier: str | None = None
    confirmation: str | None = None
    other: dict[str, Any] = dataclasses.field(default_factory=dict)

    MEMBERS: ClassVar[list[str]] = ["active", "scope", "client_id", "username", "token_type", "exp", "iat", "nbf", "sub", "aud", "iss", "jti", "cnf"]

    @staticmethod
    def decode(status: int, body: bytes) -> OAuthIntrospectionResponse:
        members = Documents.decode("umilib_auth_oauth_oauth_introspection_response_decode", status, body)
        audience = members.get("aud", [])
        scope = members.get("scope")
        return OAuthIntrospectionResponse(
            members["active"], None if scope is None else OAuthScope.parse(scope), members.get("client_id"), members.get("username"), members.get("token_type"),
            members.get("exp"), members.get("iat"), members.get("nbf"), members.get("sub"), [audience] if isinstance(audience, str) else list(audience),
            members.get("iss"), members.get("jti"), members.get("cnf", {}).get("jkt"),
            {name: value for name, value in members.items() if name not in OAuthIntrospectionResponse.MEMBERS},
        )  # fmt: skip

    def encode(self) -> str:
        if not self.active:
            return '{"active":false}'
        members: dict[str, Any] = {
            "active": True, "scope": None if self.scope is None else str(self.scope), "client_id": self.client_id, "username": self.username,
            "token_type": self.token_type, "exp": self.expires, "iat": self.issued_at, "nbf": self.not_before, "sub": self.subject,
            "aud": (self.audience[0] if len(self.audience) == 1 else self.audience) or None, "iss": self.issuer, "jti": self.identifier,
            "cnf": None if self.confirmation is None else {"jkt": self.confirmation},
        }  # fmt: skip
        members.update({name: value for name, value in self.other.items() if name not in OAuthIntrospectionResponse.MEMBERS})
        return Documents.encode(members)


@dataclasses.dataclass(frozen=True)
class OAuthDeviceAuthorizationResponse:
    """The response of the device authorization endpoint (RFC 8628 §3.2)."""

    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    verification_uri_complete: str | None = None
    interval: int | None = None

    @staticmethod
    def decode(status: int, body: bytes) -> OAuthDeviceAuthorizationResponse:
        members = Documents.decode("umilib_auth_oauth_oauth_device_authorization_response_decode", status, body)
        return OAuthDeviceAuthorizationResponse(members["device_code"], members["user_code"], members["verification_uri"], members["expires_in"], members.get("verification_uri_complete"), members.get("interval"))

    def encode(self) -> str:
        return Documents.encode(dataclasses.asdict(self))


@dataclasses.dataclass(frozen=True)
class OAuthPushedAuthorizationResponse:
    """The response of the pushed authorization request endpoint (RFC 9126 §2.2)."""

    request_uri: str
    expires_in: int

    @staticmethod
    def decode(status: int, body: bytes) -> OAuthPushedAuthorizationResponse:
        """A success is status 201."""
        members = Documents.decode("umilib_auth_oauth_oauth_pushed_authorization_response_decode", status, body)
        return OAuthPushedAuthorizationResponse(members["request_uri"], members["expires_in"])

    def encode(self) -> str:
        return Documents.encode(dataclasses.asdict(self))


# Metadata.


class OAuthMetadataKind(enum.IntEnum):
    """The kinds of metadata documents: of an authorization server (RFC 8414) and of a protected
    resource (RFC 9728)."""

    Server = 0
    Resource = 1

    def identifier_member(self) -> str:
        return "issuer" if self is OAuthMetadataKind.Server else "resource"

    def well_known(self) -> str:
        return "oauth-authorization-server" if self is OAuthMetadataKind.Server else "oauth-protected-resource"


@dataclasses.dataclass
class OAuthMetadata:
    """A metadata document (RFC 8414 §2, RFC 9728 §2): a JSON object whose members are read and set by
    name; the names of the registered members are constants of this class."""

    kind: OAuthMetadataKind
    object: dict[str, Any]

    ISSUER: ClassVar[str] = "issuer"
    AUTHORIZATION_ENDPOINT: ClassVar[str] = "authorization_endpoint"
    TOKEN_ENDPOINT: ClassVar[str] = "token_endpoint"
    JWKS_URI: ClassVar[str] = "jwks_uri"
    REGISTRATION_ENDPOINT: ClassVar[str] = "registration_endpoint"
    SCOPES_SUPPORTED: ClassVar[str] = "scopes_supported"
    RESPONSE_TYPES_SUPPORTED: ClassVar[str] = "response_types_supported"
    RESPONSE_MODES_SUPPORTED: ClassVar[str] = "response_modes_supported"
    GRANT_TYPES_SUPPORTED: ClassVar[str] = "grant_types_supported"
    TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED: ClassVar[str] = "token_endpoint_auth_methods_supported"
    TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED: ClassVar[str] = "token_endpoint_auth_signing_alg_values_supported"
    SERVICE_DOCUMENTATION: ClassVar[str] = "service_documentation"
    REVOCATION_ENDPOINT: ClassVar[str] = "revocation_endpoint"
    REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED: ClassVar[str] = "revocation_endpoint_auth_methods_supported"
    INTROSPECTION_ENDPOINT: ClassVar[str] = "introspection_endpoint"
    INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED: ClassVar[str] = "introspection_endpoint_auth_methods_supported"
    CODE_CHALLENGE_METHODS_SUPPORTED: ClassVar[str] = "code_challenge_methods_supported"
    PUSHED_AUTHORIZATION_REQUEST_ENDPOINT: ClassVar[str] = "pushed_authorization_request_endpoint"
    REQUIRE_PUSHED_AUTHORIZATION_REQUESTS: ClassVar[str] = "require_pushed_authorization_requests"
    AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED: ClassVar[str] = "authorization_response_iss_parameter_supported"
    DEVICE_AUTHORIZATION_ENDPOINT: ClassVar[str] = "device_authorization_endpoint"
    DPOP_SIGNING_ALG_VALUES_SUPPORTED: ClassVar[str] = "dpop_signing_alg_values_supported"
    PROTECTED_RESOURCES: ClassVar[str] = "protected_resources"
    RESOURCE: ClassVar[str] = "resource"
    AUTHORIZATION_SERVERS: ClassVar[str] = "authorization_servers"
    BEARER_METHODS_SUPPORTED: ClassVar[str] = "bearer_methods_supported"
    RESOURCE_SIGNING_ALG_VALUES_SUPPORTED: ClassVar[str] = "resource_signing_alg_values_supported"
    RESOURCE_NAME: ClassVar[str] = "resource_name"
    RESOURCE_DOCUMENTATION: ClassVar[str] = "resource_documentation"
    DPOP_BOUND_ACCESS_TOKENS_REQUIRED: ClassVar[str] = "dpop_bound_access_tokens_required"

    @staticmethod
    def new(kind: OAuthMetadataKind, identifier: str) -> OAuthMetadata:
        return OAuthMetadata(kind, {kind.identifier_member(): identifier})

    @staticmethod
    def decode(kind: OAuthMetadataKind, body: bytes) -> OAuthMetadata:
        """The document of the JSON ``body``, which must be an object with the identifier member."""
        return OAuthMetadata(kind, json.loads(Calls.text("umilib_auth_oauth_oauth_metadata_decode", int(kind), *Bytes.readable(body))))

    def encode(self) -> str:
        return json.dumps(self.object, separators=(",", ":"), ensure_ascii=False)

    def identifier(self) -> str:
        return self.object[self.kind.identifier_member()]

    def check(self, expected: str) -> None:
        """Raises ``Issuer`` unless the document describes ``expected`` (RFC 8414 §3.3, RFC 9728 §3.3)."""
        Library.default().call("umilib_auth_oauth_oauth_metadata_check", int(self.kind), *Text.encode(self.encode()), *Text.encode(expected))

    @staticmethod
    def location(kind: OAuthMetadataKind, identifier: str) -> str:
        """The URL of the document of ``identifier`` (RFC 8414 §3.1, RFC 9728 §3.1)."""
        return Calls.text("umilib_auth_oauth_oauth_metadata_location", int(kind), *Text.encode(identifier))

    def string(self, name: str) -> str | None:
        value = self.object.get(name)
        if value is not None and not isinstance(value, str):
            raise OAuthError("auth.oauth", "Invalid", f"the parameter {name} is not valid")
        return value

    def strings(self, name: str) -> list[str] | None:
        value = self.object.get(name)
        if value is not None and not (isinstance(value, list) and all(isinstance(item, str) for item in value)):
            raise OAuthError("auth.oauth", "Invalid", f"the parameter {name} is not valid")
        return value

    def boolean(self, name: str) -> bool | None:
        value = self.object.get(name)
        if value is not None and not isinstance(value, bool):
            raise OAuthError("auth.oauth", "Invalid", f"the parameter {name} is not valid")
        return value

    def lists(self, name: str, value: str) -> bool:
        return value in (self.strings(name) or [])

    def set_string(self, name: str, value: str) -> None:
        self.object[name] = value

    def set_strings(self, name: str, values: list[str]) -> None:
        self.object[name] = list(values)

    def set_boolean(self, name: str, value: bool) -> None:
        self.object[name] = value


# Client authentication and HTTP messages.


class OAuthClientAuthentication:
    """How a client authenticates (RFC 6749 §2.3, RFC 7523 §2.2), as the variants of the Rust enum."""

    JWT_BEARER: ClassVar[str] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    ASSERTION_LIFETIME: ClassVar[int] = 60

    @dataclasses.dataclass
    class None_:
        client_id: str
        METHOD: ClassVar[int] = 0

        def method(self) -> str:
            return "none"

    @dataclasses.dataclass
    class SecretBasic:
        client_id: str
        secret: str
        METHOD: ClassVar[int] = 1

        def method(self) -> str:
            return "client_secret_basic"

    @dataclasses.dataclass
    class SecretPost:
        client_id: str
        secret: str
        METHOD: ClassVar[int] = 2

        def method(self) -> str:
            return "client_secret_post"

    @dataclasses.dataclass
    class PrivateKeyJWT:
        client_id: str
        key: JWK
        algorithm: JWSAlgorithm
        METHOD: ClassVar[int] = 3

        def method(self) -> str:
            return "private_key_jwt"

    @staticmethod
    def arguments(authentication: Any) -> tuple[Any, ...]:
        """The arguments by which the C ABI takes ``authentication``."""
        secret = getattr(authentication, "secret", None)
        key = getattr(authentication, "key", None)
        algorithm = getattr(authentication, "algorithm", 0)
        return (authentication.METHOD, *Text.encode(authentication.client_id), *Text.encode(secret), None if key is None else key.handle, int(algorithm))

    @staticmethod
    def apply(authentication: Any, audience: str, now: int, lifetime: int, random: Random, parameters: OAuthParameters) -> str | None:
        """Adds ``authentication`` to a request to the server ``audience``, an assertion living
        ``lifetime`` seconds: parameters into ``parameters``; returns the value of the
        ``Authorization`` header if the method uses one."""
        value = Library.default().optional("umilib_auth_oauth_oauth_client_authentication_apply", Buffer, *OAuthClientAuthentication.arguments(authentication), *Text.encode(audience), now, lifetime, *random.source(), parameters.handle)
        return None if value is None else value.decode("utf-8")

    @staticmethod
    def basic_credentials(client_id: str, secret: str) -> str:
        """The ``Authorization`` value of client_secret_basic (RFC 6749 §2.3.1)."""
        return Calls.text("umilib_auth_oauth_oauth_client_authentication_basic_credentials", *Text.encode(client_id), *Text.encode(secret))

    @staticmethod
    def assertion(client_id: str, audience: str, now: int, lifetime: int, key: JWK, algorithm: JWSAlgorithm, random: Random) -> str:
        """A client assertion (RFC 7523 §3) for the server ``audience``, living ``lifetime`` seconds."""
        parameters = OAuthParameters()
        OAuthClientAuthentication.apply(OAuthClientAuthentication.PrivateKeyJWT(client_id, key, algorithm), audience, now, lifetime, random, parameters)
        return parameters.required("client_assertion")


@dataclasses.dataclass
class OAuthHTTPRequest:
    """An HTTP request a client asks to send; its fields and body may hold secrets."""

    method: str
    uri: str
    headers: list[tuple[str, str]]
    body: bytes

    FORM: ClassVar[str] = "application/x-www-form-urlencoded"
    JSON: ClassVar[str] = "application/json"

    @staticmethod
    def take(pointer: int) -> OAuthHTTPRequest:
        library = Library.default()
        try:
            method, uri, headers, body = Buffer(), Buffer(), Buffer(), Buffer()
            library.call("umilib_auth_oauth_oauth_http_request_parts", pointer, ctypes.byref(method), ctypes.byref(uri), ctypes.byref(headers), ctypes.byref(body))
            return OAuthHTTPRequest(library.take(method).decode(), library.take(uri).decode(), Calls.header_pairs(library.take(headers).decode()), library.take(body))
        finally:
            library.function("umilib_auth_oauth_oauth_http_request_free")(pointer)

    def header(self, name: str) -> str | None:
        return next((value for key, value in self.headers if key.lower() == name.lower()), None)


@dataclasses.dataclass
class OAuthEndpointRequest:
    """A request that reached an endpoint: what OAuth reads of it. ``uri`` is the absolute target URI."""

    method: str
    uri: str
    authorization: str | None = None
    dpop: str | None = None
    content_type: str | None = None
    body: bytes = b""

    def is_form(self) -> bool:
        return (self.content_type or "").split(";")[0].strip().lower() == OAuthHTTPRequest.FORM

    def handle(self) -> Handle:
        """A C handle of this request, released by its ``with`` block."""
        handle = EndpointRequestHandle(Handle.create("umilib_auth_oauth_oauth_endpoint_request_new", *Text.encode(self.method), *Text.encode(self.uri), *Bytes.readable(self.body)))
        handle.library.call("umilib_auth_oauth_oauth_endpoint_request_set_fields", handle.handle, *Text.encode(self.authorization), *Text.encode(self.dpop), *Text.encode(self.content_type))
        return handle


class EndpointRequestHandle(Handle):
    """The C handle of an :class:`OAuthEndpointRequest`."""

    FREE = "umilib_auth_oauth_oauth_endpoint_request_free"


@dataclasses.dataclass
class OAuthHTTPResponse:
    """The response an endpoint gives: the status, the header fields and the body."""

    status: int
    headers: list[tuple[str, str]]
    body: bytes

    @staticmethod
    def take(pointer: int) -> OAuthHTTPResponse:
        library = Library.default()
        try:
            status, headers, body = ctypes.c_uint16(), Buffer(), Buffer()
            library.call("umilib_auth_oauth_oauth_http_response_parts", pointer, ctypes.byref(status), ctypes.byref(headers), ctypes.byref(body))
            return OAuthHTTPResponse(status.value, Calls.header_pairs(library.take(headers).decode()), library.take(body))
        finally:
            library.function("umilib_auth_oauth_oauth_http_response_free")(pointer)

    @staticmethod
    def json(status: int, body: str) -> OAuthHTTPResponse:
        """A JSON response, never cached (RFC 6749 §5.1)."""
        return OAuthHTTPResponse(status, [("content-type", OAuthHTTPRequest.JSON), ("cache-control", "no-store")], body.encode("utf-8"))

    def header(self, name: str) -> str | None:
        return next((value for key, value in self.headers if key.lower() == name.lower()), None)


# The client.


class OAuthClient(Handle):
    """A client of the authorization code grant with PKCE and of the token endpoint, without I/O,
    configured from the metadata of its server (checked against its issuer)."""

    FREE = "umilib_auth_oauth_oauth_client_free"

    def __init__(self, metadata: OAuthMetadata, authentication: Any, redirect_uri: str) -> None:
        super().__init__(Handle.create("umilib_auth_oauth_oauth_client_new", *Text.encode(metadata.encode()), *OAuthClientAuthentication.arguments(authentication), *Text.encode(redirect_uri)))

    def pending_count(self) -> int:
        return self.library.value("umilib_auth_oauth_oauth_client_pending_count", ctypes.c_size_t, self.handle)

    def limits(self) -> tuple[int, int, int, int]:
        """The most pending requests, their lifetime, the random octets of a state, and the
        lifetime of a client assertion."""
        maximum, lifetime, octets, assertion = ctypes.c_size_t(), ctypes.c_int64(), ctypes.c_size_t(), ctypes.c_int64()
        self.library.call("umilib_auth_oauth_oauth_client_limits", self.handle, ctypes.byref(maximum), ctypes.byref(lifetime), ctypes.byref(octets), ctypes.byref(assertion))
        return maximum.value, lifetime.value, octets.value, assertion.value

    def authorize(self, scope: OAuthScope | None, resources: list[str], now: int, random: Random) -> URIReference:
        """The URL to send the user's browser to: a new state and an S256 challenge."""
        array = Text.array(resources)
        text = Calls.text("umilib_auth_oauth_oauth_client_authorize", self.handle, *Text.encode(None if scope is None else str(scope)), array[0], array[1], now, *random.source())
        return URIReference.parse(text)

    def callback(self, redirect: URIReference | str, now: int) -> OAuthTokenRequest:
        """The token request of the authorization response at ``redirect`` (RFC 6749 §10.12, RFC 9207
        §2.4); an error response raises ``Response`` after the same checks."""
        out = ctypes.c_void_p()
        Calls.with_response("umilib_auth_oauth_oauth_client_callback", self.handle, *Text.encode(str(redirect)), now, ctypes.byref(out))
        with OAuthParameters(out.value) as parameters:
            return OAuthTokenRequest.from_parameters(parameters)

    def token_request(self, request: OAuthTokenRequest, now: int, random: Random) -> OAuthHTTPRequest:
        """The HTTP request of ``request`` with the client's authentication."""
        with request.to_parameters() as parameters:
            return OAuthHTTPRequest.take(Handle.create("umilib_auth_oauth_oauth_client_token_request", self.handle, parameters.handle, now, *random.source()))

    def endpoint_request(self, endpoint: str, parameters: OAuthParameters, now: int, random: Random) -> OAuthHTTPRequest:
        """The HTTP POST of ``parameters`` to ``endpoint`` with the client's authentication."""
        return OAuthHTTPRequest.take(Handle.create("umilib_auth_oauth_oauth_client_endpoint_request", self.handle, *Text.encode(endpoint), parameters.handle, now, *random.source()))


# The authorization server.


class OAuthClientMethod(enum.IntEnum):
    """How a registered client authenticates (RFC 7591 §2)."""

    None_ = 0
    SecretBasic = 1
    SecretPost = 2
    PrivateKeyJWT = 3

    def is_confidential(self) -> bool:
        return self is not OAuthClientMethod.None_


@dataclasses.dataclass
class OAuthClientRegistration:
    """A client registered with an authorization server. The C ABI keeps only the SHA-256 digest of
    ``secret``."""

    client_id: str
    method: OAuthClientMethod
    secret: str | None = None
    keys: JWKSet | None = None
    redirect_uris: list[str] = dataclasses.field(default_factory=list)
    grant_types: list[str] = dataclasses.field(default_factory=list)
    scope: OAuthScope = dataclasses.field(default_factory=OAuthScope)
    resources: list[str] | None = None
    introspection: bool = False

    @staticmethod
    def public(client_id: str, redirect_uris: list[str], scope: OAuthScope) -> OAuthClientRegistration:
        """A public client of the authorization code grant, with refresh tokens."""
        return OAuthClientRegistration(client_id, OAuthClientMethod.None_, redirect_uris=list(redirect_uris), grant_types=[OAuthGrant.AUTHORIZATION_CODE, OAuthGrant.REFRESH_TOKEN], scope=scope)

    @staticmethod
    def confidential(client_id: str, method: OAuthClientMethod, secret: str, grant_types: list[str], scope: OAuthScope) -> OAuthClientRegistration:
        return OAuthClientRegistration(client_id, method, secret, grant_types=list(grant_types), scope=scope)


class OAuthAccessTokenFormat:
    """The form of access tokens, as the variants of the Rust enum."""

    @dataclasses.dataclass
    class Opaque:
        pass

    @dataclasses.dataclass
    class JWT:
        key: JWK
        algorithm: JWSAlgorithm
        default_audience: str


@dataclasses.dataclass
class DPoPConfig:
    """The configuration of the checks of DPoP proofs (RFC 9449)."""

    algorithms: list[JWSAlgorithm] = dataclasses.field(default_factory=lambda: [JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512, JWSAlgorithm.RS256, JWSAlgorithm.Ed25519, JWSAlgorithm.EdDSA])
    maximum_age: int = 300
    leeway: int = 60
    require_nonce: bool = False
    maximum_proofs: int = 65536
    previous_nonces: int = 1


@dataclasses.dataclass
class OAuthServerConfig:
    """The configuration of an :class:`OAuthServer`; :meth:`new` gives the defaults of the Rust type."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    introspection_endpoint: str | None
    revocation_endpoint: str | None
    pushed_authorization_request_endpoint: str | None
    device_authorization_endpoint: str | None
    verification_uri: str | None
    jwks_uri: str | None
    access_token_format: Any
    require_pkce: bool
    require_pushed_authorization_requests: bool
    rotate_refresh_tokens: bool
    code_lifetime: int
    access_token_lifetime: int
    refresh_token_lifetime: int
    pushed_request_lifetime: int
    device_code_lifetime: int
    device_interval: int
    maximum_assertion_lifetime: int
    token_octets: int
    user_code_length: int
    maximum_parameters: int
    maximum_codes: int
    maximum_codes_per_client: int
    maximum_tokens: int
    maximum_tokens_per_client: int
    maximum_pushed_requests: int
    maximum_pushed_requests_per_client: int
    maximum_devices: int
    maximum_devices_per_client: int
    maximum_assertions: int
    maximum_assertions_per_client: int
    assertion_algorithms: list[JWSAlgorithm]
    dpop: DPoPConfig

    LIMITS: ClassVar[list[str]] = [
        "require_pkce", "require_pushed_authorization_requests", "rotate_refresh_tokens", "code_lifetime", "access_token_lifetime",
        "refresh_token_lifetime", "pushed_request_lifetime", "device_code_lifetime", "device_interval", "maximum_assertion_lifetime",
        "token_octets", "user_code_length", "maximum_parameters", "maximum_codes", "maximum_codes_per_client", "maximum_tokens",
        "maximum_tokens_per_client", "maximum_pushed_requests", "maximum_pushed_requests_per_client", "maximum_devices",
        "maximum_devices_per_client", "maximum_assertions", "maximum_assertions_per_client",
    ]  # fmt: skip

    @staticmethod
    def new(issuer: str) -> OAuthServerConfig:
        """The configuration of ``issuer`` with the endpoints and settings of the Rust ``new``."""
        with ServerConfigHandle(Handle.create("umilib_auth_oauth_oauth_server_config_new", *Text.encode(issuer))) as handle:
            limits = handle.library.type("umilib_auth_oauth_OAuthServerLimits")()
            handle.library.call("umilib_auth_oauth_oauth_server_config_limits", handle.handle, ctypes.byref(limits))
            endpoints = (Calls.text("umilib_auth_oauth_oauth_server_config_endpoints", handle.handle) + "\n" * 8).split("\n")[:8]
            assertion, dpop_algorithms = Buffer(), Buffer()
            handle.library.call("umilib_auth_oauth_oauth_server_config_algorithms", handle.handle, ctypes.byref(assertion), ctypes.byref(dpop_algorithms))
            assertion_algorithms = [JWSAlgorithm(index) for index in handle.library.take(assertion)]
            dpop_list = [JWSAlgorithm(index) for index in handle.library.take(dpop_algorithms)]
        optional = [endpoint or None for endpoint in endpoints[2:]]
        dpop = DPoPConfig(dpop_list, limits.dpop_maximum_age, limits.dpop_leeway, limits.dpop_require_nonce, limits.dpop_maximum_proofs, limits.dpop_previous_nonces)
        return OAuthServerConfig(
            issuer, endpoints[0], endpoints[1], *optional, OAuthAccessTokenFormat.Opaque(),
            *[getattr(limits, name) for name in OAuthServerConfig.LIMITS],
            assertion_algorithms=assertion_algorithms,
            dpop=dpop,
        )  # fmt: skip

    def handle(self) -> Handle:
        """A C handle of this configuration, released by its ``with`` block."""
        handle = ServerConfigHandle(Handle.create("umilib_auth_oauth_oauth_server_config_new", *Text.encode(self.issuer)))
        library = handle.library
        endpoints = [self.authorization_endpoint, self.token_endpoint, *[value or "" for value in (self.introspection_endpoint, self.revocation_endpoint, self.pushed_authorization_request_endpoint, self.device_authorization_endpoint, self.verification_uri, self.jwks_uri)]]
        array = Text.array(endpoints)
        library.call("umilib_auth_oauth_oauth_server_config_set_endpoints", handle.handle, array[0], array[1])
        limits = library.type("umilib_auth_oauth_OAuthServerLimits")()
        for name in OAuthServerConfig.LIMITS:
            Fields.assign(limits, name, getattr(self, name))
        for name in ("maximum_age", "leeway", "require_nonce", "maximum_proofs", "previous_nonces"):
            Fields.assign(limits, f"dpop_{name}", getattr(self.dpop, name))
        library.call("umilib_auth_oauth_oauth_server_config_set_limits", handle.handle, limits)
        library.call("umilib_auth_oauth_oauth_server_config_set_algorithms", handle.handle, *Calls.algorithms(self.assertion_algorithms), *Calls.algorithms(self.dpop.algorithms))
        token_format = self.access_token_format
        if isinstance(token_format, OAuthAccessTokenFormat.JWT):
            library.call("umilib_auth_oauth_oauth_server_config_set_access_token_format", handle.handle, token_format.key.handle, int(token_format.algorithm), *Text.encode(token_format.default_audience))
        return handle


class ServerConfigHandle(Handle):
    """The C handle of an :class:`OAuthServerConfig`."""

    FREE = "umilib_auth_oauth_oauth_server_config_free"


@dataclasses.dataclass
class OAuthGrantRecord:
    """What a grant gave: to which client, for which user, with which scope and resources, bound to
    which DPoP key, and how the user authenticated (RFC 9470 §4)."""

    client_id: str
    subject: str | None = None
    scope: OAuthScope = dataclasses.field(default_factory=OAuthScope)
    resources: list[str] = dataclasses.field(default_factory=list)
    confirmation: str | None = None
    authentication_time: int | None = None
    authentication_context: str | None = None

    def arguments(self) -> tuple[Any, ...]:
        """The arguments by which the C ABI takes the user's decision, which needs a resource owner."""
        if self.subject is None:
            raise OAuthError("auth.oauth", "Invalid", "the parameter scope is not valid: a decision needs a subject")
        array = Text.array(self.resources)
        return (
            *Text.encode(self.subject), *Text.encode(str(self.scope) or None), array[0], array[1],
            self.authentication_time is not None, self.authentication_time or 0, *Text.encode(self.authentication_context),
        )  # fmt: skip


class OAuthAuthorization(Handle):
    """An authorization request the server took, waiting for the user's decision."""

    FREE = "umilib_auth_oauth_oauth_authorization_free"

    def parts(self) -> tuple[str, str, OAuthScope, str | None, list[str], list[tuple[str, str]]]:
        library = self.library
        client_id, redirect_uri, scope, has_state, state, resources, other = Buffer(), Buffer(), Buffer(), ctypes.c_bool(), Buffer(), Buffer(), ctypes.c_void_p()
        library.call("umilib_auth_oauth_oauth_authorization_parts", self.handle, ctypes.byref(client_id), ctypes.byref(redirect_uri), ctypes.byref(scope), ctypes.byref(has_state), ctypes.byref(state), ctypes.byref(resources), ctypes.byref(other))
        scope_text = library.take(scope).decode()
        with OAuthParameters(other.value) as parameters:
            pairs = parameters.pairs()
        return (
            library.take(client_id).decode(), library.take(redirect_uri).decode(),
            OAuthScope.parse(scope_text) if scope_text else OAuthScope(), library.take_optional_text(has_state, state),
            Calls.lines(library.take(resources).decode()), pairs,
        )  # fmt: skip

    @property
    def client_id(self) -> str:
        return self.parts()[0]

    @property
    def redirect_uri(self) -> str:
        return self.parts()[1]

    @property
    def scope(self) -> OAuthScope:
        return self.parts()[2]

    @property
    def state(self) -> str | None:
        return self.parts()[3]

    @property
    def resources(self) -> list[str]:
        return self.parts()[4]

    @property
    def other(self) -> list[tuple[str, str]]:
        return self.parts()[5]


class OAuthAuthorizationFailure(Exception):
    """A refused authorization request: :attr:`local`, an error to show the user without redirecting
    (RFC 6749 §4.1.2.1), or :attr:`redirect`, the URI carrying the error to send the user agent to."""

    def __init__(self, local: OAuthErrorResponse | None, redirect: URIReference | None) -> None:
        super().__init__(local.code if local is not None else str(redirect))
        self.local = local
        self.redirect = redirect


@dataclasses.dataclass(frozen=True)
class OAuthDeviceRecord:
    """A device authorization waiting for the user, as the user's page shows it."""

    client_id: str
    scope: OAuthScope
    resources: list[str]


class OAuthServer(Handle):
    """An authorization server without I/O (RFC 6749 §3; RFC 7662, RFC 7009, RFC 9126, RFC 8628,
    RFC 9068, RFC 9449): it keeps its clients and what it issued in bounded tables, and answers the
    requests its endpoints receive."""

    FREE = "umilib_auth_oauth_oauth_server_free"
    REQUEST_URI_PREFIX: ClassVar[str] = "urn:ietf:params:oauth:request_uri:"
    USER_CODE_CHARACTERS: ClassVar[bytes] = b"BCDFGHJKLMNPQRSTVWXZ"

    def __init__(self, config: OAuthServerConfig) -> None:
        with config.handle() as handle:
            super().__init__(Handle.create("umilib_auth_oauth_oauth_server_new", handle.handle))
        self.settings = config

    def config(self) -> OAuthServerConfig:
        return self.settings

    def register(self, registration: OAuthClientRegistration) -> None:
        """Registers ``registration``, replacing a client of the same identifier."""
        redirects = Text.array(registration.redirect_uris)
        grants = Text.array(registration.grant_types)
        resources = Calls.strings(registration.resources)
        self.library.call(
            "umilib_auth_oauth_oauth_server_register", self.handle, *Text.encode(registration.client_id), int(registration.method), *Text.encode(registration.secret),
            None if registration.keys is None else registration.keys.handle, redirects[0], redirects[1], grants[0], grants[1],
            *Text.encode(str(registration.scope) or None), resources[0], resources[1], registration.introspection,
        )  # fmt: skip

    def unregister(self, client_id: str) -> bool:
        return self.library.value("umilib_auth_oauth_oauth_server_unregister", ctypes.c_bool, self.handle, *Text.encode(client_id))

    def metadata(self) -> OAuthMetadata:
        return OAuthMetadata(OAuthMetadataKind.Server, json.loads(Calls.text("umilib_auth_oauth_oauth_server_metadata", self.handle)))

    def jwks(self) -> JWKSet | None:
        text = self.library.optional("umilib_auth_oauth_oauth_server_jwks", Buffer, self.handle)
        return None if text is None else JWKSet.from_json(text)

    def authorize(self, parameters: OAuthParameters, now: int) -> OAuthAuthorization:
        """Checks the authorization request of ``parameters``; raises :class:`OAuthAuthorizationFailure`."""
        kind, out, text = ctypes.c_uint8(), ctypes.c_void_p(), Buffer()
        self.library.call("umilib_auth_oauth_oauth_server_authorize", self.handle, parameters.handle, now, ctypes.byref(kind), ctypes.byref(out), ctypes.byref(text))
        body = self.library.take(text)
        if kind.value == 0:
            return OAuthAuthorization(out.value)
        if kind.value == 1:
            raise OAuthAuthorizationFailure(OAuthErrorResponse.decode(body), None)
        raise OAuthAuthorizationFailure(None, URIReference.parse(body.decode()))

    def approve(self, authorization: OAuthAuthorization, grant: OAuthGrantRecord, now: int, random: Random) -> URIReference:
        """Issues a code for ``authorization`` approved for ``grant`` and returns the redirect."""
        return URIReference.parse(Calls.text("umilib_auth_oauth_oauth_server_approve", self.handle, authorization.handle, *grant.arguments(), now, *random.source()))

    def deny(self, authorization: OAuthAuthorization) -> URIReference:
        return URIReference.parse(Calls.text("umilib_auth_oauth_oauth_server_deny", self.handle, authorization.handle))

    def respond(self, function: str, request: OAuthEndpointRequest, now: int, random: Random | None) -> OAuthHTTPResponse:
        with request.handle() as handle:
            arguments = (now, *random.source()) if random is not None else (now,)
            return OAuthHTTPResponse.take(Handle.create(f"umilib_auth_oauth_oauth_server_{function}", self.handle, handle.handle, *arguments))

    def token(self, request: OAuthEndpointRequest, now: int, random: Random) -> OAuthHTTPResponse:
        return self.respond("token", request, now, random)

    def introspect(self, request: OAuthEndpointRequest, now: int) -> OAuthHTTPResponse:
        return self.respond("introspect", request, now, None)

    def revoke(self, request: OAuthEndpointRequest, now: int) -> OAuthHTTPResponse:
        return self.respond("revoke", request, now, None)

    def push(self, request: OAuthEndpointRequest, now: int, random: Random) -> OAuthHTTPResponse:
        return self.respond("push", request, now, random)

    def device_authorize(self, request: OAuthEndpointRequest, now: int, random: Random) -> OAuthHTTPResponse:
        return self.respond("device_authorize", request, now, random)

    def introspection(self, token: str, now: int) -> OAuthIntrospectionResponse:
        return OAuthIntrospectionResponse.decode(200, Calls.text("umilib_auth_oauth_oauth_server_introspection", self.handle, *Text.encode(token), now).encode())

    def device(self, user_code: str, now: int) -> OAuthDeviceRecord | None:
        found, client_id, scope, resources = ctypes.c_bool(), Buffer(), Buffer(), Buffer()
        self.library.call("umilib_auth_oauth_oauth_server_device", self.handle, *Text.encode(user_code), now, ctypes.byref(found), ctypes.byref(client_id), ctypes.byref(scope), ctypes.byref(resources))
        client, scope_text, resource_text = self.library.take(client_id).decode(), self.library.take(scope).decode(), self.library.take(resources).decode()
        if not found.value:
            return None
        return OAuthDeviceRecord(client, OAuthScope.parse(scope_text) if scope_text else OAuthScope(), Calls.lines(resource_text))

    def device_approve(self, user_code: str, grant: OAuthGrantRecord, now: int) -> None:
        self.library.call("umilib_auth_oauth_oauth_server_device_approve", self.handle, *Text.encode(user_code), *grant.arguments(), now)

    def device_deny(self, user_code: str, now: int) -> None:
        self.library.call("umilib_auth_oauth_oauth_server_device_deny", self.handle, *Text.encode(user_code), now)

    def revoke_subject(self, subject: str) -> None:
        self.library.call("umilib_auth_oauth_oauth_server_revoke_subject", self.handle, *Text.encode(subject))

    def expire(self, now: int) -> None:
        self.library.call("umilib_auth_oauth_oauth_server_expire", self.handle, now)

    def rotate_dpop_nonce(self, random: Random) -> str:
        """Makes a new DPoP nonce (RFC 9449 §8); the one before it is still taken."""
        return Calls.text("umilib_auth_oauth_oauth_server_rotate_dpop_nonce", self.handle, *random.source())


# DPoP.


@dataclasses.dataclass(frozen=True)
class DPoPTarget:
    """The HTTP request a DPoP proof is for (RFC 9449 §4.2: ``htm``, ``htu``, ``ath``)."""

    method: str
    uri: str
    access_token: str | None = None

    def arguments(self) -> tuple[Any, ...]:
        return (*Text.encode(self.method), *Text.encode(self.uri), *Text.encode(self.access_token))


@dataclasses.dataclass(frozen=True)
class DPoPProof:
    """A checked DPoP proof: the thumbprint of its key (RFC 9449 §6.1) and its claims."""

    thumbprint: str
    claims: dict[str, Any]

    TYPE: ClassVar[str] = "dpop+jwt"

    @staticmethod
    def create(key: JWK, algorithm: JWSAlgorithm, target: DPoPTarget, now: int, nonce: str | None, random: Random) -> str:
        """A proof for ``target`` signed with the private ``key``."""
        return Calls.text("umilib_auth_oauth_dpop_proof_create", key.handle, int(algorithm), *target.arguments(), now, *Text.encode(nonce), *random.source())

    @staticmethod
    def verify(text: str, algorithms: list[JWSAlgorithm], target: DPoPTarget, now: int, maximum_age: int, leeway: int) -> DPoPProof:
        """The proof ``text`` with the checks of RFC 9449 §4.3 that need no state."""
        thumbprint, claims = Buffer(), Buffer()
        Library.default().call("umilib_auth_oauth_dpop_proof_verify", *Text.encode(text), *Calls.algorithms(algorithms), *target.arguments(), now, maximum_age, leeway, ctypes.byref(thumbprint), ctypes.byref(claims))
        return DPoPProof(Library.default().take(thumbprint).decode(), json.loads(Library.default().take(claims)))

    @staticmethod
    def thumbprint_of(key: JWK) -> str:
        """The base64url JWK SHA-256 thumbprint of ``key``."""
        return Calls.text("umilib_auth_oauth_dpop_proof_thumbprint", key.handle)

    @staticmethod
    def access_token_hash(access_token: str) -> str:
        return Calls.text("umilib_auth_oauth_dpop_proof_access_token_hash", *Text.encode(access_token))

    @staticmethod
    def target(uri: str) -> str:
        """``uri`` as an ``htu`` is compared (§4.3)."""
        return Calls.text("umilib_auth_oauth_dpop_proof_target", *Text.encode(uri))

    def identifier(self) -> str | None:
        return self.claims.get("jti")

    def nonce(self) -> str | None:
        return self.claims.get("nonce")


class DPoPVerifier(Handle):
    """The checks of DPoP proofs that keep state: replays and nonces (RFC 9449 §4.3, §8)."""

    FREE = "umilib_auth_oauth_dpop_verifier_free"

    def __init__(self, config: DPoPConfig | None = None) -> None:
        config = config or DPoPConfig()
        super().__init__(Handle.create("umilib_auth_oauth_dpop_verifier_new", *Calls.algorithms(config.algorithms), config.maximum_age, config.leeway, config.require_nonce, config.maximum_proofs, config.previous_nonces))

    def check(self, text: str, target: DPoPTarget, now: int) -> DPoPProof:
        """The proof ``text``, with every check of RFC 9449 §4.3; a refused proof raises ``Response``
        with ``invalid_dpop_proof`` or ``use_dpop_nonce``."""
        out, claims = Buffer(), Buffer()
        Calls.with_response("umilib_auth_oauth_dpop_verifier_check", self.handle, *Text.encode(text), *target.arguments(), now, ctypes.byref(out), ctypes.byref(claims))
        return DPoPProof(self.library.take(out).decode(), json.loads(self.library.take(claims)))

    def rotate_nonce(self, random: Random) -> str:
        return Calls.text("umilib_auth_oauth_dpop_verifier_rotate_nonce", self.handle, *random.source())

    def nonce(self) -> str | None:
        value = self.library.optional("umilib_auth_oauth_dpop_verifier_nonce", Buffer, self.handle)
        return None if value is None else value.decode()


# The protected resource.


class OAuthTokenScheme(enum.IntEnum):
    """How an access token is presented: ``Bearer`` (RFC 6750) or ``DPoP`` (RFC 9449)."""

    Bearer = 0
    DPoP = 1


@dataclasses.dataclass(frozen=True)
class OAuthPresentedToken:
    """An access token presented in a request (RFC 6750 §2.1, RFC 9449 §7.1)."""

    scheme: OAuthTokenScheme
    token: str

    @staticmethod
    def from_authorization(value: str) -> OAuthPresentedToken | None:
        """The token of the ``Authorization`` value, ``None`` for another scheme; a malformed Bearer or
        DPoP value raises ``Invalid``."""
        found, scheme, token = ctypes.c_bool(), ctypes.c_uint8(), Buffer()
        Library.default().call("umilib_auth_oauth_oauth_presented_token_from_authorization", *Text.encode(value), ctypes.byref(found), ctypes.byref(scheme), ctypes.byref(token))
        text = Library.default().take(token).decode()
        return OAuthPresentedToken(OAuthTokenScheme(scheme.value), text) if found.value else None

    def authorization(self) -> str:
        return f"{self.scheme.name} {self.token}"


@dataclasses.dataclass
class OAuthChallenge:
    """A challenge of ``WWW-Authenticate`` (RFC 9110 §11.6.1): a scheme and its parameters; a
    ``token68`` is a parameter of an empty name."""

    scheme: str
    parameters: list[tuple[str, str]] = dataclasses.field(default_factory=list)

    @staticmethod
    def parse(value: str) -> list[OAuthChallenge]:
        """The challenges of a ``WWW-Authenticate`` value."""
        return OAuthChallenge.take(Handle.create("umilib_auth_oauth_oauth_challenges_parse", *Text.encode(value)))

    @staticmethod
    def take(pointer: int) -> list[OAuthChallenge]:
        library = Library.default()
        try:
            challenges = []
            for index in range(library.value("umilib_auth_oauth_oauth_challenges_count", ctypes.c_size_t, pointer)):
                scheme, names, values = Buffer(), Buffer(), Buffer()
                library.call("umilib_auth_oauth_oauth_challenges_get", pointer, index, ctypes.byref(scheme), ctypes.byref(names), ctypes.byref(values))
                scheme_text, name_text, value_text = library.take(scheme).decode(), library.take(names).decode(), library.take(values).decode()
                count = len(name_text.split("\n")) if name_text or value_text else 0
                pairs = list(zip(name_text.split("\n"), value_text.split("\n"))) if count else []
                challenges.append(OAuthChallenge(scheme_text, pairs))
            return challenges
        finally:
            library.function("umilib_auth_oauth_oauth_challenges_free")(pointer)

    def push(self, name: str, value: str) -> None:
        self.parameters.append((name, value))

    def get(self, name: str) -> str | None:
        return next((value for key, value in self.parameters if key.lower() == name.lower()), None)

    def is_scheme(self, name: str) -> bool:
        return self.scheme.lower() == name.lower()

    def error(self) -> OAuthErrorResponse | None:
        code = self.get("error")
        return None if code is None else OAuthErrorResponse(code, self.get("error_description"), self.get("error_uri"))

    def encode(self) -> str:
        """The challenge as ``WWW-Authenticate`` carries it, every value a quoted-string."""
        names = Text.array([name for name, _ in self.parameters])
        values = Text.array([value for _, value in self.parameters])
        return Calls.text("umilib_auth_oauth_oauth_challenge_encode", *Text.encode(self.scheme), names[0], values[0], names[1])


@dataclasses.dataclass
class OAuthTokenInfo:
    """What a resource server knows of an access token once it was taken."""

    client_id: str | None = None
    subject: str | None = None
    scope: OAuthScope = dataclasses.field(default_factory=OAuthScope)
    audience: list[str] = dataclasses.field(default_factory=list)
    expires: int | None = None
    confirmation: str | None = None
    authentication_time: int | None = None
    authentication_context: str | None = None

    @staticmethod
    def take(pointer: int) -> OAuthTokenInfo:
        library = Library.default()
        try:
            flags = [ctypes.c_bool() for _ in range(4)]
            texts = [Buffer() for _ in range(6)]
            library.call(
                "umilib_auth_oauth_oauth_token_info_texts", pointer, ctypes.byref(flags[0]), ctypes.byref(texts[0]), ctypes.byref(flags[1]), ctypes.byref(texts[1]),
                ctypes.byref(texts[2]), ctypes.byref(texts[3]), ctypes.byref(flags[2]), ctypes.byref(texts[4]), ctypes.byref(flags[3]), ctypes.byref(texts[5]),
            )  # fmt: skip
            has_expires, expires, has_time, time = ctypes.c_bool(), ctypes.c_int64(), ctypes.c_bool(), ctypes.c_int64()
            library.call("umilib_auth_oauth_oauth_token_info_times", pointer, ctypes.byref(has_expires), ctypes.byref(expires), ctypes.byref(has_time), ctypes.byref(time))
            client_id = library.take_optional_text(flags[0], texts[0])
            subject = library.take_optional_text(flags[1], texts[1])
            scope = library.take(texts[2]).decode()
            audience = Calls.lines(library.take(texts[3]).decode())
            confirmation = library.take_optional_text(flags[2], texts[4])
            context = library.take_optional_text(flags[3], texts[5])
            return OAuthTokenInfo(
                client_id, subject, OAuthScope.parse(scope) if scope else OAuthScope(), audience,
                expires.value if has_expires.value else None, confirmation, time.value if has_time.value else None, context,
            )  # fmt: skip
        finally:
            library.function("umilib_auth_oauth_oauth_token_info_free")(pointer)

    def handle(self) -> Handle:
        """A C handle of this information, released by its ``with`` block."""
        audience = Text.array(self.audience)
        return TokenInfoHandle(Handle.create(
            "umilib_auth_oauth_oauth_token_info_new", *Text.encode(self.client_id), *Text.encode(self.subject), *Text.encode(str(self.scope) or None),
            audience[0], audience[1], self.expires is not None, self.expires or 0, *Text.encode(self.confirmation),
            self.authentication_time is not None, self.authentication_time or 0, *Text.encode(self.authentication_context),
        ))  # fmt: skip


class TokenInfoHandle(Handle):
    """The C handle of an :class:`OAuthTokenInfo`."""

    FREE = "umilib_auth_oauth_oauth_token_info_free"


class OAuthResourceError(Exception):
    """A refusal of a resource server: the status, the challenges (RFC 6750 §3) and the DPoP nonce to
    send (RFC 9449 §9)."""

    def __init__(self, status: int, challenges: list[OAuthChallenge], nonce: str | None, response: OAuthHTTPResponse | None = None) -> None:
        super().__init__(f"{status}: {', '.join(challenge.scheme for challenge in challenges)}")
        self.status = status
        self.challenges = challenges
        self.nonce = nonce
        self.response = response

    @staticmethod
    def take(pointer: int) -> OAuthResourceError:
        library = Library.default()
        try:
            status, has_nonce, nonce, challenges = ctypes.c_uint16(), ctypes.c_bool(), Buffer(), ctypes.c_void_p()
            library.call("umilib_auth_oauth_oauth_resource_error_parts", pointer, ctypes.byref(status), ctypes.byref(has_nonce), ctypes.byref(nonce), ctypes.byref(challenges))
            response = OAuthHTTPResponse.take(Handle.create("umilib_auth_oauth_oauth_resource_error_to_response", pointer))
            return OAuthResourceError(status.value, OAuthChallenge.take(challenges.value), library.take_optional_text(has_nonce, nonce), response)
        finally:
            library.function("umilib_auth_oauth_oauth_resource_error_free")(pointer)

    def to_response(self) -> OAuthHTTPResponse:
        """The HTTP response of the refusal: one ``WWW-Authenticate`` field per challenge."""
        if self.response is None:
            raise OAuthError("auth.oauth", "Invalid", "a refusal made in Python has no response")
        return self.response


class OAuthTokenValidation:
    """How a resource server checks tokens, as the variants of the Rust enum."""

    @dataclasses.dataclass
    class JWT:
        issuer: str
        keys: JWKSet
        algorithms: list[JWSAlgorithm]

    @dataclasses.dataclass
    class Introspection:
        pass


@dataclasses.dataclass
class OAuthResourceConfig:
    """The configuration of an :class:`OAuthResourceServer`."""

    resource: str
    validation: Any
    realm: str | None = None
    resource_metadata: str | None = None
    require_dpop: bool = False
    dpop: DPoPConfig = dataclasses.field(default_factory=DPoPConfig)
    leeway: int = 0


class OAuthResourceServer(Handle):
    """The checks of a protected resource (RFC 6750, RFC 9068 §4, RFC 9449 §7, RFC 9470, RFC 9728)
    without I/O. A refusal raises :class:`OAuthResourceError`."""

    FREE = "umilib_auth_oauth_oauth_resource_server_free"

    def __init__(self, config: OAuthResourceConfig) -> None:
        validation = config.validation
        jwt = isinstance(validation, OAuthTokenValidation.JWT)
        algorithms = Calls.algorithms(validation.algorithms if jwt else [])
        super().__init__(Handle.create(
            "umilib_auth_oauth_oauth_resource_server_new", *Text.encode(config.resource), *Text.encode(config.realm), *Text.encode(config.resource_metadata),
            *Text.encode(validation.issuer if jwt else None), validation.keys.handle if jwt else None, *algorithms, config.require_dpop,
            *Calls.algorithms(config.dpop.algorithms), config.dpop.maximum_age, config.dpop.leeway, config.dpop.require_nonce, config.dpop.maximum_proofs, config.dpop.previous_nonces, config.leeway,
        ))  # fmt: skip
        self.settings = config

    def config(self) -> OAuthResourceConfig:
        return self.settings

    def outcome(self, function: str, *arguments: Any, value: bool = True) -> Any:
        accepted, out, refusal = ctypes.c_bool(), ctypes.c_void_p(), ctypes.c_void_p()
        if value:
            self.library.call(function, *arguments, ctypes.byref(accepted), ctypes.byref(out), ctypes.byref(refusal))
        else:
            self.library.call(function, *arguments, ctypes.byref(accepted), ctypes.byref(refusal))
        if not accepted.value:
            raise OAuthResourceError.take(refusal.value)
        return OAuthTokenInfo.take(out.value) if value else None

    def metadata(self, authorization_servers: list[str], scopes: list[str]) -> OAuthMetadata:
        servers, scope_array = Text.array(authorization_servers), Text.array(scopes)
        text = Calls.text("umilib_auth_oauth_oauth_resource_server_metadata", self.handle, servers[0], servers[1], scope_array[0], scope_array[1])
        return OAuthMetadata(OAuthMetadataKind.Resource, json.loads(text))

    def refuse(self, error: OAuthErrorResponse | None, scheme: OAuthTokenScheme | None) -> OAuthResourceError:
        """A refusal of ``error`` (none for a request without credentials), challenged with ``scheme``,
        or every scheme the resource takes."""
        body = None if error is None else error.encode()
        return OAuthResourceError.take(Handle.create("umilib_auth_oauth_oauth_resource_server_refuse", self.handle, *Text.encode(body), scheme is not None, int(scheme or 0)))

    def presented(self, request: OAuthEndpointRequest) -> OAuthPresentedToken:
        with request.handle() as handle:
            accepted, scheme, token, refusal = ctypes.c_bool(), ctypes.c_uint8(), Buffer(), ctypes.c_void_p()
            self.library.call("umilib_auth_oauth_oauth_resource_server_presented", self.handle, handle.handle, ctypes.byref(accepted), ctypes.byref(scheme), ctypes.byref(token), ctypes.byref(refusal))
            text = self.library.take(token).decode()
            if not accepted.value:
                raise OAuthResourceError.take(refusal.value)
            return OAuthPresentedToken(OAuthTokenScheme(scheme.value), text)

    def accept_jwt(self, request: OAuthEndpointRequest, now: int) -> OAuthTokenInfo:
        """The JWT access token of ``request``, checked as RFC 9068 §4 says, and its DPoP binding."""
        with request.handle() as handle:
            return self.outcome("umilib_auth_oauth_oauth_resource_server_accept_jwt", self.handle, handle.handle, now)

    def accept_introspection(self, request: OAuthEndpointRequest, introspection: OAuthIntrospectionResponse, now: int) -> OAuthTokenInfo:
        """The token of ``request`` as ``introspection`` describes it, and its DPoP binding."""
        with request.handle() as handle:
            return self.outcome("umilib_auth_oauth_oauth_resource_server_accept_introspection", self.handle, handle.handle, *Text.encode(introspection.encode()), now)

    def require_scope(self, info: OAuthTokenInfo, scope: OAuthScope, scheme: OAuthTokenScheme) -> None:
        """Raises ``insufficient_scope`` unless ``info`` grants ``scope`` (RFC 6750 §3.1)."""
        with info.handle() as handle:
            self.outcome("umilib_auth_oauth_oauth_resource_server_require_scope", self.handle, handle.handle, *Text.encode(str(scope) or None), int(scheme), value=False)

    def require_authentication(self, info: OAuthTokenInfo, now: int, max_age: int | None, acr_values: list[str], scheme: OAuthTokenScheme) -> None:
        """Raises ``insufficient_user_authentication`` unless the user authenticated recently and
        strongly enough (RFC 9470 §3)."""
        values = Text.array(acr_values)
        with info.handle() as handle:
            self.outcome("umilib_auth_oauth_oauth_resource_server_require_authentication", self.handle, handle.handle, now, max_age is not None, max_age or 0, values[0], values[1], int(scheme), value=False)

    def rotate_dpop_nonce(self, random: Random) -> str:
        return Calls.text("umilib_auth_oauth_oauth_resource_server_rotate_dpop_nonce", self.handle, *random.source())
