/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_OAUTH_H
#define UMILIB_AUTH_OAUTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/jwt.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The parameters of a request or a response, in order.
 */
typedef struct umilib_auth_oauth_OAuthParameters umilib_auth_oauth_OAuthParameters;

/**
 * A PKCE code verifier, zeroized when released.
 */
typedef struct umilib_auth_oauth_PKCEVerifier umilib_auth_oauth_PKCEVerifier;

/**
 * A request that reached an endpoint.
 */
typedef struct umilib_auth_oauth_OAuthEndpointRequest umilib_auth_oauth_OAuthEndpointRequest;

/**
 * A request a client asks to send.
 */
typedef struct umilib_auth_oauth_OAuthHTTPRequest umilib_auth_oauth_OAuthHTTPRequest;

/**
 * The response of an endpoint.
 */
typedef struct umilib_auth_oauth_OAuthHTTPResponse umilib_auth_oauth_OAuthHTTPResponse;

/**
 * A client of the authorization code grant and the token endpoint.
 */
typedef struct umilib_auth_oauth_OAuthClient umilib_auth_oauth_OAuthClient;

/**
 * An authorization server.
 */
typedef struct umilib_auth_oauth_OAuthServer umilib_auth_oauth_OAuthServer;

/**
 * The configuration of an authorization server.
 */
typedef struct umilib_auth_oauth_OAuthServerConfig umilib_auth_oauth_OAuthServerConfig;

/**
 * The scalar settings of a server's configuration: lifetimes in seconds, and limits.
 */
typedef struct umilib_auth_oauth_OAuthServerLimits {
    bool require_pkce;
    bool require_pushed_authorization_requests;
    bool rotate_refresh_tokens;
    bool dpop_require_nonce;
    int64_t code_lifetime;
    int64_t access_token_lifetime;
    int64_t refresh_token_lifetime;
    int64_t pushed_request_lifetime;
    int64_t device_code_lifetime;
    int64_t device_interval;
    int64_t maximum_assertion_lifetime;
    int64_t dpop_maximum_age;
    int64_t dpop_leeway;
    size_t token_octets;
    size_t maximum_codes;
    size_t maximum_tokens;
    size_t maximum_pushed_requests;
    size_t maximum_devices;
    size_t maximum_assertions;
    size_t dpop_maximum_proofs;
    size_t dpop_previous_nonces;
    size_t user_code_length;
    size_t maximum_parameters;
    size_t maximum_codes_per_client;
    size_t maximum_tokens_per_client;
    size_t maximum_pushed_requests_per_client;
    size_t maximum_devices_per_client;
    size_t maximum_assertions_per_client;
} umilib_auth_oauth_OAuthServerLimits;

/**
 * An authorization request waiting for the user's decision.
 */
typedef struct umilib_auth_oauth_OAuthAuthorization umilib_auth_oauth_OAuthAuthorization;

/**
 * The checks of a protected resource.
 */
typedef struct umilib_auth_oauth_OAuthResourceServer umilib_auth_oauth_OAuthResourceServer;

/**
 * What a resource server knows of a token it took.
 */
typedef struct umilib_auth_oauth_OAuthTokenInfo umilib_auth_oauth_OAuthTokenInfo;

/**
 * A refusal of a resource server.
 */
typedef struct umilib_auth_oauth_OAuthResourceError umilib_auth_oauth_OAuthResourceError;

/**
 * The challenges of a WWW-Authenticate value.
 */
typedef struct umilib_auth_oauth_OAuthChallenges umilib_auth_oauth_OAuthChallenges;

/**
 * The checks of DPoP proofs that keep state.
 */
typedef struct umilib_auth_oauth_DPoPVerifier umilib_auth_oauth_DPoPVerifier;

/**
 * Writes an empty list of parameters into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_parameters_new(umilib_auth_oauth_OAuthParameters** out);

/**
 * Releases a list of parameters. Does nothing if `parameters` is null.
 */
void umilib_auth_oauth_oauth_parameters_free(umilib_auth_oauth_OAuthParameters* parameters);

/**
 * Writes the parameters of the form-encoded `length` bytes at `input` into `out`: those
 * named by the `count` strings at `repeatable` may be given more than once.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_parameters_parse(const uint8_t* input, size_t length, const char* const* repeatable, size_t count, umilib_auth_oauth_OAuthParameters** out);

/**
 * Writes the parameters of the query of the URI reference at `uri` into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_parameters_from_query(const uint8_t* uri, size_t length, umilib_auth_oauth_OAuthParameters** out);

/**
 * Writes the URI reference at `uri` with the parameters added to its query into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_parameters_add_to_query(const umilib_auth_oauth_OAuthParameters* parameters, const uint8_t* uri, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the number of parameters into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_parameters_count(const umilib_auth_oauth_OAuthParameters* parameters, size_t* out);

/**
 * Writes the name of the parameter `index` into `out_name` and its value into `out_value`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_parameters_entry(const umilib_auth_oauth_OAuthParameters* parameters, size_t index, umilib_ffi_Buffer* out_name, umilib_ffi_Buffer* out_value);

/**
 * Writes whether the parameter of the name at `name` is present into `out_has` and its
 * first value into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_parameters_get(const umilib_auth_oauth_OAuthParameters* parameters, const uint8_t* name, size_t length, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Appends the parameter of the UTF-8 `name` and `value`; an empty value is not added.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_parameters_push(umilib_auth_oauth_OAuthParameters* parameters, const uint8_t* name, size_t name_length, const uint8_t* value, size_t value_length);

/**
 * Removes every value of the parameter of the name at `name`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_parameters_remove(umilib_auth_oauth_OAuthParameters* parameters, const uint8_t* name, size_t length);

/**
 * Writes the parameters in the form encoding into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_parameters_encode(const umilib_auth_oauth_OAuthParameters* parameters, umilib_ffi_Buffer* out);

/**
 * Writes the scope of the space-delimited text at `scope` (RFC 6749 §3.3), each token once,
 * into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_scope_parse(const uint8_t* scope, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes whether every token of the scope at `scope` is in the scope at `other` into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_scope_is_subset_of(const uint8_t* scope, size_t length, const uint8_t* other, size_t other_length, bool* out);

/**
 * Writes the tokens of the scope at `scope` that are in the scope at `other` into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_scope_intersection(const uint8_t* scope, size_t length, const uint8_t* other, size_t other_length, umilib_ffi_Buffer* out);

/**
 * Writes the code verifier of the text at `text` (RFC 7636 §4.1) into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_pkce_verifier_new(const uint8_t* text, size_t length, umilib_auth_oauth_PKCEVerifier** out);

/**
 * Writes a code verifier of 32 random octets into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_pkce_verifier_generate(void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_oauth_PKCEVerifier** out);

/**
 * Zeroizes and releases a verifier. Does nothing if `verifier` is null.
 */
void umilib_auth_oauth_pkce_verifier_free(umilib_auth_oauth_PKCEVerifier* verifier);

/**
 * Writes the verifier's text into `out`, which the caller zeroizes.
 */
const umilib_ffi_Status* umilib_auth_oauth_pkce_verifier_text(const umilib_auth_oauth_PKCEVerifier* verifier, umilib_ffi_Buffer* out);

/**
 * Writes the challenge of the verifier by `method` (0 S256) into `out` (RFC 7636 §4.2).
 */
const umilib_ffi_Status* umilib_auth_oauth_pkce_verifier_challenge(const umilib_auth_oauth_PKCEVerifier* verifier, uint8_t method, umilib_ffi_Buffer* out);

/**
 * Writes the method of the name at `name` (`S256`; `plain` and others fail) into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_pkce_method_parse(const uint8_t* name, size_t length, uint8_t* out);

/**
 * Succeeds if the text at `value` is a challenge of `method` (0 S256).
 */
const umilib_ffi_Status* umilib_auth_oauth_pkce_challenge_check(uint8_t method, const uint8_t* value, size_t length);

/**
 * Writes whether `verifier` is the verifier of the challenge at `value` of `method` (RFC 7636
 * §4.6, compared in constant time) into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_pkce_challenge_verify(uint8_t method, const uint8_t* value, size_t length, const umilib_auth_oauth_PKCEVerifier* verifier, bool* out);

/**
 * Writes the JSON of the error response of the code at `code`, the description at
 * `description` and the URI at `uri` (null for none), checked against RFC 6749 Appendix A,
 * into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_error_response_encode(const uint8_t* code, size_t code_length, const uint8_t* description, size_t description_length, const uint8_t* uri, size_t uri_length, umilib_ffi_Buffer* out);

/**
 * Writes the code, whether there is a description, the description, whether there is a
 * URI and the URI of the error response of the JSON at `body` (RFC 6749 §5.2).
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_error_response_decode(const uint8_t* body, size_t length, umilib_ffi_Buffer* out_code, bool* out_has_description, umilib_ffi_Buffer* out_description, bool* out_has_uri, umilib_ffi_Buffer* out_uri);

/**
 * Writes the canonical parameters of the authorization request of `parameters` (RFC 6749
 * §4.1.1, RFC 7636 §4.3, RFC 8707, RFC 9126 §4, RFC 9449 §10) into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_authorization_request_check(const umilib_auth_oauth_OAuthParameters* parameters, umilib_auth_oauth_OAuthParameters** out);

/**
 * Writes the canonical parameters of the authorization response of `parameters` (RFC 6749
 * §4.1.2, RFC 9207) into `out`; an error response fails with Response.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_authorization_response_check(const umilib_auth_oauth_OAuthParameters* parameters, umilib_auth_oauth_OAuthParameters** out, umilib_ffi_Buffer* out_error);

/**
 * Writes the canonical parameters of the token request of `parameters` (RFC 6749 §3.2,
 * §4.1.3, §4.4.2, §6; RFC 8628 §3.4; RFC 7523 §2.1), without client authentication, into
 * `out`; an unknown grant type fails with Invalid.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_token_request_check(const umilib_auth_oauth_OAuthParameters* parameters, umilib_auth_oauth_OAuthParameters** out);

/**
 * Writes the canonical JSON of the token response of `status` and the body at `body`
 * (RFC 6749 §5.1) into `out`; an error response fails with Response.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_token_response_decode(uint16_t status, const uint8_t* body, size_t length, umilib_ffi_Buffer* out, umilib_ffi_Buffer* out_error);

/**
 * Writes the canonical JSON of the introspection response of `status` and `body` (RFC 7662
 * §2.2) into `out`; an error response fails with Response.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_introspection_response_decode(uint16_t status, const uint8_t* body, size_t length, umilib_ffi_Buffer* out, umilib_ffi_Buffer* out_error);

/**
 * Writes the canonical JSON of the device authorization response of `status` and `body`
 * (RFC 8628 §3.2) into `out`; an error response fails with Response.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_device_authorization_response_decode(uint16_t status, const uint8_t* body, size_t length, umilib_ffi_Buffer* out, umilib_ffi_Buffer* out_error);

/**
 * Writes the canonical JSON of the pushed authorization response of `status` and `body`
 * (RFC 9126 §2.2) into `out`; an error response fails with Response.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_pushed_authorization_response_decode(uint16_t status, const uint8_t* body, size_t length, umilib_ffi_Buffer* out, umilib_ffi_Buffer* out_error);

/**
 * Writes the canonical JSON of the metadata document of `kind` (0 server, RFC 8414; 1
 * resource, RFC 9728) at `body` into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_metadata_decode(uint8_t kind, const uint8_t* body, size_t length, umilib_ffi_Buffer* out);

/**
 * Succeeds if the metadata document of `kind` at `body` describes the identifier at
 * `expected` (RFC 8414 §3.3, RFC 9728 §3.3); fails with Issuer otherwise.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_metadata_check(uint8_t kind, const uint8_t* body, size_t length, const uint8_t* expected, size_t expected_length);

/**
 * Writes the URL of the metadata document of `kind` of the identifier at `identifier`
 * (RFC 8414 §3.1, RFC 9728 §3.1) into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_metadata_location(uint8_t kind, const uint8_t* identifier, size_t length, umilib_ffi_Buffer* out);

/**
 * Adds the client authentication of `method` (0 none, 1 client_secret_basic, 2
 * client_secret_post, 3 private_key_jwt) of the client at `client_id`, with the secret at
 * `secret` or the private `key` and the JWS algorithm `algorithm`, to a request to the
 * server `audience` at `now`, an assertion living `lifetime` seconds (RFC 6749 §2.3,
 * RFC 7523 §2.2): parameters go into
 * `parameters`; whether there is an `Authorization` header goes into `out_has` and its
 * value, which the caller zeroizes, into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_client_authentication_apply(uint8_t method, const uint8_t* client_id, size_t client_id_length, const uint8_t* secret, size_t secret_length, const umilib_protocol_jwt_JWK* key, uint8_t algorithm, const uint8_t* audience, size_t audience_length, int64_t now, int64_t lifetime, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_oauth_OAuthParameters* parameters, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Writes the value of the `Authorization` header of client_secret_basic for the client
 * at `client_id` and the secret at `secret` (RFC 6749 §2.3.1) into `out`, which the caller
 * zeroizes.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_client_authentication_basic_credentials(const uint8_t* client_id, size_t client_id_length, const uint8_t* secret, size_t secret_length, umilib_ffi_Buffer* out);

/**
 * Writes a request of the method at `method`, the URI at `uri` and the `length` bytes at
 * `body`, without header fields, into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_endpoint_request_new(const uint8_t* method, size_t method_length, const uint8_t* uri, size_t uri_length, const uint8_t* body, size_t length, umilib_auth_oauth_OAuthEndpointRequest** out);

/**
 * Releases a request. Does nothing if `request` is null.
 */
void umilib_auth_oauth_oauth_endpoint_request_free(umilib_auth_oauth_OAuthEndpointRequest* request);

/**
 * Sets the `Authorization`, `DPoP` and `Content-Type` header fields of the request to the
 * texts at `authorization`, `dpop` and `content_type` (null for none).
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_endpoint_request_set_fields(umilib_auth_oauth_OAuthEndpointRequest* request, const uint8_t* authorization, size_t authorization_length, const uint8_t* dpop, size_t dpop_length, const uint8_t* content_type, size_t content_type_length);

/**
 * Releases a request made by a client. Does nothing if `request` is null.
 */
void umilib_auth_oauth_oauth_http_request_free(umilib_auth_oauth_OAuthHTTPRequest* request);

/**
 * Writes the method, the URI, the header fields (`name: value` lines joined by LF) and the
 * body of a request made by a client into the outputs; the caller zeroizes the fields and
 * the body, which may hold secrets.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_http_request_parts(const umilib_auth_oauth_OAuthHTTPRequest* request, umilib_ffi_Buffer* out_method, umilib_ffi_Buffer* out_uri, umilib_ffi_Buffer* out_headers, umilib_ffi_Buffer* out_body);

/**
 * Releases a response. Does nothing if `response` is null.
 */
void umilib_auth_oauth_oauth_http_response_free(umilib_auth_oauth_OAuthHTTPResponse* response);

/**
 * Writes the status, the header fields (`name: value` lines joined by LF) and the body of a
 * response into the outputs.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_http_response_parts(const umilib_auth_oauth_OAuthHTTPResponse* response, uint16_t* out_status, umilib_ffi_Buffer* out_headers, umilib_ffi_Buffer* out_body);

/**
 * Writes a client of the server whose metadata document (checked against its issuer) is
 * the JSON at `metadata` into `out`: it authenticates with `method` (0 none, 1
 * client_secret_basic, 2 client_secret_post, 3 private_key_jwt) as the client at
 * `client_id`, with the secret at `secret` or the private `key` and the JWS algorithm
 * `algorithm`, and is redirected to the URI at `redirect_uri`; the limits are the defaults.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_client_new(const uint8_t* metadata, size_t metadata_length, uint8_t method, const uint8_t* client_id, size_t client_id_length, const uint8_t* secret, size_t secret_length, const umilib_protocol_jwt_JWK* key, uint8_t algorithm, const uint8_t* redirect_uri, size_t redirect_uri_length, umilib_auth_oauth_OAuthClient** out);

/**
 * Releases a client. Does nothing if `client` is null.
 */
void umilib_auth_oauth_oauth_client_free(umilib_auth_oauth_OAuthClient* client);

/**
 * Writes the limits of the client: the most pending requests, their lifetime in seconds,
 * the random octets of a state, and the seconds a client assertion lives.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_client_limits(const umilib_auth_oauth_OAuthClient* client, size_t* out_maximum_pending, int64_t* out_pending_lifetime, size_t* out_state_octets, int64_t* out_assertion_lifetime);

/**
 * Writes the number of authorization requests waiting for their response into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_client_pending_count(const umilib_auth_oauth_OAuthClient* client, size_t* out);

/**
 * Writes the URL to send the user's browser to (RFC 6749 §4.1.1 with PKCE, RFC 7636 §4.3)
 * for the scope at `scope` (null for none) and the `count` resources at `resources`, at
 * `now`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_client_authorize(umilib_auth_oauth_OAuthClient* client, const uint8_t* scope, size_t scope_length, const char* const* resources, size_t count, int64_t now, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes the canonical parameters of the token request of the authorization response at
 * the URI `redirect` (RFC 6749 §4.1.2, §10.12; RFC 9207 §2.4) into `out`; an error
 * response fails with Response after the same checks, its JSON into `out_error`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_client_callback(umilib_auth_oauth_OAuthClient* client, const uint8_t* redirect, size_t length, int64_t now, umilib_auth_oauth_OAuthParameters** out, umilib_ffi_Buffer* out_error);

/**
 * Writes the HTTP request of the token request of `parameters` (its canonical
 * parameters), with the client's authentication (RFC 6749 §3.2, §2.3), at `now`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_client_token_request(const umilib_auth_oauth_OAuthClient* client, const umilib_auth_oauth_OAuthParameters* parameters, int64_t now, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_oauth_OAuthHTTPRequest** out);

/**
 * Writes the HTTP POST of `parameters` to the endpoint at `endpoint` of the server, with
 * the client's authentication, at `now`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_client_endpoint_request(const umilib_auth_oauth_OAuthClient* client, const uint8_t* endpoint, size_t length, const umilib_auth_oauth_OAuthParameters* parameters, int64_t now, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_oauth_OAuthHTTPRequest** out);

/**
 * Writes the configuration of the issuer at `issuer`, with the endpoints and settings of
 * `OAuthServerConfig::new`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_config_new(const uint8_t* issuer, size_t length, umilib_auth_oauth_OAuthServerConfig** out);

/**
 * Releases a configuration. Does nothing if `config` is null.
 */
void umilib_auth_oauth_oauth_server_config_free(umilib_auth_oauth_OAuthServerConfig* config);

/**
 * Writes the scalar settings of `config` into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_config_limits(const umilib_auth_oauth_OAuthServerConfig* config, umilib_auth_oauth_OAuthServerLimits* out);

/**
 * Sets the scalar settings of `config` to `limits`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_config_set_limits(umilib_auth_oauth_OAuthServerConfig* config, umilib_auth_oauth_OAuthServerLimits limits);

/**
 * Writes the endpoints of `config`, LF-joined in the order authorization, token,
 * introspection, revocation, pushed authorization request, device authorization,
 * verification, JWKS (an absent one empty), into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_config_endpoints(const umilib_auth_oauth_OAuthServerConfig* config, umilib_ffi_Buffer* out);

/**
 * Sets the endpoints of `config` to the `count` (8) strings at `endpoints`, in the order of
 * `umilib_auth_oauth_oauth_server_config_endpoints`; an empty one after the token endpoint
 * is absent.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_config_set_endpoints(umilib_auth_oauth_OAuthServerConfig* config, const char* const* endpoints, size_t count);

/**
 * Sets the signature algorithms of client assertions and of DPoP proofs to the indices at
 * `assertion` and `dpop`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_config_set_algorithms(umilib_auth_oauth_OAuthServerConfig* config, const uint8_t* assertion, size_t assertion_count, const uint8_t* dpop, size_t dpop_count);

/**
 * Writes the indices of the signature algorithms of client assertions into `out_assertion`
 * and of DPoP proofs into `out_dpop`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_config_algorithms(const umilib_auth_oauth_OAuthServerConfig* config, umilib_ffi_Buffer* out_assertion, umilib_ffi_Buffer* out_dpop);

/**
 * Makes the access tokens of `config` opaque if `key` is null, or JWTs of RFC 9068 signed
 * with the private `key` by the JWS algorithm `algorithm`, whose default audience is the
 * text at `default_audience`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_config_set_access_token_format(umilib_auth_oauth_OAuthServerConfig* config, const umilib_protocol_jwt_JWK* key, uint8_t algorithm, const uint8_t* default_audience, size_t length);

/**
 * Writes a server of a copy of `config` into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_new(const umilib_auth_oauth_OAuthServerConfig* config, umilib_auth_oauth_OAuthServer** out);

/**
 * Releases a server. Does nothing if `server` is null.
 */
void umilib_auth_oauth_oauth_server_free(umilib_auth_oauth_OAuthServer* server);

/**
 * Writes a copy of the configuration of `server` into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_config(const umilib_auth_oauth_OAuthServer* server, umilib_auth_oauth_OAuthServerConfig** out);

/**
 * Registers the client at `client_id`, which authenticates with `method` (0 none, 1
 * client_secret_basic, 2 client_secret_post, 3 private_key_jwt) and the secret at `secret`
 * or the public `keys`, may be redirected to the `redirect_count` URIs at `redirect_uris`,
 * may use the `grant_count` grant types at `grant_types` and the scope at `scope`, and
 * may ask for the `resource_count` resources at `resources` (any if `resources` is null),
 * and may introspect if `introspection`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_register(umilib_auth_oauth_OAuthServer* server, const uint8_t* client_id, size_t client_id_length, uint8_t method, const uint8_t* secret, size_t secret_length, const umilib_protocol_jwt_JWKSet* keys, const char* const* redirect_uris, size_t redirect_count, const char* const* grant_types, size_t grant_count, const uint8_t* scope, size_t scope_length, const char* const* resources, size_t resource_count, bool introspection);

/**
 * Removes the client at `client_id` and revokes what it was issued; writes whether it was
 * registered into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_unregister(umilib_auth_oauth_OAuthServer* server, const uint8_t* client_id, size_t length, bool* out);

/**
 * Writes the JSON of the server's metadata document (RFC 8414 §2) into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_metadata(const umilib_auth_oauth_OAuthServer* server, umilib_ffi_Buffer* out);

/**
 * Writes whether the server issues JWT access tokens into `out_has` and the JSON of the
 * JWK Set of their public key into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_jwks(const umilib_auth_oauth_OAuthServer* server, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Checks the authorization request of `parameters` at `now` (RFC 6749 §4.1.1, RFC 9126
 * §4). Writes into `out_kind` 0 if it was taken, the authorization into `out`; 1 if the user
 * is to be told of the error, its JSON into `out_text`; 2 if the user agent is to be sent to
 * the URI written into `out_text`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_authorize(umilib_auth_oauth_OAuthServer* server, const umilib_auth_oauth_OAuthParameters* parameters, int64_t now, uint8_t* out_kind, umilib_auth_oauth_OAuthAuthorization** out, umilib_ffi_Buffer* out_text);

/**
 * Releases an authorization. Does nothing if `authorization` is null.
 */
void umilib_auth_oauth_oauth_authorization_free(umilib_auth_oauth_OAuthAuthorization* authorization);

/**
 * Writes the client, the redirect URI, the scope, the state (whether there is one into
 * `out_has_state`), the resources (joined by LF) and the parameters the server does not
 * know of `authorization` into the outputs.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_authorization_parts(const umilib_auth_oauth_OAuthAuthorization* authorization, umilib_ffi_Buffer* out_client_id, umilib_ffi_Buffer* out_redirect_uri, umilib_ffi_Buffer* out_scope, bool* out_has_state, umilib_ffi_Buffer* out_state, umilib_ffi_Buffer* out_resources, umilib_auth_oauth_OAuthParameters** out_other);

/**
 * Issues a code for `authorization`, which the resource owner at `subject` approved for the
 * scope at `scope` and the `count` resources at `resources` (their own or narrower),
 * having authenticated at `authentication_time` (if `has_authentication_time`) with the
 * context at `context` (null for none); writes the URI to send the user agent to into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_approve(umilib_auth_oauth_OAuthServer* server, const umilib_auth_oauth_OAuthAuthorization* authorization, const uint8_t* subject, size_t subject_length, const uint8_t* scope, size_t scope_length, const char* const* resources, size_t count, bool has_authentication_time, int64_t authentication_time, const uint8_t* context, size_t context_length, int64_t now, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes the URI to send the user agent to when the resource owner denies `authorization`
 * into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_deny(const umilib_auth_oauth_OAuthServer* server, const umilib_auth_oauth_OAuthAuthorization* authorization, umilib_ffi_Buffer* out);

/**
 * Writes the response of the token endpoint to `request` at `now` into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_token(umilib_auth_oauth_OAuthServer* server, const umilib_auth_oauth_OAuthEndpointRequest* request, int64_t now, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_oauth_OAuthHTTPResponse** out);

/**
 * Writes the response of the introspection endpoint to `request` at `now` into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_introspect(umilib_auth_oauth_OAuthServer* server, const umilib_auth_oauth_OAuthEndpointRequest* request, int64_t now, umilib_auth_oauth_OAuthHTTPResponse** out);

/**
 * Writes the response of the revocation endpoint to `request` at `now` into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_revoke(umilib_auth_oauth_OAuthServer* server, const umilib_auth_oauth_OAuthEndpointRequest* request, int64_t now, umilib_auth_oauth_OAuthHTTPResponse** out);

/**
 * Writes the response of the pushed authorization request endpoint to `request` at `now`
 * into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_push(umilib_auth_oauth_OAuthServer* server, const umilib_auth_oauth_OAuthEndpointRequest* request, int64_t now, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_oauth_OAuthHTTPResponse** out);

/**
 * Writes the response of the device authorization endpoint to `request` at `now` into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_device_authorize(umilib_auth_oauth_OAuthServer* server, const umilib_auth_oauth_OAuthEndpointRequest* request, int64_t now, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_oauth_OAuthHTTPResponse** out);

/**
 * Writes the JSON of what introspection says of the token at `token` at `now` (RFC 7662
 * §2.2) into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_introspection(const umilib_auth_oauth_OAuthServer* server, const uint8_t* token, size_t length, int64_t now, umilib_ffi_Buffer* out);

/**
 * Writes whether a pending device authorization has the user code at `user_code` into
 * `out_found`, and its client, scope and resources (joined by LF) into the other outputs.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_device(const umilib_auth_oauth_OAuthServer* server, const uint8_t* user_code, size_t length, int64_t now, bool* out_found, umilib_ffi_Buffer* out_client_id, umilib_ffi_Buffer* out_scope, umilib_ffi_Buffer* out_resources);

/**
 * Records that the user at `subject` approved the device authorization of the user code
 * at `user_code` for the scope at `scope` and the `count` resources at `resources`, having
 * authenticated as `umilib_auth_oauth_oauth_server_approve` takes it.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_device_approve(umilib_auth_oauth_OAuthServer* server, const uint8_t* user_code, size_t user_code_length, const uint8_t* subject, size_t subject_length, const uint8_t* scope, size_t scope_length, const char* const* resources, size_t count, bool has_authentication_time, int64_t authentication_time, const uint8_t* context, size_t context_length, int64_t now);

/**
 * Records that the user denied the device authorization of the user code at `user_code`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_device_deny(umilib_auth_oauth_OAuthServer* server, const uint8_t* user_code, size_t length, int64_t now);

/**
 * Revokes every token issued for the resource owner at `subject`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_revoke_subject(umilib_auth_oauth_OAuthServer* server, const uint8_t* subject, size_t length);

/**
 * Forgets what expired before `now`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_expire(umilib_auth_oauth_OAuthServer* server, int64_t now);

/**
 * Makes a new DPoP nonce (RFC 9449 §8) and writes it into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_server_rotate_dpop_nonce(umilib_auth_oauth_OAuthServer* server, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes the checks of the resource at `resource` into `out`: with the realm at `realm` and
 * the metadata URL at `resource_metadata` in its challenges (null for none); taking the JWT
 * access tokens of the issuer at `issuer`, signed by one of `keys` with one of the
 * `algorithm_count` JWS algorithms at `algorithms`, or, if `issuer` is null, introspected
 * ones; only DPoP-bound ones if `require_dpop`; DPoP proofs signed by one of the
 * `dpop_count` algorithms at `dpop_algorithms`, with an `iat` at most `dpop_maximum_age`
 * seconds old and `dpop_leeway` ahead, a nonce if `dpop_require_nonce`, and at most
 * `dpop_maximum_proofs` identifiers kept, `dpop_previous_nonces` nonces before the current
 * one taken; `leeway` seconds of clock skew on `exp`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_resource_server_new(const uint8_t* resource, size_t resource_length, const uint8_t* realm, size_t realm_length, const uint8_t* resource_metadata, size_t resource_metadata_length, const uint8_t* issuer, size_t issuer_length, const umilib_protocol_jwt_JWKSet* keys, const uint8_t* algorithms, size_t algorithm_count, bool require_dpop, const uint8_t* dpop_algorithms, size_t dpop_count, int64_t dpop_maximum_age, int64_t dpop_leeway, bool dpop_require_nonce, size_t dpop_maximum_proofs, size_t dpop_previous_nonces, uint64_t leeway, umilib_auth_oauth_OAuthResourceServer** out);

/**
 * Releases a resource server. Does nothing if `server` is null.
 */
void umilib_auth_oauth_oauth_resource_server_free(umilib_auth_oauth_OAuthResourceServer* server);

/**
 * Writes the JSON of the resource's metadata document (RFC 9728 §2), naming the
 * `server_count` authorization servers at `servers` and the `scope_count` scopes at
 * `scopes`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_resource_server_metadata(const umilib_auth_oauth_OAuthResourceServer* server, const char* const* servers, size_t server_count, const char* const* scopes, size_t scope_count, umilib_ffi_Buffer* out);

/**
 * Writes into `out` the refusal of the error response whose JSON is at `error` (null for a
 * request without credentials), challenged with `scheme` (0 Bearer, 1 DPoP) if `has_scheme`,
 * or with every scheme the resource takes.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_resource_server_refuse(const umilib_auth_oauth_OAuthResourceServer* server, const uint8_t* error, size_t error_length, bool has_scheme, uint8_t scheme, umilib_auth_oauth_OAuthResourceError** out);

/**
 * Reads the access token of `request` (RFC 6750 §2.1, RFC 9449 §7.1): writes whether there
 * is one into `out_accepted`, its scheme (0 Bearer, 1 DPoP) into `out_scheme` and the token
 * into `out_token`, or the refusal into `out_refusal`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_resource_server_presented(const umilib_auth_oauth_OAuthResourceServer* server, const umilib_auth_oauth_OAuthEndpointRequest* request, bool* out_accepted, uint8_t* out_scheme, umilib_ffi_Buffer* out_token, umilib_auth_oauth_OAuthResourceError** out_refusal);

/**
 * Takes the JWT access token of `request` at `now` (RFC 9068 §4, RFC 9449 §7): writes whether
 * it was taken into `out_accepted` and what it says into `out`, or the refusal into
 * `out_refusal`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_resource_server_accept_jwt(umilib_auth_oauth_OAuthResourceServer* server, const umilib_auth_oauth_OAuthEndpointRequest* request, int64_t now, bool* out_accepted, umilib_auth_oauth_OAuthTokenInfo** out, umilib_auth_oauth_OAuthResourceError** out_refusal);

/**
 * Takes the access token of `request` as the introspection response whose JSON is at
 * `introspection` describes it (RFC 7662 §2.2, RFC 9449 §7), as
 * `umilib_auth_oauth_oauth_resource_server_accept_jwt` does.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_resource_server_accept_introspection(umilib_auth_oauth_OAuthResourceServer* server, const umilib_auth_oauth_OAuthEndpointRequest* request, const uint8_t* introspection, size_t length, int64_t now, bool* out_accepted, umilib_auth_oauth_OAuthTokenInfo** out, umilib_auth_oauth_OAuthResourceError** out_refusal);

/**
 * Checks that `info` grants the scope at `scope` (null for none; RFC 6750 §3.1), challenged with `scheme`:
 * writes whether it does into `out_accepted`, or the refusal into `out_refusal`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_resource_server_require_scope(const umilib_auth_oauth_OAuthResourceServer* server, const umilib_auth_oauth_OAuthTokenInfo* info, const uint8_t* scope, size_t length, uint8_t scheme, bool* out_accepted, umilib_auth_oauth_OAuthResourceError** out_refusal);

/**
 * Checks that the user of `info` authenticated at most `max_age` seconds before `now` (if
 * `has_max_age`) and with one of the `count` contexts at `acr_values` (RFC 9470 §3),
 * challenged with `scheme`, as `umilib_auth_oauth_oauth_resource_server_require_scope` does.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_resource_server_require_authentication(const umilib_auth_oauth_OAuthResourceServer* server, const umilib_auth_oauth_OAuthTokenInfo* info, int64_t now, bool has_max_age, int64_t max_age, const char* const* acr_values, size_t count, uint8_t scheme, bool* out_accepted, umilib_auth_oauth_OAuthResourceError** out_refusal);

/**
 * Makes a new DPoP nonce (RFC 9449 §9) and writes it into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_resource_server_rotate_dpop_nonce(umilib_auth_oauth_OAuthResourceServer* server, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes what a token says: the client at `client_id` and the user at `subject` (null for
 * none), the scope at `scope`, the `count` audiences at `audience`, the expiry (if
 * `has_expires`), the thumbprint of its DPoP key at `confirmation` (null for none), and
 * when (if `has_authentication_time`) and how (`context`, null for none) the user
 * authenticated, into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_token_info_new(const uint8_t* client_id, size_t client_id_length, const uint8_t* subject, size_t subject_length, const uint8_t* scope, size_t scope_length, const char* const* audience, size_t count, bool has_expires, int64_t expires, const uint8_t* confirmation, size_t confirmation_length, bool has_authentication_time, int64_t authentication_time, const uint8_t* context, size_t context_length, umilib_auth_oauth_OAuthTokenInfo** out);

/**
 * Releases what a token says. Does nothing if `info` is null.
 */
void umilib_auth_oauth_oauth_token_info_free(umilib_auth_oauth_OAuthTokenInfo* info);

/**
 * Writes the texts of `info`: the client and the user (each with whether it is present),
 * the scope, the audiences joined by LF, the DPoP thumbprint and the authentication context
 * (each with whether it is present).
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_token_info_texts(const umilib_auth_oauth_OAuthTokenInfo* info, bool* out_has_client_id, umilib_ffi_Buffer* out_client_id, bool* out_has_subject, umilib_ffi_Buffer* out_subject, umilib_ffi_Buffer* out_scope, umilib_ffi_Buffer* out_audience, bool* out_has_confirmation, umilib_ffi_Buffer* out_confirmation, bool* out_has_context, umilib_ffi_Buffer* out_context);

/**
 * Writes the times of `info`: the expiry and when the user authenticated, each with whether
 * it is present.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_token_info_times(const umilib_auth_oauth_OAuthTokenInfo* info, bool* out_has_expires, int64_t* out_expires, bool* out_has_authentication_time, int64_t* out_authentication_time);

/**
 * Releases a refusal. Does nothing if `refusal` is null.
 */
void umilib_auth_oauth_oauth_resource_error_free(umilib_auth_oauth_OAuthResourceError* refusal);

/**
 * Writes the status of `refusal` into `out_status`, whether it sends a DPoP nonce into
 * `out_has_nonce`, the nonce into `out_nonce` and a copy of its challenges into
 * `out_challenges`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_resource_error_parts(const umilib_auth_oauth_OAuthResourceError* refusal, uint16_t* out_status, bool* out_has_nonce, umilib_ffi_Buffer* out_nonce, umilib_auth_oauth_OAuthChallenges** out_challenges);

/**
 * Writes the HTTP response of `refusal` (one `WWW-Authenticate` field per challenge) into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_resource_error_to_response(const umilib_auth_oauth_OAuthResourceError* refusal, umilib_auth_oauth_OAuthHTTPResponse** out);

/**
 * Writes the challenges of the `WWW-Authenticate` value at `value` (RFC 9110 §11.6.1) into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_challenges_parse(const uint8_t* value, size_t length, umilib_auth_oauth_OAuthChallenges** out);

/**
 * Releases a list of challenges. Does nothing if `challenges` is null.
 */
void umilib_auth_oauth_oauth_challenges_free(umilib_auth_oauth_OAuthChallenges* challenges);

/**
 * Writes the number of challenges into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_challenges_count(const umilib_auth_oauth_OAuthChallenges* challenges, size_t* out);

/**
 * Writes the scheme of the challenge `index` into `out_scheme`, the names of its parameters
 * joined by LF into `out_names` and their values joined by LF into `out_values` (a quoted
 * value has no LF, RFC 9110 §5.6.4).
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_challenges_get(const umilib_auth_oauth_OAuthChallenges* challenges, size_t index, umilib_ffi_Buffer* out_scheme, umilib_ffi_Buffer* out_names, umilib_ffi_Buffer* out_values);

/**
 * Writes the challenge of the scheme at `scheme` and the `count` parameters of the names at
 * `names` and the values at `values`, as `WWW-Authenticate` carries it, into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_challenge_encode(const uint8_t* scheme, size_t length, const char* const* names, const char* const* values, size_t count, umilib_ffi_Buffer* out);

/**
 * Writes whether the `Authorization` value at `value` presents a token of the Bearer or
 * DPoP scheme into `out_found`, the scheme (0 Bearer, 1 DPoP) into `out_scheme` and the
 * token into `out_token` (RFC 6750 §2.1, RFC 9449 §7.1).
 */
const umilib_ffi_Status* umilib_auth_oauth_oauth_presented_token_from_authorization(const uint8_t* value, size_t length, bool* out_found, uint8_t* out_scheme, umilib_ffi_Buffer* out_token);

/**
 * Writes a DPoP proof (RFC 9449 §4.2) for a request of the method at `method` to the URI
 * at `uri` presenting the access token at `access_token` (null for none), signed with the
 * private `key` by the JWS algorithm `algorithm` at `now`, with the nonce at `nonce` (null
 * for none), into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_dpop_proof_create(const umilib_protocol_jwt_JWK* key, uint8_t algorithm, const uint8_t* method, size_t method_length, const uint8_t* uri, size_t uri_length, const uint8_t* access_token, size_t access_token_length, int64_t now, const uint8_t* nonce, size_t nonce_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Checks the DPoP proof at `proof` for a request of the method at `method` to the URI at
 * `uri` presenting the access token at `access_token` (null for none), signed by one of the
 * `count` JWS algorithms at `algorithms`, at `now`, with an `iat` at most `maximum_age`
 * seconds old and `leeway` seconds ahead (RFC 9449 §4.3, without the replay and nonce
 * checks); writes the base64url thumbprint of its key into `out_thumbprint` and its claims
 * (JSON) into `out_claims`.
 */
const umilib_ffi_Status* umilib_auth_oauth_dpop_proof_verify(const uint8_t* proof, size_t proof_length, const uint8_t* algorithms, size_t count, const uint8_t* method, size_t method_length, const uint8_t* uri, size_t uri_length, const uint8_t* access_token, size_t access_token_length, int64_t now, int64_t maximum_age, int64_t leeway, umilib_ffi_Buffer* out_thumbprint, umilib_ffi_Buffer* out_claims);

/**
 * Writes the base64url JWK SHA-256 thumbprint of `key` (RFC 7638, RFC 9449 §6.1) into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_dpop_proof_thumbprint(const umilib_protocol_jwt_JWK* key, umilib_ffi_Buffer* out);

/**
 * Writes the `ath` of the access token at `access_token` (RFC 9449 §4.2) into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_dpop_proof_access_token_hash(const uint8_t* access_token, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the URI at `uri` as an `htu` is compared (RFC 9449 §4.3) into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_dpop_proof_target(const uint8_t* uri, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes a verifier taking the `count` JWS algorithms at `algorithms`, with an `iat` at most
 * `maximum_age` seconds old and `leeway` seconds ahead, requiring a nonce if
 * `require_nonce`, keeping at most `maximum_proofs` identifiers, and taking the
 * `previous_nonces` nonces made before the current one, into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_dpop_verifier_new(const uint8_t* algorithms, size_t count, int64_t maximum_age, int64_t leeway, bool require_nonce, size_t maximum_proofs, size_t previous_nonces, umilib_auth_oauth_DPoPVerifier** out);

/**
 * Releases a verifier. Does nothing if `verifier` is null.
 */
void umilib_auth_oauth_dpop_verifier_free(umilib_auth_oauth_DPoPVerifier* verifier);

/**
 * Checks the proof at `proof` for the request of the method at `method` to the URI at `uri`
 * presenting the access token at `access_token` (null for none) at `now`, with every check
 * of RFC 9449 §4.3; writes the thumbprint of its key into `out` and its claims (JSON) into
 * `out_claims`. A refused proof fails with Response, the JSON of `invalid_dpop_proof` or
 * `use_dpop_nonce` into `out_error`.
 */
const umilib_ffi_Status* umilib_auth_oauth_dpop_verifier_check(umilib_auth_oauth_DPoPVerifier* verifier, const uint8_t* proof, size_t proof_length, const uint8_t* method, size_t method_length, const uint8_t* uri, size_t uri_length, const uint8_t* access_token, size_t access_token_length, int64_t now, umilib_ffi_Buffer* out, umilib_ffi_Buffer* out_claims, umilib_ffi_Buffer* out_error);

/**
 * Makes a new nonce (RFC 9449 §8) and writes it into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_dpop_verifier_rotate_nonce(umilib_auth_oauth_DPoPVerifier* verifier, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes whether the verifier made a nonce into `out_has` and the current one into `out`.
 */
const umilib_ffi_Status* umilib_auth_oauth_dpop_verifier_nonce(const umilib_auth_oauth_DPoPVerifier* verifier, bool* out_has, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
