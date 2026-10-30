/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_JWT_H
#define UMILIB_PROTOCOL_JWT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/auth/cert/key.h"
#include "umilib/codec/json.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A JOSE Header (RFC 7515 §4, RFC 7516 §4).
 */
typedef struct umilib_protocol_jwt_JOSEHeader umilib_protocol_jwt_JOSEHeader;

/**
 * A JSON Web Key (RFC 7517).
 */
typedef struct umilib_protocol_jwt_JWK umilib_protocol_jwt_JWK;

/**
 * A JWK Set (RFC 7517 §5).
 */
typedef struct umilib_protocol_jwt_JWKSet umilib_protocol_jwt_JWKSet;

/**
 * What verifying a JWS accepts (RFC 8725 §3.1).
 */
typedef struct umilib_protocol_jwt_JWSConfig umilib_protocol_jwt_JWSConfig;

/**
 * A JSON Web Signature (RFC 7515).
 */
typedef struct umilib_protocol_jwt_JWS umilib_protocol_jwt_JWS;

/**
 * What decrypting a JWE accepts (RFC 8725 §3.1).
 */
typedef struct umilib_protocol_jwt_JWEConfig umilib_protocol_jwt_JWEConfig;

/**
 * A JSON Web Encryption (RFC 7516).
 */
typedef struct umilib_protocol_jwt_JWE umilib_protocol_jwt_JWE;

/**
 * A JWT Claims Set (RFC 7519 §4).
 */
typedef struct umilib_protocol_jwt_JWTClaims umilib_protocol_jwt_JWTClaims;

/**
 * What a JWT must satisfy (RFC 7519 §7.2, RFC 8725 §3).
 */
typedef struct umilib_protocol_jwt_JWTValidation umilib_protocol_jwt_JWTValidation;

/**
 * A verified or decrypted JWT: its header and its claims.
 */
typedef struct umilib_protocol_jwt_JWT umilib_protocol_jwt_JWT;

/**
 * Writes an empty header into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jose_header_new(umilib_protocol_jwt_JOSEHeader** out);

/**
 * Writes the header of the JSON text at `data`, an object without duplicate parameters, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jose_header_decode(const uint8_t* data, size_t length, umilib_protocol_jwt_JOSEHeader** out);

/**
 * Writes the JSON text of the header into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jose_header_encode(const umilib_protocol_jwt_JOSEHeader* header, umilib_ffi_Buffer* out);

/**
 * Writes whether the parameter named by the UTF-8 text at `name` is present into `out_found` and,
 * if so, a copy of its value into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jose_header_get(const umilib_protocol_jwt_JOSEHeader* header, const uint8_t* name, size_t name_length, bool* out_found, umilib_codec_json_JSONValue** out);

/**
 * Sets the parameter named by the UTF-8 text at `name` to a copy of `value`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jose_header_set(umilib_protocol_jwt_JOSEHeader* header, const uint8_t* name, size_t name_length, const umilib_codec_json_JSONValue* value);

/**
 * Sets the parameter named by the UTF-8 text at `name` to the string at `value`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jose_header_set_string(umilib_protocol_jwt_JOSEHeader* header, const uint8_t* name, size_t name_length, const uint8_t* value, size_t value_length);

/**
 * Removes the parameter named by the UTF-8 text at `name`; writes whether it was present into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jose_header_remove(umilib_protocol_jwt_JOSEHeader* header, const uint8_t* name, size_t name_length, bool* out);

/**
 * Writes a copy of the header into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jose_header_clone(const umilib_protocol_jwt_JOSEHeader* header, umilib_protocol_jwt_JOSEHeader** out);

/**
 * Releases a header. Does nothing if `header` is null.
 */
void umilib_protocol_jwt_jose_header_free(umilib_protocol_jwt_JOSEHeader* header);

/**
 * Writes the JWK of the JSON text at `data` (RFC 7517 §4, checked) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_from_json(const uint8_t* data, size_t length, umilib_protocol_jwt_JWK** out);

/**
 * Writes the JSON text of the JWK into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_to_json(const umilib_protocol_jwt_JWK* jwk, umilib_ffi_Buffer* out);

/**
 * Writes the symmetric (`oct`) JWK of the `length` bytes at `k` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_symmetric(const uint8_t* k, size_t length, umilib_protocol_jwt_JWK** out);

/**
 * Writes the JWK without its private parameters into `out`; fails with KeyMismatch for a symmetric key.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_to_public(const umilib_protocol_jwt_JWK* jwk, umilib_protocol_jwt_JWK** out);

/**
 * Writes whether the JWK holds secret material (a symmetric key or private parameters) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_is_secret(const umilib_protocol_jwt_JWK* jwk, bool* out);

/**
 * Writes the key type (`kty`) of the JWK into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_key_type(const umilib_protocol_jwt_JWK* jwk, umilib_ffi_Buffer* out);

/**
 * Writes the `kid` of the JWK, if any, into `out_has` and `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_key_id(const umilib_protocol_jwt_JWK* jwk, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Sets the `kid` of the JWK to the UTF-8 text at `key_id`, or removes it for null.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_set_key_id(umilib_protocol_jwt_JWK* jwk, const uint8_t* key_id, size_t length);

/**
 * Writes the `alg` of the JWK, if any, into `out_has` and `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_algorithm(const umilib_protocol_jwt_JWK* jwk, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Sets the `alg` of the JWK to the UTF-8 text at `algorithm`, or removes it for null.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_set_algorithm(umilib_protocol_jwt_JWK* jwk, const uint8_t* algorithm, size_t length);

/**
 * Writes the `use` of the JWK, if any, into `out_has` and `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_key_use(const umilib_protocol_jwt_JWK* jwk, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Sets the `use` of the JWK to the UTF-8 text at `key_use`, or removes it for null.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_set_key_use(umilib_protocol_jwt_JWK* jwk, const uint8_t* key_use, size_t length);

/**
 * Checks the rules of RFC 7517 the JWK must follow (consistent `use` and `key_ops`, private
 * parameters of its public key, an `x5c` of its key).
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_check(const umilib_protocol_jwt_JWK* jwk);

/**
 * Writes the thumbprint (RFC 7638) of the JWK with the hash function `hash` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_thumbprint(const umilib_protocol_jwt_JWK* jwk, uint8_t hash, umilib_ffi_Buffer* out);

/**
 * Writes the thumbprint URI (RFC 9278) of the JWK with the hash function `hash` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_thumbprint_uri(const umilib_protocol_jwt_JWK* jwk, uint8_t hash, umilib_ffi_Buffer* out);

/**
 * Writes the public key of the JWK into `out`; fails with KeyMismatch for a symmetric key.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_public_key(const umilib_protocol_jwt_JWK* jwk, umilib_auth_cert_key_PublicKey** out);

/**
 * Writes the private key of the JWK into `out`; fails with KeyMismatch for a public or symmetric key.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_private_key(const umilib_protocol_jwt_JWK* jwk, umilib_auth_cert_key_PrivateKey** out);

/**
 * Writes the JWK of the public key `key` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_from_public_key(const umilib_auth_cert_key_PublicKey* key, umilib_protocol_jwt_JWK** out);

/**
 * Writes the JWK of the private key `key`, with its private parameters, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_from_private_key(const umilib_auth_cert_key_PrivateKey* key, umilib_protocol_jwt_JWK** out);

/**
 * Writes a copy of the JWK into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_clone(const umilib_protocol_jwt_JWK* jwk, umilib_protocol_jwt_JWK** out);

/**
 * Releases a JWK, zeroizing its secret parameters. Does nothing if `jwk` is null.
 */
void umilib_protocol_jwt_jwk_free(umilib_protocol_jwt_JWK* jwk);

/**
 * Writes the JWK Set of the JSON text at `data` (RFC 7517 §5; keys of unknown types are skipped) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_set_from_json(const uint8_t* data, size_t length, umilib_protocol_jwt_JWKSet** out);

/**
 * Writes the JSON text of the JWK Set into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_set_to_json(const umilib_protocol_jwt_JWKSet* set, umilib_ffi_Buffer* out);

/**
 * Writes the number of keys of the set into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_set_len(const umilib_protocol_jwt_JWKSet* set, size_t* out);

/**
 * Writes a copy of the key at `index` of the set into `out`; InvalidArgument past the end.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_set_key(const umilib_protocol_jwt_JWKSet* set, size_t index, umilib_protocol_jwt_JWK** out);

/**
 * Appends a copy of `jwk` to the set.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_set_push(umilib_protocol_jwt_JWKSet* set, const umilib_protocol_jwt_JWK* jwk);

/**
 * Writes an empty JWK Set into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwk_set_new(umilib_protocol_jwt_JWKSet** out);

/**
 * Releases a JWK Set. Does nothing if `set` is null.
 */
void umilib_protocol_jwt_jwk_set_free(umilib_protocol_jwt_JWKSet* set);

/**
 * Writes the configuration accepting the `count` algorithms of the indices at `algorithms` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_config_new(const uint8_t* algorithms, size_t count, umilib_protocol_jwt_JWSConfig** out);

/**
 * Adds the critical header parameter named by the UTF-8 text at `name` to those understood.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_config_understand(umilib_protocol_jwt_JWSConfig* config, const uint8_t* name, size_t length);

/**
 * Sets the most signatures a JWS may have.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_config_set_maximum_signatures(umilib_protocol_jwt_JWSConfig* config, size_t maximum);

/**
 * Releases a configuration. Does nothing if `config` is null.
 */
void umilib_protocol_jwt_jws_config_free(umilib_protocol_jwt_JWSConfig* config);

/**
 * Writes a JWS of the `length` bytes at `payload`, without signatures, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_new(const uint8_t* payload, size_t length, umilib_protocol_jwt_JWS** out);

/**
 * Writes the payload of the JWS into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_payload(const umilib_protocol_jwt_JWS* jws, umilib_ffi_Buffer* out);

/**
 * Writes the number of signatures of the JWS into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_signature_count(const umilib_protocol_jwt_JWS* jws, size_t* out);

/**
 * Writes the JOSE Header (the union of its headers) of the signature at `index` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_signature_header(const umilib_protocol_jwt_JWS* jws, size_t index, umilib_protocol_jwt_JOSEHeader** out);

/**
 * Adds the signature of the payload with the protected header `protected_header` and the unprotected header
 * `header` (null for none) under `key`, drawing from `random`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_sign(umilib_protocol_jwt_JWS* jws, const umilib_protocol_jwt_JOSEHeader* protected_header, const umilib_protocol_jwt_JOSEHeader* header, const umilib_protocol_jwt_JWK* key, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Verifies the JWS under `key` (RFC 7515 §5.2); writes the index of the signature that verifies into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_verify(const umilib_protocol_jwt_JWS* jws, const umilib_protocol_jwt_JWK* key, const umilib_protocol_jwt_JWSConfig* config, size_t* out);

/**
 * Accepts an Unsecured JWS (RFC 7518 §3.6): one signature with the `alg` of `none` and no signature.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_verify_unsecured(const umilib_protocol_jwt_JWS* jws);

/**
 * Writes the JWS of the compact serialization at `text` into `out`; with a payload at `payload`
 * (`has_payload`), that of a serialization with the payload detached.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_from_compact(const uint8_t* text, size_t length, const uint8_t* payload, size_t payload_length, bool has_payload, umilib_protocol_jwt_JWS** out);

/**
 * Writes the compact serialization of the JWS, with the payload or `detached`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_to_compact(const umilib_protocol_jwt_JWS* jws, bool detached, umilib_ffi_Buffer* out);

/**
 * Writes the JWS of the JSON serialization at `data` (general or flattened) into `out`; with a
 * payload at `payload` (`has_payload`), that of a serialization with the payload detached.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_from_json(const uint8_t* data, size_t length, const uint8_t* payload, size_t payload_length, bool has_payload, umilib_protocol_jwt_JWS** out);

/**
 * Writes the JSON serialization of the JWS, general or `flattened`, with the payload or `detached`,
 * into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_to_json(const umilib_protocol_jwt_JWS* jws, bool flattened, bool detached, umilib_ffi_Buffer* out);

/**
 * Writes a copy of the JWS into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jws_clone(const umilib_protocol_jwt_JWS* jws, umilib_protocol_jwt_JWS** out);

/**
 * Releases a JWS. Does nothing if `jws` is null.
 */
void umilib_protocol_jwt_jws_free(umilib_protocol_jwt_JWS* jws);

/**
 * Writes the configuration accepting the `algorithm_count` key management algorithms at `algorithms`
 * and the `encryption_count` content encryption algorithms at `encryptions` (as indices) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_config_new(const uint8_t* algorithms, size_t algorithm_count, const uint8_t* encryptions, size_t encryption_count, umilib_protocol_jwt_JWEConfig** out);

/**
 * Adds the critical header parameter named by the UTF-8 text at `name` to those understood.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_config_understand(umilib_protocol_jwt_JWEConfig* config, const uint8_t* name, size_t length);

/**
 * Sets the largest PBES2 iteration count accepted (RFC 8725 §3.2).
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_config_set_maximum_pbes2_count(umilib_protocol_jwt_JWEConfig* config, uint32_t count);

/**
 * Sets the most recipients a JWE may have.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_config_set_maximum_recipients(umilib_protocol_jwt_JWEConfig* config, size_t maximum);

/**
 * Sets whether compressed plaintexts (`zip`) are accepted, and the largest plaintext they decompress to.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_config_set_compression(umilib_protocol_jwt_JWEConfig* config, bool compression, size_t maximum_decompressed);

/**
 * Releases a configuration. Does nothing if `config` is null.
 */
void umilib_protocol_jwt_jwe_config_free(umilib_protocol_jwt_JWEConfig* config);

/**
 * Writes the JWE of the `length` bytes at `plaintext` (RFC 7516 §5.1) into `out`: for the `count`
 * recipients of the keys at `keys` and of the per-recipient headers at `headers` (null, or an array
 * whose entries may be null), with the headers `protected_header` and `unprotected` (null for none) and the
 * JWE AAD at `aad` (`has_aad`), drawing from `random`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_encrypt(const uint8_t* plaintext, size_t length, const umilib_protocol_jwt_JOSEHeader* protected_header, const umilib_protocol_jwt_JOSEHeader* unprotected, const umilib_protocol_jwt_JWK* const* keys, const umilib_protocol_jwt_JOSEHeader* const* headers, size_t count, const uint8_t* aad, size_t aad_length, bool has_aad, void* random, const uint8_t* random_type, size_t random_type_length, umilib_protocol_jwt_JWE** out);

/**
 * Decrypts the JWE with `key` (RFC 7516 §5.2), drawing from `random`: writes the plaintext into `out`
 * and the index of the recipient it was decrypted for into `out_recipient`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_decrypt(const umilib_protocol_jwt_JWE* jwe, const umilib_protocol_jwt_JWK* key, const umilib_protocol_jwt_JWEConfig* config, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out, size_t* out_recipient);

/**
 * Writes the number of recipients of the JWE into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_recipient_count(const umilib_protocol_jwt_JWE* jwe, size_t* out);

/**
 * Writes the JOSE Header (the union of the protected, shared and per-recipient headers) of the
 * recipient at `index` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_recipient_header(const umilib_protocol_jwt_JWE* jwe, size_t index, umilib_protocol_jwt_JOSEHeader** out);

/**
 * Writes the JWE of the compact serialization at `text` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_from_compact(const uint8_t* text, size_t length, umilib_protocol_jwt_JWE** out);

/**
 * Writes the compact serialization of the JWE into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_to_compact(const umilib_protocol_jwt_JWE* jwe, umilib_ffi_Buffer* out);

/**
 * Writes the JWE of the JSON serialization at `data` (general or flattened) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_from_json(const uint8_t* data, size_t length, umilib_protocol_jwt_JWE** out);

/**
 * Writes the JSON serialization of the JWE, general or `flattened`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_to_json(const umilib_protocol_jwt_JWE* jwe, bool flattened, umilib_ffi_Buffer* out);

/**
 * Writes a copy of the JWE into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwe_clone(const umilib_protocol_jwt_JWE* jwe, umilib_protocol_jwt_JWE** out);

/**
 * Releases a JWE. Does nothing if `jwe` is null.
 */
void umilib_protocol_jwt_jwe_free(umilib_protocol_jwt_JWE* jwe);

/**
 * Writes an empty claims set into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_claims_new(umilib_protocol_jwt_JWTClaims** out);

/**
 * Writes the claims of the JSON text at `data`, an object without duplicate names, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_claims_decode(const uint8_t* data, size_t length, umilib_protocol_jwt_JWTClaims** out);

/**
 * Writes the JSON text of the claims into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_claims_encode(const umilib_protocol_jwt_JWTClaims* claims, umilib_ffi_Buffer* out);

/**
 * Writes whether the claim named by the UTF-8 text at `name` is present into `out_found` and, if so,
 * a copy of its value into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_claims_get(const umilib_protocol_jwt_JWTClaims* claims, const uint8_t* name, size_t name_length, bool* out_found, umilib_codec_json_JSONValue** out);

/**
 * Sets the claim named by the UTF-8 text at `name` to a copy of `value`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_claims_set(umilib_protocol_jwt_JWTClaims* claims, const uint8_t* name, size_t name_length, const umilib_codec_json_JSONValue* value);

/**
 * Sets the claim named by the UTF-8 text at `name` to the string at `value`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_claims_set_string(umilib_protocol_jwt_JWTClaims* claims, const uint8_t* name, size_t name_length, const uint8_t* value, size_t value_length);

/**
 * Sets the claim named by the UTF-8 text at `name` to the NumericDate `seconds` (RFC 7519 §2).
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_claims_set_numeric_date(umilib_protocol_jwt_JWTClaims* claims, const uint8_t* name, size_t name_length, int64_t seconds);

/**
 * Removes the claim named by the UTF-8 text at `name`; writes whether it was present into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_claims_remove(umilib_protocol_jwt_JWTClaims* claims, const uint8_t* name, size_t name_length, bool* out);

/**
 * Writes a copy of the claims into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_claims_clone(const umilib_protocol_jwt_JWTClaims* claims, umilib_protocol_jwt_JWTClaims** out);

/**
 * Releases a claims set. Does nothing if `claims` is null.
 */
void umilib_protocol_jwt_jwt_claims_free(umilib_protocol_jwt_JWTClaims* claims);

/**
 * Writes the validation at `now` (seconds since 1970-01-01T00:00:00Z), without leeway, expectations
 * or required claims, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_validation_new(int64_t now, umilib_protocol_jwt_JWTValidation** out);

/**
 * Sets the tolerance for `exp` and `nbf`, in seconds.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_validation_set_leeway(umilib_protocol_jwt_JWTValidation* validation, uint64_t leeway);

/**
 * Sets the issuer expected to the UTF-8 text at `issuer`, or none for null.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_validation_set_issuer(umilib_protocol_jwt_JWTValidation* validation, const uint8_t* issuer, size_t length);

/**
 * Sets the audience expected (the identifier of the recipient) to the UTF-8 text at `audience`, or
 * none for null.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_validation_set_audience(umilib_protocol_jwt_JWTValidation* validation, const uint8_t* audience, size_t length);

/**
 * Sets the subject expected to the UTF-8 text at `subject`, or none for null.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_validation_set_subject(umilib_protocol_jwt_JWTValidation* validation, const uint8_t* subject, size_t length);

/**
 * Sets the `typ` expected (RFC 8725 §3.11) to the UTF-8 text at `token_type`, or none for null.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_validation_set_token_type(umilib_protocol_jwt_JWTValidation* validation, const uint8_t* token_type, size_t length);

/**
 * Adds the claim named by the UTF-8 text at `name` to those required.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_validation_require(umilib_protocol_jwt_JWTValidation* validation, const uint8_t* name, size_t length);

/**
 * Checks `claims` held by `header` against the validation.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_validation_validate(const umilib_protocol_jwt_JWTValidation* validation, const umilib_protocol_jwt_JOSEHeader* header, const umilib_protocol_jwt_JWTClaims* claims);

/**
 * Releases a validation. Does nothing if `validation` is null.
 */
void umilib_protocol_jwt_jwt_validation_free(umilib_protocol_jwt_JWTValidation* validation);

/**
 * Writes the compact JWS of `claims` with the protected header `header` under `key` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_sign(const umilib_protocol_jwt_JWTClaims* claims, const umilib_protocol_jwt_JOSEHeader* header, const umilib_protocol_jwt_JWK* key, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes the JWT of the compact JWS at `text`, verified under `key` and validated, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_verify(const uint8_t* text, size_t length, const umilib_protocol_jwt_JWK* key, const umilib_protocol_jwt_JWSConfig* config, const umilib_protocol_jwt_JWTValidation* validation, umilib_protocol_jwt_JWT** out);

/**
 * Writes the JWT of the Unsecured JWS at `text` (RFC 7519 §6), validated, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_verify_unsecured(const uint8_t* text, size_t length, const umilib_protocol_jwt_JWTValidation* validation, umilib_protocol_jwt_JWT** out);

/**
 * Writes the compact JWE of `claims` with the protected header `header` for `key` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_encrypt(const umilib_protocol_jwt_JWTClaims* claims, const umilib_protocol_jwt_JOSEHeader* header, const umilib_protocol_jwt_JWK* key, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes the JWT of the compact JWE at `text`, decrypted with `key` and validated, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_decrypt(const uint8_t* text, size_t length, const umilib_protocol_jwt_JWK* key, const umilib_protocol_jwt_JWEConfig* config, const umilib_protocol_jwt_JWTValidation* validation, void* random, const uint8_t* random_type, size_t random_type_length, umilib_protocol_jwt_JWT** out);

/**
 * Writes the Nested JWT (RFC 7519 §5.2) of `claims`: signed under `signing_key` with
 * `signing_header`, encrypted for `encryption_key` with `encryption_header` and the `cty` of "JWT".
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_sign_and_encrypt(const umilib_protocol_jwt_JWTClaims* claims, const umilib_protocol_jwt_JOSEHeader* signing_header, const umilib_protocol_jwt_JWK* signing_key, const umilib_protocol_jwt_JOSEHeader* encryption_header, const umilib_protocol_jwt_JWK* encryption_key, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes the JWT of the Nested JWT at `text`: decrypted with `decryption_key`, verified under
 * `verification_key` and validated, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_decrypt_and_verify(const uint8_t* text, size_t length, const umilib_protocol_jwt_JWK* decryption_key, const umilib_protocol_jwt_JWEConfig* decryption, const umilib_protocol_jwt_JWK* verification_key, const umilib_protocol_jwt_JWSConfig* verification, const umilib_protocol_jwt_JWTValidation* validation, void* random, const uint8_t* random_type, size_t random_type_length, umilib_protocol_jwt_JWT** out);

/**
 * Writes a copy of the header that holds the claims of the JWT into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_header(const umilib_protocol_jwt_JWT* jwt, umilib_protocol_jwt_JOSEHeader** out);

/**
 * Writes a copy of the claims of the JWT into `out`.
 */
const umilib_ffi_Status* umilib_protocol_jwt_jwt_claims(const umilib_protocol_jwt_JWT* jwt, umilib_protocol_jwt_JWTClaims** out);

/**
 * Releases a JWT. Does nothing if `jwt` is null.
 */
void umilib_protocol_jwt_jwt_free(umilib_protocol_jwt_JWT* jwt);

#ifdef __cplusplus
}
#endif

#endif
