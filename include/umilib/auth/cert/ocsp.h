/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_CERT_OCSP_H
#define UMILIB_AUTH_CERT_OCSP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/auth/cert/key.h"
#include "umilib/auth/cert/path.h"
#include "umilib/auth/cert/x509.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The identifier of a certificate.
 */
typedef struct umilib_auth_cert_ocsp_CertID umilib_auth_cert_ocsp_CertID;

/**
 * The inputs of the checks of a response.
 */
typedef struct umilib_auth_cert_ocsp_OCSPConfig umilib_auth_cert_ocsp_OCSPConfig;

/**
 * The fields of a request.
 */
typedef struct umilib_auth_cert_ocsp_TBSRequest umilib_auth_cert_ocsp_TBSRequest;

/**
 * An OCSP request.
 */
typedef struct umilib_auth_cert_ocsp_OCSPRequest umilib_auth_cert_ocsp_OCSPRequest;

/**
 * The status of one certificate in a response.
 */
typedef struct umilib_auth_cert_ocsp_SingleResponse umilib_auth_cert_ocsp_SingleResponse;

/**
 * The signed fields of a basic response.
 */
typedef struct umilib_auth_cert_ocsp_ResponseData umilib_auth_cert_ocsp_ResponseData;

/**
 * A basic response.
 */
typedef struct umilib_auth_cert_ocsp_BasicOCSPResponse umilib_auth_cert_ocsp_BasicOCSPResponse;

/**
 * An OCSP response.
 */
typedef struct umilib_auth_cert_ocsp_OCSPResponse umilib_auth_cert_ocsp_OCSPResponse;

/**
 * Writes the identifier of `certificate`, issued by the holder of `issuer_key`, with the hash
 * function `hash` (an index of the hash functions of key) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_cert_id_new(const umilib_auth_cert_x509_Certificate* certificate, const umilib_auth_cert_key_PublicKey* issuer_key, uint8_t hash, umilib_auth_cert_ocsp_CertID** out);

/**
 * Writes the identifier of the DER of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_cert_id_from_der(const uint8_t* data, size_t length, umilib_auth_cert_ocsp_CertID** out);

/**
 * Writes the DER of the identifier into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_cert_id_to_der(const umilib_auth_cert_ocsp_CertID* cert_id, umilib_ffi_Buffer* out);

/**
 * Writes the contents octets of the INTEGER of the serial number into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_cert_id_serial_number(const umilib_auth_cert_ocsp_CertID* cert_id, umilib_ffi_Buffer* out);

/**
 * Writes whether both identifiers name the same certificate into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_cert_id_matches(const umilib_auth_cert_ocsp_CertID* cert_id, const umilib_auth_cert_ocsp_CertID* other, bool* out);

/**
 * Writes whether the identifier names `certificate`, issued by the holder of `issuer_key`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_cert_id_identifies(const umilib_auth_cert_ocsp_CertID* cert_id, const umilib_auth_cert_x509_Certificate* certificate, const umilib_auth_cert_key_PublicKey* issuer_key, bool* out);

/**
 * Releases an identifier. Does nothing if `cert_id` is null.
 */
void umilib_auth_cert_ocsp_cert_id_free(umilib_auth_cert_ocsp_CertID* cert_id);

/**
 * Writes the defaults of the checks of a response at `time` into `out`: no nonce, the default
 * key limits, SHA-1 refused, a status without `nextUpdate` current for a day, 9 signatures.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_config_new(int64_t time, umilib_auth_cert_ocsp_OCSPConfig** out);

/**
 * Sets the nonce of the request, which the response must repeat (`length` 0 removes it).
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_config_set_nonce(umilib_auth_cert_ocsp_OCSPConfig* config, const uint8_t* nonce, size_t length);

/**
 * Sets the largest RSA modulus and exponent (in bits) of delegated responders' keys.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_config_set_key_limits(umilib_auth_cert_ocsp_OCSPConfig* config, uint32_t maximum_rsa_bits, uint32_t maximum_rsa_exponent_bits);

/**
 * Sets whether signatures that hash with SHA-1 are accepted.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_config_set_accept_sha1(umilib_auth_cert_ocsp_OCSPConfig* config, bool accept);

/**
 * Sets how long (in seconds) a status without `nextUpdate` is current, and the most signatures
 * the search of a response's signer verifies.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_config_set_limits(umilib_auth_cert_ocsp_OCSPConfig* config, uint64_t lifetime_without_next_update, size_t maximum_signatures);

/**
 * Releases a configuration. Does nothing if `config` is null.
 */
void umilib_auth_cert_ocsp_ocsp_config_free(umilib_auth_cert_ocsp_OCSPConfig* config);

/**
 * Writes a nonce of 32 random octets (RFC 8954) drawn from `random` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_nonce_random(void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes the fields of a request without certificates, requestor or extensions into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_tbs_request_new(umilib_auth_cert_ocsp_TBSRequest** out);

/**
 * Appends a request for the certificate `cert_id` names.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_tbs_request_push(umilib_auth_cert_ocsp_TBSRequest* tbs, const umilib_auth_cert_ocsp_CertID* cert_id);

/**
 * Sets the requestor's name, the general name of `kind` and `length` bytes at `data` (see x509).
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_tbs_request_set_requestor_name(umilib_auth_cert_ocsp_TBSRequest* tbs, uint8_t kind, const uint8_t* data, size_t length);

/**
 * Sets the nonce of `length` bytes at `nonce` (1 to 32, RFC 8954).
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_tbs_request_set_nonce(umilib_auth_cert_ocsp_TBSRequest* tbs, const uint8_t* nonce, size_t length);

/**
 * Releases the fields of a request. Does nothing if `tbs` is null.
 */
void umilib_auth_cert_ocsp_tbs_request_free(umilib_auth_cert_ocsp_TBSRequest* tbs);

/**
 * Writes the unsigned request of `tbs` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_request_new(const umilib_auth_cert_ocsp_TBSRequest* tbs, umilib_auth_cert_ocsp_OCSPRequest** out);

/**
 * Writes the request of `tbs` signed by `key` with `algorithm`, with the certificates
 * `certificates` (null for none), drawing from `random`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_request_sign(const umilib_auth_cert_ocsp_TBSRequest* tbs, const umilib_auth_cert_key_PrivateKey* key, const umilib_auth_cert_key_SignatureAlgorithm* algorithm, const umilib_auth_cert_x509_Certificates* certificates, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_cert_ocsp_OCSPRequest** out);

/**
 * Writes the request of the DER of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_request_from_der(const uint8_t* data, size_t length, umilib_auth_cert_ocsp_OCSPRequest** out);

/**
 * Writes the DER of the request into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_request_to_der(const umilib_auth_cert_ocsp_OCSPRequest* request, umilib_ffi_Buffer* out);

/**
 * Writes the number of certificates the request asks about into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_request_count(const umilib_auth_cert_ocsp_OCSPRequest* request, size_t* out);

/**
 * Writes the identifier of the certificate at `index` the request asks about into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_request_cert_id(const umilib_auth_cert_ocsp_OCSPRequest* request, size_t index, umilib_auth_cert_ocsp_CertID** out);

/**
 * Writes whether the request has a requestor's name into `out_has` and, if it has, its general
 * name (see x509) into `out_kind` and `out` (0 and empty otherwise).
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_request_requestor_name(const umilib_auth_cert_ocsp_OCSPRequest* request, bool* out_has, uint8_t* out_kind, umilib_ffi_Buffer* out);

/**
 * Writes whether the request has a nonce into `out_has` and, if it has, the nonce into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_request_nonce(const umilib_auth_cert_ocsp_OCSPRequest* request, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Writes whether the request is signed into `out_signed` and, if it is, whether it has a list
 * of certificates into `out_has` and a copy of the list into `out` (empty otherwise).
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_request_certificates(const umilib_auth_cert_ocsp_OCSPRequest* request, bool* out_signed, bool* out_has, umilib_auth_cert_x509_Certificates** out);

/**
 * Succeeds if the request is signed and its signature verifies under `key`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_request_verify(const umilib_auth_cert_ocsp_OCSPRequest* request, const umilib_auth_cert_key_PublicKey* key);

/**
 * Releases a request. Does nothing if `request` is null.
 */
void umilib_auth_cert_ocsp_ocsp_request_free(umilib_auth_cert_ocsp_OCSPRequest* request);

/**
 * Writes the status of the certificate `cert_id` names into `out`: the status `kind` (with the
 * revocation time `revocation_time` and the reason `reason` when revoked), current from
 * `this_update` to `next_update` (if `has_next_update`), with the extensions `extensions`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_single_response_new(const umilib_auth_cert_ocsp_CertID* cert_id, uint8_t kind, int64_t revocation_time, uint8_t reason, int64_t this_update, bool has_next_update, int64_t next_update, const umilib_auth_cert_x509_Extensions* extensions, umilib_auth_cert_ocsp_SingleResponse** out);

/**
 * Writes the identifier of the certificate into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_single_response_cert_id(const umilib_auth_cert_ocsp_SingleResponse* single, umilib_auth_cert_ocsp_CertID** out);

/**
 * Writes the status kind into `out_kind` and, when revoked, the revocation time and the reason
 * (255 for none) into `out_time` and `out_reason` (0 and 255 otherwise).
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_single_response_status(const umilib_auth_cert_ocsp_SingleResponse* single, uint8_t* out_kind, int64_t* out_time, uint8_t* out_reason);

/**
 * Writes `thisUpdate` into `out_this_update`, whether there is a `nextUpdate` into
 * `out_has_next_update` and the `nextUpdate` (0 without one) into `out_next_update`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_single_response_updates(const umilib_auth_cert_ocsp_SingleResponse* single, int64_t* out_this_update, bool* out_has_next_update, int64_t* out_next_update);

/**
 * Writes a copy of the extensions into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_single_response_extensions(const umilib_auth_cert_ocsp_SingleResponse* single, umilib_auth_cert_x509_Extensions** out);

/**
 * Releases a status. Does nothing if `single` is null.
 */
void umilib_auth_cert_ocsp_single_response_free(umilib_auth_cert_ocsp_SingleResponse* single);

/**
 * Writes the fields of a response produced at `produced_at` by the responder of the name `name`
 * into `out`, without statuses or extensions.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_response_data_new_by_name(const umilib_auth_cert_x509_Name* name, int64_t produced_at, umilib_auth_cert_ocsp_ResponseData** out);

/**
 * Writes the fields of a response produced at `produced_at` by the responder of the key `key`
 * (named by the SHA-1 hash of its key) into `out`, without statuses or extensions.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_response_data_new_by_key(const umilib_auth_cert_key_PublicKey* key, int64_t produced_at, umilib_auth_cert_ocsp_ResponseData** out);

/**
 * Appends a copy of the status `single`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_response_data_push(umilib_auth_cert_ocsp_ResponseData* data, const umilib_auth_cert_ocsp_SingleResponse* single);

/**
 * Sets the nonce of `length` bytes at `nonce` (that of the request answered).
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_response_data_set_nonce(umilib_auth_cert_ocsp_ResponseData* data, const uint8_t* nonce, size_t length);

/**
 * Writes the basic response of the fields signed by `key` with `algorithm`, with the
 * certificates `certificates` (null for none), drawing from `random`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_response_data_sign(const umilib_auth_cert_ocsp_ResponseData* data, const umilib_auth_cert_key_PrivateKey* key, const umilib_auth_cert_key_SignatureAlgorithm* algorithm, const umilib_auth_cert_x509_Certificates* certificates, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_cert_ocsp_BasicOCSPResponse** out);

/**
 * Releases the fields of a response. Does nothing if `data` is null.
 */
void umilib_auth_cert_ocsp_response_data_free(umilib_auth_cert_ocsp_ResponseData* data);

/**
 * Writes the basic response of the DER of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_from_der(const uint8_t* data, size_t length, umilib_auth_cert_ocsp_BasicOCSPResponse** out);

/**
 * Writes the DER of the basic response into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_to_der(const umilib_auth_cert_ocsp_BasicOCSPResponse* response, umilib_ffi_Buffer* out);

/**
 * Writes whether the responder is named by key into `out_by_key` and the DER of its name, or
 * the SHA-1 hash of its key, into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_responder_id(const umilib_auth_cert_ocsp_BasicOCSPResponse* response, bool* out_by_key, umilib_ffi_Buffer* out);

/**
 * Writes the time the response was produced at into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_produced_at(const umilib_auth_cert_ocsp_BasicOCSPResponse* response, int64_t* out);

/**
 * Writes the number of statuses into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_count(const umilib_auth_cert_ocsp_BasicOCSPResponse* response, size_t* out);

/**
 * Writes a copy of the status at `index` into `out`, unchecked.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_get(const umilib_auth_cert_ocsp_BasicOCSPResponse* response, size_t index, umilib_auth_cert_ocsp_SingleResponse** out);

/**
 * Writes a copy of the response extensions into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_extensions(const umilib_auth_cert_ocsp_BasicOCSPResponse* response, umilib_auth_cert_x509_Extensions** out);

/**
 * Writes whether the response has a nonce into `out_has` and, if it has, the nonce into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_nonce(const umilib_auth_cert_ocsp_BasicOCSPResponse* response, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Writes a copy of the certificates of the response (empty without the field) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_certificates(const umilib_auth_cert_ocsp_BasicOCSPResponse* response, umilib_auth_cert_x509_Certificates** out);

/**
 * Writes the DER `AlgorithmIdentifier` of the signature algorithm into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_signature_algorithm(const umilib_auth_cert_ocsp_BasicOCSPResponse* response, umilib_ffi_Buffer* out);

/**
 * Writes the key that signed the response into `out`, if it may answer for the certificates of
 * the CA of the name `issuer_name` and the key `issuer_key` under `config` (RFC 6960 4.2.2.2).
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_signer(const umilib_auth_cert_ocsp_BasicOCSPResponse* response, const umilib_auth_cert_x509_Name* issuer_name, const umilib_auth_cert_key_PublicKey* issuer_key, const umilib_auth_cert_ocsp_OCSPConfig* config, umilib_auth_cert_key_PublicKey** out);

/**
 * Writes a copy of the status of the certificate `cert_id` names into `out`, after checking the
 * response as RFC 6960 section 3.2 requires, for the CA of the name `issuer_name` and the key
 * `issuer_key`, under `config`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_verify(const umilib_auth_cert_ocsp_BasicOCSPResponse* response, const umilib_auth_cert_ocsp_CertID* cert_id, const umilib_auth_cert_x509_Name* issuer_name, const umilib_auth_cert_key_PublicKey* issuer_key, const umilib_auth_cert_ocsp_OCSPConfig* config, umilib_auth_cert_ocsp_SingleResponse** out);

/**
 * Releases a basic response. Does nothing if `response` is null.
 */
void umilib_auth_cert_ocsp_basic_ocsp_response_free(umilib_auth_cert_ocsp_BasicOCSPResponse* response);

/**
 * Writes the response of the status `status` (an `OCSPResponseStatus` code) into `out`, with a
 * copy of the basic response `basic` if successful (null otherwise).
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_response_new(uint8_t status, const umilib_auth_cert_ocsp_BasicOCSPResponse* basic, umilib_auth_cert_ocsp_OCSPResponse** out);

/**
 * Writes the response of the DER of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_response_from_der(const uint8_t* data, size_t length, umilib_auth_cert_ocsp_OCSPResponse** out);

/**
 * Writes the DER of the response into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_response_to_der(const umilib_auth_cert_ocsp_OCSPResponse* response, umilib_ffi_Buffer* out);

/**
 * Writes the code of the response status into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_response_status(const umilib_auth_cert_ocsp_OCSPResponse* response, uint8_t* out);

/**
 * Writes a copy of the basic response of a successful response into `out`; fails with `Status` otherwise.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_response_basic(const umilib_auth_cert_ocsp_OCSPResponse* response, umilib_auth_cert_ocsp_BasicOCSPResponse** out);

/**
 * Releases a response. Does nothing if `response` is null.
 */
void umilib_auth_cert_ocsp_ocsp_response_free(umilib_auth_cert_ocsp_OCSPResponse* response);

/**
 * Appends a copy of the basic response to the revocation sources `sources` of path validation.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_basic_ocsp_response_add_to(const umilib_auth_cert_ocsp_BasicOCSPResponse* response, umilib_auth_cert_path_RevocationSources* sources);

/**
 * Appends a copy of the response to the revocation sources `sources` of path validation.
 */
const umilib_ffi_Status* umilib_auth_cert_ocsp_ocsp_response_add_to(const umilib_auth_cert_ocsp_OCSPResponse* response, umilib_auth_cert_path_RevocationSources* sources);

#ifdef __cplusplus
}
#endif

#endif
