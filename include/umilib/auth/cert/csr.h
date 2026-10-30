/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_CERT_CSR_H
#define UMILIB_AUTH_CERT_CSR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/auth/cert/key.h"
#include "umilib/auth/cert/x509.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The signed information of a certification request.
 */
typedef struct umilib_auth_cert_csr_CertificationRequestInfo umilib_auth_cert_csr_CertificationRequestInfo;

/**
 * A certification request (PKCS #10).
 */
typedef struct umilib_auth_cert_csr_CertificationRequest umilib_auth_cert_csr_CertificationRequest;

/**
 * Writes the information of a request into `out`: the subject `subject`, its key `public_key`
 * and, if `extensions` is not empty, an `extensionRequest` attribute of `extensions`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_info_new(const umilib_auth_cert_x509_Name* subject, const umilib_auth_cert_key_PublicKey* public_key, const umilib_auth_cert_x509_Extensions* extensions, umilib_auth_cert_csr_CertificationRequestInfo** out);

/**
 * Appends an attribute of the type `oid` (dotted text of `oid_length` bytes) with one value, the
 * DER element of `length` bytes at `value`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_info_push(umilib_auth_cert_csr_CertificationRequestInfo* info, const uint8_t* oid, size_t oid_length, const uint8_t* value, size_t length);

/**
 * Writes the DER of the information into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_info_to_der(const umilib_auth_cert_csr_CertificationRequestInfo* info, umilib_ffi_Buffer* out);

/**
 * Writes the request of the information signed by `key`, the private key of the subject, with
 * `algorithm` (drawing from `random` where the algorithm uses random bytes) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_info_sign(const umilib_auth_cert_csr_CertificationRequestInfo* info, const umilib_auth_cert_key_PrivateKey* key, const umilib_auth_cert_key_SignatureAlgorithm* algorithm, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_cert_csr_CertificationRequest** out);

/**
 * Releases the information of a request. Does nothing if `info` is null.
 */
void umilib_auth_cert_csr_certification_request_info_free(umilib_auth_cert_csr_CertificationRequestInfo* info);

/**
 * Writes the request of the DER of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_from_der(const uint8_t* data, size_t length, umilib_auth_cert_csr_CertificationRequest** out);

/**
 * Writes the request of the first PEM document (`CERTIFICATE REQUEST` or `NEW CERTIFICATE
 * REQUEST`) of `length` bytes at `text` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_from_pem(const uint8_t* text, size_t length, umilib_auth_cert_csr_CertificationRequest** out);

/**
 * Writes the DER of the request into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_to_der(const umilib_auth_cert_csr_CertificationRequest* request, umilib_ffi_Buffer* out);

/**
 * Writes the PEM text (`CERTIFICATE REQUEST`) of the request into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_to_pem(const umilib_auth_cert_csr_CertificationRequest* request, umilib_ffi_Buffer* out);

/**
 * Writes the subject's name into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_subject(const umilib_auth_cert_csr_CertificationRequest* request, umilib_auth_cert_x509_Name** out);

/**
 * Writes the subject's public key into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_public_key(const umilib_auth_cert_csr_CertificationRequest* request, umilib_auth_cert_key_PublicKey** out);

/**
 * Writes the requested extensions (empty without an `extensionRequest`) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_extensions(const umilib_auth_cert_csr_CertificationRequest* request, umilib_auth_cert_x509_Extensions** out);

/**
 * Writes the number of attributes into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_attribute_count(const umilib_auth_cert_csr_CertificationRequest* request, size_t* out);

/**
 * Writes the type (dotted text) and the number of values of the attribute at `index` into `out_oid` and `out_count`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_attribute(const umilib_auth_cert_csr_CertificationRequest* request, size_t index, umilib_ffi_Buffer* out_oid, size_t* out_count);

/**
 * Writes the DER of the value at `value_index` of the attribute at `index` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_attribute_value(const umilib_auth_cert_csr_CertificationRequest* request, size_t index, size_t value_index, umilib_ffi_Buffer* out);

/**
 * Writes the DER `AlgorithmIdentifier` of the signature algorithm into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_signature_algorithm(const umilib_auth_cert_csr_CertificationRequest* request, umilib_ffi_Buffer* out);

/**
 * Succeeds if the signature verifies under the subject's public key of the request.
 */
const umilib_ffi_Status* umilib_auth_cert_csr_certification_request_verify(const umilib_auth_cert_csr_CertificationRequest* request);

/**
 * Releases a request. Does nothing if `request` is null.
 */
void umilib_auth_cert_csr_certification_request_free(umilib_auth_cert_csr_CertificationRequest* request);

#ifdef __cplusplus
}
#endif

#endif
