/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_CERT_X509_H
#define UMILIB_AUTH_CERT_X509_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/auth/cert/key.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A distinguished name.
 */
typedef struct umilib_auth_cert_x509_Name umilib_auth_cert_x509_Name;

/**
 * A list of general names.
 */
typedef struct umilib_auth_cert_x509_GeneralNames umilib_auth_cert_x509_GeneralNames;

/**
 * A list of extensions, each of a different type.
 */
typedef struct umilib_auth_cert_x509_Extensions umilib_auth_cert_x509_Extensions;

/**
 * A certificate.
 */
typedef struct umilib_auth_cert_x509_Certificate umilib_auth_cert_x509_Certificate;

/**
 * A list of certificates.
 */
typedef struct umilib_auth_cert_x509_Certificates umilib_auth_cert_x509_Certificates;

/**
 * The signed fields of a certificate.
 */
typedef struct umilib_auth_cert_x509_TBSCertificate umilib_auth_cert_x509_TBSCertificate;

/**
 * A CRL.
 */
typedef struct umilib_auth_cert_x509_CertificateList umilib_auth_cert_x509_CertificateList;

/**
 * A list of CRLs.
 */
typedef struct umilib_auth_cert_x509_CertificateLists umilib_auth_cert_x509_CertificateLists;

/**
 * The signed fields of a CRL.
 */
typedef struct umilib_auth_cert_x509_TBSCertList umilib_auth_cert_x509_TBSCertList;

/**
 * Writes the empty name into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_name_empty(umilib_auth_cert_x509_Name** out);

/**
 * Writes the name of the DER `Name` of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_name_from_der(const uint8_t* data, size_t length, umilib_auth_cert_x509_Name** out);

/**
 * Writes the name `name` followed by a relative distinguished name of one attribute, of the
 * type `attribute` (an index of `NameAttribute::ALL`) and the `length` bytes of text at `text`,
 * into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_name_append(const umilib_auth_cert_x509_Name* name, uint8_t attribute, const uint8_t* text, size_t length, umilib_auth_cert_x509_Name** out);

/**
 * Writes the DER of the name into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_name_to_der(const umilib_auth_cert_x509_Name* name, umilib_ffi_Buffer* out);

/**
 * Writes the string representation of RFC 4514 of the name into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_name_to_rfc4514(const umilib_auth_cert_x509_Name* name, umilib_ffi_Buffer* out);

/**
 * Releases a name. Does nothing if `name` is null.
 */
void umilib_auth_cert_x509_name_free(umilib_auth_cert_x509_Name* name);

/**
 * Writes an empty list of general names into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_general_names_new(umilib_auth_cert_x509_GeneralNames** out);

/**
 * Appends the general name of `kind` and the `length` bytes at `data` to the list.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_general_names_push(umilib_auth_cert_x509_GeneralNames* names, uint8_t kind, const uint8_t* data, size_t length);

/**
 * Writes the number of names of the list into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_general_names_count(const umilib_auth_cert_x509_GeneralNames* names, size_t* out);

/**
 * Writes the kind and the bytes of the name at `index` of the list into `out_kind` and `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_general_names_get(const umilib_auth_cert_x509_GeneralNames* names, size_t index, uint8_t* out_kind, umilib_ffi_Buffer* out);

/**
 * Writes the DER of the list as the value of a `SubjectAltName`, `IssuerAltName` or
 * `CertificateIssuer` extension (at least one name; addresses of 4 or 16 octets) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_general_names_to_der(const umilib_auth_cert_x509_GeneralNames* names, umilib_ffi_Buffer* out);

/**
 * Writes the list of the value of a `SubjectAltName`, `IssuerAltName` or `CertificateIssuer`
 * extension, the `length` bytes at `data`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_general_names_from_der(const uint8_t* data, size_t length, umilib_auth_cert_x509_GeneralNames** out);

/**
 * Releases a list of general names. Does nothing if `names` is null.
 */
void umilib_auth_cert_x509_general_names_free(umilib_auth_cert_x509_GeneralNames* names);

/**
 * Writes an empty list of extensions into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_extensions_new(umilib_auth_cert_x509_Extensions** out);

/**
 * Appends the extension of type `oid` (dotted text of `oid_length` bytes), criticality
 * `critical` and the DER value of `length` bytes at `value`; fails with DuplicateExtension if
 * one of its type is already there.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_extensions_push(umilib_auth_cert_x509_Extensions* extensions, const uint8_t* oid, size_t oid_length, bool critical, const uint8_t* value, size_t length);

/**
 * Writes the number of extensions of the list into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_extensions_count(const umilib_auth_cert_x509_Extensions* extensions, size_t* out);

/**
 * Writes the type (dotted text), the criticality and the DER value of the extension at `index`
 * into `out_oid`, `out_critical` and `out_value`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_extensions_get(const umilib_auth_cert_x509_Extensions* extensions, size_t index, umilib_ffi_Buffer* out_oid, bool* out_critical, umilib_ffi_Buffer* out_value);

/**
 * Writes whether the list has an extension of type `oid` into `out_found` and, if it has, its
 * index into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_extensions_find(const umilib_auth_cert_x509_Extensions* extensions, const uint8_t* oid, size_t oid_length, bool* out_found, size_t* out);

/**
 * Releases a list of extensions. Does nothing if `extensions` is null.
 */
void umilib_auth_cert_x509_extensions_free(umilib_auth_cert_x509_Extensions* extensions);

/**
 * Writes the DER value of a `BasicConstraints` extension into `out`; `path_length` is used if `has_path_length`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_basic_constraints_encode(bool ca, bool has_path_length, uint32_t path_length, umilib_ffi_Buffer* out);

/**
 * Writes the fields of the `BasicConstraints` value of `length` bytes at `data` into `out_ca`,
 * `out_has_path_length` and `out_path_length`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_basic_constraints_decode(const uint8_t* data, size_t length, bool* out_ca, bool* out_has_path_length, uint32_t* out_path_length);

/**
 * Writes the DER value of a `KeyUsage` extension of the named bits `bits` (bit `n` is `1 << n`) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_key_usage_encode(uint16_t bits, umilib_ffi_Buffer* out);

/**
 * Writes the named bits of the `KeyUsage` value of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_key_usage_decode(const uint8_t* data, size_t length, uint16_t* out);

/**
 * Writes the DER value of an `ExtendedKeyUsage` extension of the purposes in `purposes`
 * (dotted identifiers separated by commas) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_extended_key_usage_encode(const uint8_t* purposes, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the purposes of the `ExtendedKeyUsage` value of `length` bytes at `data`, dotted
 * identifiers separated by commas, into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_extended_key_usage_decode(const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the key identifier of `key` by the first method of RFC 5280 §4.2.1.2 (the SHA-1 of the
 * `subjectPublicKey`) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_subject_key_identifier_from_public_key(const umilib_auth_cert_key_PublicKey* key, umilib_ffi_Buffer* out);

/**
 * Writes the DER value of a `SubjectKeyIdentifier` extension of the identifier of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_subject_key_identifier_encode(const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the identifier of the `SubjectKeyIdentifier` value of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_subject_key_identifier_decode(const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the DER value of an `AuthorityKeyIdentifier` extension into `out`: the key identifier
 * of `identifier_length` bytes at `identifier` if `has_identifier`, and the issuer `issuer`
 * (null for none) with the serial number of `serial_length` bytes at `serial_number`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_authority_key_identifier_encode(bool has_identifier, const uint8_t* identifier, size_t identifier_length, const umilib_auth_cert_x509_GeneralNames* issuer, const uint8_t* serial_number, size_t serial_length, umilib_ffi_Buffer* out);

/**
 * Reads the `AuthorityKeyIdentifier` value of `length` bytes at `data`: writes whether it has a
 * key identifier into `out_has_identifier` and the identifier (empty if not) into
 * `out_identifier`; whether it has the issuer and serial number into `out_has_issuer`, the
 * issuer (null if not) into `out_issuer` and the contents octets of the serial number (empty if
 * not) into `out_serial_number`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_authority_key_identifier_decode(const uint8_t* data, size_t length, bool* out_has_identifier, umilib_ffi_Buffer* out_identifier, bool* out_has_issuer, umilib_auth_cert_x509_GeneralNames** out_issuer, umilib_ffi_Buffer* out_serial_number);

/**
 * Writes the DER value of a `CRLNumber` extension of the non-negative INTEGER whose contents
 * octets are the `length` bytes at `number` (up to 20 octets, RFC 5280 §5.2.3) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_crl_number_encode(const uint8_t* number, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the contents octets of the INTEGER of the `CRLNumber` value of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_crl_number_decode(const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the DER value of a `CRLReason` extension of the code `code` (RFC 5280 §5.3.1) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_crl_reason_encode(uint8_t code, umilib_ffi_Buffer* out);

/**
 * Writes the code of the `CRLReason` value of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_crl_reason_decode(const uint8_t* data, size_t length, uint8_t* out);

/**
 * Writes a positive serial number of 159 random bits from `random` (its contents octets) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_serial_number_random(void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes the signed fields of a certificate into `out`: the version `version` (0 for v1, 2 for
 * v3), the serial number of `serial_length` bytes at `serial_number`, the signature algorithm
 * `signature`, the names `issuer` and `subject`, the validity from `not_before` through
 * `not_after`, the subject's key `public_key` and the extensions `extensions`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_tbs_certificate_new(uint8_t version, const uint8_t* serial_number, size_t serial_length, const umilib_auth_cert_key_SignatureAlgorithm* signature, const umilib_auth_cert_x509_Name* issuer, int64_t not_before, int64_t not_after, const umilib_auth_cert_x509_Name* subject, const umilib_auth_cert_key_PublicKey* public_key, const umilib_auth_cert_x509_Extensions* extensions, umilib_auth_cert_x509_TBSCertificate** out);

/**
 * Succeeds if the fields meet the requirements RFC 5280 places on what CAs issue.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_tbs_certificate_check(const umilib_auth_cert_x509_TBSCertificate* tbs);

/**
 * Writes the DER of the fields into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_tbs_certificate_to_der(const umilib_auth_cert_x509_TBSCertificate* tbs, umilib_ffi_Buffer* out);

/**
 * Writes the certificate of the fields signed by `key` (drawing from `random` where the
 * algorithm uses random bytes) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_tbs_certificate_sign(const umilib_auth_cert_x509_TBSCertificate* tbs, const umilib_auth_cert_key_PrivateKey* key, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_cert_x509_Certificate** out);

/**
 * Releases the signed fields of a certificate. Does nothing if `tbs` is null.
 */
void umilib_auth_cert_x509_tbs_certificate_free(umilib_auth_cert_x509_TBSCertificate* tbs);

/**
 * Writes the certificate of the DER of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_from_der(const uint8_t* data, size_t length, umilib_auth_cert_x509_Certificate** out);

/**
 * Writes the certificate of the first PEM document (`CERTIFICATE`) of `length` bytes at `text` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_from_pem(const uint8_t* text, size_t length, umilib_auth_cert_x509_Certificate** out);

/**
 * Writes the DER of the certificate into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_to_der(const umilib_auth_cert_x509_Certificate* certificate, umilib_ffi_Buffer* out);

/**
 * Writes the PEM text (`CERTIFICATE`) of the certificate into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_to_pem(const umilib_auth_cert_x509_Certificate* certificate, umilib_ffi_Buffer* out);

/**
 * Writes the signed bytes (the DER of the `TBSCertificate` as read) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_tbs_der(const umilib_auth_cert_x509_Certificate* certificate, umilib_ffi_Buffer* out);

/**
 * Writes the version (0 for v1, 2 for v3) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_version(const umilib_auth_cert_x509_Certificate* certificate, uint8_t* out);

/**
 * Writes the contents octets of the serial number into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_serial_number(const umilib_auth_cert_x509_Certificate* certificate, umilib_ffi_Buffer* out);

/**
 * Writes the DER `AlgorithmIdentifier` of the signature algorithm into `out` (also for an
 * algorithm this module does not know).
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_signature_algorithm(const umilib_auth_cert_x509_Certificate* certificate, umilib_ffi_Buffer* out);

/**
 * Writes the octets of the signature into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_signature(const umilib_auth_cert_x509_Certificate* certificate, umilib_ffi_Buffer* out);

/**
 * Writes the issuer's name into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_issuer(const umilib_auth_cert_x509_Certificate* certificate, umilib_auth_cert_x509_Name** out);

/**
 * Writes the subject's name into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_subject(const umilib_auth_cert_x509_Certificate* certificate, umilib_auth_cert_x509_Name** out);

/**
 * Writes the start and the end of the validity, in seconds since the epoch, into `out_not_before` and `out_not_after`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_validity(const umilib_auth_cert_x509_Certificate* certificate, int64_t* out_not_before, int64_t* out_not_after);

/**
 * Writes the subject's public key, within the default key limits, into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_public_key(const umilib_auth_cert_x509_Certificate* certificate, umilib_auth_cert_key_PublicKey** out);

/**
 * Writes a copy of the extensions into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_extensions(const umilib_auth_cert_x509_Certificate* certificate, umilib_auth_cert_x509_Extensions** out);

/**
 * Succeeds if the signature verifies under `issuer`, the public key of the issuer.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_verify(const umilib_auth_cert_x509_Certificate* certificate, const umilib_auth_cert_key_PublicKey* issuer);

/**
 * Writes whether the issuer and subject names are the same encoding into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_is_self_issued(const umilib_auth_cert_x509_Certificate* certificate, bool* out);

/**
 * Releases a certificate. Does nothing if `certificate` is null.
 */
void umilib_auth_cert_x509_certificate_free(umilib_auth_cert_x509_Certificate* certificate);

/**
 * Writes an empty list of certificates into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificates_new(umilib_auth_cert_x509_Certificates** out);

/**
 * Appends a copy of `certificate` to the list.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificates_push(umilib_auth_cert_x509_Certificates* certificates, const umilib_auth_cert_x509_Certificate* certificate);

/**
 * Writes the certificates of every PEM document (each `CERTIFICATE`) of `length` bytes at `text` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificates_from_pem(const uint8_t* text, size_t length, umilib_auth_cert_x509_Certificates** out);

/**
 * Writes the number of certificates of the list into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificates_count(const umilib_auth_cert_x509_Certificates* certificates, size_t* out);

/**
 * Writes a copy of the certificate at `index` of the list into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificates_get(const umilib_auth_cert_x509_Certificates* certificates, size_t index, umilib_auth_cert_x509_Certificate** out);

/**
 * Releases a list of certificates. Does nothing if `certificates` is null.
 */
void umilib_auth_cert_x509_certificates_free(umilib_auth_cert_x509_Certificates* certificates);

/**
 * Writes an empty list of CRLs into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_lists_new(umilib_auth_cert_x509_CertificateLists** out);

/**
 * Appends a copy of the CRL `list` to the list of CRLs.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_lists_push(umilib_auth_cert_x509_CertificateLists* lists, const umilib_auth_cert_x509_CertificateList* list);

/**
 * Writes the number of CRLs of the list into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_lists_count(const umilib_auth_cert_x509_CertificateLists* lists, size_t* out);

/**
 * Writes a copy of the CRL at `index` of the list into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_lists_get(const umilib_auth_cert_x509_CertificateLists* lists, size_t index, umilib_auth_cert_x509_CertificateList** out);

/**
 * Releases a list of CRLs. Does nothing if `lists` is null.
 */
void umilib_auth_cert_x509_certificate_lists_free(umilib_auth_cert_x509_CertificateLists* lists);

/**
 * Writes the signed fields of a CRL into `out`: the version `version` (0 for v1, 1 for v2), the
 * signature algorithm `signature`, the issuer `issuer`, `this_update`, `next_update` (if
 * `has_next_update`) and the CRL extensions `extensions`, without entries.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_tbs_cert_list_new(uint8_t version, const umilib_auth_cert_key_SignatureAlgorithm* signature, const umilib_auth_cert_x509_Name* issuer, int64_t this_update, bool has_next_update, int64_t next_update, const umilib_auth_cert_x509_Extensions* extensions, umilib_auth_cert_x509_TBSCertList** out);

/**
 * Appends the entry of the serial number of `serial_length` bytes at `serial_number`, revoked
 * at `revocation_date`, with the entry extensions `extensions`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_tbs_cert_list_push(umilib_auth_cert_x509_TBSCertList* tbs, const uint8_t* serial_number, size_t serial_length, int64_t revocation_date, const umilib_auth_cert_x509_Extensions* extensions);

/**
 * Writes the CRL of the fields signed by `key` (drawing from `random` where the algorithm uses
 * random bytes) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_tbs_cert_list_sign(const umilib_auth_cert_x509_TBSCertList* tbs, const umilib_auth_cert_key_PrivateKey* key, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_cert_x509_CertificateList** out);

/**
 * Releases the signed fields of a CRL. Does nothing if `tbs` is null.
 */
void umilib_auth_cert_x509_tbs_cert_list_free(umilib_auth_cert_x509_TBSCertList* tbs);

/**
 * Writes the CRL of the DER of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_from_der(const uint8_t* data, size_t length, umilib_auth_cert_x509_CertificateList** out);

/**
 * Writes the CRL of the first PEM document (`X509 CRL`) of `length` bytes at `text` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_from_pem(const uint8_t* text, size_t length, umilib_auth_cert_x509_CertificateList** out);

/**
 * Writes the DER of the CRL into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_to_der(const umilib_auth_cert_x509_CertificateList* list, umilib_ffi_Buffer* out);

/**
 * Writes the PEM text (`X509 CRL`) of the CRL into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_to_pem(const umilib_auth_cert_x509_CertificateList* list, umilib_ffi_Buffer* out);

/**
 * Writes the version (0 for v1, 1 for v2) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_version(const umilib_auth_cert_x509_CertificateList* list, uint8_t* out);

/**
 * Writes the issuer's name into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_issuer(const umilib_auth_cert_x509_CertificateList* list, umilib_auth_cert_x509_Name** out);

/**
 * Writes `thisUpdate` into `out`, in seconds since the epoch.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_this_update(const umilib_auth_cert_x509_CertificateList* list, int64_t* out);

/**
 * Writes whether the CRL has a `nextUpdate` into `out_found` and, if it has, the time into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_next_update(const umilib_auth_cert_x509_CertificateList* list, bool* out_found, int64_t* out);

/**
 * Writes a copy of the CRL extensions into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_extensions(const umilib_auth_cert_x509_CertificateList* list, umilib_auth_cert_x509_Extensions** out);

/**
 * Writes the number of entries into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_count(const umilib_auth_cert_x509_CertificateList* list, size_t* out);

/**
 * Writes the serial number (contents octets), the revocation date and a copy of the entry
 * extensions of the entry at `index` into `out_serial_number`, `out_revocation_date` and `out_extensions`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_get(const umilib_auth_cert_x509_CertificateList* list, size_t index, umilib_ffi_Buffer* out_serial_number, int64_t* out_revocation_date, umilib_auth_cert_x509_Extensions** out_extensions);

/**
 * Writes whether the CRL lists the serial number of `length` bytes at `serial_number` into
 * `out_found` and, if it does, the index of its entry into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_find(const umilib_auth_cert_x509_CertificateList* list, const uint8_t* serial_number, size_t length, bool* out_found, size_t* out);

/**
 * Succeeds if the signature verifies under `issuer`, the public key of the CRL issuer.
 */
const umilib_ffi_Status* umilib_auth_cert_x509_certificate_list_verify(const umilib_auth_cert_x509_CertificateList* list, const umilib_auth_cert_key_PublicKey* issuer);

/**
 * Releases a CRL. Does nothing if `list` is null.
 */
void umilib_auth_cert_x509_certificate_list_free(umilib_auth_cert_x509_CertificateList* list);

#ifdef __cplusplus
}
#endif

#endif
