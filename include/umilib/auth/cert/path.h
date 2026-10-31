/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_CERT_PATH_H
#define UMILIB_AUTH_CERT_PATH_H

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
 * The inputs of path validation and the limits of path building.
 */
typedef struct umilib_auth_cert_path_PathConfig umilib_auth_cert_path_PathConfig;

/**
 * A trust anchor.
 */
typedef struct umilib_auth_cert_path_TrustAnchor umilib_auth_cert_path_TrustAnchor;

/**
 * A list of trust anchors.
 */
typedef struct umilib_auth_cert_path_TrustAnchors umilib_auth_cert_path_TrustAnchors;

/**
 * The revocation sources of a validation other than its CRLs.
 */
typedef struct umilib_auth_cert_path_RevocationSources umilib_auth_cert_path_RevocationSources;

/**
 * The outcome of a validation: the path, or the error.
 */
typedef struct umilib_auth_cert_path_PathOutcome umilib_auth_cert_path_PathOutcome;

/**
 * Writes the defaults at `time` into `out`: the profile of RFC 5280, any policy, no name
 * constraints, at most 8 intermediates, 100 signatures, 4 nested CRL issuer paths and 2^20
 * name comparisons, the default key limits, SHA-1 refused, no revocation checking, and no
 * usage, purpose or identity.
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_config_new(int64_t time, umilib_auth_cert_path_PathConfig** out);

/**
 * Sets the profile (a [`PathProfileKind`] code).
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_config_set_profile(umilib_auth_cert_path_PathConfig* config, uint8_t profile);

/**
 * Sets the user-initial-policy-set: any policy if `any`, otherwise the dotted object
 * identifiers of `length` bytes at `policies`, separated by commas.
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_config_set_initial_policy_set(umilib_auth_cert_path_PathConfig* config, bool any, const uint8_t* policies, size_t length);

/**
 * Sets initial-explicit-policy, initial-policy-mapping-inhibit and initial-any-policy-inhibit.
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_config_set_initial_policy_flags(umilib_auth_cert_path_PathConfig* config, bool explicit_policy, bool policy_mapping_inhibit, bool any_policy_inhibit);

/**
 * Sets the initial name constraints, the DER `NameConstraints` value of `length` bytes at
 * `data` (none for 0 bytes).
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_config_set_initial_name_constraints(umilib_auth_cert_path_PathConfig* config, const uint8_t* data, size_t length);

/**
 * Sets the most intermediate certificates (not counting self-issued ones), signatures, CRL
 * issuer paths nested in one another and name comparisons.
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_config_set_limits(umilib_auth_cert_path_PathConfig* config, size_t maximum_intermediates, size_t maximum_signatures, size_t maximum_nested_signers, size_t maximum_name_checks);

/**
 * Sets the largest RSA modulus and exponent (in bits) accepted.
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_config_set_key_limits(umilib_auth_cert_path_PathConfig* config, uint32_t maximum_rsa_bits, uint32_t maximum_rsa_exponent_bits);

/**
 * Sets whether signatures that hash with SHA-1 are accepted.
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_config_set_accept_sha1(umilib_auth_cert_path_PathConfig* config, bool accept);

/**
 * Sets whether revocation is checked, whether an unknown status fails, whether delta CRLs are
 * applied, and how long (in seconds) a CRL or a status without `nextUpdate` is current.
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_config_set_revocation(umilib_auth_cert_path_PathConfig* config, bool check, bool require, bool use_deltas, uint64_t lifetime_without_next_update);

/**
 * Sets the key usages (the bits of x509, bit 0 `digitalSignature` as `1 << 0`) the target's key
 * must allow if `has_key_usage`; none otherwise.
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_config_set_key_usage(umilib_auth_cert_path_PathConfig* config, bool has_key_usage, uint16_t bits);

/**
 * Sets the purpose, the dotted object identifier of `length` bytes at `purpose`, that the
 * target's extended key usage must allow (none for 0 bytes).
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_config_set_extended_key_usage(umilib_auth_cert_path_PathConfig* config, const uint8_t* purpose, size_t length);

/**
 * Sets the identity the target must name: the [`ServiceIdentityKind`] `kind` and the `length`
 * bytes at `data` (none for `kind` 0).
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_config_set_identity(umilib_auth_cert_path_PathConfig* config, uint8_t kind, const uint8_t* data, size_t length);

/**
 * Releases a configuration. Does nothing if `config` is null.
 */
void umilib_auth_cert_path_path_config_free(umilib_auth_cert_path_PathConfig* config);

/**
 * Writes the anchor of the name `name` and the key `public_key`, with the name constraints of
 * the DER `NameConstraints` value of `length` bytes at `name_constraints` (none for 0 bytes), into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_path_trust_anchor_new(const umilib_auth_cert_x509_Name* name, const umilib_auth_cert_key_PublicKey* public_key, const uint8_t* name_constraints, size_t length, umilib_auth_cert_path_TrustAnchor** out);

/**
 * Writes the anchor of a copy of `certificate` (its subject, its key within the limits of
 * `maximum_rsa_bits` and `maximum_rsa_exponent_bits`, and its name constraints) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_path_trust_anchor_from_certificate(const umilib_auth_cert_x509_Certificate* certificate, uint32_t maximum_rsa_bits, uint32_t maximum_rsa_exponent_bits, umilib_auth_cert_path_TrustAnchor** out);

/**
 * Writes the name of the anchor into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_path_trust_anchor_name(const umilib_auth_cert_path_TrustAnchor* anchor, umilib_auth_cert_x509_Name** out);

/**
 * Writes the key of the anchor into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_path_trust_anchor_public_key(const umilib_auth_cert_path_TrustAnchor* anchor, umilib_auth_cert_key_PublicKey** out);

/**
 * Releases an anchor. Does nothing if `anchor` is null.
 */
void umilib_auth_cert_path_trust_anchor_free(umilib_auth_cert_path_TrustAnchor* anchor);

/**
 * Writes an empty list of anchors into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_path_trust_anchors_new(umilib_auth_cert_path_TrustAnchors** out);

/**
 * Appends a copy of `anchor` to the list.
 */
const umilib_ffi_Status* umilib_auth_cert_path_trust_anchors_push(umilib_auth_cert_path_TrustAnchors* anchors, const umilib_auth_cert_path_TrustAnchor* anchor);

/**
 * Writes the number of anchors of the list into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_path_trust_anchors_count(const umilib_auth_cert_path_TrustAnchors* anchors, size_t* out);

/**
 * Releases a list of anchors. Does nothing if `anchors` is null.
 */
void umilib_auth_cert_path_trust_anchors_free(umilib_auth_cert_path_TrustAnchors* anchors);

/**
 * Writes an empty list of revocation sources into `out`; the modules of the sources add to it.
 */
const umilib_ffi_Status* umilib_auth_cert_path_revocation_sources_new(umilib_auth_cert_path_RevocationSources** out);

/**
 * Writes the number of sources of the list into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_path_revocation_sources_count(const umilib_auth_cert_path_RevocationSources* sources, size_t* out);

/**
 * Releases a list of revocation sources. Does nothing if `sources` is null.
 */
void umilib_auth_cert_path_revocation_sources_free(umilib_auth_cert_path_RevocationSources* sources);

/**
 * Builds a path from `target` through `intermediates` to one of `anchors` and validates it
 * under `config`, with the CRLs `crls` and the revocation sources `sources` (null for none),
 * and writes the outcome into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_validator_validate(const umilib_auth_cert_path_PathConfig* config, const umilib_auth_cert_path_TrustAnchors* anchors, const umilib_auth_cert_x509_Certificates* intermediates, const umilib_auth_cert_x509_CertificateLists* crls, const umilib_auth_cert_path_RevocationSources* sources, const umilib_auth_cert_x509_Certificate* target, umilib_auth_cert_path_PathOutcome** out);

/**
 * Writes whether the path validated into `out_valid` and, if it did not, the status of the
 * reason into `out_reason`, the index of the certificate it concerns (0 for the target) into
 * `out_index` and, for a revoked certificate, the code of the reason into `out_revocation_reason`
 * (null, 0 and 255 otherwise).
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_outcome_error(const umilib_auth_cert_path_PathOutcome* outcome, bool* out_valid, const umilib_ffi_Status** out_reason, size_t* out_index, uint8_t* out_revocation_reason);

/**
 * Writes copies of the certificates of the path, from the target (none if it did not
 * validate), into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_outcome_certificates(const umilib_auth_cert_path_PathOutcome* outcome, umilib_auth_cert_x509_Certificates** out);

/**
 * Writes the index, in the list of anchors validated against, of the anchor of the path into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_outcome_anchor(const umilib_auth_cert_path_PathOutcome* outcome, size_t* out);

/**
 * Writes the user-constrained policy set of the path (dotted, separated by commas; it has
 * anyPolicy when every policy is valid) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_path_path_outcome_policies(const umilib_auth_cert_path_PathOutcome* outcome, umilib_ffi_Buffer* out);

/**
 * Releases an outcome. Does nothing if `outcome` is null.
 */
void umilib_auth_cert_path_path_outcome_free(umilib_auth_cert_path_PathOutcome* outcome);

#ifdef __cplusplus
}
#endif

#endif
