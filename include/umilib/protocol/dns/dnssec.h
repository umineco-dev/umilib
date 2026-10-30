/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_DNS_DNSSEC_H
#define UMILIB_PROTOCOL_DNS_DNSSEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/dns.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A DNSSEC validator and its configuration.
 */
typedef struct umilib_protocol_dns_dnssec_DNSSECValidator umilib_protocol_dns_dnssec_DNSSECValidator;

/**
 * A validating stub resolver.
 */
typedef struct umilib_protocol_dns_dnssec_DNSSECResolver umilib_protocol_dns_dnssec_DNSSECResolver;

/**
 * The limits of a validator.
 */
typedef struct umilib_protocol_dns_dnssec_DNSSECLimits {
    uint32_t minimum_rsa_bits;
    uint16_t insecure_nsec3_iterations;
    uint16_t bogus_nsec3_iterations;
    uint32_t maximum_verifications;
    uint32_t clock_skew;
    uint32_t maximum_rsa_exponent_bits;
} umilib_protocol_dns_dnssec_DNSSECLimits;

/**
 * What a verification tells: the TTL kept, the key's tag, whether the records were expanded from a wildcard.
 */
typedef struct umilib_protocol_dns_dnssec_DNSSECVerified {
    uint32_t ttl;
    uint16_t key_tag;
    bool expanded;
} umilib_protocol_dns_dnssec_DNSSECVerified;

/**
 * Writes a validator of the defaults (every algorithm and digest RFC 9904 says to implement) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_validator_new(umilib_protocol_dns_dnssec_DNSSECValidator** out);

/**
 * Releases a validator. Does nothing if `validator` is null.
 */
void umilib_protocol_dns_dnssec_dnssec_validator_free(umilib_protocol_dns_dnssec_DNSSECValidator* validator);

/**
 * Sets the algorithms in use to the `count` numbers at `algorithms`, and the digests to the
 * `digest_count` numbers at `digests`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_validator_set_algorithms(umilib_protocol_dns_dnssec_DNSSECValidator* validator, const uint8_t* algorithms, size_t count, const uint8_t* digests, size_t digest_count);

/**
 * Writes the limits into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_validator_limits(const umilib_protocol_dns_dnssec_DNSSECValidator* validator, umilib_protocol_dns_dnssec_DNSSECLimits* out);

/**
 * Sets the limits to `limits`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_validator_set_limits(umilib_protocol_dns_dnssec_DNSSECValidator* validator, umilib_protocol_dns_dnssec_DNSSECLimits limits);

/**
 * Verifies the RRset of the records of the `length` bytes of text at `records` with the RRSIG
 * records of `signatures` and the DNSKEY records of `keys`, at `time` (RFC 4035 §5.3); writes
 * what it tells into `out` and, for records expanded from a wildcard, the closest encloser into
 * `out_encloser`. Fails with Bogus and its extended error in `out_code`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_validator_verify(const umilib_protocol_dns_dnssec_DNSSECValidator* validator, const uint8_t* records, size_t length, const uint8_t* signatures, size_t signatures_length, const uint8_t* keys, size_t keys_length, uint32_t time, umilib_protocol_dns_dnssec_DNSSECVerified* out, umilib_ffi_Buffer* out_encloser, uint16_t* out_code);

/**
 * Checks the DNSKEY records of `keys`, signed by the RRSIG records of `signatures`, against the DS
 * or DNSKEY records of `anchors`, at `time` (RFC 4035 §5.2): writes whether they are secure into
 * `out_secure` and, if insecure, the extended error that tells why into `out_code`. Fails with Bogus.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_validator_verify_keys(const umilib_protocol_dns_dnssec_DNSSECValidator* validator, const uint8_t* keys, size_t keys_length, const uint8_t* signatures, size_t signatures_length, const uint8_t* anchors, size_t anchors_length, uint32_t time, bool* out_secure, uint16_t* out_code);

/**
 * Proves, with the NSEC and NSEC3 records of `records` (verified), the denial `kind` of the name
 * of `name` in the zone of `zone`: 0 that it does not exist, 1 that it has no records of the type
 * `record_type`, 2 that it was answered by the wildcard below the closest encloser of `encloser`,
 * 3 that its delegation has no DS. Writes whether the proof is secure into `out_secure` (if not,
 * an extended error, or 0, into `out_code`); fails with Bogus.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_validator_prove(const umilib_protocol_dns_dnssec_DNSSECValidator* validator, uint8_t kind, const uint8_t* name, size_t name_length, uint16_t record_type, const uint8_t* encloser, size_t encloser_length, const uint8_t* zone, size_t zone_length, const uint8_t* records, size_t length, bool* out_secure, uint16_t* out_code);

/**
 * Writes a new private key of `algorithm` (an RSA modulus of `bits`), drawn from `random`, in the
 * private key format into `out`; fails with Config for an algorithm not implemented.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_private_key_generate(uint8_t algorithm, uint32_t bits, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes the DNSKEY record of the private key of the text at `key`, owned by the zone of
 * `origin`, of `flags` and `ttl`, into `out`; fails with Syntax.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_private_key_dnskey(const uint8_t* key, size_t key_length, const uint8_t* origin, size_t origin_length, uint16_t flags, uint32_t ttl, umilib_ffi_Buffer* out);

/**
 * Writes the DS record of `digest` of that DNSKEY into `out` (RFC 4034 §5); fails with Config
 * for a digest not implemented.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_private_key_delegation(const uint8_t* key, size_t key_length, const uint8_t* origin, size_t origin_length, uint16_t flags, uint8_t digest, uint32_t ttl, umilib_ffi_Buffer* out);

/**
 * Writes the zone of the origin of `origin` and the zone-file text of `zone`, signed by the
 * `count` private keys of the NUL-terminated texts at `keys` with the DNSKEY flags at `flags`,
 * valid from `inception` to `expiration` (RFC 4035 §2), the signatures' randomness drawn from
 * `random`, its records one a line, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dns_zone_sign(const uint8_t* origin, size_t origin_length, const uint8_t* zone, size_t zone_length, const char* const* keys, const uint16_t* flags, size_t count, uint32_t inception, uint32_t expiration, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes the DS records of the root's trust anchors valid at `time` (RFC 9718) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_trust_anchor_root(int64_t time, umilib_ffi_Buffer* out);

/**
 * Writes the DS records of the trust anchors of the XML of the `length` bytes at `xml` valid at
 * `time` (RFC 9718 §2) into `out`, and the zone they are of into `out_zone`; fails with Syntax.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_trust_anchor_parse(const uint8_t* xml, size_t length, int64_t time, umilib_ffi_Buffer* out_zone, umilib_ffi_Buffer* out);

/**
 * Writes a validating resolver of `config`, the `count` servers at `upstreams`, the configuration
 * of `validator`, and the trust anchors of the XML of `anchors` (the root's if `anchors_length`
 * is 0), its cookie secret drawn from `random`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_resolver_new(umilib_protocol_dns_DNSResolverConfig config, const umilib_protocol_dns_DNSUpstream* upstreams, size_t count, const umilib_protocol_dns_dnssec_DNSSECValidator* validator, const uint8_t* anchors, size_t anchors_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_protocol_dns_dnssec_DNSSECResolver** out);

/**
 * Releases a validating resolver. Does nothing if `resolver` is null.
 */
void umilib_protocol_dns_dnssec_dnssec_resolver_free(umilib_protocol_dns_dnssec_DNSSECResolver* resolver);

/**
 * Starts resolving and validating the name of `name`, of `kind` and `record_class`, at `now` and
 * `time`, its IDs drawn from `random`, and writes the query's handle into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_resolver_resolve(umilib_protocol_dns_dnssec_DNSSECResolver* resolver, const uint8_t* name, size_t length, uint16_t kind, uint16_t record_class, uint64_t now, uint64_t time, void* random, const uint8_t* random_type, size_t random_type_length, uint64_t* out);

/**
 * Writes whether a query is to be sent into `out_found`, where into `out`, and its bytes into `out_message`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_resolver_transmit(umilib_protocol_dns_dnssec_DNSSECResolver* resolver, bool* out_found, umilib_protocol_dns_DNSTransmission* out, umilib_ffi_Buffer* out_message);

/**
 * Takes the response of the `length` bytes at `bytes` from `upstream` over `transport` to `query`, at `now` and `time`,
 * the queries it needs drawing their IDs from `random`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_resolver_receive(umilib_protocol_dns_dnssec_DNSSECResolver* resolver, uint64_t query, uint32_t upstream, uint8_t transport, const uint8_t* bytes, size_t length, uint64_t now, uint64_t time, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Writes whether a timer is set into `out_found` and when it fires (nanoseconds) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_resolver_poll_timeout(const umilib_protocol_dns_dnssec_DNSSECResolver* resolver, bool* out_found, uint64_t* out);

/**
 * Sends again the queries unanswered at `now`, and goes on with the validations, at `time`,
 * their IDs drawn from `random`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_resolver_expire(umilib_protocol_dns_dnssec_DNSSECResolver* resolver, uint64_t now, uint64_t time, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Writes whether a question is answered into `out_found`, its query into `out_query`, the status
 * of its failure (null for an answer; Bogus for a failed validation, its extended error in
 * `out_code`) into `out_error`, whether the answer is secure into `out_secure`, and the response,
 * AD set if secure, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dnssec_dnssec_resolver_poll_event(umilib_protocol_dns_dnssec_DNSSECResolver* resolver, bool* out_found, uint64_t* out_query, const umilib_ffi_Status** out_error, bool* out_secure, uint16_t* out_code, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
