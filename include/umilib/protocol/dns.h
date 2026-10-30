/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_DNS_H
#define UMILIB_PROTOCOL_DNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A DNS message (RFC 1035 §4.1).
 */
typedef struct umilib_protocol_dns_DNSMessage umilib_protocol_dns_DNSMessage;

/**
 * An authoritative name server and its zones.
 */
typedef struct umilib_protocol_dns_DNSAuthority umilib_protocol_dns_DNSAuthority;

/**
 * A stub resolver.
 */
typedef struct umilib_protocol_dns_DNSResolver umilib_protocol_dns_DNSResolver;

/**
 * The header of a message, the response code whole.
 */
typedef struct umilib_protocol_dns_DNSHeader {
    uint16_t id;
    bool response;
    uint8_t opcode;
    bool authoritative;
    bool truncated;
    bool recursion_desired;
    bool recursion_available;
    bool authentic_data;
    bool checking_disabled;
    uint16_t rcode;
} umilib_protocol_dns_DNSHeader;

/**
 * The EDNS of a message, if present.
 */
typedef struct umilib_protocol_dns_DNSEDNS {
    bool present;
    uint16_t udp_size;
    uint8_t version;
    bool dnssec_ok;
} umilib_protocol_dns_DNSEDNS;

/**
 * The configuration of an authoritative server, durations in milliseconds (0: none).
 */
typedef struct umilib_protocol_dns_DNSAuthorityConfig {
    bool minimal;
    uint16_t udp_size;
    uint32_t maximum_chain;
    uint32_t padding;
    uint32_t transfer_size;
    uint32_t keepalive;
} umilib_protocol_dns_DNSAuthorityConfig;

/**
 * The configuration of a resolver but its servers, durations in milliseconds and TTLs in seconds.
 */
typedef struct umilib_protocol_dns_DNSResolverConfig {
    uint32_t timeout;
    uint32_t maximum_timeout;
    uint32_t rounds;
    bool edns;
    uint16_t udp_size;
    bool recursion_desired;
    bool dnssec_ok;
    bool checking_disabled;
    bool cookies;
    uint32_t padding;
    uint32_t maximum_queries;
    uint32_t cache_entries;
    uint32_t cache_maximum_ttl;
    uint32_t cache_minimum_ttl;
    uint32_t cache_maximum_negative_ttl;
    uint32_t cache_failure_ttl;
} umilib_protocol_dns_DNSResolverConfig;

/**
 * A server of a resolver: its endpoint and transport.
 */
typedef struct umilib_protocol_dns_DNSUpstream {
    umilib_protocol_ip_IPEndpoint endpoint;
    uint8_t transport;
} umilib_protocol_dns_DNSUpstream;

/**
 * A query to send: of which query, to which server, over which transport.
 */
typedef struct umilib_protocol_dns_DNSTransmission {
    uint64_t query;
    uint32_t upstream;
    uint8_t transport;
} umilib_protocol_dns_DNSTransmission;

/**
 * Writes a query of `id` for the name of the `length` bytes of text at `name`, of the type
 * `kind` and the class `record_class`, with recursion desired, into `out`; fails with Syntax for a
 * name that is not one.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_message_query(const uint8_t* name, size_t length, uint16_t kind, uint16_t record_class, uint16_t id, umilib_protocol_dns_DNSMessage** out);

/**
 * Reads the message of the `length` bytes at `bytes` into `out`; fails with Malformed.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_message_decode(const uint8_t* bytes, size_t length, umilib_protocol_dns_DNSMessage** out);

/**
 * Releases a message. Does nothing if `message` is null.
 */
void umilib_protocol_dns_dns_message_free(umilib_protocol_dns_DNSMessage* message);

/**
 * Writes the message in at most `limit` bytes, whole RRsets left out from the end (RFC 2181
 * §9), into `out`; fails with TooLarge if not even the question fits.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_message_encode(const umilib_protocol_dns_DNSMessage* message, size_t limit, umilib_ffi_Buffer* out);

/**
 * Writes the header into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_message_header(const umilib_protocol_dns_DNSMessage* message, umilib_protocol_dns_DNSHeader* out);

/**
 * Sets the header to `header`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_message_set_header(umilib_protocol_dns_DNSMessage* message, umilib_protocol_dns_DNSHeader header);

/**
 * Writes the EDNS into `out`, `present` false without one.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_message_edns(const umilib_protocol_dns_DNSMessage* message, umilib_protocol_dns_DNSEDNS* out);

/**
 * Sets the EDNS to `edns` (its options kept), or removes it if not `present`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_message_set_edns(umilib_protocol_dns_DNSMessage* message, umilib_protocol_dns_DNSEDNS edns);

/**
 * Writes whether the EDNS has an option of `code` into `out_found`, and its data into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_message_option(const umilib_protocol_dns_DNSMessage* message, uint16_t code, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Sets the option of `code` to the `length` bytes at `data`, the only one of it; adds EDNS if there is none.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_message_set_option(umilib_protocol_dns_DNSMessage* message, uint16_t code, const uint8_t* data, size_t length);

/**
 * Writes whether the message has a question into `out_found`, its name (text) into
 * `out_name`, its type into `out_kind` and its class into `out_class`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_message_question(const umilib_protocol_dns_DNSMessage* message, bool* out_found, umilib_ffi_Buffer* out_name, uint16_t* out_kind, uint16_t* out_class);

/**
 * Writes the records of `section` (0 answer, 1 authority, 2 additional), one a line, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_message_records(const umilib_protocol_dns_DNSMessage* message, uint8_t section, umilib_ffi_Buffer* out);

/**
 * Adds the records of the zone-file text of the `length` bytes at `text` (absolute names, TTL 0
 * where none is given) to `section` (0 answer, 1 authority, 2 additional); fails with Syntax.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_message_add_records(umilib_protocol_dns_DNSMessage* message, uint8_t section, const uint8_t* text, size_t length);

/**
 * Writes the records of the zone file of the `length` bytes at `text`, of the origin of the
 * `origin_length` bytes at `origin` (none if 0) and the default TTL `ttl` (none if `has_ttl` is
 * false), one a line with absolute names, into `out`; on Syntax, the line into `out_line`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_zone_file_parse(const uint8_t* text, size_t length, const uint8_t* origin, size_t origin_length, bool has_ttl, uint32_t ttl, size_t* out_line, umilib_ffi_Buffer* out);

/**
 * Writes the default configuration of an authoritative server into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_authority_config_default(umilib_protocol_dns_DNSAuthorityConfig* out);

/**
 * Writes an authoritative server of `config` and no zone into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_authority_new(umilib_protocol_dns_DNSAuthorityConfig config, umilib_protocol_dns_DNSAuthority** out);

/**
 * Releases a server. Does nothing if `authority` is null.
 */
void umilib_protocol_dns_dns_authority_free(umilib_protocol_dns_DNSAuthority* authority);

/**
 * Adds the zone of the origin of the `origin_length` bytes at `origin` and the records of the
 * zone-file text of the `length` bytes at `text` (relative names of that origin, the default TTL
 * the SOA's); fails with Syntax, or Config for a zone without its one SOA at the origin.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_authority_add_zone(umilib_protocol_dns_DNSAuthority* authority, const uint8_t* origin, size_t origin_length, const uint8_t* text, size_t length);

/**
 * Sets the secrets of server cookies (RFC 9018 §5) to the `length` bytes at `secrets`, 16 a
 * secret, the first the current one; none ignores cookies. Fails with InvalidArgument for a
 * length that is not a multiple of 16.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_authority_set_cookie_secrets(umilib_protocol_dns_DNSAuthority* authority, const uint8_t* secrets, size_t length);

/**
 * Sets the clients that may transfer zones (RFC 5936) to the `count` patterns at `patterns`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_authority_set_transfers(umilib_protocol_dns_DNSAuthority* authority, const umilib_protocol_ip_IPEndpointPattern* patterns, size_t count);

/**
 * Writes the responses to the query of the `length` bytes at `query` from `peer` over
 * `transport` at `time` into `out`, each after its length in two bytes (none for a message that
 * is not answered, several for a zone transfer).
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_authority_respond(const umilib_protocol_dns_DNSAuthority* authority, const uint8_t* query, size_t length, umilib_protocol_ip_IPEndpoint peer, uint8_t transport, uint32_t time, umilib_ffi_Buffer* out);

/**
 * Writes the default configuration of a resolver into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_resolver_config_default(umilib_protocol_dns_DNSResolverConfig* out);

/**
 * Writes a resolver of `config` and the `count` servers at `upstreams`, its cookie secret
 * drawn from `random`, into `out`; fails with Config without servers.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_resolver_new(umilib_protocol_dns_DNSResolverConfig config, const umilib_protocol_dns_DNSUpstream* upstreams, size_t count, void* random, const uint8_t* random_type, size_t random_type_length, umilib_protocol_dns_DNSResolver** out);

/**
 * Releases a resolver. Does nothing if `resolver` is null.
 */
void umilib_protocol_dns_dns_resolver_free(umilib_protocol_dns_DNSResolver* resolver);

/**
 * Starts resolving the name of the `length` bytes of text at `name`, of `kind` and
 * `record_class`, at `now`, its ID drawn from `random`, and writes the query's handle into
 * `out`; fails with State at the limit of queries.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_resolver_resolve(umilib_protocol_dns_DNSResolver* resolver, const uint8_t* name, size_t length, uint16_t kind, uint16_t record_class, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length, uint64_t* out);

/**
 * Writes whether a query is to be sent into `out_found`, where into `out`, and its bytes into `out_message`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_resolver_transmit(umilib_protocol_dns_DNSResolver* resolver, bool* out_found, umilib_protocol_dns_DNSTransmission* out, umilib_ffi_Buffer* out_message);

/**
 * Takes the response of the `length` bytes at `bytes` from the server `upstream` over
 * `transport` to the query `query`, at `now`, a query sent again drawing its ID from `random`;
 * one that does not match its query is ignored.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_resolver_receive(umilib_protocol_dns_DNSResolver* resolver, uint64_t query, uint32_t upstream, uint8_t transport, const uint8_t* bytes, size_t length, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Writes whether a timer is set into `out_found` and when it fires (nanoseconds) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_resolver_poll_timeout(const umilib_protocol_dns_DNSResolver* resolver, bool* out_found, uint64_t* out);

/**
 * Sends again, to their next servers, the queries unanswered at `now`, their IDs drawn from `random`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_resolver_expire(umilib_protocol_dns_DNSResolver* resolver, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Stops resolving the query `query`; it is not told.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_resolver_cancel(umilib_protocol_dns_DNSResolver* resolver, uint64_t query);

/**
 * Writes whether a query is resolved into `out_found`, its handle into `out_query`, the status of
 * its failure (null for a response) into `out_error`, and the response into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_dns_resolver_poll_event(umilib_protocol_dns_DNSResolver* resolver, bool* out_found, uint64_t* out_query, const umilib_ffi_Status** out_error, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
