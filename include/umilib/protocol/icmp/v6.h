/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_ICMP_V6_H
#define UMILIB_PROTOCOL_ICMP_V6_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/icmp.h"
#include "umilib/protocol/ip.h"
#include "umilib/protocol/ip/v6.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The fields of a Router Advertisement (RFC 4861 §4.2, RFC 4191) but its options.
 */
typedef struct umilib_protocol_icmp_v6_NDPRouterAdvertisement {
    uint8_t current_hop_limit;
    bool managed_flag;
    bool other_flag;
    uint8_t preference;
    uint8_t flags;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retransmission_timer;
} umilib_protocol_icmp_v6_NDPRouterAdvertisement;

/**
 * The fields of a Neighbor Advertisement (RFC 4861 §4.4) but its options.
 */
typedef struct umilib_protocol_icmp_v6_NDPNeighborAdvertisement {
    bool router_flag;
    bool solicited_flag;
    bool override_flag;
    umilib_protocol_ip_IPv6Address target;
} umilib_protocol_icmp_v6_NDPNeighborAdvertisement;

/**
 * A Prefix Information option (RFC 4861 §4.6.2); lifetimes in seconds.
 */
typedef struct umilib_protocol_icmp_v6_NDPPrefixInformation {
    uint8_t prefix_length;
    bool on_link;
    bool autonomous;
    uint8_t flags;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
    umilib_protocol_ip_IPv6Address prefix;
} umilib_protocol_icmp_v6_NDPPrefixInformation;

/**
 * A Route Information option (RFC 4191 §2.3); the lifetime in seconds.
 */
typedef struct umilib_protocol_icmp_v6_NDPRouteInformation {
    uint8_t prefix_length;
    uint8_t preference;
    uint32_t lifetime;
    umilib_protocol_ip_IPv6Address prefix;
} umilib_protocol_icmp_v6_NDPRouteInformation;

/**
 * The parameters of a neighbor cache (RFC 4861 §10); durations in nanoseconds.
 */
typedef struct umilib_protocol_icmp_v6_NeighborConfig {
    uint64_t reachable_time;
    uint64_t retransmission_timer;
    uint64_t delay_first_probe_time;
    uint32_t maximum_multicast_solicitations;
    uint32_t maximum_unicast_solicitations;
    size_t maximum_entries;
    size_t maximum_queued;
} umilib_protocol_icmp_v6_NeighborConfig;

/**
 * The Neighbor Cache of RFC 4861 for 6-byte link-layer addresses.
 */
typedef struct umilib_protocol_icmp_v6_NeighborCache umilib_protocol_icmp_v6_NeighborCache;

/**
 * Packets the neighbor cache gives back.
 */
typedef struct umilib_protocol_icmp_v6_NeighborPackets umilib_protocol_icmp_v6_NeighborPackets;

/**
 * A solicitation to send, or a neighbor that did not answer.
 */
typedef struct umilib_protocol_icmp_v6_NeighborEvent umilib_protocol_icmp_v6_NeighborEvent;

/**
 * Reads the message of the `length` bytes at `bytes`, carried from `source` to `destination`,
 * whose checksum must be right, into `out` (its body is the bytes after the first eight); fails
 * with Length or Checksum.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_icmpv6_message_decode(const uint8_t* bytes, size_t length, umilib_protocol_ip_IPv6Address source, umilib_protocol_ip_IPv6Address destination, umilib_protocol_icmp_ICMPHeader* out);

/**
 * Writes the message of `header` and the `length` bytes of body at `body`, with its checksum
 * for `source` and `destination`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_icmpv6_message_encode(umilib_protocol_icmp_ICMPHeader header, const uint8_t* body, size_t length, umilib_protocol_ip_IPv6Address source, umilib_protocol_ip_IPv6Address destination, umilib_ffi_Buffer* out);

/**
 * The header of an Echo Request of `identifier` and `sequence`.
 */
umilib_protocol_icmp_ICMPHeader umilib_protocol_icmp_v6_icmpv6_message_echo_request(uint16_t identifier, uint16_t sequence);

/**
 * Writes whether `header` is an Echo Request into `out_found` and the header of its reply into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_icmpv6_message_echo_reply(umilib_protocol_icmp_ICMPHeader header, bool* out_found, umilib_protocol_icmp_ICMPHeader* out);

/**
 * Writes whether `header` is of an Echo Request or Reply into `out_found`, and its identifier and
 * sequence number into `out_identifier` and `out_sequence`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_icmpv6_message_echo(umilib_protocol_icmp_ICMPHeader header, bool* out_found, uint16_t* out_identifier, uint16_t* out_sequence);

/**
 * Writes whether `header` is a Packet Too Big into `out_found` and its MTU into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_icmpv6_message_mtu(umilib_protocol_icmp_ICMPHeader header, bool* out_found, uint32_t* out);

/**
 * Writes whether `header` is a Parameter Problem into `out_found` and its pointer into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_icmpv6_message_pointer(umilib_protocol_icmp_ICMPHeader header, bool* out_found, uint32_t* out);

/**
 * Writes the length of the invoking packet an error message of `header` and the `length` bytes
 * at `body` quotes into `out_original` and whether an extension structure follows it into
 * `out_found`; fails with Length, Version or Checksum.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_icmpv6_message_original(umilib_protocol_icmp_ICMPHeader header, const uint8_t* body, size_t length, size_t* out_original, bool* out_found);

/**
 * The bytes of a packet of `length` bytes that an error message quotes after an IPv6 header and
 * `headers` bytes of extension headers, within 1,280 bytes (RFC 4443 §2.4 (c)).
 */
size_t umilib_protocol_icmp_v6_icmpv6_message_quote_length(size_t length, size_t headers);

/**
 * Writes whether the error of the header `error` may be sent about the packet of `header` and
 * the `length` bytes of payload at `payload`, received as a link-layer multicast or broadcast if
 * `multicast` (RFC 4443 §2.4 (e)), into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_icmpv6_message_may_report(const umilib_protocol_ip_v6_IPv6Header* header, const uint8_t* payload, size_t length, bool multicast, umilib_protocol_icmp_ICMPHeader error, bool* out);

/**
 * Whether the type `kind` is that of an error message (below 128).
 */
bool umilib_protocol_icmp_v6_icmpv6_type_is_error(uint8_t kind);

/**
 * Whether an error of the type `kind` carries the length attribute of RFC 4884.
 */
bool umilib_protocol_icmp_v6_icmpv6_type_is_extensible(uint8_t kind);

/**
 * Whether `address` is a solicited-node multicast address.
 */
bool umilib_protocol_icmp_v6_ndp_message_is_solicited_node(umilib_protocol_ip_IPv6Address address);

/**
 * Checks that the message of `header` and the `length` bytes at `body`, carried by the packet of
 * `packet`, is a valid Router Solicitation (RFC 4861 §6.1.1); its options are its body. Fails
 * with Invalid.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_router_solicitation_decode(umilib_protocol_icmp_ICMPHeader header, const uint8_t* body, size_t length, const umilib_protocol_ip_v6_IPv6Header* packet);

/**
 * Writes the Router Solicitation of the `length` bytes of options at `options`, from `source`
 * to `destination`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_router_solicitation_encode(const uint8_t* options, size_t length, umilib_protocol_ip_IPv6Address source, umilib_protocol_ip_IPv6Address destination, umilib_ffi_Buffer* out);

/**
 * Reads the valid Router Advertisement (RFC 4861 §6.1.2) of `header` and the `length` bytes at
 * `body`, carried by the packet of `packet`, into `out` and the offset of its options in the body
 * into `out_offset`; fails with Invalid.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_router_advertisement_decode(umilib_protocol_icmp_ICMPHeader header, const uint8_t* body, size_t length, const umilib_protocol_ip_v6_IPv6Header* packet, umilib_protocol_icmp_v6_NDPRouterAdvertisement* out, size_t* out_offset);

/**
 * Writes the Router Advertisement of `advertisement` and the `length` bytes of options at
 * `options`, from `source` to `destination`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_router_advertisement_encode(const umilib_protocol_icmp_v6_NDPRouterAdvertisement* advertisement, const uint8_t* options, size_t length, umilib_protocol_ip_IPv6Address source, umilib_protocol_ip_IPv6Address destination, umilib_ffi_Buffer* out);

/**
 * Reads the valid Neighbor Solicitation (RFC 4861 §7.1.1) of `header` and the `length` bytes at
 * `body`, carried by the packet of `packet`: its target into `out` and the offset of its options
 * in the body into `out_offset`; fails with Invalid.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_neighbor_solicitation_decode(umilib_protocol_icmp_ICMPHeader header, const uint8_t* body, size_t length, const umilib_protocol_ip_v6_IPv6Header* packet, umilib_protocol_ip_IPv6Address* out, size_t* out_offset);

/**
 * Writes the Neighbor Solicitation for `target` with the `length` bytes of options at `options`,
 * from `source` to `destination`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_neighbor_solicitation_encode(umilib_protocol_ip_IPv6Address target, const uint8_t* options, size_t length, umilib_protocol_ip_IPv6Address source, umilib_protocol_ip_IPv6Address destination, umilib_ffi_Buffer* out);

/**
 * Reads the valid Neighbor Advertisement (RFC 4861 §7.1.2) of `header` and the `length` bytes at
 * `body`, carried by the packet of `packet`, into `out` and the offset of its options in the body
 * into `out_offset`; fails with Invalid.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_neighbor_advertisement_decode(umilib_protocol_icmp_ICMPHeader header, const uint8_t* body, size_t length, const umilib_protocol_ip_v6_IPv6Header* packet, umilib_protocol_icmp_v6_NDPNeighborAdvertisement* out, size_t* out_offset);

/**
 * Writes the Neighbor Advertisement of `advertisement` and the `length` bytes of options at
 * `options`, from `source` to `destination`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_neighbor_advertisement_encode(const umilib_protocol_icmp_v6_NDPNeighborAdvertisement* advertisement, const uint8_t* options, size_t length, umilib_protocol_ip_IPv6Address source, umilib_protocol_ip_IPv6Address destination, umilib_ffi_Buffer* out);

/**
 * Reads the Redirect (RFC 4861 §8.1, but for its first hop) of `header` and the `length` bytes at
 * `body`, carried by the packet of `packet`: its target and destination into `out_target` and
 * `out_destination` and the offset of its options in the body into `out_offset`; fails with Invalid.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_redirect_decode(umilib_protocol_icmp_ICMPHeader header, const uint8_t* body, size_t length, const umilib_protocol_ip_v6_IPv6Header* packet, umilib_protocol_ip_IPv6Address* out_target, umilib_protocol_ip_IPv6Address* out_destination, size_t* out_offset);

/**
 * Writes the Redirect to `target` for `destination` with the `length` bytes of options at
 * `options`, from `source` to `to`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_redirect_encode(umilib_protocol_ip_IPv6Address target, umilib_protocol_ip_IPv6Address destination, const uint8_t* options, size_t length, umilib_protocol_ip_IPv6Address source, umilib_protocol_ip_IPv6Address to, umilib_ffi_Buffer* out);

/**
 * Writes whether the `length` bytes of options at `options` have an option at `index` into
 * `out_found`, its type into `out_kind` and its data into `out`; fails with Invalid for an
 * option of length zero before it.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_options_get(const uint8_t* options, size_t length, size_t index, bool* out_found, uint8_t* out_kind, umilib_ffi_Buffer* out);

/**
 * Writes an option of `kind` with the `length` bytes of data at `data`, padded to 8 bytes, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_option_encode(uint8_t kind, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes whether the option of `kind` and the `length` bytes of data at `data` is an MTU option
 * into `out_found` and its MTU into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_option_mtu(uint8_t kind, const uint8_t* data, size_t length, bool* out_found, uint32_t* out);

/**
 * Checks the prefix length, the lifetimes and the flags of `information`; fails with Invalid.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_prefix_information_check(umilib_protocol_icmp_v6_NDPPrefixInformation information);

/**
 * Reads the Prefix Information option of the `length` bytes of data at `data` into `out`; fails with Invalid.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_prefix_information_decode(const uint8_t* data, size_t length, umilib_protocol_icmp_v6_NDPPrefixInformation* out);

/**
 * Writes the Prefix Information option of `information` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_prefix_information_encode(umilib_protocol_icmp_v6_NDPPrefixInformation information, umilib_ffi_Buffer* out);

/**
 * Reads the Route Information option of the `length` bytes of data at `data` into `out`; fails with Invalid.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_route_information_decode(const uint8_t* data, size_t length, umilib_protocol_icmp_v6_NDPRouteInformation* out);

/**
 * Writes the Route Information option of `information` into `out`; fails with Invalid for a
 * prefix length beyond 128.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_route_information_encode(umilib_protocol_icmp_v6_NDPRouteInformation information, umilib_ffi_Buffer* out);

/**
 * Reads the Recursive DNS Server option of the `length` bytes of data at `data`: its lifetime
 * into `out_lifetime` and its addresses, 16 bytes each, into `out`; fails with Invalid.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_recursive_dns_servers_decode(const uint8_t* data, size_t length, uint32_t* out_lifetime, umilib_ffi_Buffer* out);

/**
 * Writes the Recursive DNS Server option of `lifetime` and the `length` bytes of addresses at
 * `addresses` into `out`; fails with Invalid unless there is at least one whole address.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_ndp_recursive_dns_servers_encode(uint32_t lifetime, const uint8_t* addresses, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the default parameters of a neighbor cache (RFC 4861 §10) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_config_default(umilib_protocol_icmp_v6_NeighborConfig* out);

/**
 * Writes a neighbor cache with the parameters `config` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_cache_new(umilib_protocol_icmp_v6_NeighborConfig config, umilib_protocol_icmp_v6_NeighborCache** out);

/**
 * Releases a neighbor cache. Does nothing if `cache` is null.
 */
void umilib_protocol_icmp_v6_neighbor_cache_free(umilib_protocol_icmp_v6_NeighborCache* cache);

/**
 * Resolves `address` at `now`, keeping the `length` bytes at `packet` (none if `packet` is null):
 * writes 0 (resolved), 1 (send a multicast solicitation now) or 2 (pending) into `out_kind` and,
 * for 0, the 6 bytes of the link-layer address into `out`; fails with Limit.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_cache_resolve(umilib_protocol_icmp_v6_NeighborCache* cache, umilib_protocol_ip_IPv6Address address, const uint8_t* packet, size_t length, uint64_t now, uint8_t* out_kind, uint8_t* out);

/**
 * Writes whether `address` is resolved into `out_found`, its state into `out_state` and its 6
 * bytes of link-layer address into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_cache_lookup(const umilib_protocol_icmp_v6_NeighborCache* cache, umilib_protocol_ip_IPv6Address address, bool* out_found, uint8_t* out_state, uint8_t* out);

/**
 * A confirmation from an upper layer that `address` is reachable at `now`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_cache_confirm(umilib_protocol_icmp_v6_NeighborCache* cache, umilib_protocol_ip_IPv6Address address, uint64_t now);

/**
 * Processes the valid Neighbor Advertisement of `advertisement` and the `length` bytes of options
 * at `options`, received at `now`, and writes the packets now resolved into `out` and whether
 * the target stopped being a router into `out_no_longer_router`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_cache_receive_advertisement(umilib_protocol_icmp_v6_NeighborCache* cache, const umilib_protocol_icmp_v6_NDPNeighborAdvertisement* advertisement, const uint8_t* options, size_t length, uint64_t now, umilib_protocol_icmp_v6_NeighborPackets** out, bool* out_no_longer_router);

/**
 * Learns what a message received at `now` says of `address`: the 6 bytes of link-layer address
 * at `link` (none if `link` is null), and that the sender is a router (`router` 2), a host (1)
 * or nothing (0). Writes the packets now resolved into `out` and whether the neighbor stopped
 * being a router into `out_no_longer_router`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_cache_learn(umilib_protocol_icmp_v6_NeighborCache* cache, umilib_protocol_ip_IPv6Address address, const uint8_t* link, uint8_t router, uint64_t now, umilib_protocol_icmp_v6_NeighborPackets** out, bool* out_no_longer_router);

/**
 * Forgets `address` and writes whether it was known into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_cache_remove(umilib_protocol_icmp_v6_NeighborCache* cache, umilib_protocol_ip_IPv6Address address, bool* out);

/**
 * Writes whether the cache has something to do into `out_found` and when into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_cache_poll_timeout(const umilib_protocol_icmp_v6_NeighborCache* cache, bool* out_found, uint64_t* out);

/**
 * Advances the cache to `now` and writes whether something is due into `out_found` and what into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_cache_poll(umilib_protocol_icmp_v6_NeighborCache* cache, uint64_t now, bool* out_found, umilib_protocol_icmp_v6_NeighborEvent** out);

/**
 * Releases packets. Does nothing if `packets` is null.
 */
void umilib_protocol_icmp_v6_neighbor_packets_free(umilib_protocol_icmp_v6_NeighborPackets* packets);

/**
 * Writes the number of packets into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_packets_count(const umilib_protocol_icmp_v6_NeighborPackets* packets, size_t* out);

/**
 * Writes a copy of the packet at `index` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_packets_get(const umilib_protocol_icmp_v6_NeighborPackets* packets, size_t index, umilib_ffi_Buffer* out);

/**
 * Releases an event. Does nothing if `event` is null.
 */
void umilib_protocol_icmp_v6_neighbor_event_free(umilib_protocol_icmp_v6_NeighborEvent* event);

/**
 * Writes the kind of the event (1: solicit, 2: unreachable) into `out_kind`, its target into
 * `out_target`, whether the solicitation is unicast into `out_unicast` and the 6 bytes of its
 * link-layer address into `out_link`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_event_target(const umilib_protocol_icmp_v6_NeighborEvent* event, uint8_t* out_kind, umilib_protocol_ip_IPv6Address* out_target, bool* out_unicast, uint8_t* out_link);

/**
 * Writes a handle of the packets dropped with an unreachable neighbor into `out`.
 */
const umilib_ffi_Status* umilib_protocol_icmp_v6_neighbor_event_packets(const umilib_protocol_icmp_v6_NeighborEvent* event, umilib_protocol_icmp_v6_NeighborPackets** out);

#ifdef __cplusplus
}
#endif

#endif
