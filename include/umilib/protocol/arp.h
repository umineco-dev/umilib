/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_ARP_H
#define UMILIB_PROTOCOL_ARP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/ethernet.h"
#include "umilib/protocol/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * An ARP packet (RFC 826) of MAC and IPv4 addresses.
 */
typedef struct umilib_protocol_arp_ARPPacket {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint16_t operation;
    umilib_protocol_ethernet_MACAddress sender_hardware;
    umilib_protocol_ip_IPv4Address sender_protocol;
    umilib_protocol_ethernet_MACAddress target_hardware;
    umilib_protocol_ip_IPv4Address target_protocol;
} umilib_protocol_arp_ARPPacket;

/**
 * The parameters of a cache; durations in nanoseconds.
 */
typedef struct umilib_protocol_arp_ARPConfig {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint64_t timeout;
    uint64_t retransmission_interval;
    uint32_t maximum_requests;
    size_t maximum_entries;
    size_t maximum_queued;
} umilib_protocol_arp_ARPConfig;

/**
 * The translation table of ARP from IPv4 to MAC addresses.
 */
typedef struct umilib_protocol_arp_ARPCache umilib_protocol_arp_ARPCache;

/**
 * What the cache makes of a received packet.
 */
typedef struct umilib_protocol_arp_ARPReception umilib_protocol_arp_ARPReception;

/**
 * A request to send again, or an address that did not answer.
 */
typedef struct umilib_protocol_arp_ARPEvent umilib_protocol_arp_ARPEvent;

/**
 * Reads the packet at the start of the `length` bytes at `bytes` into `out`; fails with Length
 * for address lengths other than 6 and 4.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_packet_decode(const uint8_t* bytes, size_t length, umilib_protocol_arp_ARPPacket* out);

/**
 * Writes the 28 bytes of the packet into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_packet_encode(umilib_protocol_arp_ARPPacket packet, umilib_ffi_Buffer* out);

/**
 * A request on Ethernet for the hardware address of `target` from `sender_hardware` and
 * `sender_protocol` (0.0.0.0 for a probe).
 */
umilib_protocol_arp_ARPPacket umilib_protocol_arp_arp_packet_ethernet_request(umilib_protocol_ethernet_MACAddress sender_hardware, umilib_protocol_ip_IPv4Address sender_protocol, umilib_protocol_ip_IPv4Address target);

/**
 * The reply to the request `packet` from `hardware`, the hardware address of its target.
 */
umilib_protocol_arp_ARPPacket umilib_protocol_arp_arp_packet_reply(umilib_protocol_arp_ARPPacket packet, umilib_protocol_ethernet_MACAddress hardware);

/**
 * Whether `packet` is a probe (RFC 5227 §2.1.1).
 */
bool umilib_protocol_arp_arp_packet_is_probe(umilib_protocol_arp_ARPPacket packet);

/**
 * Whether `packet` is an announcement (RFC 5227 §2.3).
 */
bool umilib_protocol_arp_arp_packet_is_announcement(umilib_protocol_arp_ARPPacket packet);

/**
 * Writes the default parameters of a cache into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_config_default(umilib_protocol_arp_ARPConfig* out);

/**
 * Writes a cache with the parameters `config` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_cache_new(umilib_protocol_arp_ARPConfig config, umilib_protocol_arp_ARPCache** out);

/**
 * Releases a cache. Does nothing if `cache` is null.
 */
void umilib_protocol_arp_arp_cache_free(umilib_protocol_arp_ARPCache* cache);

/**
 * Resolves `address` at `now`, keeping the `length` bytes at `packet` (none if `packet` is
 * null) until the resolution ends: writes 0 (resolved), 1 (send a request now) or 2 (pending)
 * into `out_kind` and the hardware address of 0 into `out`; fails with Limit.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_cache_resolve(umilib_protocol_arp_ARPCache* cache, umilib_protocol_ip_IPv4Address address, const uint8_t* packet, size_t length, uint64_t now, uint8_t* out_kind, umilib_protocol_ethernet_MACAddress* out);

/**
 * Writes whether the hardware address of `address` is known at `now` into `out_found` and it into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_cache_lookup(const umilib_protocol_arp_ARPCache* cache, umilib_protocol_ip_IPv4Address address, uint64_t now, bool* out_found, umilib_protocol_ethernet_MACAddress* out);

/**
 * Sets the hardware address of `address` to `hardware` until it is removed.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_cache_insert_static(umilib_protocol_arp_ARPCache* cache, umilib_protocol_ip_IPv4Address address, umilib_protocol_ethernet_MACAddress hardware);

/**
 * Removes what the cache knows of `address` and writes whether it knew anything into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_cache_remove(umilib_protocol_arp_ARPCache* cache, umilib_protocol_ip_IPv4Address address, bool* out);

/**
 * Processes `packet`, received at `now` on an interface of the hardware address `hardware` and
 * the `count` protocol addresses at `local`, and writes what it makes of it into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_cache_receive(umilib_protocol_arp_ARPCache* cache, umilib_protocol_arp_ARPPacket packet, umilib_protocol_ethernet_MACAddress hardware, const umilib_protocol_ip_IPv4Address* local, size_t count, uint64_t now, umilib_protocol_arp_ARPReception** out);

/**
 * Writes whether the cache has something to do into `out_found` and when into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_cache_poll_timeout(const umilib_protocol_arp_ARPCache* cache, bool* out_found, uint64_t* out);

/**
 * Advances the cache to `now` and writes whether something is due into `out_found` and what into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_cache_poll(umilib_protocol_arp_ARPCache* cache, uint64_t now, bool* out_found, umilib_protocol_arp_ARPEvent** out);

/**
 * Releases a reception. Does nothing if `reception` is null.
 */
void umilib_protocol_arp_arp_reception_free(umilib_protocol_arp_ARPReception* reception);

/**
 * Writes whether there is a reply to send into `out_found` and it into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_reception_reply(const umilib_protocol_arp_ARPReception* reception, bool* out_found, umilib_protocol_arp_ARPPacket* out);

/**
 * Whether the packet claimed a local address from another hardware address.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_reception_conflict(const umilib_protocol_arp_ARPReception* reception, bool* out);

/**
 * Writes the number of packets kept for the sender's address, now resolved, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_reception_resolved_count(const umilib_protocol_arp_ARPReception* reception, size_t* out);

/**
 * Writes a copy of the resolved packet at `index` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_reception_resolved_get(const umilib_protocol_arp_ARPReception* reception, size_t index, umilib_ffi_Buffer* out);

/**
 * Releases an event. Does nothing if `event` is null.
 */
void umilib_protocol_arp_arp_event_free(umilib_protocol_arp_ARPEvent* event);

/**
 * Writes the kind of the event (1: send a request again, 2: unreachable) into `out_kind` and
 * its address into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_event_address(const umilib_protocol_arp_ARPEvent* event, uint8_t* out_kind, umilib_protocol_ip_IPv4Address* out);

/**
 * Writes the number of packets dropped with an unreachable address into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_event_packet_count(const umilib_protocol_arp_ARPEvent* event, size_t* out);

/**
 * Writes a copy of the dropped packet at `index` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_arp_arp_event_packet_get(const umilib_protocol_arp_ARPEvent* event, size_t index, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
