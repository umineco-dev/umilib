/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_DHCP_V6_H
#define UMILIB_PROTOCOL_DHCP_V6_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The header of a DHCPv6 message (RFC 9915 §8); the options are beside it.
 */
typedef struct umilib_protocol_dhcp_v6_DHCPv6Message {
    uint8_t kind;
    uint32_t transaction;
} umilib_protocol_dhcp_v6_DHCPv6Message;

/**
 * The header of a DHCPv6 relay agent's message (RFC 9915 §9); the options are beside it.
 */
typedef struct umilib_protocol_dhcp_v6_DHCPv6RelayMessage {
    uint8_t kind;
    uint8_t hops;
    umilib_protocol_ip_IPv6Address link;
    umilib_protocol_ip_IPv6Address peer;
} umilib_protocol_dhcp_v6_DHCPv6RelayMessage;

/**
 * An Identity Association: kind 3 IA_NA (RFC 9915 §21.4) or 25 IA_PD (§21.21); T1 and T2 in
 * seconds; the options are beside it.
 */
typedef struct umilib_protocol_dhcp_v6_DHCPv6IA {
    uint16_t kind;
    uint32_t iaid;
    uint32_t t1;
    uint32_t t2;
} umilib_protocol_dhcp_v6_DHCPv6IA;

/**
 * An IA Address option (RFC 9915 §21.6), lifetimes in seconds; the options are beside it.
 */
typedef struct umilib_protocol_dhcp_v6_DHCPv6IAAddress {
    umilib_protocol_ip_IPv6Address address;
    uint32_t preferred;
    uint32_t valid;
} umilib_protocol_dhcp_v6_DHCPv6IAAddress;

/**
 * An IA Prefix option (RFC 9915 §21.22), lifetimes in seconds; the options are beside it.
 */
typedef struct umilib_protocol_dhcp_v6_DHCPv6IAPrefix {
    uint32_t preferred;
    uint32_t valid;
    uint8_t length;
    umilib_protocol_ip_IPv6Address prefix;
} umilib_protocol_dhcp_v6_DHCPv6IAPrefix;

/**
 * How a DHCPv6 client asks, but its DUID and option codes: for a prefix if prefix, of
 * prefix_length bits if prefix_hint.
 */
typedef struct umilib_protocol_dhcp_v6_DHCPv6ClientConfig {
    uint32_t iaid;
    bool addresses;
    bool prefix;
    bool prefix_hint;
    uint8_t prefix_length;
    bool rapid_commit;
} umilib_protocol_dhcp_v6_DHCPv6ClientConfig;

/**
 * The bindings of a DHCPv6 client: acquired in nanoseconds, durations in milliseconds
 * (UINT64_MAX for infinity).
 */
typedef struct umilib_protocol_dhcp_v6_DHCPv6Lease {
    uint64_t acquired;
    uint64_t renewal;
    uint64_t rebinding;
    uint64_t valid;
} umilib_protocol_dhcp_v6_DHCPv6Lease;

/**
 * What a DHCPv6 client tells: kind 0 Bound (with its lease), 1 Expired, 2 Informed, 3 Released,
 * 4 Unanswered.
 */
typedef struct umilib_protocol_dhcp_v6_DHCPv6ClientEvent {
    uint8_t kind;
    umilib_protocol_dhcp_v6_DHCPv6Lease lease;
} umilib_protocol_dhcp_v6_DHCPv6ClientEvent;

/**
 * A DHCPv6 client without I/O (RFC 9915 §18.2).
 */
typedef struct umilib_protocol_dhcp_v6_DHCPv6Client umilib_protocol_dhcp_v6_DHCPv6Client;

/**
 * What a DHCPv6 server leases and delegates, but its DUID and options: lifetimes, T1 and T2
 * in seconds (0xFFFFFFFF for infinity; T1 and T2 of 0 let the client choose).
 */
typedef struct umilib_protocol_dhcp_v6_DHCPv6ServerConfig {
    umilib_protocol_ip_IPv6Address first;
    umilib_protocol_ip_IPv6Address last;
    umilib_protocol_ip_IPv6Address prefix;
    bool addresses;
    bool prefixes;
    uint8_t prefix_length;
    uint8_t delegated_length;
    uint8_t preference;
    bool rapid_commit;
    uint32_t preferred;
    uint32_t valid;
    uint32_t t1;
    uint32_t t2;
} umilib_protocol_dhcp_v6_DHCPv6ServerConfig;

/**
 * An address or a prefix a DHCPv6 server gave to an IA (kind its option code); until
 * expires (nanoseconds, UINT64_MAX for never).
 */
typedef struct umilib_protocol_dhcp_v6_DHCPv6Binding {
    umilib_protocol_ip_IPv6Address address;
    uint32_t iaid;
    uint16_t kind;
    uint8_t length;
    bool has_length;
    bool declined;
    uint64_t expires;
} umilib_protocol_dhcp_v6_DHCPv6Binding;

/**
 * A DHCPv6 server without I/O (RFC 9915 §18.3) and its bindings.
 */
typedef struct umilib_protocol_dhcp_v6_DHCPv6Server umilib_protocol_dhcp_v6_DHCPv6Server;

/**
 * Reads the message of the `length` bytes at `bytes` (RFC 9915 §8) into `out` and its options into
 * `out_options`; fails with Malformed for one shorter than 4 bytes, of a relay agent's type, or
 * with an option cut short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_message_decode(const uint8_t* bytes, size_t length, umilib_protocol_dhcp_v6_DHCPv6Message* out, umilib_ffi_Buffer* out_options);

/**
 * Writes the message of `message` and the options of `length` bytes at `options` into `out`; fails
 * with Malformed for a relay agent's type, a transaction ID of more than 24 bits or an option cut
 * short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_message_encode(umilib_protocol_dhcp_v6_DHCPv6Message message, const uint8_t* options, size_t length, umilib_ffi_Buffer* out);

/**
 * Reads the relay agent's message of the `length` bytes at `bytes` (RFC 9915 §9) into `out` and
 * its options, the relayed message in its Relay Message option (§21.10), into `out_options`;
 * fails with Malformed for one shorter than 34 bytes, of a type of no relay agent, or with an
 * option cut short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_relay_message_decode(const uint8_t* bytes, size_t length, umilib_protocol_dhcp_v6_DHCPv6RelayMessage* out, umilib_ffi_Buffer* out_options);

/**
 * Writes the relay agent's message of the header at `message` and the options of `length` bytes
 * at `options` into `out`; fails with Malformed for a type of no relay agent or an option cut short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_relay_message_encode(const umilib_protocol_dhcp_v6_DHCPv6RelayMessage* message, const uint8_t* options, size_t length, umilib_ffi_Buffer* out);

/**
 * Reads the IA of the option `kind` (3 IA_NA, §21.4; 25 IA_PD, §21.21) whose data are the `length`
 * bytes at `data` into `out` and its options into `out_options`; fails with Malformed for data
 * shorter than 12 bytes or an option cut short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_ia_decode(uint16_t kind, const uint8_t* data, size_t length, umilib_protocol_dhcp_v6_DHCPv6IA* out, umilib_ffi_Buffer* out_options);

/**
 * Writes the data of the option of the IA `ia` and the options of `length` bytes at `options`
 * into `out`; fails with Malformed for an option cut short and with TooLarge.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_ia_encode(umilib_protocol_dhcp_v6_DHCPv6IA ia, const uint8_t* options, size_t length, umilib_ffi_Buffer* out);

/**
 * Reads the IA Address option (RFC 9915 §21.6) whose data are the `length` bytes at `data` into
 * `out` and its options into `out_options`; fails with Malformed for data shorter than 24 bytes or
 * an option cut short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_ia_address_decode(const uint8_t* data, size_t length, umilib_protocol_dhcp_v6_DHCPv6IAAddress* out, umilib_ffi_Buffer* out_options);

/**
 * Writes the data of the IA Address option of `address` and the options of `length` bytes at
 * `options` into `out`; fails with Malformed for an option cut short and with TooLarge.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_ia_address_encode(umilib_protocol_dhcp_v6_DHCPv6IAAddress address, const uint8_t* options, size_t length, umilib_ffi_Buffer* out);

/**
 * Reads the IA Prefix option (RFC 9915 §21.22) whose data are the `length` bytes at `data` into
 * `out` and its options into `out_options`; fails with Malformed for data shorter than 25 bytes, a
 * prefix longer than 128 bits, or an option cut short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_ia_prefix_decode(const uint8_t* data, size_t length, umilib_protocol_dhcp_v6_DHCPv6IAPrefix* out, umilib_ffi_Buffer* out_options);

/**
 * Writes the data of the IA Prefix option of `prefix` and the options of `length` bytes at
 * `options` into `out`; fails with Malformed for a prefix longer than 128 bits or an option cut
 * short, and with TooLarge.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_ia_prefix_encode(umilib_protocol_dhcp_v6_DHCPv6IAPrefix prefix, const uint8_t* options, size_t length, umilib_ffi_Buffer* out);

/**
 * Reads the Status Code option (RFC 9915 §21.13) whose data are the `length` bytes at `data`: its
 * code into `out_code` and its UTF-8 message, text not UTF-8 replaced, into `out_message`; fails
 * with Malformed for data shorter than 2 bytes.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_status_code_decode(const uint8_t* data, size_t length, uint16_t* out_code, umilib_ffi_Buffer* out_message);

/**
 * Writes the data of the Status Code option of `code` and the UTF-8 message of `length` bytes at
 * `message` into `out`; fails with InvalidUTF8.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_status_code_encode(uint16_t code, const uint8_t* message, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes a client of the configuration at `config` into `out`: of the DUID of `duid_length` bytes
 * at `duid`, asking for the `count` option codes at `requested` (RFC 9915 §21.7); `now` is in
 * nanoseconds. Fails with Malformed for a DUID that umilib_protocol_dhcp_dhcp_duid_decode refuses.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_client_new(const umilib_protocol_dhcp_v6_DHCPv6ClientConfig* config, const uint8_t* duid, size_t duid_length, const uint16_t* requested, size_t count, uint64_t now, umilib_protocol_dhcp_v6_DHCPv6Client** out);

/**
 * Releases a client. Does nothing if `client` is null.
 */
void umilib_protocol_dhcp_v6_dhcpv6_client_free(umilib_protocol_dhcp_v6_DHCPv6Client* client);

/**
 * Starts the client at `now`: a Solicit for addresses or prefixes, or, asking for neither, an
 * Information-request (RFC 9915 §18.2.6), the first after a random delay of up to a second; its
 * transaction ID and delays are drawn from `random`. Fails with Random if `random` fails.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_client_start(umilib_protocol_dhcp_v6_DHCPv6Client* client, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Takes the server's message of `length` bytes at `bytes`, received at `now`; one not of the
 * exchange's transaction, with the client's DUID and a server's (RFC 9915 §16), is ignored, as is
 * a Reconfigure (§18.2.11). A new exchange draws from `random`.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_client_receive(umilib_protocol_dhcp_v6_DHCPv6Client* client, const uint8_t* bytes, size_t length, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Writes whether a message is due into `out_found` and its bytes into `out`; it goes to
 * All_DHCP_Relay_Agents_and_Servers, port 547. Fails with TooLarge for an option too long to write.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_client_transmit(umilib_protocol_dhcp_v6_DHCPv6Client* client, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes whether a timer is set into `out_found` and when umilib_protocol_dhcp_v6_dhcpv6_client_expire
 * is due (nanoseconds) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_client_poll_timeout(const umilib_protocol_dhcp_v6_DHCPv6Client* client, bool* out_found, uint64_t* out);

/**
 * Does what is due at `now`: a delayed first message, a retransmission or the end of an exchange
 * (RFC 9915 §15), Renew at T1, Rebind at T2, the end of the lease, or a refresh of stateless
 * configuration (§18.2.12); drawing from `random`.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_client_expire(umilib_protocol_dhcp_v6_DHCPv6Client* client, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Writes whether an event is pending into `out_found` and the event into `out`; of a Bound event,
 * the options of its IAs into `out_ias`, of its Reply into `out_options` and its server's DUID
 * into `out_server`; of an Informed event, its options into `out_options`. The buffers of what an
 * event has not are empty.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_client_poll_event(umilib_protocol_dhcp_v6_DHCPv6Client* client, bool* out_found, umilib_protocol_dhcp_v6_DHCPv6ClientEvent* out, umilib_ffi_Buffer* out_ias, umilib_ffi_Buffer* out_options, umilib_ffi_Buffer* out_server);

/**
 * Writes the number of the client's state into `out`: 0 Init, 1 Soliciting, 2 Requesting, 3
 * Bound, 4 Renewing, 5 Rebinding, 6 Confirming, 7 Releasing, 8 Declining, 9 Informing, 10 Informed.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_client_state(const umilib_protocol_dhcp_v6_DHCPv6Client* client, uint8_t* out);

/**
 * Writes whether the client holds a lease into `out_found`, the lease into `out`, the options of
 * its IAs into `out_ias`, of its Reply into `out_options` and its server's DUID into `out_server`.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_client_lease(const umilib_protocol_dhcp_v6_DHCPv6Client* client, bool* out_found, umilib_protocol_dhcp_v6_DHCPv6Lease* out, umilib_ffi_Buffer* out_ias, umilib_ffi_Buffer* out_options, umilib_ffi_Buffer* out_server);

/**
 * Releases the lease (RFC 9915 §18.2.7), in an exchange whose transaction ID is drawn from
 * `random`; the client stops. Fails with State without a lease, and with Random if `random` fails.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_client_release(umilib_protocol_dhcp_v6_DHCPv6Client* client, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Declines the `count` addresses at `addresses` of the lease, which DAD found in use (RFC 9915
 * §18.2.8), drawing from `random`. Fails with State without a lease or without addresses, and
 * with Random if `random` fails.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_client_decline(umilib_protocol_dhcp_v6_DHCPv6Client* client, const umilib_protocol_ip_IPv6Address* addresses, size_t count, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Confirms the lease after the link may have changed (RFC 9915 §18.2.3), after a random delay of
 * up to a second drawn from `random`. Fails with State without a lease, and with Random if
 * `random` fails.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_client_confirm(umilib_protocol_dhcp_v6_DHCPv6Client* client, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Writes the configuration of a server that leases nothing yet into `out`: lifetimes of a day
 * preferred and two valid, T1 and T2 of 0 (derived, RFC 9915 §21.4), preference 0, no Rapid Commit.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_server_config_new(umilib_protocol_dhcp_v6_DHCPv6ServerConfig* out);

/**
 * Writes a server of the configuration at `config` into `out`: of the DUID of `duid_length` bytes
 * at `duid`, giving the options of `length` bytes at `options`, each to a client that asks for it
 * (RFC 9915 §18.3.9). Fails with Malformed for a DUID that umilib_protocol_dhcp_dhcp_duid_decode
 * refuses or an option cut short, and with Config for a pool whose first address is after its
 * last, or prefixes longer than their delegated length, longer than 128 bits or more than 2^32.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_server_new(const umilib_protocol_dhcp_v6_DHCPv6ServerConfig* config, const uint8_t* duid, size_t duid_length, const uint8_t* options, size_t length, umilib_protocol_dhcp_v6_DHCPv6Server** out);

/**
 * Releases a server. Does nothing if `server` is null.
 */
void umilib_protocol_dhcp_v6_dhcpv6_server_free(umilib_protocol_dhcp_v6_DHCPv6Server* server);

/**
 * Takes the message of `length` bytes at `bytes`, a client's or a Relay-forward, received at `now`
 * (nanoseconds); writes whether a reply is due into `out_found` and its bytes into `out`: to a
 * Relay-forward, a Relay-reply of the same addresses and Interface-Id (RFC 9915 §19.3).
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_server_receive(umilib_protocol_dhcp_v6_DHCPv6Server* server, const uint8_t* bytes, size_t length, uint64_t now, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Forgets the bindings expired at `now`, but the declined addresses.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_server_expire(umilib_protocol_dhcp_v6_DHCPv6Server* server, uint64_t now);

/**
 * Writes how many bindings the server has into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_server_bindings_count(const umilib_protocol_dhcp_v6_DHCPv6Server* server, size_t* out);

/**
 * Writes the binding of `index`, in the order of addresses, into `out` and the key of its client
 * into `out_client`; fails with InvalidArgument for an index past the last.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_server_binding_entry(const umilib_protocol_dhcp_v6_DHCPv6Server* server, size_t index, umilib_protocol_dhcp_v6_DHCPv6Binding* out, umilib_ffi_Buffer* out_client);

/**
 * Sets the binding of its address (and prefix length) to `binding`, of the client of the key of
 * the `length` bytes at `client`: a binding kept elsewhere, given back.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_server_set_binding(umilib_protocol_dhcp_v6_DHCPv6Server* server, umilib_protocol_dhcp_v6_DHCPv6Binding binding, const uint8_t* client, size_t length);

/**
 * Removes the binding of `address` (and of `length` if `has_length`), if any.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v6_dhcpv6_server_remove_binding(umilib_protocol_dhcp_v6_DHCPv6Server* server, umilib_protocol_ip_IPv6Address address, uint8_t length, bool has_length);

#ifdef __cplusplus
}
#endif

#endif
