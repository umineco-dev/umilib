/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_DHCP_V4_H
#define UMILIB_PROTOCOL_DHCP_V4_H

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
 * The header of a DHCPv4 message (RFC 2131 §2), its fields as they are; the options are beside it.
 */
typedef struct umilib_protocol_dhcp_v4_DHCPv4Message {
    uint8_t op;
    uint8_t hardware_type;
    uint8_t hardware_length;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    umilib_protocol_ip_IPv4Address ciaddr;
    umilib_protocol_ip_IPv4Address yiaddr;
    umilib_protocol_ip_IPv4Address siaddr;
    umilib_protocol_ip_IPv4Address giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
} umilib_protocol_dhcp_v4_DHCPv4Message;

/**
 * A route of the classless static route option (RFC 3442 §2).
 */
typedef struct umilib_protocol_dhcp_v4_DHCPv4Route {
    umilib_protocol_ip_IPv4Address destination;
    uint8_t prefix;
    umilib_protocol_ip_IPv4Address router;
} umilib_protocol_dhcp_v4_DHCPv4Route;

/**
 * How a DHCPv4 client asks, but its client identifier, host name and option codes.
 */
typedef struct umilib_protocol_dhcp_v4_DHCPv4ClientConfig {
    umilib_protocol_ethernet_MACAddress hardware;
    bool broadcast;
    bool ipv6_only;
    uint16_t maximum_message_size;
    size_t retransmissions;
} umilib_protocol_dhcp_v4_DHCPv4ClientConfig;

/**
 * An address leased: durations in milliseconds (UINT64_MAX for infinity), acquired in nanoseconds.
 */
typedef struct umilib_protocol_dhcp_v4_DHCPv4Lease {
    umilib_protocol_ip_IPv4Address address;
    umilib_protocol_ip_IPv4Address server;
    uint64_t lease;
    uint64_t renewal;
    uint64_t rebinding;
    uint64_t acquired;
} umilib_protocol_dhcp_v4_DHCPv4Lease;

/**
 * What a DHCPv4 client tells: kind 0 Bound (with its lease), 1 Refused, 2 Expired, 3 Unanswered,
 * 4 IPv6Only (for wait milliseconds).
 */
typedef struct umilib_protocol_dhcp_v4_DHCPv4ClientEvent {
    uint8_t kind;
    umilib_protocol_dhcp_v4_DHCPv4Lease lease;
    uint64_t wait;
} umilib_protocol_dhcp_v4_DHCPv4ClientEvent;

/**
 * A DHCPv4 client without I/O (RFC 2131 §4.4).
 */
typedef struct umilib_protocol_dhcp_v4_DHCPv4Client umilib_protocol_dhcp_v4_DHCPv4Client;

/**
 * What a DHCPv4 server leases, but its reservations and options: durations in milliseconds,
 * a lease of UINT64_MAX for ever.
 */
typedef struct umilib_protocol_dhcp_v4_DHCPv4ServerConfig {
    umilib_protocol_ip_IPv4Address address;
    umilib_protocol_ip_IPv4Address first;
    umilib_protocol_ip_IPv4Address last;
    bool authoritative;
    uint64_t lease;
    uint64_t offer_time;
    uint64_t decline_time;
} umilib_protocol_dhcp_v4_DHCPv4ServerConfig;

/**
 * Where a DHCPv4 server's reply goes: to link without ARP if has_link (RFC 2131 §4.1).
 */
typedef struct umilib_protocol_dhcp_v4_DHCPv4Reply {
    umilib_protocol_ip_IPv4Address destination;
    uint16_t port;
    umilib_protocol_ethernet_MACAddress link;
    bool has_link;
} umilib_protocol_dhcp_v4_DHCPv4Reply;

/**
 * An address a DHCPv4 server gave: state 0 Offered, 1 Bound, 2 Declined; until expires
 * (nanoseconds, UINT64_MAX for never).
 */
typedef struct umilib_protocol_dhcp_v4_DHCPv4Binding {
    uint8_t state;
    uint64_t expires;
} umilib_protocol_dhcp_v4_DHCPv4Binding;

/**
 * A DHCPv4 server without I/O (RFC 2131 §4.3) and its bindings.
 */
typedef struct umilib_protocol_dhcp_v4_DHCPv4Server umilib_protocol_dhcp_v4_DHCPv4Server;

/**
 * Reads the message of the `length` bytes at `bytes` (RFC 2131 §2) into `out` and its options area
 * into `out_options`: the options of the options field, then, as the overload option says, of
 * `file` and of `sname`, which are then zero (RFC 2131 §4.1); the overload option itself is not
 * kept. Fails with Malformed for a message shorter than 240 bytes, without the magic cookie, of
 * an op other than 1 and 2, or with an option cut short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_message_decode(const uint8_t* bytes, size_t length, umilib_protocol_dhcp_v4_DHCPv4Message* out, umilib_ffi_Buffer* out_options);

/**
 * Writes the message of the header at `message` and the options area of `length` bytes at
 * `options` into `out`: the options after the magic cookie, each once, then END, padded to at
 * least 300 bytes (RFC 1542 §2.1). Fails with Malformed for an option cut short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_message_encode(const umilib_protocol_dhcp_v4_DHCPv4Message* message, const uint8_t* options, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the key a server knows the client of the message at `message` and the options area at
 * `options` by into `out`: its client identifier, or 0, its hardware type and its hardware
 * address (RFC 2131 §4.2, RFC 4361 §6.1). Fails with Malformed for an option cut short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_message_client_key(const umilib_protocol_dhcp_v4_DHCPv4Message* message, const uint8_t* options, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the options of the options area of `length` bytes at `area` (RFC 2132 §2) as an options
 * area of this module into `out`: PAD dropped, the parts of an option given in several joined
 * (RFC 3396 §7). Fails with Malformed for an option cut short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_options_decode(const uint8_t* area, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the routes of the classless static route option (RFC 3442 §2) of the options area of
 * `length` bytes at `area` into the `capacity` structures at `out`, and their number into
 * `out_count`; there are at most `length / 5`. Fails with Malformed for an option cut short or a
 * route of a prefix longer than 32, and with InvalidArgument if `capacity` is less than their number.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_options_routes(const uint8_t* area, size_t length, umilib_protocol_dhcp_v4_DHCPv4Route* out, size_t capacity, size_t* out_count);

/**
 * Writes the options area of `length` bytes at `area` with its classless static route option set
 * to the `count` routes at `routes` (RFC 3442 §2: the bits of a destination beyond its prefix are
 * not sent) into `out`. Fails with Malformed for an option cut short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_options_set_routes(const uint8_t* area, size_t length, const umilib_protocol_dhcp_v4_DHCPv4Route* routes, size_t count, umilib_ffi_Buffer* out);

/**
 * Writes a client of the configuration at `config` into `out`: known by the client identifier of
 * `client_identifier_length` bytes at `client_identifier` (option 61; by its hardware address if
 * null), naming itself by the host name at `host_name` (none if null), asking for the `count`
 * option codes at `parameters` (RFC 2132 §9.8); `now` is in nanoseconds.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_client_new(const umilib_protocol_dhcp_v4_DHCPv4ClientConfig* config, const uint8_t* client_identifier, size_t client_identifier_length, const uint8_t* host_name, size_t host_name_length, const uint8_t* parameters, size_t count, uint64_t now, umilib_protocol_dhcp_v4_DHCPv4Client** out);

/**
 * Releases a client. Does nothing if `client` is null.
 */
void umilib_protocol_dhcp_v4_dhcpv4_client_free(umilib_protocol_dhcp_v4_DHCPv4Client* client);

/**
 * Starts the client at `now`: asking again for the address at `previous` it had (INIT-REBOOT,
 * RFC 2131 §3.2), or discovering servers if `previous` is null; its xid and the jitter of its
 * retransmission are drawn from `random`. Fails with Random if `random` fails.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_client_start(umilib_protocol_dhcp_v4_DHCPv4Client* client, const umilib_protocol_ip_IPv4Address* previous, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Takes the server's message of `length` bytes at `bytes`, received at `now`; one that is not a
 * reply to the client's exchange, of its hardware address and client identifier (RFC 6842 §3),
 * of a type its state expects, is ignored. A new exchange draws from `random`.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_client_receive(umilib_protocol_dhcp_v4_DHCPv4Client* client, const uint8_t* bytes, size_t length, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Writes whether a message is due into `out_found`, its destination (255.255.255.255 to
 * broadcast) into `out_destination` and its bytes into `out`; it goes to port 67.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_client_transmit(umilib_protocol_dhcp_v4_DHCPv4Client* client, bool* out_found, umilib_protocol_ip_IPv4Address* out_destination, umilib_ffi_Buffer* out);

/**
 * Writes whether a timer is set into `out_found` and when umilib_protocol_dhcp_v4_dhcpv4_client_expire
 * is due (nanoseconds) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_client_poll_timeout(const umilib_protocol_dhcp_v4_DHCPv4Client* client, bool* out_found, uint64_t* out);

/**
 * Does what is due at `now`: a retransmission, giving up an exchange, or the next step of the
 * lease — RENEWING at T1, REBINDING at T2, and its end (RFC 2131 §4.4.5); drawing from `random`.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_client_expire(umilib_protocol_dhcp_v4_DHCPv4Client* client, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Writes whether an event is pending into `out_found`, the event into `out`, and the options area
 * of the ACK of a Bound event (empty for another) into `out_options`.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_client_poll_event(umilib_protocol_dhcp_v4_DHCPv4Client* client, bool* out_found, umilib_protocol_dhcp_v4_DHCPv4ClientEvent* out, umilib_ffi_Buffer* out_options);

/**
 * Writes the number of the client's state into `out`: 0 Init, 1 Selecting, 2 Requesting, 3
 * Rebooting, 4 Bound, 5 Renewing, 6 Rebinding (RFC 2131 §4.4, figure 5).
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_client_state(const umilib_protocol_dhcp_v4_DHCPv4Client* client, uint8_t* out);

/**
 * Writes whether the client holds a lease into `out_found`, the lease into `out`, and the options
 * area of its ACK into `out_options`.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_client_lease(const umilib_protocol_dhcp_v4_DHCPv4Client* client, bool* out_found, umilib_protocol_dhcp_v4_DHCPv4Lease* out, umilib_ffi_Buffer* out_options);

/**
 * Declines the address of the lease, which another host has (RFC 2131 §4.4.1): a DECLINE, then
 * discovery again after ten seconds (§3.1.5), of an xid from `random`. Fails with State without a
 * lease, and with Random if `random` fails.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_client_decline(umilib_protocol_dhcp_v4_DHCPv4Client* client, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Gives the address back (RFC 2131 §4.4.6): a RELEASE to the server; the client stops. Fails with
 * State without a lease.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_client_release(umilib_protocol_dhcp_v4_DHCPv4Client* client, uint64_t now);

/**
 * Writes the DHCPINFORM of a client whose address `address` is configured otherwise (RFC 2131
 * §3.4), of an xid of its own from `random` and secs 0: its destination into `out_destination`
 * and its bytes into `out`. The client's exchange goes on; the ACK, of that xid, is the caller's
 * to read. Fails with Random if `random` fails.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_client_inform(const umilib_protocol_dhcp_v4_DHCPv4Client* client, umilib_protocol_ip_IPv4Address address, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length, umilib_protocol_ip_IPv4Address* out_destination, umilib_ffi_Buffer* out);

/**
 * Writes the configuration of a server at `address` leasing `first` to `last` into `out`: for a
 * day, an offer kept a minute, a declined address an hour, not authoritative; with no
 * reservations and no options.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_server_config_new(umilib_protocol_ip_IPv4Address address, umilib_protocol_ip_IPv4Address first, umilib_protocol_ip_IPv4Address last, umilib_protocol_dhcp_v4_DHCPv4ServerConfig* out);

/**
 * Writes a server of the configuration at `config` into `out`: with `count` reservations, each
 * the client key of `key_lengths[index]` bytes at `keys[index]` (see
 * umilib_protocol_dhcp_v4_dhcpv4_message_client_key) and the address at `addresses[index]`, and
 * the options area of `length` bytes at `options`, given to every client, those it asks for
 * first. Fails with Config for a pool whose first address is after its last, and with Malformed
 * for an option cut short.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_server_new(const umilib_protocol_dhcp_v4_DHCPv4ServerConfig* config, const uint8_t* const* keys, const size_t* key_lengths, const umilib_protocol_ip_IPv4Address* addresses, size_t count, const uint8_t* options, size_t length, umilib_protocol_dhcp_v4_DHCPv4Server** out);

/**
 * Releases a server. Does nothing if `server` is null.
 */
void umilib_protocol_dhcp_v4_dhcpv4_server_free(umilib_protocol_dhcp_v4_DHCPv4Server* server);

/**
 * Takes the client's message of `length` bytes at `bytes`, received at `now` (nanoseconds); writes
 * whether a reply is due into `out_found`, where it goes into `out_reply` and its bytes into `out`
 * (RFC 2131 §4.3).
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_server_receive(umilib_protocol_dhcp_v4_DHCPv4Server* server, const uint8_t* bytes, size_t length, uint64_t now, bool* out_found, umilib_protocol_dhcp_v4_DHCPv4Reply* out_reply, umilib_ffi_Buffer* out);

/**
 * Forgets the bindings expired at `now`, but the leases bound.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_server_expire(umilib_protocol_dhcp_v4_DHCPv4Server* server, uint64_t now);

/**
 * Writes whether the server has a binding of `address` into `out_found`, the binding into `out`
 * and the key of its client (empty for a declined address) into `out_client`.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_server_binding(const umilib_protocol_dhcp_v4_DHCPv4Server* server, umilib_protocol_ip_IPv4Address address, bool* out_found, umilib_protocol_dhcp_v4_DHCPv4Binding* out, umilib_ffi_Buffer* out_client);

/**
 * Writes how many bindings the server has into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_server_bindings_count(const umilib_protocol_dhcp_v4_DHCPv4Server* server, size_t* out);

/**
 * Writes the binding of `index`, in the order of addresses, into `out_address`, `out` and
 * `out_client`; fails with InvalidArgument for an index past the last.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_server_binding_entry(const umilib_protocol_dhcp_v4_DHCPv4Server* server, size_t index, umilib_protocol_ip_IPv4Address* out_address, umilib_protocol_dhcp_v4_DHCPv4Binding* out, umilib_ffi_Buffer* out_client);

/**
 * Sets the binding of `address` to `binding`, of the client of the key of the `length` bytes at
 * `client`: a binding kept elsewhere, given back (a server's bindings are its caller's to keep).
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_server_set_binding(umilib_protocol_dhcp_v4_DHCPv4Server* server, umilib_protocol_ip_IPv4Address address, umilib_protocol_dhcp_v4_DHCPv4Binding binding, const uint8_t* client, size_t length);

/**
 * Removes the binding of `address`, if any.
 */
const umilib_ffi_Status* umilib_protocol_dhcp_v4_dhcpv4_server_remove_binding(umilib_protocol_dhcp_v4_DHCPv4Server* server, umilib_protocol_ip_IPv4Address address);

#ifdef __cplusplus
}
#endif

#endif
