/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_COAP_H
#define UMILIB_PROTOCOL_COAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A Block1 or Block2 option (RFC 7959 §2.2): the block's number, whether more
 * follow, and its size as SZX, 2^(SZX + 4) bytes.
 */
typedef struct umilib_protocol_coap_CoAPBlock {
    uint32_t number;
    bool more;
    uint8_t exponent;
} umilib_protocol_coap_CoAPBlock;

/**
 * The definition of a known CoAP option (RFC 7252 table 4): its format (0 empty,
 * 1 opaque, 2 uint, 3 string), least and greatest length, and whether it may repeat.
 */
typedef struct umilib_protocol_coap_CoAPOptionDefinition {
    uint8_t format;
    size_t least;
    size_t greatest;
    bool repeatable;
} umilib_protocol_coap_CoAPOptionDefinition;

/**
 * The transmission parameters (RFC 7252 §4.8) and the limits of a CoAP endpoint;
 * durations in milliseconds, ACK_RANDOM_FACTOR in thousandths.
 */
typedef struct umilib_protocol_coap_CoAPConfig {
    uint64_t ack_timeout;
    uint32_t ack_random_factor;
    uint32_t max_retransmit;
    size_t nstart;
    uint64_t exchange_lifetime;
    uint64_t non_lifetime;
    uint64_t ack_delay;
    size_t maximum_token;
    size_t maximum_seen;
} umilib_protocol_coap_CoAPConfig;

/**
 * An event of a CoAP endpoint: its kind (0 Request, 1 Response, 2 Timeout,
 * 3 Reset), the handle it names, and the peer of a Request.
 */
typedef struct umilib_protocol_coap_CoAPEvent {
    uint8_t kind;
    uint64_t exchange;
    uint64_t request;
    uint64_t message;
    umilib_protocol_ip_IPEndpoint peer;
} umilib_protocol_coap_CoAPEvent;

/**
 * The options of a CoAP message, in the order of their numbers (RFC 7252 §3.1).
 */
typedef struct umilib_protocol_coap_CoAPOptions umilib_protocol_coap_CoAPOptions;

/**
 * A CoAP message (RFC 7252 §3): type, code, Message ID, token, options and payload.
 */
typedef struct umilib_protocol_coap_CoAPMessage umilib_protocol_coap_CoAPMessage;

/**
 * A CoAP endpoint without I/O, client and server (RFC 7252).
 */
typedef struct umilib_protocol_coap_CoAPEndpoint umilib_protocol_coap_CoAPEndpoint;

/**
 * The observers of a CoAP server's resources (RFC 7641 §4).
 */
typedef struct umilib_protocol_coap_CoAPObservers umilib_protocol_coap_CoAPObservers;

/**
 * The receiver of a body transferred block by block (RFC 7959).
 */
typedef struct umilib_protocol_coap_CoAPBlockwise umilib_protocol_coap_CoAPBlockwise;

/**
 * A link of the CoRE Link Format (RFC 6690 §2): its target and attributes.
 */
typedef struct umilib_protocol_coap_CoAPLink umilib_protocol_coap_CoAPLink;

/**
 * A list of links of the CoRE Link Format.
 */
typedef struct umilib_protocol_coap_CoAPLinks umilib_protocol_coap_CoAPLinks;

/**
 * A rule that routes CoAP requests by their path and, if given, their method.
 */
typedef struct umilib_protocol_coap_CoAPRule umilib_protocol_coap_CoAPRule;

/**
 * Writes whether the option `number` is critical, so that an endpoint that does not know it
 * cannot ignore it (RFC 7252 §5.4.1), into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_option_number_is_critical(uint16_t number, bool* out);

/**
 * Writes whether the option `number` is unsafe to forward by a proxy that does not know it
 * (RFC 7252 §5.4.2) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_option_number_is_unsafe(uint16_t number, bool* out);

/**
 * Writes whether the option `number` is not part of the cache key (RFC 7252 §5.4.2, §5.4.6) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_option_number_is_no_cache_key(uint16_t number, bool* out);

/**
 * Writes the definition of the option `number` into `out` and whether it is a known option into
 * `out_found` (RFC 7252 table 4, RFC 7641 §2, RFC 7959 tables 1 and 2).
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_option_number_definition(uint16_t number, bool* out_found, umilib_protocol_coap_CoAPOptionDefinition* out);

/**
 * Writes an empty set of options into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_new(umilib_protocol_coap_CoAPOptions** out);

/**
 * Writes a copy of the options into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_clone(const umilib_protocol_coap_CoAPOptions* options, umilib_protocol_coap_CoAPOptions** out);

/**
 * Releases a set of options. Does nothing if `options` is null.
 */
void umilib_protocol_coap_coap_options_free(umilib_protocol_coap_CoAPOptions* options);

/**
 * Writes the number of options into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_count(const umilib_protocol_coap_CoAPOptions* options, size_t* out);

/**
 * Writes the number of the option `index`, in the order of the numbers and repeated ones in the
 * order given (RFC 7252 §3.1, §5.4.5), into `out_number` and its value into `out`; fails with
 * InvalidArgument past the end.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_entry(const umilib_protocol_coap_CoAPOptions* options, size_t index, uint16_t* out_number, umilib_ffi_Buffer* out);

/**
 * Adds the option `number` of the `length` bytes at `value` after those of its number and before
 * greater ones.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_push(umilib_protocol_coap_CoAPOptions* options, uint16_t number, const uint8_t* value, size_t length);

/**
 * Sets the one option `number` to the `length` bytes at `value`, replacing those there are.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_set(umilib_protocol_coap_CoAPOptions* options, uint16_t number, const uint8_t* value, size_t length);

/**
 * Removes every option `number`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_remove(umilib_protocol_coap_CoAPOptions* options, uint16_t number);

/**
 * Writes the value of the first option `number` into `out` and whether there is one into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_get(const umilib_protocol_coap_CoAPOptions* options, uint16_t number, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes whether there is an option `number` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_contains(const umilib_protocol_coap_CoAPOptions* options, uint16_t number, bool* out);

/**
 * Writes the uint of the first option `number` (RFC 7252 §3.2) into `out` and whether there is
 * one of at most 4 bytes into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_uint(const umilib_protocol_coap_CoAPOptions* options, uint16_t number, bool* out_found, uint32_t* out);

/**
 * Sets the one option `number` to the uint `value`, without leading zeros (RFC 7252 §3.2).
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_set_uint(umilib_protocol_coap_CoAPOptions* options, uint16_t number, uint32_t value);

/**
 * Writes the bytes of the uint `value`, without leading zeros (RFC 7252 §3.2), into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_uint_bytes(uint32_t value, umilib_ffi_Buffer* out);

/**
 * Writes the uint of the `length` bytes at `bytes` into `out` and whether they are at most 4
 * into `out_found` (RFC 7252 §3.2).
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_uint_of(const uint8_t* bytes, size_t length, bool* out_found, uint32_t* out);

/**
 * Writes whether an option makes the message one to reject (RFC 7252 §5.4.1, §5.4.3, §5.4.5) —
 * a critical option unknown, of a value its definition does not allow, or repeated though it may
 * not be — into `out_found` and the number of the first such into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_check(const umilib_protocol_coap_CoAPOptions* options, bool* out_found, uint16_t* out);

/**
 * Writes the options without the elective ones to ignore — unknown, of a value out of their
 * definition, or repeated beyond the first (RFC 7252 §5.4.1, §5.4.5) — into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_usable(const umilib_protocol_coap_CoAPOptions* options, umilib_protocol_coap_CoAPOptions** out);

/**
 * Sets the Uri-Path options of the UTF-8 text at `path` ("/a/b") and the Uri-Query options of
 * the UTF-8 text at `query` ("x=1&y", none if null), as RFC 7252 §6.4 splits a URI.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_set_uri(umilib_protocol_coap_CoAPOptions* options, const uint8_t* path, size_t path_length, const uint8_t* query, size_t query_length);

/**
 * Writes the Content-Format (RFC 7252 §5.10.3) into `out` and whether there is one into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_content_format(const umilib_protocol_coap_CoAPOptions* options, bool* out_found, uint16_t* out);

/**
 * Writes the Max-Age in seconds, 60 without the option (RFC 7252 §5.10.5), into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_max_age(const umilib_protocol_coap_CoAPOptions* options, uint32_t* out);

/**
 * Writes the Observe value, of 24 bits (RFC 7641 §2), into `out` and whether there is one into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_observe(const umilib_protocol_coap_CoAPOptions* options, bool* out_found, uint32_t* out);

/**
 * Writes the block of the option `number` (Block1 or Block2, RFC 7959 §2.2) into `out` and
 * whether there is one into `out_found`; fails with Option for a value longer than 3 bytes or of
 * the reserved SZX 7.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_options_block(const umilib_protocol_coap_CoAPOptions* options, uint16_t number, bool* out_found, umilib_protocol_coap_CoAPBlock* out);

/**
 * Writes the block `number` of `size` bytes (16 to 1024 in powers of 2), with more after it if
 * `more`, into `out`; fails with Option for another size or a number of more than 20 bits.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_block_new(uint32_t number, bool more, size_t size, umilib_protocol_coap_CoAPBlock* out);

/**
 * Reads the block of the option value of `length` bytes at `value` into `out`; fails with Option
 * for a value longer than 3 bytes or of the reserved SZX 7 (RFC 7959 §2.2).
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_block_decode(const uint8_t* value, size_t length, umilib_protocol_coap_CoAPBlock* out);

/**
 * Writes the option value of the block `block` into `out`; fails with Option for a block that is not one.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_block_encode(umilib_protocol_coap_CoAPBlock block, umilib_ffi_Buffer* out);

/**
 * Writes the size of the block in bytes into `out`; fails with Option for a block that is not one.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_block_size(umilib_protocol_coap_CoAPBlock block, size_t* out);

/**
 * Writes the offset of the block in the whole body (RFC 7959 §2.2) into `out`; fails with Option
 * for a block that is not one.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_block_offset(umilib_protocol_coap_CoAPBlock block, size_t* out);

/**
 * Writes whether the body of `length` bytes at `body` has the block `block` (RFC 7959 §2.4) into
 * `out_found`, the length of its bytes, which start at the block's offset, into `out_length`, and
 * whether more follow into `out_more`; fails with Option for a block that is not one.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_block_slice(umilib_protocol_coap_CoAPBlock block, const uint8_t* body, size_t length, bool* out_found, size_t* out_length, bool* out_more);

/**
 * Writes a message of the type `kind`, the code `code` and the Message ID `id`, without token,
 * options or payload, into `out`; fails with InvalidArgument for a type above 3.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_new(uint8_t kind, uint8_t code, uint16_t id, umilib_protocol_coap_CoAPMessage** out);

/**
 * Writes the empty message of the type `kind` and the Message ID `id`, an ACK or a RST (RFC 7252
 * §4.1, §4.2), into `out`; fails with InvalidArgument for a type above 3.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_empty(uint8_t kind, uint16_t id, umilib_protocol_coap_CoAPMessage** out);

/**
 * Writes a copy of the message into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_clone(const umilib_protocol_coap_CoAPMessage* message, umilib_protocol_coap_CoAPMessage** out);

/**
 * Releases a message. Does nothing if `message` is null.
 */
void umilib_protocol_coap_coap_message_free(umilib_protocol_coap_CoAPMessage* message);

/**
 * Reads the message of the `length` bytes at `bytes` (RFC 7252 §3, RFC 8974 §2.1) into `out`;
 * fails with Malformed for a message format error: another version, a token length of 15, an
 * option of delta or length 15, a payload marker without payload, or an empty message with a
 * token, options or payload (RFC 7252 §4.1).
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_decode(const uint8_t* bytes, size_t length, umilib_protocol_coap_CoAPMessage** out);

/**
 * Writes the bytes of the message (RFC 7252 §3) into `out`; fails with TooLarge for a token or an
 * option value above its largest length.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_encode(const umilib_protocol_coap_CoAPMessage* message, umilib_ffi_Buffer* out);

/**
 * Writes whether the `length` bytes at `bytes` have a header of version 1 into `out_found`, and
 * its type and Message ID into `out_kind` and `out_id`: what a message that cannot be read
 * otherwise is rejected by (RFC 7252 §4.2, §4.3).
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_header(const uint8_t* bytes, size_t length, bool* out_found, uint8_t* out_kind, uint16_t* out_id);

/**
 * Writes the type of the message, as its bits, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_kind(const umilib_protocol_coap_CoAPMessage* message, uint8_t* out);

/**
 * Sets the type of the message to the bits `kind`; fails with InvalidArgument above 3.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_set_kind(umilib_protocol_coap_CoAPMessage* message, uint8_t kind);

/**
 * Writes the code of the message into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_code(const umilib_protocol_coap_CoAPMessage* message, uint8_t* out);

/**
 * Sets the code of the message.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_set_code(umilib_protocol_coap_CoAPMessage* message, uint8_t code);

/**
 * Writes the Message ID of the message into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_id(const umilib_protocol_coap_CoAPMessage* message, uint16_t* out);

/**
 * Sets the Message ID of the message.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_set_id(umilib_protocol_coap_CoAPMessage* message, uint16_t id);

/**
 * Writes the token of the message into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_token(const umilib_protocol_coap_CoAPMessage* message, umilib_ffi_Buffer* out);

/**
 * Sets the token of the message to the `length` bytes at `token`, of up to 65804 bytes (RFC 8974
 * §2.1), which encoding checks.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_set_token(umilib_protocol_coap_CoAPMessage* message, const uint8_t* token, size_t length);

/**
 * Writes a copy of the options of the message into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_options(const umilib_protocol_coap_CoAPMessage* message, umilib_protocol_coap_CoAPOptions** out);

/**
 * Sets the options of the message to a copy of `options`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_set_options(umilib_protocol_coap_CoAPMessage* message, const umilib_protocol_coap_CoAPOptions* options);

/**
 * Writes the payload of the message into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_payload(const umilib_protocol_coap_CoAPMessage* message, umilib_ffi_Buffer* out);

/**
 * Sets the payload of the message to the `length` bytes at `payload`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_message_set_payload(umilib_protocol_coap_CoAPMessage* message, const uint8_t* payload, size_t length);

/**
 * Writes the default configuration (RFC 7252 §4.8, and tokens of up to 8 bytes) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_config_default(umilib_protocol_coap_CoAPConfig* out);

/**
 * Writes an endpoint of the configuration at `config`, its first Message ID drawn from `random`
 * (RFC 7252 §4.4), into `out`; fails with Config for a zero ACK_TIMEOUT, an ACK_RANDOM_FACTOR
 * below 1000 or a zero NSTART, and with Random if `random` fails.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_endpoint_new(const umilib_protocol_coap_CoAPConfig* config, void* random, const uint8_t* random_type, size_t random_type_length, umilib_protocol_coap_CoAPEndpoint** out);

/**
 * Releases an endpoint. Does nothing if `endpoint` is null.
 */
void umilib_protocol_coap_coap_endpoint_free(umilib_protocol_coap_CoAPEndpoint* endpoint);

/**
 * Sends the request `message` (Confirmable or Non-confirmable, a token of 8 random bytes if it
 * has none) to `peer` at `now`; it waits while NSTART interactions with the peer are outstanding
 * (RFC 7252 §4.7). Writes the handle its response and notifications come with into `out`; fails
 * with State for a message that is not such a request, TooLarge, and Random.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_endpoint_request(umilib_protocol_coap_CoAPEndpoint* endpoint, const umilib_protocol_ip_IPEndpoint* peer, const umilib_protocol_coap_CoAPMessage* message, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length, uint64_t* out);

/**
 * Takes the datagram of `length` bytes at `bytes` from `peer` at `now`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_endpoint_receive(umilib_protocol_coap_CoAPEndpoint* endpoint, const umilib_protocol_ip_IPEndpoint* peer, const uint8_t* bytes, size_t length, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Answers the request `exchange` with the code, options and payload of `response` at `now`:
 * piggybacked in the ACK of a Confirmable request not yet acknowledged (RFC 7252 §5.2.1), else
 * separately, Confirmable for a Confirmable request (§5.2.2) and Non-confirmable for a
 * Non-confirmable one. Fails with State for an exchange that is not awaiting its answer.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_endpoint_respond(umilib_protocol_coap_CoAPEndpoint* endpoint, uint64_t exchange, const umilib_protocol_coap_CoAPMessage* response, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Sends the notification `message` (a response with Observe, of the observer's token) of an
 * observation to `peer` at `now` (RFC 7641 §4.2); writes its handle, to learn of a RST or a
 * timeout, which end the observation (§3.6, §4.5), into `out`. Fails with State for a message
 * that is not such a response.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_endpoint_notify(umilib_protocol_coap_CoAPEndpoint* endpoint, const umilib_protocol_ip_IPEndpoint* peer, const umilib_protocol_coap_CoAPMessage* message, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length, uint64_t* out);

/**
 * Stops awaiting the request `handle` at `now`: its observation is forgotten, so that its
 * notifications are rejected (RFC 7641 §3.6), and what waited for it may go.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_endpoint_cancel(umilib_protocol_coap_CoAPEndpoint* endpoint, uint64_t handle, uint64_t now);

/**
 * Writes whether a timer is set into `out_found` and when it fires (nanoseconds) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_endpoint_poll_timeout(const umilib_protocol_coap_CoAPEndpoint* endpoint, bool* out_found, uint64_t* out);

/**
 * Does what is due at `now`: retransmissions, doubling the timeout up to MAX_RETRANSMIT (RFC 7252
 * §4.2); the end of what is not answered; the empty ACK of a request not yet answered (§5.2.2).
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_endpoint_expire(umilib_protocol_coap_CoAPEndpoint* endpoint, uint64_t now);

/**
 * Writes the next datagram to send into `out` and its peer into `out_peer`, and whether there was
 * one into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_endpoint_transmit(umilib_protocol_coap_CoAPEndpoint* endpoint, bool* out_found, umilib_protocol_ip_IPEndpoint* out_peer, umilib_ffi_Buffer* out);

/**
 * Writes whether an event is pending into `out_found`, the event into `out`, and the message of a
 * Request or a Response into `out_message` (null for another event).
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_endpoint_poll_event(umilib_protocol_coap_CoAPEndpoint* endpoint, bool* out_found, umilib_protocol_coap_CoAPEvent* out, umilib_protocol_coap_CoAPMessage** out_message);

/**
 * Writes whether a notification of the Observe value `value` received at `now` (nanoseconds) was
 * sent after the freshest one, of `freshest` received at `at`, into `out` (RFC 7641 §3.4).
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_endpoint_is_fresher(uint32_t freshest, uint64_t at, uint32_t value, uint64_t now, bool* out);

/**
 * Writes the observers of a server, of none yet, into `out`: a Confirmable notification at least
 * once a day (RFC 7641 §4.5), and at most 1024 observers.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_observers_new(umilib_protocol_coap_CoAPObservers** out);

/**
 * Releases the observers. Does nothing if `observers` is null.
 */
void umilib_protocol_coap_coap_observers_free(umilib_protocol_coap_CoAPObservers* observers);

/**
 * Writes how often, at least, a notification is Confirmable (RFC 7641 §4.5), in milliseconds, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_observers_confirm_interval(const umilib_protocol_coap_CoAPObservers* observers, uint64_t* out);

/**
 * Sets how often, at least, a notification is Confirmable, in milliseconds.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_observers_set_confirm_interval(umilib_protocol_coap_CoAPObservers* observers, uint64_t interval);

/**
 * Writes the most observers kept into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_observers_maximum(const umilib_protocol_coap_CoAPObservers* observers, size_t* out);

/**
 * Sets the most observers kept.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_observers_set_maximum(umilib_protocol_coap_CoAPObservers* observers, size_t maximum);

/**
 * Writes the number of observers into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_observers_count(const umilib_protocol_coap_CoAPObservers* observers, size_t* out);

/**
 * Writes the peer of the observer `index` into `out_peer` and its token into `out_token`; fails
 * with InvalidArgument past the end.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_observers_observer(const umilib_protocol_coap_CoAPObservers* observers, size_t index, umilib_protocol_ip_IPEndpoint* out_peer, umilib_ffi_Buffer* out_token);

/**
 * Takes the GET or FETCH request `request` of `peer` at `now`: with Observe 0 the client observes
 * the resource (an observer of the same peer and token replaced, RFC 7641 §4.1); with Observe 1
 * it stops (§3.6). Writes whether the response is to carry Observe into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_observers_register(umilib_protocol_coap_CoAPObservers* observers, const umilib_protocol_ip_IPEndpoint* peer, const umilib_protocol_coap_CoAPMessage* request, uint64_t now, bool* out);

/**
 * Writes the next Observe value, of 24 bits and strictly increasing (RFC 7641 §4.4), into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_observers_next_value(umilib_protocol_coap_CoAPObservers* observers, uint32_t* out);

/**
 * Sends, through `endpoint` at `now`, the state of the resource at the path of the `count`
 * NUL-terminated UTF-8 segments at `path` to its observers (RFC 7641 §4.2): `response` with each
 * one's token and the next Observe value, Confirmable if `confirmable` or if the observer has not
 * had a Confirmable one for the interval. A response of another class than 2 has no Observe, and
 * ends the observations.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_observers_notify(umilib_protocol_coap_CoAPObservers* observers, umilib_protocol_coap_CoAPEndpoint* endpoint, const char* const* path, size_t count, const umilib_protocol_coap_CoAPMessage* response, bool confirmable, uint64_t now, void* random, const uint8_t* random_type, size_t random_type_length);

/**
 * Takes the event at `event` of the endpoint: a notification rejected (Reset) or not
 * acknowledged (Timeout) ends its observation (RFC 7641 §3.6, §4.5). Writes whether it was one
 * into `out`; fails with InvalidArgument for a kind above 3.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_observers_handle(umilib_protocol_coap_CoAPObservers* observers, const umilib_protocol_coap_CoAPEvent* event, bool* out);

/**
 * Sets the block of the body of `length` bytes at `body` that `request` asks for in its Block2
 * (its number, at most `size` bytes), or the first, as the payload of `response` with its Block2
 * option, if the body is larger than a block or a block was asked for (RFC 7959 §2.4); and Size2
 * if the request has it (§4). Fails with Option for a block past the end, which is 4.02, or a
 * size that is not one of a block.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_blockwise_respond(const umilib_protocol_coap_CoAPMessage* request, const uint8_t* body, size_t length, size_t size, umilib_protocol_coap_CoAPMessage* response);

/**
 * Writes a receiver of a body of at most `maximum` bytes, block by block (RFC 7959 §2.4), into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_blockwise_new(size_t maximum, umilib_protocol_coap_CoAPBlockwise** out);

/**
 * Releases a receiver. Does nothing if `blockwise` is null.
 */
void umilib_protocol_coap_coap_blockwise_free(umilib_protocol_coap_CoAPBlockwise* blockwise);

/**
 * Takes the block `block` of the payload of `length` bytes at `payload`, of the message's ETag of
 * `etag_length` bytes at `etag` (none if null): in order, each but the last of the full size and
 * of the same ETag (RFC 7959 §2.4, §2.5). Writes whether the body is whole into `out`; fails with
 * State for a block out of order or of another ETag, Malformed for one not of its size before
 * the last, TooLarge past the maximum, and Option for a block that is not one.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_blockwise_receive(umilib_protocol_coap_CoAPBlockwise* blockwise, umilib_protocol_coap_CoAPBlock block, const uint8_t* payload, size_t length, const uint8_t* etag, size_t etag_length, bool* out);

/**
 * Writes the options of the request for the next block into `out`: `options` with Block2 of the
 * next number and `size` bytes, without Observe (RFC 7959 §2.4); fails with Option for a size
 * that is not one of a block.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_blockwise_next_request(const umilib_protocol_coap_CoAPBlockwise* blockwise, const umilib_protocol_coap_CoAPOptions* options, size_t size, umilib_protocol_coap_CoAPOptions** out);

/**
 * Writes the body received so far into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_blockwise_body(const umilib_protocol_coap_CoAPBlockwise* blockwise, umilib_ffi_Buffer* out);

/**
 * Writes a link to the UTF-8 text at `target`, without attributes (RFC 6690 §2), into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_link_new(const uint8_t* target, size_t length, umilib_protocol_coap_CoAPLink** out);

/**
 * Writes a copy of the link into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_link_clone(const umilib_protocol_coap_CoAPLink* link, umilib_protocol_coap_CoAPLink** out);

/**
 * Releases a link. Does nothing if `link` is null.
 */
void umilib_protocol_coap_coap_link_free(umilib_protocol_coap_CoAPLink* link);

/**
 * Adds the attribute of the UTF-8 text at `name` and that at `value` (none if null) to the link.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_link_with(umilib_protocol_coap_CoAPLink* link, const uint8_t* name, size_t name_length, const uint8_t* value, size_t value_length);

/**
 * Writes the target of the link into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_link_target(const umilib_protocol_coap_CoAPLink* link, umilib_ffi_Buffer* out);

/**
 * Writes whether the link has an attribute of the UTF-8 text at `name` (in any case) into
 * `out_found`, whether the first has a value into `out_has_value`, and its value into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_link_attribute(const umilib_protocol_coap_CoAPLink* link, const uint8_t* name, size_t length, bool* out_found, bool* out_has_value, umilib_ffi_Buffer* out);

/**
 * Writes the number of attributes of the link into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_link_attribute_count(const umilib_protocol_coap_CoAPLink* link, size_t* out);

/**
 * Writes the name of the attribute `index` of the link into `out_name`, whether it has a value
 * into `out_has_value`, and its value into `out_value`; fails with InvalidArgument past the end.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_link_attribute_entry(const umilib_protocol_coap_CoAPLink* link, size_t index, umilib_ffi_Buffer* out_name, bool* out_has_value, umilib_ffi_Buffer* out_value);

/**
 * Reads the links of the UTF-8 text at `text` (`<target>;name=value;name="quoted",...`, RFC
 * 6690 §2) into `out`; fails with Malformed for text not of the link format.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_link_parse(const uint8_t* text, size_t length, umilib_protocol_coap_CoAPLinks** out);

/**
 * Writes the text of the links (RFC 6690 §2), values quoted unless they are tokens, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_link_format(const umilib_protocol_coap_CoAPLinks* links, umilib_ffi_Buffer* out);

/**
 * Writes an empty list of links into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_links_new(umilib_protocol_coap_CoAPLinks** out);

/**
 * Releases a list of links. Does nothing if `links` is null.
 */
void umilib_protocol_coap_coap_links_free(umilib_protocol_coap_CoAPLinks* links);

/**
 * Appends a copy of `link` to the list.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_links_push(umilib_protocol_coap_CoAPLinks* links, const umilib_protocol_coap_CoAPLink* link);

/**
 * Writes the number of links into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_links_count(const umilib_protocol_coap_CoAPLinks* links, size_t* out);

/**
 * Writes a copy of the link `index` into `out`; fails with InvalidArgument past the end.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_links_get(const umilib_protocol_coap_CoAPLinks* links, size_t index, umilib_protocol_coap_CoAPLink** out);

/**
 * Writes a rule of the requests of paths at or below the UTF-8 text at `path` ("/sensors/temp"),
 * of any method, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_rule_new(const uint8_t* path, size_t length, umilib_protocol_coap_CoAPRule** out);

/**
 * Releases a rule. Does nothing if `rule` is null.
 */
void umilib_protocol_coap_coap_rule_free(umilib_protocol_coap_CoAPRule* rule);

/**
 * Limits the rule to the requests of the method (the code) `method`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_rule_with_method(umilib_protocol_coap_CoAPRule* rule, uint8_t method);

/**
 * Writes whether the rule matches `message`, a request of the rule's path or below it and of its
 * method if it has one, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_coap_coap_rule_matches(const umilib_protocol_coap_CoAPRule* rule, const umilib_protocol_coap_CoAPMessage* message, bool* out);

#ifdef __cplusplus
}
#endif

#endif
