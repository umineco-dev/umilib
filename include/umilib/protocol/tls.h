/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_TLS_H
#define UMILIB_PROTOCOL_TLS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/auth/cert/key.h"
#include "umilib/auth/cert/path.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The limits of a TLS configuration.
 */
typedef struct umilib_protocol_tls_TLSLimits {
    size_t maximum_handshake_message;
    uint16_t record_size_limit;
    size_t maximum_buffered_data;
    uint32_t maximum_key_updates;
    bool require_extended_main_secret;
    uint32_t maximum_ignored_records;
} umilib_protocol_tls_TLSLimits;

/**
 * The flags of a configuration of TLS clients.
 */
typedef struct umilib_protocol_tls_TLSClientOptions {
    bool middlebox_compatibility;
    bool send_server_name;
    bool request_certificate_status;
    bool post_handshake_authentication;
    bool early_data;
    bool ech_grease;
} umilib_protocol_tls_TLSClientOptions;

/**
 * The numbers and flags of a configuration of TLS servers.
 */
typedef struct umilib_protocol_tls_TLSServerOptions {
    bool prefer_own_cipher_suites;
    uint8_t client_authentication;
    size_t ticket_count;
    uint32_t ticket_lifetime;
    uint32_t maximum_early_data;
    int64_t freshness_window;
} umilib_protocol_tls_TLSServerOptions;

/**
 * What a TLS session negotiated; 0 for what is not negotiated yet.
 */
typedef struct umilib_protocol_tls_TLSSession {
    uint16_t version;
    uint16_t cipher_suite;
    uint16_t group;
    uint16_t peer_signature_scheme;
    bool resumed;
    uint8_t early_data;
    uint8_t ech;
    bool handshaking;
} umilib_protocol_tls_TLSSession;

/**
 * What both ends of TLS configure: versions, algorithms and limits.
 */
typedef struct umilib_protocol_tls_TLSConfig umilib_protocol_tls_TLSConfig;

/**
 * The configuration of TLS clients.
 */
typedef struct umilib_protocol_tls_TLSClientConfig umilib_protocol_tls_TLSClientConfig;

/**
 * The configuration of TLS servers.
 */
typedef struct umilib_protocol_tls_TLSServerConfig umilib_protocol_tls_TLSServerConfig;

/**
 * The verification of certificate chains to trust anchors.
 */
typedef struct umilib_protocol_tls_TLSPathVerifier umilib_protocol_tls_TLSPathVerifier;

/**
 * A certificate chain and the private key of its first certificate.
 */
typedef struct umilib_protocol_tls_TLSCertifiedKey umilib_protocol_tls_TLSCertifiedKey;

/**
 * An ECH configuration and its private key.
 */
typedef struct umilib_protocol_tls_TLSECHKey umilib_protocol_tls_TLSECHKey;

/**
 * A TLS connection without I/O.
 */
typedef struct umilib_protocol_tls_TLSConnection umilib_protocol_tls_TLSConnection;

/**
 * A rule that routes TLS connections by server name and application protocol.
 */
typedef struct umilib_protocol_tls_TLSRule umilib_protocol_tls_TLSRule;

/**
 * Writes the default configuration (every version, suite, group and scheme compiled in) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_config_new(umilib_protocol_tls_TLSConfig** out);

/**
 * Releases a configuration. Does nothing if `config` is null.
 */
void umilib_protocol_tls_tls_config_free(umilib_protocol_tls_TLSConfig* config);

/**
 * Sets the versions, most preferred first, to the `count` numbers at `versions`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_config_set_versions(umilib_protocol_tls_TLSConfig* config, const uint16_t* versions, size_t count);

/**
 * Sets the cipher suites, most preferred first, to the `count` numbers at `suites`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_config_set_cipher_suites(umilib_protocol_tls_TLSConfig* config, const uint16_t* suites, size_t count);

/**
 * Sets the groups of key exchange, most preferred first, to the `count` numbers at `groups`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_config_set_groups(umilib_protocol_tls_TLSConfig* config, const uint16_t* groups, size_t count);

/**
 * Sets the signature schemes, most preferred first, to the `count` numbers at `schemes`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_config_set_signature_schemes(umilib_protocol_tls_TLSConfig* config, const uint16_t* schemes, size_t count);

/**
 * Sets the application protocols (ALPN), most preferred first, to the `count` byte strings at `protocols` and `lengths`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_config_set_protocols(umilib_protocol_tls_TLSConfig* config, const uint8_t* const* protocols, const size_t* lengths, size_t count);

/**
 * Writes the limits of the configuration into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_config_limits(const umilib_protocol_tls_TLSConfig* config, umilib_protocol_tls_TLSLimits* out);

/**
 * Sets the limits of the configuration.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_config_set_limits(umilib_protocol_tls_TLSConfig* config, const umilib_protocol_tls_TLSLimits* limits);

/**
 * Writes the verifier of servers' certificates to the anchors of the list `anchors` (copied) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_path_verifier_servers(const umilib_auth_cert_path_TrustAnchors* anchors, umilib_protocol_tls_TLSPathVerifier** out);

/**
 * Writes the verifier of clients' certificates to the anchors of the list `anchors` (copied) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_path_verifier_clients(const umilib_auth_cert_path_TrustAnchors* anchors, umilib_protocol_tls_TLSPathVerifier** out);

/**
 * Releases a verifier. Does nothing if `verifier` is null.
 */
void umilib_protocol_tls_tls_path_verifier_free(umilib_protocol_tls_TLSPathVerifier* verifier);

/**
 * Writes the key `key` (consumed: the handle is released) with the chain of the `count` DER
 * certificates at `chain` and `lengths` (the end-entity certificate first), and the OCSP response
 * of `ocsp_length` bytes at `ocsp` to staple (none for 0 bytes), into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_certified_key_new(const uint8_t* const* chain, const size_t* lengths, size_t count, umilib_auth_cert_key_PrivateKey* key, const uint8_t* ocsp, size_t ocsp_length, umilib_protocol_tls_TLSCertifiedKey** out);

/**
 * Releases a certified key. Does nothing if `key` is null.
 */
void umilib_protocol_tls_tls_certified_key_free(umilib_protocol_tls_TLSCertifiedKey* key);

/**
 * Writes the configuration of clients of `config` (copied), checking servers with `verifier`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_client_config_new(const umilib_protocol_tls_TLSConfig* config, const umilib_protocol_tls_TLSPathVerifier* verifier, umilib_protocol_tls_TLSClientConfig** out);

/**
 * Releases a configuration of clients. Does nothing if `config` is null.
 */
void umilib_protocol_tls_tls_client_config_free(umilib_protocol_tls_TLSClientConfig* config);

/**
 * Sets the flags of the configuration of clients.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_client_config_set_options(umilib_protocol_tls_TLSClientConfig* config, const umilib_protocol_tls_TLSClientOptions* options);

/**
 * Sets the groups of the first ClientHello's key shares to the `count` numbers at `groups`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_client_config_set_key_share_groups(umilib_protocol_tls_TLSClientConfig* config, const uint16_t* groups, size_t count);

/**
 * Sets the certificate sent when a server asks for one to a copy of `key`, or none if `key` is null.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_client_config_set_certificate(umilib_protocol_tls_TLSClientConfig* config, const umilib_protocol_tls_TLSCertifiedKey* key);

/**
 * Keeps the tickets of servers in a cache of `capacity` tickets, or none for 0.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_client_config_set_session_cache(umilib_protocol_tls_TLSClientConfig* config, size_t capacity);

/**
 * Sets the server's ECH configurations to those of the `ECHConfigList` of `length` bytes at `list`; fails with Protocol for a malformed list.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_client_config_set_ech_configs(umilib_protocol_tls_TLSClientConfig* config, const uint8_t* list, size_t length);

/**
 * Writes the configuration of servers of `config` (copied), without certificates yet, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_server_config_new(const umilib_protocol_tls_TLSConfig* config, umilib_protocol_tls_TLSServerConfig** out);

/**
 * Releases a configuration of servers. Does nothing if `config` is null.
 */
void umilib_protocol_tls_tls_server_config_free(umilib_protocol_tls_TLSServerConfig* config);

/**
 * Adds a copy of `key` to the certificates the server presents, in order of preference.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_server_config_add_certificate(umilib_protocol_tls_TLSServerConfig* config, const umilib_protocol_tls_TLSCertifiedKey* key);

/**
 * Sets the numbers and flags of the configuration of servers; fails with InvalidArgument for an
 * unknown client authentication.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_server_config_set_options(umilib_protocol_tls_TLSServerConfig* config, const umilib_protocol_tls_TLSServerOptions* options);

/**
 * Sets the verifier of clients' certificates, or none if `verifier` is null.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_server_config_set_client_verifier(umilib_protocol_tls_TLSServerConfig* config, const umilib_protocol_tls_TLSPathVerifier* verifier);

/**
 * Makes tickets with the AES-256-GCM key of 32 bytes at `key` named by the 16 bytes at `name`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_server_config_set_ticket_key(umilib_protocol_tls_TLSServerConfig* config, const uint8_t* name, const uint8_t* key);

/**
 * Refuses replayed early data with a record of `capacity` ClientHellos over `window` seconds.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_server_config_set_replay_cache(umilib_protocol_tls_TLSServerConfig* config, int64_t window, size_t capacity);

/**
 * Adds a copy of the ECH key `key` to those the server decrypts with.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_server_config_add_ech_key(umilib_protocol_tls_TLSServerConfig* config, const umilib_protocol_tls_TLSECHKey* key);

/**
 * Writes the ECH key of the configuration of the `ECHConfigList` of `length` bytes at `list` (its
 * first configuration of version 0xfe0d) and the KEM's serialized private key of `private_length`
 * bytes at `private_key`, sent to rejected clients if `retry`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_ech_key_new(const uint8_t* list, size_t length, const uint8_t* private_key, size_t private_length, bool retry, umilib_protocol_tls_TLSECHKey** out);

/**
 * Writes a new ECH key of the KEM `kem_id`, for the configuration `config_id` with the `count`
 * HPKE suites at `suites` (pairs of kdf_id and aead_id), the longest name `maximum_name_length`
 * and the public name (UTF-8) of `length` bytes at `public_name`, sent to rejected clients if
 * `retry`, with randomness seeded by the `seed_length` bytes at `seed` (at least 48), into `out`;
 * fails with Config for a KEM not compiled in (ECH needs `crypto-hpke`).
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_ech_key_generate(uint8_t config_id, uint16_t kem_id, const uint16_t* suites, size_t count, uint8_t maximum_name_length, const uint8_t* public_name, size_t length, bool retry, const uint8_t* seed, size_t seed_length, umilib_protocol_tls_TLSECHKey** out);

/**
 * Writes the `ECHConfigList` of the key's configuration into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_ech_key_config_list(const umilib_protocol_tls_TLSECHKey* key, umilib_ffi_Buffer* out);

/**
 * Writes the KEM's serialized private key of the key into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_ech_key_private_key(const umilib_protocol_tls_TLSECHKey* key, umilib_ffi_Buffer* out);

/**
 * Releases an ECH key. Does nothing if `key` is null.
 */
void umilib_protocol_tls_tls_ech_key_free(umilib_protocol_tls_TLSECHKey* key);

/**
 * Writes a client connecting to the name (UTF-8) of `length` bytes at `server_name` (none for 0
 * bytes) at `time` (seconds since 1970), its ClientHello written, with randomness seeded by the
 * `seed_length` bytes at `seed` (at least 48), into `out`; fails with Config for a configuration
 * that cannot work.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_client(const umilib_protocol_tls_TLSClientConfig* config, const uint8_t* server_name, size_t length, const uint8_t* seed, size_t seed_length, int64_t time, umilib_protocol_tls_TLSConnection** out);

/**
 * Writes a server at `time` (seconds since 1970), with randomness seeded by the `seed_length`
 * bytes at `seed` (at least 48), into `out`; fails with Config for a configuration that cannot work.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_server(const umilib_protocol_tls_TLSServerConfig* config, const uint8_t* seed, size_t seed_length, int64_t time, umilib_protocol_tls_TLSConnection** out);

/**
 * Releases a connection. Does nothing if `connection` is null.
 */
void umilib_protocol_tls_tls_connection_free(umilib_protocol_tls_TLSConnection* connection);

/**
 * Takes the `length` bytes at `bytes` received from the transport; fails with Protocol, Alert or State.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_receive(umilib_protocol_tls_TLSConnection* connection, const uint8_t* bytes, size_t length);

/**
 * Writes the bytes to send to the transport into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_transmit(umilib_protocol_tls_TLSConnection* connection, umilib_ffi_Buffer* out);

/**
 * Sends the `length` bytes at `data` as application data (or early data the handshake allows);
 * fails with State before the handshake allows it or after closing.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_send(umilib_protocol_tls_TLSConnection* connection, const uint8_t* data, size_t length);

/**
 * Reads up to `length` bytes of application data into `out` and writes how many into `out_count`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_read(umilib_protocol_tls_TLSConnection* connection, uint8_t* out, size_t length, size_t* out_count);

/**
 * Writes whether an event is pending into `out_found` and its number into `out_kind`: 0 Connected,
 * 1 Readable, 2 PeerClosed, 3 Authenticated.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_poll_event(umilib_protocol_tls_TLSConnection* connection, bool* out_found, uint8_t* out_kind);

/**
 * Sends close_notify; fails with State if it was sent or the connection failed.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_close(umilib_protocol_tls_TLSConnection* connection);

/**
 * Updates the keys of sending, asking the peer to update its own if `request` (TLS 1.3); fails with State.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_update_keys(umilib_protocol_tls_TLSConnection* connection, bool request);

/**
 * Asks the client for a certificate after the handshake (TLS 1.3); fails with State.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_request_certificate(umilib_protocol_tls_TLSConnection* connection);

/**
 * Writes `length` bytes of keying material for the label of `label_length` bytes at `label` and,
 * if `has_context`, the context of `context_length` bytes at `context`, into `out`; fails with State.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_export(const umilib_protocol_tls_TLSConnection* connection, const uint8_t* label, size_t label_length, bool has_context, const uint8_t* context, size_t context_length, uint8_t* out, size_t length);

/**
 * Writes what the session negotiated into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_session(const umilib_protocol_tls_TLSConnection* connection, umilib_protocol_tls_TLSSession* out);

/**
 * Writes whether an application protocol was negotiated into `out_found` and it into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_protocol(const umilib_protocol_tls_TLSConnection* connection, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes whether the client asked for a name into `out_found` and the name (UTF-8) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_server_name(const umilib_protocol_tls_TLSConnection* connection, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes whether the peer's chain has a certificate at `index` (0 is the end-entity certificate)
 * into `out_found` and its DER into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_peer_certificate(const umilib_protocol_tls_TLSConnection* connection, size_t index, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes whether the server stapled an OCSP response into `out_found` and it into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_certificate_status(const umilib_protocol_tls_TLSConnection* connection, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes whether a server that rejected ECH sent retry configurations into `out_found` and its
 * `ECHConfigList` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_ech_retry_configs(const umilib_protocol_tls_TLSConnection* connection, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes whether the connection failed into `out_failed`, and its error: `out_kind` 0 Protocol
 * (the alert sent), 1 Alert (the alert received), 2 State, 3 Config, 4 Write, 5 Transport, and
 * the alert's description into `out_alert`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_connection_error(const umilib_protocol_tls_TLSConnection* connection, bool* out_failed, uint8_t* out_kind, uint8_t* out_alert);

/**
 * Writes the rule of the server names of the pattern (UTF-8) of `length` bytes at `pattern`
 * (`*` any, `*.domain` one label of `domain`, otherwise that name; none for 0 bytes: no name), and
 * of the application protocol of `protocol_length` bytes at `protocol` (any for 0 bytes), into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_rule_new(const uint8_t* pattern, size_t length, const uint8_t* protocol, size_t protocol_length, umilib_protocol_tls_TLSRule** out);

/**
 * Releases a rule. Does nothing if `rule` is null.
 */
void umilib_protocol_tls_tls_rule_free(umilib_protocol_tls_TLSRule* rule);

/**
 * Writes whether the rule matches the session of `connection` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_rule_matches_session(const umilib_protocol_tls_TLSRule* rule, const umilib_protocol_tls_TLSConnection* connection, bool* out);

/**
 * Writes whether the rule matches the body of a ClientHello of `length` bytes at `hello` into
 * `out`; fails with Protocol for a malformed ClientHello.
 */
const umilib_ffi_Status* umilib_protocol_tls_tls_rule_matches_client_hello(const umilib_protocol_tls_TLSRule* rule, const uint8_t* hello, size_t length, bool* out);

#ifdef __cplusplus
}
#endif

#endif
