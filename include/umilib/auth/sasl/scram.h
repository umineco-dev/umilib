/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_SASL_SCRAM_H
#define UMILIB_AUTH_SASL_SCRAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The client of SCRAM (RFC 5802) over SHA-1 or SHA-256.
 */
typedef struct umilib_auth_sasl_scram_SCRAMClient umilib_auth_sasl_scram_SCRAMClient;

/**
 * The server of SCRAM (RFC 5802) over SHA-1 or SHA-256.
 */
typedef struct umilib_auth_sasl_scram_SCRAMServer umilib_auth_sasl_scram_SCRAMServer;

/**
 * What a SCRAM server keeps for a user.
 */
typedef struct umilib_auth_sasl_scram_SCRAMCredentials umilib_auth_sasl_scram_SCRAMCredentials;

/**
 * Writes a nonce of random bytes drawn from `random` in base64 into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_nonce_random(void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes the value of `e=` of the server error at `index` into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_server_error_name(uint8_t index, umilib_ffi_Buffer* out);

/**
 * Writes the client over the hash function named by `hash` for the username at `username`, the
 * password at `password` and the client nonce at `nonce` (all UTF-8) into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_client_new(const uint8_t* hash, size_t hash_length, const uint8_t* username, size_t username_length, const uint8_t* password, size_t password_length, const uint8_t* nonce, size_t nonce_length, umilib_auth_sasl_scram_SCRAMClient** out);

/**
 * Writes the client of a SaltedPassword kept from an earlier exchange (with its salt and
 * iteration count) into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_client_from_salted_password(const uint8_t* hash, size_t hash_length, const uint8_t* username, size_t username_length, const uint8_t* salt, size_t salt_length, uint32_t iterations, const uint8_t* salted_password, size_t salted_password_length, const uint8_t* nonce, size_t nonce_length, umilib_auth_sasl_scram_SCRAMClient** out);

/**
 * Sets the authorization identity to the UTF-8 text at `authzid`, or none for null.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_client_set_authzid(umilib_auth_sasl_scram_SCRAMClient* client, const uint8_t* authzid, size_t length);

/**
 * Sets the channel binding flag `kind` (0 `n`, 1 `y`, 2 `p` with the type's name at `name`)
 * and its data at `data` (present exactly for 2).
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_client_set_channel_binding(umilib_auth_sasl_scram_SCRAMClient* client, uint8_t kind, const uint8_t* name, size_t name_length, const uint8_t* data, size_t data_length);

/**
 * Sets the iteration counts the client accepts.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_client_set_iterations(umilib_auth_sasl_scram_SCRAMClient* client, uint32_t minimum, uint32_t maximum);

/**
 * Writes the index of the mechanism the client runs (the `-PLUS` variant with channel binding) into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_client_mechanism(const umilib_auth_sasl_scram_SCRAMClient* client, uint8_t* out);

/**
 * Writes the client-first-message into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_client_client_first(umilib_auth_sasl_scram_SCRAMClient* client, umilib_ffi_Buffer* out);

/**
 * Reads the server-first-message at `message` and writes the client-final-message into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_client_receive_server_first(umilib_auth_sasl_scram_SCRAMClient* client, const uint8_t* message, size_t length, umilib_ffi_Buffer* out);

/**
 * Reads the server-final-message at `message`: succeeds if the server proved it knows the key.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_client_receive_server_final(umilib_auth_sasl_scram_SCRAMClient* client, const uint8_t* message, size_t length);

/**
 * Writes whether the exchange succeeded into `out_has` and, if so, the salt into `out_salt`,
 * the iteration count into `out_iterations` and the SaltedPassword into `out`, to keep.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_client_salted_secret(const umilib_auth_sasl_scram_SCRAMClient* client, bool* out_has, umilib_ffi_Buffer* out_salt, uint32_t* out_iterations, umilib_ffi_Buffer* out);

/**
 * Writes a copy of `client` into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_client_clone(const umilib_auth_sasl_scram_SCRAMClient* client, umilib_auth_sasl_scram_SCRAMClient** out);

/**
 * Releases a client, zeroizing its secrets. Does nothing if `client` is null.
 */
void umilib_auth_sasl_scram_scram_client_free(umilib_auth_sasl_scram_SCRAMClient* client);

/**
 * Writes the server over the hash function named by `hash`, for the `-PLUS` mechanism if `plus`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_server_new(const uint8_t* hash, size_t hash_length, bool plus, umilib_auth_sasl_scram_SCRAMServer** out);

/**
 * Adds the channel binding type named by the UTF-8 text at `name` with its data at `data`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_server_add_channel_binding(umilib_auth_sasl_scram_SCRAMServer* server, const uint8_t* name, size_t name_length, const uint8_t* data, size_t data_length);

/**
 * Reads the client-first-message at `message`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_server_receive_client_first(umilib_auth_sasl_scram_SCRAMServer* server, const uint8_t* message, size_t length);

/**
 * Writes the username (prepared with SASLprep), once the client-first-message is read, into `out_has` and `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_server_username(const umilib_auth_sasl_scram_SCRAMServer* server, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Writes the authorization identity of the client-first-message, if any, into `out_has` and `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_server_authzid(const umilib_auth_sasl_scram_SCRAMServer* server, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Writes the server-first-message for the user's `credentials` (of the same hash function) and
 * the server's part of the nonce at `nonce` into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_server_server_first(umilib_auth_sasl_scram_SCRAMServer* server, const umilib_auth_sasl_scram_SCRAMCredentials* credentials, const uint8_t* nonce, size_t nonce_length, umilib_ffi_Buffer* out);

/**
 * Reads the client-final-message at `message` and writes the server-final-message into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_server_receive_client_final(umilib_auth_sasl_scram_SCRAMServer* server, const uint8_t* message, size_t length, umilib_ffi_Buffer* out);

/**
 * Ends the exchange with the server error at `index` and writes the server-final-message that reports it into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_server_reject(umilib_auth_sasl_scram_SCRAMServer* server, uint8_t index, umilib_ffi_Buffer* out);

/**
 * Writes a copy of `server` into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_server_clone(const umilib_auth_sasl_scram_SCRAMServer* server, umilib_auth_sasl_scram_SCRAMServer** out);

/**
 * Releases a server, zeroizing its keys. Does nothing if `server` is null.
 */
void umilib_auth_sasl_scram_scram_server_free(umilib_auth_sasl_scram_SCRAMServer* server);

/**
 * Writes the credentials of the password at `password` with the salt at `salt` and `iterations`
 * over the hash function named by `hash` into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_credentials_new(const uint8_t* hash, size_t hash_length, const uint8_t* password, size_t password_length, const uint8_t* salt, size_t salt_length, uint32_t iterations, umilib_auth_sasl_scram_SCRAMCredentials** out);

/**
 * Writes the credentials of their stored parts into `out`; fails with Format for keys of another size than the hash output.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_credentials_from_parts(const uint8_t* hash, size_t hash_length, const uint8_t* salt, size_t salt_length, uint32_t iterations, const uint8_t* stored_key, size_t stored_key_length, const uint8_t* server_key, size_t server_key_length, umilib_auth_sasl_scram_SCRAMCredentials** out);

/**
 * Writes the salt into `out_salt`, the iteration count into `out_iterations`, StoredKey into
 * `out_stored_key` and ServerKey into `out_server_key`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_credentials_parts(const umilib_auth_sasl_scram_SCRAMCredentials* credentials, umilib_ffi_Buffer* out_salt, uint32_t* out_iterations, umilib_ffi_Buffer* out_stored_key, umilib_ffi_Buffer* out_server_key);

/**
 * Writes a copy of `credentials` into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_scram_scram_credentials_clone(const umilib_auth_sasl_scram_SCRAMCredentials* credentials, umilib_auth_sasl_scram_SCRAMCredentials** out);

/**
 * Releases credentials, zeroizing ServerKey. Does nothing if `credentials` is null.
 */
void umilib_auth_sasl_scram_scram_credentials_free(umilib_auth_sasl_scram_SCRAMCredentials* credentials);

#ifdef __cplusplus
}
#endif

#endif
