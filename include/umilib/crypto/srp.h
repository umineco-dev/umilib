/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_SRP_H
#define UMILIB_CRYPTO_SRP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The client of SRP (RFC 5054), of any group and hash function, with its secret exponent.
 */
typedef struct umilib_crypto_srp_SRPClient umilib_crypto_srp_SRPClient;

/**
 * The server of SRP (RFC 5054), of any group and hash function, with its verifier and secret exponent.
 */
typedef struct umilib_crypto_srp_SRPServer umilib_crypto_srp_SRPServer;

/**
 * Writes the verifier v = g^x % N of the user `identity` with `password` and `salt` (RFC 5054 section
 * 2.4), without leading zeros, into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_srp_srp_verifier(const uint8_t* group, size_t group_length, const uint8_t* hash, size_t hash_length, const uint8_t* salt, size_t salt_length, const uint8_t* identity, size_t identity_length, const uint8_t* password, size_t password_length, umilib_ffi_Buffer* out);

/**
 * Creates the client of the secret exponent a; fails with InvalidKey for a = 0 or more bytes than N.
 */
const umilib_ffi_Status* umilib_crypto_srp_srp_client_new(const uint8_t* group, size_t group_length, const uint8_t* hash, size_t hash_length, const uint8_t* secret, size_t secret_length, umilib_crypto_srp_SRPClient** out);

/**
 * Creates a client with a random exponent from the generator handle `random` of the type named by
 * `random_type`.
 */
const umilib_ffi_Status* umilib_crypto_srp_srp_client_generate(const uint8_t* group, size_t group_length, const uint8_t* hash, size_t hash_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_crypto_srp_SRPClient** out);

/**
 * Releases the client, zeroizing its secret. Does nothing if it is null.
 */
void umilib_crypto_srp_srp_client_free(umilib_crypto_srp_SRPClient* client);

/**
 * Writes A, as the client sends it (without leading zeros), into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_srp_srp_client_public_value(const umilib_crypto_srp_SRPClient* client, umilib_ffi_Buffer* out);

/**
 * Writes the premaster secret of section 2.6 for the user `identity` with `password` and the salt and B
 * of the server into a new buffer; fails with InvalidKey for B % N = 0 or u = 0.
 */
const umilib_ffi_Status* umilib_crypto_srp_srp_client_premaster_secret(const umilib_crypto_srp_SRPClient* client, const uint8_t* identity, size_t identity_length, const uint8_t* password, size_t password_length, const uint8_t* salt, size_t salt_length, const uint8_t* server_public, size_t server_public_length, umilib_ffi_Buffer* out);

/**
 * Creates the server of the verifier and the secret exponent b; fails with InvalidKey for b = 0, v % N
 * = 0 or values longer than N.
 */
const umilib_ffi_Status* umilib_crypto_srp_srp_server_new(const uint8_t* group, size_t group_length, const uint8_t* hash, size_t hash_length, const uint8_t* verifier, size_t verifier_length, const uint8_t* secret, size_t secret_length, umilib_crypto_srp_SRPServer** out);

/**
 * Creates a server of the verifier with a random exponent from the generator handle `random` of the type
 * named by `random_type`.
 */
const umilib_ffi_Status* umilib_crypto_srp_srp_server_generate(const uint8_t* group, size_t group_length, const uint8_t* hash, size_t hash_length, const uint8_t* verifier, size_t verifier_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_crypto_srp_SRPServer** out);

/**
 * Releases the server, zeroizing its secret. Does nothing if it is null.
 */
void umilib_crypto_srp_srp_server_free(umilib_crypto_srp_SRPServer* server);

/**
 * Writes B, as the server sends it (without leading zeros), into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_srp_srp_server_public_value(const umilib_crypto_srp_SRPServer* server, umilib_ffi_Buffer* out);

/**
 * Writes the premaster secret of section 2.6 for the client's A into a new buffer; fails with InvalidKey
 * for A % N = 0 or u = 0.
 */
const umilib_ffi_Status* umilib_crypto_srp_srp_server_premaster_secret(const umilib_crypto_srp_SRPServer* server, const uint8_t* client_public, size_t client_public_length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
