/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_DRAGONFLY_H
#define UMILIB_CRYPTO_DRAGONFLY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The parameters of a Dragonfly exchange.
 */
typedef struct umilib_crypto_dragonfly_DragonflyConfig {
    uint32_t iterations;
} umilib_crypto_dragonfly_DragonflyConfig;

/**
 * A peer of a Dragonfly exchange (RFC 7664), of any curve and hash function.
 */
typedef struct umilib_crypto_dragonfly_DragonflyPeer umilib_crypto_dragonfly_DragonflyPeer;

/**
 * The default parameters: 40 rounds of hunting and pecking.
 */
umilib_crypto_dragonfly_DragonflyConfig umilib_crypto_dragonfly_dragonfly_config_default(void);

/**
 * Creates the peer `identity` of an exchange with `peer_identity` over the shared `password` (section
 * 3.3), on the curve named by `curve` with the hash function named by `hash`, its secrets drawn from the
 * generator handle `random` of the type named by `random_type`. Fails with InvalidParameter when no
 * password element is found within the rounds of `config`.
 */
const umilib_ffi_Status* umilib_crypto_dragonfly_dragonfly_peer_new(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const umilib_crypto_dragonfly_DragonflyConfig* config, const uint8_t* identity, size_t identity_length, const uint8_t* peer_identity, size_t peer_identity_length, const uint8_t* password, size_t password_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_crypto_dragonfly_DragonflyPeer** out);

/**
 * Releases the peer, zeroizing its secrets. Does nothing if it is null.
 */
void umilib_crypto_dragonfly_dragonfly_peer_free(umilib_crypto_dragonfly_DragonflyPeer* peer);

/**
 * Writes the peer's commit, to send to the other peer, into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_dragonfly_dragonfly_peer_commit(const umilib_crypto_dragonfly_DragonflyPeer* peer, umilib_ffi_Buffer* out);

/**
 * Processes the commit of the other peer (section 3.4) and writes the peer's confirm, to send to the
 * other peer, into a new buffer. Fails with InvalidKey for a commit that is invalid or a reflection of
 * the peer's own.
 */
const umilib_ffi_Status* umilib_crypto_dragonfly_dragonfly_peer_process(umilib_crypto_dragonfly_DragonflyPeer* peer, const uint8_t* commit, size_t commit_length, umilib_ffi_Buffer* out);

/**
 * Checks the confirm of the other peer and writes the master key into a new buffer. Fails with
 * AuthenticationFailed for a wrong confirm and InvalidParameter before
 * [`umilib_crypto_dragonfly_dragonfly_peer_process`].
 */
const umilib_ffi_Status* umilib_crypto_dragonfly_dragonfly_peer_finish(const umilib_crypto_dragonfly_DragonflyPeer* peer, const uint8_t* confirm, size_t confirm_length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
