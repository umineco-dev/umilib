/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_RANDOM_H
#define UMILIB_CRYPTO_RANDOM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The limits of a deterministic random bit generator.
 */
typedef struct umilib_crypto_random_DRBGConfig {
    uint64_t reseed_interval;
    size_t maximum_request;
} umilib_crypto_random_DRBGConfig;

/**
 * HMAC_DRBG (SP 800-90A) over a hash function chosen when it is instantiated.
 */
typedef struct umilib_crypto_random_HMACDRBG umilib_crypto_random_HMACDRBG;

/**
 * Hash_DRBG (SP 800-90A) over a hash function chosen when it is instantiated.
 */
typedef struct umilib_crypto_random_HashDRBG umilib_crypto_random_HashDRBG;

/**
 * CTR_DRBG (SP 800-90A) over a 128-bit block cipher chosen when it is instantiated.
 */
typedef struct umilib_crypto_random_CTRDRBG umilib_crypto_random_CTRDRBG;

/**
 * Returns the limits of SP 800-90A table 2: 2^48 requests between reseeds, 2^16 bytes per request.
 */
umilib_crypto_random_DRBGConfig umilib_crypto_random_drbg_config_default(void);

/**
 * Returns `config` with every limit within SP 800-90A table 2.
 */
umilib_crypto_random_DRBGConfig umilib_crypto_random_drbg_config_clamped(umilib_crypto_random_DRBGConfig config);

/**
 * Instantiates the generator with the default limits over the hash function whose C type
 * is named by the UTF-8 text at `hash`, with the entropy input, the nonce and the
 * personalization string; fails with InvalidArgument if that hash function is unknown or
 * not enabled, with EntropyLength if the entropy input is shorter than the security
 * strength, and with NonceLength if the nonce with it is shorter than 3/2 of it.
 */
const umilib_ffi_Status* umilib_crypto_random_hmac_drbg_new(const uint8_t* hash, size_t hash_length, const uint8_t* entropy, size_t entropy_length, const uint8_t* nonce, size_t nonce_length, const uint8_t* personalization, size_t personalization_length, umilib_crypto_random_HMACDRBG** out);

/**
 * Like `_new` with the limits `config`, clamped to SP 800-90A table 2.
 */
const umilib_ffi_Status* umilib_crypto_random_hmac_drbg_with_config(const uint8_t* hash, size_t hash_length, const umilib_crypto_random_DRBGConfig* config, const uint8_t* entropy, size_t entropy_length, const uint8_t* nonce, size_t nonce_length, const uint8_t* personalization, size_t personalization_length, umilib_crypto_random_HMACDRBG** out);

/**
 * Releases the generator, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_random_hmac_drbg_free(umilib_crypto_random_HMACDRBG* state);

/**
 * Mixes the fresh entropy input and the optional additional input into the state.
 */
const umilib_ffi_Status* umilib_crypto_random_hmac_drbg_reseed(umilib_crypto_random_HMACDRBG* state, const uint8_t* entropy, size_t entropy_length, const uint8_t* additional, size_t additional_length);

/**
 * Fills the `out_length` bytes at `out` with one request, with the optional additional input,
 * which must not overlap `out`.
 */
const umilib_ffi_Status* umilib_crypto_random_hmac_drbg_generate(umilib_crypto_random_HMACDRBG* state, uint8_t* out, size_t out_length, const uint8_t* additional, size_t additional_length);

/**
 * Fills the `out_length` bytes at `out`, of any length, with requests of the maximum size.
 */
const umilib_ffi_Status* umilib_crypto_random_hmac_drbg_fill(umilib_crypto_random_HMACDRBG* state, uint8_t* out, size_t out_length);

/**
 * Erases the state; every later `_reseed`, `_generate` and `_fill` fails with Uninstantiated.
 */
const umilib_ffi_Status* umilib_crypto_random_hmac_drbg_uninstantiate(umilib_crypto_random_HMACDRBG* state);

/**
 * Writes whether the generator is instantiated into `out`.
 */
const umilib_ffi_Status* umilib_crypto_random_hmac_drbg_is_instantiated(const umilib_crypto_random_HMACDRBG* state, bool* out);

/**
 * Writes the limits of the generator into `out`.
 */
const umilib_ffi_Status* umilib_crypto_random_hmac_drbg_config(const umilib_crypto_random_HMACDRBG* state, umilib_crypto_random_DRBGConfig* out);

/**
 * Writes the security strength in bits into `out`.
 */
const umilib_ffi_Status* umilib_crypto_random_hmac_drbg_security_strength(const umilib_crypto_random_HMACDRBG* state, size_t* out);

/**
 * Instantiates the generator with the default limits over the hash function whose C type
 * is named by the UTF-8 text at `hash`, with the entropy input, the nonce and the
 * personalization string; fails with InvalidArgument if that hash function is unknown or
 * not enabled, with EntropyLength if the entropy input is shorter than the security
 * strength, and with NonceLength if the nonce with it is shorter than 3/2 of it.
 */
const umilib_ffi_Status* umilib_crypto_random_hash_drbg_new(const uint8_t* hash, size_t hash_length, const uint8_t* entropy, size_t entropy_length, const uint8_t* nonce, size_t nonce_length, const uint8_t* personalization, size_t personalization_length, umilib_crypto_random_HashDRBG** out);

/**
 * Like `_new` with the limits `config`, clamped to SP 800-90A table 2.
 */
const umilib_ffi_Status* umilib_crypto_random_hash_drbg_with_config(const uint8_t* hash, size_t hash_length, const umilib_crypto_random_DRBGConfig* config, const uint8_t* entropy, size_t entropy_length, const uint8_t* nonce, size_t nonce_length, const uint8_t* personalization, size_t personalization_length, umilib_crypto_random_HashDRBG** out);

/**
 * Releases the generator, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_random_hash_drbg_free(umilib_crypto_random_HashDRBG* state);

/**
 * Mixes the fresh entropy input and the optional additional input into the state.
 */
const umilib_ffi_Status* umilib_crypto_random_hash_drbg_reseed(umilib_crypto_random_HashDRBG* state, const uint8_t* entropy, size_t entropy_length, const uint8_t* additional, size_t additional_length);

/**
 * Fills the `out_length` bytes at `out` with one request, with the optional additional input,
 * which must not overlap `out`.
 */
const umilib_ffi_Status* umilib_crypto_random_hash_drbg_generate(umilib_crypto_random_HashDRBG* state, uint8_t* out, size_t out_length, const uint8_t* additional, size_t additional_length);

/**
 * Fills the `out_length` bytes at `out`, of any length, with requests of the maximum size.
 */
const umilib_ffi_Status* umilib_crypto_random_hash_drbg_fill(umilib_crypto_random_HashDRBG* state, uint8_t* out, size_t out_length);

/**
 * Erases the state; every later `_reseed`, `_generate` and `_fill` fails with Uninstantiated.
 */
const umilib_ffi_Status* umilib_crypto_random_hash_drbg_uninstantiate(umilib_crypto_random_HashDRBG* state);

/**
 * Writes whether the generator is instantiated into `out`.
 */
const umilib_ffi_Status* umilib_crypto_random_hash_drbg_is_instantiated(const umilib_crypto_random_HashDRBG* state, bool* out);

/**
 * Writes the limits of the generator into `out`.
 */
const umilib_ffi_Status* umilib_crypto_random_hash_drbg_config(const umilib_crypto_random_HashDRBG* state, umilib_crypto_random_DRBGConfig* out);

/**
 * Writes the security strength in bits into `out`.
 */
const umilib_ffi_Status* umilib_crypto_random_hash_drbg_security_strength(const umilib_crypto_random_HashDRBG* state, size_t* out);

/**
 * Instantiates the generator with the default limits over the 128-bit block cipher whose C type
 * is named by the UTF-8 text at `cipher`, with the entropy input, the nonce and the
 * personalization string; fails with InvalidArgument if that 128-bit block cipher is unknown or
 * not enabled, with EntropyLength if the entropy input is shorter than the security
 * strength, and with NonceLength if the nonce with it is shorter than 3/2 of it.
 */
const umilib_ffi_Status* umilib_crypto_random_ctr_drbg_new(const uint8_t* cipher, size_t cipher_length, const uint8_t* entropy, size_t entropy_length, const uint8_t* nonce, size_t nonce_length, const uint8_t* personalization, size_t personalization_length, umilib_crypto_random_CTRDRBG** out);

/**
 * Like `_new` with the limits `config`, clamped to SP 800-90A table 2.
 */
const umilib_ffi_Status* umilib_crypto_random_ctr_drbg_with_config(const uint8_t* cipher, size_t cipher_length, const umilib_crypto_random_DRBGConfig* config, const uint8_t* entropy, size_t entropy_length, const uint8_t* nonce, size_t nonce_length, const uint8_t* personalization, size_t personalization_length, umilib_crypto_random_CTRDRBG** out);

/**
 * Releases the generator, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_random_ctr_drbg_free(umilib_crypto_random_CTRDRBG* state);

/**
 * Mixes the fresh entropy input and the optional additional input into the state.
 */
const umilib_ffi_Status* umilib_crypto_random_ctr_drbg_reseed(umilib_crypto_random_CTRDRBG* state, const uint8_t* entropy, size_t entropy_length, const uint8_t* additional, size_t additional_length);

/**
 * Fills the `out_length` bytes at `out` with one request, with the optional additional input,
 * which must not overlap `out`.
 */
const umilib_ffi_Status* umilib_crypto_random_ctr_drbg_generate(umilib_crypto_random_CTRDRBG* state, uint8_t* out, size_t out_length, const uint8_t* additional, size_t additional_length);

/**
 * Fills the `out_length` bytes at `out`, of any length, with requests of the maximum size.
 */
const umilib_ffi_Status* umilib_crypto_random_ctr_drbg_fill(umilib_crypto_random_CTRDRBG* state, uint8_t* out, size_t out_length);

/**
 * Erases the state; every later `_reseed`, `_generate` and `_fill` fails with Uninstantiated.
 */
const umilib_ffi_Status* umilib_crypto_random_ctr_drbg_uninstantiate(umilib_crypto_random_CTRDRBG* state);

/**
 * Writes whether the generator is instantiated into `out`.
 */
const umilib_ffi_Status* umilib_crypto_random_ctr_drbg_is_instantiated(const umilib_crypto_random_CTRDRBG* state, bool* out);

/**
 * Writes the limits of the generator into `out`.
 */
const umilib_ffi_Status* umilib_crypto_random_ctr_drbg_config(const umilib_crypto_random_CTRDRBG* state, umilib_crypto_random_DRBGConfig* out);

/**
 * Writes the security strength in bits into `out`.
 */
const umilib_ffi_Status* umilib_crypto_random_ctr_drbg_security_strength(const umilib_crypto_random_CTRDRBG* state, size_t* out);

/**
 * Instantiates CTR_DRBG without the derivation function (SP 800-90A section 10.2.1.3.1) with
 * the limits `config` over the 128-bit block cipher whose C type is named by the UTF-8 text at
 * `cipher`: the entropy input has exactly seedlen bytes (16 and the key length) and the
 * personalization string at most seedlen.
 */
const umilib_ffi_Status* umilib_crypto_random_ctr_drbg_instantiate_without_derivation(const uint8_t* cipher, size_t cipher_length, const umilib_crypto_random_DRBGConfig* config, const uint8_t* entropy, size_t entropy_length, const uint8_t* personalization, size_t personalization_length, umilib_crypto_random_CTRDRBG** out);

#ifdef __cplusplus
}
#endif

#endif
