/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_SM2_H
#define UMILIB_CRYPTO_SM2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * One side of the key exchange of SM2 (GB/T 32918.3) on the curve of SM2 with SM3.
 */
typedef struct umilib_crypto_sm2_SM2KEP umilib_crypto_sm2_SM2KEP;

/**
 * Writes the sizes in bytes of a signing key, a verifying key and a signature of SM2DSA on the curve named by `curve` with the hash function named by `hash` into
 * `sizes` (three elements); fails with InvalidArgument for names that are unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2dsa_sizes(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, size_t* sizes);

/**
 * Generates a signing key from the generator handle `random`, whose C type is named by the UTF-8
 * text at `random_type` (such as `umilib_crypto_random_HMACDRBG`), and writes its encoding into
 * `out` of the size of a signing key.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2dsa_generate(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Writes the verifying key of the encoded signing key into `out` of the size of a verifying key.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2dsa_verifying_key(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the encoded signing key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2dsa_check_signing_key(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length);

/**
 * Succeeds if the encoded verifying key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2dsa_check_verifying_key(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length);

/**
 * Writes the signature of the message under the encoded signing key into `out` of the size of a signature.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2dsa_sign(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the signature is a signature of the message under the encoded verifying key; fails
 * with InvalidSignature otherwise and with InvalidKey for a key the scheme refuses.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2dsa_verify(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

/**
 * Writes the signature (r || s) of the message by the signer of the private key and the identity into
 * `out` of 64 bytes.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2dsa_sign_with_identity(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* identity, size_t identity_length, const uint8_t* message, size_t message_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the signature (r || s) is one of the message by the signer of the public key and the
 * identity; fails with InvalidSignature otherwise.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2dsa_verify_with_identity(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* identity, size_t identity_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

/**
 * Writes the signature r || s of the DER encoding into a new buffer; fails with InvalidSignature for
 * another encoding or values out of range.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2dsa_signature_from_der(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* der, size_t der_length, umilib_ffi_Buffer* out);

/**
 * Writes the DER encoding of the signature r || s into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2dsa_signature_to_der(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* signature, size_t signature_length, umilib_ffi_Buffer* out);

/**
 * The bytes a ciphertext of SM2PKE adds to its message: C1 (65) and C3 (32).
 */
size_t umilib_crypto_sm2_sm2pke_overhead(void);

/**
 * Writes the encryption of the message for the public key, in the order `order`, with the k of the
 * generator handle `random` of the type named by `random_type`, into `out` of the length of the
 * message plus the overhead.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2pke_encrypt(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, uint8_t order, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Writes the message of the ciphertext in the order `order` for the private key into `out` of the
 * length of the ciphertext minus the overhead; fails with DecryptionFailed for any invalid ciphertext.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2pke_decrypt(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* ciphertext, size_t ciphertext_length, uint8_t order, uint8_t* out, size_t out_length);

/**
 * Creates one side of the key exchange, of the role (0 initiator, 1 responder), the private key, the
 * identity and the ephemeral private key.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2kep_new(uint8_t role, const uint8_t* key, size_t key_length, const uint8_t* identity, size_t identity_length, const uint8_t* ephemeral, size_t ephemeral_length, umilib_crypto_sm2_SM2KEP** out);

/**
 * Creates one side of the key exchange with an ephemeral key of the generator handle `random`.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2kep_generate(uint8_t role, const uint8_t* key, size_t key_length, const uint8_t* identity, size_t identity_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_crypto_sm2_SM2KEP** out);

/**
 * Releases the side of the key exchange, zeroizing its keys. Does nothing if it is null.
 */
void umilib_crypto_sm2_sm2kep_free(umilib_crypto_sm2_SM2KEP* side);

/**
 * Writes the ephemeral public key R to send into `out` of 65 bytes (the uncompressed point).
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2kep_ephemeral_public_key(const umilib_crypto_sm2_SM2KEP* side, uint8_t* out, size_t out_length);

/**
 * Writes the shared key with the peer of the public key, the identity and the ephemeral public key
 * into `key_out`, and the confirmations S_B (0x02) into `responder` and S_A (0x03) into
 * `initiator` (32 bytes each); fails with InvalidKey if the shared point is the identity.
 */
const umilib_ffi_Status* umilib_crypto_sm2_sm2kep_agree(const umilib_crypto_sm2_SM2KEP* side, const uint8_t* peer, size_t peer_length, const uint8_t* peer_identity, size_t peer_identity_length, const uint8_t* peer_ephemeral, size_t peer_ephemeral_length, uint8_t* key_out, size_t key_out_length, uint8_t* responder, size_t responder_length, uint8_t* initiator, size_t initiator_length);

#ifdef __cplusplus
}
#endif

#endif
