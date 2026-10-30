/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_SM9_H
#define UMILIB_CRYPTO_SM9_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The encryption master key of a KGC of SM9 (ke and Ppub-e), which keeps its curve.
 */
typedef struct umilib_crypto_sm9_SM9EncryptMasterKey umilib_crypto_sm9_SM9EncryptMasterKey;

/**
 * The encryption key of a user of SM9 (its identity, hid, de and Ppub-e), which keeps its curve.
 */
typedef struct umilib_crypto_sm9_SM9EncryptUserKey umilib_crypto_sm9_SM9EncryptUserKey;

/**
 * One side of the key exchange of SM9 (GM/T 0044.3), which keeps its curve and hash function.
 */
typedef struct umilib_crypto_sm9_SM9KEP umilib_crypto_sm9_SM9KEP;

/**
 * Writes the sizes in bytes of a scalar (ke, r), a point of G_1 (x || y: Ppub-e, R, C), a point of G_2
 * (04 || x || y: de) and an output of the hash function (C3, S_A, S_B) on the curve named by `curve` with
 * the hash function named by `hash` into `sizes` (four elements).
 */
const umilib_ffi_Status* umilib_crypto_sm9_sizes(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, size_t* sizes);

/**
 * Creates the master key of ke (big-endian, 1 ≤ ke < N) on the curve named by `curve`; fails with
 * InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9_encrypt_master_key_new(const uint8_t* curve, size_t curve_length, const uint8_t* secret, size_t secret_length, umilib_crypto_sm9_SM9EncryptMasterKey** out);

/**
 * Creates a master key on the curve named by `curve` with ke drawn from the generator handle `random`,
 * whose C type is named by `random_type`.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9_encrypt_master_key_generate(const uint8_t* curve, size_t curve_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_crypto_sm9_SM9EncryptMasterKey** out);

/**
 * Releases the master key, zeroizing ke. Does nothing if it is null.
 */
void umilib_crypto_sm9_sm9_encrypt_master_key_free(umilib_crypto_sm9_SM9EncryptMasterKey* key);

/**
 * Writes ke into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9_encrypt_master_key_secret(const umilib_crypto_sm9_SM9EncryptMasterKey* key, umilib_ffi_Buffer* out);

/**
 * Writes Ppub-e (x || y) into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9_encrypt_master_key_public_key(const umilib_crypto_sm9_SM9EncryptMasterKey* key, umilib_ffi_Buffer* out);

/**
 * Creates the key of `identity` and the identifier `hid` with H1 of the hash function named by `hash`;
 * fails with InvalidParameter if t1 = 0, when the master key must be generated again.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9_encrypt_master_key_extract(const umilib_crypto_sm9_SM9EncryptMasterKey* key, const uint8_t* hash, size_t hash_length, const uint8_t* identity, size_t identity_length, uint8_t hid, umilib_crypto_sm9_SM9EncryptUserKey** out);

/**
 * Creates the key de (04 || x || y) of `identity` and `hid` under Ppub-e `master` (x || y) on the curve
 * named by `curve`; fails with InvalidKey unless both are points of their groups other than the identity.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9_encrypt_user_key_new(const uint8_t* curve, size_t curve_length, const uint8_t* identity, size_t identity_length, uint8_t hid, const uint8_t* key, size_t key_length, const uint8_t* master, size_t master_length, umilib_crypto_sm9_SM9EncryptUserKey** out);

/**
 * Releases the key, zeroizing de. Does nothing if it is null.
 */
void umilib_crypto_sm9_sm9_encrypt_user_key_free(umilib_crypto_sm9_SM9EncryptUserKey* key);

/**
 * Writes the identity of the key into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9_encrypt_user_key_identity(const umilib_crypto_sm9_SM9EncryptUserKey* key, umilib_ffi_Buffer* out);

/**
 * The identifier hid of the key.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9_encrypt_user_key_hid(const umilib_crypto_sm9_SM9EncryptUserKey* key, uint8_t* out);

/**
 * Writes de (04 || x || y) into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9_encrypt_user_key_key(const umilib_crypto_sm9_SM9EncryptUserKey* key, umilib_ffi_Buffer* out);

/**
 * Writes Ppub-e (x || y) of the key into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9_encrypt_user_key_master(const umilib_crypto_sm9_SM9EncryptUserKey* key, umilib_ffi_Buffer* out);

/**
 * Creates the side of `role` for the user of `key` with the user `peer_identity`, the hash function named
 * by `hash` and r (big-endian, 1 ≤ r < N) `ephemeral`, which must be secret, random and used once.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9kep_new(const umilib_crypto_sm9_SM9EncryptUserKey* key, const uint8_t* hash, size_t hash_length, uint8_t role, const uint8_t* peer_identity, size_t peer_identity_length, const uint8_t* ephemeral, size_t ephemeral_length, umilib_crypto_sm9_SM9KEP** out);

/**
 * Creates the side of `role` with r drawn from the generator handle `random` of the type named by
 * `random_type`.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9kep_generate(const umilib_crypto_sm9_SM9EncryptUserKey* key, const uint8_t* hash, size_t hash_length, uint8_t role, const uint8_t* peer_identity, size_t peer_identity_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_crypto_sm9_SM9KEP** out);

/**
 * Releases the side, zeroizing r and the key. Does nothing if it is null.
 */
void umilib_crypto_sm9_sm9kep_free(umilib_crypto_sm9_SM9KEP* side);

/**
 * Writes R (x || y), which the side sends to the other, into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9kep_ephemeral_public_key(const umilib_crypto_sm9_SM9KEP* side, umilib_ffi_Buffer* out);

/**
 * Writes SK of the other side's R (x || y) into `key_out` (klen / 8 bytes) and the confirmations S_B into
 * `responder` and S_A into `initiator` (each of the bytes of the hash function); fails with InvalidKey
 * unless R is a point of G_1 other than the identity.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9kep_agree(const umilib_crypto_sm9_SM9KEP* side, const uint8_t* peer_ephemeral, size_t peer_ephemeral_length, uint8_t* key_out, size_t key_out_length, uint8_t* responder, size_t responder_length, uint8_t* initiator, size_t initiator_length);

/**
 * Writes K for `identity` and `hid` under Ppub-e `master` (x || y) into `key_out` (klen / 8 bytes, not
 * empty) and C (x || y) into `encapsulated`, on the curve named by `curve` with the hash function named
 * by `hash` and r drawn from the generator handle `random` of the type named by `random_type`.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9kem_encapsulate(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* master, size_t master_length, const uint8_t* identity, size_t identity_length, uint8_t hid, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* key_out, size_t key_out_length, uint8_t* encapsulated, size_t encapsulated_length);

/**
 * The encapsulation with r (big-endian, 1 ≤ r < N) `ephemeral`, which must be secret, random and used
 * once; fails with InvalidParameter if K is zero, when another r is needed.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9kem_encapsulate_with_ephemeral(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* master, size_t master_length, const uint8_t* identity, size_t identity_length, uint8_t hid, const uint8_t* ephemeral, size_t ephemeral_length, uint8_t* key_out, size_t key_out_length, uint8_t* encapsulated, size_t encapsulated_length);

/**
 * Writes K of C (x || y) `encapsulated` for `key` into `key_out` (klen / 8 bytes, not empty), with the
 * hash function named by `hash`; fails with InvalidKey unless C is a point of G_1 other than the identity
 * and with DecryptionFailed if K is zero.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9kem_decapsulate(const umilib_crypto_sm9_SM9EncryptUserKey* key, const uint8_t* hash, size_t hash_length, const uint8_t* encapsulated, size_t encapsulated_length, uint8_t* key_out, size_t key_out_length);

/**
 * Writes the ciphertext C1 || C3 || C2 of `message` for `identity` and `hid` under Ppub-e `master`
 * (x || y) into a new buffer, on the curve named by `curve` with the hash function named by `hash`, the
 * cipher named by `cipher` (`umilib_crypto_sm9_SM9StreamCipher` or a block cipher in CBC mode) and r
 * drawn from the generator handle `random` of the type named by `random_type`.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9pke_encrypt(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* cipher, size_t cipher_length, const uint8_t* master, size_t master_length, const uint8_t* identity, size_t identity_length, uint8_t hid, const uint8_t* message, size_t message_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * The encryption with r (big-endian, 1 ≤ r < N) `ephemeral`, which must be secret, random and used once;
 * fails with InvalidParameter if K1 is zero, when another r is needed.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9pke_encrypt_with_ephemeral(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* cipher, size_t cipher_length, const uint8_t* master, size_t master_length, const uint8_t* identity, size_t identity_length, uint8_t hid, const uint8_t* message, size_t message_length, const uint8_t* ephemeral, size_t ephemeral_length, umilib_ffi_Buffer* out);

/**
 * Writes the message of `ciphertext` for `key` into a new buffer, with the hash function named by `hash`
 * and the cipher named by `cipher`; fails with DecryptionFailed for every invalid ciphertext.
 */
const umilib_ffi_Status* umilib_crypto_sm9_sm9pke_decrypt(const umilib_crypto_sm9_SM9EncryptUserKey* key, const uint8_t* hash, size_t hash_length, const uint8_t* cipher, size_t cipher_length, const uint8_t* ciphertext, size_t ciphertext_length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
