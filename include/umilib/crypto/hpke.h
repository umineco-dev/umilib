/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_HPKE_H
#define UMILIB_CRYPTO_HPKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The context of a sender of HPKE (RFC 9180 section 5.2), of any suite: it seals and exports.
 */
typedef struct umilib_crypto_hpke_HPKESenderContext umilib_crypto_hpke_HPKESenderContext;

/**
 * The context of a receiver of HPKE (RFC 9180 section 5.2), of any suite: it opens and exports.
 */
typedef struct umilib_crypto_hpke_HPKEReceiverContext umilib_crypto_hpke_HPKEReceiverContext;

/**
 * Writes Nenc, Npk and Nsk, the sizes in bytes of an enc, a public key and a private key of the KEM `kem`,
 * into `sizes` (three elements).
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_sizes(uint16_t kem, size_t* sizes);

/**
 * GenerateKeyPair() of the KEM `kem` from the generator handle `random` of the type named by
 * `random_type`: writes the private key into `private_key` of Nsk bytes and the public key into `public_key` of
 * Npk bytes.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_generate_key_pair(uint16_t kem, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* private_key, size_t private_key_length, uint8_t* public_key, size_t public_key_length);

/**
 * DeriveKeyPair(ikm) of the KEM `kem` (section 7.1.3): writes the private key into `private_key` of Nsk
 * bytes and the public key into `public_key` of Npk bytes.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_derive_key_pair(uint16_t kem, const uint8_t* ikm, size_t ikm_length, uint8_t* private_key, size_t private_key_length, uint8_t* public_key, size_t public_key_length);

/**
 * Succeeds if the private key is one of the KEM `kem` (DeserializePrivateKey of section 7.1.2); fails with
 * InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_check_private_key(uint16_t kem, const uint8_t* private_key, size_t private_key_length);

/**
 * Succeeds if the public key is one of the KEM `kem` (DeserializePublicKey and the validation of
 * section 7.1.4); fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_check_public_key(uint16_t kem, const uint8_t* public_key, size_t public_key_length);

/**
 * Writes the public key of the private key of the KEM `kem` into `out` of Npk bytes.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_public_key(uint16_t kem, const uint8_t* private_key, size_t private_key_length, uint8_t* out, size_t out_length);

/**
 * SetupBaseS, SetupPSKS, SetupAuthS or SetupAuthPSKS (section 5.1) of the suite for the public key
 * `recipient`, with an ephemeral key from the generator handle `random` of the type named by
 * `random_type`: writes enc into `encapsulated` of Nenc bytes and creates the sender's context.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_setup_sender(uint16_t kem, uint16_t kdf, uint16_t aead, const uint8_t* recipient, size_t recipient_length, const uint8_t* info, size_t info_length, const uint8_t* psk, size_t psk_length, const uint8_t* psk_id, size_t psk_id_length, const uint8_t* sender, size_t sender_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* encapsulated, size_t encapsulated_length, umilib_crypto_hpke_HPKESenderContext** out);

/**
 * [`umilib_crypto_hpke_hpke_setup_sender`] with the encoded ephemeral private key `ephemeral` (as
 * DeriveKeyPair(ikmE) gives it in the test vectors of RFC 9180 appendix A). The key must be fresh and
 * secret.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_setup_sender_with_ephemeral(uint16_t kem, uint16_t kdf, uint16_t aead, const uint8_t* recipient, size_t recipient_length, const uint8_t* info, size_t info_length, const uint8_t* psk, size_t psk_length, const uint8_t* psk_id, size_t psk_id_length, const uint8_t* sender, size_t sender_length, const uint8_t* ephemeral, size_t ephemeral_length, uint8_t* encapsulated, size_t encapsulated_length, umilib_crypto_hpke_HPKESenderContext** out);

/**
 * SetupBaseR, SetupPSKR, SetupAuthR or SetupAuthPSKR (section 5.1) of the suite for the enc
 * `encapsulated` and the private key `recipient` (with the sender's public key in the auth modes):
 * creates the receiver's context.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_setup_receiver(uint16_t kem, uint16_t kdf, uint16_t aead, const uint8_t* encapsulated, size_t encapsulated_length, const uint8_t* recipient, size_t recipient_length, const uint8_t* info, size_t info_length, const uint8_t* psk, size_t psk_length, const uint8_t* psk_id, size_t psk_id_length, const uint8_t* sender, size_t sender_length, umilib_crypto_hpke_HPKEReceiverContext** out);

/**
 * Releases the sender's context, zeroizing its secrets. Does nothing if it is null.
 */
void umilib_crypto_hpke_hpke_sender_context_free(umilib_crypto_hpke_HPKESenderContext* context);

/**
 * Writes the sequence number of the next message into `out`.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_sender_context_sequence(const umilib_crypto_hpke_HPKESenderContext* context, uint64_t* out);

/**
 * ContextS.Seal(aad, pt) (section 5.2): writes the ciphertext with its tag into a new buffer. Fails with
 * InvalidParameter for the export-only AEAD and LimitExceeded after the last sequence number.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_sender_context_seal(umilib_crypto_hpke_HPKESenderContext* context, const uint8_t* associated, size_t associated_length, const uint8_t* plaintext, size_t plaintext_length, umilib_ffi_Buffer* out);

/**
 * Context.Export(exporter_context, L) (section 5.3) into `out` of L bytes.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_sender_context_export(const umilib_crypto_hpke_HPKESenderContext* context, const uint8_t* exporter_context, size_t exporter_context_length, uint8_t* out, size_t out_length);

/**
 * Releases the receiver's context, zeroizing its secrets. Does nothing if it is null.
 */
void umilib_crypto_hpke_hpke_receiver_context_free(umilib_crypto_hpke_HPKEReceiverContext* context);

/**
 * Writes the sequence number of the next message into `out`.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_receiver_context_sequence(const umilib_crypto_hpke_HPKEReceiverContext* context, uint64_t* out);

/**
 * ContextR.Open(aad, ct) (section 5.2): writes the plaintext into a new buffer. Fails with
 * AuthenticationFailed unless the ciphertext authenticates at the next sequence number, which then does
 * not advance.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_receiver_context_open(umilib_crypto_hpke_HPKEReceiverContext* context, const uint8_t* associated, size_t associated_length, const uint8_t* ciphertext, size_t ciphertext_length, umilib_ffi_Buffer* out);

/**
 * Context.Export(exporter_context, L) (section 5.3) into `out` of L bytes.
 */
const umilib_ffi_Status* umilib_crypto_hpke_hpke_receiver_context_export(const umilib_crypto_hpke_HPKEReceiverContext* context, const uint8_t* exporter_context, size_t exporter_context_length, uint8_t* out, size_t out_length);

#ifdef __cplusplus
}
#endif

#endif
