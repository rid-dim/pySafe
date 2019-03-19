// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appcryptoh
#define bindgen_safe_appcryptoh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Get the public signing key of the app.
void app_pub_sign_key(App const* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, SignPubKeyHandle handle));

/// Generate a new sign key pair (public & private key).
void sign_generate_key_pair(App const* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, SignPubKeyHandle public_key_h, SignSecKeyHandle secret_key_h));

/// Create new public signing key from raw array.
void sign_pub_key_new(App const* app, SignPublicKey const* data, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, SignPubKeyHandle handle));

/// Retrieve the public signing key as a raw array.
void sign_pub_key_get(App const* app, SignPubKeyHandle handle, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, SignPublicKey const* pub_sign_key));

/// Free public signing key from memory.
void sign_pub_key_free(App const* app, SignPubKeyHandle handle, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Create new secret signing key from raw array.
void sign_sec_key_new(App const* app, SignSecretKey const* data, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, SignSecKeyHandle handle));

/// Retrieve the secret signing key as a raw array.
void sign_sec_key_get(App const* app, SignSecKeyHandle handle, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, SignSecretKey const* pub_sign_key));

/// Free secret signing key from memory.
void sign_sec_key_free(App const* app, SignSecKeyHandle handle, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Get the public encryption key of the app.
void app_pub_enc_key(App const* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, EncryptPubKeyHandle public_key_h));

/// Generate a new encryption key pair (public & private key).
void enc_generate_key_pair(App const* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, EncryptPubKeyHandle public_key_h, EncryptSecKeyHandle secret_key_h));

/// Create new public encryption key from raw array.
void enc_pub_key_new(App const* app, AsymPublicKey const* data, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, EncryptPubKeyHandle public_key_h));

/// Retrieve the public encryption key as a raw array.
void enc_pub_key_get(App const* app, EncryptPubKeyHandle handle, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, AsymPublicKey const* pub_enc_key));

/// Free encryption key from memory.
void enc_pub_key_free(App const* app, EncryptPubKeyHandle handle, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Create new private encryption key from raw array.
void enc_secret_key_new(App const* app, AsymSecretKey const* data, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, EncryptSecKeyHandle sk_h));

/// Retrieve the private encryption key as a raw array.
void enc_secret_key_get(App const* app, EncryptSecKeyHandle handle, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, AsymSecretKey const* sec_enc_key));

/// Free private key from memory.
void enc_secret_key_free(App const* app, EncryptSecKeyHandle handle, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Signs arbitrary data using a given secret sign key.
///
/// If `sign_sk_h` is `SIGN_WITH_APP`, then uses the app's own secret key to sign.
void sign(App const* app, uint8_t const* data, uintptr_t data_len, SignSecKeyHandle sign_sk_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* signed_data, uintptr_t signed_data_len));

/// Verifies signed data using a given public sign key.
/// Returns an error if the message could not be verified.
void verify(App const* app, uint8_t const* signed_data, uintptr_t signed_data_len, SignPubKeyHandle sign_pk_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* verified_data, uintptr_t verified_data_len));

/// Encrypts arbitrary data using a given key pair.
/// You should provide a recipient's public key and a sender's secret key.
void encrypt(App const* app, uint8_t const* data, uintptr_t data_len, EncryptPubKeyHandle public_key_h, EncryptSecKeyHandle secret_key_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* ciphertext, uintptr_t ciphertext_len));

/// Decrypts arbitrary data using a given key pair.
/// You should provide a sender's public key and a recipient's secret key.
void decrypt(App const* app, uint8_t const* data, uintptr_t data_len, EncryptPubKeyHandle public_key_h, EncryptSecKeyHandle secret_key_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* plaintext, uintptr_t plaintext_len));

/// Encrypts arbitrary data for a single recipient.
/// You should provide a recipient's public key.
void encrypt_sealed_box(App const* app, uint8_t const* data, uintptr_t data_len, EncryptPubKeyHandle public_key_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* ciphertext, uintptr_t ciphertext_len));

/// Decrypts arbitrary data for a single recipient.
/// You should provide a recipients's private and public key.
void decrypt_sealed_box(App const* app, uint8_t const* data, uintptr_t data_len, EncryptPubKeyHandle public_key_h, EncryptSecKeyHandle secret_key_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* plaintext, uintptr_t plaintext_len));

/// Returns a sha3 hash for a given data.
void sha3_hash(uint8_t const* data, uintptr_t data_len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* hash, uintptr_t hash_len));

/// Generates a unique nonce and returns the result.
void generate_nonce(void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, AsymNonce const* nonce));



#ifdef __cplusplus
}
#endif


#endif
