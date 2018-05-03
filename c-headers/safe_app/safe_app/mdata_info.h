// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appmdata_infoh
#define bindgen_safe_appmdata_infoh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Create encrypted mdata info with explicit data name and a
/// provided private key.
///
/// Callback parameters: user data, error code, mdata info handle
void mdata_info_new_private(XorNameArray const* name, uint64_t type_tag, SymSecretKey const* secret_key, SymNonce const* nonce, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataInfo const* mdata_info));

/// Create random, non-encrypted mdata info.
///
/// Callback parameters: user data, error code, mdata info handle
void mdata_info_random_public(uint64_t type_tag, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataInfo const* mdata_info));

/// Create random, encrypted mdata info.
///
/// Callback parameters: user data, error code, mdata info handle
void mdata_info_random_private(uint64_t type_tag, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataInfo const* mdata_info));

/// Encrypt mdata entry key using the corresponding mdata info.
///
/// Callback parameters: user data, error code, encrypted entry key vector, vector size
void mdata_info_encrypt_entry_key(MDataInfo const* info, uint8_t const* input, uintptr_t input_len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* enc_entry_key, uintptr_t enc_entry_key_len));

/// Encrypt mdata entry value using the corresponding mdata info.
///
/// Callback parameters: user data, error code, encrypted entry value vector, vector size
void mdata_info_encrypt_entry_value(MDataInfo const* info, uint8_t const* input, uintptr_t input_len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* enc_entry_value, uintptr_t enc_entry_value_len));

/// Decrypt mdata entry value or a key using the corresponding mdata info.
///
/// Callback parameters: user data, error code, decrypted mdata info vector, vector size
void mdata_info_decrypt(MDataInfo const* info, uint8_t const* input, uintptr_t input_len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* mdata_info_decrypt, uintptr_t mdata_info_decrypt_len));

/// Serialise `MDataInfo`.
///
/// Callback parameters: user data, error code, serialised mdata info
void mdata_info_serialise(MDataInfo const* info, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* encoded, uintptr_t encoded_len));

/// Deserialise `MDataInfo`.
///
/// Callback parameters: user data, error code, mdata info handle
void mdata_info_deserialise(uint8_t const* encoded_ptr, uintptr_t encoded_len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataInfo const* mdata_info));



#ifdef __cplusplus
}
#endif


#endif
