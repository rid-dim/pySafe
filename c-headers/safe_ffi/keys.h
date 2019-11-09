// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_ffikeysh
#define bindgen_safe_ffikeysh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

void generate_keypair(Safe* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, BlsKeyPair const* safe_key));

void keys_create(Safe* app, char const* from, char const* preload, char const* pk, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* xorurl, BlsKeyPair const* safe_key));

void keys_create_preload_test_coins(Safe* app, char const* preload, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* xorurl, BlsKeyPair const* safe_key));

void keys_balance_from_sk(Safe* app, char const* sk, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* balance));

void keys_balance_from_url(Safe* app, char const* url, char const* sk, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* balance));

void validate_sk_for_url(Safe* app, char const* sk, char const* url, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* balance));

void keys_transfer(Safe* app, char const* amount, char const* from, char const* to, uint64_t id, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t tx_id));



#ifdef __cplusplus
}
#endif


#endif
