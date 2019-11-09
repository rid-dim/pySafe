// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_ffiwalleth
#define bindgen_safe_ffiwalleth


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

void wallet_create(Safe* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* xorurl));

void wallet_insert(Safe* app, char const* key_url, char const* name, bool set_default, char const* secret_key, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* name));

void wallet_balance(Safe* app, char const* url, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* balance));

void wallet_get_default_balance(Safe* app, char const* url, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, WalletSpendableBalance const* spendable_wallet_balance, uint64_t version));

void wallet_transfer(Safe* app, char const* from, char const* to, char const* amount, uint64_t id, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t tx_id));

void wallet_get(Safe* app, char const* url, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, WalletSpendableBalances const* spendable_wallet_balance));



#ifdef __cplusplus
}
#endif


#endif
