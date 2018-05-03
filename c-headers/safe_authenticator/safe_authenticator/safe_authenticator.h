// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_authenticatorsafe_authenticatorh
#define bindgen_safe_authenticatorsafe_authenticatorh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Create a registered client. This or any one of the other companion
/// functions to get an authenticator instance must be called before initiating any
/// operation allowed by this module. The `user_data` parameter corresponds to the
/// first parameter of the `o_cb` and `o_disconnect_notifier_cb` callbacks.
///
/// Callback parameters: user data, error code, authenticator
void create_acc(char const* account_locator, char const* account_password, char const* invitation, void* user_data, void (*o_disconnect_notifier_cb)(void* user_data), void (*o_cb)(void* user_data, FfiResult const* result, Authenticator* authenticator));

/// Log into a registered account. This or any one of the other companion
/// functions to get an authenticator instance must be called before initiating
/// any operation allowed for authenticator. The `user_data` parameter corresponds to the
/// first parameter of the `o_cb` and `o_disconnect_notifier_cb` callbacks.
///
/// Callback parameters: user data, error code, authenticator
void login(char const* account_locator, char const* account_password, void* user_data, void (*o_disconnect_notifier_cb)(void* user_data), void (*o_cb)(void* user_data, FfiResult const* result, Authenticator* authenticaor));

/// Try to restore a failed connection with the network.
///
/// Callback parameters: user data, error code
void auth_reconnect(Authenticator* auth, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Get the account usage statistics.
///
/// Callback parameters: user data, error code, account info
void auth_account_info(Authenticator* auth, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, AccountInfo const* account_info));

/// Returns the expected name for the application executable without an extension
void auth_exe_file_stem(void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* filename));

/// Sets the additional path in `config_file_handler` to search for files.
void auth_set_additional_search_path(char const* new_path, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Discard and clean up the previously allocated authenticator instance.
/// Use this only if the authenticator is obtained from one of the auth
/// functions in this crate (`create_acc` or `login`).
/// Using `auth` after a call to this function is undefined behaviour.
void auth_free(Authenticator* auth);



#ifdef __cplusplus
}
#endif


#endif
