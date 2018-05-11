// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appsafe_apph
#define bindgen_safe_appsafe_apph


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Create unregistered app.
/// The `user_data` parameter corresponds to the first parameter of the
/// `o_cb` and `o_disconnect_notifier_cb` callbacks.
///
/// Callback parameters: user data, error code, app
void app_unregistered(uint8_t const* bootstrap_config, uintptr_t bootstrap_config_len, void* user_data, void (*o_disconnect_notifier_cb)(void* user_data), void (*o_cb)(void* user_data, FfiResult const* result, App* app));

/// Create a registered app.
/// The `user_data` parameter corresponds to the first parameter of the
/// `o_cb` and `o_disconnect_notifier_cb` callbacks.
///
/// Callback parameters: user data, error code, app
void app_registered(char const* app_id, AuthGranted const* auth_granted, void* user_data, void (*o_disconnect_notifier_cb)(void* user_data), void (*o_cb)(void* user_data, FfiResult const* result, App* app));

/// Try to restore a failed connection with the network.
///
/// Callback parameters: user data, error code
void app_reconnect(App* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Get the account usage statistics (mutations done and mutations available).
///
/// Callback parameters: user data, error code, account info
void app_account_info(App* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, AccountInfo const* account_info));

/// Returns the expected name for the application executable without an extension
void app_exe_file_stem(void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* filename));

/// Sets the additional path in `config_file_handler` to search for files
void app_set_additional_search_path(char const* new_path, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Discard and clean up the previously allocated app instance.
/// Use this only if the app is obtained from one of the auth
/// functions in this crate. Using `app` after a call to this
/// function is undefined behaviour.
void app_free(App* app);

/// Resets the object cache. Removes all objects currently in the object cache
/// and invalidates all existing object handles.
void app_reset_object_cache(App* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Returns the name of the app's container.
void app_container_name(char const* app_id, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* container_name));



#ifdef __cplusplus
}
#endif


#endif
