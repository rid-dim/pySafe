// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_authenticatorappsh
#define bindgen_safe_authenticatorappsh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Application registered in the authenticator
typedef struct RegisteredApp {
	/// Unique application identifier
	AppExchangeInfo app_info;
	/// List of containers that this application has access to
	ContainerPermissions const* containers;
	/// Length of the containers array
	uintptr_t containers_len;
	/// Capacity of the containers array. Internal data required
	/// for the Rust allocator.
	uintptr_t containers_cap;
} RegisteredApp;

/// Removes a revoked app from the authenticator config.
void auth_rm_revoked_app(Authenticator const* auth, char const* app_id, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Get a list of apps revoked from authenticator.
void auth_revoked_apps(Authenticator const* auth, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, AppExchangeInfo const* app_exchange_info, uintptr_t app_exchange_info_len));

/// Get a list of apps registered in authenticator.
void auth_registered_apps(Authenticator const* auth, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, RegisteredApp const* registered_app, uintptr_t registered_app_len));

/// Return a list of apps having access to an arbitrary MD object.
/// `md_name` and `md_type_tag` together correspond to a single MD.
void auth_apps_accessing_mutable_data(Authenticator const* auth, XorNameArray const* md_name, uint64_t md_type_tag, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, AppAccess const* app_access, uintptr_t app_access_len));



#ifdef __cplusplus
}
#endif


#endif
