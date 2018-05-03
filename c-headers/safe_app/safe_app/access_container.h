// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appaccess_containerh
#define bindgen_safe_appaccess_containerh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Fetch access info from the network.
///
/// Callback parameters: user data, error code
void access_container_refresh_access_info(App const* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Retrieve a list of container names that an app has access to.
///
/// Callback parameters: user data, error code, container permissions vector, vector size
void access_container_fetch(App const* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, ContainerPermissions const* container_perms, uintptr_t container_perms_len));

/// Retrieve `MDataInfo` for the given container name from the access container.
///
/// Callback parameters: user data, error code, mdata info handle
void access_container_get_container_mdata_info(App const* app, char const* name, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataInfo const* mdata_info));



#ifdef __cplusplus
}
#endif


#endif
