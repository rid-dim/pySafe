// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_apptest_utilsh
#define bindgen_safe_apptest_utilsh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Creates a random app instance for testing.
void test_create_app(char const* app_id, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, App* app));

/// Create a random app instance for testing, with access to containers.
void test_create_app_with_access(AuthReq const* auth_req, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, App* o_app));

/// Simulate a network disconnect when testing.
void test_simulate_network_disconnect(App* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));



#ifdef __cplusplus
}
#endif


#endif
