// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_ffisafe_ffih
#define bindgen_safe_ffisafe_ffih


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

void connect(char const* app_id, char const* auth_credentials, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, Safe* app));



#ifdef __cplusplus
}
#endif


#endif
