// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_ffifetchh
#define bindgen_safe_ffifetchh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

void fetch(Safe* app, char const* url, void* user_data, void (*o_published)(void* user_data, PublishedImmutableData const* data), void (*o_wallet)(void* user_data, Wallet const* data), void (*o_keys)(void* user_data, SafeKey const* data), void (*o_container)(void* user_data, FilesContainer const* data), void (*o_err)(void* user_data, FfiResult const* result));

void inspect(Safe* app, char const* url, void* user_data, void (*o_published)(void* user_data, PublishedImmutableData const* data), void (*o_wallet)(void* user_data, Wallet const* data), void (*o_keys)(void* user_data, SafeKey const* data), void (*o_container)(void* user_data, FilesContainer const* data), void (*o_err)(void* user_data, FfiResult const* result));



#ifdef __cplusplus
}
#endif


#endif
