// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_ffixorurlh
#define bindgen_safe_ffixorurlh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

void xorurl_encode(XorNameArray const* name, uint64_t type_tag, uint64_t data_type, uint16_t content_type, char const* path, char const* _sub_names, uint64_t content_version, char const* base_encoding, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* encoded_xor_url));

void xorurl_encoder(XorNameArray const* name, uint64_t type_tag, uint64_t data_type, uint16_t content_type, char const* path, char const* _sub_names, uint64_t content_version, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, XorUrlEncoder const* xor_url_encoder));

void xorurl_encoder_from_url(char const* xor_url, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, XorUrlEncoder const* xor_url_encoder));



#ifdef __cplusplus
}
#endif


#endif
