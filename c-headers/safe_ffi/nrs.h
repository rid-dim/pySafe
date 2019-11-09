// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_ffinrsh
#define bindgen_safe_ffinrsh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

void parse_url(char const* url, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, XorUrlEncoder const* xorurl_encoder));

void parse_and_resolve_url(Safe* app, char const* url, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, XorUrlEncoder const* xorurl_encoder, XorUrlEncoder const* resolved_from));

void nrs_map_container_create(Safe* app, char const* name, char const* link, bool direct_link, bool dry_run, bool set_default, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* nrs_map, ProcessedEntries const* processed_entries, char const* xorurl));

void nrs_map_container_add(Safe* app, char const* name, char const* link, bool set_default, bool direct_link, bool dry_run, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* nrs_map, char const* xorurl, uint64_t version));

void nrs_map_container_remove(Safe* app, char const* name, bool dry_run, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* nrs_map, char const* xorurl, uint64_t version));

void nrs_map_container_get(Safe* app, char const* url, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* nrs_map, uint64_t version));



#ifdef __cplusplus
}
#endif


#endif
