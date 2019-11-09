// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_ffifilesh
#define bindgen_safe_ffifilesh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

void files_container_create(Safe* app, char const* location, char const* dest, bool recursive, bool dry_run, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* xorurl, ProcessedFiles const* process_files, char const* files_map));

void files_container_get(Safe* app, char const* url, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t version, char const* files_map));

void files_container_sync(Safe* app, char const* location, char const* url, bool recursive, bool delete, bool update_nrs, bool dry_run, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t version, ProcessedFiles const* process_files, char const* files_map));

void files_container_add(Safe* app, char const* source_file, char const* url, bool force, bool update_nrs, bool dry_run, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t version, ProcessedFiles const* process_files, char const* files_map));

void files_container_add_from_raw(Safe* app, uint8_t const* data, uintptr_t data_len, char const* url, bool force, bool update_nrs, bool dry_run, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t version, ProcessedFiles const* process_files, char const* files_map));

void files_put_published_immutable(Safe* app, uint8_t const* data, uintptr_t data_len, char const* media_type, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* xorurl));

void files_get_published_immutable(Safe* app, char const* url, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* im_data, uintptr_t im_data_len));



#ifdef __cplusplus
}
#endif


#endif
