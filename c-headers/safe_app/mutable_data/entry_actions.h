// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appmutable_dataentry_actionsh
#define bindgen_safe_appmutable_dataentry_actionsh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Create new entry actions.
void mdata_entry_actions_new(App const* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataEntryActionsHandle entry_actions_h));

/// Add action to insert new entry.
void mdata_entry_actions_insert(App const* app, MDataEntryActionsHandle actions_h, uint8_t const* key, uintptr_t key_len, uint8_t const* value, uintptr_t value_len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Add action to update existing entry.
void mdata_entry_actions_update(App const* app, MDataEntryActionsHandle actions_h, uint8_t const* key, uintptr_t key_len, uint8_t const* value, uintptr_t value_len, uint64_t entry_version, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Add action to delete existing entry.
void mdata_entry_actions_delete(App const* app, MDataEntryActionsHandle actions_h, uint8_t const* key, uintptr_t key_len, uint64_t entry_version, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Free the entry actions from memory
void mdata_entry_actions_free(App const* app, MDataEntryActionsHandle actions_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));



#ifdef __cplusplus
}
#endif


#endif
