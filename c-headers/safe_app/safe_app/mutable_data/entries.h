// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appmutable_dataentriesh
#define bindgen_safe_appmutable_dataentriesh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Create new empty entries.
///
/// Callback parameters: user data, error code, entries handle
void mdata_entries_new(App const* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataEntriesHandle entries_h));

/// Insert an entry to the entries.
///
/// Callback parameters: user data, error code
void mdata_entries_insert(App const* app, MDataEntriesHandle entries_h, uint8_t const* key, uintptr_t key_len, uint8_t const* value, uintptr_t value_len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Returns the number of entries.
///
/// Callback parameters: user data, error code, length
void mdata_entries_len(App const* app, MDataEntriesHandle entries_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uintptr_t len));

/// Get the entry value at the given key.
///
/// The callbacks arguments are: user data, error code, pointer to value,
/// value length, entry version. The caller must NOT free the pointer.
void mdata_entries_get(App const* app, MDataEntriesHandle entries_h, uint8_t const* key, uintptr_t key_len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* content, uintptr_t content_len, uint64_t version));

/// Iterate over the entries.
///
/// The `o_each_cb` callback is invoked once for each entry,
/// passing user data, pointer to key, key length, pointer to value, value length
/// and entry version in that order.
///
/// The `o_done_cb` callback is invoked after the iteration is done, or in case of error.
void mdata_list_entries(App const* app, MDataEntriesHandle entries_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataEntry const* entries, uintptr_t entries_len));

/// Free the entries from memory.
///
/// Callback parameters: user data, error code
void mdata_entries_free(App const* app, MDataEntriesHandle entries_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));



#ifdef __cplusplus
}
#endif


#endif
