// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appmutable_datah
#define bindgen_safe_appmutable_datah


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Create new mutable data and put it on the network.
///
/// `permissions_h` is a handle to permissions to be set on the mutable data.
/// If `PERMISSIONS_EMPTY`, the permissions will be empty.
///
/// `entries_h` is a handle to entries for the mutable data.
/// If `ENTRIES_EMPTY`, the entries will be empty.
///
/// Callback parameters: user data, error code
void mdata_put(App const* app, MDataInfo const* info, MDataPermissionsHandle permissions_h, MDataEntriesHandle entries_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Get version of the mutable data.
///
/// Callback parameters: user data, error code, version
void mdata_get_version(App const* app, MDataInfo const* info, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t version));

/// Get size of serialised mutable data.
///
/// Callback parameters: user data, error code, serialised size
void mdata_serialised_size(App const* app, MDataInfo const* info, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t serialised_size));

/// Get value at the given key from the mutable data.
/// The arguments to the callback are:
///     1. user data
///     2. error code
///     3. pointer to content
///     4. content length
///     5. entry version
///
/// Please notice that if a value is fetched from a private `MutableData`,
/// it's not automatically decrypted.
void mdata_get_value(App const* app, MDataInfo const* info, uint8_t const* key, uintptr_t key_len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* content, uintptr_t content_len, uint64_t version));

/// Get a handle to the complete list of entries in the mutable data.
///
/// Callback parameters: user data, error code, entries handle
void mdata_entries(App const* app, MDataInfo const* info, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataEntriesHandle entries_h));

/// Get list of all keys in the mutable data.
///
/// Callback parameters: user data, error code, vector of keys, vector size
void mdata_list_keys(App const* app, MDataInfo const* info, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataKey const* keys, uintptr_t keys_len));

/// Get list of all values in the mutable data.
///
/// Callback parameters: user data, error code, vector of values, vector size
void mdata_list_values(App const* app, MDataInfo const* info, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataValue const* values, uintptr_t values_len));

/// Mutate entries of the mutable data.
///
/// Callback parameters: user data, error code
void mdata_mutate_entries(App const* app, MDataInfo const* info, MDataEntryActionsHandle actions_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Get list of all permissions set on the mutable data
///
/// Callback parameters: user data, error code, permission handle
void mdata_list_permissions(App const* app, MDataInfo const* info, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataPermissionsHandle perm_h));

/// Get list of permissions set on the mutable data for the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
///
/// Callback parameters: user data, error code, permission set handle
void mdata_list_user_permissions(App const* app, MDataInfo const* info, SignPubKeyHandle user_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, PermissionSet const* perm_set));

/// Set permissions set on the mutable data for the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
///
/// Callback parameters: user data, error code
void mdata_set_user_permissions(App const* app, MDataInfo const* info, SignPubKeyHandle user_h, PermissionSet const* permission_set, uint64_t version, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Delete permissions set on the mutable data for the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
///
/// Callback parameters: user data, error code
void mdata_del_user_permissions(App const* app, MDataInfo const* info, SignPubKeyHandle user_h, uint64_t version, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));



#ifdef __cplusplus
}
#endif


#endif
