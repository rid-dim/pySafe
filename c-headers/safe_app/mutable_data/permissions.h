// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appmutable_datapermissionsh
#define bindgen_safe_appmutable_datapermissionsh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// FFI object representing a (User, Permission Set) pair.
typedef struct UserPermissionSet {
	/// User's sign key handle.
	SignPubKeyHandle user_h;
	/// User's permission set.
	PermissionSet perm_set;
} UserPermissionSet;

/// Create new permissions.
void mdata_permissions_new(App const* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, MDataPermissionsHandle perm_h));

/// Get the number of entries in the permissions.
void mdata_permissions_len(App const* app, MDataPermissionsHandle permissions_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uintptr_t size));

/// Get the permission set corresponding to the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
void mdata_permissions_get(App const* app, MDataPermissionsHandle permissions_h, SignPubKeyHandle user_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, PermissionSet const* perm_set));

/// Return each (user, permission set) pair in the permissions.
void mdata_list_permission_sets(App const* app, MDataPermissionsHandle permissions_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, UserPermissionSet const* user_perm_sets, uintptr_t user_perm_sets_len));

/// Insert permission set for the given user to the permissions.
///
/// User is either handle to a signing key or `USER_ANYONE`.
void mdata_permissions_insert(App const* app, MDataPermissionsHandle permissions_h, SignPubKeyHandle user_h, PermissionSet const* permission_set, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Free the permissions from memory.
void mdata_permissions_free(App const* app, MDataPermissionsHandle permissions_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));



#ifdef __cplusplus
}
#endif


#endif
