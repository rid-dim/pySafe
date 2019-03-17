// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_authenticatoripch
#define bindgen_safe_authenticatoripch


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Decodes a given encoded IPC message without requiring an authorised account.
void auth_unregistered_decode_ipc_msg(char const* msg, void* user_data, void (*o_unregistered)(void* user_data, uint32_t req_id, uint8_t const* extra_data, uintptr_t extra_data_len), void (*o_err)(void* user_data, FfiResult const* result, char const* response));

/// Decodes a given encoded IPC message and calls a corresponding callback.
void auth_decode_ipc_msg(Authenticator const* auth, char const* msg, void* user_data, void (*o_auth)(void* user_data, uint32_t req_id, AuthReq const* req), void (*o_containers)(void* user_data, uint32_t req_id, ContainersReq const* req), void (*o_unregistered)(void* user_data, uint32_t req_id, uint8_t const* extra_data, uintptr_t extra_data_len), void (*o_share_mdata)(void* user_data, uint32_t req_id, ShareMDataReq const* req, MetadataResponse const* metadata, uintptr_t metadata_len), void (*o_err)(void* user_data, FfiResult const* result, char const* response));

/// Encode share mutable data response.
void encode_share_mdata_resp(Authenticator const* auth, ShareMDataReq const* req, uint32_t req_id, bool is_granted, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* response));

/// Revoke app access.
void auth_revoke_app(Authenticator const* auth, char const* app_id, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* response));

/// Flush the revocation queue.
void auth_flush_app_revocation_queue(Authenticator const* auth, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Encodes a response to unregistered client authentication request.
void encode_unregistered_resp(uint32_t req_id, bool is_granted, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* response));

/// Provides and encodes an Authenticator response.
void encode_auth_resp(Authenticator const* auth, AuthReq const* req, uint32_t req_id, bool is_granted, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* response));

/// Update containers permissions for an App.
void encode_containers_resp(Authenticator const* auth, ContainersReq const* req, uint32_t req_id, bool is_granted, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* response));



#ifdef __cplusplus
}
#endif


#endif
