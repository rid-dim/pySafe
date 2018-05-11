// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appipch
#define bindgen_safe_appipch


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Encode `AuthReq`.
///
/// Callback parameters: user data, error code, request id, encoded request
void encode_auth_req(AuthReq const* req, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint32_t req_id, char const* encoded));

/// Encode `ContainersReq`.
///
/// Callback parameters: user data, error code, request id, encoded request
void encode_containers_req(ContainersReq const* req, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint32_t req_id, char const* encoded));

/// Encode `AuthReq` for an unregistered client.
///
/// Callback parameters: user data, error code, request id, encoded request
void encode_unregistered_req(uint8_t const* extra_data, uintptr_t extra_data_len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint32_t req_id, char const* encoded));

/// Encode `ShareMDataReq`.
///
/// Callback parameters: user data, error code, request id, encoded request
void encode_share_mdata_req(ShareMDataReq const* req, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint32_t req_id, char const* encoded));

/// Decode IPC message.
void decode_ipc_msg(char const* msg, void* user_data, void (*o_auth)(void* user_data, uint32_t req_id, AuthGranted const* auth_granted), void (*o_unregistered)(void* user_data, uint32_t req_id, uint8_t const* serialised_cfg, uintptr_t serialised_cfg_len), void (*o_containers)(void* user_data, uint32_t req_id), void (*o_share_mdata)(void* user_data, uint32_t req_id), void (*o_revoked)(void* user_data), void (*o_err)(void* user_data, FfiResult const* result, uint32_t req_id));



#ifdef __cplusplus
}
#endif


#endif
