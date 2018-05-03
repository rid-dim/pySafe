// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appmutable_datametadatah
#define bindgen_safe_appmutable_datametadatah


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Serialize metadata.
///
/// Callback parameters: user data, error code, encoded metadata vector, vector size
void mdata_encode_metadata(MetadataResponse const* metadata, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* encoded, uintptr_t encoded_len));



#ifdef __cplusplus
}
#endif


#endif
