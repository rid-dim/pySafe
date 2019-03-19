// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appcipher_opth
#define bindgen_safe_appcipher_opth


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Construct `CipherOpt::PlainText` handle.
void cipher_opt_new_plaintext(App const* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, CipherOptHandle handle));

/// Construct `CipherOpt::Symmetric` handle.
void cipher_opt_new_symmetric(App const* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, CipherOptHandle handle));

/// Construct `CipherOpt::Asymmetric` handle.
void cipher_opt_new_asymmetric(App const* app, EncryptPubKeyHandle peer_encrypt_key_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, CipherOptHandle handle));

/// Free `CipherOpt` handle.
void cipher_opt_free(App const* app, CipherOptHandle handle, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));



#ifdef __cplusplus
}
#endif


#endif
