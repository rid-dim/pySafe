// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_coresafe_coreh
#define bindgen_safe_coresafe_coreh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Represents the FFI-safe account info.
typedef struct AccountInfo {
	/// Number of used mutations.
	uint64_t mutations_done;
	/// Number of available mutations.
	uint64_t mutations_available;
} AccountInfo;

/// FFI wrapper for `MDataInfo`.
typedef struct MDataInfo {
	/// Name of the mutable data.
	XorNameArray name;
	/// Type tag of the mutable data.
	uint64_t type_tag;
	/// Flag indicating whether the encryption info (`enc_key` and `enc_nonce`).
	/// is set.
	bool has_enc_info;
	/// Encryption key. Meaningful only if `has_enc_info` is `true`.
	SymSecretKey enc_key;
	/// Encryption nonce. Meaningful only if `has_enc_info` is `true`.
	SymNonce enc_nonce;
	/// Flag indicating whether the new encryption info is set.
	bool has_new_enc_info;
	/// New encryption key (used for two-phase reencryption). Meaningful only if
	/// `has_new_enc_info` is `true`.
	SymSecretKey new_enc_key;
	/// New encryption nonce (used for two-phase reencryption). Meaningful only if
	/// `has_new_enc_info` is `true`.
	SymNonce new_enc_nonce;
} MDataInfo;

/// Returns true if this crate was compiled against mock-routing.
bool is_mock_build(void);



#ifdef __cplusplus
}
#endif


#endif
