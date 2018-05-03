// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_ffi_utilsh
#define bindgen_ffi_utilsh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// FFI result wrapper
typedef struct FfiResult {
	/// Unique error code
	int32_t error_code;
	/// Error description
	char const* description;
} FfiResult;



#ifdef __cplusplus
}
#endif


#endif
