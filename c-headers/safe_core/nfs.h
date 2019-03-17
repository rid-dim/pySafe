// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_corenfsh
#define bindgen_safe_corenfsh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// FFI-wrapper for `File`.
typedef struct File {
	/// File size in bytes.
	uint64_t size;
	/// Creation time (seconds part).
	int64_t created_sec;
	/// Creation time (nanoseconds part).
	uint32_t created_nsec;
	/// Modification time (seconds part).
	int64_t modified_sec;
	/// Modification time (nanoseconds part).
	uint32_t modified_nsec;
	/// Pointer to the user metadata.
	uint8_t* user_metadata_ptr;
	/// Size of the user metadata.
	uintptr_t user_metadata_len;
	/// Capacity of the user metadata (internal field).
	uintptr_t user_metadata_cap;
	/// Name of the `ImmutableData` containing the content of this file.
	XorNameArray data_map_name;
} File;



#ifdef __cplusplus
}
#endif


#endif
