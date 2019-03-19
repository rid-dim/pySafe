// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appnfsh
#define bindgen_safe_appnfsh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Retrieve file with the given name, and its version, from the directory.
void dir_fetch_file(App const* app, MDataInfo const* parent_info, char const* file_name, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, File const* file, uint64_t version));

/// Insert the file into the parent directory.
void dir_insert_file(App const* app, MDataInfo const* parent_info, char const* file_name, File const* file, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Replace the file in the parent directory.
///
/// If `version` is `GET_NEXT_VERSION`, the correct version is obtained automatically.
void dir_update_file(App const* app, MDataInfo const* parent_info, char const* file_name, File const* file, uint64_t version, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t new_version));

/// Delete the file in the parent directory.
///
/// If `version` is `GET_NEXT_VERSION`, the correct version is obtained automatically.
void dir_delete_file(App const* app, MDataInfo const* parent_info, char const* file_name, uint64_t version, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t new_version));

/// Open the file to read or write its contents.
void file_open(App const* app, MDataInfo const* parent_info, File const* file, uint64_t open_mode, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, FileContextHandle file_h));

/// Get a size of file opened for read.
void file_size(App const* app, FileContextHandle file_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t size));

/// Read data from file.
void file_read(App const* app, FileContextHandle file_h, uint64_t position, uint64_t len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* data, uintptr_t data_len));

/// Write data to file in smaller chunks.
void file_write(App const* app, FileContextHandle file_h, uint8_t const* data, uintptr_t data_len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Close is invoked only after all the data is completely written. The
/// file is saved only when `close` is invoked.
///
/// If the file was opened in any of the write modes, returns the modified
/// file structure as a result. If the file was opened in the read mode,
/// returns the original file structure that was passed as an argument to
/// `file_open`.
///
/// Frees the file context handle.
void file_close(App const* app, FileContextHandle file_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, File const* file));



#ifdef __cplusplus
}
#endif


#endif
