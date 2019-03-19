// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_apploggingh
#define bindgen_safe_apploggingh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// This function should be called to enable logging to a file.
/// If `output_file_name_override` is provided, then this path will be used for
/// the log output file.
void app_init_logging(char const* output_file_name_override, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// This function should be called to find where log file will be created. It
/// will additionally create an empty log file in the path in the deduced
/// location and will return the file name along with complete path to it.
void app_output_log_path(char const* output_file_name, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, char const* log_path));



#ifdef __cplusplus
}
#endif


#endif
