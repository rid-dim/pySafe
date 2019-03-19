// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appimmutable_datah
#define bindgen_safe_appimmutable_datah


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Handle of a Self Encryptor Writer object.
typedef SelfEncryptorWriterHandle SEWriterHandle;

/// Handle of a Self Encryptor Reader object.
typedef SelfEncryptorReaderHandle SEReaderHandle;

/// Get a Self Encryptor.
void idata_new_self_encryptor(App const* app, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, SEWriterHandle se_h));

/// Write to Self Encryptor.
void idata_write_to_self_encryptor(App const* app, SEWriterHandle se_h, uint8_t const* data, uintptr_t data_len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Close Self Encryptor and free the Self Encryptor Writer handle.
void idata_close_self_encryptor(App const* app, SEWriterHandle se_h, CipherOptHandle cipher_opt_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, XorNameArray const* name));

/// Fetch Self Encryptor.
void idata_fetch_self_encryptor(App const* app, XorNameArray const* name, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, SEReaderHandle se_h));

/// Get serialised size of `ImmutableData`.
void idata_serialised_size(App const* app, XorNameArray const* name, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t serialised_size));

/// Get data size from Self Encryptor.
void idata_size(App const* app, SEReaderHandle se_h, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint64_t size));

/// Read from Self Encryptor.
void idata_read_from_self_encryptor(App const* app, SEReaderHandle se_h, uint64_t from_pos, uint64_t len, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result, uint8_t const* data, uintptr_t data_len));

/// Free Self Encryptor Writer handle.
void idata_self_encryptor_writer_free(App const* app, SEWriterHandle handle, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));

/// Free Self Encryptor Reader handle.
void idata_self_encryptor_reader_free(App const* app, SEReaderHandle handle, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));



#ifdef __cplusplus
}
#endif


#endif
