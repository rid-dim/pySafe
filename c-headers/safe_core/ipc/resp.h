// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_coreipcresph
#define bindgen_safe_coreipcresph


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Represents the needed keys to work with the data.
typedef struct AppKeys {
	/// Owner signing public key
	SignPublicKey owner_key;
	/// Data symmetric encryption key
	SymSecretKey enc_key;
	/// Asymmetric sign public key.
	///
	/// This is the identity of the App in the Network.
	SignPublicKey sign_pk;
	/// Asymmetric sign private key.
	SignSecretKey sign_sk;
	/// Asymmetric enc public key.
	AsymPublicKey enc_pk;
	/// Asymmetric enc private key.
	AsymSecretKey enc_sk;
} AppKeys;

/// Access container info.
typedef struct AccessContInfo {
	/// ID
	XorNameArray id;
	/// Type tag
	uint64_t tag;
	/// Nonce
	SymNonce nonce;
} AccessContInfo;

/// Information about a container (name, `MDataInfo` and permissions)
typedef struct ContainerInfo {
	/// Container name as UTF-8 encoded null-terminated string.
	char const* name;
	/// Container's `MDataInfo`
	MDataInfo mdata_info;
	/// App's permissions in the container.
	PermissionSet permissions;
} ContainerInfo;

/// Access container entry for a single app.
typedef struct AccessContainerEntry {
	/// Pointer to the array of `ContainerInfo`.
	ContainerInfo const* containers;
	/// Size of the array.
	uintptr_t containers_len;
	/// Internal field used by rust memory allocator.
	uintptr_t containers_cap;
} AccessContainerEntry;

/// Represents the authentication response.
typedef struct AuthGranted {
	/// The access keys.
	AppKeys app_keys;
	/// Access container info
	AccessContInfo access_container_info;
	/// Access container entry
	AccessContainerEntry access_container_entry;
	/// Crust's bootstrap config
	uint8_t* bootstrap_config;
	/// `bootstrap_config`'s length
	uintptr_t bootstrap_config_len;
	/// Used by Rust memory allocator
	uintptr_t bootstrap_config_cap;
} AuthGranted;

/// Information about an application that has access to an MD through `sign_key`
typedef struct AppAccess {
	/// App's or user's public key
	SignPublicKey sign_key;
	/// A list of permissions
	PermissionSet permissions;
	/// App's user-facing name
	char const* name;
	/// App id.
	char const* app_id;
} AppAccess;

/// User metadata for mutable data
typedef struct MetadataResponse {
	/// Name or purpose of this mutable data.
	char const* name;
	/// Description of how this mutable data should or should not be shared.
	char const* description;
	/// Xor name of this struct's corresponding MData object.
	XorNameArray xor_name;
	/// Type tag of this struct's corresponding MData object.
	uint64_t type_tag;
} MetadataResponse;

/// Represents an FFI-safe mutable data key.
typedef struct MDataKey {
	/// Key value pointer.
	uint8_t const* key;
	/// Key length.
	uintptr_t key_len;
} MDataKey;

/// Represents the FFI-safe mutable data value.
typedef struct MDataValue {
	/// Content pointer.
	uint8_t const* content;
	/// Content length.
	uintptr_t content_len;
	/// Entry version.
	uint64_t entry_version;
} MDataValue;

/// Represents an FFI-safe mutable data (key, value) entry.
typedef struct MDataEntry {
	/// Mutable data key.
	MDataKey key;
	/// Mutable data value.
	MDataValue value;
} MDataEntry;



#ifdef __cplusplus
}
#endif


#endif
