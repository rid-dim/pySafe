// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_ffiffi_structsh
#define bindgen_safe_ffiffi_structsh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Array containing `XorName` bytes./// Adding this here because bindgen not picking this correctly from the safe-nd.typedef uint8_t const* XorNameArray;

typedef struct BlsKeyPair {
    char const* pk;
    char const* sk;
} BlsKeyPair;

typedef struct SafeKey {
    char const* xorurl;
    XorNameArray xorname;
    NrsMapContainerInfo resolved_from;
} SafeKey;

typedef struct Wallet {
    char const* xorurl;
    XorNameArray xorname;
    uint64_t type_tag;
    WalletSpendableBalances balances;
    uint64_t data_type;
    NrsMapContainerInfo resolved_from;
} Wallet;

typedef struct FilesContainer {
    char const* xorurl;
    XorNameArray xorname;
    uint64_t type_tag;
    uint64_t version;
    char const* files_map;
    uint64_t data_type;
    NrsMapContainerInfo resolved_from;
} FilesContainer;

typedef struct PublishedImmutableData {
    char const* xorurl;
    XorNameArray xorname;
    uint8_t const* data;
    uintptr_t data_len;
    NrsMapContainerInfo resolved_from;
    char const* media_type;
} PublishedImmutableData;

typedef struct XorUrlEncoder {
    uint64_t encoding_version;
    XorNameArray xorname;
    uint64_t type_tag;
    uint64_t data_type;
    uint16_t content_type;
    char const* path;
    char const* sub_names;
    uint64_t content_version;
} XorUrlEncoder;

typedef struct WalletSpendableBalance {
    char const* xorurl;
    char const* sk;
} WalletSpendableBalance;

typedef struct WalletSpendableBalanceInfo {
    char const* wallet_name;
    bool is_default;
    WalletSpendableBalance spendable_balance;
} WalletSpendableBalanceInfo;

typedef struct WalletSpendableBalances {
    WalletSpendableBalanceInfo const* wallet_balances;
    uintptr_t wallet_balances_len;
} WalletSpendableBalances;

typedef struct ProcessedFile {
    char const* file_name;
    char const* file_meta_data;
    char const* file_xorurl;
} ProcessedFile;

typedef struct ProcessedFiles {
    ProcessedFile const* files;
    uintptr_t files_len;
} ProcessedFiles;

typedef struct FileItem {
    char const* file_meta_data;
    char const* xorurl;
} FileItem;

typedef struct FileInfo {
    char const* file_name;
    FileItem const* file_items;
    uintptr_t file_items_len;
} FileInfo;

typedef struct FilesMap {
    FileInfo const* files;
    uintptr_t files_len;
} FilesMap;

typedef struct ProcessedEntry {
    char const* name;
    char const* action;
    char const* link;
} ProcessedEntry;

typedef struct ProcessedEntries {
    ProcessedEntry const* processed_entries;
    uintptr_t processed_entries_len;
} ProcessedEntries;

typedef struct NrsMapContainerInfo {
    char const* public_name;
    char const* xorurl;
    XorNameArray xorname;
    uint64_t type_tag;
    uint64_t version;
    char const* nrs_map;
    uint64_t data_type;
} NrsMapContainerInfo;

typedef struct NrsMap {
    SubNamesMap sub_names_map;
    char const* default;
} NrsMap;

typedef struct SubNamesMapEntry {
    char const* sub_name;
    char const* sub_name_rdf;
} SubNamesMapEntry;

typedef struct SubNamesMap {
    SubNamesMapEntry const* sub_names;
    uintptr_t sub_name_len;
} SubNamesMap;



#ifdef __cplusplus
}
#endif


#endif
