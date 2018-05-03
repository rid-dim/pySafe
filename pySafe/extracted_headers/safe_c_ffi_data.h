typedef void* App;
typedef signed char int8_t;
typedef short int int16_t;
typedef int int32_t;
typedef long int int64_t;
typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long int uint64_t;
typedef signed char int_least8_t;
typedef short int int_least16_t;
typedef int int_least32_t;
typedef long int int_least64_t;
typedef unsigned char uint_least8_t;
typedef unsigned short int uint_least16_t;
typedef unsigned int uint_least32_t;
typedef unsigned long int uint_least64_t;
typedef signed char int_fast8_t;
typedef long int int_fast16_t;
typedef long int int_fast32_t;
typedef long int int_fast64_t;
typedef unsigned char uint_fast8_t;
typedef unsigned long int uint_fast16_t;
typedef unsigned long int uint_fast32_t;
typedef unsigned long int uint_fast64_t;
typedef long int intptr_t;
typedef unsigned long int uintptr_t;
typedef long int intmax_t;
typedef unsigned long int uintmax_t;
typedef uint8_t const* AsymPublicKey;
typedef uint8_t const* AsymSecretKey;
typedef uint8_t const* AsymNonce;
typedef uint8_t const* SymSecretKey;
typedef uint8_t const* SymNonce;
typedef uint8_t const* SignPublicKey;
typedef uint8_t const* SignSecretKey;
typedef uint8_t const* XorNameArray;
typedef uint64_t ObjectHandle;
typedef ObjectHandle CipherOptHandle;
typedef ObjectHandle EncryptPubKeyHandle;
typedef ObjectHandle EncryptSecKeyHandle;
typedef ObjectHandle MDataEntriesHandle;
typedef ObjectHandle MDataEntryActionsHandle;
typedef ObjectHandle MDataPermissionsHandle;
typedef ObjectHandle SelfEncryptorReaderHandle;
typedef ObjectHandle SelfEncryptorWriterHandle;
typedef ObjectHandle SignPubKeyHandle;
typedef ObjectHandle SignSecKeyHandle;
typedef ObjectHandle FileContextHandle;
typedef SelfEncryptorWriterHandle SEWriterHandle;
typedef SelfEncryptorReaderHandle SEReaderHandle;
typedef enum {
 MDataAction_Insert,
 MDataAction_Update,
 MDataAction_Delete,
 MDataAction_ManagePermissions,
} MDataAction;
typedef struct {
 int32_t error_code;
 char const* description;
} FfiResult;
typedef struct {
 uint64_t size;
 int64_t created_sec;
 uint32_t created_nsec;
 int64_t modified_sec;
 uint32_t modified_nsec;
 uint8_t* user_metadata_ptr;
 uintptr_t user_metadata_len;
 uintptr_t user_metadata_cap;
 XorNameArray data_map_name;
} File;
typedef struct {
 _Bool read;
 _Bool insert;
 _Bool update;
 _Bool delete;
 _Bool manage_permissions;
} PermissionSet;
typedef struct {
 char const* id;
 char const* scope;
 char const* name;
 char const* vendor;
} AppExchangeInfo;
typedef struct {
 char const* cont_name;
 PermissionSet access;
} ContainerPermissions;
typedef struct {
 AppExchangeInfo app;
 _Bool app_container;
 ContainerPermissions const* containers;
 uintptr_t containers_len;
 uintptr_t containers_cap;
} AuthReq;
typedef struct {
 AppExchangeInfo app;
 ContainerPermissions const* containers;
 uintptr_t containers_len;
 uintptr_t containers_cap;
} ContainersReq;
typedef struct {
 uint64_t type_tag;
 XorNameArray name;
 PermissionSet perms;
} ShareMData;
typedef struct {
 AppExchangeInfo app;
 ShareMData const* mdata;
 uintptr_t mdata_len;
 uintptr_t mdata_cap;
} ShareMDataReq;
typedef struct {
 SignPubKeyHandle user_h;
 PermissionSet perm_set;
} UserPermissionSet;
typedef struct {
 uint64_t mutations_done;
 uint64_t mutations_available;
} AccountInfo;
typedef struct {
 XorNameArray name;
 uint64_t type_tag;
 _Bool has_enc_info;
 SymSecretKey enc_key;
 SymNonce enc_nonce;
 _Bool has_new_enc_info;
 SymSecretKey new_enc_key;
 SymNonce new_enc_nonce;
} MDataInfo;
typedef struct {
 SignPublicKey owner_key;
 SymSecretKey enc_key;
 SignPublicKey sign_pk;
 SignSecretKey sign_sk;
 AsymPublicKey enc_pk;
 AsymSecretKey enc_sk;
} AppKeys;
typedef struct {
 XorNameArray id;
 uint64_t tag;
 SymNonce nonce;
} AccessContInfo;
typedef struct {
 char const* name;
 MDataInfo mdata_info;
 PermissionSet permissions;
} ContainerInfo;
typedef struct {
 ContainerInfo const* containers;
 uintptr_t containers_len;
 uintptr_t containers_cap;
} AccessContainerEntry;
typedef struct {
 AppKeys app_keys;
 AccessContInfo access_container_info;
 AccessContainerEntry access_container_entry;
 uint8_t* bootstrap_config;
 uintptr_t bootstrap_config_len;
 uintptr_t bootstrap_config_cap;
} AuthGranted;
typedef struct {
 SignPublicKey sign_key;
 PermissionSet permissions;
 char const* name;
 char const* app_id;
} AppAccess;
typedef struct {
 char const* name;
 char const* description;
 XorNameArray xor_name;
 uint64_t type_tag;
} MetadataResponse;
typedef struct {
 uint8_t const* val;
 uintptr_t val_len;
} MDataKey;
typedef struct {
 uint8_t const* content;
 uintptr_t content_len;
 uint64_t entry_version;
} MDataValue;
typedef struct {
 MDataKey key;
 MDataValue value;
} MDataEntry;
