import safenet.safeUtils as safeUtils
import queue

appQueue = queue.Queue()

class lib:
    def __init__(self,authlib,applib,fromBytes=None):
        self.safe_authenticator = authlib
        self.safe_app = applib

# first attempt to define mutable Data for us
class mutableData:
    def __init__(self,authlib,applib,fromBytes=None):
        self.lib = lib(authlib,applib)
        
        # defining the mutableData
        if fromBytes:
            self.asBytes = fromBytes
            #self.ffiMutable=ffi.new('MDataInfo *') - i think the ffi-datatypes should only exist locally in our functions
            # otherwise we can't pickle out own class (at least i got always faults when trying to do it with ffi classes yet)
        else:
            self.asBytes = None
    
    def getffiMutable():
        ffiMutable=ffi.new('MDataInfo *')
        writeBuffer = ffi.buffer(self.ffiMutable)
        writeBuffer[:]=self.asBytes
        return ffiMutable
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_encode_metadata(self, metadata, user_data, o_cb=None):
        """
            MetadataResponse*, [any], [function], [custom ffi lib]
            MetadataResponse* metadata, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* encoded, uintptr_t encoded_len)
        """
        @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _mdata_encode_metadata_o_cb(user_data ,result ,encoded ,encoded_len):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,encoded ,encoded_len)
    
    
        self.lib.safe_app.mdata_encode_metadata(metadata, user_data, _mdata_encode_metadata_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_info_new_private(self, name, type_tag, secret_key, nonce, user_data, o_cb=None):
        """
            XorNameArray*, uint64_t, SymSecretKey*, SymNonce*, [any], [function], [custom ffi lib]
            XorNameArray* name, uint64_t type_tag, SymSecretKey* secret_key, SymNonce* nonce, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataInfo* mdata_info)
        """
        @ffi.callback("void(void* ,FfiResult* ,MDataInfo*)")
        def _mdata_info_new_private_o_cb(user_data ,result ,mdata_info):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,mdata_info)
    
    
        self.lib.safe_app.mdata_info_new_private(name, type_tag, secret_key, nonce, user_data, _mdata_info_new_private_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_info_random_public(self, type_tag, user_data, o_cb=None):
        """
            uint64_t, [any], [function], [custom ffi lib]
            uint64_t type_tag, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataInfo* mdata_info)
        """
        @ffi.callback("void(void* ,FfiResult* ,MDataInfo*)")
        def _mdata_info_random_public_o_cb(user_data ,result ,mdata_info):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,mdata_info)
    
    
        self.lib.safe_app.mdata_info_random_public(type_tag, user_data, _mdata_info_random_public_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_info_random_private(self, type_tag, user_data, o_cb=None):
        """
            uint64_t, [any], [function], [custom ffi lib]
            uint64_t type_tag, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataInfo* mdata_info)
        """
        @ffi.callback("void(void* ,FfiResult* ,MDataInfo*)")
        def _mdata_info_random_private_o_cb(user_data ,result ,mdata_info):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,mdata_info)
    
    
        self.lib.safe_app.mdata_info_random_private(type_tag, user_data, _mdata_info_random_private_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_info_encrypt_entry_key(self, info, input, input_len, user_data, o_cb=None):
        """
            MDataInfo*, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
            MDataInfo* info, uint8_t* input, uintptr_t input_len, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* enc_entry_key, uintptr_t enc_entry_key_len)
        """
        @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _mdata_info_encrypt_entry_key_o_cb(user_data ,result ,enc_entry_key ,enc_entry_key_len):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,enc_entry_key ,enc_entry_key_len)
    
    
        self.lib.safe_app.mdata_info_encrypt_entry_key(info, input, input_len, user_data, _mdata_info_encrypt_entry_key_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_info_encrypt_entry_value(self, info, input, input_len, user_data, o_cb=None):
        """
            MDataInfo*, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
            MDataInfo* info, uint8_t* input, uintptr_t input_len, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* enc_entry_value, uintptr_t enc_entry_value_len)
        """
        @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _mdata_info_encrypt_entry_value_o_cb(user_data ,result ,enc_entry_value ,enc_entry_value_len):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,enc_entry_value ,enc_entry_value_len)
    
    
        self.lib.safe_app.mdata_info_encrypt_entry_value(info, input, input_len, user_data, _mdata_info_encrypt_entry_value_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_info_decrypt(self, info, input, input_len, user_data, o_cb=None):
        """
            MDataInfo*, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
            MDataInfo* info, uint8_t* input, uintptr_t input_len, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* mdata_info_decrypt, uintptr_t mdata_info_decrypt_len)
        """
        @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _mdata_info_decrypt_o_cb(user_data ,result ,mdata_info_decrypt ,mdata_info_decrypt_len):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,mdata_info_decrypt ,mdata_info_decrypt_len)
    
    
        self.lib.safe_app.mdata_info_decrypt(info, input, input_len, user_data, _mdata_info_decrypt_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_info_serialise(self, info, user_data, o_cb=None):
        """
            MDataInfo*, [any], [function], [custom ffi lib]
            MDataInfo* info, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* encoded, uintptr_t encoded_len)
        """
        @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _mdata_info_serialise_o_cb(user_data ,result ,encoded ,encoded_len):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,encoded ,encoded_len)
    
    
        self.lib.safe_app.mdata_info_serialise(info, user_data, _mdata_info_serialise_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_info_deserialise(self, encoded_ptr, encoded_len, user_data, o_cb=None):
        """
            uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
            uint8_t* encoded_ptr, uintptr_t encoded_len, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataInfo* mdata_info)
        """
        @ffi.callback("void(void* ,FfiResult* ,MDataInfo*)")
        def _mdata_info_deserialise_o_cb(user_data ,result ,mdata_info):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,mdata_info)
    
    
        self.lib.safe_app.mdata_info_deserialise(encoded_ptr, encoded_len, user_data, _mdata_info_deserialise_o_cb)
    
        
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _encode_share_mdata_req(self, req, user_data, o_cb=None):
        """
            ShareMDataReq*, [any], [function], [custom ffi lib]
            ShareMDataReq* req, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint32_t req_id, char* encoded)
        """
        @ffi.callback("void(void* ,FfiResult* ,uint32_t ,char*)")
        def _encode_share_mdata_req_o_cb(user_data ,result ,req_id ,encoded):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,req_id ,encoded)
    
    
        self.lib.safe_app.encode_share_mdata_req(req, user_data, _encode_share_mdata_req_o_cb)
    
   
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_put(self, app, info, permissions_h, entries_h, user_data, o_cb=None):
        """
            App*, MDataInfo*, MDataPermissionsHandle, MDataEntriesHandle, [any], [function], [custom ffi lib]
            App* app, MDataInfo* info, MDataPermissionsHandle permissions_h, MDataEntriesHandle entries_h, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _mdata_put_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        self.lib.safe_app.mdata_put(app, info, permissions_h, entries_h, user_data, _mdata_put_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_get_version(self, app, info, user_data, o_cb=None):
        """
            App*, MDataInfo*, [any], [function], [custom ffi lib]
            App* app, MDataInfo* info, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint64_t version)
        """
        @ffi.callback("void(void* ,FfiResult* ,uint64_t)")
        def _mdata_get_version_o_cb(user_data ,result ,version):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,version)
    
    
        self.lib.safe_app.mdata_get_version(app, info, user_data, _mdata_get_version_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_serialised_size(self, app, info, user_data, o_cb=None):
        """
            App*, MDataInfo*, [any], [function], [custom ffi lib]
            App* app, MDataInfo* info, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint64_t serialised_size)
        """
        @ffi.callback("void(void* ,FfiResult* ,uint64_t)")
        def _mdata_serialised_size_o_cb(user_data ,result ,serialised_size):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,serialised_size)
    
    
        self.lib.safe_app.mdata_serialised_size(app, info, user_data, _mdata_serialised_size_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_get_value(self, app, info, key, key_len, user_data, o_cb=None):
        """
            App*, MDataInfo*, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
            App* app, MDataInfo* info, uint8_t* key, uintptr_t key_len, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* content, uintptr_t content_len, uint64_t version)
        """
        @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t ,uint64_t)")
        def _mdata_get_value_o_cb(user_data ,result ,content ,content_len ,version):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,content ,content_len ,version)
    
    
        self.lib.safe_app.mdata_get_value(app, info, key, key_len, user_data, _mdata_get_value_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_entries(self, app, info, user_data, o_cb=None):
        """
            App*, MDataInfo*, [any], [function], [custom ffi lib]
            App* app, MDataInfo* info, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataEntriesHandle entries_h)
        """
        @ffi.callback("void(void* ,FfiResult* ,MDataEntriesHandle)")
        def _mdata_entries_o_cb(user_data ,result ,entries_h):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,entries_h)
    
    
        self.lib.safe_app.mdata_entries(app, info, user_data, _mdata_entries_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_list_keys(self, app, info, user_data, o_cb=None):
        """
            App*, MDataInfo*, [any], [function], [custom ffi lib]
            App* app, MDataInfo* info, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataKey* keys, uintptr_t keys_len)
        """
        @ffi.callback("void(void* ,FfiResult* ,MDataKey* ,uintptr_t)")
        def _mdata_list_keys_o_cb(user_data ,result ,keys ,keys_len):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,keys ,keys_len)
    
    
        self.lib.safe_app.mdata_list_keys(app, info, user_data, _mdata_list_keys_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_list_values(self, app, info, user_data, o_cb=None):
        """
            App*, MDataInfo*, [any], [function], [custom ffi lib]
            App* app, MDataInfo* info, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataValue* values, uintptr_t values_len)
        """
        @ffi.callback("void(void* ,FfiResult* ,MDataValue* ,uintptr_t)")
        def _mdata_list_values_o_cb(user_data ,result ,values ,values_len):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,values ,values_len)
    
    
        self.lib.safe_app.mdata_list_values(app, info, user_data, _mdata_list_values_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_mutate_entries(self, app, info, actions_h, user_data, o_cb=None):
        """
            App*, MDataInfo*, MDataEntryActionsHandle, [any], [function], [custom ffi lib]
            App* app, MDataInfo* info, MDataEntryActionsHandle actions_h, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _mdata_mutate_entries_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        self.lib.safe_app.mdata_mutate_entries(app, info, actions_h, user_data, _mdata_mutate_entries_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_list_permissions(self, app, info, user_data, o_cb=None):
        """
            App*, MDataInfo*, [any], [function], [custom ffi lib]
            App* app, MDataInfo* info, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataPermissionsHandle perm_h)
        """
        @ffi.callback("void(void* ,FfiResult* ,MDataPermissionsHandle)")
        def _mdata_list_permissions_o_cb(user_data ,result ,perm_h):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,perm_h)
    
    
        self.lib.safe_app.mdata_list_permissions(app, info, user_data, _mdata_list_permissions_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_list_user_permissions(self, app, info, user_h, user_data, o_cb=None):
        """
            App*, MDataInfo*, SignPubKeyHandle, [any], [function], [custom ffi lib]
            App* app, MDataInfo* info, SignPubKeyHandle user_h, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, PermissionSet* perm_set)
        """
        @ffi.callback("void(void* ,FfiResult* ,PermissionSet*)")
        def _mdata_list_user_permissions_o_cb(user_data ,result ,perm_set):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,perm_set)
    
    
        self.lib.safe_app.mdata_list_user_permissions(app, info, user_h, user_data, _mdata_list_user_permissions_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_set_user_permissions(self, app, info, user_h, permission_set, version, user_data, o_cb=None):
        """
            App*, MDataInfo*, SignPubKeyHandle, PermissionSet*, uint64_t, [any], [function], [custom ffi lib]
            App* app, MDataInfo* info, SignPubKeyHandle user_h, PermissionSet* permission_set, uint64_t version, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _mdata_set_user_permissions_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        self.lib.safe_app.mdata_set_user_permissions(app, info, user_h, permission_set, version, user_data, _mdata_set_user_permissions_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_del_user_permissions(self, app, info, user_h, version, user_data, o_cb=None):
        """
            App*, MDataInfo*, SignPubKeyHandle, uint64_t, [any], [function], [custom ffi lib]
            App* app, MDataInfo* info, SignPubKeyHandle user_h, uint64_t version, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _mdata_del_user_permissions_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        self.lib.safe_app.mdata_del_user_permissions(app, info, user_h, version, user_data, _mdata_del_user_permissions_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_permissions_new(self, app, user_data, o_cb=None):
        """
            App*, [any], [function], [custom ffi lib]
            App* app, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataPermissionsHandle perm_h)
        """
        @ffi.callback("void(void* ,FfiResult* ,MDataPermissionsHandle)")
        def _mdata_permissions_new_o_cb(user_data ,result ,perm_h):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,perm_h)
    
    
        self.lib.safe_app.mdata_permissions_new(app, user_data, _mdata_permissions_new_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_permissions_len(self, app, permissions_h, user_data, o_cb=None):
        """
            App*, MDataPermissionsHandle, [any], [function], [custom ffi lib]
            App* app, MDataPermissionsHandle permissions_h, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uintptr_t size)
        """
        @ffi.callback("void(void* ,FfiResult* ,uintptr_t)")
        def _mdata_permissions_len_o_cb(user_data ,result ,size):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,size)
    
    
        self.lib.safe_app.mdata_permissions_len(app, permissions_h, user_data, _mdata_permissions_len_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_permissions_get(self, app, permissions_h, user_h, user_data, o_cb=None):
        """
            App*, MDataPermissionsHandle, SignPubKeyHandle, [any], [function], [custom ffi lib]
            App* app, MDataPermissionsHandle permissions_h, SignPubKeyHandle user_h, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, PermissionSet* perm_set)
        """
        @ffi.callback("void(void* ,FfiResult* ,PermissionSet*)")
        def _mdata_permissions_get_o_cb(user_data ,result ,perm_set):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,perm_set)
    
    
        self.lib.safe_app.mdata_permissions_get(app, permissions_h, user_h, user_data, _mdata_permissions_get_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_list_permission_sets(self, app, permissions_h, user_data, o_cb=None):
        """
            App*, MDataPermissionsHandle, [any], [function], [custom ffi lib]
            App* app, MDataPermissionsHandle permissions_h, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, UserPermissionSet* user_perm_sets, uintptr_t user_perm_sets_len)
        """
        @ffi.callback("void(void* ,FfiResult* ,UserPermissionSet* ,uintptr_t)")
        def _mdata_list_permission_sets_o_cb(user_data ,result ,user_perm_sets ,user_perm_sets_len):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,user_perm_sets ,user_perm_sets_len)
    
    
        self.lib.safe_app.mdata_list_permission_sets(app, permissions_h, user_data, _mdata_list_permission_sets_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_permissions_insert(self, app, permissions_h, user_h, permission_set, user_data, o_cb=None):
        """
            App*, MDataPermissionsHandle, SignPubKeyHandle, PermissionSet*, [any], [function], [custom ffi lib]
            App* app, MDataPermissionsHandle permissions_h, SignPubKeyHandle user_h, PermissionSet* permission_set, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _mdata_permissions_insert_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        self.lib.safe_app.mdata_permissions_insert(app, permissions_h, user_h, permission_set, user_data, _mdata_permissions_insert_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_permissions_free(self, app, permissions_h, user_data, o_cb=None):
        """
            App*, MDataPermissionsHandle, [any], [function], [custom ffi lib]
            App* app, MDataPermissionsHandle permissions_h, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _mdata_permissions_free_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        self.lib.safe_app.mdata_permissions_free(app, permissions_h, user_data, _mdata_permissions_free_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_entry_actions_new(self, app, user_data, o_cb=None):
        """
            App*, [any], [function], [custom ffi lib]
            App* app, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataEntryActionsHandle entry_actions_h)
        """
        @ffi.callback("void(void* ,FfiResult* ,MDataEntryActionsHandle)")
        def _mdata_entry_actions_new_o_cb(user_data ,result ,entry_actions_h):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,entry_actions_h)
    
    
        self.lib.safe_app.mdata_entry_actions_new(app, user_data, _mdata_entry_actions_new_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_entry_actions_insert(self, app, actions_h, key, key_len, value, value_len, user_data, o_cb=None):
        """
            App*, MDataEntryActionsHandle, uint8_t*, uintptr_t, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
            App* app, MDataEntryActionsHandle actions_h, uint8_t* key, uintptr_t key_len, uint8_t* value, uintptr_t value_len, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _mdata_entry_actions_insert_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        self.lib.safe_app.mdata_entry_actions_insert(app, actions_h, key, key_len, value, value_len, user_data, _mdata_entry_actions_insert_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_entry_actions_update(self, app, actions_h, key, key_len, value, value_len, entry_version, user_data, o_cb=None):
        """
            App*, MDataEntryActionsHandle, uint8_t*, uintptr_t, uint8_t*, uintptr_t, uint64_t, [any], [function], [custom ffi lib]
            App* app, MDataEntryActionsHandle actions_h, uint8_t* key, uintptr_t key_len, uint8_t* value, uintptr_t value_len, uint64_t entry_version, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _mdata_entry_actions_update_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        self.lib.safe_app.mdata_entry_actions_update(app, actions_h, key, key_len, value, value_len, entry_version, user_data, _mdata_entry_actions_update_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_entry_actions_delete(self, app, actions_h, key, key_len, entry_version, user_data, o_cb=None):
        """
            App*, MDataEntryActionsHandle, uint8_t*, uintptr_t, uint64_t, [any], [function], [custom ffi lib]
            App* app, MDataEntryActionsHandle actions_h, uint8_t* key, uintptr_t key_len, uint64_t entry_version, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _mdata_entry_actions_delete_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        self.lib.safe_app.mdata_entry_actions_delete(app, actions_h, key, key_len, entry_version, user_data, _mdata_entry_actions_delete_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_entry_actions_free(self, app, actions_h, user_data, o_cb=None):
        """
            App*, MDataEntryActionsHandle, [any], [function], [custom ffi lib]
            App* app, MDataEntryActionsHandle actions_h, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _mdata_entry_actions_free_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        self.lib.safe_app.mdata_entry_actions_free(app, actions_h, user_data, _mdata_entry_actions_free_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_entries_new(self, app, user_data, o_cb=None):
        """
            App*, [any], [function], [custom ffi lib]
            App* app, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataEntriesHandle entries_h)
        """
        @ffi.callback("void(void* ,FfiResult* ,MDataEntriesHandle)")
        def _mdata_entries_new_o_cb(user_data ,result ,entries_h):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,entries_h)
    
    
        self.lib.safe_app.mdata_entries_new(app, user_data, _mdata_entries_new_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_entries_insert(self, app, entries_h, key, key_len, value, value_len, user_data, o_cb=None):
        """
            App*, MDataEntriesHandle, uint8_t*, uintptr_t, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
            App* app, MDataEntriesHandle entries_h, uint8_t* key, uintptr_t key_len, uint8_t* value, uintptr_t value_len, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _mdata_entries_insert_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        self.lib.safe_app.mdata_entries_insert(app, entries_h, key, key_len, value, value_len, user_data, _mdata_entries_insert_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_entries_len(self, app, entries_h, user_data, o_cb=None):
        """
            App*, MDataEntriesHandle, [any], [function], [custom ffi lib]
            App* app, MDataEntriesHandle entries_h, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uintptr_t len)
        """
        @ffi.callback("void(void* ,FfiResult* ,uintptr_t)")
        def _mdata_entries_len_o_cb(user_data ,result ,len):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,len)
    
    
        self.lib.safe_app.mdata_entries_len(app, entries_h, user_data, _mdata_entries_len_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_entries_get(self, app, entries_h, key, key_len, user_data, o_cb=None):
        """
            App*, MDataEntriesHandle, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
            App* app, MDataEntriesHandle entries_h, uint8_t* key, uintptr_t key_len, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* content, uintptr_t content_len, uint64_t version)
        """
        @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t ,uint64_t)")
        def _mdata_entries_get_o_cb(user_data ,result ,content ,content_len ,version):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,content ,content_len ,version)
    
    
        self.lib.safe_app.mdata_entries_get(app, entries_h, key, key_len, user_data, _mdata_entries_get_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_list_entries(self, app, entries_h, user_data, o_cb=None):
        """
            App*, MDataEntriesHandle, [any], [function], [custom ffi lib]
            App* app, MDataEntriesHandle entries_h, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataEntry* entries, uintptr_t entries_len)
        """
        @ffi.callback("void(void* ,FfiResult* ,MDataEntry* ,uintptr_t)")
        def _mdata_list_entries_o_cb(user_data ,result ,entries ,entries_len):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,entries ,entries_len)
    
    
        self.lib.safe_app.mdata_list_entries(app, entries_h, user_data, _mdata_list_entries_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=appQueue)
    def _mdata_entries_free(self, app, entries_h, user_data, o_cb=None):
        """
            App*, MDataEntriesHandle, [any], [function], [custom ffi lib]
            App* app, MDataEntriesHandle entries_h, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _mdata_entries_free_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            appQueue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        self.lib.safe_app.mdata_entries_free(app, entries_h, user_data, _mdata_entries_free_o_cb)