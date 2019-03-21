import safenet.safeUtils as safeUtils
import queue

# first attempt to define mutable Data for us
class mutableData:
    def __init__(self,authlib,applib,ffi,fromBytes=None):
        self.lib = safeUtils.lib(authlib,applib)
        self.queue = queue.Queue() 
        
        # defining the mutableData
        if fromBytes:
            self.asBytes = fromBytes
            #self.ffiMutable=ffi.new('MDataInfo *') - i think the ffi-datatypes should only exist locally in our functions
            # otherwise we can't pickle out own class (at least i got always faults when trying to do it with ffi classes yet)
        else:
            self.asBytes = None
    
    
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_list_keys(app, info, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, [any], [function], [custom ffi lib]
                App* app, MDataInfo* info, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataKey* keys, uintptr_t keys_len)
            """
            print('strange')
            #@ffi.callback("void(void* ,FfiResult* ,MDataKey* ,uintptr_t)")
            @ffi.callback("void(void* ,FfiResult* ,MDataKey* ,unsigned long)")
            def _mdata_list_keys_o_cb(user_data ,result ,keys ,keys_len):
                print('no')
                safeUtils.checkResult(result,ffi)
                #self.queue.put(ffi.string(result.keys))
                if o_cb:
                    o_cb(user_data ,result ,keys ,keys_len)
            
            print('hmhmm')
        
            safenetLib.mdata_list_keys(app, info, user_data, _mdata_list_keys_o_cb)
        self._mdata_list_keys = _mdata_list_keys        
    

    
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_encode_metadata(metadata, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                MetadataResponse*, [any], [function], [custom ffi lib]
                MetadataResponse* metadata, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* encoded, uintptr_t encoded_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _mdata_encode_metadata_o_cb(user_data ,result ,encoded ,encoded_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,encoded ,encoded_len)
        
        
            safenetLib.mdata_encode_metadata(metadata, user_data, _mdata_encode_metadata_o_cb)
        self._mdata_encode_metadata = _mdata_encode_metadata
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_info_new_private(name, type_tag, secret_key, nonce, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                XorNameArray*, uint64_t, SymSecretKey*, SymNonce*, [any], [function], [custom ffi lib]
                XorNameArray* name, uint64_t type_tag, SymSecretKey* secret_key, SymNonce* nonce, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataInfo* mdata_info)
            """
            @ffi.callback("void(void* ,FfiResult* ,MDataInfo*)")
            def _mdata_info_new_private_o_cb(user_data ,result ,mdata_info):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,mdata_info)
        
        
            safenetLib.mdata_info_new_private(name, type_tag, secret_key, nonce, user_data, _mdata_info_new_private_o_cb)
        self._mdata_info_new_private = _mdata_info_new_private
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_info_random_public(type_tag, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                uint64_t, [any], [function], [custom ffi lib]
                uint64_t type_tag, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataInfo* mdata_info)
            """
            @ffi.callback("void(void* ,FfiResult* ,MDataInfo*)")
            def _mdata_info_random_public_o_cb(user_data ,result ,mdata_info):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,mdata_info)
        
        
            safenetLib.mdata_info_random_public(type_tag, user_data, _mdata_info_random_public_o_cb)
        self._mdata_info_random_public = _mdata_info_random_public
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_info_random_private(type_tag, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                uint64_t, [any], [function], [custom ffi lib]
                uint64_t type_tag, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataInfo* mdata_info)
            """
            @ffi.callback("void(void* ,FfiResult* ,MDataInfo*)")
            def _mdata_info_random_private_o_cb(user_data ,result ,mdata_info):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,mdata_info)
        
        
            safenetLib.mdata_info_random_private(type_tag, user_data, _mdata_info_random_private_o_cb)
        self._mdata_info_random_private = _mdata_info_random_private
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_info_encrypt_entry_key(info, input, input_len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                MDataInfo*, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
                MDataInfo* info, uint8_t* input, uintptr_t input_len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* enc_entry_key, uintptr_t enc_entry_key_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _mdata_info_encrypt_entry_key_o_cb(user_data ,result ,enc_entry_key ,enc_entry_key_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,enc_entry_key ,enc_entry_key_len)
        
        
            safenetLib.mdata_info_encrypt_entry_key(info, input, input_len, user_data, _mdata_info_encrypt_entry_key_o_cb)
        self._mdata_info_encrypt_entry_key = _mdata_info_encrypt_entry_key
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_info_encrypt_entry_value(info, input, input_len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                MDataInfo*, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
                MDataInfo* info, uint8_t* input, uintptr_t input_len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* enc_entry_value, uintptr_t enc_entry_value_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _mdata_info_encrypt_entry_value_o_cb(user_data ,result ,enc_entry_value ,enc_entry_value_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,enc_entry_value ,enc_entry_value_len)
        
        
            safenetLib.mdata_info_encrypt_entry_value(info, input, input_len, user_data, _mdata_info_encrypt_entry_value_o_cb)
        self._mdata_info_encrypt_entry_value = _mdata_info_encrypt_entry_value
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_info_decrypt(info, input, input_len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                MDataInfo*, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
                MDataInfo* info, uint8_t* input, uintptr_t input_len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* mdata_info_decrypt, uintptr_t mdata_info_decrypt_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _mdata_info_decrypt_o_cb(user_data ,result ,mdata_info_decrypt ,mdata_info_decrypt_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,mdata_info_decrypt ,mdata_info_decrypt_len)
        
        
            safenetLib.mdata_info_decrypt(info, input, input_len, user_data, _mdata_info_decrypt_o_cb)
        self._mdata_info_decrypt = _mdata_info_decrypt
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_info_serialise(info, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                MDataInfo*, [any], [function], [custom ffi lib]
                MDataInfo* info, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* encoded, uintptr_t encoded_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _mdata_info_serialise_o_cb(user_data ,result ,encoded ,encoded_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,encoded ,encoded_len)
        
        
            safenetLib.mdata_info_serialise(info, user_data, _mdata_info_serialise_o_cb)
        self._mdata_info_serialise = _mdata_info_serialise
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_info_deserialise(encoded_ptr, encoded_len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
                uint8_t* encoded_ptr, uintptr_t encoded_len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataInfo* mdata_info)
            """
            @ffi.callback("void(void* ,FfiResult* ,MDataInfo*)")
            def _mdata_info_deserialise_o_cb(user_data ,result ,mdata_info):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,mdata_info)
        
        
            safenetLib.mdata_info_deserialise(encoded_ptr, encoded_len, user_data, _mdata_info_deserialise_o_cb)
        self._mdata_info_deserialise = _mdata_info_deserialise
        

        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_put(app, info, permissions_h, entries_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, MDataPermissionsHandle, MDataEntriesHandle, [any], [function], [custom ffi lib]
                App* app, MDataInfo* info, MDataPermissionsHandle permissions_h, MDataEntriesHandle entries_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _mdata_put_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.mdata_put(app, info, permissions_h, entries_h, user_data, _mdata_put_o_cb)
        self._mdata_put = _mdata_put
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_get_version(app, info, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, [any], [function], [custom ffi lib]
                App* app, MDataInfo* info, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint64_t version)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint64_t)")
            def _mdata_get_version_o_cb(user_data ,result ,version):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,version)
        
        
            safenetLib.mdata_get_version(app, info, user_data, _mdata_get_version_o_cb)
        self._mdata_get_version = _mdata_get_version
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_serialised_size(app, info, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, [any], [function], [custom ffi lib]
                App* app, MDataInfo* info, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint64_t serialised_size)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint64_t)")
            def _mdata_serialised_size_o_cb(user_data ,result ,serialised_size):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,serialised_size)
        
        
            safenetLib.mdata_serialised_size(app, info, user_data, _mdata_serialised_size_o_cb)
        self._mdata_serialised_size = _mdata_serialised_size
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_get_value(app, info, key, key_len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
                App* app, MDataInfo* info, uint8_t* key, uintptr_t key_len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* content, uintptr_t content_len, uint64_t version)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t ,uint64_t)")
            def _mdata_get_value_o_cb(user_data ,result ,content ,content_len ,version):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,content ,content_len ,version)
        
        
            safenetLib.mdata_get_value(app, info, key, key_len, user_data, _mdata_get_value_o_cb)
        self._mdata_get_value = _mdata_get_value
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_entries(app, info, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, [any], [function], [custom ffi lib]
                App* app, MDataInfo* info, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataEntriesHandle entries_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,MDataEntriesHandle)")
            def _mdata_entries_o_cb(user_data ,result ,entries_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,entries_h)
        
        
            safenetLib.mdata_entries(app, info, user_data, _mdata_entries_o_cb)
        self._mdata_entries = _mdata_entries
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_list_values(app, info, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, [any], [function], [custom ffi lib]
                App* app, MDataInfo* info, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataValue* values, uintptr_t values_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,MDataValue* ,uintptr_t)")
            def _mdata_list_values_o_cb(user_data ,result ,values ,values_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put(ffi.string(values))
                if o_cb:
                    o_cb(user_data ,result ,values ,values_len)
        
        
            safenetLib.mdata_list_values(app, info, user_data, _mdata_list_values_o_cb)
        self._mdata_list_values = _mdata_list_values
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_mutate_entries(app, info, actions_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, MDataEntryActionsHandle, [any], [function], [custom ffi lib]
                App* app, MDataInfo* info, MDataEntryActionsHandle actions_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _mdata_mutate_entries_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.mdata_mutate_entries(app, info, actions_h, user_data, _mdata_mutate_entries_o_cb)
        self._mdata_mutate_entries = _mdata_mutate_entries
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_list_permissions(app, info, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, [any], [function], [custom ffi lib]
                App* app, MDataInfo* info, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataPermissionsHandle perm_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,MDataPermissionsHandle)")
            def _mdata_list_permissions_o_cb(user_data ,result ,perm_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,perm_h)
        
        
            safenetLib.mdata_list_permissions(app, info, user_data, _mdata_list_permissions_o_cb)
        self._mdata_list_permissions = _mdata_list_permissions
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_list_user_permissions(app, info, user_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, SignPubKeyHandle, [any], [function], [custom ffi lib]
                App* app, MDataInfo* info, SignPubKeyHandle user_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, PermissionSet* perm_set)
            """
            @ffi.callback("void(void* ,FfiResult* ,PermissionSet*)")
            def _mdata_list_user_permissions_o_cb(user_data ,result ,perm_set):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,perm_set)
        
        
            safenetLib.mdata_list_user_permissions(app, info, user_h, user_data, _mdata_list_user_permissions_o_cb)
        self._mdata_list_user_permissions = _mdata_list_user_permissions
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_set_user_permissions(app, info, user_h, permission_set, version, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, SignPubKeyHandle, PermissionSet*, uint64_t, [any], [function], [custom ffi lib]
                App* app, MDataInfo* info, SignPubKeyHandle user_h, PermissionSet* permission_set, uint64_t version, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _mdata_set_user_permissions_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.mdata_set_user_permissions(app, info, user_h, permission_set, version, user_data, _mdata_set_user_permissions_o_cb)
        self._mdata_set_user_permissions = _mdata_set_user_permissions
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_del_user_permissions(app, info, user_h, version, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, SignPubKeyHandle, uint64_t, [any], [function], [custom ffi lib]
                App* app, MDataInfo* info, SignPubKeyHandle user_h, uint64_t version, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _mdata_del_user_permissions_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.mdata_del_user_permissions(app, info, user_h, version, user_data, _mdata_del_user_permissions_o_cb)
        self._mdata_del_user_permissions = _mdata_del_user_permissions
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_permissions_new(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataPermissionsHandle perm_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,MDataPermissionsHandle)")
            def _mdata_permissions_new_o_cb(user_data ,result ,perm_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,perm_h)
        
        
            safenetLib.mdata_permissions_new(app, user_data, _mdata_permissions_new_o_cb)
        self._mdata_permissions_new = _mdata_permissions_new
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_permissions_len(app, permissions_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataPermissionsHandle, [any], [function], [custom ffi lib]
                App* app, MDataPermissionsHandle permissions_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uintptr_t size)
            """
            @ffi.callback("void(void* ,FfiResult* ,uintptr_t)")
            def _mdata_permissions_len_o_cb(user_data ,result ,size):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,size)
        
        
            safenetLib.mdata_permissions_len(app, permissions_h, user_data, _mdata_permissions_len_o_cb)
        self._mdata_permissions_len = _mdata_permissions_len
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_permissions_get(app, permissions_h, user_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataPermissionsHandle, SignPubKeyHandle, [any], [function], [custom ffi lib]
                App* app, MDataPermissionsHandle permissions_h, SignPubKeyHandle user_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, PermissionSet* perm_set)
            """
            @ffi.callback("void(void* ,FfiResult* ,PermissionSet*)")
            def _mdata_permissions_get_o_cb(user_data ,result ,perm_set):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,perm_set)
        
        
            safenetLib.mdata_permissions_get(app, permissions_h, user_h, user_data, _mdata_permissions_get_o_cb)
        self._mdata_permissions_get = _mdata_permissions_get
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_list_permission_sets(app, permissions_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataPermissionsHandle, [any], [function], [custom ffi lib]
                App* app, MDataPermissionsHandle permissions_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, UserPermissionSet* user_perm_sets, uintptr_t user_perm_sets_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,UserPermissionSet* ,uintptr_t)")
            def _mdata_list_permission_sets_o_cb(user_data ,result ,user_perm_sets ,user_perm_sets_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,user_perm_sets ,user_perm_sets_len)
        
        
            safenetLib.mdata_list_permission_sets(app, permissions_h, user_data, _mdata_list_permission_sets_o_cb)
        self._mdata_list_permission_sets = _mdata_list_permission_sets
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_permissions_insert(app, permissions_h, user_h, permission_set, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataPermissionsHandle, SignPubKeyHandle, PermissionSet*, [any], [function], [custom ffi lib]
                App* app, MDataPermissionsHandle permissions_h, SignPubKeyHandle user_h, PermissionSet* permission_set, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _mdata_permissions_insert_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.mdata_permissions_insert(app, permissions_h, user_h, permission_set, user_data, _mdata_permissions_insert_o_cb)
        self._mdata_permissions_insert = _mdata_permissions_insert
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_permissions_free(app, permissions_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataPermissionsHandle, [any], [function], [custom ffi lib]
                App* app, MDataPermissionsHandle permissions_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _mdata_permissions_free_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.mdata_permissions_free(app, permissions_h, user_data, _mdata_permissions_free_o_cb)
        self._mdata_permissions_free = _mdata_permissions_free
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_entry_actions_new(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataEntryActionsHandle entry_actions_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,MDataEntryActionsHandle)")
            def _mdata_entry_actions_new_o_cb(user_data ,result ,entry_actions_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,entry_actions_h)
        
        
            safenetLib.mdata_entry_actions_new(app, user_data, _mdata_entry_actions_new_o_cb)
        self._mdata_entry_actions_new = _mdata_entry_actions_new
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_entry_actions_insert(app, actions_h, key, key_len, value, value_len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataEntryActionsHandle, uint8_t*, uintptr_t, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
                App* app, MDataEntryActionsHandle actions_h, uint8_t* key, uintptr_t key_len, uint8_t* value, uintptr_t value_len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _mdata_entry_actions_insert_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.mdata_entry_actions_insert(app, actions_h, key, key_len, value, value_len, user_data, _mdata_entry_actions_insert_o_cb)
        self._mdata_entry_actions_insert = _mdata_entry_actions_insert
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_entry_actions_update(app, actions_h, key, key_len, value, value_len, entry_version, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataEntryActionsHandle, uint8_t*, uintptr_t, uint8_t*, uintptr_t, uint64_t, [any], [function], [custom ffi lib]
                App* app, MDataEntryActionsHandle actions_h, uint8_t* key, uintptr_t key_len, uint8_t* value, uintptr_t value_len, uint64_t entry_version, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _mdata_entry_actions_update_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.mdata_entry_actions_update(app, actions_h, key, key_len, value, value_len, entry_version, user_data, _mdata_entry_actions_update_o_cb)
        self._mdata_entry_actions_update = _mdata_entry_actions_update
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_entry_actions_delete(app, actions_h, key, key_len, entry_version, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataEntryActionsHandle, uint8_t*, uintptr_t, uint64_t, [any], [function], [custom ffi lib]
                App* app, MDataEntryActionsHandle actions_h, uint8_t* key, uintptr_t key_len, uint64_t entry_version, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _mdata_entry_actions_delete_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.mdata_entry_actions_delete(app, actions_h, key, key_len, entry_version, user_data, _mdata_entry_actions_delete_o_cb)
        self._mdata_entry_actions_delete = _mdata_entry_actions_delete
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_entry_actions_free(app, actions_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataEntryActionsHandle, [any], [function], [custom ffi lib]
                App* app, MDataEntryActionsHandle actions_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _mdata_entry_actions_free_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.mdata_entry_actions_free(app, actions_h, user_data, _mdata_entry_actions_free_o_cb)
        self._mdata_entry_actions_free = _mdata_entry_actions_free
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_entries_new(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataEntriesHandle entries_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,MDataEntriesHandle)")
            def _mdata_entries_new_o_cb(user_data ,result ,entries_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,entries_h)
        
        
            safenetLib.mdata_entries_new(app, user_data, _mdata_entries_new_o_cb)
        self._mdata_entries_new = _mdata_entries_new
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_entries_insert(app, entries_h, key, key_len, value, value_len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataEntriesHandle, uint8_t*, uintptr_t, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
                App* app, MDataEntriesHandle entries_h, uint8_t* key, uintptr_t key_len, uint8_t* value, uintptr_t value_len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _mdata_entries_insert_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.mdata_entries_insert(app, entries_h, key, key_len, value, value_len, user_data, _mdata_entries_insert_o_cb)
        self._mdata_entries_insert = _mdata_entries_insert
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_entries_len(app, entries_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataEntriesHandle, [any], [function], [custom ffi lib]
                App* app, MDataEntriesHandle entries_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uintptr_t len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uintptr_t)")
            def _mdata_entries_len_o_cb(user_data ,result ,len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,len)
        
        
            safenetLib.mdata_entries_len(app, entries_h, user_data, _mdata_entries_len_o_cb)
        self._mdata_entries_len = _mdata_entries_len
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_entries_get(app, entries_h, key, key_len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataEntriesHandle, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
                App* app, MDataEntriesHandle entries_h, uint8_t* key, uintptr_t key_len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* content, uintptr_t content_len, uint64_t version)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t ,uint64_t)")
            def _mdata_entries_get_o_cb(user_data ,result ,content ,content_len ,version):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,content ,content_len ,version)
        
        
            safenetLib.mdata_entries_get(app, entries_h, key, key_len, user_data, _mdata_entries_get_o_cb)
        self._mdata_entries_get = _mdata_entries_get
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_list_entries(app, entries_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataEntriesHandle, [any], [function], [custom ffi lib]
                App* app, MDataEntriesHandle entries_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataEntry* entries, uintptr_t entries_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,MDataEntry* ,uintptr_t)")
            def _mdata_list_entries_o_cb(user_data ,result ,entries ,entries_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,entries ,entries_len)
        
        
            safenetLib.mdata_list_entries(app, entries_h, user_data, _mdata_list_entries_o_cb)
        self._mdata_list_entries = _mdata_list_entries
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _mdata_entries_free(app, entries_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataEntriesHandle, [any], [function], [custom ffi lib]
                App* app, MDataEntriesHandle entries_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _mdata_entries_free_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.mdata_entries_free(app, entries_h, user_data, _mdata_entries_free_o_cb)
        self._mdata_entries_free = _mdata_entries_free

        