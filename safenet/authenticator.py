
class authenticator:
    def __init__(self,authlib,applib):
        self.lib_auth = authlib
        self.lib_app = authlib


    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_init_logging(self, output_file_name_override, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            bytes, [any], [function], [custom ffi lib]
            char* output_file_name_override, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _auth_init_logging_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        safenetLib.auth_init_logging(output_file_name_override, user_data, _auth_init_logging_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_output_log_path(self, output_file_name, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            bytes, [any], [function], [custom ffi lib]
            char* output_file_name, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* log_path)
        """
        @ffi.callback("void(void* ,FfiResult* ,char*)")
        def _auth_output_log_path_o_cb(user_data ,result ,log_path):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,log_path)
    
    
        safenetLib.auth_output_log_path(output_file_name, user_data, _auth_output_log_path_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _create_acc(self, account_locator, account_password, invitation, user_data, o_disconnect_notifier_cb=None, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            bytes, bytes, bytes, [any], [function], [function], [custom ffi lib]
            char* account_locator, char* account_password, char* invitation, void* user_data
    
            > callback functions:
            (*o_disconnect_notifier_cb)(void* user_data)
            (*o_cb)(void* user_data, FfiResult* result, Authenticator* authenticator)
        """
        @ffi.callback("void(void*)")
        def _create_acc_o_disconnect_notifier_cb(user_data):
            self.queue.put('gotResult')
            if o_disconnect_notifier_cb:
                o_disconnect_notifier_cb(user_data)
    
    
        @ffi.callback("void(void* ,FfiResult* ,Authenticator*)")
        def _create_acc_o_cb(user_data ,result ,authenticator):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,authenticator)
    
    
        safenetLib.create_acc(account_locator, account_password, invitation, user_data, _create_acc_o_disconnect_notifier_cb, _create_acc_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _login(self, account_locator, account_password, user_data, o_disconnect_notifier_cb=None, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            bytes, bytes, [any], [function], [function], [custom ffi lib]
            char* account_locator, char* account_password, void* user_data
    
            > callback functions:
            (*o_disconnect_notifier_cb)(void* user_data)
            (*o_cb)(void* user_data, FfiResult* result, Authenticator* authenticaor)
        """
        @ffi.callback("void(void*)")
        def _login_o_disconnect_notifier_cb(user_data):
            self.queue.put('gotResult')
            if o_disconnect_notifier_cb:
                o_disconnect_notifier_cb(user_data)
    
    
        @ffi.callback("void(void* ,FfiResult* ,Authenticator*)")
        def _login_o_cb(user_data ,result ,authenticaor):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,authenticaor)
    
    
        safenetLib.login(account_locator, account_password, user_data, _login_o_disconnect_notifier_cb, _login_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_reconnect(self, auth, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, [any], [function], [custom ffi lib]
            Authenticator* auth, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _auth_reconnect_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        safenetLib.auth_reconnect(auth, user_data, _auth_reconnect_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_account_info(self, auth, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, [any], [function], [custom ffi lib]
            Authenticator* auth, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AccountInfo* account_info)
        """
        @ffi.callback("void(void* ,FfiResult* ,AccountInfo*)")
        def _auth_account_info_o_cb(user_data ,result ,account_info):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,account_info)
    
    
        safenetLib.auth_account_info(auth, user_data, _auth_account_info_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_exe_file_stem(self, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            [any], [function], [custom ffi lib]
            void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* filename)
        """
        @ffi.callback("void(void* ,FfiResult* ,char*)")
        def _auth_exe_file_stem_o_cb(user_data ,result ,filename):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,filename)
    
    
        safenetLib.auth_exe_file_stem(user_data, _auth_exe_file_stem_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_set_additional_search_path(self, new_path, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            bytes, [any], [function], [custom ffi lib]
            char* new_path, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _auth_set_additional_search_path_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        safenetLib.auth_set_additional_search_path(new_path, user_data, _auth_set_additional_search_path_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_free(self, auth, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, [custom ffi lib]
            Authenticator* auth
    
            > callback functions:
        """
        safenetLib.auth_free(auth)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_unregistered_decode_ipc_msg(self, msg, user_data, o_unregistered=None, o_err=None, safenetLib=self.lib.safe_authenticator):
        """
            bytes, [any], [function], [function], [custom ffi lib]
            char* msg, void* user_data
    
            > callback functions:
            (*o_unregistered)(void* user_data, uint32_t req_id, uint8_t* extra_data, uintptr_t extra_data_len)
            (*o_err)(void* user_data, FfiResult* result, char* response)
        """
        @ffi.callback("void(void* ,uint32_t ,uint8_t* ,uintptr_t)")
        def _auth_unregistered_decode_ipc_msg_o_unregistered(user_data ,req_id ,extra_data ,extra_data_len):
            self.queue.put('gotResult')
            if o_unregistered:
                o_unregistered(user_data ,req_id ,extra_data ,extra_data_len)
    
    
        @ffi.callback("void(void* ,FfiResult* ,char*)")
        def _auth_unregistered_decode_ipc_msg_o_err(user_data ,result ,response):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_err:
                o_err(user_data ,result ,response)
    
    
        safenetLib.auth_unregistered_decode_ipc_msg(msg, user_data, _auth_unregistered_decode_ipc_msg_o_unregistered, _auth_unregistered_decode_ipc_msg_o_err)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_decode_ipc_msg(self, auth, msg, user_data, o_auth=None, o_containers=None, o_unregistered=None, o_share_mdata=None, o_err=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, bytes, [any], [function], [function], [function], [function], [function], [custom ffi lib]
            Authenticator* auth, char* msg, void* user_data
    
            > callback functions:
            (*o_auth)(void* user_data, uint32_t req_id, AuthReq* req)
            (*o_containers)(void* user_data, uint32_t req_id, ContainersReq* req)
            (*o_unregistered)(void* user_data, uint32_t req_id, uint8_t* extra_data, uintptr_t extra_data_len)
            (*o_share_mdata)(void* user_data, uint32_t req_id, ShareMDataReq* req, MetadataResponse* metadata, uintptr_t metadata_len)
            (*o_err)(void* user_data, FfiResult* result, char* response)
        """
        @ffi.callback("void(void* ,uint32_t ,AuthReq*)")
        def _auth_decode_ipc_msg_o_auth(user_data ,req_id ,req):
            self.queue.put('gotResult')
            if o_auth:
                o_auth(user_data ,req_id ,req)
    
    
        @ffi.callback("void(void* ,uint32_t ,ContainersReq*)")
        def _auth_decode_ipc_msg_o_containers(user_data ,req_id ,req):
            self.queue.put('gotResult')
            if o_containers:
                o_containers(user_data ,req_id ,req)
    
    
        @ffi.callback("void(void* ,uint32_t ,uint8_t* ,uintptr_t)")
        def _auth_decode_ipc_msg_o_unregistered(user_data ,req_id ,extra_data ,extra_data_len):
            self.queue.put('gotResult')
            if o_unregistered:
                o_unregistered(user_data ,req_id ,extra_data ,extra_data_len)
    
    
        @ffi.callback("void(void* ,uint32_t ,ShareMDataReq* ,MetadataResponse* ,uintptr_t)")
        def _auth_decode_ipc_msg_o_share_mdata(user_data ,req_id ,req ,metadata ,metadata_len):
            self.queue.put('gotResult')
            if o_share_mdata:
                o_share_mdata(user_data ,req_id ,req ,metadata ,metadata_len)
    
    
        @ffi.callback("void(void* ,FfiResult* ,char*)")
        def _auth_decode_ipc_msg_o_err(user_data ,result ,response):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_err:
                o_err(user_data ,result ,response)
    
    
        safenetLib.auth_decode_ipc_msg(auth, msg, user_data, _auth_decode_ipc_msg_o_auth, _auth_decode_ipc_msg_o_containers, _auth_decode_ipc_msg_o_unregistered, _auth_decode_ipc_msg_o_share_mdata, _auth_decode_ipc_msg_o_err)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _encode_share_mdata_resp(self, auth, req, req_id, is_granted, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, ShareMDataReq*, uint32_t, _Bool, [any], [function], [custom ffi lib]
            Authenticator* auth, ShareMDataReq* req, uint32_t req_id, _Bool is_granted, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @ffi.callback("void(void* ,FfiResult* ,char*)")
        def _encode_share_mdata_resp_o_cb(user_data ,result ,response):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)
    
    
        safenetLib.encode_share_mdata_resp(auth, req, req_id, is_granted, user_data, _encode_share_mdata_resp_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_revoke_app(self, auth, app_id, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, bytes, [any], [function], [custom ffi lib]
            Authenticator* auth, char* app_id, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @ffi.callback("void(void* ,FfiResult* ,char*)")
        def _auth_revoke_app_o_cb(user_data ,result ,response):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)
    
    
        safenetLib.auth_revoke_app(auth, app_id, user_data, _auth_revoke_app_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_flush_app_revocation_queue(self, auth, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, [any], [function], [custom ffi lib]
            Authenticator* auth, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _auth_flush_app_revocation_queue_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        safenetLib.auth_flush_app_revocation_queue(auth, user_data, _auth_flush_app_revocation_queue_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _encode_unregistered_resp(self, req_id, is_granted, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            uint32_t, _Bool, [any], [function], [custom ffi lib]
            uint32_t req_id, _Bool is_granted, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @ffi.callback("void(void* ,FfiResult* ,char*)")
        def _encode_unregistered_resp_o_cb(user_data ,result ,response):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)
    
    
        safenetLib.encode_unregistered_resp(req_id, is_granted, user_data, _encode_unregistered_resp_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _encode_auth_resp(self, auth, req, req_id, is_granted, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, AuthReq*, uint32_t, _Bool, [any], [function], [custom ffi lib]
            Authenticator* auth, AuthReq* req, uint32_t req_id, _Bool is_granted, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @ffi.callback("void(void* ,FfiResult* ,char*)")
        def _encode_auth_resp_o_cb(user_data ,result ,response):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)
    
    
        safenetLib.encode_auth_resp(auth, req, req_id, is_granted, user_data, _encode_auth_resp_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _encode_containers_resp(self, auth, req, req_id, is_granted, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, ContainersReq*, uint32_t, _Bool, [any], [function], [custom ffi lib]
            Authenticator* auth, ContainersReq* req, uint32_t req_id, _Bool is_granted, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @ffi.callback("void(void* ,FfiResult* ,char*)")
        def _encode_containers_resp_o_cb(user_data ,result ,response):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)
    
    
        safenetLib.encode_containers_resp(auth, req, req_id, is_granted, user_data, _encode_containers_resp_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_rm_revoked_app(self, auth, app_id, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, bytes, [any], [function], [custom ffi lib]
            Authenticator* auth, char* app_id, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @ffi.callback("void(void* ,FfiResult*)")
        def _auth_rm_revoked_app_o_cb(user_data ,result):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)
    
    
        safenetLib.auth_rm_revoked_app(auth, app_id, user_data, _auth_rm_revoked_app_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_revoked_apps(self, auth, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, [any], [function], [custom ffi lib]
            Authenticator* auth, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AppExchangeInfo* app_exchange_info, uintptr_t app_exchange_info_len)
        """
        @ffi.callback("void(void* ,FfiResult* ,AppExchangeInfo* ,uintptr_t)")
        def _auth_revoked_apps_o_cb(user_data ,result ,app_exchange_info ,app_exchange_info_len):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,app_exchange_info ,app_exchange_info_len)
    
    
        safenetLib.auth_revoked_apps(auth, user_data, _auth_revoked_apps_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_registered_apps(self, auth, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, [any], [function], [custom ffi lib]
            Authenticator* auth, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, RegisteredApp* registered_app, uintptr_t registered_app_len)
        """
        @ffi.callback("void(void* ,FfiResult* ,RegisteredApp* ,uintptr_t)")
        def _auth_registered_apps_o_cb(user_data ,result ,registered_app ,registered_app_len):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,registered_app ,registered_app_len)
    
    
        safenetLib.auth_registered_apps(auth, user_data, _auth_registered_apps_o_cb)
    
    
    
    @safeUtils.safeThread(timeout=5,queue=self.queue)
    def _auth_apps_accessing_mutable_data(self, auth, md_name, md_type_tag, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, XorNameArray*, uint64_t, [any], [function], [custom ffi lib]
            Authenticator* auth, XorNameArray* md_name, uint64_t md_type_tag, void* user_data
    
            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AppAccess* app_access, uintptr_t app_access_len)
        """
        @ffi.callback("void(void* ,FfiResult* ,AppAccess* ,uintptr_t)")
        def _auth_apps_accessing_mutable_data_o_cb(user_data ,result ,app_access ,app_access_len):
            self.safeUtils.checkResult(result)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,app_access ,app_access_len)
    
    
        safenetLib.auth_apps_accessing_mutable_data(auth, md_name, md_type_tag, user_data, _auth_apps_accessing_mutable_data_o_cb)
