### Experiments with ffi_binding separation
### safe_auth lib

import safenet.safeUtils as safeUtils

def auth_init_logging(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_init_logging(output_file_name_override, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            bytes, [any], [function], [custom ffi lib]
            char* output_file_name_override, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @self.ffi.callback("void(void* ,FfiResult*)")
        def _auth_init_logging_o_cb(user_data ,result):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)


        safenetLib.auth_init_logging(output_file_name_override, user_data, _auth_init_logging_o_cb)
    self._auth_init_logging = _auth_init_logging

def auth_output_log_path(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_output_log_path(output_file_name, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            bytes, [any], [function], [custom ffi lib]
            char* output_file_name, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* log_path)
        """
        @self.ffi.callback("void(void* ,FfiResult* ,char*)")
        def _auth_output_log_path_o_cb(user_data ,result ,log_path):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,log_path)


        safenetLib.auth_output_log_path(output_file_name, user_data, _auth_output_log_path_o_cb)
    self._auth_output_log_path = _auth_output_log_path

def create_acc(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _create_acc(account_locator, account_password, invitation, user_data, o_disconnect_notifier_cb=None, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            bytes, bytes, bytes, [any], [function], [function], [custom ffi lib]
            char* account_locator, char* account_password, char* invitation, void* user_data

            > callback functions:
            (*o_disconnect_notifier_cb)(void* user_data)
            (*o_cb)(void* user_data, FfiResult* result, Authenticator* authenticator)
        """
        @self.ffi.callback("void(void*)")
        def _create_acc_o_disconnect_notifier_cb(user_data):
            self.queue.put('gotResult')
            if o_disconnect_notifier_cb:
                o_disconnect_notifier_cb(user_data)


        @self.ffi.callback("void(void* ,FfiResult* ,Authenticator*)")
        def _create_acc_o_cb(user_data ,result ,authenticator):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,authenticator)


        safenetLib.create_acc(account_locator, account_password, invitation, user_data, _create_acc_o_disconnect_notifier_cb, _create_acc_o_cb)
    self._create_acc = _create_acc

def login(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _login(account_locator, account_password, user_data, o_disconnect_notifier_cb=None, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            bytes, bytes, [any], [function], [function], [custom ffi lib]
            char* account_locator, char* account_password, void* user_data

            > callback functions:
            (*o_disconnect_notifier_cb)(void* user_data)
            (*o_cb)(void* user_data, FfiResult* result, Authenticator* authenticaor)
        """
        @self.ffi.callback("void(void*)")
        def _login_o_disconnect_notifier_cb(user_data):
            self.queue.put('gotResult')
            if o_disconnect_notifier_cb:
                o_disconnect_notifier_cb(user_data)


        @self.ffi.callback("void(void* ,FfiResult* ,Authenticator*)")
        def _login_o_cb(user_data ,result ,authenticaor):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,authenticaor)


        safenetLib.login(account_locator, account_password, user_data, _login_o_disconnect_notifier_cb, _login_o_cb)
    self._login = _login

def auth_reconnect(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_reconnect(auth, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, [any], [function], [custom ffi lib]
            Authenticator* auth, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @self.ffi.callback("void(void* ,FfiResult*)")
        def _auth_reconnect_o_cb(user_data ,result):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)


        safenetLib.auth_reconnect(auth, user_data, _auth_reconnect_o_cb)
    self._auth_reconnect = _auth_reconnect

def auth_account_info(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_account_info(auth, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, [any], [function], [custom ffi lib]
            Authenticator* auth, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AccountInfo* account_info)
        """
        @self.ffi.callback("void(void* ,FfiResult* ,AccountInfo*)")
        def _auth_account_info_o_cb(user_data ,result ,account_info):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,account_info)


        safenetLib.auth_account_info(auth, user_data, _auth_account_info_o_cb)
    self._auth_account_info = _auth_account_info

def auth_exe_file_stem(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_exe_file_stem(user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            [any], [function], [custom ffi lib]
            void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* filename)
        """
        @self.ffi.callback("void(void* ,FfiResult* ,char*)")
        def _auth_exe_file_stem_o_cb(user_data ,result ,filename):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,filename)


        safenetLib.auth_exe_file_stem(user_data, _auth_exe_file_stem_o_cb)
    self._auth_exe_file_stem = _auth_exe_file_stem

def auth_set_additional_search_path(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_set_additional_search_path(new_path, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            bytes, [any], [function], [custom ffi lib]
            char* new_path, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @self.ffi.callback("void(void* ,FfiResult*)")
        def _auth_set_additional_search_path_o_cb(user_data ,result):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)


        safenetLib.auth_set_additional_search_path(new_path, user_data, _auth_set_additional_search_path_o_cb)
    self._auth_set_additional_search_path = _auth_set_additional_search_path

def auth_free(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_free(auth, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, [custom ffi lib]
            Authenticator* auth

            > callback functions:
        """
        safenetLib.auth_free(auth)
    self._auth_free = _auth_free

def auth_unregistered_decode_ipc_msg(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_unregistered_decode_ipc_msg(msg, user_data, o_unregistered=None, o_err=None, safenetLib=self.lib.safe_authenticator):
        """
            bytes, [any], [function], [function], [custom ffi lib]
            char* msg, void* user_data

            > callback functions:
            (*o_unregistered)(void* user_data, uint32_t req_id, uint8_t* extra_data, uintptr_t extra_data_len)
            (*o_err)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi.callback("void(void* ,uint32_t ,uint8_t* ,uintptr_t)")
        def _auth_unregistered_decode_ipc_msg_o_unregistered(user_data ,req_id ,extra_data ,extra_data_len):
            self.queue.put('gotResult')
            if o_unregistered:
                o_unregistered(user_data ,req_id ,extra_data ,extra_data_len)


        @self.ffi.callback("void(void* ,FfiResult* ,char*)")
        def _auth_unregistered_decode_ipc_msg_o_err(user_data ,result ,response):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_err:
                o_err(user_data ,result ,response)


        safenetLib.auth_unregistered_decode_ipc_msg(msg, user_data, _auth_unregistered_decode_ipc_msg_o_unregistered, _auth_unregistered_decode_ipc_msg_o_err)
    self._auth_unregistered_decode_ipc_msg = _auth_unregistered_decode_ipc_msg

def auth_decode_ipc_msg(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_decode_ipc_msg(auth, msg, user_data, o_auth=None, o_containers=None, o_unregistered=None, o_share_mdata=None, o_err=None, safenetLib=self.lib.safe_authenticator):
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
        @self.ffi.callback("void(void* ,uint32_t ,AuthReq*)")
        def _auth_decode_ipc_msg_o_auth(user_data ,req_id ,req):
            self.queue.put('gotResult')
            if o_auth:
                o_auth(user_data ,req_id ,req)


        @self.ffi.callback("void(void* ,uint32_t ,ContainersReq*)")
        def _auth_decode_ipc_msg_o_containers(user_data ,req_id ,req):
            self.queue.put('gotResult')
            if o_containers:
                o_containers(user_data ,req_id ,req)


        @self.ffi.callback("void(void* ,uint32_t ,uint8_t* ,uintptr_t)")
        def _auth_decode_ipc_msg_o_unregistered(user_data ,req_id ,extra_data ,extra_data_len):
            self.queue.put('gotResult')
            if o_unregistered:
                o_unregistered(user_data ,req_id ,extra_data ,extra_data_len)


        @self.ffi.callback("void(void* ,uint32_t ,ShareMDataReq* ,MetadataResponse* ,uintptr_t)")
        def _auth_decode_ipc_msg_o_share_mdata(user_data ,req_id ,req ,metadata ,metadata_len):
            self.queue.put('gotResult')
            if o_share_mdata:
                o_share_mdata(user_data ,req_id ,req ,metadata ,metadata_len)


        @self.ffi.callback("void(void* ,FfiResult* ,char*)")
        def _auth_decode_ipc_msg_o_err(user_data ,result ,response):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_err:
                o_err(user_data ,result ,response)


        safenetLib.auth_decode_ipc_msg(auth, msg, user_data, _auth_decode_ipc_msg_o_auth, _auth_decode_ipc_msg_o_containers, _auth_decode_ipc_msg_o_unregistered, _auth_decode_ipc_msg_o_share_mdata, _auth_decode_ipc_msg_o_err)
    self._auth_decode_ipc_msg = _auth_decode_ipc_msg

def encode_share_mdata_resp(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _encode_share_mdata_resp(auth, req, req_id, is_granted, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, ShareMDataReq*, uint32_t, _Bool, [any], [function], [custom ffi lib]
            Authenticator* auth, ShareMDataReq* req, uint32_t req_id, _Bool is_granted, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi.callback("void(void* ,FfiResult* ,char*)")
        def _encode_share_mdata_resp_o_cb(user_data ,result ,response):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)


        safenetLib.encode_share_mdata_resp(auth, req, req_id, is_granted, user_data, _encode_share_mdata_resp_o_cb)
    self._encode_share_mdata_resp = _encode_share_mdata_resp

def auth_revoke_app(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_revoke_app(auth, app_id, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, bytes, [any], [function], [custom ffi lib]
            Authenticator* auth, char* app_id, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi.callback("void(void* ,FfiResult* ,char*)")
        def _auth_revoke_app_o_cb(user_data ,result ,response):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)


        safenetLib.auth_revoke_app(auth, app_id, user_data, _auth_revoke_app_o_cb)
    self._auth_revoke_app = _auth_revoke_app

def auth_flush_app_revocation_queue(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_flush_app_revocation_queue(auth, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, [any], [function], [custom ffi lib]
            Authenticator* auth, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @self.ffi.callback("void(void* ,FfiResult*)")
        def _auth_flush_app_revocation_queue_o_cb(user_data ,result):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)


        safenetLib.auth_flush_app_revocation_queue(auth, user_data, _auth_flush_app_revocation_queue_o_cb)
    self._auth_flush_app_revocation_queue = _auth_flush_app_revocation_queue

def encode_unregistered_resp(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _encode_unregistered_resp(req_id, is_granted, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            uint32_t, _Bool, [any], [function], [custom ffi lib]
            uint32_t req_id, _Bool is_granted, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi.callback("void(void* ,FfiResult* ,char*)")
        def _encode_unregistered_resp_o_cb(user_data ,result ,response):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)


        safenetLib.encode_unregistered_resp(req_id, is_granted, user_data, _encode_unregistered_resp_o_cb)
    self._encode_unregistered_resp = _encode_unregistered_resp

def encode_auth_resp(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _encode_auth_resp(auth, req, req_id, is_granted, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, AuthReq*, uint32_t, _Bool, [any], [function], [custom ffi lib]
            Authenticator* auth, AuthReq* req, uint32_t req_id, _Bool is_granted, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi.callback("void(void* ,FfiResult* ,char*)")
        def _encode_auth_resp_o_cb(user_data ,result ,response):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)


        safenetLib.encode_auth_resp(auth, req, req_id, is_granted, user_data, _encode_auth_resp_o_cb)
    self._encode_auth_resp = _encode_auth_resp

def encode_containers_resp(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _encode_containers_resp(auth, req, req_id, is_granted, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, ContainersReq*, uint32_t, _Bool, [any], [function], [custom ffi lib]
            Authenticator* auth, ContainersReq* req, uint32_t req_id, _Bool is_granted, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi.callback("void(void* ,FfiResult* ,char*)")
        def _encode_containers_resp_o_cb(user_data ,result ,response):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)


        safenetLib.encode_containers_resp(auth, req, req_id, is_granted, user_data, _encode_containers_resp_o_cb)
    self._encode_containers_resp = _encode_containers_resp

def auth_rm_revoked_app(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_rm_revoked_app(auth, app_id, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, bytes, [any], [function], [custom ffi lib]
            Authenticator* auth, char* app_id, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @self.ffi.callback("void(void* ,FfiResult*)")
        def _auth_rm_revoked_app_o_cb(user_data ,result):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)


        safenetLib.auth_rm_revoked_app(auth, app_id, user_data, _auth_rm_revoked_app_o_cb)
    self._auth_rm_revoked_app = _auth_rm_revoked_app

def auth_revoked_apps(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_revoked_apps(auth, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, [any], [function], [custom ffi lib]
            Authenticator* auth, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AppExchangeInfo* app_exchange_info, uintptr_t app_exchange_info_len)
        """
        @self.ffi.callback("void(void* ,FfiResult* ,AppExchangeInfo* ,uintptr_t)")
        def _auth_revoked_apps_o_cb(user_data ,result ,app_exchange_info ,app_exchange_info_len):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,app_exchange_info ,app_exchange_info_len)


        safenetLib.auth_revoked_apps(auth, user_data, _auth_revoked_apps_o_cb)
    self._auth_revoked_apps = _auth_revoked_apps

def auth_registered_apps(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_registered_apps(auth, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, [any], [function], [custom ffi lib]
            Authenticator* auth, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, RegisteredApp* registered_app, uintptr_t registered_app_len)
        """
        @self.ffi.callback("void(void* ,FfiResult* ,RegisteredApp* ,uintptr_t)")
        def _auth_registered_apps_o_cb(user_data ,result ,registered_app ,registered_app_len):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,registered_app ,registered_app_len)


        safenetLib.auth_registered_apps(auth, user_data, _auth_registered_apps_o_cb)
    self._auth_registered_apps = _auth_registered_apps

def auth_apps_accessing_mutable_data(self, timeout):
    @safeUtils.safeThread(timeout=timeout,queue=self.queue)
    def _auth_apps_accessing_mutable_data(auth, md_name, md_type_tag, user_data, o_cb=None, safenetLib=self.lib.safe_authenticator):
        """
            Authenticator*, XorNameArray*, uint64_t, [any], [function], [custom ffi lib]
            Authenticator* auth, XorNameArray* md_name, uint64_t md_type_tag, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AppAccess* app_access, uintptr_t app_access_len)
        """
        @self.ffi.callback("void(void* ,FfiResult* ,AppAccess* ,uintptr_t)")
        def _auth_apps_accessing_mutable_data_o_cb(user_data ,result ,app_access ,app_access_len):
            safeUtils.checkResult(result,self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,app_access ,app_access_len)


        safenetLib.auth_apps_accessing_mutable_data(auth, md_name, md_type_tag, user_data, _auth_apps_accessing_mutable_data_o_cb)
    self._auth_apps_accessing_mutable_data = _auth_apps_accessing_mutable_data
