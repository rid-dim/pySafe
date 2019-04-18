### FFI Binding Wrappers for libsafe_authenticator

import safenet.safe_utils as safeUtils
from collections import defaultdict
import queue
LOCAL_QUEUES = defaultdict(queue.Queue)

_AUTH_DEFS=["auth_init_logging","auth_output_log_path","create_acc","login","auth_reconnect","auth_account_info",
            "auth_exe_file_stem","auth_set_additional_search_path","auth_free","auth_unregistered_decode_ipc_msg",
            "auth_decode_ipc_msg","encode_share_mdata_resp","auth_revoke_app","auth_flush_app_revocation_queue",
            "encode_unregistered_resp","encode_auth_resp","encode_containers_resp","auth_rm_revoked_app",
            "auth_revoked_apps","auth_registered_apps","auth_apps_accessing_mutable_data"]

'''
The general structure of these functions is:
1. An outer wrapper, which is used to bind the function to an object (passed in as self)
    2. A decorator that implements the current threading model (passed in by the calling object)
    3. The (now threaded) function that actually invokes the c-ffi function in the client libs.
    The *_cb parameters are for passing in python callbacks
        4. A decorator from the cffi interface that declares a c callback available to the libs
        The safenet client libs use callbacks instead of returns because are asynchronous
        5. The callbacks themselves, named corresponding to the safe ffi lib signature
            6. If a python callback is passed in, it is called here. 

        The line that actually calls the ffi lib function
    The line that binds the defined function to the object passed in. 
'''

def auth_init_logging(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_init_logging(output_file_name_override, user_data, o_cb=None):
        """
            bytes, [any], [function]
            char* output_file_name_override, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult*)")
        def _auth_init_logging_o_cb(user_data ,result):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_init_logging_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_init_logging_o_cb'].put(_auth_init_logging_o_cb)


        self.lib.safe_authenticator.auth_init_logging(output_file_name_override, user_data, _auth_init_logging_o_cb)
    self._auth_init_logging = _auth_init_logging

def auth_output_log_path(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_output_log_path(output_file_name, user_data, o_cb=None):
        """
            bytes, [any], [function]
            char* output_file_name, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* log_path)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult* ,char*)")
        def _auth_output_log_path_o_cb(user_data ,result ,log_path):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_output_log_path_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,log_path)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_output_log_path_o_cb'].put(_auth_output_log_path_o_cb)


        self.lib.safe_authenticator.auth_output_log_path(output_file_name, user_data, _auth_output_log_path_o_cb)
    self._auth_output_log_path = _auth_output_log_path

def create_acc(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _create_acc(account_locator, account_password, invitation, user_data, o_disconnect_notifier_cb=None, o_cb=None):
        """
            bytes, bytes, bytes, [any], [function], [function]
            char* account_locator, char* account_password, char* invitation, void* user_data

            > callback functions:
            (*o_disconnect_notifier_cb)(void* user_data)
            (*o_cb)(void* user_data, FfiResult* result, Authenticator* authenticator)
        """
        @self.ffi_auth.callback("void(void*)")
        def _create_acc_o_disconnect_notifier_cb(user_data):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_create_acc_o_disconnect_notifier_cb'].get_nowait()}")
            self.queue.put('gotResult')
            if o_disconnect_notifier_cb:
                o_disconnect_notifier_cb(user_data)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_create_acc_o_disconnect_notifier_cb'].put(_create_acc_o_disconnect_notifier_cb)


        @self.ffi_auth.callback("void(void* ,FfiResult* ,Authenticator*)")
        def _create_acc_o_cb(user_data ,result ,authenticator):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_create_acc_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,authenticator)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_create_acc_o_cb'].put(_create_acc_o_cb)


        self.lib.safe_authenticator.create_acc(account_locator, account_password, invitation, user_data, _create_acc_o_disconnect_notifier_cb, _create_acc_o_cb)
    self._create_acc = _create_acc

def login(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _login(account_locator, account_password, user_data, o_disconnect_notifier_cb=None, o_cb=None):
        """
            bytes, bytes, [any], [function], [function]
            char* account_locator, char* account_password, void* user_data

            > callback functions:
            (*o_disconnect_notifier_cb)(void* user_data)
            (*o_cb)(void* user_data, FfiResult* result, Authenticator* authenticaor)
        """
        log.debug('login called')
        @self.ffi_auth.callback("void(void*)")
        def _login_o_disconnect_notifier_cb(user_data):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_login_o_disconnect_notifier_cb'].get_nowait()}")
            self.queue.put('gotResult')
            if o_disconnect_notifier_cb:
                o_disconnect_notifier_cb(user_data)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_login_o_disconnect_notifier_cb'].put(_login_o_disconnect_notifier_cb)


        @self.ffi_auth.callback("void(void* ,FfiResult* ,Authenticator*)")
        def _login_o_cb(user_data ,result ,authenticaor):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_login_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            user_data = self if user_data == self.ffi_auth.NULL else self.ffi_auth.from_handle(user_data)
            if o_cb:
                o_cb(user_data ,result ,authenticaor)  #  If user data is None, we should send self to the CB


        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_login_o_cb'].put(_login_o_cb)


        self.lib.safe_authenticator.login(account_locator, account_password, user_data, _login_o_disconnect_notifier_cb, _login_o_cb)
    self._login = _login

def auth_reconnect(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_reconnect(auth, user_data, o_cb=None):
        """
            Authenticator*, [any], [function]
            Authenticator* auth, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult*)")
        def _auth_reconnect_o_cb(user_data ,result):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_reconnect_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_reconnect_o_cb'].put(_auth_reconnect_o_cb)


        self.lib.safe_authenticator.auth_reconnect(auth, user_data, _auth_reconnect_o_cb)
    self._auth_reconnect = _auth_reconnect

def auth_account_info(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_account_info(auth, user_data, o_cb=None):
        """
            Authenticator*, [any], [function]
            Authenticator* auth, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AccountInfo* account_info)
        """
        log.debug('auth_acount_info called')
        @self.ffi_auth.callback("void(void* ,FfiResult* ,AccountInfo*)")
        def _auth_account_info_o_cb(user_data ,result ,account_info):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_account_info_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,account_info)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_account_info_o_cb'].put(_auth_account_info_o_cb)


        self.lib.safe_authenticator.auth_account_info(auth, user_data, _auth_account_info_o_cb)
    self._auth_account_info = _auth_account_info

def auth_exe_file_stem(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_exe_file_stem(user_data, o_cb=None):
        """
            [any], [function]
            void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* filename)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult* ,char*)")
        def _auth_exe_file_stem_o_cb(user_data ,result ,filename):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_exe_file_stem_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,filename)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_exe_file_stem_o_cb'].put(_auth_exe_file_stem_o_cb)


        self.lib.safe_authenticator.auth_exe_file_stem(user_data, _auth_exe_file_stem_o_cb)
    self._auth_exe_file_stem = _auth_exe_file_stem

def auth_set_additional_search_path(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_set_additional_search_path(new_path, user_data, o_cb=None):
        """
            bytes, [any], [function]
            char* new_path, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult*)")
        def _auth_set_additional_search_path_o_cb(user_data ,result):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_set_additional_search_path_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_set_additional_search_path_o_cb'].put(_auth_set_additional_search_path_o_cb)


        self.lib.safe_authenticator.auth_set_additional_search_path(new_path, user_data, _auth_set_additional_search_path_o_cb)
    self._auth_set_additional_search_path = _auth_set_additional_search_path

def auth_free(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_free(auth):
        """
            Authenticator*
            Authenticator* auth

            > callback functions:
        """
        self.lib.safe_authenticator.auth_free(auth)
    self._auth_free = _auth_free

def auth_unregistered_decode_ipc_msg(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_unregistered_decode_ipc_msg(msg, user_data, o_unregistered=None, o_err=None):
        """
            bytes, [any], [function], [function]
            char* msg, void* user_data

            > callback functions:
            (*o_unregistered)(void* user_data, uint32_t req_id, uint8_t* extra_data, uintptr_t extra_data_len)
            (*o_err)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi_auth.callback("void(void* ,uint32_t ,uint8_t* ,uintptr_t)")
        def _auth_unregistered_decode_ipc_msg_o_unregistered(user_data ,req_id ,extra_data ,extra_data_len):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_unregistered_decode_ipc_msg_o_unregistered'].get_nowait()}")
            self.queue.put('gotResult')
            if o_unregistered:
                o_unregistered(user_data ,req_id ,extra_data ,extra_data_len)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_unregistered_decode_ipc_msg_o_unregistered'].put(_auth_unregistered_decode_ipc_msg_o_unregistered)


        @self.ffi_auth.callback("void(void* ,FfiResult* ,char*)")
        def _auth_unregistered_decode_ipc_msg_o_err(user_data ,result ,response):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_unregistered_decode_ipc_msg_o_err'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_err:
                o_err(user_data ,result ,response)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_unregistered_decode_ipc_msg_o_err'].put(_auth_unregistered_decode_ipc_msg_o_err)


        self.lib.safe_authenticator.auth_unregistered_decode_ipc_msg(msg, user_data, _auth_unregistered_decode_ipc_msg_o_unregistered, _auth_unregistered_decode_ipc_msg_o_err)
    self._auth_unregistered_decode_ipc_msg = _auth_unregistered_decode_ipc_msg

def auth_decode_ipc_msg(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_decode_ipc_msg(auth, msg, user_data, o_auth=None, o_containers=None, o_unregistered=None, o_share_mdata=None, o_err=None):
        """
            Authenticator*, bytes, [any], [function], [function], [function], [function], [function]
            Authenticator* auth, char* msg, void* user_data

            > callback functions:
            (*o_auth)(void* user_data, uint32_t req_id, AuthReq* req)
            (*o_containers)(void* user_data, uint32_t req_id, ContainersReq* req)
            (*o_unregistered)(void* user_data, uint32_t req_id, uint8_t* extra_data, uintptr_t extra_data_len)
            (*o_share_mdata)(void* user_data, uint32_t req_id, ShareMDataReq* req, MetadataResponse* metadata, uintptr_t metadata_len)
            (*o_err)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi_auth.callback("void(void* ,uint32_t ,AuthReq*)")
        def _auth_decode_ipc_msg_o_auth(user_data ,req_id ,req):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_decode_ipc_msg_o_auth'].get_nowait()}")
            self.queue.put('gotResult')
            if o_auth:
                o_auth(user_data ,req_id ,req)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_decode_ipc_msg_o_auth'].put(_auth_decode_ipc_msg_o_auth)


        @self.ffi_auth.callback("void(void* ,uint32_t ,ContainersReq*)")
        def _auth_decode_ipc_msg_o_containers(user_data ,req_id ,req):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_decode_ipc_msg_o_containers'].get_nowait()}")
            self.queue.put('gotResult')
            if o_containers:
                o_containers(user_data ,req_id ,req)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_decode_ipc_msg_o_containers'].put(_auth_decode_ipc_msg_o_containers)


        @self.ffi_auth.callback("void(void* ,uint32_t ,uint8_t* ,uintptr_t)")
        def _auth_decode_ipc_msg_o_unregistered(user_data ,req_id ,extra_data ,extra_data_len):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_decode_ipc_msg_o_unregistered'].get_nowait()}")
            self.queue.put('gotResult')
            if o_unregistered:
                o_unregistered(user_data ,req_id ,extra_data ,extra_data_len)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_decode_ipc_msg_o_unregistered'].put(_auth_decode_ipc_msg_o_unregistered)


        @self.ffi_auth.callback("void(void* ,uint32_t ,ShareMDataReq* ,MetadataResponse* ,uintptr_t)")
        def _auth_decode_ipc_msg_o_share_mdata(user_data ,req_id ,req ,metadata ,metadata_len):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_decode_ipc_msg_o_share_mdata'].get_nowait()}")
            self.queue.put('gotResult')
            if o_share_mdata:
                o_share_mdata(user_data ,req_id ,req ,metadata ,metadata_len)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_decode_ipc_msg_o_share_mdata'].put(_auth_decode_ipc_msg_o_share_mdata)


        @self.ffi_auth.callback("void(void* ,FfiResult* ,char*)")
        def _auth_decode_ipc_msg_o_err(user_data ,result ,response):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_decode_ipc_msg_o_err'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_err:
                o_err(user_data ,result ,response)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_decode_ipc_msg_o_err'].put(_auth_decode_ipc_msg_o_err)


        self.lib.safe_authenticator.auth_decode_ipc_msg(auth, msg, user_data, _auth_decode_ipc_msg_o_auth, _auth_decode_ipc_msg_o_containers, _auth_decode_ipc_msg_o_unregistered, _auth_decode_ipc_msg_o_share_mdata, _auth_decode_ipc_msg_o_err)
    self._auth_decode_ipc_msg = _auth_decode_ipc_msg

def encode_share_mdata_resp(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _encode_share_mdata_resp(auth, req, req_id, is_granted, user_data, o_cb=None):
        """
            Authenticator*, ShareMDataReq*, uint32_t, _Bool, [any], [function]
            Authenticator* auth, ShareMDataReq* req, uint32_t req_id, _Bool is_granted, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult* ,char*)")
        def _encode_share_mdata_resp_o_cb(user_data ,result ,response):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_encode_share_mdata_resp_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_encode_share_mdata_resp_o_cb'].put(_encode_share_mdata_resp_o_cb)


        self.lib.safe_authenticator.encode_share_mdata_resp(auth, req, req_id, is_granted, user_data, _encode_share_mdata_resp_o_cb)
    self._encode_share_mdata_resp = _encode_share_mdata_resp

def auth_revoke_app(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_revoke_app(auth, app_id, user_data, o_cb=None):
        """
            Authenticator*, bytes, [any], [function]
            Authenticator* auth, char* app_id, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult* ,char*)")
        def _auth_revoke_app_o_cb(user_data ,result ,response):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_revoke_app_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_revoke_app_o_cb'].put(_auth_revoke_app_o_cb)


        self.lib.safe_authenticator.auth_revoke_app(auth, app_id, user_data, _auth_revoke_app_o_cb)
    self._auth_revoke_app = _auth_revoke_app

def auth_flush_app_revocation_queue(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_flush_app_revocation_queue(auth, user_data, o_cb=None):
        """
            Authenticator*, [any], [function]
            Authenticator* auth, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult*)")
        def _auth_flush_app_revocation_queue_o_cb(user_data ,result):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_flush_app_revocation_queue_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_flush_app_revocation_queue_o_cb'].put(_auth_flush_app_revocation_queue_o_cb)


        self.lib.safe_authenticator.auth_flush_app_revocation_queue(auth, user_data, _auth_flush_app_revocation_queue_o_cb)
    self._auth_flush_app_revocation_queue = _auth_flush_app_revocation_queue

def encode_unregistered_resp(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _encode_unregistered_resp(req_id, is_granted, user_data, o_cb=None):
        """
            uint32_t, _Bool, [any], [function]
            uint32_t req_id, _Bool is_granted, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult* ,char*)")
        def _encode_unregistered_resp_o_cb(user_data ,result ,response):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_encode_unregistered_resp_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_encode_unregistered_resp_o_cb'].put(_encode_unregistered_resp_o_cb)


        self.lib.safe_authenticator.encode_unregistered_resp(req_id, is_granted, user_data, _encode_unregistered_resp_o_cb)
    self._encode_unregistered_resp = _encode_unregistered_resp

def encode_auth_resp(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _encode_auth_resp(auth, req, req_id, is_granted, user_data, o_cb=None):
        """
            Authenticator*, AuthReq*, uint32_t, _Bool, [any], [function]
            Authenticator* auth, AuthReq* req, uint32_t req_id, _Bool is_granted, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult* ,char*)")
        def _encode_auth_resp_o_cb(user_data ,result ,response):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_encode_auth_resp_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_encode_auth_resp_o_cb'].put(_encode_auth_resp_o_cb)


        self.lib.safe_authenticator.encode_auth_resp(auth, req, req_id, is_granted, user_data, _encode_auth_resp_o_cb)
    self._encode_auth_resp = _encode_auth_resp

def encode_containers_resp(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _encode_containers_resp(auth, req, req_id, is_granted, user_data, o_cb=None):
        """
            Authenticator*, ContainersReq*, uint32_t, _Bool, [any], [function]
            Authenticator* auth, ContainersReq* req, uint32_t req_id, _Bool is_granted, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* response)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult* ,char*)")
        def _encode_containers_resp_o_cb(user_data ,result ,response):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_encode_containers_resp_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,response)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_encode_containers_resp_o_cb'].put(_encode_containers_resp_o_cb)


        self.lib.safe_authenticator.encode_containers_resp(auth, req, req_id, is_granted, user_data, _encode_containers_resp_o_cb)
    self._encode_containers_resp = _encode_containers_resp

def auth_rm_revoked_app(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_rm_revoked_app(auth, app_id, user_data, o_cb=None):
        """
            Authenticator*, bytes, [any], [function]
            Authenticator* auth, char* app_id, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult*)")
        def _auth_rm_revoked_app_o_cb(user_data ,result):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_rm_revoked_app_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_rm_revoked_app_o_cb'].put(_auth_rm_revoked_app_o_cb)


        self.lib.safe_authenticator.auth_rm_revoked_app(auth, app_id, user_data, _auth_rm_revoked_app_o_cb)
    self._auth_rm_revoked_app = _auth_rm_revoked_app

def auth_revoked_apps(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_revoked_apps(auth, user_data, o_cb=None):
        """
            Authenticator*, [any], [function]
            Authenticator* auth, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AppExchangeInfo* app_exchange_info, uintptr_t app_exchange_info_len)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult* ,AppExchangeInfo* ,uintptr_t)")
        def _auth_revoked_apps_o_cb(user_data ,result ,app_exchange_info ,app_exchange_info_len):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_revoked_apps_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,app_exchange_info ,app_exchange_info_len)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_revoked_apps_o_cb'].put(_auth_revoked_apps_o_cb)


        self.lib.safe_authenticator.auth_revoked_apps(auth, user_data, _auth_revoked_apps_o_cb)
    self._auth_revoked_apps = _auth_revoked_apps

def auth_registered_apps(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_registered_apps(auth, user_data, o_cb=None):
        """
            Authenticator*, [any], [function]
            Authenticator* auth, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, RegisteredApp* registered_app, uintptr_t registered_app_len)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult* ,RegisteredApp* ,uintptr_t)")
        def _auth_registered_apps_o_cb(user_data ,result ,registered_app ,registered_app_len):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_registered_apps_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            user_data = self if user_data == self.ffi_auth.NULL else self.ffi_auth.from_handle(user_data)
            if o_cb:
                o_cb(user_data ,result ,registered_app ,registered_app_len)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_registered_apps_o_cb'].put(_auth_registered_apps_o_cb)


        self.lib.safe_authenticator.auth_registered_apps(auth, user_data, _auth_registered_apps_o_cb)
    self._auth_registered_apps = _auth_registered_apps

def auth_apps_accessing_mutable_data(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _auth_apps_accessing_mutable_data(auth, md_name, md_type_tag, user_data, o_cb=None):
        """
            Authenticator*, XorNameArray*, uint64_t, [any], [function]
            Authenticator* auth, XorNameArray* md_name, uint64_t md_type_tag, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AppAccess* app_access, uintptr_t app_access_len)
        """
        @self.ffi_auth.callback("void(void* ,FfiResult* ,AppAccess* ,uintptr_t)")
        def _auth_apps_accessing_mutable_data_o_cb(user_data ,result ,app_access ,app_access_len):
            log.debug(f"got {LOCAL_QUEUES[f'{str(id(self))}_auth_apps_accessing_mutable_data_o_cb'].get_nowait()}")
            safeUtils.checkResult(result, self.ffi_auth, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result ,app_access ,app_access_len)

        # To ensure the reference is not GCd
        LOCAL_QUEUES[f'{str(id(self))}_auth_apps_accessing_mutable_data_o_cb'].put(_auth_apps_accessing_mutable_data_o_cb)


        self.lib.safe_authenticator.auth_apps_accessing_mutable_data(auth, md_name, md_type_tag, user_data, _auth_apps_accessing_mutable_data_o_cb)
    self._auth_apps_accessing_mutable_data = _auth_apps_accessing_mutable_data