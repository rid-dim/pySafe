### Experiments with ffi_binding separation
### safe_app lib

import safenet.safeUtils as safeUtils
_APP_DEFS=["access_container_refresh_access_info", "sign_pub_key_new", "encode_auth_req", "file_close",
            "encrypt", "decrypt_sealed_box", "encode_share_mdata_req", "sign_sec_key_new", "app_free",
            "access_container_fetch", "access_container_get_container_mdata_info",
            "app_set_additional_search_path", "dir_delete_file", "enc_pub_key_get",
            "app_reset_object_cache", "app_exe_file_stem", "sign_pub_key_get", "enc_pub_key_new",
            "app_pub_enc_key", "app_registered", "cipher_opt_new_plaintext", "sha3_hash", "test_create_app",
            "test_create_app_with_access", "encode_unregistered_req", "app_pub_sign_key",
            "sign_sec_key_free", "app_container_name", "dir_update_file", "enc_secret_key_free",
            "enc_generate_key_pair", "decrypt", "file_read", "app_account_info", "app_unregistered",
            "cipher_opt_new_symmetric", "enc_secret_key_new", "file_size", "dir_fetch_file",
            "encrypt_sealed_box", "app_output_log_path", "dir_insert_file", "app_reconnect",
            "sign_generate_key_pair", "verify", "app_init_logging", "generate_nonce", "decode_ipc_msg",
            "sign_sec_key_get", "sign", "enc_pub_key_free", "enc_secret_key_get",
            "test_simulate_network_disconnect", "encode_containers_req", "cipher_opt_new_asymmetric",
            "file_open", "file_write", "sign_pub_key_free", "cipher_opt_free"]

_IDATA_DEFS=["idata_new_self_encryptor", "idata_write_to_self_encryptor", "idata_close_self_encryptor",
            "idata_fetch_self_encryptor", "idata_serialised_size", "idata_size",
            "idata_read_from_self_encryptor", "idata_self_encryptor_writer_free",
            "idata_self_encryptor_reader_free"]


################################################################################################
# IDATA DEFS
################################################################################################
def idata_new_self_encryptor(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _idata_new_self_encryptor(app, user_data, o_cb=None):
        """
            App*, [any], [function], [custom ffi lib]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, SEWriterHandle se_h)
        """

        @self.ffi.callback("void(void* ,FfiResult* ,SEWriterHandle)")
        def _idata_new_self_encryptor_o_cb(user_data, result, se_h):
            safeUtils.checkResult(result, self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, se_h)

        self.lib.safe_app.idata_new_self_encryptor(app, user_data, _idata_new_self_encryptor_o_cb)


    self._idata_new_self_encryptor = _idata_new_self_encryptor

def idata_write_to_self_encryptor(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _idata_write_to_self_encryptor(app, se_h, data, data_len, user_data, o_cb=None):
        """
            App*, SEWriterHandle, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
            App* app, SEWriterHandle se_h, uint8_t* data, uintptr_t data_len, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi.callback("void(void* ,FfiResult*)")
        def _idata_write_to_self_encryptor_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.idata_write_to_self_encryptor(app, se_h, data, data_len, user_data, _idata_write_to_self_encryptor_o_cb)


    self._idata_write_to_self_encryptor = _idata_write_to_self_encryptor

def idata_close_self_encryptor(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _idata_close_self_encryptor(app, se_h, cipher_opt_h, user_data, o_cb=None):
        """
            App*, SEWriterHandle, CipherOptHandle, [any], [function], [custom ffi lib]
            App* app, SEWriterHandle se_h, CipherOptHandle cipher_opt_h, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, XorNameArray* name)
        """

        @self.ffi.callback("void(void* ,FfiResult* ,XorNameArray*)")
        def _idata_close_self_encryptor_o_cb(user_data, result, name):
            safeUtils.checkResult(result, self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, name)

        self.lib.safe_app.idata_close_self_encryptor(app, se_h, cipher_opt_h, user_data, _idata_close_self_encryptor_o_cb)


    self._idata_close_self_encryptor = _idata_close_self_encryptor

def idata_fetch_self_encryptor(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _idata_fetch_self_encryptor(app, name, user_data, o_cb=None):
        """
            App*, XorNameArray*, [any], [function], [custom ffi lib]
            App* app, XorNameArray* name, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, SEReaderHandle se_h)
        """

        @self.ffi.callback("void(void* ,FfiResult* ,SEReaderHandle)")
        def _idata_fetch_self_encryptor_o_cb(user_data, result, se_h):
            safeUtils.checkResult(result, self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, se_h)

        self.lib.safe_app.idata_fetch_self_encryptor(app, name, user_data, _idata_fetch_self_encryptor_o_cb)


    self._idata_fetch_self_encryptor = _idata_fetch_self_encryptor

def idata_serialised_size(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _idata_serialised_size(app, name, user_data, o_cb=None):
        """
            App*, XorNameArray*, [any], [function], [custom ffi lib]
            App* app, XorNameArray* name, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint64_t serialised_size)
        """

        @self.ffi.callback("void(void* ,FfiResult* ,uint64_t)")
        def _idata_serialised_size_o_cb(user_data, result, serialised_size):
            safeUtils.checkResult(result, self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, serialised_size)

        self.lib.safe_app.idata_serialised_size(app, name, user_data, _idata_serialised_size_o_cb)


    self._idata_serialised_size = _idata_serialised_size

def idata_size(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _idata_size(app, se_h, user_data, o_cb=None):
        """
            App*, SEReaderHandle, [any], [function], [custom ffi lib]
            App* app, SEReaderHandle se_h, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint64_t size)
        """

        @self.ffi.callback("void(void* ,FfiResult* ,uint64_t)")
        def _idata_size_o_cb(user_data, result, size):
            safeUtils.checkResult(result, self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, size)

        self.lib.safe_app.idata_size(app, se_h, user_data, _idata_size_o_cb)


    self._idata_size = _idata_size

def idata_read_from_self_encryptor(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _idata_read_from_self_encryptor(app, se_h, from_pos, len, user_data, o_cb=None):
        """
            App*, SEReaderHandle, uint64_t, uint64_t, [any], [function], [custom ffi lib]
            App* app, SEReaderHandle se_h, uint64_t from_pos, uint64_t len, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* data, uintptr_t data_len)
        """

        @self.ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _idata_read_from_self_encryptor_o_cb(user_data, result, data, data_len):
            safeUtils.checkResult(result, self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, data, data_len)

        self.lib.safe_app.idata_read_from_self_encryptor(app, se_h, from_pos, len, user_data,
                                                         _idata_read_from_self_encryptor_o_cb)


    self._idata_read_from_self_encryptor = _idata_read_from_self_encryptor

def idata_self_encryptor_writer_free(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _idata_self_encryptor_writer_free(app, handle, user_data, o_cb=None):
        """
            App*, SEWriterHandle, [any], [function], [custom ffi lib]
            App* app, SEWriterHandle handle, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi.callback("void(void* ,FfiResult*)")
        def _idata_self_encryptor_writer_free_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.idata_self_encryptor_writer_free(app, handle, user_data, _idata_self_encryptor_writer_free_o_cb)


    self._idata_self_encryptor_writer_free = _idata_self_encryptor_writer_free

def idata_self_encryptor_reader_free(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _idata_self_encryptor_reader_free(app, handle, user_data, o_cb=None):
        """
            App*, SEReaderHandle, [any], [function], [custom ffi lib]
            App* app, SEReaderHandle handle, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi.callback("void(void* ,FfiResult*)")
        def _idata_self_encryptor_reader_free_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.idata_self_encryptor_reader_free(app, handle, user_data, _idata_self_encryptor_reader_free_o_cb)


    self._idata_self_encryptor_reader_free = _idata_self_encryptor_reader_free


################################################################################################
# APP DEFS
################################################################################################
def test_create_app(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _test_create_app(app_id, user_data, o_cb=None):
        """
            bytes, [any], [function]
            char* app_id, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, App* app)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,App*)")
        def _test_create_app_o_cb(user_data, result, app):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, app)

        self.lib.safe_app.test_create_app(app_id, user_data, _test_create_app_o_cb)


    self._test_create_app = _test_create_app

def test_create_app_with_access(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _test_create_app_with_access(auth_req, user_data, o_cb=None):
        """
            AuthReq*, [any], [function]
            AuthReq* auth_req, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, App* o_app)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,App*)")
        def _test_create_app_with_access_o_cb(user_data, result, o_app):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, o_app)

        self.lib.safe_app.test_create_app_with_access(auth_req, user_data, _test_create_app_with_access_o_cb)


    self._test_create_app_with_access = _test_create_app_with_access

def test_simulate_network_disconnect(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _test_simulate_network_disconnect(app, user_data, o_cb=None):
        """
            App*, [any], [function]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _test_simulate_network_disconnect_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.test_simulate_network_disconnect(app, user_data, _test_simulate_network_disconnect_o_cb)


    self._test_simulate_network_disconnect = _test_simulate_network_disconnect

def app_init_logging(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_init_logging(output_file_name_override, user_data, o_cb=None):
        """
            bytes, [any], [function]
            char* output_file_name_override, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _app_init_logging_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.app_init_logging(output_file_name_override, user_data, _app_init_logging_o_cb)


    self._app_init_logging = _app_init_logging

def app_output_log_path(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_output_log_path(output_file_name, user_data, o_cb=None):
        """
            bytes, [any], [function]
            char* output_file_name, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* log_path)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,char*)")
        def _app_output_log_path_o_cb(user_data, result, log_path):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, log_path)

        self.lib.safe_app.app_output_log_path(output_file_name, user_data, _app_output_log_path_o_cb)


    self._app_output_log_path = _app_output_log_path

def app_unregistered(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_unregistered(bootstrap_config, bootstrap_config_len, user_data, o_disconnect_notifier_cb=None, o_cb=None):
        """
            uint8_t*, uintptr_t, [any], [function], [function]
            uint8_t* bootstrap_config, uintptr_t bootstrap_config_len, void* user_data

            > callback functions:
            (*o_disconnect_notifier_cb)(void* user_data)
            (*o_cb)(void* user_data, FfiResult* result, App* app)
        """

        @self.ffi_app.callback("void(void*)")
        def _app_unregistered_o_disconnect_notifier_cb(user_data):
            self.queue.put('gotResult')
            if o_disconnect_notifier_cb:
                o_disconnect_notifier_cb(user_data)

        @self.ffi_app.callback("void(void* ,FfiResult* ,App*)")
        def _app_unregistered_o_cb(user_data, result, app):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, app)

        self.lib.safe_app.app_unregistered(bootstrap_config, bootstrap_config_len, user_data,
                                    _app_unregistered_o_disconnect_notifier_cb, _app_unregistered_o_cb)


    self._app_unregistered = _app_unregistered

def app_registered(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_registered(app_id, auth_granted, user_data, o_disconnect_notifier_cb=None, o_cb=None):
        """
            bytes, AuthGranted*, [any], [function], [function]
            char* app_id, AuthGranted* auth_granted, void* user_data

            > callback functions:
            (*o_disconnect_notifier_cb)(void* user_data)
            (*o_cb)(void* user_data, FfiResult* result, App* app)
        """

        @self.ffi_app.callback("void(void*)")
        def _app_registered_o_disconnect_notifier_cb(user_data):
            self.queue.put('gotResult')
            if o_disconnect_notifier_cb:
                o_disconnect_notifier_cb(user_data)

        @self.ffi_app.callback("void(void* ,FfiResult* ,App*)")
        def _app_registered_o_cb(user_data, result, app):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put(app)
            if o_cb:
                o_cb(user_data, result, app)

        self.lib.safe_app.app_registered(app_id, auth_granted, user_data, _app_registered_o_disconnect_notifier_cb,
                                  _app_registered_o_cb)


    self._app_registered = _app_registered

def app_reconnect(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_reconnect(app, user_data, o_cb=None):
        """
            App*, [any], [function]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _app_reconnect_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.app_reconnect(app, user_data, _app_reconnect_o_cb)


    self._app_reconnect = _app_reconnect

def app_account_info(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_account_info(app, user_data, o_cb=None):
        """
            App*, [any], [function]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AccountInfo* account_info)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,AccountInfo*)")
        def _app_account_info_o_cb(user_data, result, account_info):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, account_info)

        self.lib.safe_app.app_account_info(app, user_data, _app_account_info_o_cb)


    self._app_account_info = _app_account_info

def app_exe_file_stem(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_exe_file_stem(user_data, o_cb=None):
        """
            [any], [function]
            void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* filename)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,char*)")
        def _app_exe_file_stem_o_cb(user_data, result, filename):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, filename)

        self.lib.safe_app.app_exe_file_stem(user_data, _app_exe_file_stem_o_cb)


    self._app_exe_file_stem = _app_exe_file_stem

def app_set_additional_search_path(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_set_additional_search_path(new_path, user_data, o_cb=None):
        """
            bytes, [any], [function]
            char* new_path, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _app_set_additional_search_path_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.app_set_additional_search_path(new_path, user_data, _app_set_additional_search_path_o_cb)


    self._app_set_additional_search_path = _app_set_additional_search_path

def app_free(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_free(app):
        """
            App*
            App* app

            > callback functions:
        """
        self.lib.safe_app.app_free(app)


    self._app_free = _app_free

def app_reset_object_cache(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_reset_object_cache(app, user_data, o_cb=None):
        """
            App*, [any], [function]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _app_reset_object_cache_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.app_reset_object_cache(app, user_data, _app_reset_object_cache_o_cb)


    self._app_reset_object_cache = _app_reset_object_cache

def app_container_name(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_container_name(app_id, user_data, o_cb=None):
        """
            bytes, [any], [function]
            char* app_id, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, char* container_name)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,char*)")
        def _app_container_name_o_cb(user_data, result, container_name):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, container_name)

        self.lib.safe_app.app_container_name(app_id, user_data, _app_container_name_o_cb)


    self._app_container_name = _app_container_name

def encode_auth_req(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _encode_auth_req(req, user_data, o_cb=None):
        """
            AuthReq*, [any], [function]
            AuthReq* req, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint32_t req_id, char* encoded)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint32_t ,char*)")
        def _encode_auth_req_o_cb(user_data, result, req_id, encoded):
            safeUtils.checkResult(result, self.ffi_app)
            request = self.ffi_app.string(encoded)
            self.queue.put(request)
            if o_cb:
                o_cb(user_data, result, req_id, encoded)

        self.lib.safe_app.encode_auth_req(req, user_data, _encode_auth_req_o_cb)


    self._encode_auth_req = _encode_auth_req

def encode_containers_req(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _encode_containers_req(req, user_data, o_cb=None):
        """
            ContainersReq*, [any], [function]
            ContainersReq* req, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint32_t req_id, char* encoded)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint32_t ,char*)")
        def _encode_containers_req_o_cb(user_data, result, req_id, encoded):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, req_id, encoded)

        self.lib.safe_app.encode_containers_req(req, user_data, _encode_containers_req_o_cb)


    self._encode_containers_req = _encode_containers_req

def encode_unregistered_req(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _encode_unregistered_req(extra_data, extra_data_len, user_data, o_cb=None):
        """
            uint8_t*, uintptr_t, [any], [function]
            uint8_t* extra_data, uintptr_t extra_data_len, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint32_t req_id, char* encoded)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint32_t ,char*)")
        def _encode_unregistered_req_o_cb(user_data, result, req_id, encoded):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, req_id, encoded)

        self.lib.safe_app.encode_unregistered_req(extra_data, extra_data_len, user_data, _encode_unregistered_req_o_cb)


    self._encode_unregistered_req = _encode_unregistered_req

def encode_share_mdata_req(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _encode_share_mdata_req(req, user_data, o_cb=None):
        """
            ShareMDataReq*, [any], [function]
            ShareMDataReq* req, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint32_t req_id, char* encoded)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint32_t ,char*)")
        def _encode_share_mdata_req_o_cb(user_data, result, req_id, encoded):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, req_id, encoded)

        self.lib.safe_app.encode_share_mdata_req(req, user_data, _encode_share_mdata_req_o_cb)


    self._encode_share_mdata_req = _encode_share_mdata_req

def decode_ipc_msg(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _decode_ipc_msg(msg, user_data, o_auth=None, o_unregistered=None, o_containers=None, o_share_mdata=None,
                        o_revoked=None, o_err=None):
        """
            bytes, [any], [function], [function], [function], [function], [function], [function]
            char* msg, void* user_data

            > callback functions:
            (*o_auth)(void* user_data, uint32_t req_id, AuthGranted* auth_granted)
            (*o_unregistered)(void* user_data, uint32_t req_id, uint8_t* serialised_cfg, uintptr_t serialised_cfg_len)
            (*o_containers)(void* user_data, uint32_t req_id)
            (*o_share_mdata)(void* user_data, uint32_t req_id)
            (*o_revoked)(void* user_data)
            (*o_err)(void* user_data, FfiResult* result, uint32_t req_id)
        """

        @self.ffi_app.callback("void(void* ,uint32_t ,AuthGranted*)")
        def _decode_ipc_msg_o_auth(user_data, req_id, auth_granted):
            self.queue.put(safeUtils.copy(auth_granted, self.ffi_app))
            if o_auth:
                o_auth(user_data, req_id, auth_granted)

        @self.ffi_app.callback("void(void* ,uint32_t ,uint8_t* ,uintptr_t)")
        def _decode_ipc_msg_o_unregistered(user_data, req_id, serialised_cfg, serialised_cfg_len):
            self.queue.put('gotResult')
            if o_unregistered:
                o_unregistered(user_data, req_id, serialised_cfg, serialised_cfg_len)

        @self.ffi_app.callback("void(void* ,uint32_t)")
        def _decode_ipc_msg_o_containers(user_data, req_id):
            self.queue.put('gotResult')
            if o_containers:
                o_containers(user_data, req_id)

        @self.ffi_app.callback("void(void* ,uint32_t)")
        def _decode_ipc_msg_o_share_mdata(user_data, req_id):
            self.queue.put('gotResult')
            if o_share_mdata:
                o_share_mdata(user_data, req_id)

        @self.ffi_app.callback("void(void*)")
        def _decode_ipc_msg_o_revoked(user_data):
            self.queue.put('gotResult')
            if o_revoked:
                o_revoked(user_data)

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint32_t)")
        def _decode_ipc_msg_o_err(user_data, result, req_id):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_err:
                o_err(user_data, result, req_id)

        self.lib.safe_app.decode_ipc_msg(msg, user_data, _decode_ipc_msg_o_auth, _decode_ipc_msg_o_unregistered,
                                  _decode_ipc_msg_o_containers, _decode_ipc_msg_o_share_mdata, _decode_ipc_msg_o_revoked,
                                  _decode_ipc_msg_o_err)


    self._decode_ipc_msg = _decode_ipc_msg

def access_container_refresh_access_info(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _access_container_refresh_access_info(app, user_data, o_cb=None):
        """
            App*, [any], [function]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _access_container_refresh_access_info_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.access_container_refresh_access_info(app, user_data, _access_container_refresh_access_info_o_cb)


    self._access_container_refresh_access_info = _access_container_refresh_access_info

def access_container_fetch(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _access_container_fetch(app, user_data, o_cb=None):
        """
            App*, [any], [function]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, ContainerPermissions* container_perms, uintptr_t container_perms_len)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,ContainerPermissions* ,uintptr_t)")
        def _access_container_fetch_o_cb(user_data, result, container_perms, container_perms_len):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, container_perms, container_perms_len)

        self.lib.safe_app.access_container_fetch(app, user_data, _access_container_fetch_o_cb)


    self._access_container_fetch = _access_container_fetch

def access_container_get_container_mdata_info(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _access_container_get_container_mdata_info(app, name, user_data, o_cb=None):
        """
            App*, bytes, [any], [function]
            App* app, char* name, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, MDataInfo* mdata_info)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,MDataInfo*)")
        def _access_container_get_container_mdata_info_o_cb(user_data, result, mdata_info):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, mdata_info)

        self.lib.safe_app.access_container_get_container_mdata_info(app, name, user_data,
                                                             _access_container_get_container_mdata_info_o_cb)


    self._access_container_get_container_mdata_info = _access_container_get_container_mdata_info

def dir_fetch_file(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _dir_fetch_file(app, parent_info, file_name, user_data, o_cb=None):
        """
            App*, MDataInfo*, bytes, [any], [function]
            App* app, MDataInfo* parent_info, char* file_name, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, File* file, uint64_t version)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,File* ,uint64_t)")
        def _dir_fetch_file_o_cb(user_data, result, file, version):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, file, version)

        self.lib.safe_app.dir_fetch_file(app, parent_info, file_name, user_data, _dir_fetch_file_o_cb)


    self._dir_fetch_file = _dir_fetch_file

def dir_insert_file(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _dir_insert_file(app, parent_info, file_name, file, user_data, o_cb=None):
        """
            App*, MDataInfo*, bytes, File*, [any], [function]
            App* app, MDataInfo* parent_info, char* file_name, File* file, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _dir_insert_file_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.dir_insert_file(app, parent_info, file_name, file, user_data, _dir_insert_file_o_cb)


    self._dir_insert_file = _dir_insert_file

def dir_update_file(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _dir_update_file(app, parent_info, file_name, file, version, user_data, o_cb=None):
        """
            App*, MDataInfo*, bytes, File*, uint64_t, [any], [function]
            App* app, MDataInfo* parent_info, char* file_name, File* file, uint64_t version, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint64_t new_version)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint64_t)")
        def _dir_update_file_o_cb(user_data, result, new_version):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, new_version)

        self.lib.safe_app.dir_update_file(app, parent_info, file_name, file, version, user_data, _dir_update_file_o_cb)


    self._dir_update_file = _dir_update_file

def dir_delete_file(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _dir_delete_file(app, parent_info, file_name, version, user_data, o_cb=None):
        """
            App*, MDataInfo*, bytes, uint64_t, [any], [function]
            App* app, MDataInfo* parent_info, char* file_name, uint64_t version, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint64_t new_version)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint64_t)")
        def _dir_delete_file_o_cb(user_data, result, new_version):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, new_version)

        self.lib.safe_app.dir_delete_file(app, parent_info, file_name, version, user_data, _dir_delete_file_o_cb)


    self._dir_delete_file = _dir_delete_file

def file_open(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _file_open(app, parent_info, file, open_mode, user_data, o_cb=None):
        """
            App*, MDataInfo*, File*, uint64_t, [any], [function]
            App* app, MDataInfo* parent_info, File* file, uint64_t open_mode, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, FileContextHandle file_h)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,FileContextHandle)")
        def _file_open_o_cb(user_data, result, file_h):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, file_h)

        self.lib.safe_app.file_open(app, parent_info, file, open_mode, user_data, _file_open_o_cb)


    self._file_open = _file_open

def file_size(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _file_size(app, file_h, user_data, o_cb=None):
        """
            App*, FileContextHandle, [any], [function]
            App* app, FileContextHandle file_h, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint64_t size)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint64_t)")
        def _file_size_o_cb(user_data, result, size):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, size)

        self.lib.safe_app.file_size(app, file_h, user_data, _file_size_o_cb)


    self._file_size = _file_size

def file_read(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _file_read(app, file_h, position, len, user_data, o_cb=None):
        """
            App*, FileContextHandle, uint64_t, uint64_t, [any], [function]
            App* app, FileContextHandle file_h, uint64_t position, uint64_t len, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* data, uintptr_t data_len)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _file_read_o_cb(user_data, result, data, data_len):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, data, data_len)

        self.lib.safe_app.file_read(app, file_h, position, len, user_data, _file_read_o_cb)


    self._file_read = _file_read

def file_write(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _file_write(app, file_h, data, data_len, user_data, o_cb=None):
        """
            App*, FileContextHandle, uint8_t*, uintptr_t, [any], [function]
            App* app, FileContextHandle file_h, uint8_t* data, uintptr_t data_len, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _file_write_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.file_write(app, file_h, data, data_len, user_data, _file_write_o_cb)


    self._file_write = _file_write

def file_close(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _file_close(app, file_h, user_data, o_cb=None):
        """
            App*, FileContextHandle, [any], [function]
            App* app, FileContextHandle file_h, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, File* file)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,File*)")
        def _file_close_o_cb(user_data, result, file):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, file)

        self.lib.safe_app.file_close(app, file_h, user_data, _file_close_o_cb)


    self._file_close = _file_close

def app_pub_sign_key(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_pub_sign_key(app, user_data, o_cb=None):
        """
            App*, [any], [function]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, SignPubKeyHandle handle)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,SignPubKeyHandle)")
        def _app_pub_sign_key_o_cb(user_data, result, handle):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, handle)

        self.lib.safe_app.app_pub_sign_key(app, user_data, _app_pub_sign_key_o_cb)


    self._app_pub_sign_key = _app_pub_sign_key

def sign_generate_key_pair(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _sign_generate_key_pair(app, user_data, o_cb=None):
        """
            App*, [any], [function]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, SignPubKeyHandle public_key_h, SignSecKeyHandle secret_key_h)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,SignPubKeyHandle ,SignSecKeyHandle)")
        def _sign_generate_key_pair_o_cb(user_data, result, public_key_h, secret_key_h):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, public_key_h, secret_key_h)

        self.lib.safe_app.sign_generate_key_pair(app, user_data, _sign_generate_key_pair_o_cb)


    self._sign_generate_key_pair = _sign_generate_key_pair

def sign_pub_key_new(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _sign_pub_key_new(app, data, user_data, o_cb=None):
        """
            App*, SignPublicKey*, [any], [function]
            App* app, SignPublicKey* data, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, SignPubKeyHandle handle)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,SignPubKeyHandle)")
        def _sign_pub_key_new_o_cb(user_data, result, handle):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, handle)

        self.lib.safe_app.sign_pub_key_new(app, data, user_data, _sign_pub_key_new_o_cb)


    self._sign_pub_key_new = _sign_pub_key_new

def sign_pub_key_get(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _sign_pub_key_get(app, handle, user_data, o_cb=None):
        """
            App*, SignPubKeyHandle, [any], [function]
            App* app, SignPubKeyHandle handle, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, SignPublicKey* pub_sign_key)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,SignPublicKey*)")
        def _sign_pub_key_get_o_cb(user_data, result, pub_sign_key):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, pub_sign_key)

        self.lib.safe_app.sign_pub_key_get(app, handle, user_data, _sign_pub_key_get_o_cb)


    self._sign_pub_key_get = _sign_pub_key_get

def sign_pub_key_free(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _sign_pub_key_free(app, handle, user_data, o_cb=None):
        """
            App*, SignPubKeyHandle, [any], [function]
            App* app, SignPubKeyHandle handle, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _sign_pub_key_free_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.sign_pub_key_free(app, handle, user_data, _sign_pub_key_free_o_cb)


    self._sign_pub_key_free = _sign_pub_key_free

def sign_sec_key_new(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _sign_sec_key_new(app, data, user_data, o_cb=None):
        """
            App*, SignSecretKey*, [any], [function]
            App* app, SignSecretKey* data, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, SignSecKeyHandle handle)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,SignSecKeyHandle)")
        def _sign_sec_key_new_o_cb(user_data, result, handle):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, handle)

        self.lib.safe_app.sign_sec_key_new(app, data, user_data, _sign_sec_key_new_o_cb)


    self._sign_sec_key_new = _sign_sec_key_new

def sign_sec_key_get(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _sign_sec_key_get(app, handle, user_data, o_cb=None):
        """
            App*, SignSecKeyHandle, [any], [function]
            App* app, SignSecKeyHandle handle, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, SignSecretKey* pub_sign_key)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,SignSecretKey*)")
        def _sign_sec_key_get_o_cb(user_data, result, pub_sign_key):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, pub_sign_key)

        self.lib.safe_app.sign_sec_key_get(app, handle, user_data, _sign_sec_key_get_o_cb)


    self._sign_sec_key_get = _sign_sec_key_get

def sign_sec_key_free(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _sign_sec_key_free(app, handle, user_data, o_cb=None):
        """
            App*, SignSecKeyHandle, [any], [function]
            App* app, SignSecKeyHandle handle, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _sign_sec_key_free_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.sign_sec_key_free(app, handle, user_data, _sign_sec_key_free_o_cb)


    self._sign_sec_key_free = _sign_sec_key_free

def app_pub_enc_key(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _app_pub_enc_key(app, user_data, o_cb=None):
        """
            App*, [any], [function]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, EncryptPubKeyHandle public_key_h)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,EncryptPubKeyHandle)")
        def _app_pub_enc_key_o_cb(user_data, result, public_key_h):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, public_key_h)

        self.lib.safe_app.app_pub_enc_key(app, user_data, _app_pub_enc_key_o_cb)


    self._app_pub_enc_key = _app_pub_enc_key

def enc_generate_key_pair(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _enc_generate_key_pair(app, user_data, o_cb=None):
        """
            App*, [any], [function]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, EncryptPubKeyHandle public_key_h, EncryptSecKeyHandle secret_key_h)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,EncryptPubKeyHandle ,EncryptSecKeyHandle)")
        def _enc_generate_key_pair_o_cb(user_data, result, public_key_h, secret_key_h):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, public_key_h, secret_key_h)

        self.lib.safe_app.enc_generate_key_pair(app, user_data, _enc_generate_key_pair_o_cb)


    self._enc_generate_key_pair = _enc_generate_key_pair

def enc_pub_key_new(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _enc_pub_key_new(app, data, user_data, o_cb=None):
        """
            App*, AsymPublicKey*, [any], [function]
            App* app, AsymPublicKey* data, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, EncryptPubKeyHandle public_key_h)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,EncryptPubKeyHandle)")
        def _enc_pub_key_new_o_cb(user_data, result, public_key_h):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, public_key_h)

        self.lib.safe_app.enc_pub_key_new(app, data, user_data, _enc_pub_key_new_o_cb)


    self._enc_pub_key_new = _enc_pub_key_new

def enc_pub_key_get(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _enc_pub_key_get(app, handle, user_data, o_cb=None):
        """
            App*, EncryptPubKeyHandle, [any], [function]
            App* app, EncryptPubKeyHandle handle, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AsymPublicKey* pub_enc_key)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,AsymPublicKey*)")
        def _enc_pub_key_get_o_cb(user_data, result, pub_enc_key):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, pub_enc_key)

        self.lib.safe_app.enc_pub_key_get(app, handle, user_data, _enc_pub_key_get_o_cb)


    self._enc_pub_key_get = _enc_pub_key_get

def enc_pub_key_free(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _enc_pub_key_free(app, handle, user_data, o_cb=None):
        """
            App*, EncryptPubKeyHandle, [any], [function]
            App* app, EncryptPubKeyHandle handle, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _enc_pub_key_free_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.enc_pub_key_free(app, handle, user_data, _enc_pub_key_free_o_cb)


    self._enc_pub_key_free = _enc_pub_key_free

def enc_secret_key_new(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _enc_secret_key_new(app, data, user_data, o_cb=None):
        """
            App*, AsymSecretKey*, [any], [function]
            App* app, AsymSecretKey* data, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, EncryptSecKeyHandle sk_h)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,EncryptSecKeyHandle)")
        def _enc_secret_key_new_o_cb(user_data, result, sk_h):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, sk_h)

        self.lib.safe_app.enc_secret_key_new(app, data, user_data, _enc_secret_key_new_o_cb)


    self._enc_secret_key_new = _enc_secret_key_new

def enc_secret_key_get(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _enc_secret_key_get(app, handle, user_data, o_cb=None):
        """
            App*, EncryptSecKeyHandle, [any], [function]
            App* app, EncryptSecKeyHandle handle, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AsymSecretKey* sec_enc_key)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,AsymSecretKey*)")
        def _enc_secret_key_get_o_cb(user_data, result, sec_enc_key):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, sec_enc_key)

        self.lib.safe_app.enc_secret_key_get(app, handle, user_data, _enc_secret_key_get_o_cb)


    self._enc_secret_key_get = _enc_secret_key_get

def enc_secret_key_free(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _enc_secret_key_free(app, handle, user_data, o_cb=None):
        """
            App*, EncryptSecKeyHandle, [any], [function]
            App* app, EncryptSecKeyHandle handle, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _enc_secret_key_free_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.enc_secret_key_free(app, handle, user_data, _enc_secret_key_free_o_cb)


    self._enc_secret_key_free = _enc_secret_key_free

def sign(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _sign(app, data, data_len, sign_sk_h, user_data, o_cb=None):
        """
            App*, uint8_t*, uintptr_t, SignSecKeyHandle, [any], [function]
            App* app, uint8_t* data, uintptr_t data_len, SignSecKeyHandle sign_sk_h, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* signed_data, uintptr_t signed_data_len)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _sign_o_cb(user_data, result, signed_data, signed_data_len):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, signed_data, signed_data_len)

        self.lib.safe_app.sign(app, data, data_len, sign_sk_h, user_data, _sign_o_cb)


    self._sign = _sign

def verify(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _verify(app, signed_data, signed_data_len, sign_pk_h, user_data, o_cb=None):
        """
            App*, uint8_t*, uintptr_t, SignPubKeyHandle, [any], [function]
            App* app, uint8_t* signed_data, uintptr_t signed_data_len, SignPubKeyHandle sign_pk_h, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* verified_data, uintptr_t verified_data_len)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _verify_o_cb(user_data, result, verified_data, verified_data_len):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, verified_data, verified_data_len)

        self.lib.safe_app.verify(app, signed_data, signed_data_len, sign_pk_h, user_data, _verify_o_cb)


    self._verify = _verify

def encrypt(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _encrypt(app, data, data_len, public_key_h, secret_key_h, user_data, o_cb=None):
        """
            App*, uint8_t*, uintptr_t, EncryptPubKeyHandle, EncryptSecKeyHandle, [any], [function]
            App* app, uint8_t* data, uintptr_t data_len, EncryptPubKeyHandle public_key_h, EncryptSecKeyHandle secret_key_h, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* ciphertext, uintptr_t ciphertext_len)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _encrypt_o_cb(user_data, result, ciphertext, ciphertext_len):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, ciphertext, ciphertext_len)

        self.lib.safe_app.encrypt(app, data, data_len, public_key_h, secret_key_h, user_data, _encrypt_o_cb)


    self._encrypt = _encrypt

def decrypt(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _decrypt(app, data, data_len, public_key_h, secret_key_h, user_data, o_cb=None):
        """
            App*, uint8_t*, uintptr_t, EncryptPubKeyHandle, EncryptSecKeyHandle, [any], [function]
            App* app, uint8_t* data, uintptr_t data_len, EncryptPubKeyHandle public_key_h, EncryptSecKeyHandle secret_key_h, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* plaintext, uintptr_t plaintext_len)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _decrypt_o_cb(user_data, result, plaintext, plaintext_len):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, plaintext, plaintext_len)

        self.lib.safe_app.decrypt(app, data, data_len, public_key_h, secret_key_h, user_data, _decrypt_o_cb)


    self._decrypt = _decrypt

def encrypt_sealed_box(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _encrypt_sealed_box(app, data, data_len, public_key_h, user_data, o_cb=None):
        """
            App*, uint8_t*, uintptr_t, EncryptPubKeyHandle, [any], [function]
            App* app, uint8_t* data, uintptr_t data_len, EncryptPubKeyHandle public_key_h, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* ciphertext, uintptr_t ciphertext_len)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _encrypt_sealed_box_o_cb(user_data, result, ciphertext, ciphertext_len):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, ciphertext, ciphertext_len)

        self.lib.safe_app.encrypt_sealed_box(app, data, data_len, public_key_h, user_data, _encrypt_sealed_box_o_cb)


    self._encrypt_sealed_box = _encrypt_sealed_box

def decrypt_sealed_box(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _decrypt_sealed_box(app, data, data_len, public_key_h, secret_key_h, user_data, o_cb=None):
        """
            App*, uint8_t*, uintptr_t, EncryptPubKeyHandle, EncryptSecKeyHandle, [any], [function]
            App* app, uint8_t* data, uintptr_t data_len, EncryptPubKeyHandle public_key_h, EncryptSecKeyHandle secret_key_h, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* plaintext, uintptr_t plaintext_len)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _decrypt_sealed_box_o_cb(user_data, result, plaintext, plaintext_len):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, plaintext, plaintext_len)

        self.lib.safe_app.decrypt_sealed_box(app, data, data_len, public_key_h, secret_key_h, user_data, _decrypt_sealed_box_o_cb)


    self._decrypt_sealed_box = _decrypt_sealed_box

def sha3_hash(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _sha3_hash(data, data_len, user_data, o_cb=None):
        """
            uint8_t*, uintptr_t, [any], [function]
            uint8_t* data, uintptr_t data_len, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, uint8_t* hash, uintptr_t hash_len)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
        def _sha3_hash_o_cb(user_data, result, hash, hash_len):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, hash, hash_len)

        self.lib.safe_app.sha3_hash(data, data_len, user_data, _sha3_hash_o_cb)


    self._sha3_hash = _sha3_hash

def generate_nonce(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _generate_nonce(user_data, o_cb=None):
        """
            [any], [function]
            void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, AsymNonce* nonce)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,AsymNonce*)")
        def _generate_nonce_o_cb(user_data, result, nonce):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, nonce)

        self.lib.safe_app.generate_nonce(user_data, _generate_nonce_o_cb)


    self._generate_nonce = _generate_nonce

def cipher_opt_new_plaintext(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _cipher_opt_new_plaintext(app, user_data, o_cb=None):
        """
            App*, [any], [function]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, CipherOptHandle handle)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,CipherOptHandle)")
        def _cipher_opt_new_plaintext_o_cb(user_data, result, handle):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, handle)

        self.lib.safe_app.cipher_opt_new_plaintext(app, user_data, _cipher_opt_new_plaintext_o_cb)


    self._cipher_opt_new_plaintext = _cipher_opt_new_plaintext

def cipher_opt_new_symmetric(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _cipher_opt_new_symmetric(app, user_data, o_cb=None):
        """
            App*, [any], [function]
            App* app, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, CipherOptHandle handle)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,CipherOptHandle)")
        def _cipher_opt_new_symmetric_o_cb(user_data, result, handle):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, handle)

        self.lib.safe_app.cipher_opt_new_symmetric(app, user_data, _cipher_opt_new_symmetric_o_cb)


    self._cipher_opt_new_symmetric = _cipher_opt_new_symmetric

def cipher_opt_new_asymmetric(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _cipher_opt_new_asymmetric(app, peer_encrypt_key_h, user_data, o_cb=None):
        """
            App*, EncryptPubKeyHandle, [any], [function]
            App* app, EncryptPubKeyHandle peer_encrypt_key_h, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result, CipherOptHandle handle)
        """

        @self.ffi_app.callback("void(void* ,FfiResult* ,CipherOptHandle)")
        def _cipher_opt_new_asymmetric_o_cb(user_data, result, handle):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result, handle)

        self.lib.safe_app.cipher_opt_new_asymmetric(app, peer_encrypt_key_h, user_data, _cipher_opt_new_asymmetric_o_cb)


    self._cipher_opt_new_asymmetric = _cipher_opt_new_asymmetric

def cipher_opt_free(self, timeout):
    @safeUtils.safeThread(timeout=timeout, queue=self.queue)
    def _cipher_opt_free(app, handle, user_data, o_cb=None):
        """
            App*, CipherOptHandle, [any], [function]
            App* app, CipherOptHandle handle, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """

        @self.ffi_app.callback("void(void* ,FfiResult*)")
        def _cipher_opt_free_o_cb(user_data, result):
            safeUtils.checkResult(result, self.ffi_app)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data, result)

        self.lib.safe_app.cipher_opt_free(app, handle, user_data, _cipher_opt_free_o_cb)


    self._cipher_opt_free = _cipher_opt_free
