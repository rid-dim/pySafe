########################################################################################################################
#
# pySafe - Authenticator Interface
#
# This is really just a stub  ... files like this should be able to import the interface and just go, but code structure
# really needs some thought
#
#
#
########################################################################################################################

# This brings all the c interfaces into this module ..  at this point still clean code
import safenet.interface as interface
import safenet.safeUtils as safeUtils
import queue

import safenet.mutableData as mutableData
import safenet.immutableData as immutableData
import safenet.authenticator as authenticator

#NULL=interface.NULL

# From here on in is just a very basic 'working' example
# todo we need heavy thought on how to structure the various classes.
class app:
    def __init__(self,
                 name='SAFE_Connection',
                 version='0.0.0',
                 vendor='rid+dask',
                 addr='http://localhost',
                 alternate_crust_config=None):
        self.name = name
        self.version = version
        self.vendor = vendor
        self.url = addr
        self.ffi_app = interface.ffi_app
        self.ffi_auth = interface.ffi_auth
        self.lib = safeUtils.lib(interface.lib_auth, interface.lib_app)
        self.authenticator = authenticator.authenticator(self.lib.safe_authenticator, self.lib.safe_app, self.ffi_auth)
        self.mutableData = mutableData.mutableData(self.lib.safe_authenticator, self.lib.safe_app, self.ffi_app)
        self.immutableData = immutableData.immutableData(self.lib.safe_authenticator, self.lib.safe_app, self.ffi_app)

        
        self.queue = queue.Queue()        
        #Try and add this here...
        #if alternate_crust_config is None:
        #    interface.add_local_crust_config()
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _test_create_app(app_id, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                bytes, [any], [function], [custom ffi lib]
                char* app_id, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, App* app)
            """
            @ffi.callback("void(void* ,FfiResult* ,App*)")
            def _test_create_app_o_cb(user_data ,result ,app):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,app)
        
        
            safenetLib.test_create_app(app_id, user_data, _test_create_app_o_cb)
        self._test_create_app = _test_create_app
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _test_create_app_with_access(auth_req, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                AuthReq*, [any], [function], [custom ffi lib]
                AuthReq* auth_req, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, App* o_app)
            """
            @ffi.callback("void(void* ,FfiResult* ,App*)")
            def _test_create_app_with_access_o_cb(user_data ,result ,o_app):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,o_app)
        
        
            safenetLib.test_create_app_with_access(auth_req, user_data, _test_create_app_with_access_o_cb)
        self._test_create_app_with_access = _test_create_app_with_access
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _test_simulate_network_disconnect(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _test_simulate_network_disconnect_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.test_simulate_network_disconnect(app, user_data, _test_simulate_network_disconnect_o_cb)
        self._test_simulate_network_disconnect = _test_simulate_network_disconnect
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_init_logging(output_file_name_override, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                bytes, [any], [function], [custom ffi lib]
                char* output_file_name_override, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _app_init_logging_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.app_init_logging(output_file_name_override, user_data, _app_init_logging_o_cb)
        self._app_init_logging = _app_init_logging
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_output_log_path(output_file_name, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                bytes, [any], [function], [custom ffi lib]
                char* output_file_name, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, char* log_path)
            """
            @ffi.callback("void(void* ,FfiResult* ,char*)")
            def _app_output_log_path_o_cb(user_data ,result ,log_path):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,log_path)
        
        
            safenetLib.app_output_log_path(output_file_name, user_data, _app_output_log_path_o_cb)
        self._app_output_log_path = _app_output_log_path
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_unregistered(bootstrap_config, bootstrap_config_len, user_data, o_disconnect_notifier_cb=None, o_cb=None, safenetLib=self.lib.safe_app):
            """
                uint8_t*, uintptr_t, [any], [function], [function], [custom ffi lib]
                uint8_t* bootstrap_config, uintptr_t bootstrap_config_len, void* user_data
        
                > callback functions:
                (*o_disconnect_notifier_cb)(void* user_data)
                (*o_cb)(void* user_data, FfiResult* result, App* app)
            """
            @ffi.callback("void(void*)")
            def _app_unregistered_o_disconnect_notifier_cb(user_data):
                self.queue.put('gotResult')
                if o_disconnect_notifier_cb:
                    o_disconnect_notifier_cb(user_data)
        
        
            @ffi.callback("void(void* ,FfiResult* ,App*)")
            def _app_unregistered_o_cb(user_data ,result ,app):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,app)
        
        
            safenetLib.app_unregistered(bootstrap_config, bootstrap_config_len, user_data, _app_unregistered_o_disconnect_notifier_cb, _app_unregistered_o_cb)
        self._app_unregistered = _app_unregistered
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_registered(app_id, auth_granted, user_data, o_disconnect_notifier_cb=None, o_cb=None, safenetLib=self.lib.safe_app):
            """
                bytes, AuthGranted*, [any], [function], [function], [custom ffi lib]
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
            def _app_registered_o_cb(user_data ,result ,app):
                safeUtils.checkResult(result,self.ffi_app)
                self.queue.put(app)
                if o_cb:
                    o_cb(user_data ,result ,app)
        
        
            safenetLib.app_registered(app_id, auth_granted, user_data, _app_registered_o_disconnect_notifier_cb, _app_registered_o_cb)
        self._app_registered = _app_registered
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_reconnect(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _app_reconnect_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.app_reconnect(app, user_data, _app_reconnect_o_cb)
        self._app_reconnect = _app_reconnect
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_account_info(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, AccountInfo* account_info)
            """
            @ffi.callback("void(void* ,FfiResult* ,AccountInfo*)")
            def _app_account_info_o_cb(user_data ,result ,account_info):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,account_info)
        
        
            safenetLib.app_account_info(app, user_data, _app_account_info_o_cb)
        self._app_account_info = _app_account_info
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_exe_file_stem(user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                [any], [function], [custom ffi lib]
                void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, char* filename)
            """
            @ffi.callback("void(void* ,FfiResult* ,char*)")
            def _app_exe_file_stem_o_cb(user_data ,result ,filename):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,filename)
        
        
            safenetLib.app_exe_file_stem(user_data, _app_exe_file_stem_o_cb)
        self._app_exe_file_stem = _app_exe_file_stem
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_set_additional_search_path(new_path, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                bytes, [any], [function], [custom ffi lib]
                char* new_path, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _app_set_additional_search_path_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.app_set_additional_search_path(new_path, user_data, _app_set_additional_search_path_o_cb)
        self._app_set_additional_search_path = _app_set_additional_search_path
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_free(app, safenetLib=self.lib.safe_app):
            """
                App*, [custom ffi lib]
                App* app
        
                > callback functions:
            """
            safenetLib.app_free(app)
        self._app_free = _app_free
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_reset_object_cache(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _app_reset_object_cache_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.app_reset_object_cache(app, user_data, _app_reset_object_cache_o_cb)
        self._app_reset_object_cache = _app_reset_object_cache
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_container_name(app_id, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                bytes, [any], [function], [custom ffi lib]
                char* app_id, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, char* container_name)
            """
            @ffi.callback("void(void* ,FfiResult* ,char*)")
            def _app_container_name_o_cb(user_data ,result ,container_name):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,container_name)
        
        
            safenetLib.app_container_name(app_id, user_data, _app_container_name_o_cb)
        self._app_container_name = _app_container_name
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _encode_auth_req(req, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                AuthReq*, [any], [function], [custom ffi lib]
                AuthReq* req, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint32_t req_id, char* encoded)
            """
            @self.ffi_app.callback("void(void* ,FfiResult* ,uint32_t ,char*)")
            def _encode_auth_req_o_cb(user_data ,result ,req_id ,encoded):
                safeUtils.checkResult(result,self.ffi_app)
                request = self.ffi_app.string(encoded)
                self.queue.put(request)
                if o_cb:
                    o_cb(user_data ,result ,req_id ,encoded)
        
        
            safenetLib.encode_auth_req(req, user_data, _encode_auth_req_o_cb)
        self._encode_auth_req = _encode_auth_req
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _encode_containers_req(req, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                ContainersReq*, [any], [function], [custom ffi lib]
                ContainersReq* req, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint32_t req_id, char* encoded)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint32_t ,char*)")
            def _encode_containers_req_o_cb(user_data ,result ,req_id ,encoded):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,req_id ,encoded)
        
        
            safenetLib.encode_containers_req(req, user_data, _encode_containers_req_o_cb)
        self._encode_containers_req = _encode_containers_req
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _encode_unregistered_req(extra_data, extra_data_len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
                uint8_t* extra_data, uintptr_t extra_data_len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint32_t req_id, char* encoded)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint32_t ,char*)")
            def _encode_unregistered_req_o_cb(user_data ,result ,req_id ,encoded):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,req_id ,encoded)
        
        
            safenetLib.encode_unregistered_req(extra_data, extra_data_len, user_data, _encode_unregistered_req_o_cb)
        self._encode_unregistered_req = _encode_unregistered_req
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _encode_share_mdata_req(req, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                ShareMDataReq*, [any], [function], [custom ffi lib]
                ShareMDataReq* req, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint32_t req_id, char* encoded)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint32_t ,char*)")
            def _encode_share_mdata_req_o_cb(user_data ,result ,req_id ,encoded):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,req_id ,encoded)
        
        
            safenetLib.encode_share_mdata_req(req, user_data, _encode_share_mdata_req_o_cb)
        self._encode_share_mdata_req = _encode_share_mdata_req
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _decode_ipc_msg(msg, user_data, o_auth=None, o_unregistered=None, o_containers=None, o_share_mdata=None, o_revoked=None, o_err=None, safenetLib=self.lib.safe_app):
            """
                bytes, [any], [function], [function], [function], [function], [function], [function], [custom ffi lib]
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
            def _decode_ipc_msg_o_auth(user_data ,req_id ,auth_granted):
                self.queue.put(safeUtils.copy(auth_granted,self.ffi_app))
                if o_auth:
                    o_auth(user_data ,req_id ,auth_granted)
        
        
            @self.ffi_app.callback("void(void* ,uint32_t ,uint8_t* ,uintptr_t)")
            def _decode_ipc_msg_o_unregistered(user_data ,req_id ,serialised_cfg ,serialised_cfg_len):
                self.queue.put('gotResult')
                if o_unregistered:
                    o_unregistered(user_data ,req_id ,serialised_cfg ,serialised_cfg_len)
        
        
            @self.ffi_app.callback("void(void* ,uint32_t)")
            def _decode_ipc_msg_o_containers(user_data ,req_id):
                self.queue.put('gotResult')
                if o_containers:
                    o_containers(user_data ,req_id)
        
        
            @self.ffi_app.callback("void(void* ,uint32_t)")
            def _decode_ipc_msg_o_share_mdata(user_data ,req_id):
                self.queue.put('gotResult')
                if o_share_mdata:
                    o_share_mdata(user_data ,req_id)
        
        
            @self.ffi_app.callback("void(void*)")
            def _decode_ipc_msg_o_revoked(user_data):
                self.queue.put('gotResult')
                if o_revoked:
                    o_revoked(user_data)
        
        
            @self.ffi_app.callback("void(void* ,FfiResult* ,uint32_t)")
            def _decode_ipc_msg_o_err(user_data ,result ,req_id):
                safeUtils.checkResult(result,self.ffi_app)
                self.queue.put('gotResult')
                if o_err:
                    o_err(user_data ,result ,req_id)
        
        
            safenetLib.decode_ipc_msg(msg, user_data, _decode_ipc_msg_o_auth, _decode_ipc_msg_o_unregistered, _decode_ipc_msg_o_containers, _decode_ipc_msg_o_share_mdata, _decode_ipc_msg_o_revoked, _decode_ipc_msg_o_err)
        self._decode_ipc_msg = _decode_ipc_msg
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _access_container_refresh_access_info(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _access_container_refresh_access_info_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.access_container_refresh_access_info(app, user_data, _access_container_refresh_access_info_o_cb)
        self._access_container_refresh_access_info = _access_container_refresh_access_info
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _access_container_fetch(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, ContainerPermissions* container_perms, uintptr_t container_perms_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,ContainerPermissions* ,uintptr_t)")
            def _access_container_fetch_o_cb(user_data ,result ,container_perms ,container_perms_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,container_perms ,container_perms_len)
        
        
            safenetLib.access_container_fetch(app, user_data, _access_container_fetch_o_cb)
        self._access_container_fetch = _access_container_fetch
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _access_container_get_container_mdata_info(app, name, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, bytes, [any], [function], [custom ffi lib]
                App* app, char* name, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, MDataInfo* mdata_info)
            """
            @ffi.callback("void(void* ,FfiResult* ,MDataInfo*)")
            def _access_container_get_container_mdata_info_o_cb(user_data ,result ,mdata_info):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,mdata_info)
        
        
            safenetLib.access_container_get_container_mdata_info(app, name, user_data, _access_container_get_container_mdata_info_o_cb)
        self._access_container_get_container_mdata_info = _access_container_get_container_mdata_info
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _dir_fetch_file(app, parent_info, file_name, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, bytes, [any], [function], [custom ffi lib]
                App* app, MDataInfo* parent_info, char* file_name, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, File* file, uint64_t version)
            """
            @ffi.callback("void(void* ,FfiResult* ,File* ,uint64_t)")
            def _dir_fetch_file_o_cb(user_data ,result ,file ,version):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,file ,version)
        
        
            safenetLib.dir_fetch_file(app, parent_info, file_name, user_data, _dir_fetch_file_o_cb)
        self._dir_fetch_file = _dir_fetch_file
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _dir_insert_file(app, parent_info, file_name, file, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, bytes, File*, [any], [function], [custom ffi lib]
                App* app, MDataInfo* parent_info, char* file_name, File* file, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _dir_insert_file_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.dir_insert_file(app, parent_info, file_name, file, user_data, _dir_insert_file_o_cb)
        self._dir_insert_file = _dir_insert_file
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _dir_update_file(app, parent_info, file_name, file, version, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, bytes, File*, uint64_t, [any], [function], [custom ffi lib]
                App* app, MDataInfo* parent_info, char* file_name, File* file, uint64_t version, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint64_t new_version)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint64_t)")
            def _dir_update_file_o_cb(user_data ,result ,new_version):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,new_version)
        
        
            safenetLib.dir_update_file(app, parent_info, file_name, file, version, user_data, _dir_update_file_o_cb)
        self._dir_update_file = _dir_update_file
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _dir_delete_file(app, parent_info, file_name, version, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, bytes, uint64_t, [any], [function], [custom ffi lib]
                App* app, MDataInfo* parent_info, char* file_name, uint64_t version, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint64_t new_version)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint64_t)")
            def _dir_delete_file_o_cb(user_data ,result ,new_version):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,new_version)
        
        
            safenetLib.dir_delete_file(app, parent_info, file_name, version, user_data, _dir_delete_file_o_cb)
        self._dir_delete_file = _dir_delete_file
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _file_open(app, parent_info, file, open_mode, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, MDataInfo*, File*, uint64_t, [any], [function], [custom ffi lib]
                App* app, MDataInfo* parent_info, File* file, uint64_t open_mode, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, FileContextHandle file_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,FileContextHandle)")
            def _file_open_o_cb(user_data ,result ,file_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,file_h)
        
        
            safenetLib.file_open(app, parent_info, file, open_mode, user_data, _file_open_o_cb)
        self._file_open = _file_open
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _file_size(app, file_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, FileContextHandle, [any], [function], [custom ffi lib]
                App* app, FileContextHandle file_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint64_t size)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint64_t)")
            def _file_size_o_cb(user_data ,result ,size):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,size)
        
        
            safenetLib.file_size(app, file_h, user_data, _file_size_o_cb)
        self._file_size = _file_size
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _file_read(app, file_h, position, len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, FileContextHandle, uint64_t, uint64_t, [any], [function], [custom ffi lib]
                App* app, FileContextHandle file_h, uint64_t position, uint64_t len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* data, uintptr_t data_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _file_read_o_cb(user_data ,result ,data ,data_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,data ,data_len)
        
        
            safenetLib.file_read(app, file_h, position, len, user_data, _file_read_o_cb)
        self._file_read = _file_read
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _file_write(app, file_h, data, data_len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, FileContextHandle, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
                App* app, FileContextHandle file_h, uint8_t* data, uintptr_t data_len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _file_write_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.file_write(app, file_h, data, data_len, user_data, _file_write_o_cb)
        self._file_write = _file_write
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _file_close(app, file_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, FileContextHandle, [any], [function], [custom ffi lib]
                App* app, FileContextHandle file_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, File* file)
            """
            @ffi.callback("void(void* ,FfiResult* ,File*)")
            def _file_close_o_cb(user_data ,result ,file):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,file)
        
        
            safenetLib.file_close(app, file_h, user_data, _file_close_o_cb)
        self._file_close = _file_close
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_pub_sign_key(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, SignPubKeyHandle handle)
            """
            @ffi.callback("void(void* ,FfiResult* ,SignPubKeyHandle)")
            def _app_pub_sign_key_o_cb(user_data ,result ,handle):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,handle)
        
        
            safenetLib.app_pub_sign_key(app, user_data, _app_pub_sign_key_o_cb)
        self._app_pub_sign_key = _app_pub_sign_key
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _sign_generate_key_pair(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, SignPubKeyHandle public_key_h, SignSecKeyHandle secret_key_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,SignPubKeyHandle ,SignSecKeyHandle)")
            def _sign_generate_key_pair_o_cb(user_data ,result ,public_key_h ,secret_key_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,public_key_h ,secret_key_h)
        
        
            safenetLib.sign_generate_key_pair(app, user_data, _sign_generate_key_pair_o_cb)
        self._sign_generate_key_pair = _sign_generate_key_pair
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _sign_pub_key_new(app, data, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, SignPublicKey*, [any], [function], [custom ffi lib]
                App* app, SignPublicKey* data, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, SignPubKeyHandle handle)
            """
            @ffi.callback("void(void* ,FfiResult* ,SignPubKeyHandle)")
            def _sign_pub_key_new_o_cb(user_data ,result ,handle):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,handle)
        
        
            safenetLib.sign_pub_key_new(app, data, user_data, _sign_pub_key_new_o_cb)
        self._sign_pub_key_new = _sign_pub_key_new
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _sign_pub_key_get(app, handle, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, SignPubKeyHandle, [any], [function], [custom ffi lib]
                App* app, SignPubKeyHandle handle, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, SignPublicKey* pub_sign_key)
            """
            @ffi.callback("void(void* ,FfiResult* ,SignPublicKey*)")
            def _sign_pub_key_get_o_cb(user_data ,result ,pub_sign_key):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,pub_sign_key)
        
        
            safenetLib.sign_pub_key_get(app, handle, user_data, _sign_pub_key_get_o_cb)
        self._sign_pub_key_get = _sign_pub_key_get
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _sign_pub_key_free(app, handle, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, SignPubKeyHandle, [any], [function], [custom ffi lib]
                App* app, SignPubKeyHandle handle, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _sign_pub_key_free_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.sign_pub_key_free(app, handle, user_data, _sign_pub_key_free_o_cb)
        self._sign_pub_key_free = _sign_pub_key_free
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _sign_sec_key_new(app, data, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, SignSecretKey*, [any], [function], [custom ffi lib]
                App* app, SignSecretKey* data, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, SignSecKeyHandle handle)
            """
            @ffi.callback("void(void* ,FfiResult* ,SignSecKeyHandle)")
            def _sign_sec_key_new_o_cb(user_data ,result ,handle):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,handle)
        
        
            safenetLib.sign_sec_key_new(app, data, user_data, _sign_sec_key_new_o_cb)
        self._sign_sec_key_new = _sign_sec_key_new
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _sign_sec_key_get(app, handle, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, SignSecKeyHandle, [any], [function], [custom ffi lib]
                App* app, SignSecKeyHandle handle, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, SignSecretKey* pub_sign_key)
            """
            @ffi.callback("void(void* ,FfiResult* ,SignSecretKey*)")
            def _sign_sec_key_get_o_cb(user_data ,result ,pub_sign_key):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,pub_sign_key)
        
        
            safenetLib.sign_sec_key_get(app, handle, user_data, _sign_sec_key_get_o_cb)
        self._sign_sec_key_get = _sign_sec_key_get
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _sign_sec_key_free(app, handle, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, SignSecKeyHandle, [any], [function], [custom ffi lib]
                App* app, SignSecKeyHandle handle, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _sign_sec_key_free_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.sign_sec_key_free(app, handle, user_data, _sign_sec_key_free_o_cb)
        self._sign_sec_key_free = _sign_sec_key_free
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _app_pub_enc_key(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, EncryptPubKeyHandle public_key_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,EncryptPubKeyHandle)")
            def _app_pub_enc_key_o_cb(user_data ,result ,public_key_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,public_key_h)
        
        
            safenetLib.app_pub_enc_key(app, user_data, _app_pub_enc_key_o_cb)
        self._app_pub_enc_key = _app_pub_enc_key
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _enc_generate_key_pair(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, EncryptPubKeyHandle public_key_h, EncryptSecKeyHandle secret_key_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,EncryptPubKeyHandle ,EncryptSecKeyHandle)")
            def _enc_generate_key_pair_o_cb(user_data ,result ,public_key_h ,secret_key_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,public_key_h ,secret_key_h)
        
        
            safenetLib.enc_generate_key_pair(app, user_data, _enc_generate_key_pair_o_cb)
        self._enc_generate_key_pair = _enc_generate_key_pair
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _enc_pub_key_new(app, data, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, AsymPublicKey*, [any], [function], [custom ffi lib]
                App* app, AsymPublicKey* data, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, EncryptPubKeyHandle public_key_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,EncryptPubKeyHandle)")
            def _enc_pub_key_new_o_cb(user_data ,result ,public_key_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,public_key_h)
        
        
            safenetLib.enc_pub_key_new(app, data, user_data, _enc_pub_key_new_o_cb)
        self._enc_pub_key_new = _enc_pub_key_new
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _enc_pub_key_get(app, handle, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, EncryptPubKeyHandle, [any], [function], [custom ffi lib]
                App* app, EncryptPubKeyHandle handle, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, AsymPublicKey* pub_enc_key)
            """
            @ffi.callback("void(void* ,FfiResult* ,AsymPublicKey*)")
            def _enc_pub_key_get_o_cb(user_data ,result ,pub_enc_key):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,pub_enc_key)
        
        
            safenetLib.enc_pub_key_get(app, handle, user_data, _enc_pub_key_get_o_cb)
        self._enc_pub_key_get = _enc_pub_key_get
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _enc_pub_key_free(app, handle, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, EncryptPubKeyHandle, [any], [function], [custom ffi lib]
                App* app, EncryptPubKeyHandle handle, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _enc_pub_key_free_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.enc_pub_key_free(app, handle, user_data, _enc_pub_key_free_o_cb)
        self._enc_pub_key_free = _enc_pub_key_free
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _enc_secret_key_new(app, data, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, AsymSecretKey*, [any], [function], [custom ffi lib]
                App* app, AsymSecretKey* data, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, EncryptSecKeyHandle sk_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,EncryptSecKeyHandle)")
            def _enc_secret_key_new_o_cb(user_data ,result ,sk_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,sk_h)
        
        
            safenetLib.enc_secret_key_new(app, data, user_data, _enc_secret_key_new_o_cb)
        self._enc_secret_key_new = _enc_secret_key_new
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _enc_secret_key_get(app, handle, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, EncryptSecKeyHandle, [any], [function], [custom ffi lib]
                App* app, EncryptSecKeyHandle handle, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, AsymSecretKey* sec_enc_key)
            """
            @ffi.callback("void(void* ,FfiResult* ,AsymSecretKey*)")
            def _enc_secret_key_get_o_cb(user_data ,result ,sec_enc_key):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,sec_enc_key)
        
        
            safenetLib.enc_secret_key_get(app, handle, user_data, _enc_secret_key_get_o_cb)
        self._enc_secret_key_get = _enc_secret_key_get
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _enc_secret_key_free(app, handle, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, EncryptSecKeyHandle, [any], [function], [custom ffi lib]
                App* app, EncryptSecKeyHandle handle, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _enc_secret_key_free_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.enc_secret_key_free(app, handle, user_data, _enc_secret_key_free_o_cb)
        self._enc_secret_key_free = _enc_secret_key_free
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _sign(app, data, data_len, sign_sk_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, uint8_t*, uintptr_t, SignSecKeyHandle, [any], [function], [custom ffi lib]
                App* app, uint8_t* data, uintptr_t data_len, SignSecKeyHandle sign_sk_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* signed_data, uintptr_t signed_data_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _sign_o_cb(user_data ,result ,signed_data ,signed_data_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,signed_data ,signed_data_len)
        
        
            safenetLib.sign(app, data, data_len, sign_sk_h, user_data, _sign_o_cb)
        self._sign = _sign
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _verify(app, signed_data, signed_data_len, sign_pk_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, uint8_t*, uintptr_t, SignPubKeyHandle, [any], [function], [custom ffi lib]
                App* app, uint8_t* signed_data, uintptr_t signed_data_len, SignPubKeyHandle sign_pk_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* verified_data, uintptr_t verified_data_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _verify_o_cb(user_data ,result ,verified_data ,verified_data_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,verified_data ,verified_data_len)
        
        
            safenetLib.verify(app, signed_data, signed_data_len, sign_pk_h, user_data, _verify_o_cb)
        self._verify = _verify
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _encrypt(app, data, data_len, public_key_h, secret_key_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, uint8_t*, uintptr_t, EncryptPubKeyHandle, EncryptSecKeyHandle, [any], [function], [custom ffi lib]
                App* app, uint8_t* data, uintptr_t data_len, EncryptPubKeyHandle public_key_h, EncryptSecKeyHandle secret_key_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* ciphertext, uintptr_t ciphertext_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _encrypt_o_cb(user_data ,result ,ciphertext ,ciphertext_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,ciphertext ,ciphertext_len)
        
        
            safenetLib.encrypt(app, data, data_len, public_key_h, secret_key_h, user_data, _encrypt_o_cb)
        self._encrypt = _encrypt
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _decrypt(app, data, data_len, public_key_h, secret_key_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, uint8_t*, uintptr_t, EncryptPubKeyHandle, EncryptSecKeyHandle, [any], [function], [custom ffi lib]
                App* app, uint8_t* data, uintptr_t data_len, EncryptPubKeyHandle public_key_h, EncryptSecKeyHandle secret_key_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* plaintext, uintptr_t plaintext_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _decrypt_o_cb(user_data ,result ,plaintext ,plaintext_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,plaintext ,plaintext_len)
        
        
            safenetLib.decrypt(app, data, data_len, public_key_h, secret_key_h, user_data, _decrypt_o_cb)
        self._decrypt = _decrypt
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _encrypt_sealed_box(app, data, data_len, public_key_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, uint8_t*, uintptr_t, EncryptPubKeyHandle, [any], [function], [custom ffi lib]
                App* app, uint8_t* data, uintptr_t data_len, EncryptPubKeyHandle public_key_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* ciphertext, uintptr_t ciphertext_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _encrypt_sealed_box_o_cb(user_data ,result ,ciphertext ,ciphertext_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,ciphertext ,ciphertext_len)
        
        
            safenetLib.encrypt_sealed_box(app, data, data_len, public_key_h, user_data, _encrypt_sealed_box_o_cb)
        self._encrypt_sealed_box = _encrypt_sealed_box
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _decrypt_sealed_box(app, data, data_len, public_key_h, secret_key_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, uint8_t*, uintptr_t, EncryptPubKeyHandle, EncryptSecKeyHandle, [any], [function], [custom ffi lib]
                App* app, uint8_t* data, uintptr_t data_len, EncryptPubKeyHandle public_key_h, EncryptSecKeyHandle secret_key_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* plaintext, uintptr_t plaintext_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _decrypt_sealed_box_o_cb(user_data ,result ,plaintext ,plaintext_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,plaintext ,plaintext_len)
        
        
            safenetLib.decrypt_sealed_box(app, data, data_len, public_key_h, secret_key_h, user_data, _decrypt_sealed_box_o_cb)
        self._decrypt_sealed_box = _decrypt_sealed_box
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _sha3_hash(data, data_len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
                uint8_t* data, uintptr_t data_len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* hash, uintptr_t hash_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _sha3_hash_o_cb(user_data ,result ,hash ,hash_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,hash ,hash_len)
        
        
            safenetLib.sha3_hash(data, data_len, user_data, _sha3_hash_o_cb)
        self._sha3_hash = _sha3_hash
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _generate_nonce(user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                [any], [function], [custom ffi lib]
                void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, AsymNonce* nonce)
            """
            @ffi.callback("void(void* ,FfiResult* ,AsymNonce*)")
            def _generate_nonce_o_cb(user_data ,result ,nonce):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,nonce)
        
        
            safenetLib.generate_nonce(user_data, _generate_nonce_o_cb)
        self._generate_nonce = _generate_nonce
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _cipher_opt_new_plaintext(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, CipherOptHandle handle)
            """
            @ffi.callback("void(void* ,FfiResult* ,CipherOptHandle)")
            def _cipher_opt_new_plaintext_o_cb(user_data ,result ,handle):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,handle)
        
        
            safenetLib.cipher_opt_new_plaintext(app, user_data, _cipher_opt_new_plaintext_o_cb)
        self._cipher_opt_new_plaintext = _cipher_opt_new_plaintext
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _cipher_opt_new_symmetric(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, CipherOptHandle handle)
            """
            @ffi.callback("void(void* ,FfiResult* ,CipherOptHandle)")
            def _cipher_opt_new_symmetric_o_cb(user_data ,result ,handle):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,handle)
        
        
            safenetLib.cipher_opt_new_symmetric(app, user_data, _cipher_opt_new_symmetric_o_cb)
        self._cipher_opt_new_symmetric = _cipher_opt_new_symmetric
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _cipher_opt_new_asymmetric(app, peer_encrypt_key_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, EncryptPubKeyHandle, [any], [function], [custom ffi lib]
                App* app, EncryptPubKeyHandle peer_encrypt_key_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, CipherOptHandle handle)
            """
            @ffi.callback("void(void* ,FfiResult* ,CipherOptHandle)")
            def _cipher_opt_new_asymmetric_o_cb(user_data ,result ,handle):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,handle)
        
        
            safenetLib.cipher_opt_new_asymmetric(app, peer_encrypt_key_h, user_data, _cipher_opt_new_asymmetric_o_cb)
        self._cipher_opt_new_asymmetric = _cipher_opt_new_asymmetric
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _cipher_opt_free(app, handle, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, CipherOptHandle, [any], [function], [custom ffi lib]
                App* app, CipherOptHandle handle, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _cipher_opt_free_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.cipher_opt_free(app, handle, user_data, _cipher_opt_free_o_cb)
        self._cipher_opt_free = _cipher_opt_free
        
        