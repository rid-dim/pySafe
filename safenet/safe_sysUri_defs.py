### FFI Binding Wrappers for libsafe_sysUri

import safenet.safe_utils as safeUtils

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

def install(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _install(bundle,vendor,name,exec_args_1 ,exec_args_len,icon,schemes,user_data, o_cb=None):
        """
            byte , bytes, bytes, char**, unsigned long, bytes, bytes, [any], [function]
            char* bundle, char* vendor, char* name, char** exec_args_1, unsigned long exec_args_len, char* icon, char* schemes, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        log.debug('sysUri install called')
        @self.ffi_sysUri.callback("void(void* ,FfiResult*)")
        def _install_o_cb(user_data ,result):
            safeUtils.checkResult(result, self.ffi_sysUri, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)


        self.lib.safe_sysUri.install(bundle,vendor,name,exec_args_1 ,exec_args_len,icon,schemes,user_data,_install_o_cb)
    self._install = _install



def open_uri(self, timeout, log, thread_decorator):
    @thread_decorator(timeout=timeout,queue=self.queue)
    def _open_uri(uri,user_data, o_cb=None):
        """
            byte , [any], [function]
            char* uri, void* user_data

            > callback functions:
            (*o_cb)(void* user_data, FfiResult* result)
        """
        log.debug('sysUri open_uri called')
        @self.ffi_sysUri.callback("void(void* ,FfiResult*)")
        def _open_uri_o_cb(user_data ,result):
            safeUtils.checkResult(result, self.ffi_sysUri, user_data)
            self.queue.put('gotResult')
            if o_cb:
                o_cb(user_data ,result)


        self.lib.safe_sysUri.open_uri(uri,user_data,_open_uri_o_cb)
    self._open_uri = _open_uri

