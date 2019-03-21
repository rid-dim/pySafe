import safenet.safeUtils as safeUtils
import queue

# first attempt to define mutable Data for us
class immutableData:
    def __init__(self,authlib,applib,ffi,fromBytes=None):
        self.lib = safeUtils.lib(authlib,applib)
        self.queue = queue.Queue() 
        
        # defining the mutableData
        if fromBytes:
            self.asBytes = fromBytes
            #self.ffiMutable=ffi.new('MDataInfo *')
            #writeBuffer = ffi.buffer(self.ffiMutable)
            #writeBuffer[:]=self.asBytes
        else:
            self.asBytes = None
            #self.ffiMutable = None


        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _idata_new_self_encryptor(app, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, [any], [function], [custom ffi lib]
                App* app, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, SEWriterHandle se_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,SEWriterHandle)")
            def _idata_new_self_encryptor_o_cb(user_data ,result ,se_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,se_h)
        
        
            safenetLib.idata_new_self_encryptor(app, user_data, _idata_new_self_encryptor_o_cb)
        self._idata_new_self_encryptor = _idata_new_self_encryptor
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _idata_write_to_self_encryptor(app, se_h, data, data_len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, SEWriterHandle, uint8_t*, uintptr_t, [any], [function], [custom ffi lib]
                App* app, SEWriterHandle se_h, uint8_t* data, uintptr_t data_len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _idata_write_to_self_encryptor_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.idata_write_to_self_encryptor(app, se_h, data, data_len, user_data, _idata_write_to_self_encryptor_o_cb)
        self._idata_write_to_self_encryptor = _idata_write_to_self_encryptor
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _idata_close_self_encryptor(app, se_h, cipher_opt_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, SEWriterHandle, CipherOptHandle, [any], [function], [custom ffi lib]
                App* app, SEWriterHandle se_h, CipherOptHandle cipher_opt_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, XorNameArray* name)
            """
            @ffi.callback("void(void* ,FfiResult* ,XorNameArray*)")
            def _idata_close_self_encryptor_o_cb(user_data ,result ,name):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,name)
        
        
            safenetLib.idata_close_self_encryptor(app, se_h, cipher_opt_h, user_data, _idata_close_self_encryptor_o_cb)
        self._idata_close_self_encryptor = _idata_close_self_encryptor
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _idata_fetch_self_encryptor(app, name, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, XorNameArray*, [any], [function], [custom ffi lib]
                App* app, XorNameArray* name, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, SEReaderHandle se_h)
            """
            @ffi.callback("void(void* ,FfiResult* ,SEReaderHandle)")
            def _idata_fetch_self_encryptor_o_cb(user_data ,result ,se_h):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,se_h)
        
        
            safenetLib.idata_fetch_self_encryptor(app, name, user_data, _idata_fetch_self_encryptor_o_cb)
        self._idata_fetch_self_encryptor = _idata_fetch_self_encryptor
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _idata_serialised_size(app, name, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, XorNameArray*, [any], [function], [custom ffi lib]
                App* app, XorNameArray* name, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint64_t serialised_size)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint64_t)")
            def _idata_serialised_size_o_cb(user_data ,result ,serialised_size):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,serialised_size)
        
        
            safenetLib.idata_serialised_size(app, name, user_data, _idata_serialised_size_o_cb)
        self._idata_serialised_size = _idata_serialised_size
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _idata_size(app, se_h, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, SEReaderHandle, [any], [function], [custom ffi lib]
                App* app, SEReaderHandle se_h, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint64_t size)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint64_t)")
            def _idata_size_o_cb(user_data ,result ,size):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,size)
        
        
            safenetLib.idata_size(app, se_h, user_data, _idata_size_o_cb)
        self._idata_size = _idata_size
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _idata_read_from_self_encryptor(app, se_h, from_pos, len, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, SEReaderHandle, uint64_t, uint64_t, [any], [function], [custom ffi lib]
                App* app, SEReaderHandle se_h, uint64_t from_pos, uint64_t len, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result, uint8_t* data, uintptr_t data_len)
            """
            @ffi.callback("void(void* ,FfiResult* ,uint8_t* ,uintptr_t)")
            def _idata_read_from_self_encryptor_o_cb(user_data ,result ,data ,data_len):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result ,data ,data_len)
        
        
            safenetLib.idata_read_from_self_encryptor(app, se_h, from_pos, len, user_data, _idata_read_from_self_encryptor_o_cb)
        self._idata_read_from_self_encryptor = _idata_read_from_self_encryptor
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _idata_self_encryptor_writer_free(app, handle, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, SEWriterHandle, [any], [function], [custom ffi lib]
                App* app, SEWriterHandle handle, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _idata_self_encryptor_writer_free_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.idata_self_encryptor_writer_free(app, handle, user_data, _idata_self_encryptor_writer_free_o_cb)
        self._idata_self_encryptor_writer_free = _idata_self_encryptor_writer_free
        
        
        
        @safeUtils.safeThread(timeout=5,queue=self.queue)
        def _idata_self_encryptor_reader_free(app, handle, user_data, o_cb=None, safenetLib=self.lib.safe_app):
            """
                App*, SEReaderHandle, [any], [function], [custom ffi lib]
                App* app, SEReaderHandle handle, void* user_data
        
                > callback functions:
                (*o_cb)(void* user_data, FfiResult* result)
            """
            @ffi.callback("void(void* ,FfiResult*)")
            def _idata_self_encryptor_reader_free_o_cb(user_data ,result):
                safeUtils.checkResult(result,ffi)
                self.queue.put('gotResult')
                if o_cb:
                    o_cb(user_data ,result)
        
        
            safenetLib.idata_self_encryptor_reader_free(app, handle, user_data, _idata_self_encryptor_reader_free_o_cb)
        self._idata_self_encryptor_reader_free = _idata_self_encryptor_reader_free
