import safenet.base_classes as base
import queue

class Authenticator(base.FullAuthenticator):
    # Auto binds all auth methods
    def __init__(self):
        self.ffi=self.ffi_auth      # Uses Authlib exclusively. Do any classes use both?
        self.queue = queue.Queue()  # Each object has it's own queue for ffi calls
        self.bind_ffi_methods()

    ## Now, public methods here
    def login(self,sec,pwd, o_cb):
        self._login(sec,pwd,self.ffi_auth.NULL)

class CustomAuthenticator(base.BindableBase):
    # This way is individually specified
    ffi_auth_methods={'auth_init_logging' : 5}

    def __init__(self):
        self.ffi=self.ffi_auth      # Uses Authlib exclusively. Do any classes use both?
        self.queue = queue.Queue()  # Each object has it's own queue for ffi calls
        self.bind_ffi_methods()

    ## Now, public methods here



if __name__ == '__main__':
    # we test it!
    A = Authenticator()
    A._auth_exe_file_stem(A.ffi_auth.NULL)
    A._auth_set_additional_search_path(A.ffi_auth.new('char[]',b'../compiled_binaries/'),A.ffi_auth.NULL)
    A.login(b'a',b'd', A.ffi_auth.NULL)
    print(A.queue.qsize())