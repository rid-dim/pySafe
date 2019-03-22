########################################################################################################################
#
# pySafe - Authenticator
#
# This file encapsulates the interface for the authenticator library.
#
# The authenticator is a critical component of any app, and is required for many tasks.
#
# The implementations for the various functions should be the last place in the library you will see ffi.
#  Higher level abstractions should be able to use the public methods with pure python objects
#
########################################################################################################################

import safenet.base_classes as base
import getpass
import queue

class Authenticator(base.FullAuthenticator):
    # Auto binds all auth methods
    def __init__(self):
        #self.ffi=self.ffi_auth      # Uses Authlib exclusively. Do any classes use both? No longer needed as ffi
                                     # defs know the correct one.  Only enable for convenience
        self.queue = queue.Queue()  # Each object has it's own queue for ffi calls
        self.bind_ffi_methods()

    ## Now, public methods here

    # Note, the autoinvoke takes care of the bound ffi_methods, not necessary to explicitly define a function unless
    # we want behaviour different than the following:
    # def login(self, secret, password, userdata=None, o_cb=None):
        # self._login(*self.ensure_correct_form(secret, password, userdata, self.login_cb))

    @staticmethod
    def login_cb(result):
        print('login result', result)

class CustomAuthenticator(base.BindableBase):
    # This way only the individually specified ffi funcs are bound
    ffi_auth_methods={'auth_init_logging' : 5}

    def __init__(self):
        self.ffi=self.ffi_auth      # Uses Authlib exclusively. Do any classes use both?
        self.queue = queue.Queue()  # Each object has it's own queue for ffi calls
        self.bind_ffi_methods()

    ## Now, public methods here



if __name__ == '__main__':
    # we test it!
    A = Authenticator()
    def printfilestem(one,two,stem):
        print(A.ffi_auth.string(stem))

    # Note again that these methods were never defined, and can be called with regular strings and python objects:)
    A.auth_exe_file_stem(None, printfilestem)
    A.auth_set_additional_search_path('D:/Programming/pySafe/compiled_binaries/',None)
    A.login('secret','password', None, A.login_cb)
