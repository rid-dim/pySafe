########################################################################################################################
#
# pySafe - the interface to the 'interface'
#
# this file is intended as the gatekeeper to the actual interface.
# - kept separate to separate c binding logic from 'interaction with c binding' logic
# - another advantage is that this separation will make it easier if we want to change the safe_ffi_interface to a
#   'compiling' mode at some point in the future
# .. maybe merge someday
#
# it is used by base_classes, which then underlie the high level interfaces
#
########################################################################################################################

from safenet.safe_ffi_interface import lib_app,lib_auth,lib_sysUri,print_app_funcs,print_auth_funcs,print_sysUri_funcs, ffi_app,ffi_auth,ffi_sysUri

'''
This brings in:
lib_app:        the opened safe_app FFI object, bound to right system binaries 
ffi_app:        the ffi which is used to cdef new objects for interacting with lib_app 
lib_auth:       the opened safe_auth FFI object, bound to right system binaries
ffi_auth:       the ffi which is used to cdef new objects for interacting with lib_auth
print_x_funcs():  print all defined c functions for ffi interface 'x' (auth, app)  
'''

## Keep for now.. todo delete when confident
print('SAFE python-rust interface generated, bound and available')

class lib:
    '''
    To integrate rid's proof of concept on a first pass.   Possibly better to delete and simply assign them directly
    in InterfacesWithSafe
    '''
    def __init__(self,authlib,applib,sysUrilib):
        self.safe_authenticator = authlib
        self.safe_app = applib
        self.safe_sysUri = sysUrilib

class InterfacesWithSafe:
    '''
    A base class with the safe libraries bound to it
    '''
    ffi_app=ffi_app
    ffi_auth=ffi_auth
    ffi_sysUri=ffi_sysUri
    lib=lib(lib_auth,lib_app,lib_sysUri)



