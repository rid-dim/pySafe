########################################################################################################################
#
# pySafe - C FFI interface
#
# The purpose of this file is to parse and define the function signatures and structures defined in
#  ./extracted_headers/*.h
#
# This can be done inline, but at present is done from the 'header' files for cleanliness of code and to facilitate
# interoperation with the utility that can generate these files.
#
# The current intended use of this file is to be imported in its entirety by 'interface.py' only.  Nothing in this file
# should be *directly* available to the end-user. It's all about setting up the c interface and supporting abstraction.
#
# The current implementation is the 'ABI - Inline' mode of cffi operation.  As we benchmark performance, it may be
# useful to switch it to actually compiling a library rather than doing it all in Python. See
# https://cffi.readthedocs.io/en/latest/overview.html#simple-example-abi-level-in-line
#
########################################################################################################################

import safenet.localization as localization
from cffi import FFI
from functools import partial

# We first initialize separate ffi interfaces for the app and auth libraries.  The symbols with loaded dlls come later
ffi_app = FFI()
ffi_auth = FFI()
ffi_sysUri = FFI()


#############################
#  Private methods
#############################

def __get_file_contents(fname):
    with open(fname, 'r') as f:
        return f.read()

def __split_to_lines(data):
    return [line.strip('\r\n') for line in data.splitlines()]

def __register_func_sig(f, d):
    '''
    registers all function names in global:functions.
    Only useful for print_funcs and get_function_signature right now, but later could be useful for online help
    #todo parse for signature and callback
    '''
    bits = f.split(maxsplit=1)
    first_bracket=bits[1].find('(')
    f=bits[1][:first_bracket]
    rest=bits[1][first_bracket:]
    d[f]=rest

#############################
#  At this point, we load the data and register it.
#############################

_func_defs_app=__get_file_contents(localization.APP_FUNCHEADERS)
_struct_defs_app=__get_file_contents(localization.APP_DATAHEADERS)
_func_defs_auth=__get_file_contents(localization.AUTH_FUNCHEADERS)
_struct_defs_auth=__get_file_contents(localization.AUTH_DATAHEADERS)
_func_defs_sysUri=__get_file_contents(localization.SYSURI_FUNCHEADERS)
_struct_defs_sysUri=__get_file_contents(localization.SYSURI_DATAHEADERS)

ffi_app.cdef(_struct_defs_app)
ffi_app.cdef(_func_defs_app)
lib_app = ffi_app.dlopen(localization.SAFEAPPFILE)

ffi_auth.cdef(_struct_defs_auth)
ffi_auth.cdef(_func_defs_auth)
lib_auth = ffi_auth.dlopen(localization.SAFEAUTHFILE)

ffi_sysUri.cdef(_struct_defs_sysUri)
ffi_sysUri.cdef(_func_defs_sysUri)
lib_sysUri = ffi_sysUri.dlopen(localization.SAFESYSURIFILE)

# Now, all c header definitions are available, and callable through lib_app and lib_auth.
# Again, this is ABI-Inline mode for cffi, and it can be 'slow and fraught with errors'.. we see!

#############################
#  For development help, store the bound functions and structs and their signatures. This section may disappear later
#############################

#  Utility methods for printing and signatures

def print_funcs(ffi_name,d):
    '''
    prints all registered functions and their signatures
    '''
    max_len= max([len(k) for k in d.keys()]) + 1
    print (f'listing all functions bound from SAFE {ffi_name} FFI: (func:sig)\n---------')
    for k,v in d.items():
        # ..to support eventual logging rather than directly print
        outstr=f'{k:{max_len}}:{v}'
        print (outstr)
    print('----\n')


def get_function_signature(f,d=None):
    '''
    returns the signature of a bound c function
    '''
    if d is None: d={}
    return d.get(f, f'function not found: {f}')

def print_dtypes():
    pass
    # may be nice to implement later for debugging


_app_c_functions = {}
_app_c_structs = {}
_auth_c_functions = {}
_auth_c_structs = {}
_sysUri_c_functions = {}
_sysUri_c_structs = {}

for f in __split_to_lines(_func_defs_app):
    if f:
        __register_func_sig(f, _app_c_functions)

for f in __split_to_lines(_func_defs_auth):
    if f:
        __register_func_sig(f, _auth_c_functions)

for f in __split_to_lines(_func_defs_sysUri):
    if f:
        __register_func_sig(f, _sysUri_c_functions)

print_app_funcs = partial(print_funcs,'lib_app',_app_c_functions)
print_auth_funcs = partial(print_funcs,'lib_authenticator',_auth_c_functions)
print_sysUri_funcs = partial(print_funcs,'lib_sysUri',_sysUri_c_functions)

if __name__=='__main__':
    print_app_funcs()
    print_auth_funcs()
    print_sysUri_funcs()

