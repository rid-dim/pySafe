########################################################################################################################
#
# pySafe - C FFI interface
#
# The purpose of this file is to parse and define the function signatures and structures defined in
#  ./safe_c_ffi_funcs.h   -> the header signatures
#  ./safe_c_datatypes.h   -> the data structures
#
# This can be done inline, but at present is done from the 'header' files for cleanliness of code and to facilitate
# interoperation with the utility that can generate these files.
#
# The current intended use of this file is to be imported in its entirety by 'interface.py' only.  Nothing in this file
# should be *directly* available to the end-user
#
# The current implementation is the 'ABI - Inline' mode of cffi operation.  As we benchmark performance, it may be
# useful to switch it to actually compiling a library rather than doing it all in Python. See
# https://cffi.readthedocs.io/en/latest/overview.html#simple-example-abi-level-in-line
#
########################################################################################################################
import pySafe.localization
from cffi import FFI
ffi = FFI()

_c_functions = {}
_c_structs = {}

# todo has implications for where ./extracted_binaries etc. are

#############################
#  Private methods
#############################

def __get_file_contents(fname):
    with open(fname, 'r') as f:
        return f.read()

def __split_to_lines(data):
    return [line.strip('\r\n') for line in data.splitlines()]

def __register_func_sig(f):
    '''
    registers all function names in global:functions.
    Only useful for print_funcs and get_function_signature right now, but later could be useful for online help
    #todo parse for signature and callback
    '''
    global _c_functions
    bits = f.split(maxsplit=1)
    first_bracket=bits[1].find('(')
    f=bits[1][:first_bracket]
    rest=bits[1][first_bracket:]
    _c_functions[f]=rest

#############################
#  Utility methods
#############################


def print_funcs():
    '''
    prints all registered functions and their signatures
    '''
    max_len= max([len(k) for k in _c_functions.keys()]) + 1
    print ('listing all functions bound from SAFE binary FFI: (func:sig)\n---------')
    for k,v in _c_functions.items():
        # ..to support eventual logging rather than directly print
        outstr=f'{k:{max_len}}:{v}'
        print (outstr)
    print('----\n')


def get_function_signature(f):
    '''
    returns the signature of a bound c function
    '''
    return _c_functions.get(f, f'function not found: {f}')

def print_dtypes():
    pass
    # may be nice to implement later for debugging

#############################
#
#  At this point, with functions defined, we load the data and register it.
#
#############################

_func_defs=__get_file_contents(pySafe.localization.SAFEFUNCHEADERS)
_struct_defs=__get_file_contents(pySafe.localization.SAFEDATAHEADERS)
#todo check/write tests for windows path compatibility of above

ffi.cdef(_struct_defs)
ffi.cdef(_func_defs)
lib_app = ffi.dlopen(pySafe.localization.SAFEAPPFILE)
lib_auth = ffi.dlopen(pySafe.localization.SAFEAUTHFILE)


# Now, all c header definitions are available, and callable through lib_app and lib_auth.
# Again, this is ABI-Inline mode for cffi, and it can be 'slow and fraught with errors'.. we see!
# todo seperate headers into app and auth?


# Helper to make signatures available for pretty printing. Maybe not necessary.
for f in __split_to_lines(_func_defs):
    __register_func_sig(f)


if __name__=='__main__':
    print_funcs()