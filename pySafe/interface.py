########################################################################################################################
#
# pySafe - the interface to the 'interface'
#
# this file is intended as the gatekeeper to the actual interface.
# - kept seperate to seperate c binding logic from 'interaction with c binding' logic
# - another advantage is that this seperation will make it easier if we want to change the safe_ffi_interface to a
#   'compiling' mode at some point in the future
# .. maybe merge someday
#
# includes safe_ffi_interface.py wholesale..
#
########################################################################################################################

import pySafe.localization
from pySafe.safe_ffi_interface import *

'''
This brings in:
ffi:            the interface manager object with the header definitions
lib_app:        the opened safe_app  so 
lib_auth:       the opened safe_auth  so
print_funcs():  print all defined c functions 
print_structs():print all defined c structs 
'''

# convenience, lazyness, simplifying namespace
NULL=ffi.NULL
safe_callback=ffi.callback


####
#  FFI Datatype casters
####

def _guarantee_encoded_string(s, encoding='UTF-8'):
    '''
    :param s: the string to be encoded.
    :param encoding:  The encoding of the string
    :return: a bytes object of the string
    '''

    # Todo This should be subject to HEAVY testing

    if type(s) == str:
        return s.encode(encoding=encoding)
    else:
        return s


def ffi_str(s):
    '''
    :param s: a python string
    :return: a pointer to the string suitable for passing to the ffi c interface
    '''
    s=_guarantee_encoded_string(s)
    return ffi.new('char[]',s)



####
#  FFI initialization functions
####


def add_local_crust_config(config_path=pySafe.localization.BINPATH):
    '''
    adds config_path to the library configuration
    '''
    print(f'adding {config_path} to config search path')
    lib_auth.auth_set_additional_search_path(ffi_str(config_path), NULL, config_search_result_cb)

def print_default_ffi_result(result, actionDescription):
    if result.error_code == 0:
        print(f'..success: {actionDescription}')
    else:
        print('An error occured - Code: ' + str(result.error_code))
        print('Error description: ' + str(ffi.string(result.description)))

#####
#  Initialization callbacks
#####



@safe_callback("void(void*, FfiResult*)")
def config_search_result_cb(user_data, result):
    print_default_ffi_result(result, 'changing search path')

@safe_callback("void(void*,FfiResult*, char*)")
def stem_callback(user_data, result, name):
    global userData, myResult

    userData = user_data
    myResult = result
    print_default_ffi_result(result, 'executing app_exe_file_stem')
    print(f'..callback file_stem name: {ffi.string(name)}')




## Keep for now.. todo delete when confident
print('Basic SAFE interface generated')
print_funcs()



## todo .. is this the right place for this?
lib_app.app_exe_file_stem(ffi.NULL, stem_callback)





if __name__=='__main__':
    pass

