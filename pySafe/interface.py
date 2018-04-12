########################################################################################################################
#
#  pySafe - the interface to the 'interface'
#
#  this file is intended as the gatekeeper to the actual interface.
#
#  includes safe_ffi_interface.py wholesale..
#
########################################################################################################################

from pySafe.safe_ffi_interface import *
'''
This brings in:
ffi:            the interface manager object with the header definitions
lib_app:        the opened safe_app  so 
lib_auth:       the opened safe_auth  so
print_funcs():  print all defined c functions 
print_structs():print all defined c structs 
'''

NULL=ffi.NULL
safe_cb=ffi.callback


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


if __name__=='__main__':
    # now we be testin'
    print_funcs()  # a safe_ffi_interface method
    print('basic testing...')

