########################################################################################################################
#
#  pySafe - utility functions
#
#
#
########################################################################################################################

from .safe_ffi_interface import *


def _guarantee_encoded_string(s, encoding=None):
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
