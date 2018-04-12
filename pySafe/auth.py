########################################################################################################################
#
#  pySafe - Authenticator Interface
#
########################################################################################################################

# This brings all the c interfaces into this module .. maybe better to keep it in a namespace?
from .safe_ffi_interface import *

import util_funcs


class Auth:
    def __init__(self,
                 name='noAuth',
                 version='0.0.0',
                 vendor='rid',
                 libLocation='../compiled_binaries/libsafe_authenticator.so',
                 addr='http://localhost'):
        self.name = name
        self.version = version
        self.vendor = vendor
        self.url = addr
        self.lib = ffi.dlopen(libLocation)

    def defaultFfiResult(self, result, actionDescription):

        if result.error_code == 0:
            print('successfully ' + actionDescription)
        else:
            print('an Error occured - Error Code: ' + str(result.error_code))
            print('Error description: ' + str(ffi.string(result.description)))

    def toByteIfString(self, parameter, encoding):
        if type(parameter) == str:
            return parameter.encode()
        else:
            return parameter