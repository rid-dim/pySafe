########################################################################################################################
#
#  Data Class definitions.
#
#  These abstract 1-1 the data structs found in the C ffi api.
#    The point is to be able to instantiate them with straight python objects
#    If used in a function call, the .to_ffi() method will convert all their members to c-compatible formats
#      and return a cffi object of their type.
#
#  Implementation notes: will replace much of safe_utils .. e.g. checkResult and the directly instantiated funcs like
#    AppExchangeInfo
#
#  The base class has a generic to_ffi that may need to be overridden for troublesome data classes
#
########################################################################################################################

from safenet.interface import ffi_auth,ffi_app

#ffi_inits={'char*':'char[]'}


class PySafeDataObject():

    _structname = ''  # store the ffi definition_name
    _ffi=None         # A container for the cffi object

    @property
    def ffi(self):
        if self._ffi is None:
            self._ffi = self. to_ffi()
        return self._ffi

    def to_ffi(self):
        '''
        :return: a cffi object corresponding to a c struct of the same name e.g. 'AppExchangeInfo'
        '''
        raise NotImplementedError('to_ffi must be overridden')

    def to_json(self):
        '''
        :return: a json object with data about the object and it's members.
        '''
        raise NotImplementedError('to_json must be overridden')

    @staticmethod
    def from_ffi():
        raise NotImplementedError('from_ffi must be overridden')

    @staticmethod
    def from_json():
        raise NotImplementedError('from_json must be overridden')

