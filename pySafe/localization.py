import os

def find_bin_dir():
    pass



def _lvl_down(path):
    '''
    Move down one directory
    '''
    return os.path.split(path)[0]

def _lvl_up(path, up_dir):
    '''
    Move up one ..specified.. directory
    '''
    return os.path.join(path, up_dir)

def get_mod_loc(module):
    return os.path.dirname(module.__file__)


# __file__ is relative to localization.py result

# todo These variables must always return the correct library location.. Test test test

BINPATH = os.path.dirname(_lvl_down(__file__))+os.sep+'compiled_binaries'
HEADERPATH = os.path.dirname(__file__)+os.sep+'extracted_headers'


SAFEAPPFILE=os.path.join(BINPATH,'libsafe_app.so')
SAFEAUTHFILE=os.path.join(BINPATH,'libsafe_authenticator.so')
SAFECRUSTCONFIG=os.path.join(BINPATH,'python3.crust.config')


SAFEFUNCHEADERS=os.path.join(HEADERPATH,'safe_c_ffi_funcs.h')
SAFEDATAHEADERS=os.path.join(HEADERPATH,'safe_c_ffi_data.h')
