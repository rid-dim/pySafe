########################################################################################################################
#
# Localization
#
# Simple utilities to find and standardize naming of project directories.  Keeps things simpler when moving accross
# machines
#
# Needs a serious pass later when we start allowing configurable options etc..
#
########################################################################################################################
import platform
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
LOGPATH = os.path.dirname(_lvl_down(__file__)) + os.sep + 'logs'
HEADERPATH = os.path.dirname(__file__)+os.sep+'extracted_headers'

LINUX_AUTHLIB = 'libsafe_authenticator.so'
LINUX_APPLIB = 'libsafe_app.so'
WIN_AUTHLIB = 'NOT_IMPLEMENTED'
WIN_APPLIB = 'NOT_IMPLEMENTED'

APPLIB = LINUX_APPLIB if platform.system() == 'Linux' else WIN_APPLIB
AUTHLIB = LINUX_AUTHLIB if platform.system() == 'Linux' else WIN_AUTHLIB

SAFEAPPFILE = os.path.join(BINPATH, APPLIB)
SAFEAUTHFILE = os.path.join(BINPATH, AUTHLIB)

# Eventually need a utility to find this.
SAFECRUSTCONFIG=os.path.join(BINPATH,'python3.crust.config')

# Review this after the autogenerators
APP_FUNCHEADERS=os.path.join(HEADERPATH,'safe_app_function_declarations')
APP_DATAHEADERS=os.path.join(HEADERPATH,'safe_app_datatype_declarations')
AUTH_FUNCHEADERS=os.path.join(HEADERPATH,'safe_authenticator_function_declarations')
AUTH_DATAHEADERS=os.path.join(HEADERPATH,'safe_authenticator_datatype_declarations')
