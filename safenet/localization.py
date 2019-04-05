########################################################################################################################
# Localization
#
# Utilities to initialize the package correctly on different machines and OSes.   Some light utilities for finding
#    files, and checks to ensure that the OS correct binaries are the ones actually linked to by the interface.
#
# If the correct binaries are not found, this module will kill the program with an error showing which ones were not
#    correct.
#
# Needs a serious pass later when we start allowing configurable options etc..
#
########################################################################################################################

import platform
import os
import safenet.config

### Helper Functions
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
    # __file__ is relative to localization.py location
    return os.path.dirname(module.__file__)

### Detect and set up binary and OS specific configuration.

# todo These variables must always return the correct library location.. Test test test

BINPATH = os.path.dirname(_lvl_down(__file__))+os.sep+'compiled_binaries'
LOGPATH = os.path.dirname(_lvl_down(__file__)) + os.sep + 'logs'
HEADERPATH = os.path.dirname(__file__)+os.sep+'extracted_headers'

# Inject this into the config file
if safenet.config.GLOBAL_BINPATH is None:
    safenet.config.GLOBAL_BINPATH=os.path.abspath(BINPATH)

LINUX_AUTHLIB = 'libsafe_authenticator.so'
LINUX_APPLIB = 'libsafe_app.so'
LINUX_SYSURILIB = 'libsystem_uri.so'
WIN_AUTHLIB = 'libsafe_authenticator.dll'
WIN_APPLIB = 'libsafe_app.dll'
WIN_SYSURILIB = 'libsystem_uri.dll'

# Select the platform specific libraries, and test if they exist.
APPLIB,AUTHLIB = None, None
if platform.system() == 'Linux':
    APPLIB, AUTHLIB, SYSURILIB = LINUX_APPLIB, LINUX_AUTHLIB, LINUX_SYSURILIB
if platform.system() == 'Windows':
    APPLIB, AUTHLIB, SYSURILIB = WIN_APPLIB, WIN_AUTHLIB, WIN_SYSURILIB

SAFEAPPFILE = os.path.join(BINPATH, APPLIB)
SAFEAUTHFILE = os.path.join(BINPATH, AUTHLIB)
SAFESYSURIFILE = os.path.join(BINPATH, SYSURILIB)

# Make sure the appropriate files exist
filecheck=True
for item in [SAFEAPPFILE,SAFEAUTHFILE,SAFESYSURIFILE]:
    if not os.path.exists(item):
        print (f'{item} not found')
        filecheck=False

if not filecheck:
    print(f'---\nThe above SAFE binaries for {platform.system()} are missing.\n'
          f'..Ensure they are in {BINPATH} and try again')
    exit(1)

# Eventually need a utility to find this.
SAFECRUSTCONFIG=os.path.join(BINPATH,'python3.crust.config')

# Review this after the autogenerators
APP_FUNCHEADERS=os.path.join(HEADERPATH,'safe_app_function_declarations')
APP_DATAHEADERS=os.path.join(HEADERPATH,'safe_app_datatype_declarations')
AUTH_FUNCHEADERS=os.path.join(HEADERPATH,'safe_authenticator_function_declarations')
AUTH_DATAHEADERS=os.path.join(HEADERPATH,'safe_authenticator_datatype_declarations')
SYSURI_FUNCHEADERS=os.path.join(HEADERPATH,'system_uri_function_declarations')
SYSURI_DATAHEADERS=os.path.join(HEADERPATH,'safe_app_datatype_declarations')

safenet.config.GLOBAL_BINPATH=os.path.abspath(BINPATH)
