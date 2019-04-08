import safenet.interface as interface
import safenet.safe_auth_defs as safe_auth_defs
import safenet.safe_app_defs as safe_app_defs
import safenet.safe_sysUri_defs as safe_sysUri_defs
import safenet.config as config
from safenet.safe_utils import ensure_correct_form, safeThread, IncrementingUserData

import logging
log = logging.getLogger(config.GLOBAL_LOGGER_NAME)


# Find the bindable methods
available_auth_defs={item for item in dir(safe_auth_defs) if not item.startswith('_') and not item.startswith('safeU')}
available_app_defs={item for item in dir(safe_app_defs) if not item.startswith('_') and not item.startswith('safeU')}
available_sysUri_defs={item for item in dir(safe_sysUri_defs) if not item.startswith('_') and not item.startswith('safeU')}


class AutoInvoke():
    '''
    Wraps a function call to scan the args and do a simple conversion to the cffi-equivalent.  Only works
    for simple functions.  If this fails, the function needs to be overridden in the appropriate class.
    '''
    def __init__(self,f,ffi):
        self.f=f
        self.ffi=ffi
    def __call__(self, *args, **kwargs):
        # First we add the ffi, which is picked off by the ensure correct form function and used
        # to cdef the appropriate datatypes for each argument, which is then passed to the underlying
        # function, which should always be a ffi function.
        args=[self.ffi]+[a for a in args]
        self.f(*ensure_correct_form(*args),**kwargs)

class HasLogger():
    log=log

class BindableBase(interface.InterfacesWithSafe, HasLogger):
    '''
    Provides the essential bindings to the ffi interface and functions to adjust them.
    Used as a base class for classes that have methods that interface with the safenet ffi.
    '''
    ffi_auth_methods = {}
    ffi_app_methods = {}
    ffi_sysUri_methods = {}
    global_config = config
    UserData=IncrementingUserData

    # cleaner method
    ensure_correct_form=ensure_correct_form

    def bind_ffi_methods(self):
        # The first four lines here are simply to allow sets and lists to work (with the global default timeout)
        if not isinstance(self.ffi_app_methods, dict):
            self.ffi_app_methods={item:None for item in self.ffi_app_methods}
        if not isinstance(self.ffi_auth_methods, dict):
            self.ffi_auth_methods={item:None for item in self.ffi_auth_methods}
        if not isinstance(self.ffi_sysUri_methods, dict):
            self.ffi_sysUri_methods={item:None for item in self.ffi_sysUri_methods}

        for meth, timeout in self.ffi_auth_methods.items():
            self.bind_ffi_method(meth,timeout, safe_auth_defs)
        for meth, timeout in self.ffi_app_methods.items():
            self.bind_ffi_method(meth,timeout, safe_app_defs)
        for meth, timeout in self.ffi_sysUri_methods.items():
            self.bind_ffi_method(meth,timeout, safe_sysUri_defs)

    def bind_ffi_method(self, methodname, timeout, lib):
        '''
        Here we call the method from app_defs or safe_auth_defs, and pass it the current object for binding,
        the timeout to use in the threader, the log implementation, and the chosen threading decorator
        '''
        try:
            bind_func = getattr(lib, methodname)
            if timeout is None:
                bind_func(self, config.GLOBAL_DEFAULT_TIMEOUT, self.log.getChild('ffi_out'), safeThread)
            else:
                bind_func(self,timeout, self.log.getChild('ffi_out'), safeThread)
        except:
            log.critical(f'tried binding bad function name "{methodname}" in library {lib.__name__}')


    def __getattr__(self, item):
        # Missed attribute lookup:  If it's in the bound method spec, and the _ffi version is bound, return a
        # wrapper function that calls the underlying _ffi method with the arguments cleaned.
        # Wonderfully useful, and saves us from implementing 70 methods but won't work with all methods
        # With this and the changes to safe_app_defs and safe_auth_defs, we no longer need self.ffi
        # as the correct interface is always known from context when autoinvoking a c ffi function
        if item in self.ffi_app_methods.keys() and hasattr(self,f'_{item}'):
            return AutoInvoke(getattr(self,f'_{item}'),self.ffi_app)
        elif item in self.ffi_auth_methods.keys() and hasattr(self,f'_{item}'):
            return AutoInvoke(getattr(self, f'_{item}'), self.ffi_auth)
        elif item in self.ffi_sysUri_methods.keys() and hasattr(self,f'_{item}'):
            return AutoInvoke(getattr(self, f'_{item}'), self.ffi_sysUri)
        else:
            raise AttributeError(item)


class FullAuthenticator(BindableBase):
    # Update the dictionary to load all available methods when bind is called
    ffi_auth_methods = {item:config.GLOBAL_DEFAULT_TIMEOUT for item in safe_auth_defs._AUTH_DEFS}

class StandardApp(BindableBase):
    # Uses the standard methods
    ffi_app_methods  = safe_app_defs._APP_DEFS

class StandardImmutableData(BindableBase):
    # All the idata methods
    ffi_app_methods = safe_app_defs._IDATA_DEFS

class StandardMutableData(BindableBase):
    # All the mdata methods
    ffi_app_methods = safe_app_defs._MDATA_DEFS

class SysUri(BindableBase):
    # All the mdata methods
    ffi_sysUri_methods = {item:config.GLOBAL_DEFAULT_TIMEOUT for item in available_sysUri_defs}

