import safenet.interface as interface
import safenet.safe_auth_defs as safe_auth_defs
import safenet.safe_app_defs as safe_app_defs
import safenet.config as config
from safenet.safeUtils import ensure_correct_form

# Find the bindable methods
available_auth_defs={item for item in dir(safe_auth_defs) if not item.startswith('_') and not item.startswith('safeU')}
available_app_defs={item for item in dir(safe_auth_defs) if not item.startswith('_') and not item.startswith('safeU')}

class AutoInvoke():
    def __init__(self,f,ffi):
        self.f=f
        self.ffi=ffi
    def __call__(self, *args, **kwargs):
        # First we add the ffi, which is picked off by the ensure correct form function and used
        # to cdef the appropriate datatypes for each argument, which is then passed to the underlying
        # function, which should always be a ffi function.
        args=[self.ffi]+[a for a in args]
        self.f(*ensure_correct_form(*args),**kwargs)

class BindableBase(interface.InterfacesWithSafe):
    '''
    Provides the essential bindings to the ffi interface and functions to adjust them.
    Used as a base class for classes that have methods that interface with the safenet ffi.
    '''
    ffi_auth_methods = {}
    ffi_app_methods = {}

    # cleaner method
    ensure_correct_form=ensure_correct_form

    def bind_ffi_methods(self):
        for meth, timeout in self.ffi_auth_methods.items():
            self.bind_ffi_method(meth,timeout, safe_auth_defs)
        for meth, timeout in self.ffi_app_methods.items():
            self.bind_ffi_method(meth,timeout, safe_app_defs)

    def bind_ffi_method(self, methodname, timeout, lib):
        try:
            bind_func = getattr(lib, methodname)
            if timeout is None:
                bind_func(self,config.GlobalDefaultTimeout)
            else:
                bind_func(self,timeout)
        except:
            print (f'illegal function name {methodname} in library {lib}')

    def __getattr__(self, item):
        # Missed attribute lookup:  If it's in the bound method spec, and the _ffi version is bound, return a
        # wrapper function that calls the underlying _ffi method with the arguments cleaned.
        # wonderfully useful, but may be a bad idea.
        if item in self.ffi_auth_methods.keys() or item in self.ffi_app_methods.keys() and hasattr(self,f'_{item}'):
            return AutoInvoke(getattr(self,f'_{item}'),self.ffi)



class FullAuthenticator(BindableBase):
    # Update the dictionary to load all available methods when bind is called
    ffi_auth_methods = {item:config.GlobalDefaultTimeout for item in available_auth_defs}
