import safenet.interface as interface
import safenet.safe_auth_defs as safe_auth_defs
import safenet.safe_app_defs as safe_app_defs
import safenet.config as config

# Find the bindable methods
available_auth_defs={item for item in dir(safe_auth_defs) if not item.startswith('_') and not item.startswith('safeU')}
available_app_defs={item for item in dir(safe_auth_defs) if not item.startswith('_') and not item.startswith('safeU')}

class BindableBase(interface.InterfacesWithSafe):
    ffi_auth_methods = {}
    ffi_app_methods = {}

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

class FullAuthenticator(BindableBase):
    ffi_auth_methods = {item:config.GlobalDefaultTimeout for item in available_auth_defs}
