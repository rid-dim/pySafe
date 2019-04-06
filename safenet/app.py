########################################################################################################################
#
# pySafe - App Interface
#
# This is really just a stub  ... files like this should be able to import the interface and just go, but code structure
# really needs some thought
#
#
#
########################################################################################################################

import safenet.base_classes as base
import safenet.authenticator as authenticator
import safenet.mutabledata as mutabledata
import safenet.immutabledata as immutabledata
import safenet.sysUri as sysUri
import queue

class App(base.FullApp):
    def __init__(self,
                 name='SAFE_Connection',
                 version='0.0.0',
                 vendor='rid+dask',
                 addr='http://localhost'):
        self.name = name
        self.version = version
        self.vendor = vendor
        self.url = addr
        self.authenticator = authenticator.Authenticator()
        self.mutableData = mutabledata.MutableData()
        self.immutableData = immutabledata.ImmutableData()
        self.sysUri = sysUri.SysUri()

        self.queue = queue.Queue()   # Each object has it's own queue for ffi calls
        self.bind_ffi_methods()

    # Public methods of this class override the auto bound ffi methods and are generally necessary where simple
    # string and null pointer conversion of python objects are not sufficient.  Default functionality is equivalent to:
    #  def login(self, secret, password, userdata=None, o_cb=None):
    #     self._login(*self.ensure_correct_form(secret, password, userdata, self.login_cb))
    # A full listing of the class methods automatically bound can be found in safe_app_defs.py (_APP_DEFS)
        
if __name__ == '__main__':
    # we test it!
    A = App()
