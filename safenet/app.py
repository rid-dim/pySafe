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

class App(base.StandardApp):
    def __init__(self,
                 name='SAFE_Connection',
                 version='0.0.0',
                 vendor='rid+dask',
                 addr='http://localhost'):
        self.name = name
        self.version = version
        self.vendor = vendor
        self.url = addr
        self.granted_auth_pointer = None
        self.app_pointer = None
        self.authenticator = authenticator.Authenticator
        self.mutableData = mutabledata.MutableData
        self.immutableData = immutabledata.ImmutableData
        self.sysUri = sysUri.SysUri()

        self.queue = queue.Queue()   # Each object has it's own queue for ffi calls
        self.bind_ffi_methods()

    # Public methods of this class override the auto bound ffi methods and are generally necessary where simple
    # string and null pointer conversion of python objects are not sufficient.  Default functionality is equivalent to:
    #  def login(self, secret, password, userdata=None, o_cb=None):
    #     self._login(*self.ensure_correct_form(secret, password, userdata, self.login_cb))
    # A full listing of the class methods automatically bound can be found in safe_app_defs.py (_APP_DEFS)
    def get_app_pointer(self):
        return self.app_pointer

    def mData(self):
        return self.mutableData(app_pointer=self.app_pointer)

    def iData(self):
        return self.immutableData(app_pointer=self.app_pointer)

    def encode_authentication(self, auth_data):
        self.encode_auth_req(auth_data, None)
        return self.queue.get()

    def setup_app(self, auth_data, granted_authentication):
        self.decode_ipc_msg(granted_authentication, None)
        self.granted_auth_pointer = self.queue.get()

        self.app_registered(auth_data.app.id, self.granted_auth_pointer[0], None)
        self.app_pointer = self.queue.get()

    def get_pub_key_handle(self):
        self.app_pub_sign_key(self.app_pointer, None)
        return self.queue.get()

    def cipher_new_plaintext(self):
        self.cipher_opt_new_plaintext(self.app_pointer, None)
        return self.queue.get()

        
if __name__ == '__main__':
    # we test it!
    A = App()
