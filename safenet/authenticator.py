########################################################################################################################
#
# pySafe - Authenticator
#
# This file encapsulates the interface for the authenticator library.
#
# The authenticator is a critical component of any app, and is required for many tasks. Later, it may be a design
# decision access this through another abstraction (e.g. session or connection)
#
# The implementations for the various functions should be the last place in the library you will see ffi.
#  Higher level abstractions should be able to use the public methods with pure python objects
#
########################################################################################################################

import safenet.base_classes as base
import queue

class Authenticator(base.FullAuthenticator):
    '''
    A python interface to the SAFE authenticator object
    At present, introspection fails because of the auto-binding.  For further reference on methods:
    https://github.com/maidsafe/safe_client_libs/wiki
    safenet/safe_auth_defs.py
    '''

    def __init__(self):
        self.is_setup=False
        self._ref_to_pyObject=self.ffi_auth.new_handle(self)
        self._ref_to_clientObject=None
        self._apps=None
        self.queue = queue.Queue()  # Each object has it's own queue for ffi calls

        # Need to get rid of this.
        self._info=None

        self._setup()

    def _setup(self):
        '''
        Does the basic priming of the authenticator and libraries.  Really only needs be done once per connection
        session
        '''
        self.bind_ffi_methods()
        self.auth_set_additional_search_path(self.global_config.GLOBAL_BINPATH, None)
        self.auth_exe_file_stem(None, None)
        self.is_setup=True

    @property
    def pointer(self):
        return self._ref_to_pyObject
    @property
    def handle(self):
        return self._ref_to_clientObject


    # Public methods of this class override the auto bound ffi methods and are generally necessary where simple
    # string and null pointer conversion of python objects are not sufficient.  Default functionality is equivalent to:
    #  def login(self, secret, password, userdata=None, o_cb=None):
    #     self._login(*self.ensure_correct_form(secret, password, userdata, self.login_cb))
    # A full listing of the class methods automatically bound can be found in safe_auth_defs.py

    def account_info(self):
        self.auth_account_info(self.handle, self.pointer, o_cb = self.info_cb)
        self.queue.get()


    # Callback methods
    @staticmethod
    def login_cb(user_data ,result, authenticator):
        #user_data=Authenticator.ffi_auth.from_handle(user_data)
        user_data._ref_to_clientObject=authenticator

    @staticmethod
    def info_cb(user_data ,result ,account_info):
        user_data=Authenticator.ffi_auth.from_handle(user_data)
        print('Account Balance:')
        print('Puts Used     :', account_info.mutations_done)
        print('Puts Remaining:', account_info.mutations_available)
        user_data._info = account_info

    @staticmethod
    def registered_apps_cb(user_data ,result ,registered_app ,registered_app_len):
        #user_data=Authenticator.ffi_auth.from_handle(user_data)
        user_data._apps=registered_app
        print(f'registered apps: {registered_app_len}')
        for x in range(0,registered_app_len):
            print(f' -> {user_data.ffi_auth.string(registered_app[x].app_info.name).decode()}:{user_data.ffi_auth.string(registered_app[x].app_info.id).decode()}')
            print(f' access:')
            for y in range(0,registered_app.containers_len):
                print(f'       - {user_data.ffi_auth.string(registered_app.containers[y].cont_name).decode()}')


# now there is only one
#Authenticator=Authenticator()

if __name__ == '__main__':
    A = Authenticator()

    def printfilestem(one,two,stem):
        print(A.ffi_auth.string(stem))
    # Note again that these methods were never defined, and can be called with regular strings and python objects:)
    A.login('secret','password', None, None)
