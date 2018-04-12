########################################################################################################################
#
#  pySafe - Authenticator Interface
#
########################################################################################################################

# This brings all the c interfaces into this module .. maybe better to keep it in a namespace?
import pySafe.interface as interface

NULL=interface.NULL

class Connection:
    def __init__(self,
                 name='SAFE_Connection',
                 version='0.0.0',
                 vendor='rid+dask',
                 addr='http://localhost',
                 alternate_crust_config=None):
        self.name = name
        self.version = version
        self.vendor = vendor
        self.url = addr
        self.lib_auth = interface.lib_auth
        self.lib_app = interface.lib_app

        #Try and add this here...
        if alternate_crust_config is None:
            interface.add_local_crust_config()


    def login(self, account_locator, account_password, user_data=None, disconnect_notifier_cb=None, cb=None,
              encoding='utf-8'):
        ''' string/bytes, string/bytes, [any], [function], [function], [encoding]
            char* account_locator, char* account_password, void* user_data

            > return values of the callback functions:
            disconnect_notifier_cb - void* user_data
            cb - void* user_data, FfiResult* result, Authenticator* authenticator
        '''


        @interface.safe_callback("void(void*)")
        def o_disconnect_notifier_cb(user_data):

            ## ?? wise to define this inline?
            if disconnect_notifier_cb:
                disconnect_notifier_cb(user_data)
            else:
                pass

        @interface.safe_callback("void(void*,FfiResult*,Authenticator*)")
        def o_cb(user_data, result, authenticator):

            ## ??  wise to define this inline?
            if cb:
                cb(user_data, result, authenticator)
            else:
                interface.print_default_ffi_result(result, 'HOO! logged into the SAFE Network')


        account_locator = interface.ffi_str(account_locator)
        password = interface.ffi_str(account_password)
        if user_data:
            userData = interface.ffi.new_handle(user_data)
        else:
            userData = NULL

        self.lib_auth.login(account_locator, password, userData, o_disconnect_notifier_cb, o_cb)




