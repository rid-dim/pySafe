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
                 addr='http://localhost'):
        self.name = name
        self.version = version
        self.vendor = vendor
        self.url = addr
        self.lib_auth = interface.lib_auth
        self.lib_app = interface.lib_app

    def defaultFfiResult(self, result, actionDescription):

        if result.error_code == 0:
            print('successfully ' + actionDescription)
        else:
            print('an Error occured - Error Code: ' + str(result.error_code))
            print('Error description: ' + str(interface.ffi.string(result.description)))

    def toByteIfString(self, parameter, encoding):
        if type(parameter) == str:
            return parameter.encode()
        else:
            return parameter




    def login(self, account_locator, account_password, user_data=None, disconnect_notifier_cb=None, cb=None,
              encoding='utf-8'):
        ''' string/bytes, string/bytes, [any], [function], [function], [encoding]
            char* account_locator, char* account_password, void* user_data

            > return values of the callback functions:
            disconnect_notifier_cb - void* user_data
            cb - void* user_data, FfiResult* result, Authenticator* authenticator
        '''

        @interface.ffi.callback("void(void*)")
        def o_disconnect_notifier_cb(user_data):

            if disconnect_notifier_cb:
                disconnect_notifier_cb(user_data)
            else:
                pass

        @interface.ffi.callback("void(void*,FfiResult*,Authenticator*)")
        def o_cb(user_data, result, authenticator):

            if cb:
                cb(user_data, result, authenticator)
            else:
                self.defaultFfiResult(result, 'logged into the SAFE Network')

        account_locator = interface.ffi_str(account_locator)
        password = interface.ffi_str(account_password)
        if user_data:
            userData = interface.ffi.new_handle(user_data)
        else:
            userData = NULL

        self.lib_auth.login(account_locator, password, userData, o_disconnect_notifier_cb, o_cb)


