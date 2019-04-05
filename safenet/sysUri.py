########################################################################################################################
#
# pySafe - SysUri
#
# SysUri offers an interface to create local uri scheme handler and execute those uri-schemes
#
#
# The Authenticator uses the unique app-Name, does a base64-encoding of this unique name and puts a "safe-" in front
#
# on App authentication the authenticator then opens e.g.
#  - safe-TmV3UHJvZ0lkX1VpcXVlX3RoaW5n://[encodedAuthentication]
#
# with the local uri scheme the OS [e.g. on Linux you can find the defined schemes at ~/.local/share/applications/]
# then knows that it needs to execute the command
# - python ~/myAwesomeApp/requestHandler.py [encodedAuthentication]
#
########################################################################################################################

import safenet.base_classes as base
import queue

class SysUri(base.SysUri):
    '''
    A python interface to the SAFE SysUri object
    At present, introspection fails because of the auto-binding.  For further reference on methods:
    https://github.com/maidsafe/safe_client_libs/wiki
    safenet/safe_sysUri_defs.py
    '''

    def __init__(self):
        self.queue = queue.Queue()  # Each object has it's own queue for ffi calls
        self.bind_ffi_methods()


if __name__ == '__main__':
    S = SysUri()
