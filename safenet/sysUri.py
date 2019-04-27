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
import safenet.safe_utils as safeUtils
import base64
import os
import random
import string
import tempfile

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
        
    def quickSetup(self,authReq,encodedRequest,icon=b''):
        schemeName=b'safe-'+base64.b64encode(self.ffi_sysUri.string(authReq.app.id)).strip(b'=')
        with tempfile.NamedTemporaryFile() as f:
            pathToHandler=(f.name).encode()
     
            exec_args=self.ffi_sysUri.new('char[]',b'python')
            exec_args2=self.ffi_sysUri.new('char[]',pathToHandler)
            exec_args_1 = self.ffi_sysUri.new('char*[]',[exec_args,exec_args2])
            bundle = self.ffi_sysUri.string(authReq.app.id)
            vendor = self.ffi_sysUri.string(authReq.app.vendor)
            name = self.ffi_sysUri.string(authReq.app.name)
            self.install(*safeUtils.ensure_correct_form(self.ffi_sysUri,
                                                        bundle,
                                                        vendor,
                                                        name,
                                                        exec_args_1,
                                                        2,
                                                        icon,
                                                        schemeName,
                                                        None))
            
            port = random.randint(1024, 49151)
            self.log.info(f'filename is: {pathToHandler} and port number is: {port}')
            
            encodedReturnVal = safeUtils.catchSysUriCall(self.open_uri, (b'safe-auth://'+encodedRequest,None),port,pathToHandler,safeUtils.writeRequestHandler)
        return encodedReturnVal.split(':')[-1]


if __name__ == '__main__':
    S = SysUri()
