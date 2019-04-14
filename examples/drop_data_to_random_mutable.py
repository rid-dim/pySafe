#!/usr/bin/env python
# coding: utf-8

import safenet
safenet.setup_logger(file_level=safenet.log_util.WARNING)
myApp = safenet.App()
myAuth_,addData=safenet.safe_utils.AuthReq(myApp.ffi_app.NULL,0,0,id=b'testProgramName',scope=b'noScope'
                       ,name=b'randomProg',vendor=b'no_vendor',app_container=True,ffi=myApp.ffi_app)

myApp.encode_auth_req(myAuth_,myApp.ffi_app.NULL)
encodedAuth = myApp.queue.get()

grantedAuth = myApp.sysUri.quickSetup(myAuth_,encodedAuth)

# the granted auth (a long string) then needs to be decoded to get the authGranted-pointer from the safe-api

myApp.decode_ipc_msg(grantedAuth,None)
grantedAuthPointer = myApp.queue.get()

# that is then used to get the app-pointer

appPointer = myApp.queue.get()

## now we have an app and can start doing stuff

# creating a mutable Object
myMutable = safenet.MutableData()

# define Entries and drop them onto Safe

entries={'firstkey':'this is awesome',
         'secondKey':'and soon it should be',
         'thirdKey':'even easier to use safe with python',
         'i love safe':'and this is just the start'}

infoData = myMutable.new_random_public(appPointer,29787,entries)

# and here we get the xor address to view our mutable data in the browser (remember to turn o the experimental api (!) otherwise
# the data will not be shown)

print(safenet.safe_utils.getXorAddresOfMutable(infoData,myMutable.ffi_app))


