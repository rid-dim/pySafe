#!/usr/bin/env python
# coding: utf-8

import safenet
safenet.setup_logger(file_level=safenet.log_util.WARNING)
myApp = safenet.App()
myAuth_,addData=safenet.safe_utils.AuthReq(myApp.ffi_app.NULL,0,0,id=b'testProgramName',scope=b'noScope'
                       ,name=b'randomProg',vendor=b'no_vendor',app_container=True,ffi=myApp.ffi_app)

encodedAuth = myApp.encode_authentication(myAuth_)
grantedAuth = myApp.sysUri.quickSetup(myAuth_,encodedAuth)
myApp.setup_app(myAuth_,grantedAuth)

# ### now we have an app and can start doing stuff

# creating a mutable Object
myMutable = myApp.mData()

# define Entries and drop them onto Safe
import datetime

entries={'firstkey':'this is awesome',
         'secondKey':'and soon it should be',
         'thirdKey':'even easier to use safe with python',
         'i love safe':'and this is just the start',
         'thisWasUploaded at':datetime.datetime.utcnow().strftime('%Y-%m-%d - %H:%M:%S UTC'),
         'additionalEntry':input('enter your custom value here: ')}

infoData = myMutable.new_random_public(29787,entries)

print()
print('you can view your mutable here:')
print(safenet.safe_utils.getXorAddresOfMutable(infoData,myMutable.ffi_app))






