# Demo 1
# Demonstrates some basic functionality of the library and serves as a reminder of what needs to be cleaned up
# This file will be done when there is no weird variables or boilerplate

import safenet
import time

# try it with and without the logger enabled.
# check config.py for default settings. check log_util.setup_logger() for kw arguments
# if you want to intercept the messages, you can inject your own handlers.

safenet.setup_logger()

with open('creds.txt') as f:   #  For simplicity, my credentials are in a simple file called creds.txt.
    creds=f.readlines()[0].strip().split()
    usrnm,psw = creds[0],creds[1]

# Logging in is easy!
myAuth=safenet.Authenticator()
#myAuth.login(usrnm,psw,myAuth.pointer, o_cb=myAuth.login_cb)   # works, as it goes through user data
myAuth.login(usrnm,psw,None, o_cb=myAuth.login_cb)

# Necessary to avoid issues with threading ..
safenet.log.info('sleeping until login cb')
while myAuth.handle is None:
    time.sleep(0.1)

#myAuth.auth_account_info(myAuth.handle, myAuth.pointer, o_cb=myAuth.info_cb)  # this way uses userdata
myAuth.account_info()


# Necessary to avoid issues with threading ..
safenet.log.info('sleeping until info cb')
while myAuth._info is None:
    time.sleep(0.1)

myAuth.auth_registered_apps(myAuth.handle, myAuth.pointer, o_cb=myAuth.registered_apps_cb)

safenet.log.info('sleeping until apps cb')
while myAuth._apps is None:
    time.sleep(0.1)



#myApp=safenet.App()
#I = safenet.ImmutableData()
#I.idata_new_self_encryptor()