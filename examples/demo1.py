# Demo 1
# Demonstrates some basic functionality of the library

import safenet

# try it with and without the logger enabled.
# check config.py for default settings. check log_util.setup_logger() for kw arguments
# if you want to intercept the messages, you can inject your own handlers.
safenet.setup_logger()


# Logging in is easy!
myAuth=safenet.Authenticator()
myAuth.login('a','b',None)

