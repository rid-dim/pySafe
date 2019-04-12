##
#
# This is just for testing now.  It will be the entry point for any pysafe exe
# Should take args, e.g.  pysafe --rpc  would start the rpc server, etc.
#
# Build with pyinstaller pysafe-universal.spec
#
#import time
#print ('PAUSING TO DEBUG TEMP DIRECTORY')
#time.sleep(5)
import safenet
import argparse


if __name__=='__main__':
    safenet.setup_logger()

    # Logging in is easy!
    myAuth = safenet.Authenticator()
    myAuth.login('a', 'b', None)
    print('Safenet load success')