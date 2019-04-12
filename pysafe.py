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

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--rpc", help="run an rpc server")
args = parser.parse_args()

if args.rpc:
    print('Running an RPC server .. not really though :(')

else:
    import safenet
    safenet.setup_logger()
    print('Running in some other mode')

    # Logging in is easy!
    myAuth = safenet.Authenticator()
    myAuth.login('a', 'b', None)