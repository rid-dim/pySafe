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

import argparse, getpass
parser = argparse.ArgumentParser()
parser.add_argument("--rpc", help="run an rpc server on port : ")
parser.add_argument("--user", help="supply user name")
parser.add_argument("--pw", help="supply password")
parser.add_argument("--verbose", help="verbose", action='store_true')
parser.add_argument("--authenticate", help="authenticate this request")

args = parser.parse_args()

if args.rpc:
    print(f'Running an RPC server on port:{args.rpc} .. not really though :(')

else:
    import safenet
    if args.verbose:
        safenet.setup_logger()
    else:
        safenet.setup_logger(std_style='print',master_level='warning')
    print('Running in some other mode')

    # Logging in is easy!
    myAuth = safenet.Authenticator()
    if not args.user:
        args.user=getpass.getpass(prompt='USER:')
    if not args.pw:
        args.pw = getpass.getpass(prompt='PASSWORD:')

    myAuth.login(args.user, args.pw, None)

    if args.authenticate:
        print('At some point this will do something.')