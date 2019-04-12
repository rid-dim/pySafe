##
#
# This is just for testing now.  It will be the entry point for any pysafe exe
# Should take args, e.g.  pysafe --rpc  would start the rpc server, etc.
#
# Build with pyinstaller pysafe.py --hidden-import=_cffi_backend --onefile
#
import safenet
import argparse

if __name__=='__main__':
    print('Safenet load success')