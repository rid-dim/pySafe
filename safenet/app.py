########################################################################################################################
#
# pySafe - Authenticator Interface
#
# This is really just a stub  ... files like this should be able to import the interface and just go, but code structure
# really needs some thought
#
#
#
########################################################################################################################

# This brings all the c interfaces into this module ..  at this point still clean code
import safenet.base_classes as base
import safenet.authenticator as authenticator
import safenet.mutabledata as mutabledata
import safenet.immutabledata as immutabledata

import queue

# From here on in is just a very basic 'working' example
# todo we need heavy thought on how to structure the various classes.
class App(base.StandardApp):
    def __init__(self,
                 name='SAFE_Connection',
                 version='0.0.0',
                 vendor='rid+dask',
                 addr='http://localhost'):
        self.name = name
        self.version = version
        self.vendor = vendor
        self.url = addr
        self.authenticator = authenticator.Authenticator()
        self.mutableData = mutabledata.MutableData()
        self.immutableData = immutabledata.ImmutableData()

        self.queue = queue.Queue()   # Each object has it's own queue for ffi calls
        self.bind_ffi_methods()

        ## Now, public methods here
        
        
if __name__ == '__main__':
    # we test it!
    A = App()
