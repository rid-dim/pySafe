import safenet.base_classes as base
import safenet.safe_utils as safeUtils
import queue

class MutableData(base.StandardMutableData):
    def __init__(self,fromBytes=None):
        self.queue = queue.Queue()
        self.bind_ffi_methods()
        
        # defining the mutableData
        if fromBytes:
            self.asBytes = fromBytes
            #self.ffiMutable=ffi.new('MDataInfo *') - i think the ffi-datatypes should only exist locally in our functions
            # otherwise we can't pickle out own class (at least i got always faults when trying to do it with ffi classes yet)
        else:
            self.asBytes = None

    ## Now, public methods here
    

        