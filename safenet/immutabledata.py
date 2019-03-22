import safenet.base_classes as base
import safenet.safeUtils as safeUtils
import queue

# first attempt to define mutable Data for us
class ImmutableData(base.StandardImmutableData):

    def __init__(self,fromBytes=None):
        self.queue = queue.Queue()
        self.bind_ffi_methods()
        
        # defining the mutableData
        if fromBytes:
            self.asBytes = fromBytes
            #self.ffiMutable=ffi.new('MDataInfo *')
            #writeBuffer = ffi.buffer(self.ffiMutable)
            #writeBuffer[:]=self.asBytes
        else:
            self.asBytes = None
            #self.ffiMutable = None

