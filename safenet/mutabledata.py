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

    def new_random_public(self, app_pointer, type_tag, content_as_dict=None):
        self.mdata_permissions_new(app_pointer, None)
        permission_handle = self.queue.get()

        self.mdata_entries_new(app_pointer, None)
        entry_handle = self.queue.get()

        for item in content_as_dict:
            self.mdata_entries_insert(app_pointer, entry_handle, item, len(item), content_as_dict[item],
                                           len(content_as_dict[item]), None)
            self.queue.get()

        self.mdata_info_random_public(type_tag, None)
        random_info = self.queue.get()

        self.mdata_put(app_pointer, random_info, permission_handle, entry_handle, None)
        self.queue.get()

        return random_info
