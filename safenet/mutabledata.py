import safenet.base_classes as base
import safenet.safe_utils as safeUtils
import queue

class MutableData(base.StandardMutableData):
    def __init__(self, app_pointer=None, fromBytes=None):
        self.queue = queue.Queue()
        self.bind_ffi_methods()
        self.app_pointer = app_pointer
        
        # defining the mutableData
        if fromBytes:
            self.asBytes = fromBytes
            #self.ffiMutable=ffi.new('MDataInfo *') - i think the ffi-datatypes should only exist locally in our functions
            # otherwise we can't pickle out own class (at least i got always faults when trying to do it with ffi classes yet)
        else:
            self.asBytes = None

    ## Now, public methods here

    def new_random_public(self, type_tag, sign_key_handle, content_as_dict=None):
        self.mdata_permissions_new(self.app_pointer, None)
        permission_handle = self.queue.get()

        self.mdata_entries_new(self.app_pointer, None)
        entry_handle = self.queue.get()

        #self.app_pub_sign_key(self.app_pointer, None)
        #sign_key_handle = self.queue.get()

        for item in content_as_dict:
            self.mdata_entries_insert(self.app_pointer, entry_handle, item, len(item), content_as_dict[item],
                                           len(content_as_dict[item]), None)
            self.queue.get()

        permissions = safeUtils.PermissionSet(ffi=self.ffi_app)

        self.mdata_permissions_insert(self.app_pointer, permission_handle, sign_key_handle, permissions, None)
        self.queue.get()

        self.mdata_info_random_public(type_tag, None)
        random_info = self.queue.get()

        self.mdata_put(self.app_pointer, random_info, permission_handle, entry_handle, None)
        self.queue.get()

        return random_info

    def insertEntries(self, info_data, content_as_dict):
        self.mdata_entry_actions_new(self.app_pointer, None)
        entry_handle = self.queue.get()

        for item in content_as_dict:

            self.mdata_entry_actions_insert(self.app_pointer, entry_handle, item, len(item), content_as_dict[item],
                                           len(content_as_dict[item]), None)
            self.queue.get()


        self.mdata_mutate_entries(self.app_pointer, info_data, entry_handle, None)
        self.queue.get()

    def getCurrentState(self, info_data):

        self.mdata_list_values(self.app_pointer, info_data, None)
        values = self.queue.get()

        self.mdata_list_keys(self.app_pointer, info_data, None)
        keys = self.queue.get()

        return dict(zip(keys, values))