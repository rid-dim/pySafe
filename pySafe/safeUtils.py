########################################################################################################################
#
# pySafe - pySafeUtils
#
# this wants to be a collection of helper functions that makes handling the data coming from the safe API 
# a piece of cake =)
#
# p.s. yes - the cake is a lie
#
########################################################################################################################


# here we start out with a copy function that takes care of the inner values as well
def copy(data,ffi):
    '''
    copies all kinds of safe-API-Data and returns 
    newData,[all,necessary,linked,c,elements]
    '''
    if ffi.typeof(data) == ffi.typeof('FfiResult *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        if data.description != ffi.NULL:
            description = ffi.new('char[]',ffi.string(data.description))
        else:
            description = ffi.NULL
        newData.description = description
        
        return newData,[description]
    
    elif ffi.typeof(data) == ffi.typeof('File *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        user_metadata_ptr = ffi.new('uint8_t[]',data.user_metadata_len)
        #copyLen=int(ffi.sizeof(data.user_metadata_ptr)*data.user_metadata_len)
        ffi.buffer(user_metadata_ptr,data.user_metadata_len)[:]=ffi.buffer(data.user_metadata_ptr,data.user_metadata_len)[:]
        newData.user_metadata_ptr = user_metadata_ptr
        
        return newData,[user_metadata_ptr]
    
    elif ffi.typeof(data) == ffi.typeof('AppExchangeInfo *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        id = ffi.new('char[]',ffi.string(data.id))
        scope = ffi.new('char[]',ffi.string(data.scope))
        name = ffi.new('char[]',ffi.string(data.name))
        vendor = ffi.new('char[]',ffi.string(data.vendor))
        newData.id = id
        newData.scope = scope
        newData.name = name
        newData.vendor = vendor
        
        return newData,[id, scope, name, vendor]
    
    elif ffi.typeof(data) == ffi.typeof('ContainerPermissions *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        cont_name = ffi.new('char[]',ffi.string(data.cont_name))
        newData.cont_name = cont_name
        
        return newData,[cont_name]
    
    elif ffi.typeof(data) == ffi.typeof('AuthReq *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        containers = ffi.new('ContainerPermissions[]',data.containers_len)
        #copyLen=int(ffi.sizeof(data.containers)*data.containers_len)
        ffi.buffer(containers,data.containers_len)[:]=ffi.buffer(data.containers,data.containers_len)[:]
        newData.containers = containers
        containerNames=[]
        for i in range(data.containers_len):
            containerNames.append(ffi.new('char[]',ffi.string(data.containers[i].cont_name)))
            newData.containers[i].cont_name=containerNames[-1]
        
        return newData,[containers,containerNames]
    
    elif ffi.typeof(data) == ffi.typeof('ContainersReq *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        containers = ffi.new('ContainerPermissions[]',data.containers_len)
        #copyLen=int(ffi.sizeof(data.containers)*data.containers_len)
        ffi.buffer(containers,data.containers_len)[:]=ffi.buffer(data.containers,data.containers_len)[:]
        newData.containers = containers
        containerNames=[]
        for i in range(data.containers_len):
            containerNames.append(ffi.new('char[]',ffi.string(data.containers[i].cont_name)))
            newData.containers[i].cont_name=containerNames[-1]
        
        return newData,[containers,containerNames]
    
    elif ffi.typeof(data) == ffi.typeof('ShareMDataReq *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        mdata = ffi.new('ShareMData[]',data.mdata_len)
        #copyLen=int(ffi.sizeof(data.mdata)*data.mdata_len)
        ffi.buffer(mdata,data.mdata_len)[:]=ffi.buffer(data.mdata,data.mdata_len)[:]
        newData.mdata = mdata
        
        return newData,[mdata]
    
    elif ffi.typeof(data) == ffi.typeof('ContainerInfo *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        name = ffi.new('char[]',ffi.string(data.name))
        newData.name = name
        
        return newData,[name]
    
    elif ffi.typeof(data) == ffi.typeof('AccessContainerEntry *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        containers = ffi.new('ContainerInfo[]',data.containers_len)
        #copyLen=int(ffi.sizeof(data.containers)*data.containers_len)
        ffi.buffer(containers,data.containers_len)[:]=ffi.buffer(data.containers,data.containers_len)[:]
        newData.containers = containers
        
        return newData,[containers]
    
    elif ffi.typeof(data) == ffi.typeof('AuthGranted *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        bootstrap_config = ffi.new('unsigned char[]',data.bootstrap_config_len)
        #copyLen=int(ffi.sizeof(data.bootstrap_config)*data.bootstrap_config_len)
        ffi.buffer(bootstrap_config,data.bootstrap_config_len)[:]=ffi.buffer(data.bootstrap_config,data.bootstrap_config_len)[:]
        newData.bootstrap_config = bootstrap_config
        
        containers = ffi.new('ContainerInfo[]',data.access_container_entry.containers_len)
        #copyLen=int(ffi.sizeof(data.access_container_entry.containers)*data.access_container_entry.containers_len)
        ffi.buffer(containers,data.access_container_entry.containers_len)[:]=ffi.buffer(data.access_container_entry.containers,data.access_container_entry.containers_len)[:]
        newData.access_container_entry.containers = containers
        containerNames=[]
        for i in range(data.access_container_entry.containers_len):
            containerNames.append(ffi.new('char[]',ffi.string(data.access_container_entry.containers[i].name)))
            newData.access_container_entry.containers[i].name=containerNames[-1]
        
        return newData,[bootstrap_config,containers,containerNames]
    
    elif ffi.typeof(data) == ffi.typeof('AppAccess *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        name = ffi.new('char[]',ffi.string(data.name))
        app_id = ffi.new('char[]',ffi.string(data.app_id))
        newData.name = name
        newData.app_id = app_id
        
        return newData,[name, app_id]
    
    elif ffi.typeof(data) == ffi.typeof('MetadataResponse *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        name = ffi.new('char[]',ffi.string(data.name))
        description = ffi.new('char[]',ffi.string(data.description))
        newData.name = name
        newData.description = description
        
        return newData,[name, description]
    
    elif ffi.typeof(data) == ffi.typeof('MDataKey *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        val = ffi.new('uint8_t[]',data.val_len)
        #copyLen=int(ffi.sizeof(data.val)*data.val_len)
        ffi.buffer(val,data.val_len)[:]=ffi.buffer(data.val,data.val_len)[:]
        newData.val = val
        
        return newData,[val]
    
    elif ffi.typeof(data) == ffi.typeof('MDataValue *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        content = ffi.new('uint8_t[]',data.content_len)
        #copyLen=int(ffi.sizeof(data.content)*data.content_len)
        ffi.buffer(content,data.content_len)[:]=ffi.buffer(data.content,data.content_len)[:]
        newData.content = content
        
        return newData,[content]
    
    elif ffi.typeof(data) == ffi.typeof('MDataEntry *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        val = ffi.new('uint8_t[]',data.key.val_len)
        #copyLen=int(ffi.sizeof(data.key.val)*data.key.val_len)
        ffi.buffer(val,data.key.val_len)[:]=ffi.buffer(data.key.val,data.key.val_len)[:]
        newData.key.val = val
        
        content = ffi.new('uint8_t[]',data.value.content_len)
        #copyLen=int(ffi.sizeof(data.value.content)*data.value.content_len)
        ffi.buffer(content,data.value.content_len)[:]=ffi.buffer(data.value.content,data.value.content_len)[:]
        newData.value.content = content
        
        return newData,[val,content]
    
    else:
        newData = ffi.new(ffi.typeof(data),data[0])
        return newData,[]
