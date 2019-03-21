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

# push callbacks into other threads to avoid trouble with concurrent access
from threading import Thread
from functools import wraps
import multihash
import cid

def safeThread(*args, **kwargs):
    '''
    A decorator function to align python calls with the internal threads of the rust library.
    :param kwargs: can be used to pass a default timeout or a specific queue instance
    :return: a python function running in its own thread.
    '''

    ## These work because the function defaults to the outer namespace.  Perhaps cleaner to put inside innerThreader?
    ## cleaner use of kwargs
    waitSeconds = kwargs.get('timeout', 5)
    myQueue = kwargs.get('queue', None)
        
    def threader(fun):
        @wraps(fun)
        def innerThreader(*args,**kwargs):
            oneThread = Thread(target=fun,args=args,kwargs=kwargs)
            oneThread.start()
            if myQueue:
                result = myQueue.get(timeout=waitSeconds)
                return result
        return innerThreader
    return threader



def getXorAddresOfMutable(data, ffi):
    xorName_asBytes = ffi.buffer(data.name)[:]
    myHash = multihash.encode(xorName_asBytes,'sha3-256')
    myCid = cid.make_cid(1,'dag-pb',myHash)
    encodedAddress = myCid.encode('base32').decode()
    return 'safe://' + encodedAddress + ':' + str(data.type_tag)
        
def getffiMutable(asBytes,ffi):
    ffiMutable=ffi.new('MDataInfo *')
    writeBuffer = ffi.buffer(ffiMutable)
    writeBuffer[:]=asBytes
    return ffiMutable
        
def checkResult(result,ffi):
    if result.error_code != 0:
        errorDescription = ffi.string(result.description)
        print('Following Error occured: ' + str(errorDescription))
        print('Error code: ' + str(result.error_code))
    else:
        print('action succeeded')
        
def AppExchangeInfo(id=b'noId',scope=b'noScope',name=b'noName',vendor=b'nobody',ffi=None):
    id = ffi.new('char[]',id)
    scope = ffi.new('char[]',scope)
    name = ffi.new('char[]',name)
    vendor = ffi.new('char[]',vendor)

    myStruct = ffi.new('AppExchangeInfo *',[id,scope,name,vendor])
    
    return myStruct, [id, scope, name, vendor]
        
def PermissionSet(read=True,insert=True,update=True,delete=True,manage_permissions=True,ffi=None):
    return ffi.new('PermissionSet *',[read,insert,update,delete,manage_permissions])

def ContainerPermissions(name=b'noName',access=None,ffi=None):
    containerName = ffi.new('char[]',name)
    if not access:
        access = PermissionSet(ffi=ffi)
    container = ffi.new('ContainerPermissions *',[containerName,access[0]])
    
    return container, [containerName,access]

def AuthReq(permissions,containers_len,containers_cap,id=b'noId',scope=b'pythonscript',
            name=b'noName',vendor=b'nobody',app_container=True,ffi=None):
    
    newExChangeInfo,infopayload = AppExchangeInfo(id,scope,name,vendor,ffi=ffi)
    
    authReq = ffi.new('AuthReq *',[newExChangeInfo[0],app_container,permissions,containers_len,containers_cap])
    
    return authReq, [newExChangeInfo,infopayload]

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
        copyLen=int(ffi.sizeof(ffi.new('uint8_t[1]'))*data.user_metadata_len)
        ffi.buffer(user_metadata_ptr,copyLenn)[:]=ffi.buffer(data.user_metadata_ptr,copyLen)[:]
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
        copyLen=int(ffi.sizeof(ffi.new('ContainerPermissions[1]'))*data.containers_len)
        ffi.buffer(containers,copyLen)[:]=ffi.buffer(data.containers,copyLen)[:]
        newData.containers = containers
        containerNames=[]
        for i in range(data.containers_len):
            containerNames.append(ffi.new('char[]',ffi.string(data.containers[i].cont_name)))
            newData.containers[i].cont_name=containerNames[-1]
        
        return newData,[containers,containerNames]
    
    elif ffi.typeof(data) == ffi.typeof('ContainersReq *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        containers = ffi.new('ContainerPermissions[]',data.containers_len)
        copyLen=int(ffi.sizeof(ffi.new('ContainerPermissions[1]'))*data.containers_len)
        ffi.buffer(containers,copyLen)[:]=ffi.buffer(data.containers,copyLen)[:]
        newData.containers = containers
        containerNames=[]
        for i in range(data.containers_len):
            containerNames.append(ffi.new('char[]',ffi.string(data.containers[i].cont_name)))
            newData.containers[i].cont_name=containerNames[-1]
        
        return newData,[containers,containerNames]
    
    elif ffi.typeof(data) == ffi.typeof('ShareMDataReq *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        mdata = ffi.new('ShareMData[]',data.mdata_len)
        copyLen=int(ffi.sizeof(ffi.new('ShareMData[1]'))*data.mdata_len)
        ffi.buffer(mdata,copyLen)[:]=ffi.buffer(data.mdata,copyLen)[:]
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
        copyLen=int(ffi.sizeof(ffi.new('ContainerInfo[1]'))*data.containers_len)
        ffi.buffer(containers,copyLen)[:]=ffi.buffer(data.containers,copyLen)[:]
        newData.containers = containers
        
        return newData,[containers]
    
    elif ffi.typeof(data) == ffi.typeof('AuthGranted *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        bootstrap_config = ffi.new('unsigned char[]',data.bootstrap_config_len)
        copyLen=int(ffi.sizeof(ffi.new('unsigned char[1]'))*data.bootstrap_config_len)
        ffi.buffer(bootstrap_config,copyLen)[:]=ffi.buffer(data.bootstrap_config,copyLen)[:]
        newData.bootstrap_config = bootstrap_config
        
        containers = ffi.new('ContainerInfo[]',data.access_container_entry.containers_len)
        copyLen=int(ffi.sizeof(ffi.new('ContainerInfo[1]'))*data.access_container_entry.containers_len)
        ffi.buffer(containers,copyLen)[:]=ffi.buffer(data.access_container_entry.containers,copyLen)[:]
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
        copyLen=int(ffi.sizeof(ffi.new('uint8_t[1]'))*data.val_len)
        ffi.buffer(val,copyLen)[:]=ffi.buffer(data.val,copyLen)[:]
        newData.val = val
        
        return newData,[val]
    
    elif ffi.typeof(data) == ffi.typeof('MDataValue *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        content = ffi.new('uint8_t[]',data.content_len)
        copyLen=int(ffi.sizeof(ffi.new('uint8_t[1]'))*data.content_len)
        ffi.buffer(content,copyLen)[:]=ffi.buffer(data.content,copyLen)[:]
        newData.content = content
        
        return newData,[content]
    
    elif ffi.typeof(data) == ffi.typeof('MDataEntry *'):
        newData = ffi.new(ffi.typeof(data),data[0])
        
        val = ffi.new('uint8_t[]',data.key.val_len)
        copyLen=int(ffi.sizeof(ffi.new('uint8_t[1]'))*data.key.val_len)
        ffi.buffer(val,copyLen)[:]=ffi.buffer(data.key.val,copyLen)[:]
        newData.key.val = val
        
        content = ffi.new('uint8_t[]',data.value.content_len)
        copyLen=int(ffi.sizeof(ffi.new('uint8_t[1]'))*data.value.content_len)
        ffi.buffer(content,copyLen)[:]=ffi.buffer(data.value.content,copyLen)[:]
        newData.value.content = content
        
        return newData,[val,content]
    
    
    else:
        newData = ffi.new(ffi.typeof(data),data[0])
        return newData,[]
