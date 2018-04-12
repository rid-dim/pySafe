
# coding: utf-8

# ### Just an example/idea how SAFE Datatypes in Python could be defined for easy creation of 'empty containers' to test the callback-functions one wants to pass to a library function

# In[1]:

from cffi import FFI
ffi = FFI()


# In[2]:

datatypes='''
typedef int int32_t;
typedef struct {
    int32_t error_code;
    char* description;
} FfiResult;
typedef struct {
    void* core_tx;
    void* _core_joiner;
} Authenticator;
'''


# In[3]:

ffi.cdef(datatypes)


# In[8]:

class SafeUtils:
    def __init__(self, myStr=b'', num=0):
        self.datattypes=datatypes
            
    def getCString(cString, maxStringLength=int(1e6)):
        foundEndOfString=False
        for stringPosition in range(maxStringLength):
            if cString[stringPosition] == b'\x00':
                completeString = ffi.unpack(cString,stringPosition)
                break
        return completeString
    


# In[5]:

class FfiRes:
    def __init__(self, myStr=b'', num=0):
        if type(myStr) == bytes:
            self._description = ffi.new('char[]',myStr)
        else:
            print('description is not datat type bytes')
            self._description = ffi.new('char[]',b'')
        self.description = myStr
        self.error_code = num
        self.entity = ffi.new('FfiResult*',[self.error_code,self._description])
        
    def getNum(self):
        return self.entity.error_code
    
    def getString(self):
        return SafeUtils.getCString(self.entity.description)


# In[6]:

class Authenticator:
    def __init__(self):
        self.core_tx = ffi.new_handle(self)
        self._core_joiner = ffi.newhandle(self)
        self.entity = ffi.new('FfiResult *',[self.core_tx,self.self._core_joiner])


# In[7]:

class cstr:
    def __init__(self,myStringToCreate):
        self.entity = ffi.new('char[]',myStringToCreate)


# In[ ]:




# In[ ]:



